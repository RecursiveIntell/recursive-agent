//! Locked, crash-recoverable receipt chain and descriptor-relative artifact store.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use recursive_agent_contracts::{
    content_digest, derive_artifact_id, derive_receipt_id, project_runtime_events,
    validate_receipt_sequence, ArtifactDescriptorV1, AuthorityLineageEntryV1, ContentDigest,
    ContractError, CurrentRunId, CurrentStepId, LifecycleValidationMode, PackVerificationResultV1,
    ReceiptIdentityMaterialV1, ReceiptKindV1, ReceiptOutcomeV1, ReceiptV1, RunPackEventSummaryV1,
    RunPackEvidenceProjectionV1, RunPackFileEntryV1, RunPackManifestV1, RunPackProjectionOriginV1,
    RunPackVaultRefV1, RunPackVerificationV1, RunTerminalStateV1, RuntimeEventV1, GENESIS_SEED,
};
use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_ARTIFACT_SIZE: u64 = 16 * 1024 * 1024;
const IO_BUFFER_SIZE: usize = 64 * 1024;
const MAX_CHAIN_META_BYTES: u64 = 16 * 1024;
const MAX_ARTIFACT_META_BYTES: u64 = 16 * 1024;
const MAX_RECEIPT_LOG_BYTES: u64 = 64 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Server-owned opaque storage for verified Run Packs.
#[derive(Debug, Clone)]
pub struct PackVault {
    root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct VaultAdmission {
    object_id: String,
    path: PathBuf,
    receipt: VaultAdmissionReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultAdmissionReceipt {
    source_pack_digest: ContentDigest,
    final_manifest_digest: ContentDigest,
    final_content_digest: ContentDigest,
    object_id: String,
    recorded_at: DateTime<Utc>,
}

impl VaultAdmission {
    pub fn object_id(&self) -> &str {
        &self.object_id
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn manifest_digest(&self) -> &ContentDigest {
        &self.receipt.final_manifest_digest
    }
    pub fn recorded_at(&self) -> DateTime<Utc> {
        self.receipt.recorded_at
    }

    /// Construct projection facts only from this server-admitted, reverified object.
    pub fn build_evidence_projection(
        &self,
        mut origin: RunPackProjectionOriginV1,
    ) -> Result<RunPackEvidenceProjectionV1, LedgerError> {
        origin.recorded_at = self.receipt.recorded_at;
        let snapshot = verified_run_pack_snapshot(&self.path)?;
        if snapshot.pack_verification().manifest_digest != self.receipt.final_manifest_digest
            || content_digest(&snapshot.manifest.files)? != self.receipt.final_content_digest
        {
            return Err(LedgerError::RunPackInvalid(
                "vault admission binding mismatch".into(),
            ));
        }
        let relative_ref = format!("objects/{}", self.object_id);
        let verification_receipt_digest = content_digest(&self.receipt)?;
        snapshot.build_evidence_projection_from_metadata(
            RunPackVerificationV1 {
                verifier_contract_version: "recursive-agent.run-pack-verifier/v1".into(),
                verified_at: self.receipt.recorded_at,
                verification_receipt_digest,
                outcome: recursive_agent_contracts::RunPackVerificationOutcomeV1::Verified,
            },
            RunPackVaultRefV1 {
                object_id: self.object_id.clone(),
                relative_ref,
                retention_state: recursive_agent_contracts::RunPackRetentionStateV1::Available,
            },
            origin,
        )
    }
}

impl PackVault {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, LedgerError> {
        let root = root.into();
        std::fs::create_dir_all(root.join("objects"))?;
        std::fs::create_dir_all(root.join("admissions"))?;
        std::fs::create_dir_all(root.join("quarantine"))?;
        Ok(Self { root })
    }

    fn admission_receipt_path(&self, object_id: &str) -> Result<PathBuf, LedgerError> {
        Self::validate_relative_ref(object_id)?;
        Ok(self
            .root
            .join("admissions")
            .join(format!("{object_id}.json")))
    }

    fn persist_admission_receipt(
        &self,
        receipt: &VaultAdmissionReceipt,
    ) -> Result<(), LedgerError> {
        let path = self.admission_receipt_path(&receipt.object_id)?;
        let bytes = recursive_agent_contracts::jcs_canonical(receipt)?;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn admission_receipts(&self) -> Result<Vec<VaultAdmissionReceipt>, LedgerError> {
        let mut receipts = Vec::new();
        for entry in std::fs::read_dir(self.root.join("admissions"))? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                return Err(LedgerError::RunPackInvalid(
                    "vault admission receipt is not a regular file".into(),
                ));
            }
            let bytes = std::fs::read(entry.path())?;
            let receipt =
                serde_json::from_slice::<VaultAdmissionReceipt>(&bytes).map_err(|error| {
                    LedgerError::RunPackInvalid(format!("invalid admission receipt: {error}"))
                })?;
            if recursive_agent_contracts::jcs_canonical(&receipt)? != bytes {
                return Err(LedgerError::RunPackInvalid(
                    "admission receipt is not canonical".into(),
                ));
            }
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    fn admission_receipt(&self, object_id: &str) -> Result<VaultAdmissionReceipt, LedgerError> {
        let path = self.admission_receipt_path(object_id)?;
        let bytes = std::fs::read(path).map_err(|_| {
            LedgerError::RunPackInvalid("vault object has no admission receipt".into())
        })?;
        let receipt = serde_json::from_slice::<VaultAdmissionReceipt>(&bytes).map_err(|error| {
            LedgerError::RunPackInvalid(format!("invalid admission receipt: {error}"))
        })?;
        if receipt.object_id != object_id
            || recursive_agent_contracts::jcs_canonical(&receipt)? != bytes
        {
            return Err(LedgerError::RunPackInvalid(
                "vault admission receipt binding mismatch".into(),
            ));
        }
        Ok(receipt)
    }

    pub fn validate_relative_ref(value: &str) -> Result<(), LedgerError> {
        if value.is_empty()
            || value.contains('\\')
            || value.starts_with('/')
            || value
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
        {
            return Err(LedgerError::RunPackInvalid(
                "unsafe vault relative reference".into(),
            ));
        }
        Ok(())
    }
    pub fn admit(&self, source: &Path) -> Result<VaultAdmission, LedgerError> {
        self.admit_with_failpoint(source, None)
            .and_then(|result| result)
    }

    /// Exercise one durable admission boundary and return as if the process stopped.
    /// The next exact retry must reconcile the durable receipt/object pair.
    pub fn admit_with_interruption(
        &self,
        source: &Path,
    ) -> Result<Result<VaultAdmission, LedgerError>, LedgerError> {
        self.admit_with_failpoint(source, Some(RunPackExportStage::CopyComplete))
    }

    pub fn admit_with_interruption_at(
        &self,
        source: &Path,
        stage: RunPackExportStage,
    ) -> Result<Result<VaultAdmission, LedgerError>, LedgerError> {
        self.admit_with_failpoint(source, Some(stage))
    }

    fn admit_with_failpoint(
        &self,
        source: &Path,
        failpoint: Option<RunPackExportStage>,
    ) -> Result<Result<VaultAdmission, LedgerError>, LedgerError> {
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(self.root.join(".admission.lock"))?;
        rustix::fs::flock(lock.as_fd(), FlockOperation::LockExclusive)
            .map_err(std::io::Error::from)?;
        let result = self.admit_locked(source, failpoint);
        let unlock = rustix::fs::flock(lock.as_fd(), FlockOperation::Unlock);
        match (result, unlock) {
            (Ok(admission), Ok(())) => Ok(Ok(admission)),
            (Err(error @ LedgerError::InjectedRunPackExportInterruption(_)), Ok(())) => {
                Ok(Err(error))
            }
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(std::io::Error::from(error).into()),
        }
    }

    fn admit_locked(
        &self,
        source: &Path,
        failpoint: Option<RunPackExportStage>,
    ) -> Result<VaultAdmission, LedgerError> {
        let source_snapshot = verified_run_pack_snapshot(source)?;
        let source_content_digest = content_digest(&source_snapshot.manifest.files)?;
        let source_pack_digest = content_digest(&(
            "recursive-agent-vault-source-pack/v1",
            source_snapshot.pack_verification().manifest_digest.clone(),
            source_content_digest,
        ))?;
        if let Some(receipt) = self.admission_receipts()?.into_iter().find(|receipt| {
            receipt.source_pack_digest == source_pack_digest
                && receipt.final_manifest_digest
                    == source_snapshot.pack_verification().manifest_digest
        }) {
            let destination = self.root.join("objects").join(&receipt.object_id);
            if destination.is_dir() {
                return Ok(VaultAdmission {
                    object_id: receipt.object_id.clone(),
                    path: destination,
                    receipt,
                });
            }
            if destination.exists() {
                return Err(LedgerError::RunPackInvalid(
                    "durably admitted vault object is not a directory".into(),
                ));
            }

            // The receipt is durable provenance, not a disposable admission
            // reservation. A retry repairs the missing publication using the
            // receipt's original object identity and recorded time.
            let stage = self.root.join(format!(".stage-{}", receipt.object_id));
            copy_pack_tree(source, &stage)?;
            if let Err(error) = verify_run_pack(&stage) {
                let _ = std::fs::remove_dir_all(&stage);
                return Err(error);
            }
            let snapshot = verified_run_pack_snapshot(&stage)?;
            if snapshot.pack_verification().manifest_digest != receipt.final_manifest_digest
                || content_digest(&snapshot.manifest.files)? != receipt.final_content_digest
            {
                let _ = std::fs::remove_dir_all(&stage);
                return Err(LedgerError::RunPackInvalid(
                    "repair source no longer matches durable admission receipt".into(),
                ));
            }
            std::fs::rename(&stage, &destination)?;
            return Ok(VaultAdmission {
                object_id: receipt.object_id.clone(),
                path: destination,
                receipt,
            });
        }
        let object_id = new_vault_object_id()?;
        let relative = format!("objects/{object_id}");
        Self::validate_relative_ref(&relative)?;
        let destination = self.root.join(&relative);
        if destination.exists() {
            return Err(LedgerError::RunPackInvalid("vault object collision".into()));
        }
        let stage = self.root.join(format!(".stage-{object_id}"));
        copy_pack_tree(source, &stage)?;
        if failpoint == Some(RunPackExportStage::CopyComplete) {
            let _ = std::fs::remove_dir_all(&stage);
            return Err(LedgerError::InjectedRunPackExportInterruption(
                RunPackExportStage::CopyComplete,
            ));
        }
        if let Err(error) = verify_run_pack(&stage) {
            let _ = std::fs::remove_dir_all(&stage);
            return Err(error);
        }
        if failpoint == Some(RunPackExportStage::VerifyComplete) {
            let _ = std::fs::remove_dir_all(&stage);
            return Err(LedgerError::InjectedRunPackExportInterruption(
                RunPackExportStage::VerifyComplete,
            ));
        }
        let snapshot = verified_run_pack_snapshot(&stage)?;
        let final_content_digest = content_digest(&snapshot.manifest.files)?;
        let staged_source_pack_digest = content_digest(&(
            "recursive-agent-vault-source-pack/v1",
            snapshot.pack_verification().manifest_digest.clone(),
            final_content_digest.clone(),
        ))?;
        let recorded_at = Utc::now();
        let receipt = VaultAdmissionReceipt {
            source_pack_digest: staged_source_pack_digest,
            final_manifest_digest: snapshot.pack_verification().manifest_digest.clone(),
            final_content_digest,
            object_id: object_id.clone(),
            recorded_at,
        };
        self.persist_admission_receipt(&receipt)?;
        if failpoint == Some(RunPackExportStage::ReceiptPersisted) {
            let _ = std::fs::remove_dir_all(&stage);
            return Err(LedgerError::InjectedRunPackExportInterruption(
                RunPackExportStage::ReceiptPersisted,
            ));
        }
        std::fs::rename(&stage, &destination)?;
        if failpoint == Some(RunPackExportStage::Published) {
            return Err(LedgerError::InjectedRunPackExportInterruption(
                RunPackExportStage::Published,
            ));
        }
        Ok(VaultAdmission {
            object_id,
            path: destination,
            receipt,
        })
    }
    pub fn admission(&self, object_id: &str) -> Result<VaultAdmission, LedgerError> {
        let receipt = self.admission_receipt(object_id)?;
        let path = self.root.join("objects").join(object_id);
        if !path.is_dir() {
            return Err(LedgerError::ArtifactMissing(object_id.into()));
        }
        let snapshot = verified_run_pack_snapshot(&path)?;
        if snapshot.pack_verification().manifest_digest != receipt.final_manifest_digest
            || content_digest(&snapshot.manifest.files)? != receipt.final_content_digest
        {
            return Err(LedgerError::RunPackInvalid(
                "vault object no longer matches admission receipt".into(),
            ));
        }
        Ok(VaultAdmission {
            object_id: object_id.into(),
            path,
            receipt,
        })
    }

    pub fn get(&self, object_id: &str) -> Result<PathBuf, LedgerError> {
        Ok(self.admission(object_id)?.path)
    }
    pub fn verify(&self, object_id: &str) -> Result<VerifiedRunPackSnapshot, LedgerError> {
        verified_run_pack_snapshot(&self.admission(object_id)?.path)
    }
    pub fn quarantine(&self, object_id: &str) -> Result<PathBuf, LedgerError> {
        let _receipt = self.admission_receipt(object_id)?;
        let source = self.root.join("objects").join(object_id);
        if !source.is_dir() {
            return Err(LedgerError::ArtifactMissing(object_id.into()));
        }
        let destination = self.root.join("quarantine").join(object_id);
        std::fs::rename(source, &destination)?;
        Ok(destination)
    }
    pub fn object_ids(&self) -> Result<Vec<String>, LedgerError> {
        Ok(std::fs::read_dir(self.root.join("objects"))?
            .filter_map(Result::ok)
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect())
    }
}

fn new_vault_object_id() -> Result<String, LedgerError> {
    let mut entropy = [0_u8; 32];
    getrandom::fill(&mut entropy).map_err(|error| {
        LedgerError::RunPackInvalid(format!("vault entropy unavailable: {error}"))
    })?;
    Ok(format!("vault-{}", hex::encode(entropy)))
}

fn copy_pack_tree(source: &Path, destination: &Path) -> Result<(), LedgerError> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            copy_pack_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), target)?;
        } else {
            return Err(LedgerError::RunPackInvalid(
                "pack contains non-regular entry".into(),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("contract error: {0}")]
    Contract(#[from] ContractError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("chain divergence at receipt {index}: {reason}")]
    ChainDivergence { index: usize, reason: String },
    #[error("receipt log has an ambiguous trailing record")]
    AmbiguousTrailingRecord,
    #[error("receipt log line {index} is not canonical JCS")]
    NonCanonicalReceipt { index: usize },
    #[error("duplicate authoritative receipt id at index {index}: {receipt_id}")]
    DuplicateReceipt { index: usize, receipt_id: String },
    #[error("chain metadata is missing")]
    MetadataMissing,
    #[error("chain metadata mismatch: {0}")]
    MetadataMismatch(String),
    #[error("verified run does not match expected run: expected {expected}, observed {observed}")]
    ExpectedRunMismatch { expected: String, observed: String },
    #[error("run directory identity does not bind verified run {observed}")]
    DirectoryRunMismatch { observed: String },
    #[error("artifact {0} not found")]
    ArtifactMissing(String),
    #[error("artifact {artifact_id} is corrupted: {reason}")]
    ArtifactCorrupted { artifact_id: String, reason: String },
    #[error("artifact {artifact_id} exceeds maximum size {maximum}: {observed}")]
    ArtifactTooLarge {
        artifact_id: String,
        observed: u64,
        maximum: u64,
    },
    #[error("injected append interruption after {0:?}")]
    InjectedInterruption(AppendStage),
    #[error("injected run pack export interruption after {0:?}")]
    InjectedRunPackExportInterruption(RunPackExportStage),
    #[error("child link verification failed: {0}")]
    ChildLinkInvalid(String),
    #[error("run pack is invalid: {0}")]
    RunPackInvalid(String),
}

#[derive(Debug, Clone)]
pub struct RunPackPlan {
    pub source_run_id: CurrentRunId,
    pub files: Vec<RunPackFileEntryV1>,
    generated_files: BTreeMap<String, Vec<u8>>,
}

impl RunPackPlan {
    pub fn manifest(&self) -> RunPackManifestV1 {
        RunPackManifestV1 {
            schema_version: RunPackManifestV1::SCHEMA_VERSION,
            source_run_id: self.source_run_id.clone(),
            files: self.files.clone(),
        }
    }
}

/// Durable cross-chain binding emitted by a live parent before child dispatch.
/// This type is owned by the ledger so verification never depends on a scheduler
/// projection or an adapter return value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildRunLinkV1 {
    pub parent_run_id: CurrentRunId,
    pub parent_receipt_id: recursive_agent_contracts::CurrentReceiptId,
    pub parent_control_permit_id: recursive_agent_contracts::CurrentPermitId,
    pub child_run_id: CurrentRunId,
    pub child_control_permit_id: recursive_agent_contracts::CurrentPermitId,
    pub root_operation_id: CurrentRunId,
    pub reserved_budget: recursive_agent_contracts::OperationBudgetV1,
    pub child_envelope_digest: ContentDigest,
    pub child_terminal_receipt_id: Option<recursive_agent_contracts::CurrentReceiptId>,
    pub child_terminal_state: Option<RunTerminalStateV1>,
    pub child_chain_head: Option<String>,
    pub cancelled: bool,
}

#[derive(Debug, Clone)]
pub struct RunPaths {
    pub root: PathBuf,
}

impl RunPaths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn receipts_path(&self) -> PathBuf {
        self.root.join("receipts.ndjson")
    }

    pub fn chain_meta_path(&self) -> PathBuf {
        self.root.join("chain.meta")
    }

    pub fn artifacts_dir(&self) -> PathBuf {
        self.root.join("artifacts")
    }

    pub fn ensure(&self) -> Result<(), LedgerError> {
        let root = open_directory_tree(&self.root, true)?;
        let _artifacts = open_child_directory(&root, "artifacts", true)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRootIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainMeta {
    pub genesis: String,
    pub head: String,
    pub length: u64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMode {
    StrictCurrent,
    LegacyIntegrityOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendStage {
    ArtifactWrite,
    PartialRecord,
    FullReceiptAppend,
    LogFsync,
    MetadataTempWrite,
    MetadataFsync,
    MetadataRename,
    DirectoryFsync,
}

/// Deterministic interruption points for testing transactional Run Pack export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunPackExportStage {
    /// Every planned source entry has been copied and re-digested, but the
    /// manifest has not yet been written or published.
    CopyComplete,
    VerifyComplete,
    ReceiptPersisted,
    Published,
}

fn genesis_digest() -> ContentDigest {
    ContentDigest::compute(GENESIS_SEED)
}

pub fn chain_digest_from_raw(
    predecessor: &ContentDigest,
    canonical_receipt: &[u8],
) -> Result<ContentDigest, LedgerError> {
    let predecessor_bytes = hex::decode(predecessor.hex()).map_err(|error| {
        ContractError::Malformed(format!("predecessor digest is not hexadecimal: {error}"))
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&predecessor_bytes);
    hasher.update(canonical_receipt);
    ContentDigest::from_hex(hasher.finalize().to_hex().to_string())
        .map_err(|error| ContractError::Malformed(format!("chain digest: {error}")))
        .map_err(LedgerError::Contract)
}

#[derive(Debug)]
struct LogScan {
    head: ContentDigest,
    length: u64,
    receipt_ids: BTreeSet<String>,
    receipts: Vec<ReceiptV1>,
}

fn empty_scan() -> LogScan {
    LogScan {
        head: genesis_digest(),
        length: 0,
        receipt_ids: BTreeSet::new(),
        receipts: Vec::new(),
    }
}

fn recover_and_scan(root: &File) -> Result<LogScan, LedgerError> {
    let fd = match secure_open_at(
        root,
        "receipts.ndjson",
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(empty_scan()),
        Err(error) => return Err(error.into()),
    };
    let mut file = File::from(fd);
    if !file.metadata()?.is_file() {
        return Err(LedgerError::MetadataMismatch(
            "receipt log must be a regular file".into(),
        ));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_RECEIPT_LOG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECEIPT_LOG_BYTES {
        return Err(LedgerError::MetadataMismatch(
            "receipt log exceeds the explicit verification bound".into(),
        ));
    }
    if bytes.is_empty() {
        return Ok(empty_scan());
    }
    if bytes.last() != Some(&b'\n') {
        recover_tail(&mut file, &mut bytes)?;
    }
    scan_complete_bytes(&bytes)
}

fn recover_tail(file: &mut File, bytes: &mut Vec<u8>) -> Result<(), LedgerError> {
    let tail_start = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    let tail = &bytes[tail_start..];
    match serde_json::from_slice::<ReceiptV1>(tail) {
        Ok(receipt) => {
            let canonical = receipt.canonical_bytes()?;
            if canonical != tail {
                return Err(LedgerError::AmbiguousTrailingRecord);
            }
            file.seek(SeekFrom::End(0))?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            bytes.push(b'\n');
        }
        Err(error) if error.is_eof() => {
            let durable_len =
                u64::try_from(tail_start).map_err(|_| LedgerError::AmbiguousTrailingRecord)?;
            file.set_len(durable_len)?;
            file.sync_all()?;
            bytes.truncate(tail_start);
        }
        Err(_) => return Err(LedgerError::AmbiguousTrailingRecord),
    }
    Ok(())
}

fn scan_complete_bytes(bytes: &[u8]) -> Result<LogScan, LedgerError> {
    let mut scan = empty_scan();
    if bytes.is_empty() {
        return Ok(scan);
    }
    if bytes.last() != Some(&b'\n') {
        return Err(LedgerError::AmbiguousTrailingRecord);
    }
    for (index, raw_line) in bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        if raw_line.is_empty() {
            return Err(LedgerError::ChainDivergence {
                index,
                reason: "empty receipt record".into(),
            });
        }
        let receipt: ReceiptV1 =
            serde_json::from_slice(raw_line).map_err(|error| LedgerError::ChainDivergence {
                index,
                reason: format!("malformed receipt JSON: {error}"),
            })?;
        let canonical = receipt.canonical_bytes()?;
        if canonical != raw_line {
            return Err(LedgerError::NonCanonicalReceipt { index });
        }
        if !scan.receipt_ids.insert(receipt.receipt_id.to_string()) {
            return Err(LedgerError::DuplicateReceipt {
                index,
                receipt_id: receipt.receipt_id.to_string(),
            });
        }
        if receipt.prev_chain_digest != scan.head {
            return Err(LedgerError::ChainDivergence {
                index,
                reason: "predecessor chain digest mismatch".into(),
            });
        }
        scan.head = chain_digest_from_raw(&scan.head, &canonical)?;
        scan.length += 1;
        scan.receipts.push(receipt);
    }
    validate_receipt_sequence(&scan.receipts, LifecycleValidationMode::AppendInProgress)?;
    Ok(scan)
}

fn with_exclusive_lock<T>(
    root: &File,
    operation: impl FnOnce(&File) -> Result<T, LedgerError>,
) -> Result<T, LedgerError> {
    if !root.metadata()?.is_dir() {
        return Err(LedgerError::MetadataMismatch(
            "pinned ledger serialization capability must be a directory".into(),
        ));
    }
    rustix::fs::flock(root.as_fd(), FlockOperation::LockExclusive).map_err(std::io::Error::from)?;
    let result = operation(root);
    let unlock = rustix::fs::flock(root.as_fd(), FlockOperation::Unlock);
    match (result, unlock) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(LedgerError::Io(error.into())),
    }
}

pub fn open(paths: &RunPaths) -> Result<ChainHandle, LedgerError> {
    let root_handle = open_directory_tree(&paths.root, true)?;
    open_from_dir_fd(paths, &root_handle)
}

pub fn open_from_dir_fd(paths: &RunPaths, root: &File) -> Result<ChainHandle, LedgerError> {
    let root_identity = run_root_identity(root)?;
    let root_handle = Arc::new(root.try_clone()?);
    let _artifacts = open_child_directory(&root_handle, "artifacts", true)?;
    with_exclusive_lock(&root_handle, |root| {
        let (scan, created_at) = reconcile_locked(root)?;
        Ok(ChainHandle {
            paths: paths.clone(),
            root: Arc::clone(&root_handle),
            head: scan.head,
            length: scan.length,
            created_at,
            receipt_ids: scan.receipt_ids,
            root_identity,
        })
    })
}

fn existing_creation_time(root: &File) -> Option<DateTime<Utc>> {
    read_bounded_regular_at(root, "chain.meta", MAX_CHAIN_META_BYTES)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<ChainMeta>(&bytes).ok())
        .map(|meta| meta.created_at)
}

fn reconcile_locked(root: &File) -> Result<(LogScan, DateTime<Utc>), LedgerError> {
    let scan = recover_and_scan(root)?;
    validate_authoritative_sequence(
        root,
        &scan.receipts,
        LifecycleValidationMode::AppendInProgress,
    )?;
    let created_at = existing_creation_time(root).unwrap_or_else(Utc::now);
    let expected = metadata_for(&scan, created_at);
    let current = read_bounded_regular_at(root, "chain.meta", MAX_CHAIN_META_BYTES)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<ChainMeta>(&bytes).ok());
    if current.as_ref() != Some(&expected) {
        write_metadata_atomic(root, &expected, None)?;
    }
    Ok((scan, created_at))
}

fn metadata_for(scan: &LogScan, created_at: DateTime<Utc>) -> ChainMeta {
    ChainMeta {
        genesis: genesis_digest().to_string(),
        head: scan.head.to_string(),
        length: scan.length,
        created_at,
    }
}

fn write_metadata_atomic(
    root: &File,
    meta: &ChainMeta,
    interrupt_after: Option<AppendStage>,
) -> Result<(), LedgerError> {
    let bytes = recursive_agent_contracts::jcs_canonical(meta)?;
    let (temp_name, mut file) = create_unique_temp(root, ".chain.meta.tmp")?;
    file.write_all(&bytes)?;
    if interrupt_after == Some(AppendStage::MetadataTempWrite) {
        return Err(LedgerError::InjectedInterruption(
            AppendStage::MetadataTempWrite,
        ));
    }
    file.sync_all()?;
    if interrupt_after == Some(AppendStage::MetadataFsync) {
        return Err(LedgerError::InjectedInterruption(
            AppendStage::MetadataFsync,
        ));
    }
    rustix::fs::renameat(root.as_fd(), &temp_name, root.as_fd(), "chain.meta")
        .map_err(std::io::Error::from)?;
    if interrupt_after == Some(AppendStage::MetadataRename) {
        return Err(LedgerError::InjectedInterruption(
            AppendStage::MetadataRename,
        ));
    }
    root.sync_all()?;
    if interrupt_after == Some(AppendStage::DirectoryFsync) {
        return Err(LedgerError::InjectedInterruption(
            AppendStage::DirectoryFsync,
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub struct ChainHandle {
    paths: RunPaths,
    root: Arc<File>,
    head: ContentDigest,
    length: u64,
    created_at: DateTime<Utc>,
    receipt_ids: BTreeSet<String>,
    root_identity: RunRootIdentity,
}

impl ChainHandle {
    pub fn paths(&self) -> &RunPaths {
        &self.paths
    }

    pub fn head(&self) -> &ContentDigest {
        &self.head
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn run_root_identity(&self) -> RunRootIdentity {
        self.root_identity
    }

    pub fn artifact_store(&self) -> Result<ArtifactStore, LedgerError> {
        ArtifactStore::from_run_root_fd(&self.root, true)
    }

    pub fn append(&mut self, receipt: ReceiptV1) -> Result<ContentDigest, LedgerError> {
        self.append_with_interruption(receipt, None)
    }

    pub fn append_with_interruption(
        &mut self,
        receipt: ReceiptV1,
        interrupt_after: Option<AppendStage>,
    ) -> Result<ContentDigest, LedgerError> {
        let result = with_exclusive_lock(&self.root, |root| {
            let (mut scan, _) = reconcile_locked(root)?;
            validate_append(&scan, &receipt)?;
            let mut proposed = scan.receipts.clone();
            proposed.push(receipt.clone());
            validate_authoritative_sequence(
                root,
                &proposed,
                LifecycleValidationMode::AppendInProgress,
            )?;
            let canonical = receipt.canonical_bytes()?;
            let mut line = canonical.clone();
            line.push(b'\n');
            let log_fd = secure_open_at(
                root,
                "receipts.ndjson",
                OFlags::WRONLY
                    | OFlags::CREATE
                    | OFlags::APPEND
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                Mode::RUSR | Mode::WUSR,
            )?;
            let mut log = File::from(log_fd);
            if !log.metadata()?.is_file() {
                return Err(LedgerError::MetadataMismatch(
                    "receipt log must be a regular file".into(),
                ));
            }
            if interrupt_after == Some(AppendStage::PartialRecord) {
                let split = line.len() / 2;
                log.write_all(&line[..split])?;
                log.sync_all()?;
                return Err(LedgerError::InjectedInterruption(
                    AppendStage::PartialRecord,
                ));
            }
            log.write_all(&line)?;
            if interrupt_after == Some(AppendStage::FullReceiptAppend) {
                return Err(LedgerError::InjectedInterruption(
                    AppendStage::FullReceiptAppend,
                ));
            }
            log.sync_all()?;
            if interrupt_after == Some(AppendStage::LogFsync) {
                return Err(LedgerError::InjectedInterruption(AppendStage::LogFsync));
            }
            scan.head = chain_digest_from_raw(&scan.head, &canonical)?;
            scan.length += 1;
            scan.receipt_ids.insert(receipt.receipt_id.to_string());
            scan.receipts.push(receipt);
            write_metadata_atomic(root, &metadata_for(&scan, self.created_at), interrupt_after)?;
            Ok(scan)
        });
        match result {
            Ok(scan) => {
                self.head = scan.head.clone();
                self.length = scan.length;
                self.receipt_ids = scan.receipt_ids;
                Ok(scan.head)
            }
            Err(error) => Err(error),
        }
    }
}

fn validate_append(scan: &LogScan, receipt: &ReceiptV1) -> Result<(), LedgerError> {
    if receipt.prev_chain_digest != scan.head {
        return Err(LedgerError::ChainDivergence {
            index: scan.receipts.len(),
            reason: "append predecessor does not match locked current head".into(),
        });
    }
    if scan.receipt_ids.contains(receipt.receipt_id.as_str()) {
        return Err(LedgerError::DuplicateReceipt {
            index: scan.receipts.len(),
            receipt_id: receipt.receipt_id.to_string(),
        });
    }
    receipt.validate_material()?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ChainVerification {
    pub ok: bool,
    pub current_strict_success: bool,
    pub length: u64,
    pub final_head: String,
    pub verified_artifacts: u64,
    pub terminal_state: RunTerminalStateV1,
    pub verified_run_id: Option<CurrentRunId>,
    pub first_divergence: Option<ChainDivergence>,
}

#[derive(Debug, Clone)]
pub struct ChainDivergence {
    pub index: usize,
    pub reason: String,
    pub expected_head: String,
    pub observed_head: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedReceiptSnapshot {
    verification: ChainVerification,
    receipts: Arc<[ReceiptV1]>,
}

/// A read-only receipt projection admitted only after strict Run Pack
/// verification from the pack's own filesystem bytes. It deliberately holds
/// no source-run path, runtime service, or artifact-store handle.
#[derive(Debug, Clone)]
pub struct VerifiedRunPackSnapshot {
    pack_verification: PackVerificationResultV1,
    manifest: RunPackManifestV1,
    receipt_snapshot: VerifiedReceiptSnapshot,
}

/// Read a verified but not-yet-terminal parent transcript. This is the only
/// snapshot admitted while a live parent is still appending child lifecycle
/// receipts; it applies the same canonical, artifact, permit, and run-binding
/// checks as strict verification except for the final `RunFinalized` receipt.
pub fn appendable_snapshot_expected_run_from_dir_fd(
    root: &File,
    expected_run_id: &CurrentRunId,
) -> Result<VerifiedReceiptSnapshot, LedgerError> {
    with_exclusive_lock(root, |root| {
        let (scan, _) = reconcile_locked(root)?;
        let (lifecycle, verified_artifacts) = validate_authoritative_sequence(
            root,
            &scan.receipts,
            LifecycleValidationMode::AppendInProgress,
        )?;
        if lifecycle.run_id.as_ref() != Some(expected_run_id) {
            return Err(LedgerError::ExpectedRunMismatch {
                expected: expected_run_id.to_string(),
                observed: lifecycle
                    .run_id
                    .as_ref()
                    .map_or_else(|| "none".into(), ToString::to_string),
            });
        }
        Ok(VerifiedReceiptSnapshot {
            verification: ChainVerification {
                ok: true,
                current_strict_success: false,
                length: scan.length,
                final_head: scan.head.to_string(),
                verified_artifacts,
                terminal_state: lifecycle
                    .terminal_state
                    .unwrap_or(RunTerminalStateV1::LegacyUnknown),
                verified_run_id: lifecycle.run_id,
                first_divergence: None,
            },
            receipts: Arc::from(scan.receipts),
        })
    })
}

#[derive(Debug, Clone)]
pub struct LegacyIntegrityInspection {
    pub length: u64,
    pub final_head: String,
}

impl VerifiedReceiptSnapshot {
    pub fn verification(&self) -> &ChainVerification {
        &self.verification
    }

    pub fn receipts(&self) -> &[ReceiptV1] {
        &self.receipts
    }
}

impl VerifiedRunPackSnapshot {
    pub fn pack_verification(&self) -> &PackVerificationResultV1 {
        &self.pack_verification
    }

    pub fn verification(&self) -> &ChainVerification {
        self.receipt_snapshot.verification()
    }

    pub fn receipts(&self) -> &[ReceiptV1] {
        self.receipt_snapshot.receipts()
    }

    fn build_evidence_projection_from_metadata(
        &self,
        verification: RunPackVerificationV1,
        vault: RunPackVaultRefV1,
        origin: RunPackProjectionOriginV1,
    ) -> Result<RunPackEvidenceProjectionV1, LedgerError> {
        if !self.pack_verification.ok || !self.verification().current_strict_success {
            return Err(LedgerError::RunPackInvalid(
                "projection requires strict verified pack".into(),
            ));
        }
        let run_id = self.verification().verified_run_id.clone().ok_or_else(|| {
            LedgerError::RunPackInvalid("verified pack lacks source run identity".into())
        })?;
        let receipt_chain_digest = ContentDigest::from_hex(self.verification().final_head.clone())
            .map_err(|error| ContractError::Malformed(format!("chain digest: {error}")))?;
        let mut artifact_digests = self
            .receipts()
            .iter()
            .flat_map(|receipt| {
                receipt
                    .artifact_refs
                    .iter()
                    .map(|artifact| artifact.digest.clone())
            })
            .collect::<Vec<_>>();
        artifact_digests.sort();
        artifact_digests.dedup();
        let mut projection = RunPackEvidenceProjectionV1 {
            schema: RunPackEvidenceProjectionV1::SCHEMA.into(),
            projection_id: ContentDigest::compute(b"pending"),
            run_id,
            pack_manifest_digest: self.pack_verification.manifest_digest.clone(),
            pack_content_digest: content_digest(&self.manifest.files)?,
            verification,
            vault,
            origin,
            event_summary: RunPackEventSummaryV1 {
                terminal_state: self.verification().terminal_state,
                receipt_chain_digest,
                artifact_digests,
            },
        };
        projection.projection_id = projection.derived_projection_id()?;
        projection.validate()?;
        Ok(projection)
    }
}

/// Strictly validate the child-link set associated with a parent snapshot.
pub fn verify_child_links(
    parent: &VerifiedReceiptSnapshot,
    links: &[ChildRunLinkV1],
) -> Result<(), LedgerError> {
    let parent_id = parent
        .verification
        .verified_run_id
        .as_ref()
        .ok_or_else(|| LedgerError::ChildLinkInvalid("parent run is unverified".into()))?;
    let mut seen = BTreeSet::new();
    for link in links {
        if !seen.insert(link.child_run_id.to_string()) {
            return Err(LedgerError::ChildLinkInvalid(format!(
                "duplicate child {}",
                link.child_run_id
            )));
        }
        if link.parent_run_id != *parent_id {
            return Err(LedgerError::ChildLinkInvalid("parent run mismatch".into()));
        }
        if !parent
            .receipts
            .iter()
            .any(|r| r.receipt_id == link.parent_receipt_id && r.run_id == link.parent_run_id)
        {
            return Err(LedgerError::ChildLinkInvalid(format!(
                "missing parent admission receipt {}",
                link.parent_receipt_id
            )));
        }
        if !link.cancelled
            && (link.child_terminal_receipt_id.is_none()
                || link.child_terminal_state.is_none()
                || link.child_chain_head.is_none())
        {
            return Err(LedgerError::ChildLinkInvalid(
                "child link lacks verified terminal closure".into(),
            ));
        }
    }
    Ok(())
}

/// Strictly validate every durable child admission/link/closure tuple in a
/// parent snapshot. The parent remains appendable until finalization, so the
/// caller chooses whether each prepared child must already have a closure.
/// Child terminal evidence is always read from the canonical sibling run
/// directory, never accepted from an adapter return value.
pub fn verify_child_links_in_runtime_root(
    parent: &VerifiedReceiptSnapshot,
    parent_store: &ArtifactStore,
    output_root: &Path,
    require_closure: bool,
) -> Result<(), LedgerError> {
    let parent_id = parent
        .verification
        .verified_run_id
        .as_ref()
        .ok_or_else(|| LedgerError::ChildLinkInvalid("parent run is unverified".into()))?;
    let mut prepared = BTreeMap::new();
    let mut linked = BTreeMap::new();
    let mut closed = BTreeMap::new();
    let mut child_runs = BTreeSet::new();

    for receipt in parent.receipts() {
        let proposal = receipt.args_digest.to_string();
        match receipt.kind {
            ReceiptKindV1::ChildAdmissionPrepared => {
                if prepared
                    .insert(proposal, receipt.receipt_id.clone())
                    .is_some()
                {
                    return Err(LedgerError::ChildLinkInvalid(
                        "duplicate child admission preparation".into(),
                    ));
                }
            }
            ReceiptKindV1::ChildLinked => {
                let link = child_link_from_receipt(parent_store, receipt)?;
                validate_admission_link(parent_id, receipt, &prepared, &link, false)?;
                if !child_runs.insert(link.child_run_id.to_string()) {
                    return Err(LedgerError::ChildLinkInvalid(format!(
                        "duplicate child run {}",
                        link.child_run_id
                    )));
                }
                if linked.insert(proposal, link).is_some() {
                    return Err(LedgerError::ChildLinkInvalid("duplicate child link".into()));
                }
            }
            ReceiptKindV1::ChildClosed => {
                let link = child_link_from_receipt(parent_store, receipt)?;
                validate_admission_link(parent_id, receipt, &prepared, &link, true)?;
                if closed.insert(proposal, link).is_some() {
                    return Err(LedgerError::ChildLinkInvalid(
                        "duplicate child closure".into(),
                    ));
                }
            }
            _ => {}
        }
    }

    for (proposal, admission_receipt_id) in &prepared {
        let link = linked.get(proposal).ok_or_else(|| {
            LedgerError::ChildLinkInvalid(format!(
                "prepared child {} has no immutable link",
                admission_receipt_id
            ))
        })?;
        let closure = closed.get(proposal);
        if require_closure && closure.is_none() {
            return Err(LedgerError::ChildLinkInvalid(format!(
                "prepared child {} lacks a terminal closure",
                admission_receipt_id
            )));
        }
        let Some(closure) = closure else {
            continue;
        };
        if !same_child_link_admission(link, closure) {
            return Err(LedgerError::ChildLinkInvalid(
                "child closure changes immutable link material".into(),
            ));
        }
        let terminal_receipt_id = closure.child_terminal_receipt_id.as_ref().ok_or_else(|| {
            LedgerError::ChildLinkInvalid("child closure omits terminal receipt".into())
        })?;
        let terminal_state = closure.child_terminal_state.ok_or_else(|| {
            LedgerError::ChildLinkInvalid("child closure omits terminal state".into())
        })?;
        let chain_head = closure.child_chain_head.as_ref().ok_or_else(|| {
            LedgerError::ChildLinkInvalid("child closure omits chain head".into())
        })?;
        let child_paths =
            RunPaths::new(output_root.join(content_digest(&link.child_run_id)?.to_string()));
        let child = verified_snapshot_directory_bound(&child_paths)?;
        let child_verification = child.verification();
        let child_terminal = child
            .receipts()
            .last()
            .ok_or_else(|| LedgerError::ChildLinkInvalid("child transcript is empty".into()))?;
        if child_terminal.kind != ReceiptKindV1::RunFinalized
            || child_terminal.receipt_id != *terminal_receipt_id
            || child_verification.terminal_state != terminal_state
            || child_verification.final_head != *chain_head
        {
            return Err(LedgerError::ChildLinkInvalid(
                "child terminal evidence does not match closure".into(),
            ));
        }
    }
    if require_closure && (prepared.len() != linked.len() || prepared.len() != closed.len()) {
        return Err(LedgerError::ChildLinkInvalid(
            "parent child lifecycle is incomplete".into(),
        ));
    }
    Ok(())
}

fn child_link_from_receipt(
    store: &ArtifactStore,
    receipt: &ReceiptV1,
) -> Result<ChildRunLinkV1, LedgerError> {
    if receipt.artifact_refs.len() != 1 {
        return Err(LedgerError::ChildLinkInvalid(
            "child link receipt requires exactly one artifact".into(),
        ));
    }
    let descriptor = receipt
        .artifact_refs
        .first()
        .ok_or_else(|| LedgerError::ChildLinkInvalid("child link artifact is absent".into()))?;
    serde_json::from_slice(&store.get(descriptor)?).map_err(|error| {
        LedgerError::ChildLinkInvalid(format!("child link artifact is malformed: {error}"))
    })
}

fn validate_admission_link(
    parent_id: &CurrentRunId,
    receipt: &ReceiptV1,
    prepared: &BTreeMap<String, recursive_agent_contracts::CurrentReceiptId>,
    link: &ChildRunLinkV1,
    closure: bool,
) -> Result<(), LedgerError> {
    let proposal = receipt.args_digest.to_string();
    let admission = prepared.get(&proposal).ok_or_else(|| {
        LedgerError::ChildLinkInvalid("child link has no prepared proposal".into())
    })?;
    if link.parent_run_id != *parent_id
        || link.parent_receipt_id != *admission
        || link.root_operation_id != *parent_id
        || link.child_run_id == *parent_id
        || (closure
            && (link.child_terminal_receipt_id.is_none()
                || link.child_terminal_state.is_none()
                || link.child_chain_head.is_none()))
        || (!closure
            && (link.child_terminal_receipt_id.is_some()
                || link.child_terminal_state.is_some()
                || link.child_chain_head.is_some()))
    {
        return Err(LedgerError::ChildLinkInvalid(
            "child link does not bind its parent admission".into(),
        ));
    }
    Ok(())
}

fn same_child_link_admission(left: &ChildRunLinkV1, right: &ChildRunLinkV1) -> bool {
    left.parent_run_id == right.parent_run_id
        && left.parent_receipt_id == right.parent_receipt_id
        && left.parent_control_permit_id == right.parent_control_permit_id
        && left.child_run_id == right.child_run_id
        && left.child_control_permit_id == right.child_control_permit_id
        && left.root_operation_id == right.root_operation_id
        && left.reserved_budget == right.reserved_budget
        && left.child_envelope_digest == right.child_envelope_digest
        && left.cancelled == right.cancelled
}

pub fn verify_expected_run(
    paths: &RunPaths,
    expected_run_id: &CurrentRunId,
) -> Result<ChainVerification, LedgerError> {
    let root = open_directory_tree(&paths.root, false)?;
    verify_expected_run_from_dir_fd(&root, expected_run_id)
}

pub fn verify_expected_run_from_dir_fd(
    root: &File,
    expected_run_id: &CurrentRunId,
) -> Result<ChainVerification, LedgerError> {
    let verification = verify_from_dir_fd(root, VerificationMode::StrictCurrent)?;
    if verification.verified_run_id.as_ref() != Some(expected_run_id) {
        return Err(LedgerError::ExpectedRunMismatch {
            expected: expected_run_id.to_string(),
            observed: verification
                .verified_run_id
                .as_ref()
                .map_or_else(|| "none".into(), ToString::to_string),
        });
    }
    Ok(verification)
}

pub fn verify_directory_bound(paths: &RunPaths) -> Result<ChainVerification, LedgerError> {
    let root = open_directory_tree(&paths.root, false)?;
    let verification = verify_from_dir_fd(&root, VerificationMode::StrictCurrent)?;
    let verified_run_id =
        verification
            .verified_run_id
            .as_ref()
            .ok_or_else(|| LedgerError::DirectoryRunMismatch {
                observed: "none".into(),
            })?;
    let expected_name = content_digest(verified_run_id)?.to_string();
    let observed_name = paths.root.file_name().and_then(std::ffi::OsStr::to_str);
    if observed_name != Some(expected_name.as_str()) {
        return Err(LedgerError::DirectoryRunMismatch {
            observed: verified_run_id.to_string(),
        });
    }
    Ok(verification)
}

pub fn verified_snapshot_directory_bound(
    paths: &RunPaths,
) -> Result<VerifiedReceiptSnapshot, LedgerError> {
    let root = open_directory_tree(&paths.root, false)?;
    with_exclusive_lock(&root, |root| {
        let (scan, _) = reconcile_locked(root)?;
        let verification = verify_scan_locked(root, &scan, VerificationMode::StrictCurrent)?;
        validate_directory_binding(paths, &verification)?;
        Ok(VerifiedReceiptSnapshot {
            verification,
            receipts: Arc::from(scan.receipts),
        })
    })
}

fn pack_entry(path: &str, role: &str, bytes: &[u8]) -> RunPackFileEntryV1 {
    RunPackFileEntryV1 {
        path: path.into(),
        role: role.into(),
        byte_length: bytes.len() as u64,
        digest: ContentDigest::compute(bytes),
    }
}

fn scan_existing_read_only(root: &File) -> Result<LogScan, LedgerError> {
    let bytes = read_bounded_regular_at(root, "receipts.ndjson", MAX_RECEIPT_LOG_BYTES)?;
    scan_complete_bytes(&bytes)
}

fn validate_chain_metadata_read_only(root: &File, scan: &LogScan) -> Result<(), LedgerError> {
    let bytes =
        read_bounded_regular_at(root, "chain.meta", MAX_CHAIN_META_BYTES).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                LedgerError::MetadataMissing
            } else {
                LedgerError::Io(error)
            }
        })?;
    let metadata: ChainMeta = serde_json::from_slice(&bytes)?;
    if recursive_agent_contracts::jcs_canonical(&metadata)? != bytes {
        return Err(LedgerError::MetadataMismatch(
            "chain metadata is not canonical JCS".into(),
        ));
    }
    if metadata != metadata_for(scan, metadata.created_at) {
        return Err(LedgerError::MetadataMismatch(
            "chain metadata does not bind the receipt chain".into(),
        ));
    }
    Ok(())
}

fn strict_pack_snapshot(
    root: &File,
    paths: &RunPaths,
) -> Result<VerifiedReceiptSnapshot, LedgerError> {
    let scan = scan_existing_read_only(root)?;
    validate_chain_metadata_read_only(root, &scan)?;
    let verification = verify_scan_locked(root, &scan, VerificationMode::StrictCurrent)?;
    validate_directory_binding(paths, &verification)?;
    Ok(VerifiedReceiptSnapshot {
        verification,
        receipts: Arc::from(scan.receipts),
    })
}

fn pack_plan_from_snapshot(
    root: &File,
    snapshot: &VerifiedReceiptSnapshot,
    store: &ArtifactStore,
) -> Result<RunPackPlan, LedgerError> {
    let receipts = read_bounded_regular_at(root, "receipts.ndjson", MAX_RECEIPT_LOG_BYTES)?;
    let meta = read_bounded_regular_at(root, "chain.meta", MAX_RECEIPT_LOG_BYTES)?;
    let mut files = vec![
        pack_entry("receipts.ndjson", "receipts", &receipts),
        pack_entry("chain.meta", "chain-meta", &meta),
    ];
    let mut descriptors = BTreeMap::<String, ArtifactDescriptorV1>::new();
    for receipt in snapshot.receipts() {
        for descriptor in &receipt.artifact_refs {
            let name = artifact_name(descriptor)?;
            if let Some(previous) = descriptors.insert(name.clone(), descriptor.clone()) {
                if previous != *descriptor {
                    return Err(LedgerError::RunPackInvalid(format!(
                        "conflicting artifact descriptor {name}"
                    )));
                }
            }
        }
    }
    for (name, descriptor) in descriptors {
        store.verify_descriptor(&descriptor)?;
        let bytes = store.get(&descriptor)?;
        files.push(pack_entry(&format!("artifacts/{name}"), "artifact", &bytes));
        let metadata =
            read_bounded_regular_at(&store.dir, &format!("{name}.meta"), MAX_ARTIFACT_META_BYTES)?;
        files.push(pack_entry(
            &format!("artifacts/{name}.meta"),
            "artifact-descriptor",
            &metadata,
        ));
    }
    let source_run_id = snapshot
        .verification()
        .verified_run_id
        .clone()
        .ok_or_else(|| LedgerError::RunPackInvalid("missing run identity".into()))?;
    let generated_files = generated_provenance_files(&source_run_id, snapshot)?;
    for (path, bytes) in &generated_files {
        let role = match path.as_str() {
            "OPERATOR_REPORT.json" => "operator-report",
            "SOURCE_PROVENANCE.json" => "source-provenance",
            "TOOLCHAIN.json" => "toolchain",
            _ => {
                return Err(LedgerError::RunPackInvalid(
                    "unknown generated pack file".into(),
                ))
            }
        };
        files.push(pack_entry(path, role, bytes));
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(RunPackPlan {
        source_run_id,
        files,
        generated_files,
    })
}

fn generated_provenance_files(
    source_run_id: &CurrentRunId,
    snapshot: &VerifiedReceiptSnapshot,
) -> Result<BTreeMap<String, Vec<u8>>, LedgerError> {
    let verification = snapshot.verification();
    let terminal_classification = serde_json::to_value(verification.terminal_state)?;
    let mut files = BTreeMap::new();
    files.insert(
        "SOURCE_PROVENANCE.json".into(),
        recursive_agent_contracts::jcs_canonical(&serde_json::json!({
            "schema_version": 1,
            "source_run_id": source_run_id,
            "source_verification_outcome": "verified",
            "source_verification_ref": "chain.meta",
            "source_commit": "unknown",
            "source_diff_state": "unknown",
            "rust_version": "unknown",
            "cargo_version": "unknown",
            "command_argv": [],
            "timestamp_classification": "unknown"
        }))?,
    );
    files.insert(
        "TOOLCHAIN.json".into(),
        recursive_agent_contracts::jcs_canonical(&serde_json::json!({
            "schema_version": 1,
            "rust_version": "unknown",
            "cargo_version": "unknown",
            "command_argv": [],
            "timestamp_classification": "unknown"
        }))?,
    );
    files.insert(
        "OPERATOR_REPORT.json".into(),
        recursive_agent_contracts::jcs_canonical(&serde_json::json!({
            "schema_version": 1,
            "source_run_id": source_run_id,
            "source_verification_outcome": "verified",
            "source_verification_ref": "chain.meta",
            "terminal_classification": terminal_classification,
            "descriptive_only": true
        }))?,
    );
    Ok(files)
}

pub fn plan_run_pack(paths: &RunPaths) -> Result<RunPackPlan, LedgerError> {
    let root = open_directory_tree(&paths.root, false)?;
    with_exclusive_lock(&root, |root| {
        let snapshot = strict_pack_snapshot(root, paths)?;
        let store = ArtifactStore::from_run_root_fd(root, false)?;
        pack_plan_from_snapshot(root, &snapshot, &store)
    })
}

fn validate_pack_path(path: &str) -> Result<Vec<&str>, LedgerError> {
    if path.is_empty() || path.contains('\\') || path.contains(':') || Path::new(path).is_absolute()
    {
        return Err(LedgerError::RunPackInvalid(format!("unsafe path {path}")));
    }
    let p: Vec<_> = path.split('/').collect();
    if p.iter().any(|x| x.is_empty() || *x == "." || *x == "..") {
        return Err(LedgerError::RunPackInvalid(format!("unsafe path {path}")));
    }
    Ok(p)
}
fn read_pack_entry(root: &File, e: &RunPackFileEntryV1) -> Result<Vec<u8>, LedgerError> {
    let p = validate_pack_path(&e.path)?;
    let mut d = root.try_clone()?;
    for x in &p[..p.len() - 1] {
        d = open_child_directory(&d, x, false)?;
    }
    let b = read_bounded_regular_at(&d, p[p.len() - 1], MAX_RECEIPT_LOG_BYTES)?;
    if b.len() as u64 != e.byte_length || ContentDigest::compute(&b) != e.digest {
        return Err(LedgerError::RunPackInvalid(format!(
            "digest mismatch {}",
            e.path
        )));
    }
    Ok(b)
}

fn validate_pack_entry_role(entry: &RunPackFileEntryV1) -> Result<(), LedgerError> {
    let expected_role = match entry.path.as_str() {
        "receipts.ndjson" => "receipts",
        "chain.meta" => "chain-meta",
        "OPERATOR_REPORT.json" => "operator-report",
        "SOURCE_PROVENANCE.json" => "source-provenance",
        "TOOLCHAIN.json" => "toolchain",
        _ => {
            let name = entry.path.strip_prefix("artifacts/").ok_or_else(|| {
                LedgerError::RunPackInvalid(format!("unexpected pack path {}", entry.path))
            })?;
            if name.contains('/') {
                return Err(LedgerError::RunPackInvalid(format!(
                    "artifact path is not a single file {}",
                    entry.path
                )));
            }
            let (digest, role) = if let Some(digest) = name.strip_suffix(".meta") {
                (digest, "artifact-descriptor")
            } else {
                (name, "artifact")
            };
            if digest.len() != 64
                || !digest.chars().all(|character| {
                    character.is_ascii_hexdigit() && !character.is_ascii_uppercase()
                })
            {
                return Err(LedgerError::RunPackInvalid(format!(
                    "artifact path does not contain a content digest {}",
                    entry.path
                )));
            }
            role
        }
    };
    if entry.role != expected_role {
        return Err(LedgerError::RunPackInvalid(format!(
            "role does not match path {}",
            entry.path
        )));
    }
    Ok(())
}

fn collect_pack_entries(
    d: &File,
    pre: &str,
    out: &mut BTreeSet<String>,
) -> Result<(), LedgerError> {
    for i in std::fs::read_dir(format!("/proc/self/fd/{}", d.as_raw_fd()))? {
        let i = i?;
        let n = i
            .file_name()
            .to_str()
            .ok_or_else(|| LedgerError::RunPackInvalid("non-UTF8 name".into()))?
            .to_owned();
        if n == "PACK_MANIFEST.json" && pre.is_empty() {
            continue;
        }
        let r = if pre.is_empty() {
            n.clone()
        } else {
            format!("{pre}/{n}")
        };
        let t = i.file_type()?;
        if t.is_symlink() {
            return Err(LedgerError::RunPackInvalid(format!("symlink {r}")));
        }
        if t.is_dir() {
            let c = open_child_directory(d, &n, false)?;
            collect_pack_entries(&c, &r, out)?;
        } else if t.is_file() {
            out.insert(r);
        } else {
            return Err(LedgerError::RunPackInvalid(format!(
                "non-regular entry {r}"
            )));
        }
    }
    Ok(())
}

fn verified_run_pack_snapshot_from_dir_fd(
    root: &File,
) -> Result<VerifiedRunPackSnapshot, LedgerError> {
    let mb = read_bounded_regular_at(root, "PACK_MANIFEST.json", MAX_RECEIPT_LOG_BYTES)?;
    let m: RunPackManifestV1 = serde_json::from_slice(&mb)?;
    m.validate()?;
    if recursive_agent_contracts::jcs_canonical(&m)? != mb {
        return Err(LedgerError::RunPackInvalid(
            "manifest is not canonical JCS".into(),
        ));
    }
    let mut expected = BTreeSet::new();
    let mut has_receipts = false;
    let mut has_chain_meta = false;
    for entry in &m.files {
        validate_pack_entry_role(entry)?;
        if !expected.insert(entry.path.clone()) {
            return Err(LedgerError::RunPackInvalid("duplicate path".into()));
        }
        has_receipts |= entry.path == "receipts.ndjson";
        has_chain_meta |= entry.path == "chain.meta";
        read_pack_entry(root, entry)?;
    }
    if !has_receipts || !has_chain_meta {
        return Err(LedgerError::RunPackInvalid(
            "manifest omits canonical receipt evidence".into(),
        ));
    }
    let mut actual = BTreeSet::new();
    collect_pack_entries(root, "", &mut actual)?;
    if actual != expected {
        return Err(LedgerError::RunPackInvalid("missing or extra files".into()));
    }
    let scan = scan_existing_read_only(root)?;
    validate_chain_metadata_read_only(root, &scan)?;
    let verification = verify_scan_locked(root, &scan, VerificationMode::StrictCurrent)?;
    if verification.verified_run_id.as_ref() != Some(&m.source_run_id) {
        return Err(LedgerError::RunPackInvalid(
            "manifest source run identity mismatch".into(),
        ));
    }
    Ok(VerifiedRunPackSnapshot {
        pack_verification: PackVerificationResultV1 {
            schema_version: RunPackManifestV1::SCHEMA_VERSION,
            ok: true,
            manifest_digest: ContentDigest::compute(&mb),
        },
        manifest: m,
        receipt_snapshot: VerifiedReceiptSnapshot {
            verification,
            receipts: Arc::from(scan.receipts),
        },
    })
}

fn verify_run_pack_from_dir_fd(root: &File) -> Result<PackVerificationResultV1, LedgerError> {
    Ok(verified_run_pack_snapshot_from_dir_fd(root)?
        .pack_verification
        .clone())
}

pub fn verify_run_pack(root: &Path) -> Result<PackVerificationResultV1, LedgerError> {
    let rf = open_directory_tree(root, false)?;
    with_exclusive_lock(&rf, verify_run_pack_from_dir_fd)
}

/// Verify a Run Pack from its own bytes and expose only the resulting
/// verified receipt evidence for recorded replay projections.
pub fn verified_run_pack_snapshot(root: &Path) -> Result<VerifiedRunPackSnapshot, LedgerError> {
    let root = open_directory_tree(root, false)?;
    with_exclusive_lock(&root, verified_run_pack_snapshot_from_dir_fd)
}

fn write_new_pack_file(root: &File, path: &str, bytes: &[u8]) -> Result<(), LedgerError> {
    let components = validate_pack_path(path)?;
    let (leaf, parents) = components
        .split_last()
        .ok_or_else(|| LedgerError::RunPackInvalid("empty pack path".into()))?;
    let mut directory = root.try_clone()?;
    for parent in parents {
        directory = open_child_directory(&directory, parent, true)?;
    }
    let fd = secure_open_at(
        &directory,
        leaf,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?;
    let mut file = File::from(fd);
    file.write_all(bytes)?;
    file.sync_all()?;
    directory.sync_all()?;
    Ok(())
}

fn create_unique_pack_directory(parent: &File) -> Result<(String, File), LedgerError> {
    for _ in 0..1024 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!(".run-pack.{}.{}", std::process::id(), sequence);
        match rustix::fs::mkdirat(parent.as_fd(), &name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) => return Ok((name.clone(), open_child_directory(parent, &name, false)?)),
            Err(error)
                if std::io::Error::from(error).kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(std::io::Error::from(error).into()),
        }
    }
    Err(LedgerError::RunPackInvalid(
        "unable to allocate a destination temporary directory".into(),
    ))
}

fn remove_directory_contents(directory: &File) -> Result<(), LedgerError> {
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| LedgerError::RunPackInvalid("non-UTF8 temporary entry".into()))?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            let child = open_child_directory(directory, name, false)?;
            remove_directory_contents(&child)?;
            rustix::fs::unlinkat(directory.as_fd(), name, AtFlags::REMOVEDIR)
                .map_err(std::io::Error::from)?;
        } else {
            rustix::fs::unlinkat(directory.as_fd(), name, AtFlags::empty())
                .map_err(std::io::Error::from)?;
        }
    }
    directory.sync_all()?;
    Ok(())
}

fn remove_temp_pack_directory(parent: &File, name: &str) -> Result<(), LedgerError> {
    let directory = open_child_directory(parent, name, false)?;
    remove_directory_contents(&directory)?;
    rustix::fs::unlinkat(parent.as_fd(), name, AtFlags::REMOVEDIR).map_err(std::io::Error::from)?;
    parent.sync_all()?;
    Ok(())
}

struct TempPackGuard {
    parent: File,
    name: Option<String>,
}

impl TempPackGuard {
    fn new(parent: &File, name: String) -> Result<Self, LedgerError> {
        Ok(Self {
            parent: parent.try_clone()?,
            name: Some(name),
        })
    }

    fn disarm(&mut self) {
        self.name = None;
    }
}

impl Drop for TempPackGuard {
    fn drop(&mut self) {
        if let Some(name) = self.name.take() {
            let _ = remove_temp_pack_directory(&self.parent, &name);
        }
    }
}

fn destination_parent_and_name(destination: &Path) -> Result<(File, String), LedgerError> {
    let parent_path = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| LedgerError::RunPackInvalid("destination has no parent".into()))?;
    let name = destination
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .ok_or_else(|| LedgerError::RunPackInvalid("destination has an unsafe name".into()))?
        .to_owned();
    Ok((open_directory_tree(parent_path, false)?, name))
}

fn ensure_destination_absent(parent: &File, name: &str) -> Result<(), LedgerError> {
    match secure_open_at(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(_) => Err(LedgerError::RunPackInvalid(
            "destination already exists".into(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LedgerError::RunPackInvalid(format!(
            "destination is existing or unsafe: {error}"
        ))),
    }
}

pub fn export_run_pack(
    paths: &RunPaths,
    destination: &Path,
) -> Result<PackVerificationResultV1, LedgerError> {
    export_run_pack_with_interruption(paths, destination, None)
}

/// Export a pack with an optional deterministic interruption point. The
/// interruption surface proves that incomplete packs are cleaned up before
/// publication.
pub fn export_run_pack_with_interruption(
    paths: &RunPaths,
    destination: &Path,
    interrupt_after: Option<RunPackExportStage>,
) -> Result<PackVerificationResultV1, LedgerError> {
    let (parent, destination_name) = destination_parent_and_name(destination)?;
    ensure_destination_absent(&parent, &destination_name)?;
    let (temporary_name, temporary_root) = create_unique_pack_directory(&parent)?;
    let mut guard = TempPackGuard::new(&parent, temporary_name.clone())?;
    let source_root = open_directory_tree(&paths.root, false)?;
    let result = with_exclusive_lock(&source_root, |source_root| {
        let snapshot = strict_pack_snapshot(source_root, paths)?;
        let store = ArtifactStore::from_run_root_fd(source_root, false)?;
        let plan = pack_plan_from_snapshot(source_root, &snapshot, &store)?;
        for entry in &plan.files {
            let bytes = match plan.generated_files.get(&entry.path) {
                Some(bytes) => bytes.clone(),
                None => read_pack_entry(source_root, entry)?,
            };
            write_new_pack_file(&temporary_root, &entry.path, &bytes)?;
            if read_pack_entry(&temporary_root, entry)? != bytes {
                return Err(LedgerError::RunPackInvalid(format!(
                    "copied bytes changed while exporting {}",
                    entry.path
                )));
            }
        }
        if interrupt_after == Some(RunPackExportStage::CopyComplete) {
            return Err(LedgerError::InjectedRunPackExportInterruption(
                RunPackExportStage::CopyComplete,
            ));
        }
        let manifest = plan.manifest();
        let manifest_bytes = manifest.canonical_bytes()?;
        write_new_pack_file(&temporary_root, "PACK_MANIFEST.json", &manifest_bytes)?;
        if read_bounded_regular_at(&temporary_root, "PACK_MANIFEST.json", MAX_RECEIPT_LOG_BYTES)?
            != manifest_bytes
        {
            return Err(LedgerError::RunPackInvalid(
                "pack manifest changed while exporting".into(),
            ));
        }
        temporary_root.sync_all()?;
        with_exclusive_lock(&temporary_root, verify_run_pack_from_dir_fd)
    })?;
    parent.sync_all()?;
    rustix::fs::renameat_with(
        parent.as_fd(),
        &temporary_name,
        parent.as_fd(),
        &destination_name,
        RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)?;
    parent.sync_all()?;
    guard.disarm();
    Ok(result)
}

/// Open one strictly verified directory-bound snapshot and its artifact store
/// from the same pinned run-root descriptor. Consumers that must interpret
/// receipt-referenced artifacts after verification use this rather than
/// reopening the path and creating a verification-to-artifact TOCTOU window.
pub fn verified_snapshot_with_artifact_store_directory_bound(
    paths: &RunPaths,
) -> Result<(VerifiedReceiptSnapshot, ArtifactStore), LedgerError> {
    let root = open_directory_tree(&paths.root, false)?;
    with_exclusive_lock(&root, |root| {
        let (scan, _) = reconcile_locked(root)?;
        let verification = verify_scan_locked(root, &scan, VerificationMode::StrictCurrent)?;
        validate_directory_binding(paths, &verification)?;
        let store = ArtifactStore::from_run_root_fd(root, false)?;
        Ok((
            VerifiedReceiptSnapshot {
                verification,
                receipts: Arc::from(scan.receipts),
            },
            store,
        ))
    })
}

/// Read a causally ordered event slice projected only from reconciled,
/// authoritative receipt bytes that have passed lifecycle, artifact, permit,
/// and run-directory validation under the ledger lock.
pub fn committed_events_directory_bound(
    paths: &RunPaths,
    after: Option<u64>,
) -> Result<Vec<RuntimeEventV1>, LedgerError> {
    let root = open_directory_tree(&paths.root, false)?;
    with_exclusive_lock(&root, |root| {
        let (scan, _) = reconcile_locked(root)?;
        let (lifecycle, _) = validate_authoritative_sequence(
            root,
            &scan.receipts,
            LifecycleValidationMode::AppendInProgress,
        )?;
        let run_id =
            lifecycle
                .run_id
                .as_ref()
                .ok_or_else(|| LedgerError::DirectoryRunMismatch {
                    observed: "none".into(),
                })?;
        validate_run_directory_binding(paths, run_id)?;
        let events = project_runtime_events(&scan.receipts)?;
        Ok(events
            .into_iter()
            .filter(|event| match after {
                Some(cursor) => event.sequence > cursor,
                None => true,
            })
            .collect())
    })
}

pub fn verified_snapshot_expected_run_from_dir_fd(
    root: &File,
    expected_run_id: &CurrentRunId,
) -> Result<VerifiedReceiptSnapshot, LedgerError> {
    with_exclusive_lock(root, |root| {
        let (scan, _) = reconcile_locked(root)?;
        let verification = verify_scan_locked(root, &scan, VerificationMode::StrictCurrent)?;
        if verification.verified_run_id.as_ref() != Some(expected_run_id) {
            return Err(LedgerError::ExpectedRunMismatch {
                expected: expected_run_id.to_string(),
                observed: verification
                    .verified_run_id
                    .as_ref()
                    .map_or_else(|| "none".into(), ToString::to_string),
            });
        }
        Ok(VerifiedReceiptSnapshot {
            verification,
            receipts: Arc::from(scan.receipts),
        })
    })
}

fn validate_directory_binding(
    paths: &RunPaths,
    verification: &ChainVerification,
) -> Result<(), LedgerError> {
    let verified_run_id =
        verification
            .verified_run_id
            .as_ref()
            .ok_or_else(|| LedgerError::DirectoryRunMismatch {
                observed: "none".into(),
            })?;
    validate_run_directory_binding(paths, verified_run_id)
}

fn validate_run_directory_binding(
    paths: &RunPaths,
    verified_run_id: &CurrentRunId,
) -> Result<(), LedgerError> {
    let expected_name = content_digest(verified_run_id)?.to_string();
    let observed_name = paths.root.file_name().and_then(std::ffi::OsStr::to_str);
    if observed_name != Some(expected_name.as_str()) {
        return Err(LedgerError::DirectoryRunMismatch {
            observed: verified_run_id.to_string(),
        });
    }
    Ok(())
}

pub fn inspect_legacy_integrity(
    paths: &RunPaths,
) -> Result<LegacyIntegrityInspection, LedgerError> {
    let verification = verify_with_mode_private(paths, VerificationMode::LegacyIntegrityOnly)?;
    Ok(LegacyIntegrityInspection {
        length: verification.length,
        final_head: verification.final_head,
    })
}

fn verify_with_mode_private(
    paths: &RunPaths,
    mode: VerificationMode,
) -> Result<ChainVerification, LedgerError> {
    let root = open_directory_tree(&paths.root, false)?;
    verify_from_dir_fd(&root, mode)
}

fn verify_from_dir_fd(
    root: &File,
    mode: VerificationMode,
) -> Result<ChainVerification, LedgerError> {
    with_exclusive_lock(root, |root| {
        let (scan, _) = reconcile_locked(root)?;
        verify_scan_locked(root, &scan, mode)
    })
}

fn verify_scan_locked(
    root: &File,
    scan: &LogScan,
    mode: VerificationMode,
) -> Result<ChainVerification, LedgerError> {
    let lifecycle_mode = match mode {
        VerificationMode::StrictCurrent => LifecycleValidationMode::StrictCurrent,
        VerificationMode::LegacyIntegrityOnly => LifecycleValidationMode::LegacyIntegrityOnly,
    };
    let (lifecycle, verified_artifacts) =
        validate_authoritative_sequence(root, &scan.receipts, lifecycle_mode)?;
    let verified_run_id = lifecycle.run_id;
    let terminal_state = lifecycle
        .terminal_state
        .unwrap_or(RunTerminalStateV1::LegacyUnknown);
    Ok(ChainVerification {
        ok: true,
        current_strict_success: matches!(mode, VerificationMode::StrictCurrent),
        length: scan.length,
        final_head: scan.head.to_string(),
        verified_artifacts,
        terminal_state,
        verified_run_id,
        first_divergence: None,
    })
}

fn validate_authoritative_sequence(
    root: &File,
    receipts: &[ReceiptV1],
    mode: LifecycleValidationMode,
) -> Result<(recursive_agent_contracts::LifecycleValidation, u64), LedgerError> {
    let lifecycle = validate_receipt_sequence(receipts, mode)?;
    let store = ArtifactStore::open_existing_from_root(root)?;
    let mut verified = BTreeSet::new();
    for receipt in receipts {
        for descriptor in &receipt.artifact_refs {
            if verified.insert(descriptor.owner_id.to_string()) {
                store.verify_descriptor(descriptor)?;
            }
        }
    }
    if !matches!(mode, LifecycleValidationMode::LegacyIntegrityOnly) {
        validate_permit_continuity(receipts, &store)?;
    }
    Ok((lifecycle, verified.len() as u64))
}

fn validate_permit_continuity(
    receipts: &[ReceiptV1],
    store: &ArtifactStore,
) -> Result<(), LedgerError> {
    use recursive_agent_policy::{PermitEvidenceStateV1, PermitEvidenceV1, PermitPurposeV1};

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ObservedPermitState {
        Issued,
        Consumed,
        Rejected,
        Revoked,
    }

    struct RetainedPermit {
        permit_id: recursive_agent_contracts::CurrentPermitId,
        binding_digest: ContentDigest,
        purpose: PermitPurposeV1,
        issued_at: DateTime<Utc>,
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        state: ObservedPermitState,
        evidence: PermitEvidenceV1,
    }

    let mut retained = std::collections::BTreeMap::<CurrentStepId, RetainedPermit>::new();
    let mut controls = std::collections::BTreeMap::<
        recursive_agent_contracts::CurrentPermitId,
        PermitEvidenceV1,
    >::new();
    let mut control_states = std::collections::BTreeMap::<
        recursive_agent_contracts::CurrentPermitId,
        PermitEvidenceStateV1,
    >::new();
    let mut computed_allocations = std::collections::BTreeMap::<
        recursive_agent_contracts::CurrentPermitId,
        std::collections::BTreeMap<
            recursive_agent_contracts::CurrentPermitId,
            recursive_agent_policy::PermitBudgetV1,
        >,
    >::new();

    for (index, receipt) in receipts.iter().enumerate() {
        if matches!(
            receipt.kind,
            ReceiptKindV1::ArtifactStored | ReceiptKindV1::StepCompleted
        ) {
            let permit = retained.get(&receipt.step_id).ok_or_else(|| {
                permit_divergence(index, "observed effect has no retained permit transition")
            })?;
            if permit.purpose != PermitPurposeV1::Effect
                || permit.state != ObservedPermitState::Consumed
            {
                return Err(permit_divergence(
                    index,
                    "observed effect requires one consumed effect permit",
                ));
            }
            let parent_id = permit
                .evidence
                .binding
                .parent_permit_id
                .as_ref()
                .ok_or_else(|| permit_divergence(index, "effect omits control parent"))?;
            let parent = controls.get(parent_id).ok_or_else(|| {
                permit_divergence(index, "effect control parent evidence is absent")
            })?;
            if !matches!(
                control_states.get(parent_id),
                Some(PermitEvidenceStateV1::Issued)
            ) || receipt.valid_time < parent.binding.not_before
                || receipt.valid_time >= parent.binding.expires_at
            {
                return Err(permit_divergence(
                    index,
                    "parent expiry or revocation dominates observed effect success",
                ));
            }
        }
        if matches!(receipt.kind, ReceiptKindV1::RunFinalized)
            && matches!(receipt.outcome, ReceiptOutcomeV1::Ok)
            && retained.values().any(|permit| {
                permit.purpose == PermitPurposeV1::Effect
                    && permit.state != ObservedPermitState::Consumed
            })
        {
            return Err(permit_divergence(
                index,
                "successful finalization contradicts a rejected or revoked effect permit",
            ));
        }
        if matches!(receipt.kind, ReceiptKindV1::RunFinalized)
            && matches!(receipt.outcome, ReceiptOutcomeV1::Ok)
            && control_states.values().any(|state| {
                !matches!(
                    state,
                    PermitEvidenceStateV1::Revoked {
                        reason: recursive_agent_policy::PermitRevocationReasonV1::Operator,
                        ..
                    }
                )
            })
        {
            return Err(permit_divergence(
                index,
                "successful finalization requires orderly control closure",
            ));
        }
        let expected_state = match receipt.kind {
            ReceiptKindV1::PermitIssued => "issued",
            ReceiptKindV1::PermitConsumed => "consumed",
            ReceiptKindV1::PermitRejected => "rejected",
            ReceiptKindV1::PermitRevoked => "revoked",
            _ => continue,
        };
        if receipt.artifact_refs.len() != 1 {
            return Err(permit_divergence(
                index,
                &format!("{expected_state} permit event requires exactly one evidence artifact"),
            ));
        }
        let descriptor = receipt
            .artifact_refs
            .first()
            .ok_or_else(|| permit_divergence(index, "permit evidence artifact is missing"))?;
        let bytes = store.get(descriptor)?;
        let evidence: PermitEvidenceV1 = serde_json::from_slice(&bytes).map_err(|error| {
            permit_divergence(index, &format!("permit evidence is malformed: {error}"))
        })?;
        evidence.validate().map_err(|error| {
            permit_divergence(
                index,
                &format!("permit evidence validation failed: {error}"),
            )
        })?;
        let state_matches = matches!(
            (&receipt.kind, &evidence.state),
            (ReceiptKindV1::PermitIssued, PermitEvidenceStateV1::Issued)
                | (
                    ReceiptKindV1::PermitConsumed,
                    PermitEvidenceStateV1::Consumed { .. }
                )
                | (
                    ReceiptKindV1::PermitRejected,
                    PermitEvidenceStateV1::Rejected { .. }
                )
                | (
                    ReceiptKindV1::PermitRevoked,
                    PermitEvidenceStateV1::Revoked { .. }
                )
        );
        let state_time = match &evidence.state {
            PermitEvidenceStateV1::Issued => evidence.binding.issued_at,
            PermitEvidenceStateV1::Consumed { at }
            | PermitEvidenceStateV1::Rejected { at, .. }
            | PermitEvidenceStateV1::Revoked { at, .. } => *at,
        };
        let lineage_matches = receipt
            .lineage
            .iter()
            .filter_map(|entry| entry.permit_id.as_ref())
            .all(|permit_id| permit_id == &evidence.permit_id);
        if !state_matches
            || state_time != receipt.valid_time
            || evidence.binding.run_id != receipt.run_id
            || evidence.binding.step_id != receipt.step_id
            || evidence.binding.action_digest != receipt.spec_digest
            || evidence.binding.args_digest != receipt.args_digest
            || !lineage_matches
        {
            return Err(permit_divergence(
                index,
                "permit evidence does not bind its receipt and neighboring lifecycle",
            ));
        }

        match receipt.kind {
            ReceiptKindV1::PermitIssued => {
                if retained.contains_key(&receipt.step_id) {
                    return Err(permit_divergence(
                        index,
                        "PermitIssued duplicates a retained step permit",
                    ));
                }
                if evidence.purpose == PermitPurposeV1::Control {
                    if controls
                        .insert(evidence.permit_id.clone(), evidence.clone())
                        .is_some()
                    {
                        return Err(permit_divergence(index, "duplicate control permit"));
                    }
                    control_states
                        .insert(evidence.permit_id.clone(), PermitEvidenceStateV1::Issued);
                } else {
                    let parent_id =
                        evidence.binding.parent_permit_id.as_ref().ok_or_else(|| {
                            permit_divergence(index, "effect permit omits its control parent")
                        })?;
                    let parent = controls.get(parent_id).ok_or_else(|| {
                        permit_divergence(index, "effect permit parent evidence is absent")
                    })?;
                    recursive_agent_policy::validate_delegation_evidence(
                        parent,
                        &evidence,
                        evidence.binding.issued_at,
                    )
                    .map_err(|error| {
                        permit_divergence(
                            index,
                            &format!("effect permit widens its control parent: {error}"),
                        )
                    })?;
                    let allocations = computed_allocations.entry(parent_id.clone()).or_default();
                    if allocations
                        .insert(evidence.permit_id.clone(), evidence.binding.budget.clone())
                        .is_some()
                    {
                        return Err(permit_divergence(index, "duplicate child allocation"));
                    }
                    let mut wall = 0_u64;
                    let mut output = 0_u64;
                    let mut artifact = 0_u64;
                    for budget in allocations.values() {
                        wall = wall.checked_add(budget.max_wall_time_ms).ok_or_else(|| {
                            permit_divergence(index, "cumulative wall allocation overflow")
                        })?;
                        output = output.checked_add(budget.max_output_bytes).ok_or_else(|| {
                            permit_divergence(index, "cumulative output allocation overflow")
                        })?;
                        artifact =
                            artifact
                                .checked_add(budget.max_artifact_bytes)
                                .ok_or_else(|| {
                                    permit_divergence(
                                        index,
                                        "cumulative artifact allocation overflow",
                                    )
                                })?;
                    }
                    let ceiling = parent.delegation_ceiling.as_ref().ok_or_else(|| {
                        permit_divergence(index, "control permit lacks a delegation ceiling")
                    })?;
                    if wall > ceiling.budget.max_wall_time_ms
                        || output > ceiling.budget.max_output_bytes
                        || artifact > ceiling.budget.max_artifact_bytes
                    {
                        return Err(permit_divergence(
                            index,
                            "cumulative child allocation exceeds the control ceiling",
                        ));
                    }
                }
                retained.insert(
                    receipt.step_id.clone(),
                    RetainedPermit {
                        permit_id: evidence.permit_id.clone(),
                        binding_digest: evidence.binding_digest.clone(),
                        purpose: evidence.purpose,
                        issued_at: evidence.binding.issued_at,
                        not_before: evidence.binding.not_before,
                        expires_at: evidence.binding.expires_at,
                        state: ObservedPermitState::Issued,
                        evidence: evidence.clone(),
                    },
                );
            }
            ReceiptKindV1::PermitConsumed
            | ReceiptKindV1::PermitRejected
            | ReceiptKindV1::PermitRevoked => {
                let prior = retained.get_mut(&receipt.step_id).ok_or_else(|| {
                    permit_divergence(index, "permit terminal transition precedes issuance")
                })?;
                if prior.permit_id != evidence.permit_id
                    || prior.binding_digest != evidence.binding_digest
                    || prior.purpose != evidence.purpose
                    || prior.issued_at != evidence.binding.issued_at
                    || prior.not_before != evidence.binding.not_before
                    || prior.expires_at != evidence.binding.expires_at
                    || prior.evidence.binding != evidence.binding
                    || prior.evidence.delegation_ceiling != evidence.delegation_ceiling
                    || prior.evidence.executable_authority != evidence.executable_authority
                {
                    return Err(permit_divergence(
                        index,
                        "permit transition identity or binding changed within the step",
                    ));
                }
                if prior.state != ObservedPermitState::Issued {
                    return Err(permit_divergence(
                        index,
                        "permit transition contradicts an existing terminal state",
                    ));
                }
                prior.state = match receipt.kind {
                    ReceiptKindV1::PermitConsumed => ObservedPermitState::Consumed,
                    ReceiptKindV1::PermitRejected => ObservedPermitState::Rejected,
                    ReceiptKindV1::PermitRevoked => ObservedPermitState::Revoked,
                    _ => return Err(permit_divergence(index, "unreachable permit transition")),
                };
                if matches!(receipt.kind, ReceiptKindV1::PermitRevoked)
                    && evidence.purpose == PermitPurposeV1::Control
                {
                    let expected = match computed_allocations.get(&evidence.permit_id) {
                        Some(allocations) => allocations.clone(),
                        None => std::collections::BTreeMap::new(),
                    };
                    if evidence.child_allocations != expected {
                        return Err(permit_divergence(
                            index,
                            "control revocation does not bind exact child allocations",
                        ));
                    }
                    control_states.insert(evidence.permit_id.clone(), evidence.state.clone());
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn permit_divergence(index: usize, reason: &str) -> LedgerError {
    LedgerError::ChainDivergence {
        index,
        reason: reason.into(),
    }
}

#[derive(Debug, Clone)]
pub struct ArtifactStore {
    dir: Arc<File>,
    run_root_identity: RunRootIdentity,
    artifact_root_identity: RunRootIdentity,
}

impl ArtifactStore {
    pub fn from_run_root_fd(root: &File, create: bool) -> Result<Self, LedgerError> {
        let pinned_root_identity = run_root_identity(root)?;
        let dir = open_child_directory(root, "artifacts", create)?;
        let artifact_root_identity = run_root_identity(&dir)?;
        Ok(Self {
            dir: Arc::new(dir),
            run_root_identity: pinned_root_identity,
            artifact_root_identity,
        })
    }

    fn open_existing_from_root(root: &File) -> Result<Self, LedgerError> {
        Self::from_run_root_fd(root, false)
    }

    pub fn run_root_identity(&self) -> RunRootIdentity {
        self.run_root_identity
    }

    pub fn artifact_root_identity(&self) -> RunRootIdentity {
        self.artifact_root_identity
    }

    pub fn put(
        &self,
        bytes: &[u8],
        media_type: impl Into<String>,
        encoding: Option<String>,
    ) -> Result<ArtifactDescriptorV1, LedgerError> {
        let byte_length =
            u64::try_from(bytes.len()).map_err(|_| LedgerError::ArtifactTooLarge {
                artifact_id: "pending".into(),
                observed: u64::MAX,
                maximum: MAX_ARTIFACT_SIZE,
            })?;
        let owner_id = derive_artifact_id(bytes)?;
        if byte_length > MAX_ARTIFACT_SIZE {
            return Err(LedgerError::ArtifactTooLarge {
                artifact_id: owner_id.to_string(),
                observed: byte_length,
                maximum: MAX_ARTIFACT_SIZE,
            });
        }
        let descriptor = ArtifactDescriptorV1 {
            owner_id,
            digest: ContentDigest::compute(bytes),
            byte_length,
            media_type: media_type.into(),
            encoding,
        };
        descriptor.validate()?;
        let name = artifact_name(&descriptor)?;
        match secure_open_at(
            &self.dir,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => {
                let mut file = File::from(fd);
                file.write_all(bytes)?;
                file.sync_all()?;
                self.dir.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = self.get(&descriptor)?;
                if existing != bytes {
                    return Err(LedgerError::ArtifactCorrupted {
                        artifact_id: descriptor.owner_id.to_string(),
                        reason: "existing content-addressed bytes differ".into(),
                    });
                }
            }
            Err(error) => return Err(LedgerError::Io(error)),
        }
        self.persist_descriptor(&descriptor)?;
        Ok(descriptor)
    }

    pub fn get(&self, descriptor: &ArtifactDescriptorV1) -> Result<Vec<u8>, LedgerError> {
        let mut file = self.open_verified(descriptor)?;
        let capacity =
            usize::try_from(descriptor.byte_length).map_err(|_| LedgerError::ArtifactTooLarge {
                artifact_id: descriptor.owner_id.to_string(),
                observed: descriptor.byte_length,
                maximum: MAX_ARTIFACT_SIZE,
            })?;
        let mut bytes = Vec::with_capacity(capacity.min(IO_BUFFER_SIZE));
        std::io::Read::by_ref(&mut file)
            .take(descriptor.byte_length.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > descriptor.byte_length {
            return Err(LedgerError::ArtifactTooLarge {
                artifact_id: descriptor.owner_id.to_string(),
                observed: bytes.len() as u64,
                maximum: descriptor.byte_length,
            });
        }
        verify_observed_bytes(descriptor, &bytes)?;
        Ok(bytes)
    }

    pub fn verify_descriptor(&self, descriptor: &ArtifactDescriptorV1) -> Result<(), LedgerError> {
        let mut file = self.open_verified(descriptor)?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0_u8; IO_BUFFER_SIZE];
        let mut observed = 0_u64;
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            observed = observed.saturating_add(read as u64);
            if observed > MAX_ARTIFACT_SIZE || observed > descriptor.byte_length {
                return Err(LedgerError::ArtifactTooLarge {
                    artifact_id: descriptor.owner_id.to_string(),
                    observed,
                    maximum: MAX_ARTIFACT_SIZE.min(descriptor.byte_length),
                });
            }
            hasher.update(&buffer[..read]);
        }
        if observed != descriptor.byte_length {
            return Err(corrupt(descriptor, "byte length mismatch"));
        }
        let observed_digest = hasher.finalize().to_hex().to_string();
        if observed_digest != descriptor.digest.hex() {
            return Err(corrupt(descriptor, "content digest mismatch"));
        }
        Ok(())
    }

    fn open_verified(&self, descriptor: &ArtifactDescriptorV1) -> Result<File, LedgerError> {
        descriptor.validate()?;
        let stored = self.read_stored_descriptor(descriptor)?;
        if stored != *descriptor {
            return Err(corrupt(descriptor, "stored descriptor metadata mismatch"));
        }
        if descriptor.byte_length > MAX_ARTIFACT_SIZE {
            return Err(LedgerError::ArtifactTooLarge {
                artifact_id: descriptor.owner_id.to_string(),
                observed: descriptor.byte_length,
                maximum: MAX_ARTIFACT_SIZE,
            });
        }
        let name = artifact_name(descriptor)?;
        let fd = secure_open_at(
            &self.dir,
            &name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                LedgerError::ArtifactMissing(descriptor.owner_id.to_string())
            } else {
                LedgerError::Io(error)
            }
        })?;
        let file = File::from(fd);
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(corrupt(
                descriptor,
                "opened descriptor is not a regular file",
            ));
        }
        if metadata.len() > MAX_ARTIFACT_SIZE {
            return Err(LedgerError::ArtifactTooLarge {
                artifact_id: descriptor.owner_id.to_string(),
                observed: metadata.len(),
                maximum: MAX_ARTIFACT_SIZE,
            });
        }
        if metadata.len() != descriptor.byte_length {
            return Err(corrupt(descriptor, "opened descriptor length mismatch"));
        }
        Ok(file)
    }

    fn persist_descriptor(&self, descriptor: &ArtifactDescriptorV1) -> Result<(), LedgerError> {
        let name = format!("{}.meta", artifact_name(descriptor)?);
        let bytes = recursive_agent_contracts::jcs_canonical(descriptor)?;
        match secure_open_at(
            &self.dir,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => {
                let mut file = File::from(fd);
                file.write_all(&bytes)?;
                file.sync_all()?;
                self.dir.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let stored = self.read_stored_descriptor(descriptor)?;
                if stored != *descriptor {
                    return Err(corrupt(descriptor, "descriptor metadata conflict"));
                }
            }
            Err(error) => return Err(LedgerError::Io(error)),
        }
        Ok(())
    }

    fn read_stored_descriptor(
        &self,
        descriptor: &ArtifactDescriptorV1,
    ) -> Result<ArtifactDescriptorV1, LedgerError> {
        let name = format!("{}.meta", artifact_name(descriptor)?);
        let fd = secure_open_at(
            &self.dir,
            &name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                LedgerError::ArtifactMissing(descriptor.owner_id.to_string())
            } else {
                LedgerError::Io(error)
            }
        })?;
        let file = File::from(fd);
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_ARTIFACT_META_BYTES {
            return Err(corrupt(
                descriptor,
                "descriptor metadata is not a bounded regular file",
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_ARTIFACT_META_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_ARTIFACT_META_BYTES {
            return Err(corrupt(
                descriptor,
                "descriptor metadata exceeds its read bound",
            ));
        }
        let stored: ArtifactDescriptorV1 = serde_json::from_slice(&bytes)
            .map_err(|_| corrupt(descriptor, "descriptor metadata is malformed"))?;
        if recursive_agent_contracts::jcs_canonical(&stored)? != bytes {
            return Err(corrupt(descriptor, "descriptor metadata is noncanonical"));
        }
        Ok(stored)
    }
}

#[cfg(target_os = "linux")]
fn secure_open_at(
    directory: &File,
    name: &str,
    flags: OFlags,
    mode: Mode,
) -> std::io::Result<std::os::fd::OwnedFd> {
    Ok(rustix::fs::openat2(
        directory.as_fd(),
        name,
        flags,
        mode,
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?)
}

#[cfg(not(target_os = "linux"))]
fn secure_open_at(
    directory: &File,
    name: &str,
    flags: OFlags,
    mode: Mode,
) -> std::io::Result<std::os::fd::OwnedFd> {
    if name.contains('/') || name == "." || name == ".." {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "artifact name is not a single component",
        ));
    }
    Ok(rustix::fs::openat(
        directory.as_fd(),
        name,
        flags | OFlags::NOFOLLOW,
        mode,
    )?)
}

fn open_directory_tree(path: &Path, create: bool) -> Result<File, LedgerError> {
    if path.as_os_str().is_empty() || path == Path::new("/") {
        return Err(LedgerError::MetadataMismatch(
            "run root must be a specific directory".into(),
        ));
    }
    let start = if path.is_absolute() { "/" } else { "." };
    let start_fd = rustix::fs::open(
        start,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let mut directory = File::from(start_fd);
    for component in path.components() {
        let name = match component {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(name) => name,
            std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                return Err(LedgerError::MetadataMismatch(
                    "run root may not contain parent or platform-prefix components".into(),
                ));
            }
        };
        directory = open_named_directory(&directory, name, create)?;
    }
    Ok(directory)
}

#[cfg(unix)]
fn run_root_identity(directory: &File) -> Result<RunRootIdentity, LedgerError> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.mode() & 0o022 != 0 {
        return Err(LedgerError::MetadataMismatch(
            "run-root directory must not be group/world writable".into(),
        ));
    }
    Ok(RunRootIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn open_child_directory(parent: &File, name: &str, create: bool) -> Result<File, LedgerError> {
    open_named_directory(parent, std::ffi::OsStr::new(name), create)
}

fn open_named_directory(
    parent: &File,
    name: &std::ffi::OsStr,
    create: bool,
) -> Result<File, LedgerError> {
    let name = name
        .to_str()
        .ok_or_else(|| LedgerError::MetadataMismatch("non-UTF-8 run root component".into()))?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match secure_open_at(parent, name, flags, Mode::empty()) {
        Ok(fd) => Ok(File::from(fd)),
        Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
            match rustix::fs::mkdirat(parent.as_fd(), name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                Ok(()) => {}
                Err(error)
                    if std::io::Error::from(error).kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
            let fd = secure_open_at(parent, name, flags, Mode::empty())?;
            Ok(File::from(fd))
        }
        Err(error) => Err(error.into()),
    }
}

fn read_bounded_regular_at(directory: &File, name: &str, maximum: u64) -> std::io::Result<Vec<u8>> {
    let fd = secure_open_at(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    let file = File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "opened file is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "opened file exceeds bound",
        ));
    }
    Ok(bytes)
}

fn create_unique_temp(root: &File, prefix: &str) -> Result<(String, File), LedgerError> {
    for _ in 0..1024 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!("{prefix}.{}.{}", std::process::id(), sequence);
        match secure_open_at(
            root,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => return Ok((name, File::from(fd))),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(LedgerError::MetadataMismatch(
        "unable to allocate collision-safe metadata temporary file".into(),
    ))
}

fn artifact_name(descriptor: &ArtifactDescriptorV1) -> Result<String, LedgerError> {
    let suffix = descriptor
        .owner_id
        .as_str()
        .strip_prefix("v1:recursive-agent/artifact/v1:det:")
        .ok_or_else(|| corrupt(descriptor, "wrong artifact owner domain"))?;
    if suffix != descriptor.digest.hex() {
        return Err(corrupt(descriptor, "artifact owner id and digest disagree"));
    }
    Ok(suffix.into())
}

fn corrupt(descriptor: &ArtifactDescriptorV1, reason: &str) -> LedgerError {
    LedgerError::ArtifactCorrupted {
        artifact_id: descriptor.owner_id.to_string(),
        reason: reason.into(),
    }
}

fn verify_observed_bytes(
    descriptor: &ArtifactDescriptorV1,
    bytes: &[u8],
) -> Result<(), LedgerError> {
    if u64::try_from(bytes.len()).ok() != Some(descriptor.byte_length) {
        return Err(corrupt(descriptor, "byte length mismatch"));
    }
    if ContentDigest::compute(bytes) != descriptor.digest {
        return Err(corrupt(descriptor, "content digest mismatch"));
    }
    if derive_artifact_id(bytes)? != descriptor.owner_id {
        return Err(corrupt(descriptor, "artifact owner mismatch"));
    }
    Ok(())
}

pub struct ReceiptDraftV1 {
    pub run_id: CurrentRunId,
    pub step_id: CurrentStepId,
    pub kind: ReceiptKindV1,
    pub valid_time: DateTime<Utc>,
    pub lineage: Vec<AuthorityLineageEntryV1>,
    pub spec_digest: ContentDigest,
    pub args_digest: ContentDigest,
    pub artifact_refs: Vec<ArtifactDescriptorV1>,
    pub outcome: ReceiptOutcomeV1,
}

pub fn make_receipt(
    draft: ReceiptDraftV1,
    predecessor: ContentDigest,
) -> Result<ReceiptV1, LedgerError> {
    recursive_agent_contracts::validate_lineage(&draft.lineage)?;
    for descriptor in &draft.artifact_refs {
        descriptor.validate()?;
    }
    let receipt_id = derive_receipt_id(&ReceiptIdentityMaterialV1 {
        run_id: &draft.run_id,
        step_id: &draft.step_id,
        kind: &draft.kind,
        lineage: &draft.lineage,
        spec_digest: &draft.spec_digest,
        args_digest: &draft.args_digest,
        outcome: &draft.outcome,
        artifact_refs: &draft.artifact_refs,
        predecessor_chain_digest: &predecessor,
    })?;
    Ok(ReceiptV1 {
        receipt_id,
        run_id: draft.run_id,
        step_id: draft.step_id,
        kind: draft.kind,
        valid_time: draft.valid_time,
        recorded_time: Utc::now(),
        lineage: draft.lineage,
        spec_digest: draft.spec_digest,
        args_digest: draft.args_digest,
        artifact_refs: draft.artifact_refs,
        outcome: draft.outcome,
        prev_chain_digest: predecessor,
    })
}

pub fn digest_of<T: serde::Serialize>(value: &T) -> Result<ContentDigest, ContractError> {
    content_digest(value)
}

pub fn canonical_of<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ContractError> {
    recursive_agent_contracts::jcs_canonical(value)
}

pub fn put_string(store: &ArtifactStore, body: &str) -> Result<ArtifactDescriptorV1, LedgerError> {
    store.put(body.as_bytes(), "application/json", Some("utf-8".into()))
}

pub fn get_string(
    store: &ArtifactStore,
    descriptor: &ArtifactDescriptorV1,
) -> Result<String, LedgerError> {
    let bytes = store.get(descriptor)?;
    String::from_utf8(bytes)
        .map_err(|error| ContractError::Malformed(format!("artifact not utf-8: {error}")).into())
}

pub fn ensure_dir(path: &Path) -> Result<(), LedgerError> {
    let _directory = open_directory_tree(path, true)?;
    Ok(())
}
