//! Locked, crash-recoverable receipt chain and descriptor-relative artifact store.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsFd;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use recursive_agent_contracts::{
    content_digest, derive_artifact_id, derive_receipt_id, project_runtime_events,
    validate_receipt_sequence, ArtifactDescriptorV1, AuthorityLineageEntryV1, ContentDigest,
    ContractError, CurrentRunId, CurrentStepId, LifecycleValidationMode, ReceiptIdentityMaterialV1,
    ReceiptKindV1, ReceiptOutcomeV1, ReceiptV1, RunTerminalStateV1, RuntimeEventV1, GENESIS_SEED,
};
use rustix::fs::{FlockOperation, Mode, OFlags, ResolveFlags};
use thiserror::Error;

pub const MAX_ARTIFACT_SIZE: u64 = 16 * 1024 * 1024;
const IO_BUFFER_SIZE: usize = 64 * 1024;
const MAX_CHAIN_META_BYTES: u64 = 16 * 1024;
const MAX_ARTIFACT_META_BYTES: u64 = 16 * 1024;
const MAX_RECEIPT_LOG_BYTES: u64 = 64 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
    #[error("child link verification failed: {0}")]
    ChildLinkInvalid(String),
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
