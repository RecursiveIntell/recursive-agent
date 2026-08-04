//! Append-only receipt chain and content-addressed artifact store.
//!
//! The chain is content-addressed: every receipt binds to its predecessor
//! by `prev_chain_digest`. The chain is provider-free and offline
//! verifiable. Anything that wants to mutate the chain must write a new
//! receipt; nothing in this crate mutates an existing receipt.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Utc;
use recursive_agent_contracts::{
    content_digest, jcs_canonical, ContentDigest, ContractError, ReceiptV1, GENESIS_SEED,
};
use thiserror::Error;

/// Errors that surface as typed rejections, not panics.
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
    #[error("artifact {0} not found")]
    ArtifactMissing(String),
}

/// On-disk state of a run.
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
        fs::create_dir_all(&self.root)?;
        fs::create_dir_all(self.artifacts_dir())?;
        Ok(())
    }
}

/// A material record of the chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainMeta {
    pub genesis: String,
    pub head: String,
    pub length: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

fn genesis_digest() -> ContentDigest {
    // The genesis is the BLAKE3 hash of GENESIS_SEED, wrapped as a raw
    // content digest. This binds the chain to the program identity.
    stack_ids::ContentDigest::compute(GENESIS_SEED)
}

/// Open a run directory. If the directory does not exist, initialize it.
pub fn open(paths: &RunPaths) -> Result<ChainHandle, LedgerError> {
    paths.ensure()?;
    if paths.chain_meta_path().exists() {
        let meta_text = fs::read_to_string(paths.chain_meta_path())?;
        let meta: ChainMeta = serde_json::from_str(&meta_text)?;
        let head = ContentDigest::from_hex(meta.head.trim_start_matches("blake3:"))
            .map_err(|e| LedgerError::Contract(ContractError::Malformed(format!("head: {e:?}"))))?;
        let length = meta.length;
        Ok(ChainHandle {
            paths: paths.clone(),
            head,
            length,
        })
    } else {
        let genesis = genesis_digest();
        let meta = ChainMeta {
            genesis: genesis.to_string(),
            head: genesis.to_string(),
            length: 0,
            created_at: Utc::now(),
        };
        fs::write(
            paths.chain_meta_path(),
            serde_json::to_string_pretty(&meta)?,
        )?;
        Ok(ChainHandle {
            paths: paths.clone(),
            head: genesis,
            length: 0,
        })
    }
}

/// A live handle to a chain.
#[derive(Debug, Clone)]
pub struct ChainHandle {
    paths: RunPaths,
    head: ContentDigest,
    length: u64,
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

    /// Append a receipt. The receipt is rewritten with the correct
    /// `prev_chain_digest`; the chain head is updated and persisted.
    pub fn append(&mut self, mut receipt: ReceiptV1) -> Result<ContentDigest, LedgerError> {
        receipt.prev_chain_digest = self.head.clone();
        let bytes = jcs_canonical(&receipt)?;
        let line = format!(
            "{}\n",
            std::str::from_utf8(&bytes).map_err(|e| {
                LedgerError::Contract(ContractError::Malformed(format!(
                    "non-utf8 canonical bytes: {e}"
                )))
            })?
        );

        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.paths.receipts_path())?;
        f.write_all(line.as_bytes())?;
        f.sync_all()?;

        // Compute new chain digest as blake3(prev.hex || canonical_bytes).
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.head.hex().as_bytes());
        hasher.update(&bytes);
        let next_hex = hasher.finalize().to_hex().to_string();
        let next = ContentDigest::from_hex(next_hex)
            .map_err(|e| LedgerError::Contract(ContractError::Malformed(format!("next: {e:?}"))))?;
        self.head = next.clone();
        self.length += 1;

        let meta = ChainMeta {
            genesis: genesis_digest().to_string(),
            head: next.to_string(),
            length: self.length,
            created_at: Utc::now(),
        };
        fs::write(
            self.paths.chain_meta_path(),
            serde_json::to_string_pretty(&meta)?,
        )?;
        Ok(next)
    }
}

/// Verification result.
#[derive(Debug, Clone)]
pub struct ChainVerification {
    pub ok: bool,
    pub length: u64,
    pub final_head: String,
    pub first_divergence: Option<ChainDivergence>,
}

#[derive(Debug, Clone)]
pub struct ChainDivergence {
    pub index: usize,
    pub reason: String,
    pub expected_head: String,
    pub observed_head: String,
}

/// Read-only verification. Walks the chain from disk and re-derives the
/// chain digest.
pub fn verify(paths: &RunPaths) -> Result<ChainVerification, LedgerError> {
    if !paths.receipts_path().exists() {
        return Ok(ChainVerification {
            ok: true,
            length: 0,
            final_head: genesis_digest().to_string(),
            first_divergence: None,
        });
    }
    let text = fs::read_to_string(paths.receipts_path())?;
    let mut head = genesis_digest();
    let mut index: usize = 0;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let receipt: ReceiptV1 = serde_json::from_str(line)?;
        if receipt.prev_chain_digest != head {
            return Ok(ChainVerification {
                ok: false,
                length: index as u64,
                final_head: head.to_string(),
                first_divergence: Some(ChainDivergence {
                    index,
                    reason: "prev_chain_digest mismatch".into(),
                    expected_head: receipt.prev_chain_digest.to_string(),
                    observed_head: head.to_string(),
                }),
            });
        }
        let bytes = jcs_canonical(&receipt)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(head.hex().as_bytes());
        hasher.update(&bytes);
        let next_hex = hasher.finalize().to_hex().to_string();
        head = ContentDigest::from_hex(next_hex)
            .map_err(|e| LedgerError::Contract(ContractError::Malformed(format!("next: {e:?}"))))?;
        index += 1;
    }
    Ok(ChainVerification {
        ok: true,
        length: index as u64,
        final_head: head.to_string(),
        first_divergence: None,
    })
}

/// A content-addressed artifact store.
#[derive(Debug, Clone)]
pub struct ArtifactStore {
    dir: PathBuf,
}

impl ArtifactStore {
    pub fn new(paths: &RunPaths) -> Result<Self, LedgerError> {
        paths.ensure()?;
        Ok(Self {
            dir: paths.artifacts_dir(),
        })
    }

    pub fn put(&self, bytes: &[u8]) -> Result<String, LedgerError> {
        let digest = blake3::hash(bytes);
        let hex_digest = digest.to_hex().to_string();
        let path = self.dir.join(&hex_digest);
        if !path.exists() {
            fs::write(&path, bytes)?;
        }
        Ok(format!("blake3:{hex_digest}"))
    }

    pub fn get(&self, artifact_id: &str) -> Result<Vec<u8>, LedgerError> {
        let hex_digest = artifact_id
            .strip_prefix("blake3:")
            .ok_or_else(|| LedgerError::ArtifactMissing(artifact_id.into()))?;
        let path = self.dir.join(hex_digest);
        if !path.exists() {
            return Err(LedgerError::ArtifactMissing(artifact_id.into()));
        }
        Ok(fs::read(&path)?)
    }

    pub fn exists(&self, artifact_id: &str) -> bool {
        match artifact_id.strip_prefix("blake3:") {
            Some(hex_digest) => self.dir.join(hex_digest).exists(),
            None => false,
        }
    }
}

/// Build a receipt from raw fields. Convenience for tests and the runner.
#[allow(clippy::too_many_arguments)]
pub fn make_receipt(
    receipt_id_str: &str,
    run_id_str: &str,
    step_id_str: &str,
    kind: recursive_agent_contracts::ReceiptKindV1,
    lineage: Vec<recursive_agent_contracts::AuthorityLineageEntryV1>,
    spec_digest: ContentDigest,
    args_digest: ContentDigest,
    artifact_refs: Vec<String>,
    outcome: recursive_agent_contracts::ReceiptOutcomeV1,
) -> Result<ReceiptV1, LedgerError> {
    recursive_agent_contracts::validate_lineage(&lineage).map_err(LedgerError::Contract)?;
    let now = Utc::now();
    Ok(ReceiptV1 {
        receipt_id: receipt_id_str.into(),
        run_id: run_id_str.into(),
        step_id: step_id_str.into(),
        kind,
        valid_time: now,
        recorded_time: now,
        lineage,
        spec_digest,
        args_digest,
        artifact_refs,
        outcome,
        prev_chain_digest: genesis_digest(),
    })
}

#[allow(dead_code)]
pub fn digest_of<T: serde::Serialize>(value: &T) -> Result<ContentDigest, ContractError> {
    content_digest(value)
}

#[allow(dead_code)]
pub fn canonical_of<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ContractError> {
    jcs_canonical(value)
}

/// Helper: write a string payload to the artifact store and return the
/// content-addressed reference.
pub fn put_string(store: &ArtifactStore, body: &str) -> Result<String, LedgerError> {
    store.put(body.as_bytes())
}

/// Helper: read a payload back through the artifact store as `String`.
pub fn get_string(store: &ArtifactStore, artifact_id: &str) -> Result<String, LedgerError> {
    let bytes = store.get(artifact_id)?;
    String::from_utf8(bytes).map_err(|e| {
        LedgerError::Contract(ContractError::Malformed(format!("artifact not utf-8: {e}")))
    })
}

/// Ensure a directory exists, creating parents as needed.
pub fn ensure_dir(p: &Path) -> Result<(), LedgerError> {
    fs::create_dir_all(p)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn genesis_is_deterministic() {
        let a = genesis_digest();
        let b = genesis_digest();
        assert_eq!(a, b);
    }

    #[test]
    fn open_initializes_chain() {
        let tmp = std::env::temp_dir().join(format!("rec-agent-test-{}", uuid::Uuid::new_v4()));
        let paths = RunPaths::new(&tmp);
        let h = open(&paths).unwrap();
        assert_eq!(h.length(), 0);
        assert_eq!(h.head(), &genesis_digest());
    }

    #[test]
    fn chain_round_trip_and_verify() {
        use recursive_agent_contracts::{
            AuthorityLineageEntryV1, LineageOrigin, ReceiptKindV1, ReceiptOutcomeV1,
        };
        let tmp = std::env::temp_dir().join(format!("rec-agent-test-{}", uuid::Uuid::new_v4()));
        let paths = RunPaths::new(&tmp);
        let mut h = open(&paths).unwrap();
        let lineage = vec![
            AuthorityLineageEntryV1 {
                origin: LineageOrigin::Request,
                principal: "ra".into(),
                permit_id: None,
                policy_version: "m0".into(),
            },
            AuthorityLineageEntryV1 {
                origin: LineageOrigin::Plan,
                principal: "ra".into(),
                permit_id: None,
                policy_version: "m0".into(),
            },
            AuthorityLineageEntryV1 {
                origin: LineageOrigin::Policy,
                principal: "ra".into(),
                permit_id: Some("pmt:x".into()),
                policy_version: "m0".into(),
            },
            AuthorityLineageEntryV1 {
                origin: LineageOrigin::Tool,
                principal: "ra".into(),
                permit_id: Some("pmt:x".into()),
                policy_version: "m0".into(),
            },
            AuthorityLineageEntryV1 {
                origin: LineageOrigin::Effect,
                principal: "ra".into(),
                permit_id: Some("pmt:x".into()),
                policy_version: "m0".into(),
            },
        ];
        let r = make_receipt(
            "rcpt:1",
            "run:r1",
            "step:s1",
            ReceiptKindV1::StepStarted,
            lineage.clone(),
            content_digest(&serde_json::json!({"spec": 1})).unwrap(),
            content_digest(&serde_json::json!({"args": 1})).unwrap(),
            vec![],
            ReceiptOutcomeV1::Ok,
        )
        .unwrap();
        h.append(r).unwrap();
        let v = verify(&paths).unwrap();
        assert!(v.ok, "verify failed: {:?}", v.first_divergence);
        assert_eq!(v.length, 1);
    }
}
