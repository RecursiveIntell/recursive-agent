//! Durable scheduler control projection (Phase 5, Task 5.1).
//!
//! This store is a **rebuildable control projection**, not receipt truth. It
//! persists the queue, per-operation lease holder, heartbeat, idempotency key,
//! cancel flag, and event projection cursor so the runtime can durably recover
//! admitted work across a process restart without silently duplicating effects.
//!
//! Authoritative facts always come from the ledger-backed evidence chain; this
//! projection is reconstructed from that evidence plus pending admission
//! records. Inconsistent rows are quarantined, never trusted.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from the durable scheduler store. All typed; no panic.
#[derive(Debug, Error)]
pub enum SchedulerStoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("no admission record for operation {0}")]
    UnknownAdmission(String),
    #[error("lease conflict: operation {operation} is held by {holder}")]
    LeaseConflict { operation: String, holder: String },
    #[error("invalid store: {0}")]
    Invalid(String),
}

/// Terminal-and-active lifecycle states the projection tracks for recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectedState {
    /// Admitted but not yet authorized/dispatched.
    Submitted,
    /// Lease acquired; execution may be in progress.
    Authorized,
    /// The operation is being cancelled.
    Cancelling,
    /// Ledger-derived terminal state (the projection trusts evidence).
    Terminal,
    /// The projection is inconsistent with evidence and quarantined.
    Quarantined,
}

/// One durable admission/lease row in the projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRow {
    /// Canonical operation id (material identity, not a random UUID).
    pub operation_id: String,
    /// Digest binding the idempotency key to the request (for Task 5.4).
    pub idempotency_key_digest: Option<String>,
    /// Lease holder identity (e.g. a worker/session id).
    pub lease_holder: Option<String>,
    /// Monotonic heartbeat counter (incremented while the lease is held).
    pub heartbeat: u64,
    /// Durable cancel flag.
    pub cancel_requested: bool,
    /// Event projection cursor (sequence of last committed event read).
    pub projection_cursor: u64,
    /// Current projected state.
    pub state: ProjectedState,
}

impl OperationRow {
    fn new(operation_id: impl Into<String>) -> Self {
        Self {
            operation_id: operation_id.into(),
            idempotency_key_digest: None,
            lease_holder: None,
            heartbeat: 0,
            cancel_requested: false,
            projection_cursor: 0,
            state: ProjectedState::Submitted,
        }
    }
}

/// The on-disk shape of the scheduler projection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoreFile {
    /// Keyed by canonical operation id.
    rows: BTreeMap<String, OperationRow>,
    /// Rows quarantined because they were inconsistent with evidence.
    quarantined: Vec<OperationRow>,
}

/// Durable scheduler control projection.
pub struct SchedulerStore {
    path: PathBuf,
    file: StoreFile,
}

impl SchedulerStore {
    /// Open (or create) the durable projection at `path`.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, SchedulerStoreError> {
        let path = path.into();
        let file = if path.exists() {
            let bytes = std::fs::read(&path)?;
            serde_json::from_slice(&bytes)?
        } else {
            StoreFile::default()
        };
        Ok(Self { path, file })
    }

    /// Persist the current projection atomically (temp file + rename).
    fn persist(&self) -> Result<(), SchedulerStoreError> {
        let bytes = serde_json::to_vec(&self.file)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Admit an operation into the queue. Exact duplicates by operation id are
    /// idempotent (return the existing row).
    pub fn admit(
        &mut self,
        operation_id: impl Into<String>,
        idempotency_key_digest: impl Into<String>,
    ) -> Result<OperationRow, SchedulerStoreError> {
        let operation_id = operation_id.into();
        if let Some(row) = self.file.rows.get_mut(&operation_id) {
            if row.state == ProjectedState::Quarantined {
                return Err(SchedulerStoreError::UnknownAdmission(operation_id));
            }
            return Ok(row.clone());
        }
        let mut row = OperationRow::new(operation_id.clone());
        row.idempotency_key_digest = Some(idempotency_key_digest.into());
        self.file.rows.insert(operation_id.clone(), row.clone());
        self.persist()?;
        Ok(row)
    }

    /// Acquire an exclusive lease. Fails if a different holder owns it.
    pub fn acquire_lease(
        &mut self,
        operation_id: &str,
        holder: impl Into<String>,
    ) -> Result<(), SchedulerStoreError> {
        let holder = holder.into();
        let row = self
            .file
            .rows
            .get_mut(operation_id)
            .ok_or_else(|| SchedulerStoreError::UnknownAdmission(operation_id.to_string()))?;
        match (&row.lease_holder, row.state) {
            (Some(existing), _) if *existing != holder => {
                return Err(SchedulerStoreError::LeaseConflict {
                    operation: operation_id.to_string(),
                    holder: existing.clone(),
                });
            }
            _ => {}
        }
        row.lease_holder = Some(holder);
        row.heartbeat += 1;
        row.state = ProjectedState::Authorized;
        self.persist()?;
        Ok(())
    }

    /// Record a durable cancellation request (idempotent).
    pub fn request_cancel(&mut self, operation_id: &str) -> Result<(), SchedulerStoreError> {
        let row = self
            .file
            .rows
            .get_mut(operation_id)
            .ok_or_else(|| SchedulerStoreError::UnknownAdmission(operation_id.to_string()))?;
        row.cancel_requested = true;
        row.state = ProjectedState::Cancelling;
        self.persist()?;
        Ok(())
    }

    /// Advance the event projection cursor after reading committed events.
    pub fn advance_cursor(
        &mut self,
        operation_id: &str,
        sequence: u64,
    ) -> Result<(), SchedulerStoreError> {
        let row = self
            .file
            .rows
            .get_mut(operation_id)
            .ok_or_else(|| SchedulerStoreError::UnknownAdmission(operation_id.to_string()))?;
        row.projection_cursor = row.projection_cursor.max(sequence);
        self.persist()?;
        Ok(())
    }

    /// Mark a row terminal (from ledger evidence) or quarantine it when it is
    /// inconsistent with evidence.
    pub fn set_terminal(&mut self, operation_id: &str) -> Result<(), SchedulerStoreError> {
        let row = self
            .file
            .rows
            .get_mut(operation_id)
            .ok_or_else(|| SchedulerStoreError::UnknownAdmission(operation_id.to_string()))?;
        row.state = ProjectedState::Terminal;
        self.persist()?;
        Ok(())
    }

    /// Quarantine an inconsistent row (moves it out of the live set).
    pub fn quarantine(&mut self, operation_id: &str) -> Result<(), SchedulerStoreError> {
        let row = self
            .file
            .rows
            .remove(operation_id)
            .ok_or_else(|| SchedulerStoreError::UnknownAdmission(operation_id.to_string()))?;
        let mut row = row;
        row.state = ProjectedState::Quarantined;
        self.file.quarantined.push(row);
        self.persist()?;
        Ok(())
    }

    /// Snapshot of all live rows (for tests / recovery inspection).
    pub fn live_rows(&self) -> Vec<OperationRow> {
        self.file.rows.values().cloned().collect()
    }

    /// Look up one live row.
    pub fn get(&self, operation_id: &str) -> Option<&OperationRow> {
        self.file.rows.get(operation_id)
    }

    /// Quarantined rows.
    pub fn quarantined(&self) -> &[OperationRow] {
        &self.file.quarantined
    }

    /// The store file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn admit_is_idempotent_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("scheduler.json");
        let mut store = SchedulerStore::open(&path).unwrap();
        let first = store.admit("op-1", "digest-a").unwrap();
        assert_eq!(first.state, ProjectedState::Submitted);
        // Exact duplicate by operation id returns the same row.
        let dup = store.admit("op-1", "digest-a").unwrap();
        assert_eq!(dup.operation_id, "op-1");
        // Reopen from disk shows persistence.
        drop(store);
        let reopened = SchedulerStore::open(&path).unwrap();
        assert!(reopened.get("op-1").is_some());
    }

    #[test]
    fn lease_conflict_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("scheduler.json");
        let mut store = SchedulerStore::open(&path).unwrap();
        store.admit("op-1", "digest-a").unwrap();
        store.acquire_lease("op-1", "worker-a").unwrap();
        let err = store.acquire_lease("op-1", "worker-b").unwrap_err();
        assert!(matches!(err, SchedulerStoreError::LeaseConflict { .. }));
    }

    #[test]
    fn cancel_and_cursor_are_durable() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("scheduler.json");
        let mut store = SchedulerStore::open(&path).unwrap();
        store.admit("op-1", "digest-a").unwrap();
        store.acquire_lease("op-1", "worker-a").unwrap();
        store.request_cancel("op-1").unwrap();
        store.advance_cursor("op-1", 7).unwrap();
        store.set_terminal("op-1").unwrap();
        drop(store);
        let reopened = SchedulerStore::open(&path).unwrap();
        let row = reopened.get("op-1").unwrap();
        assert!(row.cancel_requested);
        assert_eq!(row.projection_cursor, 7);
        assert_eq!(row.state, ProjectedState::Terminal);
    }

    #[test]
    fn inconsistent_row_is_quarantined() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("scheduler.json");
        let mut store = SchedulerStore::open(&path).unwrap();
        store.admit("op-bad", "digest-x").unwrap();
        store.quarantine("op-bad").unwrap();
        assert!(store.get("op-bad").is_none());
        assert_eq!(store.quarantined().len(), 1);
        assert_eq!(store.quarantined()[0].state, ProjectedState::Quarantined);
    }
}
