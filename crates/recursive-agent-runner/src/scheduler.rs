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

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use rustix::fs::FlockOperation;
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
    #[error("lease is fenced: operation={operation} holder={holder} generation={generation}")]
    LeaseFenced {
        operation: String,
        holder: String,
        generation: u64,
    },
    #[error("lease generation exhausted for operation {0}")]
    LeaseGenerationExhausted(String),
    #[error("lease holder must be non-empty")]
    InvalidLeaseHolder,
    #[error("scheduler recovery is required after an uncertain storage operation")]
    RecoveryRequired,
    #[error("operation or idempotency key already has a different binding")]
    IdempotencyConflict,
    #[error("operation is not eligible for a new lease")]
    IneligibleLease,
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
#[serde(deny_unknown_fields)]
pub struct OperationRow {
    /// Canonical operation id (material identity, not a random UUID).
    pub operation_id: String,
    /// Rebuildable causal-family visibility only; never authority.
    #[serde(default)]
    pub parent_operation_id: Option<String>,
    /// Rebuildable causal-family root visibility only; never authority.
    #[serde(default)]
    pub root_operation_id: Option<String>,
    /// Rebuildable child visibility projection only; never authority.
    #[serde(default)]
    pub children: Vec<String>,
    /// Digest binding the idempotency key to the request (for Task 5.4).
    pub idempotency_key_digest: Option<String>,
    /// Lease holder identity (e.g. a worker/session id).
    pub lease_holder: Option<String>,
    /// Monotonic fencing generation. A transferred generation permanently
    /// invalidates every earlier in-process grant.
    #[serde(default)]
    pub lease_generation: u64,
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
            parent_operation_id: None,
            root_operation_id: None,
            children: Vec::new(),
            idempotency_key_digest: None,
            lease_holder: None,
            lease_generation: 0,
            heartbeat: 0,
            cancel_requested: false,
            projection_cursor: 0,
            state: ProjectedState::Submitted,
        }
    }
}

/// Non-serializable in-process lease capability issued by the scheduler owner.
///
/// It is a physical scheduling fence, not policy authority or receipt truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseGrantV1 {
    operation_id: String,
    holder: String,
    generation: u64,
}

impl LeaseGrantV1 {
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn holder(&self) -> &str {
        &self.holder
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// The on-disk shape of the scheduler projection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    lock: File,
    gate: Mutex<()>,
    uncertain: AtomicBool,
}

const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;

impl SchedulerStore {
    /// Open a projection in an operator-controlled directory. Sidecar flock
    /// serializes cooperating processes; this is not hostile-parent isolation.
    /// Read accessors are snapshots, never scheduling or policy permission.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, SchedulerStoreError> {
        let path = path.into();
        let name = path
            .file_name()
            .ok_or_else(|| SchedulerStoreError::Invalid("scheduler path has no filename".into()))?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = parent.canonicalize()?;
        let mut lock_name = name.to_os_string();
        lock_name.push(".scheduler-lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(parent.join(lock_name))?;
        if !lock.metadata()?.is_file() {
            return Err(SchedulerStoreError::Invalid(
                "scheduler lock is not a file".into(),
            ));
        }
        let mut store = Self {
            path: parent.join(name),
            file: StoreFile::default(),
            lock,
            gate: Mutex::new(()),
            uncertain: AtomicBool::new(false),
        };
        store.file = store.with_lock(|| {
            let current = match store.read_current() {
                Ok(file) => file,
                Err(SchedulerStoreError::Io(error))
                    if error.kind() == std::io::ErrorKind::NotFound
                        && store.lock.metadata()?.len() == 0 =>
                {
                    let empty = StoreFile::default();
                    store.persist(&empty)?;
                    empty
                }
                Err(error) => return Err(error),
            };
            // This marker records storage initialization only. If the data
            // file later vanishes, opening the projection must not silently
            // forget its tombstones and admit previously settled operations.
            if store.lock.metadata()?.len() == 0 {
                let mut marker = &store.lock;
                marker.write_all(b"scheduler-storage-initialized-v1\n")?;
                marker.sync_all()?;
            }
            Ok(current)
        })?;
        Ok(store)
    }

    fn with_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, SchedulerStoreError>,
    ) -> Result<T, SchedulerStoreError> {
        if self.uncertain.load(Ordering::Acquire) {
            return Err(SchedulerStoreError::RecoveryRequired);
        }
        let _guard = self
            .gate
            .lock()
            .map_err(|_| SchedulerStoreError::RecoveryRequired)?;
        // Recheck after waiting: another thread may have poisoned this handle.
        if self.uncertain.load(Ordering::Acquire) {
            return Err(SchedulerStoreError::RecoveryRequired);
        }
        rustix::fs::flock(self.lock.as_fd(), FlockOperation::LockExclusive)
            .map_err(std::io::Error::from)?;
        let result = operation();
        let unlocked = rustix::fs::flock(self.lock.as_fd(), FlockOperation::Unlock);
        if unlocked.is_err() {
            self.uncertain.store(true, Ordering::Release);
            return Err(SchedulerStoreError::RecoveryRequired);
        }
        result
    }

    fn read_current(&self) -> Result<StoreFile, SchedulerStoreError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&self.path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_STORE_BYTES {
            return Err(SchedulerStoreError::Invalid(
                "scheduler input exceeds its file bound".into(),
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_STORE_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_STORE_BYTES {
            return Err(SchedulerStoreError::Invalid(
                "scheduler input exceeds its file bound".into(),
            ));
        }
        let value = recursive_agent_contracts::parse_strict_json_value(&bytes)
            .map_err(|_| SchedulerStoreError::Invalid("invalid scheduler JSON".into()))?;
        let file: StoreFile = serde_json::from_value(value)?;
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for (id, row) in &file.rows {
            if id != &row.operation_id || row.state == ProjectedState::Quarantined {
                return Err(SchedulerStoreError::Invalid(
                    "invalid scheduler row identity".into(),
                ));
            }
        }
        for row in file.rows.values().chain(file.quarantined.iter()) {
            if row.operation_id.is_empty()
                || !ids.insert(&row.operation_id)
                || row
                    .idempotency_key_digest
                    .as_ref()
                    .is_some_and(|key| key.is_empty() || !keys.insert(key))
            {
                return Err(SchedulerStoreError::Invalid(
                    "conflicting scheduler identity binding".into(),
                ));
            }
        }
        if file
            .quarantined
            .iter()
            .any(|row| row.state != ProjectedState::Quarantined)
        {
            return Err(SchedulerStoreError::Invalid(
                "invalid quarantine state".into(),
            ));
        }
        Ok(file)
    }

    fn persist(&self, file: &StoreFile) -> Result<(), SchedulerStoreError> {
        let bytes = serde_json::to_vec(file)?;
        if bytes.len() as u64 > MAX_STORE_BYTES {
            return Err(SchedulerStoreError::Invalid(
                "scheduler output exceeds its file bound".into(),
            ));
        }
        let parent = self
            .path
            .parent()
            .ok_or_else(|| SchedulerStoreError::Invalid("missing parent".into()))?;
        // A unique create-new temporary file cannot overwrite another store's
        // pending write or follow the old predictable .tmp symlink.
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary.persist(&self.path).map_err(|error| error.error)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn update<T>(
        &mut self,
        change: impl FnOnce(&mut StoreFile) -> Result<T, SchedulerStoreError>,
    ) -> Result<T, SchedulerStoreError> {
        let result = self.with_lock(|| {
            let mut candidate = self.read_current().map_err(|error| {
                self.uncertain.store(true, Ordering::Release);
                error
            })?;
            let output = change(&mut candidate)?;
            // No capability or new in-memory projection escapes before durable
            // publication. Any uncertain I/O makes this handle unusable until
            // explicit recovery opens and reconciles the committed owner state.
            self.persist(&candidate).map_err(|error| {
                self.uncertain.store(true, Ordering::Release);
                error
            })?;
            Ok((candidate, output))
        });
        match result {
            Ok((candidate, output)) => {
                self.file = candidate;
                Ok(output)
            }
            Err(error) => {
                if matches!(
                    &error,
                    SchedulerStoreError::Io(_) | SchedulerStoreError::RecoveryRequired
                ) {
                    self.uncertain.store(true, Ordering::Release);
                }
                Err(error)
            }
        }
    }

    /// Admit an operation into the queue. Exact duplicates by operation id are
    /// idempotent (return the existing row).
    pub fn admit(
        &mut self,
        operation_id: impl Into<String>,
        idempotency_key_digest: impl Into<String>,
    ) -> Result<OperationRow, SchedulerStoreError> {
        let operation_id = operation_id.into();
        let key = idempotency_key_digest.into();
        if operation_id.is_empty() || key.is_empty() {
            return Err(SchedulerStoreError::Invalid(
                "empty admission identity".into(),
            ));
        }
        self.update(|file| {
            if file
                .quarantined
                .iter()
                .any(|row| row.operation_id == operation_id)
            {
                return Err(SchedulerStoreError::UnknownAdmission(operation_id));
            }
            if let Some(row) = file.rows.get(&operation_id) {
                if row.idempotency_key_digest.as_deref() != Some(key.as_str()) {
                    return Err(SchedulerStoreError::IdempotencyConflict);
                }
                return Ok(row.clone());
            }
            if file
                .rows
                .values()
                .chain(file.quarantined.iter())
                .any(|row| row.idempotency_key_digest.as_deref() == Some(key.as_str()))
            {
                return Err(SchedulerStoreError::IdempotencyConflict);
            }
            let mut row = OperationRow::new(operation_id.clone());
            row.idempotency_key_digest = Some(key);
            file.rows.insert(operation_id, row.clone());
            Ok(row)
        })
    }

    /// Add a causal child to the rebuildable projection. This does not admit,
    /// reserve, authorize, or dispatch the child.
    pub fn project_child(
        &mut self,
        parent_operation_id: &str,
        root_operation_id: &str,
        child_operation_id: &str,
    ) -> Result<(), SchedulerStoreError> {
        self.update(|file| {
            if parent_operation_id == child_operation_id || root_operation_id.is_empty() {
                return Err(SchedulerStoreError::Invalid(
                    "invalid child projection".into(),
                ));
            }
            if let Some(child) = file.rows.get(child_operation_id) {
                if child
                    .parent_operation_id
                    .as_deref()
                    .is_some_and(|parent| parent != parent_operation_id)
                    || child
                        .root_operation_id
                        .as_deref()
                        .is_some_and(|root| root != root_operation_id)
                {
                    return Err(SchedulerStoreError::Invalid(
                        "child projection mismatch".into(),
                    ));
                }
            }
            let parent = file
                .rows
                .get_mut(parent_operation_id)
                .ok_or_else(|| SchedulerStoreError::UnknownAdmission(parent_operation_id.into()))?;
            if parent
                .root_operation_id
                .as_deref()
                .is_some_and(|root| root != root_operation_id)
            {
                return Err(SchedulerStoreError::Invalid(
                    "root projection mismatch".into(),
                ));
            }
            parent.root_operation_id = Some(root_operation_id.into());
            if !parent
                .children
                .iter()
                .any(|child| child == child_operation_id)
            {
                parent.children.push(child_operation_id.into());
            }
            if let Some(child) = file.rows.get_mut(child_operation_id) {
                child.parent_operation_id = Some(parent_operation_id.into());
                child.root_operation_id = Some(root_operation_id.into());
            }
            Ok(())
        })
    }

    pub fn children_of(&self, parent_operation_id: &str) -> Vec<String> {
        self.file
            .rows
            .get(parent_operation_id)
            .map_or_else(Vec::new, |row| row.children.clone())
    }

    /// Acquire an exclusive lease. Fails if a different holder owns it.
    pub fn acquire_lease(
        &mut self,
        operation_id: &str,
        holder: impl Into<String>,
    ) -> Result<LeaseGrantV1, SchedulerStoreError> {
        let holder = holder.into();
        if holder.is_empty() {
            return Err(SchedulerStoreError::InvalidLeaseHolder);
        }
        self.update(|file| {
            let row = file
                .rows
                .get_mut(operation_id)
                .ok_or_else(|| SchedulerStoreError::UnknownAdmission(operation_id.to_string()))?;
            if row.cancel_requested
                || !matches!(
                    row.state,
                    ProjectedState::Submitted | ProjectedState::Authorized
                )
            {
                return Err(SchedulerStoreError::IneligibleLease);
            }
            match &row.lease_holder {
                Some(existing) if *existing != holder => {
                    return Err(SchedulerStoreError::LeaseConflict {
                        operation: operation_id.to_string(),
                        holder: existing.clone(),
                    });
                }
                None => {
                    row.lease_generation =
                        row.lease_generation.checked_add(1).ok_or_else(|| {
                            SchedulerStoreError::LeaseGenerationExhausted(operation_id.into())
                        })?;
                }
                _ => {}
            }
            row.heartbeat = row.heartbeat.checked_add(1).ok_or_else(|| {
                SchedulerStoreError::LeaseGenerationExhausted(operation_id.into())
            })?;
            row.lease_holder = Some(holder.clone());
            row.state = ProjectedState::Authorized;
            Ok(LeaseGrantV1 {
                operation_id: row.operation_id.clone(),
                holder,
                generation: row.lease_generation,
            })
        })
    }

    /// Explicitly transfer one current lease to a new generation. The old
    /// generation remains useful only as historical reconciliation input.
    pub fn transfer_lease(
        &mut self,
        current: &LeaseGrantV1,
        next_holder: impl Into<String>,
    ) -> Result<LeaseGrantV1, SchedulerStoreError> {
        let next_holder = next_holder.into();
        if next_holder.is_empty() {
            return Err(SchedulerStoreError::InvalidLeaseHolder);
        }
        self.update(|file| {
            Self::validate_grant_in(file, current)?;
            let row = file.rows.get_mut(&current.operation_id).ok_or_else(|| {
                SchedulerStoreError::UnknownAdmission(current.operation_id.clone())
            })?;
            row.lease_generation = row.lease_generation.checked_add(1).ok_or_else(|| {
                SchedulerStoreError::LeaseGenerationExhausted(current.operation_id.clone())
            })?;
            row.heartbeat = row.heartbeat.checked_add(1).ok_or_else(|| {
                SchedulerStoreError::LeaseGenerationExhausted(current.operation_id.clone())
            })?;
            row.lease_holder = Some(next_holder.clone());
            Ok(LeaseGrantV1 {
                operation_id: current.operation_id.clone(),
                holder: next_holder,
                generation: row.lease_generation,
            })
        })
    }

    /// Require the current lease generation before a worker starts another
    /// effect. Policy/permit admission remains a separate mandatory gate.
    pub fn authorize_effect_start(&self, grant: &LeaseGrantV1) -> Result<(), SchedulerStoreError> {
        self.validate_grant(grant)
    }

    /// Require the current lease generation before publishing a result as
    /// current. Receipt verification remains authoritative for terminal truth.
    pub fn authorize_publish(&self, grant: &LeaseGrantV1) -> Result<(), SchedulerStoreError> {
        self.validate_grant(grant)
    }

    fn validate_grant(&self, grant: &LeaseGrantV1) -> Result<(), SchedulerStoreError> {
        // Point-in-time scheduling check against the durable current owner,
        // not a grant to bypass policy or a lock held across external effects.
        self.with_lock(|| Self::validate_grant_in(&self.read_current()?, grant))
    }

    fn validate_grant_in(
        file: &StoreFile,
        grant: &LeaseGrantV1,
    ) -> Result<(), SchedulerStoreError> {
        let row = file
            .rows
            .get(&grant.operation_id)
            .ok_or_else(|| SchedulerStoreError::UnknownAdmission(grant.operation_id.clone()))?;
        let current = row.state == ProjectedState::Authorized
            && !row.cancel_requested
            && row.lease_holder.as_deref() == Some(grant.holder.as_str())
            && row.lease_generation == grant.generation;
        if current {
            return Ok(());
        }
        Err(SchedulerStoreError::LeaseFenced {
            operation: grant.operation_id.clone(),
            holder: grant.holder.clone(),
            generation: grant.generation,
        })
    }

    /// Record a durable cancellation request (idempotent).
    pub fn request_cancel(&mut self, operation_id: &str) -> Result<(), SchedulerStoreError> {
        self.update(|file| {
            let row = file
                .rows
                .get_mut(operation_id)
                .ok_or_else(|| SchedulerStoreError::UnknownAdmission(operation_id.into()))?;
            row.cancel_requested = true;
            if row.state != ProjectedState::Terminal {
                row.state = ProjectedState::Cancelling;
            }
            Ok(())
        })
    }

    /// Advance the event projection cursor after reading committed events.
    pub fn advance_cursor(
        &mut self,
        operation_id: &str,
        sequence: u64,
    ) -> Result<(), SchedulerStoreError> {
        self.update(|file| {
            let row = file
                .rows
                .get_mut(operation_id)
                .ok_or_else(|| SchedulerStoreError::UnknownAdmission(operation_id.into()))?;
            row.projection_cursor = row.projection_cursor.max(sequence);
            Ok(())
        })
    }

    /// Mark a row terminal from ledger evidence. Terminal rows cannot be leased.
    pub fn set_terminal(&mut self, operation_id: &str) -> Result<(), SchedulerStoreError> {
        self.update(|file| {
            let row = file
                .rows
                .get_mut(operation_id)
                .ok_or_else(|| SchedulerStoreError::UnknownAdmission(operation_id.into()))?;
            row.state = ProjectedState::Terminal;
            Ok(())
        })
    }

    /// Quarantine is retained as a tombstone for operation and key admission.
    pub fn quarantine(&mut self, operation_id: &str) -> Result<(), SchedulerStoreError> {
        self.update(|file| {
            let mut row = file
                .rows
                .remove(operation_id)
                .ok_or_else(|| SchedulerStoreError::UnknownAdmission(operation_id.into()))?;
            row.state = ProjectedState::Quarantined;
            file.quarantined.push(row);
            Ok(())
        })
    }

    /// Last-observed snapshot of rows (for recovery inspection, never authority).
    pub fn live_rows(&self) -> Vec<OperationRow> {
        self.file.rows.values().cloned().collect()
    }

    /// Look up a row in this handle's last-observed snapshot; never authority.
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
