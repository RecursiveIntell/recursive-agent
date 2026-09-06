//! One service-owned admission domain for managed physical leaves.
//!
//! Logical parents, Graph-ready nodes and IPC connections are projections, not
//! active leaves. A reservation becomes active only after the global slot and
//! every declared lane are atomically available. Queue materialization and
//! artifact reservations are bounded before expansion. Cancelled work can remain
//! in `draining` until the underlying provider/worker is reconciled.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable lane used for provider-backed work.
pub const PROVIDER_LANE: &str = "provider";
/// Stable lane used for admitted tool work.
pub const TOOL_LANE: &str = "tool";
/// Stable lane used for sandboxed child processes.
pub const SANDBOX_PROCESS_LANE: &str = "sandbox-process";

const DEFAULT_CONTEXT_CAPACITY_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_ARTIFACT_RESERVATION_PER_LEAF_BYTES: u64 = 64 * 1024 * 1024;

fn default_artifact_capacity() -> u64 {
    u64::MAX
}

/// Native admission configuration. `global_max_active` remains the sole global
/// physical-leaf ceiling; lane caps may only narrow it. Byte capacities are
/// separate queue/materialization reservations and never masquerade as leaves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedAdmissionConfigV1 {
    pub revision: u64,
    pub global_max_active: usize,
    pub lane_caps: BTreeMap<String, usize>,
    pub max_queued: usize,
    pub max_materialized_context_bytes: u64,
    #[serde(default = "default_artifact_capacity")]
    pub max_reserved_artifact_bytes: u64,
}

impl ManagedAdmissionConfigV1 {
    /// Build the default managed configuration from the canonical global cap.
    pub fn from_global(global_max_active: usize) -> Self {
        let leaf_count = u64::try_from(global_max_active).map_or(u64::MAX, |value| value);
        Self {
            revision: 1,
            global_max_active,
            lane_caps: BTreeMap::from([
                (PROVIDER_LANE.into(), global_max_active),
                (TOOL_LANE.into(), global_max_active),
                (SANDBOX_PROCESS_LANE.into(), global_max_active),
            ]),
            max_queued: global_max_active.saturating_mul(16).max(1),
            max_materialized_context_bytes: DEFAULT_CONTEXT_CAPACITY_BYTES,
            max_reserved_artifact_bytes: DEFAULT_ARTIFACT_RESERVATION_PER_LEAF_BYTES
                .saturating_mul(leaf_count),
        }
    }

    pub fn validate(&self) -> Result<(), ManagedAdmissionError> {
        if self.revision == 0
            || self.global_max_active == 0
            || self.max_queued == 0
            || self.max_materialized_context_bytes == 0
            || self.max_reserved_artifact_bytes == 0
        {
            return Err(ManagedAdmissionError::InvalidConfig(
                "revision, global, queue, context and artifact caps must be positive".into(),
            ));
        }
        if self
            .lane_caps
            .iter()
            .any(|(lane, cap)| lane.is_empty() || *cap == 0 || *cap > self.global_max_active)
        {
            return Err(ManagedAdmissionError::InvalidConfig(
                "every lane must be named and have a positive cap no wider than global".into(),
            ));
        }
        Ok(())
    }
}

/// Cumulative ceilings fixed for one admitted operation or explicit family
/// scope. Reconfiguration never mutates a scope's retained budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedBudgetV1 {
    pub max_attempts: u64,
    pub max_wall_time_ms: u64,
    pub max_tokens: u64,
    pub max_cost_microunits: u64,
    pub max_artifact_bytes: u64,
    pub max_context_bytes: u64,
}

impl Default for ManagedBudgetV1 {
    fn default() -> Self {
        Self {
            max_attempts: 1,
            max_wall_time_ms: 120_000,
            max_tokens: u64::MAX,
            max_cost_microunits: u64::MAX,
            max_artifact_bytes: DEFAULT_ARTIFACT_RESERVATION_PER_LEAF_BYTES,
            max_context_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Deterministic queue class. Interactive work receives the next feasible slot;
/// FIFO ticket order is preserved within each class. This prevents a model-
/// affinity backlog from starving later interactive work without giving any
/// adapter its own scheduler.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedQueueClassV1 {
    Interactive,
    #[default]
    Normal,
}

/// Units atomically required from one configured lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneRequirementV1 {
    pub lane: String,
    pub units: usize,
}

/// Closed admission request for one physical leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedAdmissionRequestV1 {
    pub operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_scope_id: Option<String>,
    pub model_ref: String,
    pub lanes: Vec<LaneRequirementV1>,
    pub context_bytes: u64,
    #[serde(default)]
    pub estimated_artifact_bytes: u64,
    pub budget: ManagedBudgetV1,
    #[serde(default)]
    pub queue_class: ManagedQueueClassV1,
    /// Zero means fail immediately rather than entering the visible queue.
    pub queue_timeout_ms: u64,
    /// When present, the complete simultaneously required roster size.
    pub require_simultaneous_members: Option<usize>,
}

impl ManagedAdmissionRequestV1 {
    pub fn provider(
        operation_id: impl Into<String>,
        model_ref: impl Into<String>,
        budget: ManagedBudgetV1,
    ) -> Self {
        Self {
            operation_id: operation_id.into(),
            parent_operation_id: None,
            budget_scope_id: None,
            model_ref: model_ref.into(),
            lanes: vec![LaneRequirementV1 {
                lane: PROVIDER_LANE.into(),
                units: 1,
            }],
            context_bytes: 0,
            estimated_artifact_bytes: 0,
            budget,
            queue_class: ManagedQueueClassV1::Normal,
            queue_timeout_ms: 0,
            require_simultaneous_members: None,
        }
    }

    pub fn tool(
        operation_id: impl Into<String>,
        model_ref: impl Into<String>,
        budget: ManagedBudgetV1,
    ) -> Self {
        Self {
            operation_id: operation_id.into(),
            parent_operation_id: None,
            budget_scope_id: None,
            model_ref: model_ref.into(),
            lanes: vec![LaneRequirementV1 {
                lane: TOOL_LANE.into(),
                units: 1,
            }],
            context_bytes: 0,
            estimated_artifact_bytes: 0,
            budget,
            queue_class: ManagedQueueClassV1::Normal,
            queue_timeout_ms: 0,
            require_simultaneous_members: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedUsageV1 {
    pub attempts: u64,
    pub wall_time_ms: u64,
    pub tokens: u64,
    pub cost_microunits: u64,
    pub artifact_bytes: u64,
    pub context_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedAdmissionSnapshotV1 {
    pub config_revision: u64,
    pub global_max_active: usize,
    pub selected: Vec<String>,
    pub queued: Vec<String>,
    pub active: Vec<String>,
    pub draining: Vec<String>,
    pub cancelled: Vec<String>,
    pub lane_active_units: BTreeMap<String, usize>,
    pub provider_requests_in_flight: usize,
    pub selected_context_bytes: u64,
    pub selected_artifact_bytes: u64,
    pub total_attempts: u64,
    pub total_wall_time_ms: u64,
    pub total_tokens: u64,
    pub total_cost_microunits: u64,
    pub total_artifact_bytes: u64,
    pub total_context_bytes: u64,
    pub budget_scope_attempts: BTreeMap<String, u64>,
    pub submitted_config_revisions: BTreeMap<String, u64>,
    pub admitted_config_revisions: BTreeMap<String, u64>,
    pub queue_tickets: BTreeMap<String, u64>,
    pub queue_classes: BTreeMap<String, ManagedQueueClassV1>,
    pub unknown_spend_operations: Vec<String>,
    pub open_ipc_connections: usize,
    pub queue_policy: String,
    pub enforcement_scope: String,
    pub unmanaged_host_load_enforced: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ManagedAdmissionError {
    #[error("invalid managed admission configuration: {0}")]
    InvalidConfig(String),
    #[error("managed route/model is missing")]
    MissingRoute,
    #[error("managed lane is not configured: {0}")]
    MissingLane(String),
    #[error("managed lane request is invalid: {0}")]
    InvalidLane(String),
    #[error("operation is already selected, queued, active, draining, cancelled or terminal: {0}")]
    DuplicateOperation(String),
    #[error("parent admission is fenced by cancellation: {0}")]
    ParentFenced(String),
    #[error("simultaneous roster of {requested} exceeds capacity {configured}")]
    SimultaneousCapacity { requested: usize, configured: usize },
    #[error("managed queue capacity exhausted: {configured}")]
    QueueCapacity { configured: usize },
    #[error("managed physical capacity exhausted: {configured}")]
    Capacity { configured: usize },
    #[error("managed admission queue timed out")]
    QueueTimeout,
    #[error("materialized context exceeds per-operation managed budget")]
    ContextBudget,
    #[error("materialized context reservation {requested} exceeds available capacity {available}")]
    ContextCapacity { requested: u64, available: u64 },
    #[error("artifact reservation {requested} exceeds available capacity {available}")]
    ArtifactCapacity { requested: u64, available: u64 },
    #[error("managed cumulative budget scope conflicts with retained scope: {0}")]
    BudgetScopeConflict(String),
    #[error("managed cumulative budget exceeded: {0}")]
    BudgetExceeded(&'static str),
    #[error("managed admission state is poisoned")]
    StatePoisoned,
    #[error("managed operation is not active: {0}")]
    NotActive(String),
    #[error("managed operation is not draining: {0}")]
    NotDraining(String),
    #[error("provider request is still in flight: {0}")]
    ProviderStillInFlight(String),
}

#[derive(Debug, Clone)]
struct QueuedLeaf {
    ticket: u64,
    submitted_config_revision: u64,
    request: ManagedAdmissionRequestV1,
}

#[derive(Debug, Clone)]
struct ActiveLeaf {
    ticket: u64,
    submitted_config_revision: u64,
    admitted_config_revision: u64,
    request: ManagedAdmissionRequestV1,
    provider_in_flight: bool,
}

#[derive(Debug, Clone)]
struct UsageRecord {
    scope_id: String,
    submitted_config_revision: u64,
    admitted_config_revision: u64,
    usage: ManagedUsageV1,
    unknown_spend: bool,
}

#[derive(Debug, Clone, Copy)]
struct UsageDelta {
    attempts: u64,
    wall_time_ms: u64,
    tokens: u64,
    cost_microunits: u64,
    artifact_bytes: u64,
    context_bytes: u64,
}

#[derive(Debug)]
struct AdmissionState {
    config: ManagedAdmissionConfigV1,
    next_ticket: u64,
    selected: BTreeSet<String>,
    queue: VecDeque<QueuedLeaf>,
    active: BTreeMap<String, ActiveLeaf>,
    draining: BTreeMap<String, ActiveLeaf>,
    cancelled: BTreeSet<String>,
    fenced_parents: BTreeSet<String>,
    usage: BTreeMap<String, UsageRecord>,
    scope_budgets: BTreeMap<String, ManagedBudgetV1>,
    open_ipc_connections: usize,
}

struct SharedAdmission {
    state: Mutex<AdmissionState>,
    changed: Condvar,
}

/// Cloneable handle to the one service-owned admission domain.
#[derive(Clone)]
pub struct ManagedAdmissionDomain {
    shared: Arc<SharedAdmission>,
}

impl ManagedAdmissionDomain {
    /// Construct from a validated canonical global cap.
    pub fn from_global(global_max_active: usize) -> Self {
        // Runtime dependency construction validates the configured ceiling.
        // Direct misuse with zero remains fail-closed instead of being silently
        // widened to one physical leaf.
        Self::new_unchecked(ManagedAdmissionConfigV1::from_global(global_max_active))
    }

    fn new_unchecked(config: ManagedAdmissionConfigV1) -> Self {
        Self {
            shared: Arc::new(SharedAdmission {
                state: Mutex::new(AdmissionState {
                    config,
                    next_ticket: 1,
                    selected: BTreeSet::new(),
                    queue: VecDeque::new(),
                    active: BTreeMap::new(),
                    draining: BTreeMap::new(),
                    cancelled: BTreeSet::new(),
                    fenced_parents: BTreeSet::new(),
                    usage: BTreeMap::new(),
                    scope_budgets: BTreeMap::new(),
                    open_ipc_connections: 0,
                }),
                changed: Condvar::new(),
            }),
        }
    }

    pub fn with_config(config: ManagedAdmissionConfigV1) -> Result<Self, ManagedAdmissionError> {
        config.validate()?;
        Ok(Self::new_unchecked(config))
    }

    /// Atomically reserve global and lane resources, queueing under deterministic
    /// interactive-next-slot/FIFO policy when requested. Context and artifact
    /// materialization are reserved before queue insertion, so ready work cannot
    /// expand those dimensions without bound. A waiting logical parent holds no
    /// physical reservation.
    pub fn reserve(
        &self,
        request: ManagedAdmissionRequestV1,
    ) -> Result<ManagedReservation, ManagedAdmissionError> {
        self.validate_request(&request)?;
        let started = Instant::now();
        let timeout = Duration::from_millis(request.queue_timeout_ms);
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| ManagedAdmissionError::StatePoisoned)?;

        if let Some(parent) = request.parent_operation_id.as_deref() {
            if state.fenced_parents.contains(parent) {
                return Err(ManagedAdmissionError::ParentFenced(parent.into()));
            }
        }
        if state.selected.contains(&request.operation_id)
            || state
                .queue
                .iter()
                .any(|queued| queued.request.operation_id == request.operation_id)
            || state.active.contains_key(&request.operation_id)
            || state.draining.contains_key(&request.operation_id)
            || state.cancelled.contains(&request.operation_id)
            || state.usage.contains_key(&request.operation_id)
        {
            return Err(ManagedAdmissionError::DuplicateOperation(
                request.operation_id,
            ));
        }
        if let Some(requested) = request.require_simultaneous_members {
            if requested > state.config.global_max_active {
                return Err(ManagedAdmissionError::SimultaneousCapacity {
                    requested,
                    configured: state.config.global_max_active,
                });
            }
        }

        let selected_context = selected_context_bytes(&state);
        let context_available = state
            .config
            .max_materialized_context_bytes
            .saturating_sub(selected_context);
        if request.context_bytes > context_available {
            return Err(ManagedAdmissionError::ContextCapacity {
                requested: request.context_bytes,
                available: context_available,
            });
        }
        let selected_artifacts = selected_artifact_bytes(&state);
        let artifact_available = state
            .config
            .max_reserved_artifact_bytes
            .saturating_sub(selected_artifacts);
        if request.estimated_artifact_bytes > artifact_available {
            return Err(ManagedAdmissionError::ArtifactCapacity {
                requested: request.estimated_artifact_bytes,
                available: artifact_available,
            });
        }

        let scope_id = request_scope_id(&request);
        if let Some(existing) = state.scope_budgets.get(&scope_id) {
            if existing != &request.budget {
                return Err(ManagedAdmissionError::BudgetScopeConflict(scope_id));
            }
        } else {
            state
                .scope_budgets
                .insert(scope_id.clone(), request.budget.clone());
        }

        let submitted_config_revision = state.config.revision;
        state.selected.insert(request.operation_id.clone());
        let ticket = state.next_ticket;
        state.next_ticket = state.next_ticket.saturating_add(1);
        state.queue.push_back(QueuedLeaf {
            ticket,
            submitted_config_revision,
            request: request.clone(),
        });
        if state.queue.len() > state.config.max_queued {
            remove_queued(&mut state.queue, ticket);
            state.selected.remove(&request.operation_id);
            cleanup_scope_if_unused(&mut state, &scope_id);
            return Err(ManagedAdmissionError::QueueCapacity {
                configured: state.config.max_queued,
            });
        }

        loop {
            if !state.queue.iter().any(|queued| queued.ticket == ticket) {
                return Err(ManagedAdmissionError::ParentFenced(
                    request
                        .parent_operation_id
                        .clone()
                        .unwrap_or_else(|| request.operation_id.clone()),
                ));
            }
            let is_turn = next_admissible_ticket(&state) == Some(ticket);
            if is_turn {
                let position = state
                    .queue
                    .iter()
                    .position(|queued| queued.ticket == ticket)
                    .ok_or(ManagedAdmissionError::StatePoisoned)?;
                let queued = state
                    .queue
                    .remove(position)
                    .ok_or(ManagedAdmissionError::StatePoisoned)?;
                let operation_id = queued.request.operation_id.clone();
                let admitted_config_revision = state.config.revision;
                state.usage.insert(
                    operation_id.clone(),
                    UsageRecord {
                        scope_id,
                        submitted_config_revision: queued.submitted_config_revision,
                        admitted_config_revision,
                        usage: ManagedUsageV1::default(),
                        unknown_spend: false,
                    },
                );
                state.active.insert(
                    operation_id.clone(),
                    ActiveLeaf {
                        ticket,
                        submitted_config_revision: queued.submitted_config_revision,
                        admitted_config_revision,
                        request: queued.request,
                        provider_in_flight: false,
                    },
                );
                self.shared.changed.notify_all();
                return Ok(ManagedReservation {
                    domain: self.clone(),
                    operation_id,
                    released: false,
                });
            }
            if timeout.is_zero() {
                remove_queued(&mut state.queue, ticket);
                state.selected.remove(&request.operation_id);
                cleanup_scope_if_unused(&mut state, &scope_id);
                return Err(ManagedAdmissionError::Capacity {
                    configured: state.config.global_max_active,
                });
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                remove_queued(&mut state.queue, ticket);
                state.selected.remove(&request.operation_id);
                cleanup_scope_if_unused(&mut state, &scope_id);
                return Err(ManagedAdmissionError::QueueTimeout);
            }
            let (next, timed) = self
                .shared
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| ManagedAdmissionError::StatePoisoned)?;
            state = next;
            if timed.timed_out() && next_admissible_ticket(&state) != Some(ticket) {
                remove_queued(&mut state.queue, ticket);
                state.selected.remove(&request.operation_id);
                cleanup_scope_if_unused(&mut state, &scope_id);
                return Err(ManagedAdmissionError::QueueTimeout);
            }
        }
    }

    fn validate_request(
        &self,
        request: &ManagedAdmissionRequestV1,
    ) -> Result<(), ManagedAdmissionError> {
        if request.operation_id.is_empty() || request.model_ref.is_empty() {
            return Err(ManagedAdmissionError::MissingRoute);
        }
        if request
            .parent_operation_id
            .as_deref()
            .is_some_and(|parent| parent.is_empty() || parent == request.operation_id)
        {
            return Err(ManagedAdmissionError::InvalidConfig(
                "parent operation identity must be non-empty and differ from the leaf".into(),
            ));
        }
        if request
            .budget_scope_id
            .as_deref()
            .is_some_and(str::is_empty)
        {
            return Err(ManagedAdmissionError::InvalidConfig(
                "budget scope identity must be non-empty".into(),
            ));
        }
        if request.budget.max_attempts == 0
            || request.budget.max_wall_time_ms == 0
            || request.budget.max_artifact_bytes == 0
            || request.budget.max_context_bytes == 0
        {
            return Err(ManagedAdmissionError::InvalidConfig(
                "operation budgets must have positive attempt, wall, artifact and context ceilings"
                    .into(),
            ));
        }
        if request.estimated_artifact_bytes > request.budget.max_artifact_bytes {
            return Err(ManagedAdmissionError::BudgetExceeded("artifact_bytes"));
        }
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| ManagedAdmissionError::StatePoisoned)?;
        if request.context_bytes > request.budget.max_context_bytes
            || request.context_bytes > state.config.max_materialized_context_bytes
        {
            return Err(ManagedAdmissionError::ContextBudget);
        }
        let mut seen = BTreeSet::new();
        for lane in &request.lanes {
            if lane.units == 0 || !seen.insert(lane.lane.as_str()) {
                return Err(ManagedAdmissionError::InvalidLane(lane.lane.clone()));
            }
            let Some(cap) = state.config.lane_caps.get(&lane.lane) else {
                return Err(ManagedAdmissionError::MissingLane(lane.lane.clone()));
            };
            if lane.units > *cap {
                return Err(ManagedAdmissionError::Capacity { configured: *cap });
            }
        }
        Ok(())
    }

    /// Apply a new restrictive or wider configuration revision. Existing work
    /// keeps its original budget and reservation; new admissions obey current
    /// capacity while retaining their submitted revision for audit.
    pub fn reconfigure(
        &self,
        mut config: ManagedAdmissionConfigV1,
    ) -> Result<(), ManagedAdmissionError> {
        config.validate()?;
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| ManagedAdmissionError::StatePoisoned)?;
        if config.revision <= state.config.revision {
            return Err(ManagedAdmissionError::InvalidConfig(
                "configuration revision must increase".into(),
            ));
        }
        config.max_queued = config.max_queued.max(state.queue.len());
        state.config = config;
        self.shared.changed.notify_all();
        Ok(())
    }

    pub fn contains_active(&self, operation_id: &str) -> Result<bool, ManagedAdmissionError> {
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| ManagedAdmissionError::StatePoisoned)?;
        Ok(state.active.contains_key(operation_id) || state.draining.contains_key(operation_id))
    }

    /// Compatibility-only explicit projection setter. Production daemon paths
    /// use `connection_opened`/`connection_closed` so counts follow RAII guards.
    pub fn set_open_ipc_connections(
        &self,
        connections: usize,
    ) -> Result<(), ManagedAdmissionError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| ManagedAdmissionError::StatePoisoned)?;
        state.open_ipc_connections = connections;
        Ok(())
    }

    pub fn connection_opened(&self) -> Result<(), ManagedAdmissionError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| ManagedAdmissionError::StatePoisoned)?;
        state.open_ipc_connections = state.open_ipc_connections.saturating_add(1);
        Ok(())
    }

    pub fn connection_closed(&self) -> Result<(), ManagedAdmissionError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| ManagedAdmissionError::StatePoisoned)?;
        state.open_ipc_connections = state.open_ipc_connections.saturating_sub(1);
        Ok(())
    }

    fn set_provider_in_flight(
        &self,
        operation_id: &str,
        in_flight: bool,
    ) -> Result<(), ManagedAdmissionError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| ManagedAdmissionError::StatePoisoned)?;
        let leaf = if let Some(active) = state.active.get_mut(operation_id) {
            active
        } else if let Some(draining) = state.draining.get_mut(operation_id) {
            draining
        } else {
            return Err(ManagedAdmissionError::NotActive(operation_id.into()));
        };
        if !leaf
            .request
            .lanes
            .iter()
            .any(|lane| lane.lane == PROVIDER_LANE)
        {
            return Err(ManagedAdmissionError::InvalidLane(PROVIDER_LANE.into()));
        }
        leaf.provider_in_flight = in_flight;
        self.shared.changed.notify_all();
        Ok(())
    }

    /// Record externally observed provider termination for an active or draining
    /// operation. Capacity remains reserved until normal release/reconciliation.
    pub fn observe_provider_complete(
        &self,
        operation_id: &str,
    ) -> Result<(), ManagedAdmissionError> {
        self.set_provider_in_flight(operation_id, false)
    }

    /// Fence a cancelled parent, remove its queued descendants without reserving
    /// leaves, and move every active descendant to draining without releasing
    /// capacity. A racing waiter observes the fence and exits with a typed error.
    pub fn mark_descendants_draining(
        &self,
        parent_operation_id: &str,
    ) -> Result<usize, ManagedAdmissionError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| ManagedAdmissionError::StatePoisoned)?;
        state.fenced_parents.insert(parent_operation_id.into());

        let queued_ids: Vec<(String, String)> = state
            .queue
            .iter()
            .filter(|leaf| leaf.request.parent_operation_id.as_deref() == Some(parent_operation_id))
            .map(|leaf| {
                (
                    leaf.request.operation_id.clone(),
                    request_scope_id(&leaf.request),
                )
            })
            .collect();
        state.queue.retain(|leaf| {
            leaf.request.parent_operation_id.as_deref() != Some(parent_operation_id)
        });
        for (operation_id, scope_id) in &queued_ids {
            state.selected.remove(operation_id);
            state.cancelled.insert(operation_id.clone());
            cleanup_scope_if_unused(&mut state, scope_id);
        }

        let active_ids: Vec<String> = state
            .active
            .iter()
            .filter(|(_, leaf)| {
                leaf.request.parent_operation_id.as_deref() == Some(parent_operation_id)
            })
            .map(|(operation_id, _)| operation_id.clone())
            .collect();
        for operation_id in &active_ids {
            if let Some(active) = state.active.remove(operation_id) {
                if active.provider_in_flight {
                    if let Some(usage) = state.usage.get_mut(operation_id) {
                        usage.unknown_spend = true;
                    }
                }
                state.cancelled.insert(operation_id.clone());
                state.draining.insert(operation_id.clone(), active);
            }
        }
        if !queued_ids.is_empty() || !active_ids.is_empty() {
            self.shared.changed.notify_all();
        }
        Ok(queued_ids.len().saturating_add(active_ids.len()))
    }

    pub fn snapshot(&self) -> Result<ManagedAdmissionSnapshotV1, ManagedAdmissionError> {
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| ManagedAdmissionError::StatePoisoned)?;
        let mut lane_active_units = BTreeMap::new();
        for leaf in state.active.values().chain(state.draining.values()) {
            for lane in &leaf.request.lanes {
                *lane_active_units.entry(lane.lane.clone()).or_insert(0) += lane.units;
            }
        }
        let mut budget_scope_attempts = BTreeMap::new();
        let mut submitted_config_revisions = BTreeMap::new();
        let mut admitted_config_revisions = BTreeMap::new();
        let mut queue_tickets = BTreeMap::new();
        let mut queue_classes = BTreeMap::new();
        for queued in &state.queue {
            submitted_config_revisions.insert(
                queued.request.operation_id.clone(),
                queued.submitted_config_revision,
            );
            queue_tickets.insert(queued.request.operation_id.clone(), queued.ticket);
            queue_classes.insert(
                queued.request.operation_id.clone(),
                queued.request.queue_class,
            );
        }
        for (operation_id, leaf) in state.active.iter().chain(state.draining.iter()) {
            submitted_config_revisions.insert(operation_id.clone(), leaf.submitted_config_revision);
            admitted_config_revisions.insert(operation_id.clone(), leaf.admitted_config_revision);
            queue_tickets.insert(operation_id.clone(), leaf.ticket);
            queue_classes.insert(operation_id.clone(), leaf.request.queue_class);
        }
        for (operation_id, record) in &state.usage {
            submitted_config_revisions
                .entry(operation_id.clone())
                .or_insert(record.submitted_config_revision);
            admitted_config_revisions
                .entry(operation_id.clone())
                .or_insert(record.admitted_config_revision);
            *budget_scope_attempts
                .entry(record.scope_id.clone())
                .or_insert(0) += record.usage.attempts;
        }
        let total_attempts = state
            .usage
            .values()
            .map(|record| record.usage.attempts)
            .sum();
        let total_wall_time_ms = state
            .usage
            .values()
            .map(|record| record.usage.wall_time_ms)
            .sum();
        let total_tokens = state.usage.values().map(|record| record.usage.tokens).sum();
        let total_cost_microunits = state
            .usage
            .values()
            .map(|record| record.usage.cost_microunits)
            .sum();
        let total_artifact_bytes = state
            .usage
            .values()
            .map(|record| record.usage.artifact_bytes)
            .sum();
        let total_context_bytes = state
            .usage
            .values()
            .map(|record| record.usage.context_bytes)
            .sum();
        Ok(ManagedAdmissionSnapshotV1 {
            config_revision: state.config.revision,
            global_max_active: state.config.global_max_active,
            selected: state.selected.iter().cloned().collect(),
            queued: state
                .queue
                .iter()
                .map(|queued| queued.request.operation_id.clone())
                .collect(),
            active: state.active.keys().cloned().collect(),
            draining: state.draining.keys().cloned().collect(),
            cancelled: state.cancelled.iter().cloned().collect(),
            lane_active_units,
            provider_requests_in_flight: state
                .active
                .values()
                .chain(state.draining.values())
                .filter(|leaf| leaf.provider_in_flight)
                .count(),
            selected_context_bytes: selected_context_bytes(&state),
            selected_artifact_bytes: selected_artifact_bytes(&state),
            total_attempts,
            total_wall_time_ms,
            total_tokens,
            total_cost_microunits,
            total_artifact_bytes,
            total_context_bytes,
            budget_scope_attempts,
            submitted_config_revisions,
            admitted_config_revisions,
            queue_tickets,
            queue_classes,
            unknown_spend_operations: state
                .usage
                .iter()
                .filter(|(_, record)| record.unknown_spend)
                .map(|(operation_id, _)| operation_id.clone())
                .collect(),
            open_ipc_connections: state.open_ipc_connections,
            queue_policy: "interactive_next_feasible_then_fifo_ticket".into(),
            enforcement_scope: "managed_native_physical_leaves_only".into(),
            unmanaged_host_load_enforced: false,
        })
    }

    fn release_active(&self, operation_id: &str) -> Result<(), ManagedAdmissionError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| ManagedAdmissionError::StatePoisoned)?;
        state
            .active
            .remove(operation_id)
            .ok_or_else(|| ManagedAdmissionError::NotActive(operation_id.into()))?;
        state.selected.remove(operation_id);
        self.shared.changed.notify_all();
        Ok(())
    }

    fn move_to_draining(&self, operation_id: &str) -> Result<(), ManagedAdmissionError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| ManagedAdmissionError::StatePoisoned)?;
        let active = state
            .active
            .remove(operation_id)
            .ok_or_else(|| ManagedAdmissionError::NotActive(operation_id.into()))?;
        if active.provider_in_flight {
            if let Some(usage) = state.usage.get_mut(operation_id) {
                usage.unknown_spend = true;
            }
        }
        state.cancelled.insert(operation_id.into());
        state.draining.insert(operation_id.into(), active);
        self.shared.changed.notify_all();
        Ok(())
    }

    /// Move an active provider/worker into draining when cancellation has been
    /// requested but termination is not yet observed.
    pub fn mark_active_draining(&self, operation_id: &str) -> Result<(), ManagedAdmissionError> {
        self.move_to_draining(operation_id)
    }

    /// Release a draining reservation only after worker/provider termination or
    /// terminal owner evidence has been reconciled.
    pub fn reconcile_draining(&self, operation_id: &str) -> Result<(), ManagedAdmissionError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| ManagedAdmissionError::StatePoisoned)?;
        if state
            .draining
            .get(operation_id)
            .ok_or_else(|| ManagedAdmissionError::NotDraining(operation_id.into()))?
            .provider_in_flight
        {
            return Err(ManagedAdmissionError::ProviderStillInFlight(
                operation_id.into(),
            ));
        }
        state
            .draining
            .remove(operation_id)
            .ok_or_else(|| ManagedAdmissionError::NotDraining(operation_id.into()))?;
        state.selected.remove(operation_id);
        self.shared.changed.notify_all();
        Ok(())
    }

    fn charge(
        &self,
        operation_id: &str,
        delta: UsageDelta,
    ) -> Result<ManagedUsageV1, ManagedAdmissionError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| ManagedAdmissionError::StatePoisoned)?;
        if !state.active.contains_key(operation_id) && !state.draining.contains_key(operation_id) {
            return Err(ManagedAdmissionError::NotActive(operation_id.into()));
        }
        let scope_id = state
            .usage
            .get(operation_id)
            .ok_or(ManagedAdmissionError::StatePoisoned)?
            .scope_id
            .clone();
        let budget = state
            .scope_budgets
            .get(&scope_id)
            .ok_or(ManagedAdmissionError::StatePoisoned)?
            .clone();
        let usage = state
            .usage
            .get_mut(operation_id)
            .ok_or(ManagedAdmissionError::StatePoisoned)?;
        usage.usage.attempts = usage.usage.attempts.saturating_add(delta.attempts);
        usage.usage.wall_time_ms = usage.usage.wall_time_ms.saturating_add(delta.wall_time_ms);
        usage.usage.tokens = usage.usage.tokens.saturating_add(delta.tokens);
        usage.usage.cost_microunits = usage
            .usage
            .cost_microunits
            .saturating_add(delta.cost_microunits);
        usage.usage.artifact_bytes = usage
            .usage
            .artifact_bytes
            .saturating_add(delta.artifact_bytes);
        usage.usage.context_bytes = usage
            .usage
            .context_bytes
            .saturating_add(delta.context_bytes);
        let operation_snapshot = usage.usage.clone();

        let scope_usage = state
            .usage
            .values()
            .filter(|record| record.scope_id == scope_id)
            .fold(ManagedUsageV1::default(), |mut total, record| {
                total.attempts = total.attempts.saturating_add(record.usage.attempts);
                total.wall_time_ms = total.wall_time_ms.saturating_add(record.usage.wall_time_ms);
                total.tokens = total.tokens.saturating_add(record.usage.tokens);
                total.cost_microunits = total
                    .cost_microunits
                    .saturating_add(record.usage.cost_microunits);
                total.artifact_bytes = total
                    .artifact_bytes
                    .saturating_add(record.usage.artifact_bytes);
                total.context_bytes = total
                    .context_bytes
                    .saturating_add(record.usage.context_bytes);
                total
            });
        let exceeded = if scope_usage.attempts > budget.max_attempts {
            Some("attempts")
        } else if scope_usage.wall_time_ms > budget.max_wall_time_ms {
            Some("wall_time_ms")
        } else if scope_usage.tokens > budget.max_tokens {
            Some("tokens")
        } else if scope_usage.cost_microunits > budget.max_cost_microunits {
            Some("cost_microunits")
        } else if scope_usage.artifact_bytes > budget.max_artifact_bytes {
            Some("artifact_bytes")
        } else if scope_usage.context_bytes > budget.max_context_bytes {
            Some("context_bytes")
        } else {
            None
        };
        if let Some(kind) = exceeded {
            return Err(ManagedAdmissionError::BudgetExceeded(kind));
        }
        Ok(operation_snapshot)
    }
}

fn request_scope_id(request: &ManagedAdmissionRequestV1) -> String {
    request
        .budget_scope_id
        .clone()
        .unwrap_or_else(|| request.operation_id.clone())
}

fn cleanup_scope_if_unused(state: &mut AdmissionState, scope_id: &str) {
    let retained = state
        .queue
        .iter()
        .any(|leaf| request_scope_id(&leaf.request) == scope_id)
        || state
            .active
            .values()
            .chain(state.draining.values())
            .any(|leaf| request_scope_id(&leaf.request) == scope_id)
        || state
            .usage
            .values()
            .any(|record| record.scope_id == scope_id);
    if !retained {
        state.scope_budgets.remove(scope_id);
    }
}

fn remove_queued(queue: &mut VecDeque<QueuedLeaf>, ticket: u64) {
    queue.retain(|queued| queued.ticket != ticket);
}

fn selected_context_bytes(state: &AdmissionState) -> u64 {
    state
        .queue
        .iter()
        .map(|leaf| leaf.request.context_bytes)
        .chain(state.active.values().map(|leaf| leaf.request.context_bytes))
        .chain(
            state
                .draining
                .values()
                .map(|leaf| leaf.request.context_bytes),
        )
        .fold(0_u64, u64::saturating_add)
}

fn selected_artifact_bytes(state: &AdmissionState) -> u64 {
    state
        .queue
        .iter()
        .map(|leaf| leaf.request.estimated_artifact_bytes)
        .chain(
            state
                .active
                .values()
                .map(|leaf| leaf.request.estimated_artifact_bytes),
        )
        .chain(
            state
                .draining
                .values()
                .map(|leaf| leaf.request.estimated_artifact_bytes),
        )
        .fold(0_u64, u64::saturating_add)
}

fn can_fit(state: &AdmissionState, request: &ManagedAdmissionRequestV1) -> bool {
    if state.active.len().saturating_add(state.draining.len()) >= state.config.global_max_active {
        return false;
    }
    request.lanes.iter().all(|required| {
        let used: usize = state
            .active
            .values()
            .chain(state.draining.values())
            .flat_map(|leaf| leaf.request.lanes.iter())
            .filter(|lane| lane.lane == required.lane)
            .map(|lane| lane.units)
            .sum();
        state
            .config
            .lane_caps
            .get(&required.lane)
            .is_some_and(|cap| used.saturating_add(required.units) <= *cap)
    })
}

fn next_admissible_ticket(state: &AdmissionState) -> Option<u64> {
    [
        ManagedQueueClassV1::Interactive,
        ManagedQueueClassV1::Normal,
    ]
    .into_iter()
    .find_map(|class| {
        state
            .queue
            .iter()
            .find(|queued| queued.request.queue_class == class && can_fit(state, &queued.request))
            .map(|queued| queued.ticket)
    })
}

/// RAII physical reservation. Normal drop releases capacity; callers must
/// explicitly convert an ambiguous cancelled request to draining first.
pub struct ManagedReservation {
    domain: ManagedAdmissionDomain,
    operation_id: String,
    released: bool,
}

impl ManagedReservation {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Charge one physical attempt before dispatch. Even an over-budget attempt
    /// increments cumulative accounting and is denied before the effect.
    pub fn charge_attempt(
        &self,
        wall_time_ms: u64,
        tokens: u64,
        cost_microunits: u64,
        artifact_bytes: u64,
        context_bytes: u64,
    ) -> Result<ManagedUsageV1, ManagedAdmissionError> {
        self.domain.charge(
            &self.operation_id,
            UsageDelta {
                attempts: 1,
                wall_time_ms,
                tokens,
                cost_microunits,
                artifact_bytes,
                context_bytes,
            },
        )
    }

    /// Settle usage observed after an already charged attempt without incrementing
    /// the attempt count a second time.
    pub fn settle_usage(
        &self,
        wall_time_ms: u64,
        tokens: u64,
        cost_microunits: u64,
        artifact_bytes: u64,
        context_bytes: u64,
    ) -> Result<ManagedUsageV1, ManagedAdmissionError> {
        self.domain.charge(
            &self.operation_id,
            UsageDelta {
                attempts: 0,
                wall_time_ms,
                tokens,
                cost_microunits,
                artifact_bytes,
                context_bytes,
            },
        )
    }

    /// Mark the exact provider request as physically in flight while retaining
    /// the active leaf and lane reservations.
    pub fn mark_provider_in_flight(&self) -> Result<(), ManagedAdmissionError> {
        self.domain.set_provider_in_flight(&self.operation_id, true)
    }

    /// Record observed provider return/termination. This does not itself release
    /// the leaf; normal completion or draining reconciliation owns release.
    pub fn mark_provider_complete(&self) -> Result<(), ManagedAdmissionError> {
        self.domain
            .set_provider_in_flight(&self.operation_id, false)
    }

    /// Retain capacity after cancellation when provider/worker stop is not yet
    /// observed. Only explicit reconciliation releases a draining reservation.
    pub fn mark_draining(mut self) -> Result<(), ManagedAdmissionError> {
        self.domain.move_to_draining(&self.operation_id)?;
        self.released = true;
        Ok(())
    }

    /// Release a normally completed physical leaf.
    pub fn release(mut self) -> Result<(), ManagedAdmissionError> {
        self.domain.release_active(&self.operation_id)?;
        self.released = true;
        Ok(())
    }
}

impl Drop for ManagedReservation {
    fn drop(&mut self) {
        if !self.released {
            if self.domain.release_active(&self.operation_id).is_err() {
                // A concurrent cancellation may have moved the reservation to
                // draining. Reaching Drop means the synchronous worker has now
                // returned, so reconciliation may safely release it only when
                // provider liveness was also observed complete.
                let _ = self.domain.reconcile_draining(&self.operation_id);
            }
            self.released = true;
        }
    }
}
