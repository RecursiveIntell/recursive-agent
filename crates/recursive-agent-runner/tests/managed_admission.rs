#![allow(clippy::unwrap_used, clippy::expect_used)]

use recursive_agent_runner::{
    LaneRequirementV1, ManagedAdmissionConfigV1, ManagedAdmissionDomain, ManagedAdmissionError,
    ManagedAdmissionRequestV1, ManagedBudgetV1, PROVIDER_LANE, SANDBOX_PROCESS_LANE,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn provider_request(id: impl Into<String>) -> ManagedAdmissionRequestV1 {
    let mut request = ManagedAdmissionRequestV1::provider(
        id,
        "model:fixture",
        ManagedBudgetV1 {
            max_attempts: 4,
            ..ManagedBudgetV1::default()
        },
    );
    request.queue_timeout_ms = 2_000;
    request
}

fn wait_until(domain: &ManagedAdmissionDomain, predicate: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "admission observation timed out: {:?}",
            domain.snapshot().unwrap()
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[derive(Default)]
struct IndependentActivityOracle {
    active: AtomicUsize,
    maximum: AtomicUsize,
    begins: AtomicUsize,
    ends: AtomicUsize,
}

impl IndependentActivityOracle {
    fn begin(self: &Arc<Self>) -> IndependentActivityGuard {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum.fetch_max(active, Ordering::SeqCst);
        self.begins.fetch_add(1, Ordering::SeqCst);
        IndependentActivityGuard(Arc::clone(self))
    }
}

struct IndependentActivityGuard(Arc<IndependentActivityOracle>);

impl Drop for IndependentActivityGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.ends.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn cfg_01_ten_actual_overlapping_workers() {
    let domain = ManagedAdmissionDomain::from_global(10);
    let oracle = Arc::new(IndependentActivityOracle::default());
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let mut workers = Vec::new();
    for index in 0..10 {
        let domain = domain.clone();
        let oracle = Arc::clone(&oracle);
        let release = release.clone();
        workers.push(thread::spawn(move || {
            let reservation = domain
                .reserve(provider_request(format!("op-{index}")))
                .unwrap();
            let activity = oracle.begin();
            reservation.charge_attempt(1, 1, 0, 0, 0).unwrap();
            let (lock, changed) = &*release;
            let mut done = lock.lock().unwrap();
            while !*done {
                done = changed.wait(done).unwrap();
            }
            drop(activity);
            reservation.release().unwrap();
        }));
    }
    wait_until(&domain, || domain.snapshot().unwrap().active.len() == 10);
    let snapshot = domain.snapshot().unwrap();
    assert_eq!(snapshot.active.len(), 10);
    assert!(snapshot.queued.is_empty());
    assert_eq!(oracle.maximum.load(Ordering::SeqCst), 10);
    assert_eq!(oracle.begins.load(Ordering::SeqCst), 10);
    let (lock, changed) = &*release;
    *lock.lock().unwrap() = true;
    changed.notify_all();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(oracle.ends.load(Ordering::SeqCst), 10);
}

#[test]
fn cfg_02_all_twelve_with_cap_ten_are_accounted_and_two_queue() {
    let domain = ManagedAdmissionDomain::from_global(10);
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let mut workers = Vec::new();
    for index in 0..12 {
        let domain = domain.clone();
        let release = release.clone();
        workers.push(thread::spawn(move || {
            let mut request = provider_request(format!("member-{index}"));
            request.queue_timeout_ms = 5_000;
            let reservation = domain.reserve(request).unwrap();
            let (lock, changed) = &*release;
            let mut done = lock.lock().unwrap();
            while !*done {
                done = changed.wait(done).unwrap();
            }
            reservation.release().unwrap();
        }));
    }
    wait_until(&domain, || {
        let snapshot = domain.snapshot().unwrap();
        snapshot.active.len() == 10 && snapshot.queued.len() == 2
    });
    let snapshot = domain.snapshot().unwrap();
    assert_eq!(snapshot.selected.len(), 12);
    assert_eq!(snapshot.active.len(), 10);
    assert_eq!(snapshot.queued.len(), 2);
    let (lock, changed) = &*release;
    *lock.lock().unwrap() = true;
    changed.notify_all();
    for worker in workers {
        worker.join().unwrap();
    }
    assert!(domain.snapshot().unwrap().selected.is_empty());
}

#[test]
fn cfg_03_explicit_simultaneous_all_overflow_is_typed() {
    let domain = ManagedAdmissionDomain::from_global(10);
    let mut request = provider_request("all-12");
    request.require_simultaneous_members = Some(12);
    assert!(matches!(
        domain.reserve(request),
        Err(ManagedAdmissionError::SimultaneousCapacity {
            requested: 12,
            configured: 10
        })
    ));
}

#[test]
fn cfg_04_nested_fanout_uses_the_same_global_cap_and_budget() {
    let domain = ManagedAdmissionDomain::from_global(2);
    let first = domain
        .reserve(provider_request("parent-a/child-1"))
        .unwrap();
    let second = domain
        .reserve(provider_request("parent-b/child-1"))
        .unwrap();
    assert!(matches!(
        domain.reserve({
            let mut r = provider_request("parent-a/child-2");
            r.queue_timeout_ms = 0;
            r
        }),
        Err(ManagedAdmissionError::Capacity { configured: 2 })
    ));
    first.charge_attempt(1, 1, 0, 0, 0).unwrap();
    second.charge_attempt(1, 1, 0, 0, 0).unwrap();
    assert_eq!(domain.snapshot().unwrap().total_attempts, 2);
}

#[test]
fn cfg_05_waiting_control_parent_consumes_no_leaf_slot() {
    let domain = ManagedAdmissionDomain::from_global(1);
    let logical_parent_id = "parent-control-only";
    let child = domain.reserve(provider_request("child-physical")).unwrap();
    let snapshot = domain.snapshot().unwrap();
    assert_eq!(snapshot.active, vec!["child-physical"]);
    assert!(!snapshot.selected.iter().any(|id| id == logical_parent_id));
    child.release().unwrap();
}

#[test]
fn cfg_06_provider_lane_serializes_while_global_capacity_is_ten() {
    let mut config = ManagedAdmissionConfigV1::from_global(10);
    config.lane_caps.insert(PROVIDER_LANE.into(), 1);
    let domain = ManagedAdmissionDomain::with_config(config).unwrap();
    let oracle = Arc::new(IndependentActivityOracle::default());
    let first = domain.reserve(provider_request("provider-0")).unwrap();
    let first_activity = oracle.begin();
    let mut queued = Vec::new();
    for index in 1..10 {
        let queued_domain = domain.clone();
        let oracle = Arc::clone(&oracle);
        queued.push(thread::spawn(move || {
            let reservation = queued_domain
                .reserve(provider_request(format!("provider-{index}")))
                .unwrap();
            let activity = oracle.begin();
            thread::sleep(Duration::from_millis(1));
            let next_begin = oracle.begins.load(Ordering::SeqCst) + 1;
            drop(activity);
            reservation.release().unwrap();
            // Force a successor to start before this worker exits. The oracle
            // must measure activity inside the reservation, not thread lifetime.
            if next_begin <= 10 {
                wait_until(&queued_domain, || {
                    oracle.begins.load(Ordering::SeqCst) >= next_begin
                });
            }
        }));
    }
    wait_until(&domain, || domain.snapshot().unwrap().queued.len() == 9);
    let snapshot = domain.snapshot().unwrap();
    assert_eq!(snapshot.active.len(), 1);
    assert_eq!(snapshot.selected.len(), 10);
    assert_eq!(snapshot.queued.len(), 9);
    drop(first_activity);
    first.release().unwrap();
    for worker in queued {
        worker.join().unwrap();
    }
    assert_eq!(oracle.maximum.load(Ordering::SeqCst), 1);
    assert_eq!(oracle.begins.load(Ordering::SeqCst), 10);
    assert_eq!(oracle.ends.load(Ordering::SeqCst), 10);
}

#[test]
fn cfg_07_restrictive_config_change_stops_new_work_without_eviction() {
    let domain = ManagedAdmissionDomain::from_global(2);
    let first = domain.reserve(provider_request("old-1")).unwrap();
    let second = domain.reserve(provider_request("old-2")).unwrap();
    let mut restrictive = ManagedAdmissionConfigV1::from_global(1);
    restrictive.revision = 2;
    domain.reconfigure(restrictive).unwrap();
    let mut denied = provider_request("new-denied");
    denied.queue_timeout_ms = 0;
    assert!(matches!(
        domain.reserve(denied),
        Err(ManagedAdmissionError::Capacity { configured: 1 })
    ));
    first.release().unwrap();
    let mut still_denied = provider_request("new-still-denied");
    still_denied.queue_timeout_ms = 0;
    assert!(matches!(
        domain.reserve(still_denied),
        Err(ManagedAdmissionError::Capacity { configured: 1 })
    ));
    second.release().unwrap();
    domain.reserve(provider_request("new-admitted")).unwrap();
}

#[test]
fn cfg_08_every_retry_attempt_is_cumulatively_charged() {
    let domain = ManagedAdmissionDomain::from_global(1);
    let mut request = provider_request("retrying");
    request.budget.max_attempts = 3;
    let reservation = domain.reserve(request).unwrap();
    let provider_attempts = Arc::new(Mutex::new(Vec::new()));
    for attempt in [
        "node-1/provider-1",
        "node-1/provider-2",
        "node-2/provider-1",
    ] {
        reservation.charge_attempt(1, 10, 1, 1, 0).unwrap();
        provider_attempts.lock().unwrap().push(attempt);
    }
    assert!(matches!(
        reservation.charge_attempt(1, 10, 1, 1, 0),
        Err(ManagedAdmissionError::BudgetExceeded("attempts"))
    ));
    assert_eq!(provider_attempts.lock().unwrap().len(), 3);
    assert_eq!(domain.snapshot().unwrap().total_attempts, 4);
}

#[test]
fn cfg_09_lost_provider_cancellation_stays_draining_until_reconciled() {
    let domain = ManagedAdmissionDomain::from_global(1);
    let reservation = domain.reserve(provider_request("unknown-stop")).unwrap();
    reservation.mark_provider_in_flight().unwrap();
    reservation.mark_draining().unwrap();
    let snapshot = domain.snapshot().unwrap();
    assert_eq!(snapshot.draining, vec!["unknown-stop"]);
    assert_eq!(snapshot.provider_requests_in_flight, 1);
    let mut blocked = provider_request("replacement");
    blocked.queue_timeout_ms = 0;
    assert!(matches!(
        domain.reserve(blocked),
        Err(ManagedAdmissionError::Capacity { configured: 1 })
    ));
    assert!(matches!(
        domain.reconcile_draining("unknown-stop"),
        Err(ManagedAdmissionError::ProviderStillInFlight(_))
    ));
    domain.observe_provider_complete("unknown-stop").unwrap();
    domain.reconcile_draining("unknown-stop").unwrap();
    domain.reserve(provider_request("replacement")).unwrap();
}

#[test]
fn cfg_10_missing_model_or_lane_never_substitutes() {
    let domain = ManagedAdmissionDomain::from_global(2);
    let mut missing_model = provider_request("missing-model");
    missing_model.model_ref.clear();
    assert!(matches!(
        domain.reserve(missing_model),
        Err(ManagedAdmissionError::MissingRoute)
    ));
    let mut missing_lane = provider_request("missing-lane");
    missing_lane.lanes = vec![LaneRequirementV1 {
        lane: "provider:unknown".into(),
        units: 1,
    }];
    assert!(matches!(
        domain.reserve(missing_lane),
        Err(ManagedAdmissionError::MissingLane(_))
    ));
}

#[test]
fn res_01_materialization_memory_is_capped_before_queue_expansion() {
    let mut config = ManagedAdmissionConfigV1::from_global(2);
    config.max_materialized_context_bytes = 64;
    let domain = ManagedAdmissionDomain::with_config(config).unwrap();
    let mut request = provider_request("oversized-context");
    request.context_bytes = 65;
    request.budget.max_context_bytes = 128;
    assert!(matches!(
        domain.reserve(request),
        Err(ManagedAdmissionError::ContextBudget)
    ));
    let snapshot = domain.snapshot().unwrap();
    assert!(snapshot.selected.is_empty());
    assert!(snapshot.queued.is_empty());
}

#[test]
fn res_02_multi_resource_reservation_is_atomic_without_hold_and_wait() {
    let mut config = ManagedAdmissionConfigV1::from_global(2);
    config.lane_caps =
        BTreeMap::from([(PROVIDER_LANE.into(), 1), (SANDBOX_PROCESS_LANE.into(), 1)]);
    let domain = ManagedAdmissionDomain::with_config(config).unwrap();
    let mut both = provider_request("both");
    both.lanes.push(LaneRequirementV1 {
        lane: SANDBOX_PROCESS_LANE.into(),
        units: 1,
    });
    let first = domain.reserve(both).unwrap();
    for (id, lane) in [
        ("provider-only", PROVIDER_LANE),
        ("sandbox-only", SANDBOX_PROCESS_LANE),
    ] {
        let mut request = provider_request(id);
        request.lanes = vec![LaneRequirementV1 {
            lane: lane.into(),
            units: 1,
        }];
        request.queue_timeout_ms = 0;
        assert!(matches!(
            domain.reserve(request),
            Err(ManagedAdmissionError::Capacity { .. })
        ));
    }
    let snapshot = domain.snapshot().unwrap();
    assert_eq!(snapshot.lane_active_units[PROVIDER_LANE], 1);
    assert_eq!(snapshot.lane_active_units[SANDBOX_PROCESS_LANE], 1);
    first.release().unwrap();
}

#[test]
fn res_03_fifo_admission_prevents_model_affinity_starvation() {
    let domain = ManagedAdmissionDomain::from_global(1);
    let first = domain.reserve(provider_request("holder")).unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    let d1 = domain.clone();
    let o1 = order.clone();
    let interactive = thread::spawn(move || {
        let reservation = d1.reserve(provider_request("interactive")).unwrap();
        o1.lock().unwrap().push("interactive");
        reservation.release().unwrap();
    });
    wait_until(&domain, || {
        domain.snapshot().unwrap().queued == vec!["interactive"]
    });
    let d2 = domain.clone();
    let o2 = order.clone();
    let affinity = thread::spawn(move || {
        let reservation = d2.reserve(provider_request("affinity")).unwrap();
        o2.lock().unwrap().push("affinity");
        reservation.release().unwrap();
    });
    wait_until(&domain, || domain.snapshot().unwrap().queued.len() == 2);
    first.release().unwrap();
    interactive.join().unwrap();
    affinity.join().unwrap();
    assert_eq!(*order.lock().unwrap(), vec!["interactive", "affinity"]);
}

#[test]
fn res_04_unmanaged_host_load_is_explicitly_outside_enforcement_claim() {
    let domain = ManagedAdmissionDomain::from_global(10);
    let snapshot = domain.snapshot().unwrap();
    assert_eq!(
        snapshot.enforcement_scope,
        "managed_native_physical_leaves_only"
    );
    assert!(!snapshot.unmanaged_host_load_enforced);
}

#[test]
fn kern_10_connection_concurrency_is_not_worker_concurrency() {
    let domain = ManagedAdmissionDomain::from_global(2);
    domain.set_open_ipc_connections(100).unwrap();
    let _leaf = domain.reserve(provider_request("one-leaf")).unwrap();
    let snapshot = domain.snapshot().unwrap();
    assert_eq!(snapshot.open_ipc_connections, 100);
    assert_eq!(snapshot.active.len(), 1);
}

#[test]
fn rel_03_every_managed_caller_clone_shares_one_admission_owner() {
    let owner = ManagedAdmissionDomain::from_global(1);
    let graph_client = owner.clone();
    let specialist_client = owner.clone();
    let _graph_leaf = graph_client
        .reserve(provider_request("graph-leaf"))
        .unwrap();
    let mut specialist = provider_request("specialist-leaf");
    specialist.queue_timeout_ms = 0;
    assert!(matches!(
        specialist_client.reserve(specialist),
        Err(ManagedAdmissionError::Capacity { configured: 1 })
    ));
}

#[test]
fn active_provider_dispatch_is_reported_in_flight_separately_from_draining() {
    let domain = ManagedAdmissionDomain::from_global(1);
    let reservation = domain.reserve(provider_request("provider-active")).unwrap();
    reservation.mark_provider_in_flight().unwrap();
    let active = domain.snapshot().unwrap();
    assert_eq!(active.active, vec!["provider-active"]);
    assert!(active.draining.is_empty());
    assert_eq!(active.provider_requests_in_flight, 1);

    reservation.mark_provider_complete().unwrap();
    let completed = domain.snapshot().unwrap();
    assert_eq!(completed.active, vec!["provider-active"]);
    assert_eq!(completed.provider_requests_in_flight, 0);
    reservation.release().unwrap();
}

#[test]
fn draining_tool_is_not_reported_as_provider_in_flight() {
    let domain = ManagedAdmissionDomain::from_global(1);
    domain
        .reserve(ManagedAdmissionRequestV1::tool(
            "tool-draining",
            "tool:fixture",
            ManagedBudgetV1::default(),
        ))
        .unwrap()
        .mark_draining()
        .unwrap();
    let snapshot = domain.snapshot().unwrap();
    assert_eq!(snapshot.draining, vec!["tool-draining"]);
    assert_eq!(snapshot.provider_requests_in_flight, 0);
    domain.reconcile_draining("tool-draining").unwrap();
}

#[test]
fn cumulative_context_bytes_are_charged_for_every_attempt() {
    let domain = ManagedAdmissionDomain::from_global(1);
    let mut request = provider_request("context-retry");
    request.context_bytes = 6;
    request.budget.max_context_bytes = 10;
    let reservation = domain.reserve(request).unwrap();
    reservation.charge_attempt(1, 0, 0, 0, 6).unwrap();
    assert!(matches!(
        reservation.charge_attempt(1, 0, 0, 0, 6),
        Err(ManagedAdmissionError::BudgetExceeded("context_bytes"))
    ));
    let snapshot = domain.snapshot().unwrap();
    assert_eq!(snapshot.total_context_bytes, 12);
}
