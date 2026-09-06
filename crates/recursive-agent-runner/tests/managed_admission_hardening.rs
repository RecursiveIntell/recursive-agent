#![allow(clippy::unwrap_used, clippy::expect_used)]

use llm_tool_runtime::{ToolRegistry, ToolRuntime};
use recursive_agent_runner::{
    Clock, ManagedAdmissionConfigV1, ManagedAdmissionDomain, ManagedAdmissionError,
    ManagedAdmissionRequestV1, ManagedBudgetV1, ManagedQueueClassV1, RuntimeDependencies,
    RuntimeLedgerDependencyV1, RuntimePolicyDependencyV1, RuntimeProviderDependencyV1,
    RuntimeSandboxDependencyV1, RuntimeService, RuntimeStoreDependencyV1,
};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::UNIX_EPOCH
    }

    fn monotonic_now(&self) -> Duration {
        Duration::ZERO
    }
}

fn dependencies(
    root: &std::path::Path,
    runtime: Arc<ToolRuntime>,
) -> Result<RuntimeDependencies, Box<dyn std::error::Error>> {
    Ok(RuntimeDependencies::builder()
        .policy(RuntimePolicyDependencyV1::Native)
        .sandbox(RuntimeSandboxDependencyV1::Native)
        .tool_runtime(runtime)
        .provider(RuntimeProviderDependencyV1::Disabled)
        .ledger(RuntimeLedgerDependencyV1::Native)
        .clock(Arc::new(FixedClock))
        .store(RuntimeStoreDependencyV1::Native)
        .output_root(root)
        .build()?)
}

fn request(id: impl Into<String>) -> ManagedAdmissionRequestV1 {
    let mut request = ManagedAdmissionRequestV1::provider(
        id,
        "model:fixture",
        ManagedBudgetV1 {
            max_attempts: 4,
            max_context_bytes: 1_024,
            max_artifact_bytes: 1_024,
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

#[test]
fn managed_runtime_facades_can_share_one_explicit_owner() -> Result<(), Box<dyn std::error::Error>>
{
    let owner = ManagedAdmissionDomain::from_global(1);
    let runtime = Arc::new(ToolRuntime::new(ToolRegistry::new()));
    let first_root = tempfile::tempdir()?;
    let second_root = tempfile::tempdir()?;
    let first = RuntimeService::new_with_managed_admission(
        dependencies(first_root.path(), Arc::clone(&runtime))?,
        owner.clone(),
    );
    let second = RuntimeService::new_with_managed_admission(
        dependencies(second_root.path(), runtime)?,
        owner,
    );

    let first_domain = first.managed_admission_domain();
    let second_domain = second.managed_admission_domain();
    let _held = first_domain.reserve(request("first-service"))?;
    let mut denied = request("second-service");
    denied.queue_timeout_ms = 0;
    assert!(matches!(
        second_domain.reserve(denied),
        Err(ManagedAdmissionError::Capacity { configured: 1 })
    ));
    Ok(())
}

#[test]
fn queued_materialized_context_is_cumulatively_bounded_before_expansion() {
    let mut config = ManagedAdmissionConfigV1::from_global(1);
    config.max_materialized_context_bytes = 100;
    let domain = ManagedAdmissionDomain::with_config(config).unwrap();

    let mut holder = request("holder");
    holder.context_bytes = 20;
    let _held = domain.reserve(holder).unwrap();

    let queued_domain = domain.clone();
    let queued = thread::spawn(move || {
        let mut queued = request("queued-large-context");
        queued.context_bytes = 70;
        queued_domain.reserve(queued)
    });
    wait_until(&domain, || domain.snapshot().unwrap().queued.len() == 1);

    let mut later = request("later-context");
    later.context_bytes = 20;
    assert!(matches!(
        domain.reserve(later),
        Err(ManagedAdmissionError::ContextCapacity {
            requested: 20,
            available: 10
        })
    ));
    assert_eq!(domain.snapshot().unwrap().selected_context_bytes, 90);
    drop(_held);
    let _ = queued.join().unwrap();
}

#[test]
fn artifact_reservation_is_cumulative_and_atomic() {
    let mut config = ManagedAdmissionConfigV1::from_global(2);
    config.max_reserved_artifact_bytes = 100;
    let domain = ManagedAdmissionDomain::with_config(config).unwrap();

    let mut first = request("artifact-one");
    first.estimated_artifact_bytes = 60;
    let _held = domain.reserve(first).unwrap();

    let mut denied = request("artifact-two");
    denied.estimated_artifact_bytes = 50;
    assert!(matches!(
        domain.reserve(denied),
        Err(ManagedAdmissionError::ArtifactCapacity {
            requested: 50,
            available: 40
        })
    ));
    let snapshot = domain.snapshot().unwrap();
    assert_eq!(snapshot.selected_artifact_bytes, 60);
    assert_eq!(snapshot.selected, vec!["artifact-one"]);
}

#[test]
fn interactive_work_gets_the_next_slot_ahead_of_affinity_backlog() {
    let domain = ManagedAdmissionDomain::from_global(1);
    let holder = domain.reserve(request("holder")).unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut workers = Vec::new();

    for id in ["affinity-1", "affinity-2"] {
        let worker_domain = domain.clone();
        let order = Arc::clone(&order);
        workers.push(thread::spawn(move || {
            let reservation = worker_domain.reserve(request(id)).unwrap();
            order.lock().unwrap().push(id);
            reservation.release().unwrap();
        }));
        wait_until(&domain, || {
            domain.snapshot().unwrap().queued.len() == workers.len()
        });
    }

    let interactive_domain = domain.clone();
    let interactive_order = Arc::clone(&order);
    workers.push(thread::spawn(move || {
        let mut interactive = request("interactive");
        interactive.queue_class = ManagedQueueClassV1::Interactive;
        let reservation = interactive_domain.reserve(interactive).unwrap();
        interactive_order.lock().unwrap().push("interactive");
        reservation.release().unwrap();
    }));
    wait_until(&domain, || domain.snapshot().unwrap().queued.len() == 3);

    holder.release().unwrap();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(
        *order.lock().unwrap(),
        vec!["interactive", "affinity-1", "affinity-2"]
    );
}

#[test]
fn submission_and_admission_config_revisions_are_visible_and_stable() {
    let domain = ManagedAdmissionDomain::from_global(1);
    let holder = domain.reserve(request("holder")).unwrap();
    let queued_domain = domain.clone();
    let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let worker_release = Arc::clone(&release);
    let worker = thread::spawn(move || {
        let reservation = queued_domain
            .reserve(request("queued-on-revision-one"))
            .unwrap();
        let (lock, changed) = &*worker_release;
        let mut done = lock.lock().unwrap();
        while !*done {
            done = changed.wait(done).unwrap();
        }
        reservation.release().unwrap();
    });
    wait_until(&domain, || domain.snapshot().unwrap().queued.len() == 1);

    let mut revision_two = ManagedAdmissionConfigV1::from_global(1);
    revision_two.revision = 2;
    domain.reconfigure(revision_two).unwrap();
    holder.release().unwrap();
    wait_until(&domain, || {
        domain.snapshot().unwrap().active == vec!["queued-on-revision-one"]
    });

    let snapshot = domain.snapshot().unwrap();
    assert_eq!(
        snapshot.submitted_config_revisions["queued-on-revision-one"],
        1
    );
    assert_eq!(
        snapshot.admitted_config_revisions["queued-on-revision-one"],
        2
    );
    let (lock, changed) = &*release;
    *lock.lock().unwrap() = true;
    changed.notify_all();
    worker.join().unwrap();
}

#[test]
fn unknown_provider_spend_remains_visible_after_stop_reconciliation() {
    let domain = ManagedAdmissionDomain::from_global(1);
    let reservation = domain.reserve(request("lost-provider")).unwrap();
    reservation.mark_provider_in_flight().unwrap();
    reservation.mark_draining().unwrap();
    assert_eq!(
        domain.snapshot().unwrap().unknown_spend_operations,
        vec!["lost-provider"]
    );
    domain.observe_provider_complete("lost-provider").unwrap();
    domain.reconcile_draining("lost-provider").unwrap();
    let snapshot = domain.snapshot().unwrap();
    assert!(snapshot.draining.is_empty());
    assert_eq!(snapshot.unknown_spend_operations, vec!["lost-provider"]);
}

#[test]
fn family_scope_charges_attempts_across_multiple_children() {
    let domain = ManagedAdmissionDomain::from_global(1);
    for index in 0..2 {
        let mut child = request(format!("child-{index}"));
        child.budget_scope_id = Some("family-root".into());
        child.budget.max_attempts = 2;
        let reservation = domain.reserve(child).unwrap();
        reservation.charge_attempt(1, 1, 0, 0, 0).unwrap();
        reservation.release().unwrap();
    }

    let mut third = request("child-2");
    third.budget_scope_id = Some("family-root".into());
    third.budget.max_attempts = 2;
    let reservation = domain.reserve(third).unwrap();
    assert!(matches!(
        reservation.charge_attempt(1, 1, 0, 0, 0),
        Err(ManagedAdmissionError::BudgetExceeded("attempts"))
    ));
    let snapshot = domain.snapshot().unwrap();
    assert_eq!(snapshot.total_attempts, 3);
    assert_eq!(snapshot.budget_scope_attempts["family-root"], 3);
}

#[test]
fn cancellation_fences_queued_and_future_descendants() {
    let domain = ManagedAdmissionDomain::from_global(1);
    let mut active_request = request("active-child");
    active_request.parent_operation_id = Some("cancelled-parent".into());
    let active = domain.reserve(active_request).unwrap();

    let queued_domain = domain.clone();
    let queued = thread::spawn(move || {
        let mut request = request("queued-child");
        request.parent_operation_id = Some("cancelled-parent".into());
        queued_domain.reserve(request)
    });
    wait_until(&domain, || domain.snapshot().unwrap().queued.len() == 1);

    assert_eq!(
        domain
            .mark_descendants_draining("cancelled-parent")
            .unwrap(),
        2
    );
    assert!(matches!(
        queued.join().unwrap(),
        Err(ManagedAdmissionError::ParentFenced(parent)) if parent == "cancelled-parent"
    ));
    let mut future = request("future-child");
    future.parent_operation_id = Some("cancelled-parent".into());
    assert!(matches!(
        domain.reserve(future),
        Err(ManagedAdmissionError::ParentFenced(parent)) if parent == "cancelled-parent"
    ));
    let snapshot = domain.snapshot().unwrap();
    assert_eq!(snapshot.draining, vec!["active-child"]);
    assert_eq!(snapshot.cancelled, vec!["active-child", "queued-child"]);
    drop(active);
    assert!(domain.snapshot().unwrap().draining.is_empty());
}

#[test]
fn opposite_lane_order_contention_has_no_partial_claim_or_deadlock() {
    let mut config = ManagedAdmissionConfigV1::from_global(2);
    config.lane_caps.insert("gpu".into(), 1);
    config.lane_caps.insert("provider".into(), 1);
    let domain = ManagedAdmissionDomain::with_config(config).unwrap();

    let mut first_request = request("provider-then-gpu");
    first_request
        .lanes
        .push(recursive_agent_runner::LaneRequirementV1 {
            lane: "gpu".into(),
            units: 1,
        });
    let first = domain.reserve(first_request).unwrap();

    let second_domain = domain.clone();
    let second = thread::spawn(move || {
        let mut reverse = request("gpu-then-provider");
        reverse.lanes = vec![
            recursive_agent_runner::LaneRequirementV1 {
                lane: "gpu".into(),
                units: 1,
            },
            recursive_agent_runner::LaneRequirementV1 {
                lane: "provider".into(),
                units: 1,
            },
        ];
        let reservation = second_domain.reserve(reverse).unwrap();
        reservation.release().unwrap();
    });
    wait_until(&domain, || domain.snapshot().unwrap().queued.len() == 1);
    let blocked = domain.snapshot().unwrap();
    assert_eq!(blocked.active, vec!["provider-then-gpu"]);
    assert_eq!(blocked.queued, vec!["gpu-then-provider"]);
    assert_eq!(blocked.lane_active_units["provider"], 1);
    assert_eq!(blocked.lane_active_units["gpu"], 1);

    first.release().unwrap();
    second.join().unwrap();
    assert!(domain.snapshot().unwrap().active.is_empty());
}

#[test]
fn external_host_process_remains_observed_but_unmanaged() -> Result<(), Box<dyn std::error::Error>>
{
    let mut child = std::process::Command::new("sh")
        .args(["-c", "exec sleep 2"])
        .spawn()?;
    assert!(child.try_wait()?.is_none());

    let domain = ManagedAdmissionDomain::from_global(10);
    let snapshot = domain.snapshot()?;
    assert_eq!(
        snapshot.enforcement_scope,
        "managed_native_physical_leaves_only"
    );
    assert!(!snapshot.unmanaged_host_load_enforced);
    assert!(child.try_wait()?.is_none());

    child.kill()?;
    let _ = child.wait()?;
    Ok(())
}
