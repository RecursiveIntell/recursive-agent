use chrono::{DateTime, TimeDelta, Utc};
use recursive_agent_contracts::{
    content_digest, derive_run_id, derive_step_id, RunSpecV1, StepSpecV1, ToolCallSpecV1,
};
use recursive_agent_policy::{
    ActorPrincipalV1, DelegatedActionV1, DelegationCeilingV1, DelegationTransitionV1,
    DurablePermitStore, EffectScopeV1, PermitBindingV1, PermitBudgetV1, PermitRevocationReasonV1,
};
use recursive_agent_policy::{ExecutionPermitV1, PolicyError};
use std::sync::atomic::{AtomicUsize, Ordering};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn permit_store(path: &std::path::Path) -> Result<DurablePermitStore, Box<dyn std::error::Error>> {
    let root = std::fs::File::open(path)?;
    Ok(DurablePermitStore::from_dir_fd(&root)?)
}

fn dispatch_for_test<T>(
    store: &DurablePermitStore,
    permit: &ExecutionPermitV1,
    binding: &PermitBindingV1,
    now: DateTime<Utc>,
    effect: impl FnOnce() -> T,
) -> Result<T, PolicyError> {
    let _consumed_evidence = store.consume(&permit.permit_id, binding, now)?;
    Ok(effect())
}

fn now() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_700_000_000)
}

fn binding() -> Result<PermitBindingV1, Box<dyn std::error::Error>> {
    let call = ToolCallSpecV1 {
        tool: "echo".into(),
        args: serde_json::json!({"text": "x"}),
        frozen_clock: Some(now()),
    };
    let spec = RunSpecV1 {
        name: "dispatch".into(),
        steps: vec![StepSpecV1 {
            name: "effect".into(),
            call: call.clone(),
        }],
        frozen_clock: Some(now()),
        policy_version: "policy-v1".into(),
    };
    let run_id = derive_run_id(&spec)?;
    let step_id = derive_step_id(&run_id, 0, "effect", &call)?;
    let effect = EffectScopeV1 {
        scope_name: "pure".into(),
        read_roots: vec![],
        write_roots: vec![],
        network_allowed: false,
    };
    Ok(PermitBindingV1 {
        actor: ActorPrincipalV1::try_new("actor:test")?,
        action_digest: content_digest(&call)?,
        effect_digest: content_digest(&effect)?,
        effect,
        budget: PermitBudgetV1 {
            max_wall_time_ms: 100,
            max_output_bytes: 100,
            max_artifact_bytes: 100,
        },
        policy_version: "policy-v1".into(),
        parent_permit_id: None,
        parent_operation_id: Some(run_id.clone()),
        issued_at: now(),
        not_before: now(),
        expires_at: now() + TimeDelta::seconds(10),
        run_id,
        step_id,
        tool: "echo".into(),
        args_digest: content_digest(&serde_json::json!({"text": "x"}))?,
    })
}

#[test]
fn every_rejected_lease_keeps_dispatch_counter_zero() -> TestResult {
    for mutation in [
        "actor", "action", "effect", "budget", "parent", "policy", "args",
    ] {
        let root = tempfile::tempdir()?;
        let store = permit_store(root.path())?;
        let authorized = binding()?;
        let permit = store.issue(&authorized, now())?;
        let mut changed = authorized.clone();
        match mutation {
            "actor" => changed.actor = ActorPrincipalV1::try_new("actor:other")?,
            "action" => changed.action_digest = content_digest(&"other")?,
            "effect" => {
                changed.effect.scope_name = "changed".into();
                changed.effect_digest = content_digest(&changed.effect)?;
            }
            "budget" => changed.budget.max_wall_time_ms += 1,
            "parent" => changed.parent_operation_id = None,
            "policy" => changed.policy_version = "other".into(),
            "args" => changed.args_digest = content_digest(&"other")?,
            _ => unreachable!(),
        }
        let counter = AtomicUsize::new(0);
        assert!(dispatch_for_test(&store, &permit, &changed, now(), || {
            counter.fetch_add(1, Ordering::SeqCst);
        })
        .is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 0, "mutation {mutation}");
    }

    let root = tempfile::tempdir()?;
    let store = permit_store(root.path())?;
    let authorized = binding()?;
    let permit = store.issue(&authorized, now())?;
    store.revoke(&permit.permit_id, PermitRevocationReasonV1::Operator, now())?;
    let counter = AtomicUsize::new(0);
    assert!(dispatch_for_test(&store, &permit, &authorized, now(), || {
        counter.fetch_add(1, Ordering::SeqCst);
    })
    .is_err());
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    let root = tempfile::tempdir()?;
    let store = permit_store(root.path())?;
    let parent_binding = binding()?;
    let mut child_binding = binding()?;
    child_binding.parent_operation_id = Some(parent_binding.run_id.clone());
    let ceiling = DelegationCeilingV1 {
        actor: parent_binding.actor.clone(),
        policy_version: parent_binding.policy_version.clone(),
        run_id: parent_binding.run_id.clone(),
        transition: DelegationTransitionV1::ControlToEffect,
        actions: vec![DelegatedActionV1 {
            tool: child_binding.tool.clone(),
            action_digest: child_binding.action_digest.clone(),
            args_digest: child_binding.args_digest.clone(),
            effect: child_binding.effect.clone(),
            effect_digest: child_binding.effect_digest.clone(),
            executable_authority: Vec::new(),
        }],
        budget: parent_binding.budget.clone(),
        not_before: parent_binding.not_before,
        expires_at: parent_binding.expires_at,
    };
    let parent = store.issue_control(&parent_binding, ceiling, now())?;
    child_binding.parent_permit_id = Some(parent.permit_id.clone());
    let child = store.issue_effect(&child_binding, Vec::new(), now())?;
    store.revoke(&parent.permit_id, PermitRevocationReasonV1::Operator, now())?;
    let counter = AtomicUsize::new(0);
    assert!(
        dispatch_for_test(&store, &child, &child_binding, now(), || {
            counter.fetch_add(1, Ordering::SeqCst);
        })
        .is_err()
    );
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    let root = tempfile::tempdir()?;
    let store = permit_store(root.path())?;
    let authorized = binding()?;
    let permit = store.issue(&authorized, now())?;
    let counter = AtomicUsize::new(0);
    assert!(
        dispatch_for_test(&store, &permit, &authorized, authorized.expires_at, || {
            counter.fetch_add(1, Ordering::SeqCst);
        })
        .is_err()
    );
    assert_eq!(counter.load(Ordering::SeqCst), 0);
    Ok(())
}
