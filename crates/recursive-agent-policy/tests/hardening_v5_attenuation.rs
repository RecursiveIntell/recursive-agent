use chrono::{DateTime, TimeDelta, Utc};
use recursive_agent_contracts::{
    content_digest, derive_run_id, derive_step_id, RunSpecV1, StepSpecV1, ToolCallSpecV1,
};
use recursive_agent_policy::{
    ActorPrincipalV1, DelegatedActionV1, DelegationCeilingV1, DelegationTransitionV1,
    DurablePermitStore, EffectScopeV1, PermitBindingV1, PermitBudgetV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn now() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_700_000_000)
}

fn binding(tool: &str, label: &str) -> Result<PermitBindingV1, Box<dyn std::error::Error>> {
    let call = ToolCallSpecV1 {
        tool: tool.into(),
        args: serde_json::json!({"text": label}),
        frozen_clock: Some(now()),
    };
    let spec = RunSpecV1 {
        name: "attenuation-red".into(),
        steps: vec![StepSpecV1 {
            name: label.into(),
            call: call.clone(),
        }],
        frozen_clock: Some(now()),
        policy_version: "policy-v1".into(),
    };
    let run_id = derive_run_id(&spec)?;
    let step_id = derive_step_id(&run_id, 0, label, &call)?;
    let effect = EffectScopeV1 {
        scope_name: tool.into(),
        read_roots: Vec::new(),
        write_roots: Vec::new(),
        network_allowed: false,
    };
    Ok(PermitBindingV1 {
        actor: ActorPrincipalV1::try_new("actor:parent")?,
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
        expires_at: now() + TimeDelta::seconds(5),
        run_id,
        step_id,
        tool: tool.into(),
        args_digest: content_digest(&call.args)?,
    })
}

fn child_of(
    parent: &recursive_agent_policy::ExecutionPermitV1,
    parent_binding: &PermitBindingV1,
    label: &str,
) -> Result<PermitBindingV1, Box<dyn std::error::Error>> {
    let mut child = binding("echo", label)?;
    child.run_id = parent_binding.run_id.clone();
    child.parent_permit_id = Some(parent.permit_id.clone());
    child.parent_operation_id = Some(parent_binding.run_id.clone());
    Ok(child)
}

fn issue_parent(
    store: &DurablePermitStore,
    parent_binding: &PermitBindingV1,
    allowed_child: &PermitBindingV1,
) -> Result<recursive_agent_policy::ExecutionPermitV1, Box<dyn std::error::Error>> {
    let ceiling = DelegationCeilingV1 {
        actor: parent_binding.actor.clone(),
        policy_version: parent_binding.policy_version.clone(),
        run_id: parent_binding.run_id.clone(),
        transition: DelegationTransitionV1::ControlToEffect,
        actions: vec![DelegatedActionV1 {
            tool: allowed_child.tool.clone(),
            action_digest: allowed_child.action_digest.clone(),
            args_digest: allowed_child.args_digest.clone(),
            effect: allowed_child.effect.clone(),
            effect_digest: allowed_child.effect_digest.clone(),
            executable_authority: Vec::new(),
        }],
        budget: parent_binding.budget.clone(),
        not_before: parent_binding.not_before,
        expires_at: parent_binding.expires_at,
    };
    Ok(store.issue_control(parent_binding, ceiling, now())?)
}

#[test]
fn later_wider_and_unrelated_children_are_denied() -> TestResult {
    for mutation in [
        "expiry", "budget", "actor", "policy", "tool", "effect", "run",
    ] {
        let root = tempfile::tempdir()?;
        let root_file = std::fs::File::open(root.path())?;
        let store = DurablePermitStore::from_dir_fd(&root_file)?;
        let parent_binding = binding("runner.lifecycle", "parent")?;
        let prototype = binding("echo", "child")?;
        let parent = issue_parent(&store, &parent_binding, &prototype)?;
        let mut child = child_of(&parent, &parent_binding, "child")?;
        match mutation {
            "expiry" => child.expires_at = parent_binding.expires_at + TimeDelta::seconds(1),
            "budget" => child.budget.max_output_bytes = parent_binding.budget.max_output_bytes + 1,
            "actor" => child.actor = ActorPrincipalV1::try_new("actor:other")?,
            "policy" => child.policy_version = "policy-v2".into(),
            "tool" => child.tool = "shell".into(),
            "effect" => {
                child.effect.read_roots = vec!["/tmp".into()];
                child.effect_digest = content_digest(&child.effect)?;
            }
            "run" => child.parent_operation_id = None,
            _ => return Err("unknown mutation".into()),
        }
        assert!(
            store.issue_effect(&child, Vec::new(), now()).is_err(),
            "unsafe child mutation {mutation} was admitted"
        );
    }
    Ok(())
}

#[test]
fn cumulative_children_cannot_overallocate_parent_budget() -> TestResult {
    let root = tempfile::tempdir()?;
    let root_file = std::fs::File::open(root.path())?;
    let store = DurablePermitStore::from_dir_fd(&root_file)?;
    let mut parent_binding = binding("runner.lifecycle", "parent")?;
    parent_binding.budget.max_output_bytes = 100;
    let prototype = binding("echo", "first")?;
    let parent = issue_parent(&store, &parent_binding, &prototype)?;
    let mut first = child_of(&parent, &parent_binding, "first")?;
    first.budget.max_output_bytes = 75;
    let mut second = child_of(&parent, &parent_binding, "first")?;
    second.step_id = binding("echo", "second")?.step_id;
    second.budget.max_output_bytes = 75;
    assert!(store.issue_effect(&first, Vec::new(), now()).is_ok());
    assert!(
        store.issue_effect(&second, Vec::new(), now()).is_err(),
        "cumulative allocation exceeded the parent's durable budget"
    );
    Ok(())
}

#[test]
fn consumed_child_cannot_dispatch_after_parent_expiry() -> TestResult {
    let root = tempfile::tempdir()?;
    let root_file = std::fs::File::open(root.path())?;
    let store = DurablePermitStore::from_dir_fd(&root_file)?;
    let mut parent_binding = binding("runner.lifecycle", "parent")?;
    parent_binding.expires_at = now() + TimeDelta::milliseconds(50);
    let mut prototype = binding("echo", "child")?;
    prototype.expires_at = parent_binding.expires_at;
    let parent = issue_parent(&store, &parent_binding, &prototype)?;
    let mut child = child_of(&parent, &parent_binding, "child")?;
    child.expires_at = parent_binding.expires_at;
    let child_permit = store.issue_effect(&child, Vec::new(), now())?;
    let _consumed = store.consume(&child_permit.permit_id, &child, now())?;
    let starts = std::sync::atomic::AtomicUsize::new(0);
    let dispatch_time = parent_binding.expires_at;
    if store
        .validate_parent_authority(&child_permit.permit_id, dispatch_time)
        .is_ok()
    {
        starts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    assert_eq!(starts.load(std::sync::atomic::Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn retry_after_parent_reservation_does_not_double_count_child_budget() -> TestResult {
    let root = tempfile::tempdir()?;
    let root_file = std::fs::File::open(root.path())?;
    let store = DurablePermitStore::from_dir_fd(&root_file)?;
    let parent_binding = binding("runner.lifecycle", "parent")?;
    let prototype = binding("echo", "child")?;
    let parent = issue_parent(&store, &parent_binding, &prototype)?;
    let child = child_of(&parent, &parent_binding, "child")?;

    let first = store.issue_effect(&child, Vec::new(), now())?;
    let state_name = format!("permit-{}.json", content_digest(&first.permit_id)?.hex());
    std::fs::remove_file(root.path().join(state_name))?;

    let retried = store.issue_effect(&child, Vec::new(), now())?;
    assert_eq!(retried.permit_id, first.permit_id);
    let parent_state = store.state(&parent.permit_id)?;
    assert_eq!(parent_state.child_allocations.len(), 1);
    assert_eq!(
        parent_state.child_allocations.get(&first.permit_id),
        Some(&child.budget)
    );
    assert!(store.state(&first.permit_id).is_ok());
    Ok(())
}
