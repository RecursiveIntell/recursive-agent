use chrono::{DateTime, TimeDelta, Utc};
use proptest::prelude::*;
use recursive_agent_contracts::{
    content_digest, derive_run_id, derive_step_id, RunSpecV1, StepSpecV1, ToolCallSpecV1,
};
use recursive_agent_policy::{
    ActorPrincipalV1, DelegatedActionV1, DelegationCeilingV1, DelegationTransitionV1,
    DurablePermitStore, EffectScopeV1, PermitBindingV1, PermitBudgetV1, PermitEvidenceV1,
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
        audiences: vec![allowed_child.tool.clone()],
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

#[test]
fn persisted_delegation_proof_binds_identity_and_rejects_tampering() -> TestResult {
    let root = tempfile::tempdir()?;
    let root_file = std::fs::File::open(root.path())?;
    let store = DurablePermitStore::from_dir_fd(&root_file)?;
    let parent_binding = binding("runner.lifecycle", "parent")?;
    let prototype = binding("echo", "child")?;
    let parent = issue_parent(&store, &parent_binding, &prototype)?;
    let child_binding = child_of(&parent, &parent_binding, "child")?;
    let child = store.issue_effect(&child_binding, Vec::new(), now())?;
    let parent_evidence = PermitEvidenceV1::from_record(&store.state(&parent.permit_id)?)?;
    let child_evidence = PermitEvidenceV1::from_record(&store.state(&child.permit_id)?)?;

    let child_json = serde_json::to_value(&child_evidence)?;
    let proof = child_json
        .get("delegation_identity")
        .ok_or("delegated child evidence lacks a persisted derivation proof")?;
    assert_eq!(proof["actor"], parent_binding.actor.as_str());
    assert_eq!(proof["delegate"], child_binding.actor.as_str());
    assert_eq!(proof["audience"], child_binding.tool);
    assert_eq!(proof["depth"], 1);

    for (field, value) in [
        ("actor", serde_json::json!("actor:other")),
        ("delegate", serde_json::json!("actor:other")),
        ("audience", serde_json::json!("shell")),
        ("depth", serde_json::json!(2)),
    ] {
        let mut tampered_json = child_json.clone();
        tampered_json["delegation_identity"][field] = value;
        let tampered: PermitEvidenceV1 = serde_json::from_value(tampered_json)?;
        assert!(recursive_agent_policy::validate_delegation_attenuation(
            &parent_evidence,
            &tampered,
            now(),
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn persisted_identity_is_accepted_only_at_its_derived_depth() -> TestResult {
    let root = tempfile::tempdir()?;
    let root_file = std::fs::File::open(root.path())?;
    let store = DurablePermitStore::from_dir_fd(&root_file)?;
    let parent_binding = binding("runner.lifecycle", "parent")?;
    let prototype = binding("echo", "child")?;
    let parent = issue_parent(&store, &parent_binding, &prototype)?;
    let child_binding = child_of(&parent, &parent_binding, "child")?;
    let child = store.issue_effect(&child_binding, Vec::new(), now())?;
    let parent_evidence = PermitEvidenceV1::from_record(&store.state(&parent.permit_id)?)?;
    let child_evidence = PermitEvidenceV1::from_record(&store.state(&child.permit_id)?)?;
    recursive_agent_policy::validate_delegation_attenuation(
        &parent_evidence,
        &child_evidence,
        now(),
    )?;
    Ok(())
}

#[test]
fn nested_controls_are_strictly_attenuated_and_prove_transitive_depth() -> TestResult {
    let root = tempfile::tempdir()?;
    let root_file = std::fs::File::open(root.path())?;
    let store = DurablePermitStore::from_dir_fd(&root_file)?;
    let root_binding = binding("runner.lifecycle", "root")?;
    let leaf_prototype = binding("echo", "leaf")?;
    let root_ceiling = DelegationCeilingV1 {
        actor: root_binding.actor.clone(),
        policy_version: root_binding.policy_version.clone(),
        run_id: root_binding.run_id.clone(),
        transition: DelegationTransitionV1::ControlToControl,
        audiences: vec!["runner.lifecycle".into()],
        actions: vec![DelegatedActionV1 {
            tool: leaf_prototype.tool.clone(),
            action_digest: leaf_prototype.action_digest.clone(),
            args_digest: leaf_prototype.args_digest.clone(),
            effect: leaf_prototype.effect.clone(),
            effect_digest: leaf_prototype.effect_digest.clone(),
            executable_authority: Vec::new(),
        }],
        budget: root_binding.budget.clone(),
        not_before: root_binding.not_before,
        expires_at: root_binding.expires_at,
    };
    let root_control = store.issue_control(&root_binding, root_ceiling, now())?;

    let mut child_binding = binding("runner.lifecycle", "child-control")?;
    child_binding.run_id = root_binding.run_id.clone();
    child_binding.parent_permit_id = Some(root_control.permit_id.clone());
    child_binding.parent_operation_id = Some(root_binding.run_id.clone());
    child_binding.budget.max_output_bytes = 99;
    let child_ceiling = DelegationCeilingV1 {
        actor: child_binding.actor.clone(),
        policy_version: child_binding.policy_version.clone(),
        run_id: child_binding.run_id.clone(),
        transition: DelegationTransitionV1::ControlToEffect,
        audiences: vec!["echo".into()],
        actions: vec![DelegatedActionV1 {
            tool: leaf_prototype.tool.clone(),
            action_digest: leaf_prototype.action_digest.clone(),
            args_digest: leaf_prototype.args_digest.clone(),
            effect: leaf_prototype.effect.clone(),
            effect_digest: leaf_prototype.effect_digest.clone(),
            executable_authority: Vec::new(),
        }],
        budget: child_binding.budget.clone(),
        not_before: child_binding.not_before,
        expires_at: child_binding.expires_at,
    };
    let child_control = store.issue_control(&child_binding, child_ceiling, now())?;

    let mut leaf_binding = child_of(&child_control, &child_binding, "leaf")?;
    leaf_binding.budget.max_output_bytes = 50;
    let leaf = store.issue_effect(&leaf_binding, Vec::new(), now())?;
    let root_evidence = PermitEvidenceV1::from_record(&store.state(&root_control.permit_id)?)?;
    let child_evidence = PermitEvidenceV1::from_record(&store.state(&child_control.permit_id)?)?;
    let leaf_evidence = PermitEvidenceV1::from_record(&store.state(&leaf.permit_id)?)?;
    recursive_agent_policy::validate_delegation_attenuation(
        &root_evidence,
        &child_evidence,
        now(),
    )?;
    recursive_agent_policy::validate_delegation_attenuation(
        &child_evidence,
        &leaf_evidence,
        now(),
    )?;
    let child_identity = child_evidence
        .delegation_identity
        .as_ref()
        .ok_or("child control evidence lacks delegation identity")?;
    let leaf_identity = leaf_evidence
        .delegation_identity
        .as_ref()
        .ok_or("leaf effect evidence lacks delegation identity")?;
    assert_eq!(child_identity.depth, 1);
    assert_eq!(leaf_identity.depth, 2);
    Ok(())
}

#[test]
fn nested_control_with_extra_audience_is_denied() -> TestResult {
    let root = tempfile::tempdir()?;
    let root_file = std::fs::File::open(root.path())?;
    let store = DurablePermitStore::from_dir_fd(&root_file)?;
    let root_binding = binding("runner.lifecycle", "root")?;
    let leaf_prototype = binding("echo", "leaf")?;
    let root_ceiling = DelegationCeilingV1 {
        actor: root_binding.actor.clone(),
        policy_version: root_binding.policy_version.clone(),
        run_id: root_binding.run_id.clone(),
        transition: DelegationTransitionV1::ControlToControl,
        audiences: vec!["runner.lifecycle".into()],
        actions: vec![DelegatedActionV1 {
            tool: leaf_prototype.tool.clone(),
            action_digest: leaf_prototype.action_digest.clone(),
            args_digest: leaf_prototype.args_digest.clone(),
            effect: leaf_prototype.effect.clone(),
            effect_digest: leaf_prototype.effect_digest.clone(),
            executable_authority: Vec::new(),
        }],
        budget: root_binding.budget.clone(),
        not_before: root_binding.not_before,
        expires_at: root_binding.expires_at,
    };
    let root_control = store.issue_control(&root_binding, root_ceiling, now())?;

    let mut child_binding = binding("runner.lifecycle", "child-control")?;
    child_binding.run_id = root_binding.run_id.clone();
    child_binding.parent_permit_id = Some(root_control.permit_id.clone());
    child_binding.parent_operation_id = Some(root_binding.run_id.clone());
    child_binding.budget.max_output_bytes = 99;
    let child_ceiling = DelegationCeilingV1 {
        actor: child_binding.actor.clone(),
        policy_version: child_binding.policy_version.clone(),
        run_id: child_binding.run_id.clone(),
        transition: DelegationTransitionV1::ControlToEffect,
        audiences: vec!["echo".into(), "shell".into()],
        actions: vec![DelegatedActionV1 {
            tool: leaf_prototype.tool.clone(),
            action_digest: leaf_prototype.action_digest.clone(),
            args_digest: leaf_prototype.args_digest.clone(),
            effect: leaf_prototype.effect.clone(),
            effect_digest: leaf_prototype.effect_digest.clone(),
            executable_authority: Vec::new(),
        }],
        budget: child_binding.budget.clone(),
        not_before: child_binding.not_before,
        expires_at: child_binding.expires_at,
    };

    assert!(
        store
            .issue_control(&child_binding, child_ceiling, now())
            .is_err(),
        "a child control may not introduce a new audience"
    );
    Ok(())
}

fn widened_budget_child_is_rejected(extra: u64) -> TestResult {
    let root = tempfile::tempdir()?;
    let root_file = std::fs::File::open(root.path())?;
    let store = DurablePermitStore::from_dir_fd(&root_file)?;
    let parent_binding = binding("runner.lifecycle", "parent")?;
    let prototype = binding("echo", "child")?;
    let parent = issue_parent(&store, &parent_binding, &prototype)?;
    let mut child = child_of(&parent, &parent_binding, "child")?;
    child.budget.max_output_bytes = parent_binding
        .budget
        .max_output_bytes
        .checked_add(extra)
        .ok_or("test budget overflow")?;
    if store.issue_effect(&child, Vec::new(), now()).is_ok() {
        return Err("a child effect with a wider budget was admitted".into());
    }
    Ok(())
}

fn nested_control_with_added_audience_is_rejected(extra_audience: String) -> TestResult {
    let root = tempfile::tempdir()?;
    let root_file = std::fs::File::open(root.path())?;
    let store = DurablePermitStore::from_dir_fd(&root_file)?;
    let root_binding = binding("runner.lifecycle", "root")?;
    let leaf_prototype = binding("echo", "leaf")?;
    let root_ceiling = DelegationCeilingV1 {
        actor: root_binding.actor.clone(),
        policy_version: root_binding.policy_version.clone(),
        run_id: root_binding.run_id.clone(),
        transition: DelegationTransitionV1::ControlToControl,
        audiences: vec!["runner.lifecycle".into()],
        actions: vec![DelegatedActionV1 {
            tool: leaf_prototype.tool.clone(),
            action_digest: leaf_prototype.action_digest.clone(),
            args_digest: leaf_prototype.args_digest.clone(),
            effect: leaf_prototype.effect.clone(),
            effect_digest: leaf_prototype.effect_digest.clone(),
            executable_authority: Vec::new(),
        }],
        budget: root_binding.budget.clone(),
        not_before: root_binding.not_before,
        expires_at: root_binding.expires_at,
    };
    let root_control = store.issue_control(&root_binding, root_ceiling, now())?;

    let mut child_binding = binding("runner.lifecycle", "child-control")?;
    child_binding.run_id = root_binding.run_id.clone();
    child_binding.parent_permit_id = Some(root_control.permit_id.clone());
    child_binding.parent_operation_id = Some(root_binding.run_id.clone());
    child_binding.budget.max_output_bytes = 99;
    let mut audiences = vec!["echo".into(), extra_audience];
    audiences.sort();
    let child_ceiling = DelegationCeilingV1 {
        actor: child_binding.actor.clone(),
        policy_version: child_binding.policy_version.clone(),
        run_id: child_binding.run_id.clone(),
        transition: DelegationTransitionV1::ControlToEffect,
        audiences,
        actions: vec![DelegatedActionV1 {
            tool: leaf_prototype.tool.clone(),
            action_digest: leaf_prototype.action_digest.clone(),
            args_digest: leaf_prototype.args_digest.clone(),
            effect: leaf_prototype.effect.clone(),
            effect_digest: leaf_prototype.effect_digest.clone(),
            executable_authority: Vec::new(),
        }],
        budget: child_binding.budget.clone(),
        not_before: child_binding.not_before,
        expires_at: child_binding.expires_at,
    };
    if store
        .issue_control(&child_binding, child_ceiling, now())
        .is_ok()
    {
        return Err("a child control with an extra audience was admitted".into());
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn any_positive_effect_budget_widening_is_rejected(extra in 1_u64..10_000) {
        prop_assert!(widened_budget_child_is_rejected(extra).is_ok());
    }

    #[test]
    fn any_added_child_control_audience_is_rejected(extra_audience in "[a-z]{1,16}") {
        prop_assume!(extra_audience != "echo");
        prop_assert!(nested_control_with_added_audience_is_rejected(extra_audience).is_ok());
    }
}
