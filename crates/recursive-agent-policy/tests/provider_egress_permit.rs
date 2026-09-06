use chrono::{DateTime, TimeDelta, Utc};
use recursive_agent_contracts::{
    content_digest, derive_run_id, derive_step_id, ProviderEgressBindingMaterialV1,
    ProviderEgressBindingV1, RunSpecV1, StepSpecV1, ToolCallSpecV1,
};
use recursive_agent_policy::{
    authorize_provider_egress, ActorPrincipalV1, DelegatedActionV1, DelegationCeilingV1,
    DelegationTransitionV1, DurablePermitStore, EffectScopeV1, PermitBindingV1, PermitBudgetV1,
    PermitEvidenceStateV1, PolicyError, ProviderEgressAdmissionRequestV1,
    ProviderEgressAdmissionVerifier, ValidatedProviderEgressAdmissionV1,
};

fn open_store(path: &std::path::Path) -> Result<DurablePermitStore, PolicyError> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let directory = std::fs::File::from(fd);
    let _ = ResolveFlags::NO_SYMLINKS;
    DurablePermitStore::from_dir_fd(&directory)
}

fn now() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_700_000_000)
}

struct AllowCurrentEgress;

impl ProviderEgressAdmissionVerifier for AllowCurrentEgress {
    fn authorize(
        &self,
        _admission: &ValidatedProviderEgressAdmissionV1,
    ) -> Result<(), PolicyError> {
        Ok(())
    }
}

#[test]
fn only_validated_candidate_egress_can_issue_and_consume_a_network_effect_permit(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let store = open_store(root.path())?;
    let request = serde_json::json!({
        "kind": "ollama",
        "model": "fixture-model",
        "prompt": "exact sealed prompt",
        "max_tokens": 8
    });
    let binding = ProviderEgressBindingV1::seal(ProviderEgressBindingMaterialV1 {
        policy_basis_ref: "policy:fixture".into(),
        policy_basis_digest: format!("sha256:{}", "a".repeat(64)),
        context_digest: format!("sha256:{}", "b".repeat(64)),
        source_revision: "source:fixture".into(),
        graph_obligation_ref: "graph-obligation:node-1".into(),
        graph_obligation_digest: format!("blake3:{}", "c".repeat(64)),
        route_class: "candidate".into(),
        provider_identity: "ollama:http://127.0.0.1:11434".into(),
        model_ref: "model:fixture".into(),
        input_tokens: 4,
        output_reserve: 8,
        request_digest: content_digest(&request)?,
        not_after: now() + TimeDelta::seconds(120),
    })?;
    let tool_args = serde_json::json!({"binding": binding, "request": request});
    let args_digest = content_digest(&tool_args)?;
    let admission_request = ProviderEgressAdmissionRequestV1::new(
        "sealed_completion",
        serde_json::from_value(tool_args["binding"].clone())?,
        content_digest(&tool_args["request"])?,
        args_digest.clone(),
    )?;
    let admission = authorize_provider_egress(&AllowCurrentEgress, &admission_request, now())?;

    let call = ToolCallSpecV1 {
        tool: "sealed_completion".into(),
        args: tool_args,
        frozen_clock: None,
    };
    let spec = RunSpecV1 {
        name: "provider-egress-permit-fixture".into(),
        steps: vec![StepSpecV1 {
            name: "sealed_completion".into(),
            call: call.clone(),
        }],
        frozen_clock: None,
        policy_version: "candidate-egress-v1".into(),
    };
    let run_id = derive_run_id(&spec)?;
    let step_id = derive_step_id(&run_id, 0, "sealed_completion", &call)?;
    let effect = EffectScopeV1 {
        scope_name: "sealed_completion".into(),
        read_roots: Vec::new(),
        write_roots: Vec::new(),
        network_allowed: true,
    };
    let budget = PermitBudgetV1 {
        max_wall_time_ms: 1_000,
        max_output_bytes: 4_096,
        max_artifact_bytes: 4_096,
    };
    let lifecycle_call = ToolCallSpecV1 {
        tool: "runner.lifecycle".into(),
        args: serde_json::json!({"operation": "provider-egress-v3"}),
        frozen_clock: None,
    };
    let lifecycle_step_id = derive_step_id(&run_id, 1, "run-lifecycle", &lifecycle_call)?;
    let lifecycle_effect = EffectScopeV1 {
        scope_name: "runner.lifecycle".into(),
        read_roots: Vec::new(),
        write_roots: Vec::new(),
        network_allowed: false,
    };
    let actor = ActorPrincipalV1::try_new("recursive-agent")?;
    let control_binding = PermitBindingV1 {
        actor: actor.clone(),
        action_digest: content_digest(&lifecycle_call)?,
        effect_digest: content_digest(&lifecycle_effect)?,
        effect: lifecycle_effect,
        budget: budget.clone(),
        policy_version: "candidate-egress-v1".into(),
        parent_permit_id: None,
        parent_operation_id: Some(run_id.clone()),
        issued_at: now(),
        not_before: now(),
        expires_at: now() + TimeDelta::seconds(60),
        run_id: run_id.clone(),
        step_id: lifecycle_step_id,
        tool: "runner.lifecycle".into(),
        args_digest: content_digest(&lifecycle_call.args)?,
    };
    let ceiling = DelegationCeilingV1 {
        actor: actor.clone(),
        policy_version: "candidate-egress-v1".into(),
        run_id: run_id.clone(),
        transition: DelegationTransitionV1::ControlToEffect,
        audiences: vec!["sealed_completion".into()],
        actions: vec![DelegatedActionV1 {
            tool: "sealed_completion".into(),
            action_digest: content_digest(&call)?,
            args_digest: args_digest.clone(),
            effect: effect.clone(),
            effect_digest: content_digest(&effect)?,
            executable_authority: Vec::new(),
        }],
        budget: budget.clone(),
        not_before: now(),
        expires_at: now() + TimeDelta::seconds(60),
    };
    let control = store.issue_control(&control_binding, ceiling, now())?;
    let dispatch_time = now() + TimeDelta::milliseconds(1);
    let effect_binding = PermitBindingV1 {
        actor,
        action_digest: content_digest(&call)?,
        effect_digest: content_digest(&effect)?,
        effect,
        budget,
        policy_version: "candidate-egress-v1".into(),
        parent_permit_id: Some(control.permit_id),
        parent_operation_id: Some(run_id.clone()),
        issued_at: dispatch_time,
        not_before: dispatch_time,
        expires_at: now() + TimeDelta::seconds(30),
        run_id,
        step_id,
        tool: "sealed_completion".into(),
        args_digest,
    };

    assert!(store
        .issue_effect(&effect_binding, Vec::new(), now())
        .is_err());
    // Real clocks advance between policy evaluation and durable permit issue.
    // The admission remains valid while its sealed binding remains current.
    let permit = store.issue_provider_egress(&effect_binding, &admission, dispatch_time)?;
    let consumed = store.consume(&permit.permit_id, &effect_binding, dispatch_time)?;
    assert!(matches!(
        consumed.state,
        PermitEvidenceStateV1::Consumed { .. }
    ));
    assert!(consumed.binding.effect.network_allowed);
    Ok(())
}
