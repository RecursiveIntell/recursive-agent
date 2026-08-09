use recursive_agent_contracts::{
    content_digest, derive_child_operation_id, derive_child_operation_material_digest,
    derive_child_operation_proposal_digest, derive_operation_id,
    parse_child_operation_envelope_v2_bytes, parse_child_operation_proposal_v2_bytes,
    parse_operation_envelope_bytes, ActorAuthorityV1, AuthorityOriginV1, CausalLinkV1,
    ChildOperationEnvelopeV2, ChildOperationProposalV2, ChildRunAuthorityV1, ContentDigest,
    CurrentPermitId, CurrentReceiptId, CurrentRunId, DeclaredEffectsV1, OperationBudgetV1,
    OperationEnvelopeV1, OperationSchemaV1, ProvenanceRefV1, ReplayClassV1, ReplayIntentV1,
    ReplaySpecV1, RunSpecV1, StepSpecV1, ToolCallSpecV1,
};

fn root_operation() -> Result<OperationEnvelopeV1, Box<dyn std::error::Error>> {
    let run_spec = RunSpecV1 {
        name: "phase7-root".into(),
        steps: vec![StepSpecV1 {
            name: "echo".into(),
            call: ToolCallSpecV1 {
                tool: "echo".into(),
                args: serde_json::json!({"text": "phase7"}),
                frozen_clock: None,
            },
        }],
        frozen_clock: None,
        policy_version: "policy-v1".into(),
    };
    Ok(OperationEnvelopeV1 {
        schema: OperationSchemaV1::V1,
        actor: ActorAuthorityV1 {
            principal: "actor:phase7".into(),
            origin: AuthorityOriginV1::Direct,
        },
        causality: CausalLinkV1 {
            parent_operation_id: None,
            root_operation_id: None,
        },
        budget: OperationBudgetV1 {
            max_wall_time_ms: 1_000,
            max_output_bytes: 4_096,
            max_artifact_bytes: 4_096,
            max_steps: 1,
        },
        effects: DeclaredEffectsV1 {
            read_roots: Vec::new(),
            write_roots: Vec::new(),
            network_allowed: false,
            action_digest: content_digest(&run_spec)?,
        },
        provenance: vec![ProvenanceRefV1 {
            source: "urn:test:phase7".into(),
            digest: ContentDigest::compute(b"phase7-request"),
        }],
        replay: ReplaySpecV1 {
            class: ReplayClassV1::Deterministic,
            intent: ReplayIntentV1::ExecuteOnce,
        },
        run_spec,
    })
}

#[test]
fn v1_ingress_rejects_a_delegated_v2_shape_without_child_authority(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut candidate = root_operation()?;
    let root = derive_operation_id(&candidate)?;
    candidate.schema = OperationSchemaV1::V2;
    candidate.actor.origin = AuthorityOriginV1::Delegated;
    candidate.causality = CausalLinkV1 {
        parent_operation_id: Some(root.clone()),
        root_operation_id: Some(root),
    };

    let encoded = serde_json::to_vec(&candidate)?;
    assert!(
        parse_operation_envelope_bytes(&encoded).is_err(),
        "the V1 ingress admitted a delegated V2 shape without child authority"
    );
    Ok(())
}

fn child_operation() -> Result<ChildOperationEnvelopeV2, Box<dyn std::error::Error>> {
    let root = root_operation()?;
    let root_id = derive_operation_id(&root)?;
    let permit_id = CurrentPermitId::try_new(format!(
        "v1:recursive-agent/permit/v1:det:{}",
        "a".repeat(64)
    ))?;
    let receipt_id = CurrentReceiptId::try_new(format!(
        "v1:recursive-agent/receipt/v1:det:{}",
        "b".repeat(64)
    ))?;
    let mut child = ChildOperationEnvelopeV2 {
        schema: OperationSchemaV1::V2,
        actor: ActorAuthorityV1 {
            principal: "actor:phase7".into(),
            origin: AuthorityOriginV1::Delegated,
        },
        causality: CausalLinkV1 {
            parent_operation_id: Some(root_id.clone()),
            root_operation_id: Some(root_id.clone()),
        },
        child_authority: ChildRunAuthorityV1 {
            parent_operation_id: root_id.clone(),
            root_operation_id: root_id,
            parent_control_permit_id: permit_id,
            parent_admission_receipt_id: receipt_id,
            requested_budget: root.budget.clone(),
            child_operation_digest: ContentDigest::compute(b"placeholder"),
        },
        budget: root.budget,
        effects: root.effects,
        provenance: root.provenance,
        replay: root.replay,
        run_spec: root.run_spec,
    };
    child.child_authority.child_operation_digest = derive_child_operation_material_digest(&child)?;
    Ok(child)
}

#[test]
fn v2_child_proposal_is_closed_without_admission_identity() -> Result<(), Box<dyn std::error::Error>>
{
    let child = child_operation()?;
    let proposal = ChildOperationProposalV2 {
        schema: child.schema,
        actor: child.actor.clone(),
        causality: child.causality.clone(),
        budget: child.budget.clone(),
        effects: child.effects.clone(),
        provenance: child.provenance.clone(),
        replay: child.replay.clone(),
        run_spec: child.run_spec.clone(),
    };

    proposal.validate()?;
    let encoded = serde_json::to_vec(&proposal)?;
    assert_eq!(parse_child_operation_proposal_v2_bytes(&encoded)?, proposal);
    assert_eq!(
        derive_child_operation_proposal_digest(&proposal)?,
        derive_child_operation_material_digest(&child)?,
        "the pre-admission proposal digest must bind exactly the later V2 material"
    );
    assert!(
        !String::from_utf8(encoded)?.contains("parent_admission_receipt_id"),
        "caller input must not carry a self-referential parent admission receipt ID"
    );
    Ok(())
}

#[test]
fn v2_child_operation_requires_closed_authority_and_material_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let child = child_operation()?;
    child.validate()?;
    let encoded = serde_json::to_vec(&child)?;
    assert_eq!(parse_child_operation_envelope_v2_bytes(&encoded)?, child);
    let baseline_id = derive_child_operation_id(&child)?;

    let mut wrong_budget = child.clone();
    wrong_budget.budget.max_output_bytes += 1;
    assert!(wrong_budget.validate().is_err());

    let mut wrong_parent = child.clone();
    wrong_parent.child_authority.parent_operation_id =
        CurrentRunId::try_new(format!("v1:recursive-agent/run/v1:det:{}", "c".repeat(64)))?;
    assert!(wrong_parent.validate().is_err());

    let mut changed_permit = child.clone();
    changed_permit.child_authority.parent_control_permit_id = CurrentPermitId::try_new(format!(
        "v1:recursive-agent/permit/v1:det:{}",
        "d".repeat(64)
    ))?;
    changed_permit.validate()?;
    assert_ne!(derive_child_operation_id(&changed_permit)?, baseline_id);

    let mut wrong_digest = child.clone();
    wrong_digest.child_authority.child_operation_digest = ContentDigest::compute(b"tampered");
    assert!(wrong_digest.validate().is_err());
    Ok(())
}
