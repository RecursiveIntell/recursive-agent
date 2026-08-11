use recursive_agent_contracts::{
    content_digest, derive_operation_id, jcs_canonical, parse_operation_envelope_bytes,
    ActorAuthorityV1, AuthorityOriginV1, CausalLinkV1, ContentDigest, DeclaredEffectsV1,
    OperationBudgetV1, OperationEnvelopeV1, OperationIngressError, OperationSchemaV1,
    ProvenanceRefV1, ReplayClassV1, ReplayIntentV1, ReplaySpecV1, RunSpecV1, StepSpecV1,
    ToolCallSpecV1,
};

fn sample_envelope() -> Result<OperationEnvelopeV1, Box<dyn std::error::Error>> {
    let run_spec = RunSpecV1 {
        name: "phase2-envelope".into(),
        steps: vec![StepSpecV1 {
            name: "echo".into(),
            call: ToolCallSpecV1 {
                tool: "echo".into(),
                args: serde_json::json!({"text": "hello"}),
                frozen_clock: None,
            },
        }],
        frozen_clock: None,
        policy_version: "policy-v1".into(),
    };
    Ok(OperationEnvelopeV1 {
        schema: OperationSchemaV1::V1,
        actor: ActorAuthorityV1 {
            principal: "actor:test".into(),
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
            source: "urn:test:request".into(),
            digest: ContentDigest::compute(b"phase2-request"),
        }],
        replay: ReplaySpecV1 {
            class: ReplayClassV1::Deterministic,
            intent: ReplayIntentV1::ExecuteOnce,
        },
        run_spec,
    })
}

fn sample_shell_envelope() -> Result<OperationEnvelopeV1, Box<dyn std::error::Error>> {
    let mut envelope = sample_envelope()?;
    envelope.run_spec.steps[0].call = ToolCallSpecV1 {
        tool: "shell".into(),
        args: serde_json::json!({
            "command": "/usr/bin/printf",
            "args": ["phase2"],
            "allowed_read_paths": ["/tmp/input"],
            "allowed_write_paths": ["/tmp/output"],
            "allow_network": false,
            "timeout_ms": 1_000,
            "max_output_bytes": 4_096
        }),
        frozen_clock: None,
    };
    envelope.effects = DeclaredEffectsV1 {
        read_roots: vec!["/tmp/input".into()],
        write_roots: vec!["/tmp/output".into()],
        network_allowed: false,
        action_digest: content_digest(&envelope.run_spec)?,
    };
    envelope.replay.class = ReplayClassV1::RecordedEffect;
    Ok(envelope)
}

#[test]
fn operation_schema_accepts_only_exact_registered_tags() -> Result<(), Box<dyn std::error::Error>> {
    let v1: OperationSchemaV1 = serde_json::from_str(r#""recursive-agent.operation/v1""#)?;
    assert_eq!(v1, OperationSchemaV1::V1);
    let v2: OperationSchemaV1 = serde_json::from_str(r#""recursive-agent.operation/v2""#)?;
    assert_eq!(v2, OperationSchemaV1::V2);

    let ambiguous = serde_json::from_str::<OperationSchemaV1>(r#""v1""#);
    assert!(ambiguous.is_err(), "ambiguous schema tag was accepted");
    Ok(())
}

#[test]
fn complete_operation_envelope_round_trips_without_a_second_run_model(
) -> Result<(), Box<dyn std::error::Error>> {
    let envelope = sample_envelope()?;
    let encoded = serde_json::to_vec(&envelope)?;
    let decoded: OperationEnvelopeV1 = serde_json::from_slice(&encoded)?;

    assert_eq!(decoded, envelope);
    assert_eq!(decoded.run_spec.steps.len(), 1);
    assert_eq!(decoded.run_spec.steps[0].name, "echo");
    Ok(())
}

#[test]
fn repo_audit_operation_has_no_caller_supplied_filesystem_path(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut envelope = sample_envelope()?;
    envelope.run_spec.steps[0].name = "repo_audit".into();
    envelope.run_spec.steps[0].call = ToolCallSpecV1 {
        tool: "repo_audit".into(),
        args: serde_json::json!({
            "scope_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }),
        frozen_clock: None,
    };
    envelope.effects.action_digest = content_digest(&envelope.run_spec)?;
    envelope.validate()?;

    let mut widened = envelope;
    widened.run_spec.steps[0].call.args = serde_json::json!({"root": "/tmp/escape"});
    widened.effects.action_digest = content_digest(&widened.run_spec)?;
    assert!(
        widened.validate().is_err(),
        "repo_audit accepted a caller-controlled filesystem path"
    );
    Ok(())
}

#[test]
fn operation_envelope_rejects_unknown_closed_fields() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = serde_json::to_value(sample_envelope()?)?;
    for (label, pointer) in [
        ("envelope", ""),
        ("actor", "/actor"),
        ("causality", "/causality"),
        ("budget", "/budget"),
        ("effects", "/effects"),
        ("provenance", "/provenance/0"),
        ("replay", "/replay"),
    ] {
        let mut candidate = encoded.clone();
        let target = if pointer.is_empty() {
            &mut candidate
        } else {
            candidate
                .pointer_mut(pointer)
                .ok_or_else(|| format!("missing test pointer {pointer}"))?
        };
        target
            .as_object_mut()
            .ok_or_else(|| format!("test pointer {pointer} is not an object"))?
            .insert("unexpected".into(), serde_json::json!(true));

        let decoded = serde_json::from_value::<OperationEnvelopeV1>(candidate);
        assert!(decoded.is_err(), "unknown field at {label} was accepted");
    }
    Ok(())
}

#[test]
fn operation_envelope_rejects_invalid_operation_budgets() -> Result<(), Box<dyn std::error::Error>>
{
    let mut cases = Vec::new();

    let mut wall_zero = sample_envelope()?;
    wall_zero.budget.max_wall_time_ms = 0;
    cases.push(("zero wall time", wall_zero));

    let mut wall_over = sample_envelope()?;
    wall_over.budget.max_wall_time_ms = 300_001;
    cases.push(("over-limit wall time", wall_over));

    let mut output_zero = sample_envelope()?;
    output_zero.budget.max_output_bytes = 0;
    cases.push(("zero output", output_zero));

    let mut output_over = sample_envelope()?;
    output_over.budget.max_output_bytes = 65_537;
    cases.push(("over-limit output", output_over));

    let mut artifact_zero = sample_envelope()?;
    artifact_zero.budget.max_artifact_bytes = 0;
    cases.push(("zero artifacts", artifact_zero));

    let mut artifact_over = sample_envelope()?;
    artifact_over.budget.max_artifact_bytes = 65_537;
    cases.push(("over-limit artifacts", artifact_over));

    let mut steps_zero = sample_envelope()?;
    steps_zero.budget.max_steps = 0;
    cases.push(("zero steps", steps_zero));

    let mut steps_over = sample_envelope()?;
    steps_over.budget.max_steps = 5;
    cases.push(("over-limit steps", steps_over));

    let mut steps_underdeclared = sample_envelope()?;
    steps_underdeclared.run_spec.steps.push(StepSpecV1 {
        name: "second".into(),
        call: ToolCallSpecV1 {
            tool: "echo".into(),
            args: serde_json::json!({"text": "second"}),
            frozen_clock: None,
        },
    });
    cases.push(("underdeclared step budget", steps_underdeclared));

    for (label, envelope) in cases {
        assert!(envelope.validate().is_err(), "{label} was accepted");
    }
    Ok(())
}

#[test]
fn operation_identity_is_deterministic_and_binds_all_semantic_surfaces(
) -> Result<(), Box<dyn std::error::Error>> {
    let baseline = sample_envelope()?;
    let baseline_id = derive_operation_id(&baseline)?;
    assert_eq!(baseline_id, derive_operation_id(&baseline)?);

    let mut variants = Vec::new();

    let mut actor = baseline.clone();
    actor.actor.principal = "actor:other".into();
    variants.push(("actor", actor));

    let mut budget = baseline.clone();
    budget.budget.max_output_bytes += 1;
    variants.push(("budget", budget));

    let mut effects = baseline.clone();
    effects.effects.read_roots.push("/tmp/input".into());
    variants.push(("effects", effects));

    let mut provenance = baseline.clone();
    provenance.provenance[0].digest = ContentDigest::compute(b"other-request");
    variants.push(("provenance", provenance));

    let mut replay = baseline.clone();
    replay.replay.class = ReplayClassV1::RecordedEffect;
    variants.push(("replay", replay));

    let mut payload = baseline.clone();
    payload.run_spec.name = "other-run".into();
    variants.push(("payload", payload));

    for (label, variant) in variants {
        assert_ne!(
            derive_operation_id(&variant)?,
            baseline_id,
            "{label} did not affect operation identity"
        );
    }
    Ok(())
}

#[test]
fn operation_envelope_enforces_authority_causality_shape() -> Result<(), Box<dyn std::error::Error>>
{
    let parent = derive_operation_id(&sample_envelope()?)?;

    let mut direct_with_parent = sample_envelope()?;
    direct_with_parent.causality.parent_operation_id = Some(parent.clone());
    direct_with_parent.causality.root_operation_id = Some(parent.clone());
    assert!(
        direct_with_parent.validate().is_err(),
        "direct authority accepted delegated lineage"
    );

    let mut delegated_without_lineage = sample_envelope()?;
    delegated_without_lineage.actor.origin = AuthorityOriginV1::Delegated;
    assert!(
        delegated_without_lineage.validate().is_err(),
        "delegated authority accepted no lineage"
    );

    let mut delegated_without_root = sample_envelope()?;
    delegated_without_root.actor.origin = AuthorityOriginV1::Delegated;
    delegated_without_root.causality.parent_operation_id = Some(parent.clone());
    assert!(
        delegated_without_root.validate().is_err(),
        "delegated authority accepted no root"
    );

    let mut delegated = sample_envelope()?;
    delegated.actor.origin = AuthorityOriginV1::Delegated;
    delegated.causality.parent_operation_id = Some(parent.clone());
    delegated.causality.root_operation_id = Some(parent);
    assert!(
        delegated.validate().is_err(),
        "V1 ingress admitted delegated child authority"
    );
    Ok(())
}

#[test]
fn operation_envelope_rejects_invalid_actor_and_provenance_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = Vec::new();

    let mut empty_actor = sample_envelope()?;
    empty_actor.actor.principal.clear();
    cases.push(("empty actor", empty_actor));

    let mut padded_actor = sample_envelope()?;
    padded_actor.actor.principal = " actor:test".into();
    cases.push(("padded actor", padded_actor));

    let mut oversized_actor = sample_envelope()?;
    oversized_actor.actor.principal = "a".repeat(257);
    cases.push(("oversized actor", oversized_actor));

    let mut control_actor = sample_envelope()?;
    control_actor.actor.principal = "actor:\ncontrol".into();
    cases.push(("control actor", control_actor));

    let mut no_provenance = sample_envelope()?;
    no_provenance.provenance.clear();
    cases.push(("empty provenance", no_provenance));

    let mut too_many_provenance = sample_envelope()?;
    too_many_provenance.provenance = (0..33)
        .map(|index| ProvenanceRefV1 {
            source: format!("urn:test:{index}"),
            digest: ContentDigest::compute(index.to_string().as_bytes()),
        })
        .collect();
    cases.push(("too many provenance refs", too_many_provenance));

    let mut empty_source = sample_envelope()?;
    empty_source.provenance[0].source.clear();
    cases.push(("empty provenance source", empty_source));

    let mut padded_source = sample_envelope()?;
    padded_source.provenance[0].source = " urn:test:request".into();
    cases.push(("padded provenance source", padded_source));

    let mut oversized_source = sample_envelope()?;
    oversized_source.provenance[0].source = "s".repeat(4097);
    cases.push(("oversized provenance source", oversized_source));

    let mut duplicate_source = sample_envelope()?;
    duplicate_source
        .provenance
        .push(duplicate_source.provenance[0].clone());
    cases.push(("duplicate provenance source", duplicate_source));

    for (label, envelope) in cases {
        assert!(envelope.validate().is_err(), "{label} was accepted");
    }
    Ok(())
}

#[test]
fn operation_envelope_rejects_effect_mismatch_and_underdeclaration(
) -> Result<(), Box<dyn std::error::Error>> {
    sample_shell_envelope()?.validate()?;
    let mut cases = Vec::new();

    let mut wrong_digest = sample_shell_envelope()?;
    wrong_digest.effects.action_digest = ContentDigest::compute(b"wrong-action");
    cases.push(("wrong action digest", wrong_digest));

    let mut missing_read = sample_shell_envelope()?;
    missing_read.effects.read_roots.clear();
    cases.push(("missing read root", missing_read));

    let mut missing_write = sample_shell_envelope()?;
    missing_write.effects.write_roots.clear();
    cases.push(("missing write root", missing_write));

    let mut excess_read = sample_shell_envelope()?;
    excess_read.effects.read_roots.push("/tmp/extra".into());
    cases.push(("excess read authority", excess_read));

    let mut excess_network = sample_envelope()?;
    excess_network.effects.network_allowed = true;
    cases.push(("excess network authority", excess_network));

    let mut duplicate_write = sample_shell_envelope()?;
    duplicate_write
        .effects
        .write_roots
        .push("/tmp/output".into());
    cases.push(("duplicate write root", duplicate_write));

    for (label, envelope) in cases {
        assert!(envelope.validate().is_err(), "{label} was accepted");
    }
    Ok(())
}

#[test]
fn operation_envelope_enforces_replay_classification() -> Result<(), Box<dyn std::error::Error>> {
    let mut deterministic_shell = sample_shell_envelope()?;
    deterministic_shell.replay.class = ReplayClassV1::Deterministic;
    assert!(
        deterministic_shell.validate().is_err(),
        "shell execution was classified as deterministic"
    );

    let mut recorded_pure = sample_envelope()?;
    recorded_pure.replay.class = ReplayClassV1::RecordedEffect;
    assert!(
        recorded_pure.validate().is_err(),
        "pure operation was classified as a recorded effect"
    );

    let mut non_replayable_read = sample_shell_envelope()?;
    non_replayable_read.replay.class = ReplayClassV1::NonReplayable;
    non_replayable_read.replay.intent = ReplayIntentV1::ReadRecorded;
    assert!(
        non_replayable_read.validate().is_err(),
        "non-replayable operation requested recorded replay"
    );

    sample_envelope()?.validate()?;
    sample_shell_envelope()?.validate()?;
    Ok(())
}

#[test]
fn operation_byte_ingress_rejects_hostile_vectors_before_admission(
) -> Result<(), Box<dyn std::error::Error>> {
    let envelope = sample_envelope()?;
    let valid = serde_json::to_vec(&envelope)?;
    assert_eq!(parse_operation_envelope_bytes(&valid)?, envelope);

    let valid_text = String::from_utf8(valid.clone())?;
    let duplicate = valid_text.replacen(
        "\"principal\":\"actor:test\"",
        "\"principal\":\"actor:test\",\"principal\":\"actor:shadow\"",
        1,
    );
    assert!(matches!(
        parse_operation_envelope_bytes(duplicate.as_bytes()),
        Err(OperationIngressError::DuplicateKey)
    ));

    let mut unknown = serde_json::to_value(&envelope)?;
    unknown
        .as_object_mut()
        .ok_or("envelope fixture is not an object")?
        .insert("unexpected".into(), serde_json::json!(true));
    assert!(matches!(
        parse_operation_envelope_bytes(&serde_json::to_vec(&unknown)?),
        Err(OperationIngressError::Malformed)
    ));

    let mut missing = serde_json::to_value(&envelope)?;
    missing
        .as_object_mut()
        .ok_or("envelope fixture is not an object")?
        .remove("actor");
    assert!(matches!(
        parse_operation_envelope_bytes(&serde_json::to_vec(&missing)?),
        Err(OperationIngressError::Malformed)
    ));

    let mut invalid_budget = envelope.clone();
    invalid_budget.budget.max_steps = 0;
    assert!(matches!(
        parse_operation_envelope_bytes(&serde_json::to_vec(&invalid_budget)?),
        Err(OperationIngressError::Semantic(_))
    ));

    let mut malformed_id = serde_json::to_value(&envelope)?;
    malformed_id["causality"]["parent_operation_id"] = serde_json::json!("not-a-current-run-id");
    assert!(matches!(
        parse_operation_envelope_bytes(&serde_json::to_vec(&malformed_id)?),
        Err(OperationIngressError::Malformed)
    ));

    let oversized = vec![b' '; 1024 * 1024 + 1];
    assert!(matches!(
        parse_operation_envelope_bytes(&oversized),
        Err(OperationIngressError::InputTooLarge { .. })
    ));
    Ok(())
}

#[test]
fn operation_v1_canonical_fixed_vector_is_stable() -> Result<(), Box<dyn std::error::Error>> {
    const VECTOR: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/receipts/phase-2/task-2.1-operation-contract/operation-v1.vector.json"
    ));
    const SCHEMA: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/receipts/phase-2/task-2.1-operation-contract/operation-v1.schema.json"
    ));

    let envelope = sample_envelope()?;
    envelope.validate()?;
    let canonical = String::from_utf8(jcs_canonical(&envelope)?)?;
    assert_eq!(canonical, VECTOR);
    assert_eq!(parse_operation_envelope_bytes(VECTOR.as_bytes())?, envelope);

    assert_eq!(
        content_digest(&envelope)?.hex(),
        "d512e800e2a997ce7dd5a82b4e0a5669fc87e8039356d33f13c7207647c677cc"
    );
    assert_eq!(
        derive_operation_id(&envelope)?.to_string(),
        "v1:recursive-agent/run/v1:det:d512e800e2a997ce7dd5a82b4e0a5669fc87e8039356d33f13c7207647c677cc"
    );
    assert_eq!(
        ContentDigest::compute(VECTOR.as_bytes()).hex(),
        "d512e800e2a997ce7dd5a82b4e0a5669fc87e8039356d33f13c7207647c677cc"
    );

    let schema: serde_json::Value = serde_json::from_str(SCHEMA)?;
    assert_eq!(
        schema["$id"],
        serde_json::json!("urn:recursive-agent:schema:operation:v1")
    );
    assert_eq!(
        schema["properties"]["schema"]["const"],
        serde_json::json!("recursive-agent.operation/v1")
    );
    assert_eq!(
        ContentDigest::compute(SCHEMA.as_bytes()).hex(),
        "a3fc54094021e46d39819caa0ca5210042cfde6ee8d03f8351bd255a2abd686b"
    );
    Ok(())
}
