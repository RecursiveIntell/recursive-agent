use chrono::{TimeZone, Utc};
use recursive_agent_contracts::{
    content_digest, parse_child_operation_envelope_v2_bytes, parse_operation_envelope_bytes,
    parse_provider_egress_operation_v3_bytes, ActorAuthorityV1, AuthorityOriginV1, ContentDigest,
    DeclaredEffectsV1, OperationBudgetV1, ProvenanceRefV1, ProviderEgressBindingMaterialV1,
    ProviderEgressBindingV1, ProviderEgressOperationEnvelopeV3,
    ProviderEgressOperationIngressError, ProviderEgressOperationSchemaV1, ReplayClassV1,
    ReplayIntentV1, ReplaySpecV1, SealedCompletionArgumentsV3, SealedCompletionCallV3,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn sealed_call() -> Result<SealedCompletionCallV3, Box<dyn std::error::Error>> {
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
        not_after: Utc
            .with_ymd_and_hms(2030, 1, 1, 0, 0, 0)
            .single()
            .ok_or("fixture expiry is invalid")?,
    })?;
    Ok(SealedCompletionCallV3 {
        tool: "sealed_completion".into(),
        arguments: SealedCompletionArgumentsV3 { binding, request },
    })
}

fn operation() -> Result<ProviderEgressOperationEnvelopeV3, Box<dyn std::error::Error>> {
    let sealed_completion = sealed_call()?;
    Ok(ProviderEgressOperationEnvelopeV3 {
        schema: ProviderEgressOperationSchemaV1::V3,
        actor: ActorAuthorityV1 {
            principal: "actor:egress-fixture".into(),
            origin: AuthorityOriginV1::Direct,
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
            network_allowed: true,
            action_digest: content_digest(&sealed_completion)?,
        },
        provenance: vec![ProvenanceRefV1 {
            source: "urn:test:provider-egress-operation".into(),
            digest: ContentDigest::compute(b"provider-egress-operation"),
        }],
        replay: ReplaySpecV1 {
            class: ReplayClassV1::RecordedEffect,
            intent: ReplayIntentV1::ExecuteOnce,
        },
        sealed_completion,
    })
}

#[test]
fn v3_accepts_exactly_one_opaque_sealed_completion_call_without_widening_v1_or_v2() -> TestResult {
    let operation = operation()?;
    let bytes = serde_json::to_vec(&operation)?;
    assert_eq!(parse_provider_egress_operation_v3_bytes(&bytes)?, operation);
    assert!(parse_operation_envelope_bytes(&bytes).is_err());
    assert!(parse_child_operation_envelope_v2_bytes(&bytes).is_err());
    Ok(())
}

#[test]
fn v3_rejects_request_drift_and_closed_shape_widening_before_policy_or_backend() -> TestResult {
    let candidate = operation()?;
    let mut request_drift = serde_json::to_value(&candidate)?;
    request_drift["sealed_completion"]["arguments"]["request"]["prompt"] =
        serde_json::json!("changed after binding");
    assert!(
        parse_provider_egress_operation_v3_bytes(&serde_json::to_vec(&request_drift)?).is_err()
    );

    let mut unknown_argument = serde_json::to_value(&candidate)?;
    unknown_argument["sealed_completion"]["arguments"]["extra"] = serde_json::json!(true);
    assert!(
        parse_provider_egress_operation_v3_bytes(&serde_json::to_vec(&unknown_argument)?).is_err()
    );

    let mut generic_tool = serde_json::to_value(&candidate)?;
    generic_tool["sealed_completion"]["tool"] = serde_json::json!("llm");
    assert!(parse_provider_egress_operation_v3_bytes(&serde_json::to_vec(&generic_tool)?).is_err());

    let encoded = String::from_utf8(serde_json::to_vec(&candidate)?)?;
    let duplicate_schema = format!(
        "{{\"schema\":\"recursive-agent.operation/v3\",{}",
        encoded.trim_start_matches('{')
    );
    assert!(matches!(
        parse_provider_egress_operation_v3_bytes(duplicate_schema.as_bytes()),
        Err(ProviderEgressOperationIngressError::DuplicateKey)
    ));

    let mut expired = operation()?;
    let binding = &expired.sealed_completion.arguments.binding;
    expired.sealed_completion.arguments.binding =
        ProviderEgressBindingV1::seal(ProviderEgressBindingMaterialV1 {
            policy_basis_ref: binding.policy_basis_ref.clone(),
            policy_basis_digest: binding.policy_basis_digest.clone(),
            context_digest: binding.context_digest.clone(),
            source_revision: binding.source_revision.clone(),
            graph_obligation_ref: binding.graph_obligation_ref.clone(),
            graph_obligation_digest: binding.graph_obligation_digest.clone(),
            route_class: binding.route_class.clone(),
            provider_identity: binding.provider_identity.clone(),
            model_ref: binding.model_ref.clone(),
            input_tokens: binding.input_tokens,
            output_reserve: binding.output_reserve,
            request_digest: binding.request_digest.clone(),
            not_after: Utc
                .with_ymd_and_hms(2020, 1, 1, 0, 0, 0)
                .single()
                .ok_or("expired fixture time is invalid")?,
        })?;
    expired.effects.action_digest = content_digest(&expired.sealed_completion)?;
    let expired_bytes = serde_json::to_vec(&expired)?;
    assert_eq!(
        parse_provider_egress_operation_v3_bytes(&expired_bytes)?,
        expired
    );
    assert!(expired
        .validate_at(
            Utc.with_ymd_and_hms(2026, 9, 5, 0, 0, 0)
                .single()
                .ok_or("dispatch fixture time is invalid")?
        )
        .is_err());
    Ok(())
}
