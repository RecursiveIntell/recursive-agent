use recursive_agent_contracts::{
    derive_normal_chat_attempt_id, parse_normal_chat_attempt_v1_bytes,
    parse_normal_chat_operation_v1_bytes, parse_provider_egress_operation_v3_bytes, ContentDigest,
    CurrentRunId, NormalChatAttemptIngressError, NormalChatAttemptV1, NormalChatBudgetV1,
    NormalChatOperationIngressError, NormalChatOperationSchemaV1, NormalChatOperationV1,
    NormalChatReplayV1, ProvenanceRefV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn parent_run() -> Result<CurrentRunId, Box<dyn std::error::Error>> {
    Ok(CurrentRunId::try_new(format!(
        "v1:recursive-agent/run/v1:det:{}",
        "a".repeat(64)
    ))?)
}

fn operation() -> Result<NormalChatOperationV1, Box<dyn std::error::Error>> {
    Ok(NormalChatOperationV1 {
        schema: NormalChatOperationSchemaV1::V1,
        conversation_ref: "conversation:fixture-1".into(),
        parent_run_id: Some(parent_run()?),
        materialization_ref: "materialization:fixture-1".into(),
        materialization_digest: format!("sha256:{}", "b".repeat(64)),
        policy_basis_ref: "policy-basis:fixture-1".into(),
        policy_basis_digest: format!("blake3:{}", "c".repeat(64)),
        source_revision: "source:fixture-1".into(),
        route_class: "managed_local".into(),
        provider_identity: "openai_compatible:https://provider.test/v1".into(),
        model_ref: "model:fixture".into(),
        request_digest: format!("sha256:{}", "d".repeat(64)),
        budget: NormalChatBudgetV1 {
            max_attempts: 2,
            input_tokens: 10,
            output_reserve: 20,
            max_wall_time_ms: 1_000,
        },
        replay: NormalChatReplayV1::RecordedResponseOnly,
        provenance: vec![ProvenanceRefV1 {
            source: "urn:test:normal-chat".into(),
            digest: ContentDigest::compute(b"normal-chat-provenance"),
        }],
    })
}

#[test]
fn normal_chat_attempt_id_rejects_unvalidated_wire_values() -> TestResult {
    for raw in [
        String::new(),
        "arbitrary".into(),
        format!("v1:wrong-domain:det:{}", "a".repeat(64)),
        format!(
            "v1:recursive-agent/normal-chat-attempt/v1:det:{}",
            "A".repeat(64)
        ),
    ] {
        assert!(
            serde_json::from_value::<recursive_agent_contracts::NormalChatAttemptId>(
                serde_json::json!(raw)
            )
            .is_err()
        );
    }
    let valid =
        derive_normal_chat_attempt_id(&operation()?, 1, &ContentDigest::compute(b"id-roundtrip"))?;
    assert_eq!(
        serde_json::from_value::<recursive_agent_contracts::NormalChatAttemptId>(
            serde_json::to_value(&valid)?
        )?,
        valid
    );
    Ok(())
}

#[test]
fn normal_chat_attempt_rejects_ordinal_above_declared_ceiling() -> TestResult {
    let candidate = operation()?;
    let request_digest = ContentDigest::compute(b"bounded-request");
    assert!(derive_normal_chat_attempt_id(
        &candidate,
        candidate.budget.max_attempts + 1,
        &request_digest
    )
    .is_err());
    assert!(NormalChatAttemptV1::new(
        candidate.clone(),
        candidate.budget.max_attempts + 1,
        request_digest
    )
    .is_err());
    Ok(())
}

#[test]
fn normal_chat_v1_is_closed_and_attempt_identity_is_deterministic() -> TestResult {
    let candidate = operation()?;
    let encoded = serde_json::to_vec(&candidate)?;
    assert_eq!(parse_normal_chat_operation_v1_bytes(&encoded)?, candidate);

    let provider_request_digest = ContentDigest::compute(b"native-conversation-request");
    let first = derive_normal_chat_attempt_id(&candidate, 1, &provider_request_digest)?;
    assert_eq!(
        first,
        derive_normal_chat_attempt_id(&candidate, 1, &provider_request_digest)?
    );
    assert_ne!(
        first,
        derive_normal_chat_attempt_id(&candidate, 2, &provider_request_digest)?
    );

    let mut different_materialization = candidate.clone();
    different_materialization.materialization_digest = format!("sha256:{}", "e".repeat(64));
    assert_ne!(
        first,
        derive_normal_chat_attempt_id(&different_materialization, 1, &provider_request_digest)?
    );
    assert!(parse_provider_egress_operation_v3_bytes(&encoded).is_err());
    Ok(())
}

#[test]
fn normal_chat_attempt_v1_binds_native_request_digest_and_cannot_be_tampered() -> TestResult {
    let attempt = NormalChatAttemptV1::new(
        operation()?,
        1,
        ContentDigest::compute(b"native-conversation-request"),
    )?;
    let encoded = serde_json::to_vec(&attempt)?;
    assert_eq!(parse_normal_chat_attempt_v1_bytes(&encoded)?, attempt);

    let mut tampered = serde_json::to_value(&attempt)?;
    tampered["provider_request_digest"] = serde_json::json!(ContentDigest::compute(
        b"different-native-conversation-request"
    ));
    assert!(parse_normal_chat_attempt_v1_bytes(&serde_json::to_vec(&tampered)?).is_err());

    let duplicate = format!(
        "{{\"attempt_number\":1,{}",
        String::from_utf8(encoded)?.trim_start_matches('{')
    );
    assert!(matches!(
        parse_normal_chat_attempt_v1_bytes(duplicate.as_bytes()),
        Err(NormalChatAttemptIngressError::DuplicateKey)
    ));
    Ok(())
}

#[test]
fn normal_chat_v1_rejects_credentials_unknown_fields_and_duplicate_keys() -> TestResult {
    let candidate = operation()?;
    let mut credential = serde_json::to_value(&candidate)?;
    credential["api_key"] = serde_json::json!("sk-not-allowed");
    assert!(parse_normal_chat_operation_v1_bytes(&serde_json::to_vec(&credential)?).is_err());

    let mut terminal_status = serde_json::to_value(&candidate)?;
    terminal_status["terminal_state"] = serde_json::json!("succeeded");
    assert!(parse_normal_chat_operation_v1_bytes(&serde_json::to_vec(&terminal_status)?).is_err());

    let mut bad_budget = candidate.clone();
    bad_budget.budget.max_attempts = 0;
    assert!(parse_normal_chat_operation_v1_bytes(&serde_json::to_vec(&bad_budget)?).is_err());

    let encoded = String::from_utf8(serde_json::to_vec(&candidate)?)?;
    let duplicate_schema = format!(
        "{{\"schema\":\"recursive-agent.normal-chat/v1\",{}",
        encoded.trim_start_matches('{')
    );
    assert!(matches!(
        parse_normal_chat_operation_v1_bytes(duplicate_schema.as_bytes()),
        Err(NormalChatOperationIngressError::DuplicateKey)
    ));
    Ok(())
}

#[test]
fn normal_chat_retry_attempts_share_logical_run_identity() -> TestResult {
    let operation = operation()?;
    let request_digest = ContentDigest::compute(b"retry-request");
    let first = NormalChatAttemptV1::new(operation.clone(), 1, request_digest.clone())?;
    let second = NormalChatAttemptV1::new(operation, 2, request_digest)?;

    assert_ne!(first.attempt_id, second.attempt_id);
    assert_eq!(first.run_id()?, second.run_id()?);
    Ok(())
}
