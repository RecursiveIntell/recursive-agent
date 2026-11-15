//! Reconciliation tests for the source-only V2 contract extraction.
//! These tests do not create permits, launch providers, or admit physical egress.
use recursive_agent_contracts::{
    jcs_canonical, parse_normal_chat_call_request_v2_bytes, parse_normal_chat_operation_v2_bytes,
    parse_normal_chat_session_v1_bytes, NormalChatSessionSchemaV1, NormalChatSessionV1,
};

fn session() -> NormalChatSessionV1 {
    let sha256_a = format!("sha256:{}", "a".repeat(64));
    let sha256_b = format!("sha256:{}", "b".repeat(64));
    NormalChatSessionV1 {
        schema: NormalChatSessionSchemaV1::V1,
        conversation_ref: "r08-inert-session".into(),
        parent_session_run_id: None,
        ares_home_digest: sha256_a,
        grant_revision: 1,
        policy_basis_digest: sha256_b,
    }
}

#[test]
fn session_identity_is_canonical_but_not_a_capability() -> Result<(), Box<dyn std::error::Error>> {
    let expected = session();
    let canonical = jcs_canonical(&expected)?;
    let parsed = parse_normal_chat_session_v1_bytes(&canonical)?;
    assert_eq!(parsed, expected);
    assert_eq!(parsed.run_id()?, expected.run_id()?);
    Ok(())
}

#[test]
fn session_rejects_unknown_or_duplicate_members() -> Result<(), Box<dyn std::error::Error>> {
    let mut unknown = serde_json::to_value(session())?;
    unknown["send_authorized"] = serde_json::json!(true);
    assert!(parse_normal_chat_session_v1_bytes(&jcs_canonical(&unknown)?).is_err());

    let canonical = String::from_utf8(jcs_canonical(&session())?)?;
    let duplicate = canonical.replacen(
        "\"grant_revision\":",
        "\"grant_revision\":2,\"grant_revision\":",
        1,
    );
    assert!(parse_normal_chat_session_v1_bytes(duplicate.as_bytes()).is_err());
    Ok(())
}

#[test]
fn v2_request_contracts_reject_trailing_and_unqualified_input() {
    for invalid in [
        b"{}".as_slice(),
        b"{\"schema\":\"wrong\"}".as_slice(),
        b"{} {}".as_slice(),
    ] {
        assert!(parse_normal_chat_operation_v2_bytes(invalid).is_err());
        assert!(parse_normal_chat_call_request_v2_bytes(invalid).is_err());
    }
}

#[test]
fn v2_attempt_refuses_request_larger_than_its_operation_budget(
) -> Result<(), Box<dyn std::error::Error>> {
    use recursive_agent_contracts::{
        derive_normal_chat_attempt_id_v2, ContentDigest, CurrentRunId, NormalChatAttemptV2,
        NormalChatBudgetV2, NormalChatOperationSchemaV2, NormalChatOperationV2,
        NormalChatReplayV2, NormalChatRequestProjectionSchemaV2, ProvenanceRefV1,
    };
    let operation = NormalChatOperationV2 {
        schema: NormalChatOperationSchemaV2::V2,
        conversation_ref: "r08-test".into(),
        parent_run_id: CurrentRunId::try_new(format!(
            "v1:recursive-agent/run/v1:det:{}", "a".repeat(64)
        ))?,
        materialization_ref: "r08-materialization".into(),
        materialization_digest: format!("sha256:{}", "b".repeat(64)),
        policy_basis_ref: "r08-policy".into(),
        policy_basis_digest: format!("sha256:{}", "c".repeat(64)),
        source_revision: "r08-test-revision".into(),
        route_class: "local-test-only".into(),
        provider_identity: "test-provider".into(),
        model_ref: "test-model".into(),
        api_mode: "test-mode".into(),
        request_digest: format!("sha256:{}", "d".repeat(64)),
        request_projection_schema: NormalChatRequestProjectionSchemaV2::AresJsonSortedV1,
        budget: NormalChatBudgetV2 {
            output_reserve: 16,
            max_wall_time_ms: 1_000,
            max_request_bytes: 1_024,
        },
        replay: NormalChatReplayV2::Unavailable,
        provenance: vec![ProvenanceRefV1 {
            source: "r08-source".into(),
            digest: ContentDigest::compute(b"source"),
        }],
    };
    operation.validate()?;
    let digest = ContentDigest::compute(b"physical-body");
    assert!(derive_normal_chat_attempt_id_v2(&operation, 1, &digest, 1_024).is_ok());
    assert!(derive_normal_chat_attempt_id_v2(&operation, 1, &digest, 1_025).is_err());
    assert!(NormalChatAttemptV2::new(
        operation.clone(),
        1,
        digest,
        2_048,
        "r08-dispatch-intent".into(),
        operation.parent_run_id.clone(),
    )
    .is_err());
    Ok(())
}
