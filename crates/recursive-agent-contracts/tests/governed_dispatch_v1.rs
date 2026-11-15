use recursive_agent_contracts::{
    content_digest, parse_normal_chat_attempt_v1_bytes, parse_normal_chat_attempt_v2_bytes,
    parse_normal_chat_call_request_v2_bytes, parse_normal_chat_operation_v1_bytes,
    parse_normal_chat_operation_v2_bytes, ContentDigest, NormalChatAttemptV2,
    NormalChatCallRequestV2, NormalChatOperationV2, MAX_NORMAL_CHAT_REQUEST_BYTES_V2,
};
use serde::Serialize;
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn call_request_is_authority_free_and_preparation_binds_exact_intent_and_body() -> TestResult {
    let fixture = json!({
        "schema":"recursive-agent.normal-chat-call-request/v2", "operation":operation_v2_fixture(),
        "provider_request_digest":ContentDigest::compute(b"body"),
        "provider_request_bytes":4,"dispatch_intent_ref":"intent:one"
    });
    let call = parse_normal_chat_call_request_v2_bytes(&serde_json::to_vec(&fixture)?)?;
    assert_eq!(serde_json::to_value(&call)?, fixture);
    assert_eq!(call.preparation_digest()?, content_digest(&call)?);
    let mut changed = call.clone();
    changed.dispatch_intent_ref = "intent:two".into();
    assert_ne!(call.preparation_digest()?, changed.preparation_digest()?);
    changed = call.clone();
    changed.provider_request_bytes += 1;
    assert_ne!(call.preparation_digest()?, changed.preparation_digest()?);
    for key in [
        "attempt_number",
        "parent_admission_receipt_id",
        "requested_budget",
        "permit_id",
    ] {
        let mut bad = fixture.clone();
        bad[key] = json!(1);
        assert!(parse_normal_chat_call_request_v2_bytes(&serde_json::to_vec(&bad)?).is_err());
    }
    let mut bad = call;
    bad.provider_request_bytes = bad.operation.budget.max_request_bytes + 1;
    assert!(bad.validate().is_err());
    let encoded = serde_json::to_string(&fixture)?;
    let duplicate = format!(
        "{{\"dispatch_intent_ref\":\"intent:duplicate\",{}",
        encoded.trim_start_matches('{')
    );
    assert!(parse_normal_chat_call_request_v2_bytes(duplicate.as_bytes()).is_err());
    let _typed: NormalChatCallRequestV2 = changed;
    Ok(())
}

#[test]
fn preparation_projection_is_owned_lossless_and_excludes_allocation_ids() -> TestResult {
    let attempt = attempt_v2_fixture(1, "intent:projection", b"body")?;
    let call = NormalChatCallRequestV2::from_attempt(&attempt)?;
    assert_eq!(call.operation, attempt.operation);
    assert_eq!(
        call.provider_request_digest,
        attempt.provider_request_digest
    );
    assert_eq!(call.provider_request_bytes, attempt.provider_request_bytes);
    assert_eq!(call.dispatch_intent_ref, attempt.dispatch_intent_ref);
    let mut second = attempt.clone();
    second.attempt_number = 2;
    second.attempt_id = recursive_agent_contracts::derive_normal_chat_attempt_id_v2(
        &second.operation,
        2,
        &second.provider_request_digest,
        second.provider_request_bytes,
    )?;
    assert_eq!(call, NormalChatCallRequestV2::from_attempt(&second)?);
    let mut invalid = attempt;
    invalid.provider_request_bytes += 1;
    assert!(NormalChatCallRequestV2::from_attempt(&invalid).is_err());
    Ok(())
}

fn operation_v2_fixture() -> Value {
    json!({
        "schema": "recursive-agent.normal-chat/v2",
        "conversation_ref": "conversation:fixture-1",
        "parent_run_id": format!(
            "v1:recursive-agent/run/v1:det:{}",
            "a".repeat(64)
        ),
        "materialization_ref": "materialization:fixture-1",
        "materialization_digest": format!("sha256:{}", "b".repeat(64)),
        "policy_basis_ref": "normal-chat-grant:fixture-revision-1",
        "policy_basis_digest": format!("blake3:{}", "c".repeat(64)),
        "source_revision": "source:fixture-1",
        "route_class": "conversation",
        "provider_identity": "openai_compatible:https://provider.test/v1",
        "model_ref": "model:fixture",
        "api_mode": "chat_completions",
        "request_digest": format!("sha256:{}", "d".repeat(64)),
        "request_projection_schema": "ares-json-sorted-v1",
        "budget": {
            "output_reserve": 20,
            "max_wall_time_ms": 1000,
            "max_request_bytes": 65536
        },
        "replay": "unavailable",
        "provenance": [{
            "source": "urn:test:normal-chat",
            "digest": ContentDigest::compute(b"normal-chat-provenance")
        }]
    })
}

#[test]
fn normal_chat_operation_v2_accepts_the_closed_fixture_without_widening_v1() -> TestResult {
    let fixture = operation_v2_fixture();
    let encoded = serde_json::to_vec(&fixture)?;
    let parsed = parse_normal_chat_operation_v2_bytes(&encoded)?;

    assert_eq!(serde_json::to_value(parsed)?, fixture);
    assert!(parse_normal_chat_operation_v1_bytes(&encoded).is_err());
    Ok(())
}

#[test]
fn normal_chat_operation_v2_rejects_unknown_fields_and_wrong_schema() -> TestResult {
    let mut unknown = operation_v2_fixture();
    unknown["unexpected_authority"] = json!(true);
    assert!(parse_normal_chat_operation_v2_bytes(&serde_json::to_vec(&unknown)?).is_err());

    let mut wrong_schema = operation_v2_fixture();
    wrong_schema["schema"] = json!("recursive-agent.normal-chat/v1");
    assert!(parse_normal_chat_operation_v2_bytes(&serde_json::to_vec(&wrong_schema)?).is_err());
    Ok(())
}

#[test]
fn normal_chat_operation_v2_rejects_duplicate_keys_and_oversized_input() -> TestResult {
    let encoded = String::from_utf8(serde_json::to_vec(&operation_v2_fixture())?)?;
    let duplicate_schema = format!(
        "{{\"schema\":\"recursive-agent.normal-chat/v2\",{}",
        encoded.trim_start_matches('{')
    );
    assert!(parse_normal_chat_operation_v2_bytes(duplicate_schema.as_bytes()).is_err());

    let oversized = vec![b' '; (1024 * 1024) + 1];
    assert!(parse_normal_chat_operation_v2_bytes(&oversized).is_err());
    Ok(())
}

fn attempt_v2_fixture(
    attempt_number: u32,
    dispatch_intent_ref: &str,
    provider_body: &[u8],
) -> Result<NormalChatAttemptV2, Box<dyn std::error::Error>> {
    let operation =
        parse_normal_chat_operation_v2_bytes(&serde_json::to_vec(&operation_v2_fixture())?)?;
    let session_run_id = operation.parent_run_id.clone();
    Ok(NormalChatAttemptV2::new(
        operation,
        attempt_number,
        ContentDigest::compute(provider_body),
        provider_body.len() as u64,
        dispatch_intent_ref.to_owned(),
        session_run_id,
    )?)
}

#[test]
fn normal_chat_attempt_v2_binds_physical_send_and_derives_a_child_run() -> TestResult {
    let first = attempt_v2_fixture(1, "ares-dispatch-intent:fixture-1", b"provider-body-1")?;
    let repeated = attempt_v2_fixture(1, "ares-dispatch-intent:fixture-1", b"provider-body-1")?;
    let retry = attempt_v2_fixture(2, "ares-dispatch-intent:fixture-2", b"provider-body-2")?;

    assert_eq!(first, repeated);
    assert_ne!(first.attempt_id, retry.attempt_id);
    assert_ne!(first.run_id()?, retry.run_id()?);
    assert_eq!(first.operation, retry.operation);

    let encoded = serde_json::to_vec(&first)?;
    assert_eq!(parse_normal_chat_attempt_v2_bytes(&encoded)?, first);
    assert!(parse_normal_chat_attempt_v1_bytes(&encoded).is_err());
    Ok(())
}

#[test]
fn normal_chat_attempt_v2_rejects_tampered_identity_and_session_parent() -> TestResult {
    let attempt = attempt_v2_fixture(1, "ares-dispatch-intent:fixture-1", b"provider-body")?;
    let mut tampered_id = serde_json::to_value(&attempt)?;
    tampered_id["attempt_id"] = json!("arbitrary");
    assert!(parse_normal_chat_attempt_v2_bytes(&serde_json::to_vec(&tampered_id)?).is_err());

    let mut wrong_parent = serde_json::to_value(&attempt)?;
    wrong_parent["session_run_id"] =
        json!(format!("v1:recursive-agent/run/v1:det:{}", "e".repeat(64)));
    assert!(parse_normal_chat_attempt_v2_bytes(&serde_json::to_vec(&wrong_parent)?).is_err());
    Ok(())
}

#[test]
fn normal_chat_attempt_v2_rejects_unknown_duplicate_and_oversized_inputs() -> TestResult {
    let encoded = serde_json::to_vec(&attempt_v2_fixture(
        1,
        "ares-dispatch-intent:fixture-1",
        b"provider-body",
    )?)?;
    let mut unknown = serde_json::from_slice::<Value>(&encoded)?;
    unknown["terminal_state"] = json!("succeeded");
    assert!(parse_normal_chat_attempt_v2_bytes(&serde_json::to_vec(&unknown)?).is_err());

    let encoded_text = String::from_utf8(encoded)?;
    let duplicate_schema = format!(
        "{{\"schema\":\"recursive-agent.normal-chat-attempt/v2\",{}",
        encoded_text.trim_start_matches('{')
    );
    assert!(parse_normal_chat_attempt_v2_bytes(duplicate_schema.as_bytes()).is_err());

    let oversized = vec![b' '; (1024 * 1024) + 1];
    assert!(parse_normal_chat_attempt_v2_bytes(&oversized).is_err());
    Ok(())
}

#[test]
fn normal_chat_operation_v2_enforces_per_attempt_budget_bounds() -> TestResult {
    let mut zero_output_reserve = operation_v2_fixture();
    zero_output_reserve["budget"]["output_reserve"] = json!(0);
    assert!(
        parse_normal_chat_operation_v2_bytes(&serde_json::to_vec(&zero_output_reserve)?).is_err()
    );

    let mut oversized_request = operation_v2_fixture();
    oversized_request["budget"]["max_request_bytes"] = json!(MAX_NORMAL_CHAT_REQUEST_BYTES_V2 + 1);
    assert!(
        parse_normal_chat_operation_v2_bytes(&serde_json::to_vec(&oversized_request)?).is_err()
    );
    Ok(())
}

#[test]
fn normal_chat_attempt_v2_requires_and_binds_physical_body_length() -> TestResult {
    let attempt = attempt_v2_fixture(1, "ares-dispatch-intent:length", b"physical-body")?;
    let mut missing = serde_json::to_value(&attempt)?;
    missing
        .as_object_mut()
        .ok_or("attempt is not an object")?
        .remove("provider_request_bytes");
    assert!(parse_normal_chat_attempt_v2_bytes(&serde_json::to_vec(&missing)?).is_err());
    for bytes in [0, MAX_NORMAL_CHAT_REQUEST_BYTES_V2 + 1] {
        let mut invalid = serde_json::to_value(&attempt)?;
        invalid["provider_request_bytes"] = json!(bytes);
        assert!(parse_normal_chat_attempt_v2_bytes(&serde_json::to_vec(&invalid)?).is_err());
    }
    let mut changed = serde_json::to_value(&attempt)?;
    changed["provider_request_bytes"] = json!(1);
    assert!(parse_normal_chat_attempt_v2_bytes(&serde_json::to_vec(&changed)?).is_err());
    Ok(())
}

#[derive(Serialize)]
struct AttemptIdentityMaterialV2Fixture<'a> {
    operation: &'a NormalChatOperationV2,
    attempt_number: u32,
    provider_request_digest: &'a ContentDigest,
    provider_request_bytes: u64,
}

#[test]
fn normal_chat_attempt_v2_uses_the_approved_identity_domain_and_preimage() -> TestResult {
    let attempt = attempt_v2_fixture(1, "ares-dispatch-intent:fixture-1", b"provider-body")?;
    let material = AttemptIdentityMaterialV2Fixture {
        operation: &attempt.operation,
        attempt_number: attempt.attempt_number,
        provider_request_digest: &attempt.provider_request_digest,
        provider_request_bytes: attempt.provider_request_bytes,
    };
    let digest = content_digest(&material)?;
    let expected_owner =
        stack_ids::TrialId::deterministic("recursive-agent/normal-chat-attempt/v2", digest.hex())
            .map_err(|error| {
            std::io::Error::other(format!("attempt ID derivation failed: {error:?}"))
        })?;

    assert_eq!(attempt.attempt_id.as_str(), expected_owner.as_str());
    Ok(())
}
