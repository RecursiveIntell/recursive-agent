use recursive_agent_contracts::{
    content_digest, parse_normal_chat_session_v1_bytes, CurrentRunId, KernelRunId,
    NormalChatSessionIngressErrorV1, MAX_RUN_SPEC_INPUT_BYTES,
};
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn fixture() -> Value {
    json!({
        "schema": "recursive-agent.normal-chat-session/v1",
        "conversation_ref": "conversation:canonical-session-generation-1",
        "parent_session_run_id": null,
        "ares_home_digest": format!("sha256:{}", "a".repeat(64)),
        "grant_revision": 1,
        "policy_basis_digest": format!("sha256:{}", "b".repeat(64)),
    })
}
#[test]
fn session_identity_roundtrips_and_is_derived_by_existing_run_owner() -> TestResult {
    let value = fixture();
    let session = parse_normal_chat_session_v1_bytes(&serde_json::to_vec(&value)?)?;
    assert_eq!(serde_json::to_value(&session)?, value);
    let expected = CurrentRunId::from_owner(
        KernelRunId::deterministic("recursive-agent/run/v1", content_digest(&session)?.hex())
            .map_err(|error| format!("owner derivation: {error:?}"))?,
    )?;
    assert_eq!(session.run_id()?, expected);
    assert_eq!(session.run_id()?, session.run_id()?);
    Ok(())
}
#[test]
fn session_identity_binds_every_owner_supplied_coordinate() -> TestResult {
    let base = parse_normal_chat_session_v1_bytes(&serde_json::to_vec(&fixture())?)?.run_id()?;
    for (field, value) in [
        (
            "conversation_ref",
            json!("conversation:canonical-session-generation-2"),
        ),
        (
            "parent_session_run_id",
            json!(format!("v1:recursive-agent/run/v1:det:{}", "c".repeat(64))),
        ),
        (
            "ares_home_digest",
            json!(format!("sha256:{}", "d".repeat(64))),
        ),
        ("grant_revision", json!(2)),
        (
            "policy_basis_digest",
            json!(format!("sha256:{}", "e".repeat(64))),
        ),
    ] {
        let mut changed = fixture();
        changed[field] = value;
        assert_ne!(
            parse_normal_chat_session_v1_bytes(&serde_json::to_vec(&changed)?)?.run_id()?,
            base,
            "{field}"
        );
    }
    Ok(())
}
#[test]
fn session_boundary_rejects_extra_authority_missing_identity_and_bad_versions() -> TestResult {
    for (field, value) in [
        ("caps", json!({"max_attempts": 999})),
        ("network_allowed", json!(true)),
        ("permit_id", json!("caller-authored")),
    ] {
        let mut changed = fixture();
        changed[field] = value;
        assert!(matches!(
            parse_normal_chat_session_v1_bytes(&serde_json::to_vec(&changed)?),
            Err(NormalChatSessionIngressErrorV1::Malformed)
        ));
    }
    for field in [
        "schema",
        "conversation_ref",
        "ares_home_digest",
        "grant_revision",
        "policy_basis_digest",
    ] {
        let mut changed = fixture();
        changed
            .as_object_mut()
            .ok_or("fixture not an object")?
            .remove(field);
        assert!(
            parse_normal_chat_session_v1_bytes(&serde_json::to_vec(&changed)?).is_err(),
            "{field}"
        );
    }
    let mut changed = fixture();
    changed["schema"] = json!("recursive-agent.normal-chat-session/v2");
    assert!(parse_normal_chat_session_v1_bytes(&serde_json::to_vec(&changed)?).is_err());
    Ok(())
}
#[test]
fn session_boundary_rejects_duplicate_oversize_and_semantic_errors() -> TestResult {
    let encoded = serde_json::to_string(&fixture())?;
    let duplicate = format!("{{\"grant_revision\":1,{}", encoded.trim_start_matches('{'));
    assert!(matches!(
        parse_normal_chat_session_v1_bytes(duplicate.as_bytes()),
        Err(NormalChatSessionIngressErrorV1::DuplicateKey)
    ));
    assert!(matches!(
        parse_normal_chat_session_v1_bytes(&vec![b' '; MAX_RUN_SPEC_INPUT_BYTES as usize + 1]),
        Err(NormalChatSessionIngressErrorV1::InputTooLarge { .. })
    ));
    for (field, value) in [
        ("grant_revision", json!(0)),
        ("conversation_ref", json!("")),
        ("conversation_ref", json!("bad\nreference")),
        ("ares_home_digest", json!("sha256:invalid")),
        (
            "policy_basis_digest",
            json!(format!("blake3:{}", "b".repeat(64))),
        ),
        ("parent_session_run_id", json!("not-owner-issued")),
    ] {
        let mut changed = fixture();
        changed[field] = value;
        assert!(
            parse_normal_chat_session_v1_bytes(&serde_json::to_vec(&changed)?).is_err(),
            "{field}"
        );
    }
    Ok(())
}
