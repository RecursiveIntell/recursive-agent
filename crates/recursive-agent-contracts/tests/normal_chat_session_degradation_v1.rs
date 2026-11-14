use recursive_agent_contracts::{
    derive_artifact_id, jcs_canonical, parse_normal_chat_session_degradation_v1_bytes,
    ArtifactDescriptorV1, ContentDigest, NormalChatSessionDegradationV1,
    MAX_NORMAL_CHAT_SESSION_DEGRADATION_BYTES_V1,
};
use serde_json::{json, Value};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn id(domain: &str, byte: char) -> String {
    format!(
        "v1:recursive-agent/{domain}/v1:det:{}",
        byte.to_string().repeat(64)
    )
}
fn descriptor(bytes: &[u8]) -> Result<ArtifactDescriptorV1, Box<dyn std::error::Error>> {
    Ok(ArtifactDescriptorV1 {
        owner_id: derive_artifact_id(bytes)?,
        digest: ContentDigest::compute(bytes),
        byte_length: bytes.len() as u64,
        media_type: "application/json".into(),
        encoding: None,
    })
}
fn fixture() -> Result<Value, Box<dyn std::error::Error>> {
    Ok(json!({
        "schema":"recursive-agent.normal-chat-session-degradation/v1",
        "parent_run_id":id("run",'a'),"root_step_id":id("step",'a'),"root_permit_id":id("permit",'a'),
        "root_revocation_receipt_id":id("receipt",'a'),"root_revocation_evidence":descriptor(b"root")?,
        "family_closed_at":"2026-10-16T00:00:01Z","family_parent_revoked_at":null,"finalized_at":"2026-10-16T00:00:02Z",
        "children":[{"prepared_receipt_id":id("receipt",'b'),"linked_receipt_id":id("receipt",'c'),"closed_receipt_id":id("receipt",'d'),
            "child_run_id":id("run",'b'),"child_terminal_receipt_id":id("receipt",'e'),"child_chain_head":ContentDigest::compute(b"child-head"),
            "child_closed_artifact":descriptor(b"closure")?,"unknown_source":{"source":"missing_executor_outcome_v1","evidence":descriptor(b"recovery")?}}]
    }))
}
#[test]
fn closed_canonical_marker_preserves_reference_only_recovery_provenance() -> TestResult {
    let raw = fixture()?;
    let bytes = jcs_canonical(&raw)?;
    let marker = parse_normal_chat_session_degradation_v1_bytes(&bytes)?;
    let _: NormalChatSessionDegradationV1 = marker.clone();
    assert_eq!(jcs_canonical(&marker)?, bytes);
    for forbidden in [
        "usage",
        "duration_ms",
        "response",
        "report",
        "grant",
        "unknown",
    ] {
        assert!(!raw.as_object().ok_or("object")?.contains_key(forbidden));
    }
    Ok(())
}
#[test]
fn marker_parser_rejects_unknown_duplicate_noncanonical_and_oversize_material() -> TestResult {
    let raw = fixture()?;
    for mode in [
        "unknown",
        "wrong-schema",
        "alias-source",
        "unknown-source-field",
        "empty",
        "known-only",
        "duplicate-child",
        "parent-as-child",
        "invalid-time",
        "wrong-descriptor",
        "wrong-id",
    ] {
        let mut value = raw.clone();
        match mode {
            "unknown" => value["unknown"] = json!(true),
            "wrong-schema" => {
                value["schema"] = json!("recursive-agent.normal-chat-session-degradation/v2")
            }
            "alias-source" => {
                value["children"][0]["unknown_source"]["source"] = json!("provider_timeout")
            }
            "unknown-source-field" => value["children"][0]["unknown_source"]["usage"] = json!(0),
            "empty" => value["children"] = json!([]),
            "known-only" => value["children"][0]["unknown_source"] = json!(null),
            "duplicate-child" => value["children"]
                .as_array_mut()
                .ok_or("children")?
                .push(raw["children"][0].clone()),
            "parent-as-child" => {
                value["children"][0]["child_run_id"] = value["parent_run_id"].clone()
            }
            "invalid-time" => value["finalized_at"] = json!("2026-10-16T00:00:00Z"),
            "wrong-descriptor" => {
                value["root_revocation_evidence"]["media_type"] = json!("text/plain")
            }
            _ => value["root_step_id"] = json!(id("run", 'a')),
        };
        assert!(
            parse_normal_chat_session_degradation_v1_bytes(&jcs_canonical(&value)?).is_err(),
            "{mode}"
        );
    }
    let bytes = jcs_canonical(&raw)?;
    let mut whitespace = vec![b' '];
    whitespace.extend(&bytes);
    assert!(parse_normal_chat_session_degradation_v1_bytes(&whitespace).is_err());
    let duplicate = format!(
        "{{\"schema\":\"recursive-agent.normal-chat-session-degradation/v1\",{}",
        String::from_utf8(bytes)?.trim_start_matches('{')
    );
    assert!(parse_normal_chat_session_degradation_v1_bytes(duplicate.as_bytes()).is_err());
    assert!(parse_normal_chat_session_degradation_v1_bytes(&vec![
        b' ';
        MAX_NORMAL_CHAT_SESSION_DEGRADATION_BYTES_V1
            + 1
    ])
    .is_err());
    Ok(())
}
#[test]
fn reported_unknown_references_require_both_distinct_source_artifacts() -> TestResult {
    let mut value = fixture()?;
    value["children"][0]["unknown_source"] = json!({"source":"reported_unknown_v2","evidence":[descriptor(b"settlement")?,descriptor(b"degradation")?]});
    let expected = jcs_canonical(&value)?;
    assert_eq!(
        jcs_canonical(&parse_normal_chat_session_degradation_v1_bytes(&expected)?)?,
        expected
    );
    for evidence in [
        json!([]),
        json!([descriptor(b"only")?]),
        json!([descriptor(b"same")?, descriptor(b"same")?]),
        json!([descriptor(b"a")?, descriptor(b"b")?, descriptor(b"c")?]),
    ] {
        value["children"][0]["unknown_source"]["evidence"] = evidence;
        assert!(parse_normal_chat_session_degradation_v1_bytes(&jcs_canonical(&value)?).is_err());
    }
    Ok(())
}
