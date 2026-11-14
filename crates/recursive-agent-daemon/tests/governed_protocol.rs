//! Closed v2 ingress remains disjoint from v1 and cannot enroll authority.
use recursive_agent_contracts::{content_digest, CurrentRunId, KernelRunId};
use recursive_agent_daemon::protocol_v2::{decode_governed_request_frame, GovernedIpcRequestV2};
use recursive_agent_daemon::{decode_request_frame, IpcDecodeError};
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn framed(value: &Value) -> Vec<u8> {
    let bytes = value.to_string().into_bytes();
    let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
    frame.extend(bytes);
    frame
}
fn envelope(body: Value) -> Value {
    json!({"schema":"recursive-agent.ipc/request/v2","protocol_version":2,
        "request_id":"fixture-request-1","request":body})
}
fn run() -> Result<CurrentRunId, Box<dyn std::error::Error>> {
    Ok(CurrentRunId::from_owner(KernelRunId::deterministic(
        "recursive-agent/run/v1",
        recursive_agent_contracts::ContentDigest::compute(b"governed-ipc-fixture").hex(),
    )?)?)
}
#[test]
fn open_shape_is_closed_and_v1_never_downgrades_it() -> TestResult {
    let value = envelope(
        json!({"kind":"normal_chat_session_open", "conversation_ref":"session:fixture-1", "parent_session_run_id":null}),
    );
    let parsed = decode_governed_request_frame(&framed(&value)).map_err(|e| format!("{e:?}"))?;
    assert!(matches!(
        parsed.request,
        GovernedIpcRequestV2::NormalChatSessionOpen { .. }
    ));
    assert!(decode_request_frame(&framed(&value)).is_err());
    let mut grant = value.clone();
    grant["request"]["grant"] = json!({"any_route":true});
    assert_eq!(
        decode_governed_request_frame(&framed(&grant)),
        Err(IpcDecodeError::Malformed)
    );
    let mut missing = value.clone();
    missing["request"]
        .as_object_mut()
        .ok_or("fixture request is not an object")?
        .remove("parent_session_run_id");
    assert_eq!(
        decode_governed_request_frame(&framed(&missing)),
        Err(IpcDecodeError::Malformed)
    );
    Ok(())
}
#[test]
fn all_request_ids_are_bounded_nonempty_and_control_free() -> TestResult {
    let template = envelope(
        json!({"kind":"normal_chat_attempt_readback", "session_run_id":run()?, "dispatch_intent_ref":"intent:fixture-1"}),
    );
    for bad in ["", "request\n1", &"x".repeat(257)] {
        let mut v = template.clone();
        v["request_id"] = json!(bad);
        assert_eq!(
            decode_governed_request_frame(&framed(&v)),
            Err(IpcDecodeError::Malformed)
        );
    }
    Ok(())
}
#[test]
fn nested_duplicates_unknowns_lossy_option_and_wrong_versions_refuse() -> TestResult {
    let template = envelope(
        json!({"kind":"normal_chat_run_close", "session_run_id":run()?, "reason":"session_finalized"}),
    );
    let good = decode_governed_request_frame(&framed(&template)).map_err(|e| format!("{e:?}"))?;
    assert_eq!(serde_json::to_value(good)?, template);
    let raw = serde_json::to_string(&template)?.replace(
        "\"reason\":\"session_finalized\"",
        "\"reason\":\"session_finalized\",\"reason\":\"session_reset\"",
    );
    let mut frame = (raw.len() as u32).to_be_bytes().to_vec();
    frame.extend(raw.as_bytes());
    assert_eq!(
        decode_governed_request_frame(&frame),
        Err(IpcDecodeError::DuplicateKey)
    );
    for reason in [
        json!("ok"),
        json!(null),
        json!({"kind":"session_finalized"}),
    ] {
        let mut bad = template.clone();
        bad["request"]["reason"] = reason;
        assert_eq!(
            decode_governed_request_frame(&framed(&bad)),
            Err(IpcDecodeError::Malformed)
        );
    }
    let mut wrong = template.clone();
    wrong["protocol_version"] = json!(1);
    assert!(decode_governed_request_frame(&framed(&wrong)).is_err());
    let _ = content_digest(&template)?;
    Ok(())
}
#[test]
fn bad_id_intent_empty_conversation_and_oversize_are_rejected() -> TestResult {
    for body in [
        json!({"kind":"normal_chat_attempt_readback","session_run_id":"fake","dispatch_intent_ref":"intent:1"}),
        json!({"kind":"normal_chat_attempt_readback","session_run_id":run()?,"dispatch_intent_ref":""}),
        json!({"kind":"normal_chat_session_open","conversation_ref":"","parent_session_run_id":null}),
    ] {
        assert_eq!(
            decode_governed_request_frame(&framed(&envelope(body))),
            Err(IpcDecodeError::Malformed)
        );
    }
    assert!(decode_governed_request_frame(&u32::MAX.to_be_bytes()).is_err());
    Ok(())
}
