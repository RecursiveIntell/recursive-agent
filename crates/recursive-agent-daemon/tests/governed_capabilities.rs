//! Parser/startup metadata queries carry no authority or session mutation input.
use recursive_agent_daemon::protocol_v2::{decode_governed_request_frame, GovernedIpcRequestV2};
use recursive_agent_daemon::IpcDecodeError;
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn frame(request: Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec(&json!({"schema":"recursive-agent.ipc/request/v2",
        "protocol_version":2,"request_id":"capabilities-fixture","request":request}))?;
    let mut frame = u32::try_from(bytes.len())?.to_be_bytes().to_vec();
    frame.extend(bytes);
    Ok(frame)
}
#[test]
fn capability_query_is_closed_and_cannot_carry_authority_or_scope() -> TestResult {
    let request = json!({"kind":"normal_chat_capabilities"});
    let parsed =
        decode_governed_request_frame(&frame(request.clone())?).map_err(|e| format!("{e:?}"))?;
    assert!(matches!(
        parsed.request,
        GovernedIpcRequestV2::NormalChatCapabilities {}
    ));
    for field in ["grant", "session_run_id", "any_route", "caps", "mode"] {
        let mut extra = request.clone();
        extra[field] = json!(true);
        assert_eq!(
            decode_governed_request_frame(&frame(extra)?),
            Err(IpcDecodeError::Malformed)
        );
    }
    Ok(())
}
