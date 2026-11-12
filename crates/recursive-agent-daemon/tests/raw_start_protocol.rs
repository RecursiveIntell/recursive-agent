use recursive_agent_daemon::{decode_request_frame, IpcDecodeError, IpcRequestV1};

fn frame(value: &serde_json::Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec(value)?;
    let mut result = u32::try_from(bytes.len())?.to_be_bytes().to_vec();
    result.extend(bytes);
    Ok(result)
}

#[test]
fn raw_start_is_a_closed_additive_carrier() -> Result<(), Box<dyn std::error::Error>> {
    let mut payload = serde_json::json!({
        "schema":"recursive-agent.ipc/request/v1", "protocol_version":1,
        "request_id":"raw-start", "request":{"kind":"start_native_raw", "operation_json_b64":"e30="},
    });
    let request = decode_request_frame(&frame(&payload)?)
        .map_err(|e| format!("raw start rejected: {e:?}"))?;
    assert!(matches!(
        request.request,
        IpcRequestV1::StartNativeRaw { .. }
    ));
    payload["request"]["allow_network"] = serde_json::json!(true);
    assert_eq!(
        decode_request_frame(&frame(&payload)?),
        Err(IpcDecodeError::Malformed)
    );
    Ok(())
}
