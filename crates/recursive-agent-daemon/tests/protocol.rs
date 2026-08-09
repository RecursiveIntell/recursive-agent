use recursive_agent_daemon::{
    decode_request_frame, ConnectionRequestIds, IpcDecodeError, IPC_PROTOCOL_VERSION_V1,
    MAX_REQUEST_IDS_PER_CONNECTION,
};

fn frame(payload: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut framed = u32::try_from(payload.len())?.to_be_bytes().to_vec();
    framed.extend_from_slice(payload);
    Ok(framed)
}

#[test]
fn unsupported_protocol_version_is_typed_and_pre_effect() -> Result<(), Box<dyn std::error::Error>>
{
    let payload = br#"{
        "schema":"recursive-agent.ipc/request/v1",
        "protocol_version":2,
        "request_id":"req-version-2",
        "request":{"kind":"status","run_id":"run-1"}
    }"#;
    assert_eq!(
        decode_request_frame(&frame(payload)?),
        Err(IpcDecodeError::UnsupportedProtocolVersion {
            received: 2,
            supported: IPC_PROTOCOL_VERSION_V1,
        })
    );
    Ok(())
}

#[test]
fn duplicate_keys_in_original_wire_bytes_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let payload = br#"{
        "schema":"recursive-agent.ipc/request/v1",
        "protocol_version":1,
        "protocol_version":1,
        "request_id":"req-duplicate",
        "request":{"kind":"status","run_id":"run-1"}
    }"#;
    assert_eq!(
        decode_request_frame(&frame(payload)?),
        Err(IpcDecodeError::DuplicateKey)
    );
    Ok(())
}

#[test]
fn duplicate_request_ids_are_rejected_per_connection() -> Result<(), Box<dyn std::error::Error>> {
    let payload = br#"{
        "schema":"recursive-agent.ipc/request/v1",
        "protocol_version":1,
        "request_id":"req-reused",
        "request":{"kind":"status","run_id":"run-1"}
    }"#;
    let request = decode_request_frame(&frame(payload)?)
        .map_err(|error| format!("valid request rejected: {error:?}"))?;
    let mut ids = ConnectionRequestIds::new();
    assert_eq!(ids.admit(&request), Ok(()));
    Ok(())
}

#[test]
fn request_id_registry_has_a_hard_connection_budget() -> Result<(), Box<dyn std::error::Error>> {
    let payload = br#"{
        "schema":"recursive-agent.ipc/request/v1",
        "protocol_version":1,
        "request_id":"req-template",
        "request":{"kind":"status","run_id":"run-1"}
    }"#;
    let template = decode_request_frame(&frame(payload)?)
        .map_err(|error| format!("valid request rejected: {error:?}"))?;
    let mut ids = ConnectionRequestIds::new();
    for index in 0..MAX_REQUEST_IDS_PER_CONNECTION {
        let mut request = template.clone();
        request.request_id = format!("req-{index}");
        ids.admit(&request)
            .map_err(|error| format!("in-budget request rejected: {error:?}"))?;
    }
    let mut overflow = template;
    overflow.request_id = "req-overflow".to_owned();
    assert_eq!(
        ids.admit(&overflow),
        Err(IpcDecodeError::RequestIdLimitExceeded {
            max: MAX_REQUEST_IDS_PER_CONNECTION,
        })
    );
    Ok(())
}
