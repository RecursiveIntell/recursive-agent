//! Raw transport digests are a distinct closed projection, never sorted JSON.
use recursive_agent_policy::parse_normal_chat_executor_report_v2_bytes;
use serde_json::json;

#[test]
fn raw_response_projection_is_distinct_and_empty_complete_is_valid(
) -> Result<(), Box<dyn std::error::Error>> {
    for bytes in [0_u64, 18] {
        let value = json!({"schema":"recursive-agent.normal-chat-executor-report/v2",
            "state":"succeeded","duration_ms":1,"response":{
            "projection_schema":"ares.transport-response-body/v1","digest":format!("sha256:{}", "a".repeat(64)),
            "byte_length":bytes,"complete":true},"usage":null});
        let parsed = parse_normal_chat_executor_report_v2_bytes(&serde_json::to_vec(&value)?)?;
        assert_eq!(
            serde_json::to_value(parsed)?["response"]["projection_schema"],
            "ares.transport-response-body/v1"
        );
    }
    Ok(())
}

#[test]
fn unknown_raw_projection_and_empty_sorted_json_are_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    for projection in [
        "ares.transport-response-body/v2",
        "ares-response-json-sorted-v1",
    ] {
        let value = json!({"schema":"recursive-agent.normal-chat-executor-report/v2",
            "state":"succeeded","duration_ms":1,"response":{
            "projection_schema":projection,"digest":format!("sha256:{}", "b".repeat(64)),
            "byte_length":0,"complete":true},"usage":null});
        assert!(parse_normal_chat_executor_report_v2_bytes(&serde_json::to_vec(&value)?).is_err());
    }
    Ok(())
}
