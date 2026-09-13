use recursive_agent_provider::{
    prepare_openai_compatible_chat_request_v2, ConversationMessageV2, ConversationRequestSchemaV2,
    ConversationRequestV2, CredentialRef, ProviderError, ProviderSpecV1, ToolCallV2,
    ValidatedEndpoint,
};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn provider() -> Result<ProviderSpecV1, ProviderError> {
    Ok(ProviderSpecV1::OpenAiCompatible {
        base_url: ValidatedEndpoint::try_new("https://api.example.test/")?,
        model: "fixture-model".into(),
        credential_ref: CredentialRef::try_new("environment:TEST_PROVIDER_KEY")?,
    })
}

fn request() -> Result<ConversationRequestV2, ProviderError> {
    ConversationRequestV2::try_new(
        provider()?,
        vec![
            ConversationMessageV2::system("follow the policy"),
            ConversationMessageV2::user("inspect the current state\nusing the available lookup"),
            ConversationMessageV2::assistant_tool_calls(vec![ToolCallV2::try_new(
                "call-1",
                "lookup",
                json!({"query": "status"}),
            )?])?,
            ConversationMessageV2::tool_result("call-1", "current state is clean")?,
            ConversationMessageV2::assistant_text("the checked state is clean")?,
        ],
        Some(256),
    )
}

#[test]
fn structured_conversation_v2_preserves_tool_call_result_association() -> TestResult {
    let request = request()?;
    assert_eq!(request.schema, ConversationRequestSchemaV2::V2);
    let prepared = prepare_openai_compatible_chat_request_v2(&request)?;
    assert_eq!(
        prepared,
        json!({
            "model": "fixture-model",
            "messages": [
                {"role": "system", "content": "follow the policy"},
                {"role": "user", "content": "inspect the current state\nusing the available lookup"},
                {"role": "assistant", "content": null, "tool_calls": [{
                    "id": "call-1",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": "{\"query\":\"status\"}"}
                }]},
                {"role": "tool", "tool_call_id": "call-1", "content": "current state is clean"},
                {"role": "assistant", "content": "the checked state is clean"}
            ],
            "max_tokens": 256,
            "stream": false
        })
    );
    Ok(())
}

#[test]
fn structured_conversation_v2_rejects_unbound_duplicate_and_missing_tool_results() -> TestResult {
    let request = request()?;

    let mut unknown = serde_json::to_value(&request)?;
    unknown["messages"][3]["tool_call_id"] = json!("missing-call");
    assert!(serde_json::from_value::<ConversationRequestV2>(unknown).is_err());

    let mut duplicate = serde_json::to_value(&request)?;
    duplicate["messages"]
        .as_array_mut()
        .ok_or("messages were not serialized as an array")?
        .insert(
            4,
            json!({"role": "tool", "tool_call_id": "call-1", "content": "duplicate"}),
        );
    assert!(serde_json::from_value::<ConversationRequestV2>(duplicate).is_err());

    let mut repeated_call = serde_json::to_value(&request)?;
    repeated_call["messages"][2]["tool_calls"]
        .as_array_mut()
        .ok_or("assistant tool calls were not serialized as an array")?
        .push(json!({
            "id": "call-1",
            "name": "lookup",
            "arguments": {"query": "duplicate"}
        }));
    assert!(serde_json::from_value::<ConversationRequestV2>(repeated_call).is_err());

    let mut missing = serde_json::to_value(&request)?;
    missing["messages"]
        .as_array_mut()
        .ok_or("messages were not serialized as an array")?
        .remove(3);
    assert!(serde_json::from_value::<ConversationRequestV2>(missing).is_err());
    Ok(())
}

#[test]
fn structured_conversation_v2_rejects_unknown_raw_credential_and_multimodal_widening() -> TestResult
{
    let request = request()?;
    for (path, value) in [
        (("provider", "api_key"), json!("raw-secret")),
        (
            ("messages", "image_url"),
            json!("https://example.test/image.png"),
        ),
        (("messages", "unexpected"), json!(true)),
    ] {
        let mut encoded = serde_json::to_value(&request)?;
        if path.0 == "provider" {
            encoded["provider"][path.1] = value;
        } else {
            encoded["messages"][0][path.1] = value;
        }
        assert!(serde_json::from_value::<ConversationRequestV2>(encoded).is_err());
    }
    Ok(())
}
