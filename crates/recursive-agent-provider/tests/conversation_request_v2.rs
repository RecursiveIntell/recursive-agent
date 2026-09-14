use boundary_compiler::canonicalize_v2;
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

#[test]
fn v2_tool_arguments_use_libraries_utf16_canonical_order() -> TestResult {
    let arguments = json!({"\u{e000}": 1, "\u{10000}": 2});
    let request = ConversationRequestV2::try_new(
        provider()?,
        vec![
            ConversationMessageV2::user("inspect"),
            ConversationMessageV2::assistant_tool_calls(vec![ToolCallV2::try_new(
                "call-order",
                "lookup",
                arguments.clone(),
            )?])?,
            ConversationMessageV2::tool_result("call-order", "done")?,
        ],
        Some(64),
    )?;
    let prepared = prepare_openai_compatible_chat_request_v2(&request)?;
    let rendered = prepared["messages"][1]["tool_calls"][0]["function"]["arguments"]
        .as_str()
        .ok_or("arguments were not rendered as a string")?;
    assert_eq!(rendered, canonicalize_v2(&arguments)?);
    assert_eq!(rendered, "{\"𐀀\":2,\"\":1}");
    assert_ne!(rendered, serde_json::to_string(&arguments)?);
    Ok(())
}

#[test]
fn v2_rejects_interrupted_unresolved_tool_groups() -> TestResult {
    let call_one = ToolCallV2::try_new("call-one", "lookup", json!({"query": "one"}))?;
    let call_two = ToolCallV2::try_new("call-two", "lookup", json!({"query": "two"}))?;
    let interrupted = ConversationRequestV2::try_new(
        provider()?,
        vec![
            ConversationMessageV2::user("inspect"),
            ConversationMessageV2::assistant_tool_calls(vec![call_one.clone()])?,
            ConversationMessageV2::user("unrelated interruption"),
            ConversationMessageV2::tool_result("call-one", "done")?,
        ],
        Some(64),
    );
    assert!(matches!(
        interrupted,
        Err(ProviderError::InvalidConversationToolResult)
    ));

    let second_group = ConversationRequestV2::try_new(
        provider()?,
        vec![
            ConversationMessageV2::user("inspect"),
            ConversationMessageV2::assistant_tool_calls(vec![call_one, call_two])?,
            ConversationMessageV2::assistant_text("interrupted")?,
        ],
        Some(64),
    );
    assert!(matches!(
        second_group,
        Err(ProviderError::InvalidConversationToolResult)
    ));
    Ok(())
}

#[test]
fn v2_accepts_a_contiguous_parallel_tool_result_group() -> TestResult {
    let request = ConversationRequestV2::try_new(
        provider()?,
        vec![
            ConversationMessageV2::user("inspect"),
            ConversationMessageV2::assistant_tool_calls(vec![
                ToolCallV2::try_new("call-one", "lookup", json!({"query": "one"}))?,
                ToolCallV2::try_new("call-two", "lookup", json!({"query": "two"}))?,
            ])?,
            ConversationMessageV2::tool_result("call-two", "two")?,
            ConversationMessageV2::tool_result("call-one", "one")?,
        ],
        Some(64),
    )?;
    assert_eq!(request.messages.len(), 4);
    Ok(())
}

#[test]
fn v2_rejects_nonrepresentable_numeric_arguments_at_admission() -> TestResult {
    let result = ConversationRequestV2::try_new(
        provider()?,
        vec![
            ConversationMessageV2::user("inspect"),
            ConversationMessageV2::assistant_tool_calls(vec![ToolCallV2::try_new(
                "call-number",
                "lookup",
                json!({"large": 9_007_199_254_740_993_u64}),
            )?])?,
            ConversationMessageV2::tool_result("call-number", "done")?,
        ],
        Some(64),
    );
    assert!(matches!(
        result,
        Err(ProviderError::InvalidConversationToolCall)
    ));
    Ok(())
}

#[test]
fn v2_enforces_exact_message_group_and_cumulative_tool_limits() -> TestResult {
    let exact_messages = ConversationRequestV2::try_new(
        provider()?,
        (0..256)
            .map(|index| ConversationMessageV2::user(format!("message-{index}")))
            .collect(),
        Some(64),
    );
    assert!(exact_messages.is_ok());

    let too_many_messages = ConversationRequestV2::try_new(
        provider()?,
        (0..257)
            .map(|index| ConversationMessageV2::user(format!("message-{index}")))
            .collect(),
        Some(64),
    );
    assert!(too_many_messages.is_err());

    let group_calls = (0..65)
        .map(|index| ToolCallV2::try_new(format!("group-{index}"), "lookup", json!({})))
        .collect::<Result<Vec<_>, _>>()?;
    let too_many_in_group = ConversationRequestV2::try_new(
        provider()?,
        vec![
            ConversationMessageV2::user("inspect"),
            ConversationMessageV2::assistant_tool_calls(group_calls)?,
        ],
        Some(64),
    );
    assert!(too_many_in_group.is_err());

    let mut cumulative = vec![ConversationMessageV2::user("inspect")];
    for group in [64_usize, 64, 1] {
        let calls = (0..group)
            .map(|index| {
                ToolCallV2::try_new(
                    format!("total-{}-{index}", cumulative.len()),
                    "lookup",
                    json!({}),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let ids = calls.iter().map(|call| call.id.clone()).collect::<Vec<_>>();
        cumulative.push(ConversationMessageV2::assistant_tool_calls(calls)?);
        for id in ids {
            cumulative.push(ConversationMessageV2::tool_result(id, "done")?);
        }
    }
    assert!(ConversationRequestV2::try_new(provider()?, cumulative, Some(64)).is_err());

    let mut nested = json!({"leaf": true});
    for _ in 0..70 {
        nested = json!({"next": nested});
    }
    let too_deep = ConversationRequestV2::try_new(
        provider()?,
        vec![
            ConversationMessageV2::user("inspect"),
            ConversationMessageV2::assistant_tool_calls(vec![ToolCallV2::try_new(
                "call-deep",
                "lookup",
                nested,
            )?])?,
            ConversationMessageV2::tool_result("call-deep", "done")?,
        ],
        Some(64),
    );
    assert!(too_deep.is_err());

    let oversized = json!({"payload": "x".repeat(1_100_000)});
    let too_large = ConversationRequestV2::try_new(
        provider()?,
        vec![
            ConversationMessageV2::user("inspect"),
            ConversationMessageV2::assistant_tool_calls(vec![ToolCallV2::try_new(
                "call-large",
                "lookup",
                oversized,
            )?])?,
            ConversationMessageV2::tool_result("call-large", "done")?,
        ],
        Some(64),
    );
    assert!(too_large.is_err());
    Ok(())
}
