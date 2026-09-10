use recursive_agent_provider::{
    prepare_openai_compatible_chat_request, CompletionBackend, CompletionRequestV1,
    CompletionResponseV1, ConversationMessageV1, ConversationRequestSchemaV1,
    ConversationRequestV1, ConversationRoleV1, CredentialRef, ProviderError, ProviderSpecV1,
    ValidatedEndpoint,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct LegacyOnlyBackend;

impl CompletionBackend for LegacyOnlyBackend {
    fn complete(
        &self,
        _request: &CompletionRequestV1,
    ) -> Result<CompletionResponseV1, ProviderError> {
        Err(ProviderError::Unavailable)
    }
}

fn request() -> Result<ConversationRequestV1, Box<dyn std::error::Error>> {
    ConversationRequestV1::try_new(
        ProviderSpecV1::OpenAiCompatible {
            base_url: ValidatedEndpoint::try_new("https://api.example.test/")?,
            model: "fixture-model".into(),
            credential_ref: CredentialRef::try_new("environment:TEST_PROVIDER_KEY")?,
        },
        vec![
            ConversationMessageV1::new(ConversationRoleV1::System, "follow the policy"),
            ConversationMessageV1::new(ConversationRoleV1::User, "what changed?"),
            ConversationMessageV1::new(ConversationRoleV1::Assistant, "the request is closed"),
        ],
        Some(256),
    )
    .map_err(Into::into)
}

#[test]
fn raw_conversation_duplicate_matrix_preserves_valid_siblings() -> TestResult {
    let original = request()?;
    let encoded = serde_json::to_string(&original)?;
    assert_eq!(
        serde_json::from_str::<ConversationRequestV1>(&encoded)?,
        original
    );
    let value = serde_json::to_value(&original)?;
    for key in ["schema", "provider", "messages", "max_tokens"] {
        let needle = format!("\"{key}\":");
        let replacement = format!("\"{key}\":{},\"{key}\":", value[key]);
        let duplicate = encoded.replacen(&needle, &replacement, 1);
        let error = serde_json::from_str::<ConversationRequestV1>(&duplicate)
            .err()
            .ok_or("duplicate root field accepted")?;
        assert!(error.to_string().contains("duplicate"), "{key}: {error}");
    }
    for key in ["kind", "base_url", "model", "credential_ref"] {
        let needle = format!("\"{key}\":");
        let replacement = format!("\"{key}\":{},\"{key}\":", value["provider"][key]);
        let duplicate = encoded.replacen(&needle, &replacement, 1);
        let error = serde_json::from_str::<ConversationRequestV1>(&duplicate)
            .err()
            .ok_or("duplicate provider field accepted")?;
        assert!(error.to_string().contains("duplicate"), "{key}: {error}");
    }
    for key in ["role", "content"] {
        let needle = format!("\"{key}\":");
        let replacement = format!("\"{key}\":{},\"{key}\":", value["messages"][0][key]);
        let duplicate = encoded.replacen(&needle, &replacement, 1);
        let error = serde_json::from_str::<ConversationRequestV1>(&duplicate)
            .err()
            .ok_or("duplicate message field accepted")?;
        assert!(error.to_string().contains("duplicate"), "{key}: {error}");
    }
    // JSON escapes must not hide identity-equivalent duplicate keys.
    let escaped = encoded.replacen(
        "\"model\":",
        "\"mo\\u0064el\":\"fixture-model\",\"model\":",
        1,
    );
    assert!(serde_json::from_str::<ConversationRequestV1>(&escaped).is_err());
    for suffix in ["{}", "false", "garbage"] {
        assert!(
            serde_json::from_str::<ConversationRequestV1>(&format!("{encoded}{suffix}")).is_err()
        );
    }
    Ok(())
}

#[test]
fn provider_raw_json_rejects_duplicate_fields_before_value_conversion() -> TestResult {
    let raw = r#"{"kind":"open_ai_compatible","base_url":"https://api.example.test/","model":"first","model":"second","credential_ref":"environment:TEST_PROVIDER_KEY"}"#;
    assert!(serde_json::from_str::<ProviderSpecV1>(raw).is_err());
    let conversation = format!(
        r#"{{"schema":"recursive-agent.provider-conversation-request/v1","provider":{raw},"messages":[{{"role":"user","content":"hello"}}],"max_tokens":8}}"#
    );
    assert!(serde_json::from_str::<ConversationRequestV1>(&conversation).is_err());
    Ok(())
}

#[test]
fn legacy_completion_backends_fail_closed_for_conversation_requests() -> TestResult {
    let error = LegacyOnlyBackend
        .complete_conversation(&request()?)
        .err()
        .ok_or("legacy backend unexpectedly accepted a conversation request")?;
    assert!(matches!(error, ProviderError::Unavailable));
    Ok(())
}

#[test]
fn conversation_request_v1_preserves_ordered_text_messages_and_prepares_openai_body() -> TestResult
{
    let request = request()?;
    assert_eq!(request.schema, ConversationRequestSchemaV1::V1);
    assert_eq!(
        request
            .messages
            .iter()
            .map(|message| (&message.role, message.content.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (&ConversationRoleV1::System, "follow the policy"),
            (&ConversationRoleV1::User, "what changed?"),
            (&ConversationRoleV1::Assistant, "the request is closed"),
        ]
    );

    let prepared = prepare_openai_compatible_chat_request(&request)?;
    assert_eq!(
        serde_json::to_value(prepared)?,
        serde_json::json!({
            "model": "fixture-model",
            "messages": [
                {"role": "system", "content": "follow the policy"},
                {"role": "user", "content": "what changed?"},
                {"role": "assistant", "content": "the request is closed"}
            ],
            "max_tokens": 256,
            "stream": false
        })
    );
    Ok(())
}

#[test]
fn conversation_request_v1_serializes_and_deserializes_as_a_closed_schema() -> TestResult {
    let request = request()?;
    let serialized = serde_json::to_vec(&request)?;
    assert_eq!(
        serde_json::from_slice::<ConversationRequestV1>(&serialized)?,
        request
    );
    assert_eq!(
        serde_json::to_value(&request)?["schema"],
        "recursive-agent.provider-conversation-request/v1"
    );
    Ok(())
}

#[test]
fn conversation_request_v1_rejects_unknown_credential_retry_and_fallback_fields() -> TestResult {
    let request = request()?;
    for (field, value) in [
        ("api_key", serde_json::json!("raw-secret")),
        ("credential", serde_json::json!("raw-secret")),
        ("retry", serde_json::json!({"max_attempts": 3})),
        ("fallback", serde_json::json!({"provider": "other"})),
        ("unexpected", serde_json::json!(true)),
    ] {
        let mut encoded = serde_json::to_value(&request)?;
        encoded[field] = value;
        let error = serde_json::from_value::<ConversationRequestV1>(encoded)
            .err()
            .ok_or("unexpected conversation request field parsed")?;
        assert!(!error.to_string().contains("raw-secret"));
    }
    let mut nested_raw_key = serde_json::to_value(&request)?;
    nested_raw_key["provider"]["api_key"] = serde_json::Value::Null;
    let nested_error = serde_json::from_value::<ConversationRequestV1>(nested_raw_key)
        .err()
        .ok_or("nested raw api_key:null parsed")?;
    assert!(!nested_error.to_string().contains("raw-secret"));

    Ok(())
}

#[test]
fn conversation_request_v1_rejects_tool_and_multimodal_message_content() -> TestResult {
    let request = request()?;

    let mut tool_content = serde_json::to_value(&request)?;
    tool_content["messages"][1]["tool_calls"] = serde_json::json!([{"name": "lookup"}]);
    assert!(serde_json::from_value::<ConversationRequestV1>(tool_content).is_err());

    let mut multimodal_content = serde_json::to_value(&request)?;
    multimodal_content["messages"][1]["content"] = serde_json::json!([
        {"type": "text", "text": "what changed?"},
        {"type": "image_url", "image_url": {"url": "https://example.test/image.png"}}
    ]);
    assert!(serde_json::from_value::<ConversationRequestV1>(multimodal_content).is_err());
    Ok(())
}
