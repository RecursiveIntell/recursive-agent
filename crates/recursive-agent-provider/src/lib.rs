//! Secret-free provider contracts for receipt-bearing LLM calls.
//!
//! Serializable requests contain only opaque credential references. Resolved
//! secret bytes exist only while constructing the sensitive authorization
//! header and are never formatted, serialized, or included in provider errors.

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use url::Url;

/// A normalized, secret-free HTTP(S) provider origin admitted at ingress.
/// Invalid URLs cannot be represented by this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedEndpoint(Url);

impl ValidatedEndpoint {
    pub fn try_new(value: impl AsRef<str>) -> Result<Self, ProviderError> {
        validate_base_url(value.as_ref()).map(Self)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn route_url(&self, route: ProviderRoute) -> Url {
        endpoint(&self.0, route)
    }
}

impl Serialize for ValidatedEndpoint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ValidatedEndpoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::try_new(value).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<&str> for ValidatedEndpoint {
    type Error = ProviderError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl TryFrom<String> for ValidatedEndpoint {
    type Error = ProviderError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CredentialRef(String);

impl CredentialRef {
    pub fn try_new(value: impl Into<String>) -> Result<Self, ProviderError> {
        let value = value.into();
        let Some(variable) = value.strip_prefix("environment:") else {
            return Err(ProviderError::InvalidCredentialReference);
        };
        if !is_portable_environment_name(variable) {
            return Err(ProviderError::InvalidCredentialReference);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CredentialRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::try_new(value).map_err(|_| {
            serde::de::Error::custom(
                "invalid credential reference; expected environment:PORTABLE_NAME",
            )
        })
    }
}

fn is_portable_environment_name(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CredentialResolveError {
    #[error("credential was not found")]
    Missing,
    #[error("credential reference is unsupported")]
    UnsupportedReference,
    #[error("credential value is empty or invalid")]
    InvalidValue,
}

pub trait CredentialResolver {
    fn resolve(
        &self,
        credential_ref: &CredentialRef,
    ) -> Result<SecretBytes, CredentialResolveError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EnvironmentCredentialResolver;

impl CredentialResolver for EnvironmentCredentialResolver {
    fn resolve(
        &self,
        credential_ref: &CredentialRef,
    ) -> Result<SecretBytes, CredentialResolveError> {
        let variable = credential_ref
            .as_str()
            .strip_prefix("environment:")
            .ok_or(CredentialResolveError::UnsupportedReference)?;
        if variable.trim().is_empty() {
            return Err(CredentialResolveError::UnsupportedReference);
        }
        let value = std::env::var(variable).map_err(|error| match error {
            std::env::VarError::NotPresent => CredentialResolveError::Missing,
            std::env::VarError::NotUnicode(_) => CredentialResolveError::InvalidValue,
        })?;
        if value.is_empty() {
            return Err(CredentialResolveError::InvalidValue);
        }
        Ok(SecretBytes::new(value.into_bytes()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderSpecV1 {
    Ollama {
        base_url: ValidatedEndpoint,
        model: String,
    },
    OpenAiCompatible {
        base_url: ValidatedEndpoint,
        model: String,
        credential_ref: CredentialRef,
    },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ProviderSpecWire {
    Ollama {
        base_url: ValidatedEndpoint,
        model: String,
    },
    OpenAiCompatible {
        base_url: ValidatedEndpoint,
        model: String,
        credential_ref: Option<CredentialRef>,
        #[serde(
            default,
            rename = "api_key",
            deserialize_with = "reject_raw_provider_key"
        )]
        _raw_key: (),
    },
}

fn reject_raw_provider_key<'de, D: Deserializer<'de>>(_deserializer: D) -> Result<(), D::Error> {
    Err(serde::de::Error::custom(
        "raw provider credentials are forbidden; migrate to credential_ref: environment:NAME",
    ))
}

impl<'de> Deserialize<'de> for ProviderSpecV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match ProviderSpecWire::deserialize(deserializer)? {
            ProviderSpecWire::Ollama { base_url, model } => Ok(Self::Ollama { base_url, model }),
            ProviderSpecWire::OpenAiCompatible {
                base_url,
                model,
                credential_ref,
                _raw_key: (),
            } => {
                let credential_ref = credential_ref.ok_or_else(|| {
                    serde::de::Error::custom(
                        "missing credential_ref; expected environment:PORTABLE_NAME",
                    )
                })?;
                Ok(Self::OpenAiCompatible {
                    base_url,
                    model,
                    credential_ref,
                })
            }
        }
    }
}

impl ProviderSpecV1 {
    /// Canonical secret-free provider identity used by native egress bindings.
    pub fn egress_provider_identity(&self) -> String {
        let (kind, base_url) = match self {
            Self::Ollama { base_url, .. } => ("ollama", base_url),
            Self::OpenAiCompatible { base_url, .. } => ("openai_compatible", base_url),
        };
        format!("{kind}:{}", base_url.as_str().trim_end_matches('/'))
    }

    /// Canonical model reference used by native egress bindings.
    pub fn egress_model_ref(&self) -> String {
        let model = match self {
            Self::Ollama { model, .. } | Self::OpenAiCompatible { model, .. } => model,
        };
        format!("model:{model}")
    }

    /// Require policy-facing binding metadata to describe this exact decoded route.
    pub fn matches_egress_binding(&self, provider_identity: &str, model_ref: &str) -> bool {
        self.egress_provider_identity() == provider_identity && self.egress_model_ref() == model_ref
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionRequestV1 {
    pub provider: ProviderSpecV1,
    pub prompt: String,
    pub max_tokens: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionResponseV1 {
    pub model: String,
    pub text: String,
    pub raw: serde_json::Value,
}

/// Exact schema tag for the closed provider conversation request representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConversationRequestSchemaV1 {
    #[serde(rename = "recursive-agent.provider-conversation-request/v1")]
    V1,
}

/// The only conversational roles admitted by the initial provider adapter boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationRoleV1 {
    System,
    User,
    Assistant,
}

/// One ordered, text-only conversation message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationMessageV1 {
    pub role: ConversationRoleV1,
    pub content: String,
}

impl ConversationMessageV1 {
    pub fn new(role: ConversationRoleV1, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
        }
    }
}

/// Closed, secret-free input for a future native chat-completions adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationRequestV1 {
    pub schema: ConversationRequestSchemaV1,
    pub provider: ProviderSpecV1,
    pub messages: Vec<ConversationMessageV1>,
    pub max_tokens: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConversationRequestWireV1 {
    schema: ConversationRequestSchemaV1,
    provider: ProviderSpecV1,
    messages: Vec<ConversationMessageV1>,
    max_tokens: Option<u32>,
}

impl<'de> Deserialize<'de> for ConversationRequestV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ConversationRequestWireV1::deserialize(deserializer)?;
        Self::from_parts(wire.schema, wire.provider, wire.messages, wire.max_tokens)
            .map_err(serde::de::Error::custom)
    }
}

impl ConversationRequestV1 {
    pub fn try_new(
        provider: ProviderSpecV1,
        messages: Vec<ConversationMessageV1>,
        max_tokens: Option<u32>,
    ) -> Result<Self, ProviderError> {
        Self::from_parts(
            ConversationRequestSchemaV1::V1,
            provider,
            messages,
            max_tokens,
        )
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        Self::from_parts(
            self.schema,
            self.provider.clone(),
            self.messages.clone(),
            self.max_tokens,
        )
        .map(|_| ())
    }

    fn from_parts(
        schema: ConversationRequestSchemaV1,
        provider: ProviderSpecV1,
        messages: Vec<ConversationMessageV1>,
        max_tokens: Option<u32>,
    ) -> Result<Self, ProviderError> {
        if schema != ConversationRequestSchemaV1::V1 {
            return Err(ProviderError::UnsupportedConversationSchema);
        }
        if messages.is_empty() {
            return Err(ProviderError::EmptyConversation);
        }
        Ok(Self {
            schema,
            provider,
            messages,
            max_tokens,
        })
    }
}

/// Prepared OpenAI-compatible request body, intentionally excluding endpoint and credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenAiCompatibleChatRequestV1 {
    pub model: String,
    pub messages: Vec<ConversationMessageV1>,
    pub max_tokens: Option<u32>,
    pub stream: bool,
}

/// Prepare a closed text-only request body without resolving credentials or performing I/O.
pub fn prepare_openai_compatible_chat_request(
    request: &ConversationRequestV1,
) -> Result<OpenAiCompatibleChatRequestV1, ProviderError> {
    request.validate()?;
    let ProviderSpecV1::OpenAiCompatible { model, .. } = &request.provider else {
        return Err(ProviderError::UnsupportedConversationProvider);
    };
    Ok(OpenAiCompatibleChatRequestV1 {
        model: model.clone(),
        messages: request.messages.clone(),
        max_tokens: request.max_tokens,
        stream: false,
    })
}

/// Exact schema tag for a structured conversation that preserves read-only tool
/// request/result association. V1 remains text-only and is never widened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConversationRequestSchemaV2 {
    #[serde(rename = "recursive-agent.provider-conversation-request/v2")]
    V2,
}

/// One closed provider tool invocation. Arguments remain structured until the
/// provider renderer produces its exact JSON string representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCallV2 {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

impl ToolCallV2 {
    pub fn try_new(
        id: impl Into<String>,
        name: impl Into<String>,
        arguments: serde_json::Value,
    ) -> Result<Self, ProviderError> {
        let value = Self {
            id: id.into(),
            name: name.into(),
            arguments,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ProviderError> {
        validate_conversation_identifier(&self.id, "tool call id")?;
        validate_conversation_identifier(&self.name, "tool call name")?;
        if !self.arguments.is_object() {
            return Err(ProviderError::InvalidConversationToolCall);
        }
        Ok(())
    }
}

/// Ordered text-only provider messages with typed tool request/result linkage.
/// Non-text/multimodal parts are intentionally not represented by this profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConversationMessageV2 {
    System {
        content: String,
    },
    User {
        content: String,
    },
    Assistant {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tool_calls: Vec<ToolCallV2>,
    },
    Tool {
        tool_call_id: String,
        content: String,
    },
}

impl ConversationMessageV2 {
    pub fn system(content: impl Into<String>) -> Self {
        Self::System {
            content: content.into(),
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self::User {
            content: content.into(),
        }
    }

    pub fn assistant_text(content: impl Into<String>) -> Result<Self, ProviderError> {
        let value = Self::Assistant {
            content: Some(content.into()),
            tool_calls: Vec::new(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn assistant_tool_calls(tool_calls: Vec<ToolCallV2>) -> Result<Self, ProviderError> {
        let value = Self::Assistant {
            content: None,
            tool_calls,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn tool_result(
        tool_call_id: impl Into<String>,
        content: impl Into<String>,
    ) -> Result<Self, ProviderError> {
        let value = Self::Tool {
            tool_call_id: tool_call_id.into(),
            content: content.into(),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ProviderError> {
        match self {
            Self::System { content } | Self::User { content } => {
                validate_conversation_content(content)
            }
            Self::Assistant {
                content,
                tool_calls,
            } => {
                if content.as_ref().is_some_and(|value| value.is_empty())
                    || content.is_none() && tool_calls.is_empty()
                {
                    return Err(ProviderError::InvalidConversationMessage);
                }
                if let Some(value) = content {
                    validate_conversation_content(value)?;
                }
                for call in tool_calls {
                    call.validate()?;
                }
                Ok(())
            }
            Self::Tool {
                tool_call_id,
                content,
            } => {
                validate_conversation_identifier(tool_call_id, "tool result id")?;
                validate_conversation_content(content)
            }
        }
    }
}

/// Closed V2 request. V2 admits ordered text messages and complete tool
/// request/result pairs; it cannot be silently decoded as V1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationRequestV2 {
    pub schema: ConversationRequestSchemaV2,
    pub provider: ProviderSpecV1,
    pub messages: Vec<ConversationMessageV2>,
    pub max_tokens: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConversationRequestWireV2 {
    schema: ConversationRequestSchemaV2,
    provider: ProviderSpecV1,
    messages: Vec<ConversationMessageV2>,
    max_tokens: Option<u32>,
}

impl<'de> Deserialize<'de> for ConversationRequestV2 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ConversationRequestWireV2::deserialize(deserializer)?;
        Self::from_parts(wire.schema, wire.provider, wire.messages, wire.max_tokens)
            .map_err(serde::de::Error::custom)
    }
}

impl ConversationRequestV2 {
    pub fn try_new(
        provider: ProviderSpecV1,
        messages: Vec<ConversationMessageV2>,
        max_tokens: Option<u32>,
    ) -> Result<Self, ProviderError> {
        Self::from_parts(
            ConversationRequestSchemaV2::V2,
            provider,
            messages,
            max_tokens,
        )
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        Self::from_parts(
            self.schema,
            self.provider.clone(),
            self.messages.clone(),
            self.max_tokens,
        )
        .map(|_| ())
    }

    fn from_parts(
        schema: ConversationRequestSchemaV2,
        provider: ProviderSpecV1,
        messages: Vec<ConversationMessageV2>,
        max_tokens: Option<u32>,
    ) -> Result<Self, ProviderError> {
        if schema != ConversationRequestSchemaV2::V2 {
            return Err(ProviderError::UnsupportedConversationSchema);
        }
        if messages.is_empty() {
            return Err(ProviderError::EmptyConversation);
        }
        let mut declared = std::collections::BTreeSet::new();
        let mut unresolved = std::collections::BTreeSet::new();
        for message in &messages {
            message.validate()?;
            match message {
                ConversationMessageV2::Assistant { tool_calls, .. } => {
                    for call in tool_calls {
                        if !declared.insert(call.id.clone()) || !unresolved.insert(call.id.clone())
                        {
                            return Err(ProviderError::InvalidConversationToolCall);
                        }
                    }
                }
                ConversationMessageV2::Tool { tool_call_id, .. } => {
                    if !unresolved.remove(tool_call_id) {
                        return Err(ProviderError::InvalidConversationToolResult);
                    }
                }
                ConversationMessageV2::System { .. } | ConversationMessageV2::User { .. } => {}
            }
        }
        if !unresolved.is_empty() {
            return Err(ProviderError::InvalidConversationToolResult);
        }
        Ok(Self {
            schema,
            provider,
            messages,
            max_tokens,
        })
    }
}

/// Render one V2 request as the exact non-streaming OpenAI-compatible payload.
/// This is preparation only: it resolves no credential and performs no I/O.
pub fn prepare_openai_compatible_chat_request_v2(
    request: &ConversationRequestV2,
) -> Result<serde_json::Value, ProviderError> {
    request.validate()?;
    let ProviderSpecV1::OpenAiCompatible { model, .. } = &request.provider else {
        return Err(ProviderError::UnsupportedConversationProvider);
    };
    let messages = request
        .messages
        .iter()
        .map(render_openai_message_v2)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(serde_json::json!({
        "model": model,
        "messages": messages,
        "max_tokens": request.max_tokens,
        "stream": false,
    }))
}

fn render_openai_message_v2(
    message: &ConversationMessageV2,
) -> Result<serde_json::Value, ProviderError> {
    match message {
        ConversationMessageV2::System { content } => {
            Ok(serde_json::json!({"role": "system", "content": content}))
        }
        ConversationMessageV2::User { content } => {
            Ok(serde_json::json!({"role": "user", "content": content}))
        }
        ConversationMessageV2::Assistant {
            content,
            tool_calls,
        } => {
            let calls = tool_calls
                .iter()
                .map(|call| {
                    Ok(serde_json::json!({
                        "id": call.id,
                        "type": "function",
                        "function": {
                            "name": call.name,
                            "arguments": serde_json::to_string(&call.arguments)
                                .map_err(|_| ProviderError::InvalidConversationToolCall)?,
                        },
                    }))
                })
                .collect::<Result<Vec<_>, ProviderError>>()?;
            let mut value = serde_json::json!({"role": "assistant", "content": content});
            if !calls.is_empty() {
                value["tool_calls"] = serde_json::Value::Array(calls);
            }
            Ok(value)
        }
        ConversationMessageV2::Tool {
            tool_call_id,
            content,
        } => Ok(serde_json::json!({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": content,
        })),
    }
}

fn validate_conversation_identifier(value: &str, _name: &str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > 256
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return Err(ProviderError::InvalidConversationToolCall);
    }
    Ok(())
}

fn validate_conversation_content(value: &str) -> Result<(), ProviderError> {
    if value.is_empty() || value.len() > 1024 * 1024 {
        return Err(ProviderError::InvalidConversationMessage);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("conversation request schema is unsupported")]
    UnsupportedConversationSchema,
    #[error("conversation request must contain at least one message")]
    EmptyConversation,
    #[error("conversation message is malformed or unsupported")]
    InvalidConversationMessage,
    #[error("conversation tool call is malformed or duplicated")]
    InvalidConversationToolCall,
    #[error("conversation tool result is unbound, duplicated, or missing")]
    InvalidConversationToolResult,
    #[error("conversation request requires an OpenAI-compatible provider")]
    UnsupportedConversationProvider,
    #[error("empty base_url for provider")]
    EmptyBaseUrl,
    #[error("empty model for provider")]
    EmptyModel,
    #[error("invalid credential reference")]
    InvalidCredentialReference,
    #[error("credential was not found")]
    MissingCredential,
    #[error("credential reference is unsupported")]
    UnsupportedCredentialReference,
    #[error("credential value is invalid")]
    InvalidCredential,
    #[error("provider URL was rejected: {reason}")]
    InvalidProviderUrl { reason: ProviderUrlRejection },
    #[error("http request failed during {operation}")]
    Http { operation: &'static str },
    #[error("provider returned non-success status {status}")]
    HttpStatus { status: u16 },
    #[error("provider execution is unavailable in Phase 1")]
    Unavailable,
    #[error("malformed provider response: {0}")]
    Malformed(String),
}

/// A provider boundary that performs one explicitly requested completion.
/// Implementations must never hide retries, fallback providers, or credential
/// resolution behind the planner contract.
pub trait CompletionBackend {
    fn complete(
        &self,
        request: &CompletionRequestV1,
    ) -> Result<CompletionResponseV1, ProviderError>;

    /// Legacy backends must opt in explicitly before they can receive a
    /// structured conversation. The default is fail-closed and performs no I/O.
    fn complete_conversation(
        &self,
        _request: &ConversationRequestV1,
    ) -> Result<CompletionResponseV1, ProviderError> {
        Err(ProviderError::Unavailable)
    }

    /// V2 callers must opt in explicitly. The default performs no I/O so a
    /// legacy backend cannot accidentally accept structured tool history.
    fn complete_conversation_v2(
        &self,
        _request: &ConversationRequestV2,
    ) -> Result<CompletionResponseV1, ProviderError> {
        Err(ProviderError::Unavailable)
    }
}

/// Explicit HTTP provider backend for Ollama and OpenAI-compatible APIs.
/// Constructing this backend does not perform network I/O; calls happen only
/// when `complete` is invoked by an admitted runtime path.
#[derive(Debug, Clone)]
pub struct HttpCompletionBackend {
    timeout: std::time::Duration,
}

impl HttpCompletionBackend {
    pub fn new(timeout: std::time::Duration) -> Result<Self, ProviderError> {
        if timeout.is_zero() {
            return Err(ProviderError::Http {
                operation: "client_build",
            });
        }
        Ok(Self { timeout })
    }

    fn build_client(&self) -> Result<reqwest::blocking::Client, ProviderError> {
        reqwest::blocking::Client::builder()
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| ProviderError::Http {
                operation: "client_build",
            })
    }

    fn complete_openai_conversation_with_resolver<R: CredentialResolver>(
        &self,
        provider: &ProviderSpecV1,
        body: serde_json::Value,
        resolver: &R,
    ) -> Result<CompletionResponseV1, ProviderError> {
        let ProviderSpecV1::OpenAiCompatible {
            base_url,
            model,
            credential_ref,
        } = provider
        else {
            return Err(ProviderError::UnsupportedConversationProvider);
        };
        let credential = resolver
            .resolve(credential_ref)
            .map_err(map_credential_error)?;
        let token = std::str::from_utf8(credential.as_bytes())
            .map_err(|_| ProviderError::InvalidCredential)?;
        let response = self
            .build_client()?
            .post(base_url.route_url(ProviderRoute::OpenAiChatCompletions))
            .bearer_auth(token)
            .json(&body)
            .send()
            .map_err(|_| ProviderError::Http {
                operation: "openai_conversation",
            })?;
        decode_openai_response(model, response)
    }

    /// Execute one validated V1 conversation through a caller-provided secret
    /// resolver. The resolver exists for owner-controlled composition and
    /// loopback fixtures; callers still own admission and effect authority.
    pub fn complete_conversation_with_resolver<R: CredentialResolver>(
        &self,
        request: &ConversationRequestV1,
        resolver: &R,
    ) -> Result<CompletionResponseV1, ProviderError> {
        request.validate()?;
        let body = serde_json::to_value(prepare_openai_compatible_chat_request(request)?).map_err(
            |_| ProviderError::Malformed("conversation request serialization failed".into()),
        )?;
        self.complete_openai_conversation_with_resolver(&request.provider, body, resolver)
    }

    /// Execute one validated V2 conversation through a caller-provided secret
    /// resolver. This preserves the provider-owned rendered tool association.
    pub fn complete_conversation_v2_with_resolver<R: CredentialResolver>(
        &self,
        request: &ConversationRequestV2,
        resolver: &R,
    ) -> Result<CompletionResponseV1, ProviderError> {
        request.validate()?;
        let body = prepare_openai_compatible_chat_request_v2(request)?;
        self.complete_openai_conversation_with_resolver(&request.provider, body, resolver)
    }
}

fn map_credential_error(error: CredentialResolveError) -> ProviderError {
    match error {
        CredentialResolveError::Missing => ProviderError::MissingCredential,
        CredentialResolveError::UnsupportedReference => {
            ProviderError::UnsupportedCredentialReference
        }
        CredentialResolveError::InvalidValue => ProviderError::InvalidCredential,
    }
}

fn decode_openai_response(
    model: &str,
    response: reqwest::blocking::Response,
) -> Result<CompletionResponseV1, ProviderError> {
    let status = response.status();
    if !status.is_success() {
        return Err(ProviderError::HttpStatus {
            status: status.as_u16(),
        });
    }
    let raw = response
        .json::<serde_json::Value>()
        .map_err(|error| ProviderError::Malformed(error.to_string()))?;
    let text = raw
        .get("choices")
        .and_then(|choices| choices.get(0))
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(serde_json::Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| ProviderError::Malformed("missing non-empty content".into()))?;
    Ok(CompletionResponseV1 {
        model: model.to_owned(),
        text: text.to_owned(),
        raw,
    })
}

impl Default for HttpCompletionBackend {
    fn default() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(120),
        }
    }
}

impl CompletionBackend for HttpCompletionBackend {
    fn complete(
        &self,
        request: &CompletionRequestV1,
    ) -> Result<CompletionResponseV1, ProviderError> {
        let client = self.build_client()?;
        match &request.provider {
            ProviderSpecV1::Ollama { base_url, model } => {
                let mut body = serde_json::json!({
                    "model": model,
                    "prompt": request.prompt,
                    "stream": false,
                });
                if let Some(max_tokens) = request.max_tokens {
                    body["options"] = serde_json::json!({ "num_predict": max_tokens });
                }
                let response = client
                    .post(base_url.route_url(ProviderRoute::OllamaGenerate))
                    .json(&body)
                    .send()
                    .map_err(|_| ProviderError::Http {
                        operation: "ollama_completion",
                    })?;
                let status = response.status();
                if !status.is_success() {
                    return Err(ProviderError::HttpStatus {
                        status: status.as_u16(),
                    });
                }
                let raw = response
                    .json::<serde_json::Value>()
                    .map_err(|error| ProviderError::Malformed(error.to_string()))?;
                let text = raw
                    .get("response")
                    .and_then(serde_json::Value::as_str)
                    .filter(|text| !text.is_empty())
                    .ok_or_else(|| ProviderError::Malformed("missing non-empty response".into()))?;
                Ok(CompletionResponseV1 {
                    model: model.clone(),
                    text: text.to_owned(),
                    raw,
                })
            }
            ProviderSpecV1::OpenAiCompatible {
                base_url,
                model,
                credential_ref,
            } => {
                let credential = EnvironmentCredentialResolver
                    .resolve(credential_ref)
                    .map_err(|error| match error {
                        CredentialResolveError::Missing => ProviderError::MissingCredential,
                        CredentialResolveError::UnsupportedReference => {
                            ProviderError::UnsupportedCredentialReference
                        }
                        CredentialResolveError::InvalidValue => ProviderError::InvalidCredential,
                    })?;
                let token = std::str::from_utf8(credential.as_bytes())
                    .map_err(|_| ProviderError::InvalidCredential)?;
                let mut body = serde_json::json!({
                    "model": model,
                    "messages": [{"role": "user", "content": request.prompt}],
                    "stream": false,
                });
                if let Some(max_tokens) = request.max_tokens {
                    body["max_tokens"] = serde_json::json!(max_tokens);
                }
                let response = client
                    .post(base_url.route_url(ProviderRoute::OpenAiChatCompletions))
                    .bearer_auth(token)
                    .json(&body)
                    .send()
                    .map_err(|_| ProviderError::Http {
                        operation: "openai_completion",
                    })?;
                let status = response.status();
                if !status.is_success() {
                    return Err(ProviderError::HttpStatus {
                        status: status.as_u16(),
                    });
                }
                let raw = response
                    .json::<serde_json::Value>()
                    .map_err(|error| ProviderError::Malformed(error.to_string()))?;
                let text = raw
                    .get("choices")
                    .and_then(|choices| choices.get(0))
                    .and_then(|choice| choice.get("message"))
                    .and_then(|message| message.get("content"))
                    .and_then(serde_json::Value::as_str)
                    .filter(|text| !text.is_empty())
                    .ok_or_else(|| ProviderError::Malformed("missing non-empty content".into()))?;
                Ok(CompletionResponseV1 {
                    model: model.clone(),
                    text: text.to_owned(),
                    raw,
                })
            }
        }
    }

    fn complete_conversation(
        &self,
        request: &ConversationRequestV1,
    ) -> Result<CompletionResponseV1, ProviderError> {
        self.complete_conversation_with_resolver(request, &EnvironmentCredentialResolver)
    }

    fn complete_conversation_v2(
        &self,
        request: &ConversationRequestV2,
    ) -> Result<CompletionResponseV1, ProviderError> {
        self.complete_conversation_v2_with_resolver(request, &EnvironmentCredentialResolver)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderUrlRejection {
    Malformed,
    UnsupportedScheme,
    MissingAuthority,
    UserInfoForbidden,
    QueryForbidden,
    FragmentForbidden,
    ControlCharacter,
    PathForbidden,
}

impl std::fmt::Display for ProviderUrlRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

fn validate_base_url(value: &str) -> Result<Url, ProviderError> {
    if value.is_empty() {
        return Err(ProviderError::EmptyBaseUrl);
    }
    if value.chars().any(char::is_control) {
        return Err(ProviderError::InvalidProviderUrl {
            reason: ProviderUrlRejection::ControlCharacter,
        });
    }
    let mut parsed = Url::parse(value).map_err(|_| ProviderError::InvalidProviderUrl {
        reason: ProviderUrlRejection::Malformed,
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ProviderError::InvalidProviderUrl {
            reason: ProviderUrlRejection::UnsupportedScheme,
        });
    }
    if parsed.cannot_be_a_base() || parsed.host_str().is_none() {
        return Err(ProviderError::InvalidProviderUrl {
            reason: ProviderUrlRejection::MissingAuthority,
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ProviderError::InvalidProviderUrl {
            reason: ProviderUrlRejection::UserInfoForbidden,
        });
    }
    if parsed.query().is_some() {
        return Err(ProviderError::InvalidProviderUrl {
            reason: ProviderUrlRejection::QueryForbidden,
        });
    }
    if parsed.fragment().is_some() {
        return Err(ProviderError::InvalidProviderUrl {
            reason: ProviderUrlRejection::FragmentForbidden,
        });
    }
    if parsed.path() != "/" {
        return Err(ProviderError::InvalidProviderUrl {
            reason: ProviderUrlRejection::PathForbidden,
        });
    }
    parsed.set_path("/");
    Ok(parsed)
}

#[derive(Debug, Clone, Copy)]
pub enum ProviderRoute {
    OllamaGenerate,
    OpenAiChatCompletions,
}

fn endpoint(base: &Url, route: ProviderRoute) -> Url {
    let mut endpoint = base.clone();
    endpoint.set_path(match route {
        ProviderRoute::OllamaGenerate => "/api/generate",
        ProviderRoute::OpenAiChatCompletions => "/v1/chat/completions",
    });
    endpoint
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn ollama_url_has_no_double_slash() -> TestResult {
        assert_eq!(
            validate_base_url("http://127.0.0.1:11434/")?.as_str(),
            "http://127.0.0.1:11434/"
        );
        Ok(())
    }

    #[test]
    fn empty_base_rejected() {
        assert!(matches!(
            validate_base_url("///"),
            Err(ProviderError::InvalidProviderUrl { .. })
        ));
    }

    #[test]
    fn ollama_spec_round_trips() -> TestResult {
        let spec = ProviderSpecV1::Ollama {
            base_url: ValidatedEndpoint::try_new("http://127.0.0.1:11434")?,
            model: "llama3.2:3b".into(),
        };
        let encoded = serde_json::to_value(&spec)?;
        assert_eq!(serde_json::from_value::<ProviderSpecV1>(encoded)?, spec);
        Ok(())
    }

    #[test]
    fn provider_specs_derive_stable_secret_free_egress_binding_identity() -> TestResult {
        let spec = ProviderSpecV1::Ollama {
            base_url: ValidatedEndpoint::try_new("http://127.0.0.1:11434/")?,
            model: "fixture-model".into(),
        };
        assert_eq!(
            spec.egress_provider_identity(),
            "ollama:http://127.0.0.1:11434"
        );
        assert_eq!(spec.egress_model_ref(), "model:fixture-model");
        assert!(spec.matches_egress_binding("ollama:http://127.0.0.1:11434", "model:fixture-model"));
        assert!(!spec.matches_egress_binding("ollama:http://127.0.0.1:11434", "model:other"));
        Ok(())
    }

    #[test]
    fn fixed_provider_routes_are_appended_to_origin_only() -> TestResult {
        let endpoint = ValidatedEndpoint::try_new("https://example.test/")?;
        assert_eq!(
            endpoint.route_url(ProviderRoute::OllamaGenerate).as_str(),
            "https://example.test/api/generate"
        );
        assert_eq!(
            endpoint
                .route_url(ProviderRoute::OpenAiChatCompletions)
                .as_str(),
            "https://example.test/v1/chat/completions"
        );
        Ok(())
    }
}
