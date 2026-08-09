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
        api_key: Option<serde_json::Value>,
    },
}

impl<'de> Deserialize<'de> for ProviderSpecV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match ProviderSpecWire::deserialize(deserializer)? {
            ProviderSpecWire::Ollama { base_url, model } => Ok(Self::Ollama { base_url, model }),
            ProviderSpecWire::OpenAiCompatible {
                base_url,
                model,
                credential_ref,
                api_key,
            } => {
                if api_key.is_some() {
                    return Err(serde::de::Error::custom(
                        "raw provider credentials are forbidden; migrate to credential_ref: environment:NAME",
                    ));
                }
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

#[derive(Debug, Error)]
pub enum ProviderError {
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
