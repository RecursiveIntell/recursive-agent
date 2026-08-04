//! Phase 2 provider integration. Adds a typed, boundary-checked LLM
//! provider layer behind the existing receipt-bearing `llm` tool.
//!
//! Two adapters are supported:
//! - **Ollama** (local `/api/generate`)
//! - **OpenAI-compatible** (`/v1/chat/completions`)
//!
//! Every call is shaped by a typed [`ProviderSpecV1`]; the prompt, spec,
//! and returned text are all bound into the run's receipt chain by the
//! caller (the `llm` tool in the tools crate). This crate performs no
//! persistence and no receipt writing — it is a pure request/response
//! boundary.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A typed, serializable description of an LLM provider endpoint.
///
/// The `kind` discriminant is explicit so a run spec can be validated
/// before any network I/O occurs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderSpecV1 {
    /// Local Ollama server. `base_url` should be the server root
    /// (e.g. `http://127.0.0.1:11434`); the adapter appends `/api/generate`.
    Ollama { base_url: String, model: String },
    /// Any OpenAI-compatible chat completions endpoint. `base_url` should
    /// be the server root (e.g. `https://api.example.com/v1`); the adapter
    /// appends `/chat/completions`. `api_key` is optional.
    OpenAiCompatible {
        base_url: String,
        model: String,
        api_key: Option<String>,
    },
}

/// Arguments for a single completion request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionRequestV1 {
    pub provider: ProviderSpecV1,
    pub prompt: String,
    /// Optional token ceiling. Ollama maps this to `num_predict`;
    /// OpenAI-compatible maps it to `max_tokens`.
    pub max_tokens: Option<u32>,
}

/// The typed, canonical response from a provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionResponseV1 {
    /// The model identifier that served the request.
    pub model: String,
    /// The generated text (assistant content).
    pub text: String,
    /// The full raw JSON body returned by the provider, captured for
    /// evidence. This is the untrusted response; `text` is the
    /// JCS-canonical, parsed extraction.
    pub raw: serde_json::Value,
}

/// Errors surfaced by the provider layer. All are typed; no panic.
#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("unknown provider kind: {0}")]
    UnknownKind(String),
    #[error("empty base_url for provider")]
    EmptyBaseUrl,
    #[error("empty model for provider")]
    EmptyModel,
    #[error("http request failed: {0}")]
    Http(String),
    #[error("provider returned non-success status {status}: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("malformed provider response: {0}")]
    Malformed(String),
}

/// Execute a single completion against the configured provider.
///
/// This is a blocking call (reqwest blocking client). It performs network
/// I/O and never panics. On any failure it returns a typed
/// [`ProviderError`]; the caller is responsible for recording the outcome
/// on the receipt chain.
pub fn complete(request: &CompletionRequestV1) -> Result<CompletionResponseV1, ProviderError> {
    match &request.provider {
        ProviderSpecV1::Ollama { base_url, model } => complete_ollama(base_url, model, request),
        ProviderSpecV1::OpenAiCompatible {
            base_url,
            model,
            api_key,
        } => complete_openai(base_url, model, api_key.as_deref(), request),
    }
}

fn complete_ollama(
    base_url: &str,
    model: &str,
    request: &CompletionRequestV1,
) -> Result<CompletionResponseV1, ProviderError> {
    let base = trim_trailing_slash(base_url)?;
    let url = format!("{base}/api/generate");
    let mut body = serde_json::json!({
        "model": model,
        "prompt": request.prompt,
        "stream": false,
    });
    if let Some(t) = request.max_tokens {
        body["options"] = serde_json::json!({ "num_predict": t });
    }
    let client = blocking_client()?;
    let raw: serde_json::Value = client
        .post(&url)
        .json(&body)
        .send()
        .map_err(|e| ProviderError::Http(e.to_string()))?
        .error_for_status()
        .map_err(|e| ProviderError::Http(e.to_string()))?
        .json()
        .map_err(|e| ProviderError::Malformed(e.to_string()))?;
    let text = raw
        .get("response")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| ProviderError::Malformed("missing 'response' field".into()))?;
    Ok(CompletionResponseV1 {
        model: model.to_string(),
        text,
        raw,
    })
}

fn complete_openai(
    base_url: &str,
    model: &str,
    api_key: Option<&str>,
    request: &CompletionRequestV1,
) -> Result<CompletionResponseV1, ProviderError> {
    let base = trim_trailing_slash(base_url)?;
    let url = format!("{base}/chat/completions");
    let mut body = serde_json::json!({
        "model": model,
        "messages": [{ "role": "user", "content": request.prompt }],
        "stream": false,
    });
    if let Some(t) = request.max_tokens {
        body["max_tokens"] = serde_json::json!(t);
    }
    let client = blocking_client()?;
    let mut req = client.post(&url).json(&body);
    if let Some(key) = api_key {
        req = req.bearer_auth(key);
    }
    let raw: serde_json::Value = req
        .send()
        .map_err(|e| ProviderError::Http(e.to_string()))?
        .error_for_status()
        .map_err(|e| ProviderError::Http(e.to_string()))?
        .json()
        .map_err(|e| ProviderError::Malformed(e.to_string()))?;
    let text = raw
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    Ok(CompletionResponseV1 {
        model: model.to_string(),
        text,
        raw,
    })
}

fn trim_trailing_slash(s: &str) -> Result<String, ProviderError> {
    let t = s.trim_end_matches('/');
    if t.is_empty() {
        return Err(ProviderError::EmptyBaseUrl);
    }
    Ok(t.to_string())
}

fn blocking_client() -> Result<reqwest::blocking::Client, ProviderError> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| ProviderError::Http(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn ollama_url_has_no_double_slash() {
        let base = trim_trailing_slash("http://127.0.0.1:11434/").unwrap();
        assert_eq!(base, "http://127.0.0.1:11434");
    }

    #[test]
    fn openai_url_appends_chat_completions() {
        let base = trim_trailing_slash("https://api.example.com/v1").unwrap();
        assert_eq!(base, "https://api.example.com/v1");
    }

    #[test]
    fn empty_base_rejected() {
        let err = trim_trailing_slash("///").unwrap_err();
        assert!(matches!(err, ProviderError::EmptyBaseUrl));
    }

    #[test]
    fn spec_round_trips_jcs_serialization() {
        let spec = ProviderSpecV1::Ollama {
            base_url: "http://127.0.0.1:11434".into(),
            model: "llama3.2:3b".into(),
        };
        let v = serde_json::to_value(&spec).unwrap();
        let back: ProviderSpecV1 = serde_json::from_value(v).unwrap();
        assert_eq!(spec, back);
    }
}
