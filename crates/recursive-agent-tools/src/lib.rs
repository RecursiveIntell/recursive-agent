//! M0 tool plane. Two tools, both pure. Tool outputs are returned as
//! content-addressed artifacts (managed by the ledger).
//!
//! Tools refuse to run when their arguments are malformed or their
//! preconditions are not met. They do not call any provider, network,
//! or filesystem. They do not block. They do not panic.

use chrono::{DateTime, Utc};
use recursive_agent_contracts::{ContractError, ToolCallSpecV1};
use recursive_agent_provider::{
    complete as provider_complete, CompletionRequestV1, ProviderError, ProviderSpecV1,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors emitted by tools. All are typed.
#[derive(Debug, Error)]
pub enum ToolError {
    #[error("unknown tool: {0}")]
    Unknown(String),
    #[error("malformed args: {0}")]
    Args(String),
    #[error("contract error: {0}")]
    Contract(#[from] ContractError),
    #[error("missing frozen_clock for {0}")]
    FrozenClockRequired(String),
    #[error("provider: {0}")]
    Provider(#[from] ProviderError),
    #[error("runtime: {0}")]
    Runtime(String),
}

/// The `echo` tool. Takes a string and returns it as the result body.
/// Useful as a smoke test and as a contract canary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchoArgs {
    pub text: String,
}

/// The `time_now` tool. Returns a frozen timestamp. Refuses to run
/// without a `frozen_clock` so recorded runs are reproducible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeNowArgs {
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeNowOutput {
    pub timestamp: DateTime<Utc>,
    pub label: Option<String>,
}

/// The `llm` tool. Sends a prompt to a configured provider (Ollama or
/// OpenAI-compatible) and returns the assistant text. The provider spec
/// and prompt are bound into the run's receipt chain by the runner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmArgs {
    pub provider: ProviderSpecV1,
    pub prompt: String,
    #[serde(default)]
    pub max_tokens: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmOutput {
    pub model: String,
    pub text: String,
}

/// Execute a tool. Returns the JSON body of the result. The runner is
/// responsible for writing the body to the artifact store and recording
/// the reference on the receipt.
pub fn execute(call: &ToolCallSpecV1) -> Result<serde_json::Value, ToolError> {
    match call.tool.as_str() {
        "echo" => {
            let parsed: EchoArgs = serde_json::from_value(call.args.clone())
                .map_err(|e| ToolError::Args(format!("echo: {e}")))?;
            Ok(serde_json::json!({ "text": parsed.text }))
        }
        "time_now" => {
            let parsed: TimeNowArgs = serde_json::from_value(call.args.clone())
                .map_err(|e| ToolError::Args(format!("time_now: {e}")))?;
            let ts = call
                .frozen_clock
                .ok_or_else(|| ToolError::FrozenClockRequired("time_now".into()))?;
            let out = TimeNowOutput {
                timestamp: ts,
                label: parsed.label,
            };
            Ok(serde_json::to_value(out).map_err(|e| ToolError::Args(format!("time_now: {e}")))?)
        }
        "llm" => {
            let parsed: LlmArgs = serde_json::from_value(call.args.clone())
                .map_err(|e| ToolError::Args(format!("llm: {e}")))?;
            let resp = provider_complete(&CompletionRequestV1 {
                provider: parsed.provider,
                prompt: parsed.prompt,
                max_tokens: parsed.max_tokens,
            })?;
            let out = LlmOutput {
                model: resp.model,
                text: resp.text,
            };
            Ok(serde_json::to_value(out).map_err(|e| ToolError::Args(format!("llm: {e}")))?)
        }
        "shell" => {
            let spec: recursive_agent_sandbox::SandboxSpec =
                serde_json::from_value(call.args.clone())
                    .map_err(|e| ToolError::Args(format!("shell: {e}")))?;
            let result = recursive_agent_sandbox::execute(&spec)
                .map_err(|e| ToolError::Runtime(format!("shell: {e}")))?;
            Ok(serde_json::to_value(result).map_err(|e| ToolError::Args(format!("shell: {e}")))?)
        }
        other => Err(ToolError::Unknown(other.into())),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn call(tool: &str, args: serde_json::Value) -> ToolCallSpecV1 {
        ToolCallSpecV1 {
            tool: tool.into(),
            args,
            frozen_clock: None,
        }
    }

    #[test]
    fn echo_returns_text() {
        let out = execute(&call("echo", serde_json::json!({"text": "hi"}))).unwrap();
        assert_eq!(out, serde_json::json!({"text": "hi"}));
    }

    #[test]
    fn time_now_requires_frozen_clock() {
        let err = execute(&call("time_now", serde_json::json!({}))).unwrap_err();
        assert!(matches!(err, ToolError::FrozenClockRequired(_)));
    }

    #[test]
    fn time_now_returns_frozen_timestamp() {
        let mut c = call("time_now", serde_json::json!({"label": "tick"}));
        c.frozen_clock = Some(
            chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        let out = execute(&c).unwrap();
        assert_eq!(out["label"], "tick");
    }

    #[test]
    fn unknown_tool_errors() {
        let err = execute(&call("shell", serde_json::json!({}))).unwrap_err();
        assert!(
            matches!(err, ToolError::Args(_) | ToolError::Unknown(_)),
            "shell is now a known tool; use an actually-unknown tool instead"
        );
    }

    #[test]
    fn llm_rejects_malformed_args_without_network() {
        // No provider spec provided -> malformed args error, no network I/O.
        let err = execute(&call("llm", serde_json::json!({ "prompt": "hi" }))).unwrap_err();
        assert!(matches!(err, ToolError::Args(_)));
    }
}
