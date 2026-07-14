//! M0 tool plane. Two tools, both pure. Tool outputs are returned as
//! content-addressed artifacts (managed by the ledger).
//!
//! Tools refuse to run when their arguments are malformed or their
//! preconditions are not met. They do not call any provider, network,
//! or filesystem. They do not block. They do not panic.

use chrono::{DateTime, Utc};
use recursive_agent_contracts::{ContractError, ToolCallSpecV1};
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
        assert!(matches!(err, ToolError::Unknown(_)));
    }
}
