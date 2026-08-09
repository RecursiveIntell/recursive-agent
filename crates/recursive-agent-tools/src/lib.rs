//! M0 tool plane. Two tools, both pure. Tool outputs are returned as
//! content-addressed artifacts (managed by the ledger).
//!
//! Tools refuse to run when their arguments are malformed or their
//! preconditions are not met. They do not call any provider, network,
//! or filesystem. They do not block. They do not panic.

use chrono::{DateTime, Utc};
use recursive_agent_contracts::{ContractError, ToolCallSpecV1};
use recursive_agent_policy::PermitEvidenceV1;
use recursive_agent_provider::{ProviderError, ProviderSpecV1};
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
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("runtime: {0}")]
    Runtime(String),
    #[error("admitted tool runtime failed: {reason}")]
    OwnerRuntime {
        reason: String,
        observation: Box<serde_json::Value>,
    },
    #[error("tool executor is unavailable in the bounded Phase 1 allowlist: {0}")]
    Unavailable(String),
    #[error("authorized execution budget was exceeded: {0}")]
    BudgetExceeded(String),
    #[error("shell observation is non-success: {reason}")]
    ShellNonSuccess {
        reason: String,
        observation: Box<serde_json::Value>,
    },
    #[error("authorized execution lease expired: {0}")]
    LeaseExpired(String),
}

impl ToolError {
    pub fn failure_observation(&self) -> Option<&serde_json::Value> {
        match self {
            Self::ShellNonSuccess { observation, .. } | Self::OwnerRuntime { observation, .. } => {
                Some(observation)
            }
            _ => None,
        }
    }

    pub fn timed_out(&self) -> bool {
        matches!(self, Self::LeaseExpired(_))
            || self
                .failure_observation()
                .and_then(|value| value.get("timed_out"))
                .and_then(serde_json::Value::as_bool)
                == Some(true)
    }
}

/// The `echo` tool. Takes a string and returns it as the result body.
/// Useful as a smoke test and as a contract canary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EchoArgs {
    pub text: String,
}

/// The `time_now` tool. Returns a frozen timestamp. Refuses to run
/// without a `frozen_clock` so recorded runs are reproducible.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// The `mcp_call` tool. Connects to an external MCP server and calls a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpCallArgs {
    pub server_command: String,
    #[serde(default)]
    pub server_args: Vec<String>,
    pub tool_name: String,
    pub tool_args: serde_json::Value,
    #[serde(default = "default_mcp_timeout")]
    pub timeout_ms: u64,
}

fn default_mcp_timeout() -> u64 {
    30_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpCallOutput {
    pub server: String,
    pub tool: String,
    pub result: serde_json::Value,
    pub elapsed_ms: u64,
}

/// Memory tool args.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPutArgs {
    pub namespace: String,
    pub key: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryGetArgs {
    pub namespace: String,
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySearchArgs {
    pub namespace: String,
    pub query: String,
    #[serde(default = "default_top_k")]
    pub top_k: usize,
}

fn default_top_k() -> usize {
    5
}

/// Skill tool args.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillRunArgs {
    pub skill_name: String,
    #[serde(default)]
    pub bindings: std::collections::HashMap<String, serde_json::Value>,
}

/// Delegate tool args — spawns a child ra process for a sub-run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegateArgs {
    pub spec_path: std::path::PathBuf,
    #[serde(default = "default_delegate_timeout")]
    pub timeout_ms: u64,
}

fn default_delegate_timeout() -> u64 {
    60_000
}

/// Execute a tool. Returns the JSON body of the result. The runner is
/// responsible for writing the body to the artifact store and recording
/// the reference on the receipt.
pub fn execute(
    call: &ToolCallSpecV1,
    evidence: PermitEvidenceV1,
) -> Result<serde_json::Value, ToolError> {
    evidence
        .validate_consumed_call(call)
        .map_err(|error| ToolError::Runtime(error.to_string()))?;
    let value = match call.tool.as_str() {
        "echo" => {
            let parsed: EchoArgs = serde_json::from_value(call.args.clone())
                .map_err(|e| ToolError::Args(format!("echo: {e}")))?;
            serde_json::json!({ "text": parsed.text })
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
            serde_json::to_value(out).map_err(|e| ToolError::Args(format!("time_now: {e}")))?
        }
        "shell" | "llm" | "mcp_call" | "memory_put" | "memory_get" | "memory_search"
        | "skill_run" | "delegate" => return Err(ToolError::Unavailable(call.tool.clone())),
        other => return Err(ToolError::Unknown(other.into())),
    };
    let bytes = serde_json::to_vec(&value)?;
    let observed = u64::try_from(bytes.len())
        .map_err(|_| ToolError::BudgetExceeded("observation length does not fit u64".into()))?;
    evidence
        .enforce_observation_bounds(observed, observed)
        .map_err(|error| ToolError::BudgetExceeded(error.to_string()))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;
    use recursive_agent_contracts::{
        content_digest, derive_run_id, derive_step_id, RunSpecV1, StepSpecV1,
    };
    use recursive_agent_policy::{
        ActorPrincipalV1, DurablePermitStore, EffectScopeV1, PermitBindingV1, PermitBudgetV1,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn call(tool: &str, args: serde_json::Value) -> ToolCallSpecV1 {
        ToolCallSpecV1 {
            tool: tool.into(),
            args,
            frozen_clock: None,
        }
    }

    fn context(
        call: &ToolCallSpecV1,
        max_output_bytes: u64,
    ) -> Result<PermitEvidenceV1, Box<dyn std::error::Error>> {
        context_with_wall(call, max_output_bytes, 1_000)
    }

    fn context_with_wall(
        call: &ToolCallSpecV1,
        max_output_bytes: u64,
        max_wall_time_ms: u64,
    ) -> Result<PermitEvidenceV1, Box<dyn std::error::Error>> {
        let now = chrono::DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_700_000_000);
        let spec = RunSpecV1 {
            name: "tool-test".into(),
            steps: vec![StepSpecV1 {
                name: "step".into(),
                call: call.clone(),
            }],
            frozen_clock: Some(now),
            policy_version: "policy-v1".into(),
        };
        let run_id = derive_run_id(&spec)?;
        let step_id = derive_step_id(&run_id, 0, "step", call)?;
        let effect = EffectScopeV1 {
            scope_name: call.tool.clone(),
            read_roots: Vec::new(),
            write_roots: Vec::new(),
            network_allowed: false,
        };
        let binding = PermitBindingV1 {
            actor: ActorPrincipalV1::try_new("actor:test")?,
            action_digest: content_digest(call)?,
            effect_digest: content_digest(&effect)?,
            effect,
            budget: PermitBudgetV1 {
                max_wall_time_ms,
                max_output_bytes,
                max_artifact_bytes: max_output_bytes,
            },
            policy_version: "policy-v1".into(),
            parent_permit_id: None,
            parent_operation_id: Some(run_id.clone()),
            issued_at: now,
            not_before: now,
            expires_at: now + TimeDelta::seconds(1),
            run_id,
            step_id,
            tool: call.tool.clone(),
            args_digest: content_digest(&call.args)?,
        };
        let root = tempfile::tempdir()?;
        let root_file = std::fs::File::open(root.path())?;
        let store = DurablePermitStore::from_dir_fd(&root_file)?;
        let permit = store.issue(&binding, now)?;
        Ok(store.consume(&permit.permit_id, &binding, now)?)
    }

    #[test]
    fn echo_returns_text() -> TestResult {
        let call = call("echo", serde_json::json!({"text": "hi"}));
        let out = execute(&call, context(&call, 1_024)?)?;
        assert_eq!(out, serde_json::json!({"text": "hi"}));
        Ok(())
    }

    #[test]
    fn time_now_requires_frozen_clock() -> TestResult {
        let call = call("time_now", serde_json::json!({}));
        let Err(err) = execute(&call, context(&call, 1_024)?) else {
            return Err("time_now unexpectedly accepted a missing frozen clock".into());
        };
        assert!(matches!(err, ToolError::FrozenClockRequired(_)));
        Ok(())
    }

    #[test]
    fn time_now_returns_frozen_timestamp() -> TestResult {
        let mut c = call("time_now", serde_json::json!({"label": "tick"}));
        c.frozen_clock =
            Some(chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")?.with_timezone(&Utc));
        let out = execute(&c, context(&c, 1_024)?)?;
        assert_eq!(out["label"], "tick");
        Ok(())
    }

    #[test]
    fn unknown_tool_errors() -> TestResult {
        let call = call("not-a-tool", serde_json::json!({}));
        let Err(err) = execute(&call, context(&call, 1_024)?) else {
            return Err("unknown tool unexpectedly executed".into());
        };
        assert!(
            matches!(err, ToolError::Args(_) | ToolError::Unknown(_)),
            "shell is now a known tool; use an actually-unknown tool instead"
        );
        Ok(())
    }

    #[test]
    fn llm_rejects_malformed_args_without_network() -> TestResult {
        // No provider spec provided -> malformed args error, no network I/O.
        let call = call("llm", serde_json::json!({ "prompt": "hi" }));
        let Err(err) = execute(&call, context(&call, 1_024)?) else {
            return Err("quarantined llm tool unexpectedly executed".into());
        };
        assert!(matches!(err, ToolError::Unavailable(_)));
        Ok(())
    }

    #[test]
    fn output_budget_is_actually_enforced() -> TestResult {
        let call = call("echo", serde_json::json!({"text": "far too large"}));
        let Err(err) = execute(&call, context(&call, 1)?) else {
            return Err("output overrun unexpectedly succeeded".into());
        };
        assert!(matches!(err, ToolError::BudgetExceeded(_)));
        Ok(())
    }

    #[test]
    fn pure_tool_surface_has_no_wall_clock_or_effect_dispatch() -> TestResult {
        let call = call("echo", serde_json::json!({"text": "late"}));
        let evidence = context_with_wall(&call, 1_024, 1)?;
        assert_eq!(
            execute(&call, evidence)?,
            serde_json::json!({"text": "late"})
        );
        Ok(())
    }

    #[test]
    fn invalid_provider_endpoint_is_rejected_in_tool_args_before_state_exists() -> TestResult {
        let sentinel = "tool-endpoint-sentinel";
        let value = serde_json::json!({
            "provider": {
                "kind": "open_ai_compatible",
                "base_url": format!("https://example.test/{sentinel}"),
                "model": "model",
                "credential_ref": "environment:SAFE_KEY"
            },
            "prompt": "hello"
        });
        let Err(error) = serde_json::from_value::<LlmArgs>(value) else {
            return Err("invalid endpoint unexpectedly created tool arguments".into());
        };
        assert!(!error.to_string().contains(sentinel));
        Ok(())
    }
}
