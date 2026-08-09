//! Strict MCP-to-native translation (Phase 6, Task 6.2).
//!
//! This module is a translation edge, not an execution owner. It validates MCP
//! `tools/call` input and constructs a canonical `OperationEnvelopeV1` with a
//! server-derived peer identity and an explicitly attenuated lease. It never
//! dispatches tools itself, never reads wall-clock `time_now`, and never mints
//! run ids or receipts — those belong to the runtime and ledger.

use recursive_agent_contracts::{
    content_digest, ActorAuthorityV1, AuthorityOriginV1, CausalLinkV1, ContentDigest,
    DeclaredEffectsV1, OperationBudgetV1, OperationEnvelopeV1, OperationSchemaV1, ProvenanceRefV1,
    ReplayClassV1, ReplayIntentV1, ReplaySpecV1, RunSpecV1, StepSpecV1, ToolCallSpecV1,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from strict MCP-to-native translation. All typed; no panic.
#[derive(Debug, Error)]
pub enum TranslateError {
    #[error("malformed MCP tools/call: {0}")]
    Malformed(String),
    #[error("translation rejected by contract: {0}")]
    Contract(String),
}

/// Canonical translation of one MCP `tools/call` into a V1 operation envelope.
///
/// `peer` is the server-derived peer identity (from the authenticated MCP
/// transport), never caller-supplied. `lease_budget_ms` is the caller-supplied
/// attenuated lease budget; the operation never exceeds it.
pub fn translate_tools_call(
    peer: &str,
    tool: &str,
    args: serde_json::Value,
    lease_budget_ms: u64,
) -> Result<OperationEnvelopeV1, TranslateError> {
    if tool.trim().is_empty() {
        return Err(TranslateError::Malformed("tool name is empty".into()));
    }
    if lease_budget_ms == 0 {
        return Err(TranslateError::Malformed(
            "lease budget must be non-zero".into(),
        ));
    }
    let call = ToolCallSpecV1 {
        tool: tool.into(),
        args,
        frozen_clock: None,
    };
    let run_spec = RunSpecV1 {
        name: "mcp-translate".into(),
        steps: vec![StepSpecV1 {
            name: "mcp".into(),
            call,
        }],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    };
    Ok(OperationEnvelopeV1 {
        schema: OperationSchemaV1::V1,
        // Server-derived peer identity, never caller-supplied.
        actor: ActorAuthorityV1 {
            principal: peer.into(),
            origin: AuthorityOriginV1::Remote,
        },
        causality: CausalLinkV1 {
            parent_operation_id: None,
            root_operation_id: None,
        },
        budget: OperationBudgetV1 {
            max_wall_time_ms: lease_budget_ms,
            max_output_bytes: 4_096,
            max_artifact_bytes: 65_536,
            max_steps: 1,
        },
        effects: DeclaredEffectsV1 {
            read_roots: Vec::new(),
            write_roots: Vec::new(),
            network_allowed: false,
            action_digest: content_digest(&run_spec)
                .map_err(|e| TranslateError::Contract(e.to_string()))?,
        },
        provenance: vec![ProvenanceRefV1 {
            source: format!("urn:recursive-agent:mcp:{peer}"),
            digest: ContentDigest::compute(format!("mcp:{tool}").as_bytes()),
        }],
        replay: ReplaySpecV1 {
            class: ReplayClassV1::Deterministic,
            intent: ReplayIntentV1::ExecuteOnce,
        },
        run_spec,
    })
}

/// The result of a translated MCP call: the run handle identity is derived by
/// the runtime/ledger, never minted here. The translation only reports the
/// canonical operation id it constructed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationResult {
    /// Canonical operation identity derived from the constructed envelope.
    pub operation_id: String,
    /// Server-derived peer identity bound into the operation.
    pub peer: String,
}

/// Derive the canonical operation id for a translated envelope (delegates to
/// the contracts digest; the MCP server never mints a run id).
pub fn operation_identity(envelope: &OperationEnvelopeV1) -> Result<String, TranslateError> {
    recursive_agent_contracts::derive_operation_id(envelope)
        .map(|id| id.to_string())
        .map_err(|e| TranslateError::Contract(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn translation_uses_server_peer_not_caller_and_respects_lease() {
        let envelope = translate_tools_call(
            "peer:mcp-client-1",
            "echo",
            serde_json::json!({"text": "ok"}),
            3_000,
        )
        .unwrap();
        assert_eq!(envelope.actor.principal, "peer:mcp-client-1");
        assert_eq!(envelope.actor.origin, AuthorityOriginV1::Remote);
        assert_eq!(envelope.budget.max_wall_time_ms, 3_000);
        // No frozen clock is injected here (no wall-clock time_now).
        assert!(envelope.run_spec.frozen_clock.is_none());
        assert!(envelope.run_spec.steps[0].call.frozen_clock.is_none());
        // Operation id is derived, never minted by the adapter.
        let id = operation_identity(&envelope).unwrap();
        assert!(!id.is_empty());
        assert_eq!(
            operation_identity(&envelope).unwrap(),
            id,
            "derived id is deterministic"
        );
    }

    #[test]
    fn empty_tool_and_zero_lease_are_rejected() {
        assert!(translate_tools_call("peer", "", serde_json::json!({}), 1_000).is_err());
        assert!(translate_tools_call("peer", "echo", serde_json::json!({}), 0).is_err());
    }
}
