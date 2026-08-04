//! M0 policy: static allowlist, family-qualified permits, lineage rules.
//!
//! The policy refuses anything not on the allowlist. Permits are
//! recorded as durable markers (the caller is expected to write a
//! `PermitConsumed` receipt to the chain for replay protection).

use std::collections::BTreeSet;

use recursive_agent_contracts::{
    AuthorityLineageEntryV1, ContractError, LineageOrigin, ReceiptV1, RunSpecV1, ToolCallSpecV1,
};
use thiserror::Error;

/// Errors emitted by the policy layer. All are typed and non-fatal.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("tool not in allowlist: {0}")]
    ToolNotAllowed(String),
    #[error("args exceed max bytes: {0} > {1}")]
    ArgsTooLarge(usize, usize),
    #[error("lineage failed: {0}")]
    Lineage(#[from] ContractError),
    #[error("permit {0} not authorized for tool {1}")]
    PermitMismatch(String, String),
    #[error("tool {0} requires frozen_clock; got None")]
    FrozenClockRequired(String),
}

/// The M0 allowlist. Two pure tools plus the Phase 2 `llm` provider
/// tool. `time_now` requires a frozen clock so a recorded run is
/// reproducible; `llm` is authorized only when a provider is configured.
#[derive(Debug, Clone)]
pub struct Allowlist {
    pub allowed: BTreeSet<String>,
    pub max_arg_bytes: usize,
    pub policy_version: String,
}

impl Default for Allowlist {
    fn default() -> Self {
        Self {
            allowed: BTreeSet::from(["echo".into(), "time_now".into(), "llm".into()]),
            max_arg_bytes: 16 * 1024,
            policy_version: "m0-2".into(),
        }
    }
}

impl Allowlist {
    pub fn authorize(
        &self,
        spec: &RunSpecV1,
        step_name: &str,
        call: &ToolCallSpecV1,
    ) -> Result<(), PolicyError> {
        if !self.allowed.contains(&call.tool) {
            return Err(PolicyError::ToolNotAllowed(call.tool.clone()));
        }
        let arg_bytes = serde_json::to_vec(&call.args)
            .map_err(|e| ContractError::Malformed(format!("args: {e}")))?;
        if arg_bytes.len() > self.max_arg_bytes {
            return Err(PolicyError::ArgsTooLarge(
                arg_bytes.len(),
                self.max_arg_bytes,
            ));
        }
        if call.tool == "time_now" && call.frozen_clock.is_none() && spec.frozen_clock.is_none() {
            return Err(PolicyError::FrozenClockRequired(call.tool.clone()));
        }
        let _ = step_name; // reserved for per-step rule hooks in later phases
        Ok(())
    }
}

/// Build a default lineage for a step. The lineage is the same shape for
/// every step in M0: request, plan, policy, tool, effect. Approval is
/// skipped in M0; later phases will insert it before tool.
pub fn build_lineage(permit_id: &str, policy_version: &str) -> Vec<AuthorityLineageEntryV1> {
    let principal = "recursive-agent".to_string();
    vec![
        AuthorityLineageEntryV1 {
            origin: LineageOrigin::Request,
            principal: principal.clone(),
            permit_id: None,
            policy_version: policy_version.to_string(),
        },
        AuthorityLineageEntryV1 {
            origin: LineageOrigin::Plan,
            principal: principal.clone(),
            permit_id: None,
            policy_version: policy_version.to_string(),
        },
        AuthorityLineageEntryV1 {
            origin: LineageOrigin::Policy,
            principal: principal.clone(),
            permit_id: Some(permit_id.to_string()),
            policy_version: policy_version.to_string(),
        },
        AuthorityLineageEntryV1 {
            origin: LineageOrigin::Tool,
            principal: principal.clone(),
            permit_id: Some(permit_id.to_string()),
            policy_version: policy_version.to_string(),
        },
        AuthorityLineageEntryV1 {
            origin: LineageOrigin::Effect,
            principal: principal.clone(),
            permit_id: Some(permit_id.to_string()),
            policy_version: policy_version.to_string(),
        },
    ]
}

/// Issue a permit for a tool. The permit ID is family-qualified. The
/// runner is expected to also write a `PermitConsumed` receipt after
/// dispatch; this function only returns the typed permit.
pub fn issue_permit(run_id_short: &str, tool: &str) -> Result<String, PolicyError> {
    let suffix = format!("{}-{}-{}", run_id_short, tool, deterministic_suffix(tool));
    let id =
        recursive_agent_contracts::FamilyId::new("pmt", suffix).map_err(PolicyError::Lineage)?;
    Ok(id.as_str().to_string())
}

fn deterministic_suffix(tool: &str) -> String {
    // The suffix is derived from the tool name; it is stable per run
    // because the run is single-issuer. Future phases will issue per-step
    // permits with a stronger binding.
    let mut h: u64 = 1469598103934665603;
    for b in tool.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    format!("{h:016x}")
}

/// Defense-in-depth: refuse to emit a `ReceiptV1` whose lineage fails
/// the canonical contract check. Use this in the runner before any
/// `chain.append` call.
pub fn assert_lineage_for_receipt(receipt: &ReceiptV1) -> Result<(), PolicyError> {
    recursive_agent_contracts::validate_lineage(&receipt.lineage).map_err(PolicyError::Lineage)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn default_allowlist_accepts_echo() {
        let al = Allowlist::default();
        let spec = RunSpecV1 {
            name: "t".into(),
            steps: vec![],
            frozen_clock: Some(chrono::Utc::now()),
            policy_version: al.policy_version.clone(),
        };
        let call = ToolCallSpecV1 {
            tool: "echo".into(),
            args: serde_json::json!({"text": "hi"}),
            frozen_clock: None,
        };
        al.authorize(&spec, "s1", &call).unwrap();
    }

    #[test]
    fn default_allowlist_rejects_unknown_tool() {
        let al = Allowlist::default();
        let spec = RunSpecV1 {
            name: "t".into(),
            steps: vec![],
            frozen_clock: Some(chrono::Utc::now()),
            policy_version: al.policy_version.clone(),
        };
        let call = ToolCallSpecV1 {
            tool: "shell".into(),
            args: serde_json::json!({"cmd": "rm -rf /"}),
            frozen_clock: None,
        };
        match al.authorize(&spec, "s1", &call).unwrap_err() {
            PolicyError::ToolNotAllowed(t) => assert_eq!(t, "shell"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn time_now_requires_frozen_clock() {
        let al = Allowlist::default();
        let spec = RunSpecV1 {
            name: "t".into(),
            steps: vec![],
            frozen_clock: None,
            policy_version: al.policy_version.clone(),
        };
        let call = ToolCallSpecV1 {
            tool: "time_now".into(),
            args: serde_json::json!({}),
            frozen_clock: None,
        };
        match al.authorize(&spec, "s1", &call).unwrap_err() {
            PolicyError::FrozenClockRequired(t) => assert_eq!(t, "time_now"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn lineage_is_canonical() {
        let chain = build_lineage("pmt:abc", "m0-1");
        recursive_agent_contracts::validate_lineage(&chain).unwrap();
    }

    #[test]
    fn permit_is_family_qualified() {
        let id = issue_permit("r1", "echo").unwrap();
        assert!(id.starts_with("pmt:"));
    }
}
