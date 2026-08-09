//! Immutable Phase 1 sandbox plans, results, and retained enforcement evidence.
//!
//! This crate deliberately owns no process-launch function. The only production
//! execution engine is a private module of recursive-agent-runner.
//!
//! A downstream caller cannot invoke a sandbox executor because none is exported:
//! ```compile_fail
//! let plan = recursive_agent_sandbox::SandboxSpec {
//!     command: "/usr/bin/printf".into(),
//!     args: vec!["plan-only".into()],
//!     allowed_read_paths: vec![],
//!     allowed_write_paths: vec![],
//!     allow_network: false,
//!     timeout_ms: 1_000,
//!     max_output_bytes: 1_024,
//! };
//! recursive_agent_sandbox::execute(&plan);
//! ```

use recursive_agent_policy::{AuthorizedContextEvidenceV1, ExecutableAuthorityV1};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const OUTPUT_LIMIT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSpec {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub allowed_read_paths: Vec<String>,
    #[serde(default)]
    pub allowed_write_paths: Vec<String>,
    #[serde(default)]
    pub allow_network: bool,
    pub timeout_ms: u64,
    #[serde(default = "default_output_limit_bytes")]
    pub max_output_bytes: u64,
}

fn default_output_limit_bytes() -> u64 {
    OUTPUT_LIMIT_BYTES as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMechanism {
    Bubblewrap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementOutcome {
    Enforced,
    Failed,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementRecord {
    pub mechanism: SandboxMechanism,
    pub outcome: EnforcementOutcome,
    pub policy_digest: String,
    pub launcher_path: String,
    pub launcher_version: Option<String>,
    pub bash_trampoline_path: Option<String>,
    pub launcher_argv: Vec<String>,
    pub private_pid_namespace: bool,
    pub parent_death_control: bool,
    pub network_isolated: bool,
    pub network_mechanism: Option<String>,
    pub seccomp_policy_digest: Option<String>,
    pub denied_network_syscalls: Vec<String>,
    pub effective_operation_roots: Vec<OperationRootEvidence>,
    pub effective_runtime_read_roots: Vec<String>,
    pub trusted_executables: Vec<ExecutableAuthorityV1>,
    pub authorization: Option<AuthorizedContextEvidenceV1>,
    pub setup_proof_digest: Option<String>,
    pub setup_proof_verified: bool,
    pub reason_code: Option<SandboxFailureReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRootEvidence {
    pub path: String,
    pub descriptor_identity: String,
    pub access_mode: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxFailureReason {
    UnsupportedPlatform,
    LauncherMissing,
    LauncherProbeFailed,
    LauncherSetupFailed,
    LauncherTimedOut,
    UnsafeExecutable,
    AuthorizationExpired,
    SeccompGenerationFailed,
    DescriptorTransferFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub stdout_dropped_bytes: u64,
    pub stderr_dropped_bytes: u64,
    pub timed_out: bool,
    pub authority_terminated: bool,
    pub wall_time_ms: u64,
    pub enforcement: EnforcementRecord,
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("empty command")]
    EmptyCommand,
    #[error("timeout must be greater than zero; got {0}")]
    InvalidTimeout(u64),
    #[error("output limit must be greater than zero; got {0}")]
    InvalidOutputLimit(u64),
    #[error("network access is unavailable in Phase 1")]
    NetworkForbidden,
    #[error("sandbox authorization rejected: {0}")]
    AuthorizationDenied(String),
    #[error("requested allowlist path does not exist: {0}")]
    MissingAllowPath(String),
    #[error("sandbox path must be absolute and canonicalizable: {0}")]
    InvalidPath(String),
    #[error("sandbox launcher is unavailable")]
    LauncherUnavailable { enforcement: Box<EnforcementRecord> },
    #[error("sandbox setup failed")]
    SetupFailed { enforcement: Box<EnforcementRecord> },
    #[error("sandbox is unsupported on this platform")]
    UnsupportedPlatform { enforcement: Box<EnforcementRecord> },
    #[error("sandbox io failed: {0}")]
    Io(String),
    #[error("sandbox wait failed: {0}")]
    Wait(String),
}

/// Pure validation for a downstream-provided sandbox plan.
pub fn validate_plan(spec: &SandboxSpec) -> Result<(), SandboxError> {
    if spec.command.trim().is_empty() {
        return Err(SandboxError::EmptyCommand);
    }
    if spec.timeout_ms == 0 {
        return Err(SandboxError::InvalidTimeout(0));
    }
    if spec.max_output_bytes == 0 {
        return Err(SandboxError::InvalidOutputLimit(0));
    }
    if spec.allow_network {
        return Err(SandboxError::NetworkForbidden);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_validation_is_pure_and_fail_closed() {
        let valid = SandboxSpec {
            command: "/usr/bin/printf".into(),
            args: vec!["ok".into()],
            allowed_read_paths: Vec::new(),
            allowed_write_paths: Vec::new(),
            allow_network: false,
            timeout_ms: 1_000,
            max_output_bytes: 1_024,
        };
        assert!(validate_plan(&valid).is_ok());
        let mut networked = valid.clone();
        networked.allow_network = true;
        assert!(matches!(
            validate_plan(&networked),
            Err(SandboxError::NetworkForbidden)
        ));
    }
}
