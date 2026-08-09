use std::path::{Path, PathBuf};
use std::sync::Arc;

use llm_tool_runtime::ToolRuntime;
use recursive_agent_provider::ProviderSpecV1;

use crate::{Clock, RuntimeDependencyError};

/// The only policy implementation admitted for native V1 execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePolicyDependencyV1 {
    /// `recursive-agent-policy` allowlist and durable permit owner.
    Native,
}

/// The only sandbox implementation admitted for native V1 execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSandboxDependencyV1 {
    /// `recursive-agent-sandbox` host enforcement owner.
    Native,
}

/// Provider availability is explicit; absence is never an implicit fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeProviderDependencyV1 {
    /// This service instance rejects operations requiring a provider.
    Disabled,
    /// Secret-free provider identity/configuration.
    Configured(ProviderSpecV1),
}

/// The only authoritative receipt-chain implementation admitted for V1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeLedgerDependencyV1 {
    /// `recursive-agent-ledger` canonical filesystem ledger.
    Native,
}

/// The only authoritative artifact-store implementation admitted for V1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeStoreDependencyV1 {
    /// `recursive-agent-ledger::ArtifactStore` under the pinned run root.
    Native,
}

/// Complete dependency set required before `RuntimeService` may exist.
pub struct RuntimeDependencies {
    pub(crate) policy: RuntimePolicyDependencyV1,
    pub(crate) sandbox: RuntimeSandboxDependencyV1,
    pub(crate) tool_runtime: Arc<ToolRuntime>,
    pub(crate) provider: RuntimeProviderDependencyV1,
    pub(crate) ledger: RuntimeLedgerDependencyV1,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) store: RuntimeStoreDependencyV1,
    pub(crate) output_root: PathBuf,
}

impl RuntimeDependencies {
    /// Start a fail-closed dependency builder with no inferred defaults.
    pub fn builder() -> RuntimeDependenciesBuilder {
        RuntimeDependenciesBuilder::default()
    }

    /// Borrow the admitted native policy owner marker.
    pub fn policy(&self) -> RuntimePolicyDependencyV1 {
        self.policy
    }

    /// Borrow the admitted native sandbox owner marker.
    pub fn sandbox(&self) -> RuntimeSandboxDependencyV1 {
        self.sandbox
    }

    /// Borrow the canonical tool runtime admitted for descriptor validation.
    pub fn tool_runtime(&self) -> &ToolRuntime {
        &self.tool_runtime
    }

    /// Borrow the explicit provider mode.
    pub fn provider(&self) -> &RuntimeProviderDependencyV1 {
        &self.provider
    }

    /// Borrow the admitted native ledger owner marker.
    pub fn ledger(&self) -> RuntimeLedgerDependencyV1 {
        self.ledger
    }

    /// Borrow the injected runtime clock.
    pub fn clock(&self) -> &dyn Clock {
        self.clock.as_ref()
    }

    /// Borrow the admitted native store owner marker.
    pub fn store(&self) -> RuntimeStoreDependencyV1 {
        self.store
    }

    /// Borrow the parent directory used for content-addressed run roots.
    pub fn output_root(&self) -> &Path {
        &self.output_root
    }
}

/// Explicit builder; every owner must be named by the caller.
#[derive(Default)]
pub struct RuntimeDependenciesBuilder {
    policy: Option<RuntimePolicyDependencyV1>,
    sandbox: Option<RuntimeSandboxDependencyV1>,
    tool_runtime: Option<Arc<ToolRuntime>>,
    provider: Option<RuntimeProviderDependencyV1>,
    ledger: Option<RuntimeLedgerDependencyV1>,
    clock: Option<Arc<dyn Clock>>,
    store: Option<RuntimeStoreDependencyV1>,
    output_root: Option<PathBuf>,
}

impl RuntimeDependenciesBuilder {
    pub fn policy(mut self, dependency: RuntimePolicyDependencyV1) -> Self {
        self.policy = Some(dependency);
        self
    }

    pub fn sandbox(mut self, dependency: RuntimeSandboxDependencyV1) -> Self {
        self.sandbox = Some(dependency);
        self
    }

    pub fn tool_runtime(mut self, dependency: Arc<ToolRuntime>) -> Self {
        self.tool_runtime = Some(dependency);
        self
    }

    pub fn provider(mut self, dependency: RuntimeProviderDependencyV1) -> Self {
        self.provider = Some(dependency);
        self
    }

    pub fn ledger(mut self, dependency: RuntimeLedgerDependencyV1) -> Self {
        self.ledger = Some(dependency);
        self
    }

    pub fn clock(mut self, dependency: Arc<dyn Clock>) -> Self {
        self.clock = Some(dependency);
        self
    }

    pub fn store(mut self, dependency: RuntimeStoreDependencyV1) -> Self {
        self.store = Some(dependency);
        self
    }

    pub fn output_root(mut self, dependency: impl Into<PathBuf>) -> Self {
        self.output_root = Some(dependency.into());
        self
    }

    /// Admit dependencies only when every canonical owner is explicit.
    pub fn build(self) -> Result<RuntimeDependencies, RuntimeDependencyError> {
        let mut names = Vec::new();
        if self.policy.is_none() {
            names.push("policy");
        }
        if self.sandbox.is_none() {
            names.push("sandbox");
        }
        if self.tool_runtime.is_none() {
            names.push("tool_runtime");
        }
        if self.provider.is_none() {
            names.push("provider");
        }
        if self.ledger.is_none() {
            names.push("ledger");
        }
        if self.clock.is_none() {
            names.push("clock");
        }
        if self.store.is_none() {
            names.push("store");
        }
        if self.output_root.is_none() {
            names.push("output_root");
        }
        if !names.is_empty() {
            return Err(RuntimeDependencyError::Missing { names });
        }

        match (
            self.policy,
            self.sandbox,
            self.tool_runtime,
            self.provider,
            self.ledger,
            self.clock,
            self.store,
            self.output_root,
        ) {
            (
                Some(policy),
                Some(sandbox),
                Some(tool_runtime),
                Some(provider),
                Some(ledger),
                Some(clock),
                Some(store),
                Some(output_root),
            ) => Ok(RuntimeDependencies {
                policy,
                sandbox,
                tool_runtime,
                provider,
                ledger,
                clock,
                store,
                output_root,
            }),
            _ => Err(RuntimeDependencyError::Missing { names: Vec::new() }),
        }
    }
}
