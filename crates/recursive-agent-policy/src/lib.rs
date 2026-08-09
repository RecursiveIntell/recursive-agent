//! Static allowlist and durable, single-use capability leases.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsFd;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use recursive_agent_contracts::{
    content_digest, derive_permit_id, jcs_canonical, AuthorityLineageEntryV1, ContentDigest,
    ContractError, CurrentPermitId, CurrentRunId, CurrentStepId, LineageOrigin,
    PermitIdentityMaterialV1, ReceiptV1, RunSpecV1, ToolCallSpecV1,
};
use rustix::fs::{FlockOperation, Mode, OFlags, ResolveFlags};
use thiserror::Error;

const MAX_PERMIT_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_LIVE_LEASE_MILLISECONDS: i64 = 300_000;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct ActorPrincipalV1(String);

impl ActorPrincipalV1 {
    pub fn try_new(value: impl Into<String>) -> Result<Self, PolicyError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 256
            || !value
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-_.:@/".contains(character))
        {
            return Err(PolicyError::InvalidLease("invalid actor principal".into()));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Explicit grantor, delegate, audience, and delegation depth for one edge.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationIdentityV1 {
    pub actor: ActorPrincipalV1,
    pub delegate: ActorPrincipalV1,
    pub audience: String,
    pub depth: u32,
}

impl DelegationIdentityV1 {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.audience.is_empty()
            || self.audience.chars().any(char::is_control)
            || self.depth == 0
        {
            return Err(PolicyError::InvalidLease(
                "invalid delegation identity".into(),
            ));
        }
        Ok(())
    }
}

impl<'de> serde::Deserialize<'de> for ActorPrincipalV1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::try_new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectScopeV1 {
    pub scope_name: String,
    pub read_roots: Vec<String>,
    pub write_roots: Vec<String>,
    pub network_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermitBudgetV1 {
    pub max_wall_time_ms: u64,
    pub max_output_bytes: u64,
    pub max_artifact_bytes: u64,
}

impl PermitBudgetV1 {
    pub fn is_within(&self, authorized: &Self) -> bool {
        self.max_wall_time_ms <= authorized.max_wall_time_ms
            && self.max_output_bytes <= authorized.max_output_bytes
            && self.max_artifact_bytes <= authorized.max_artifact_bytes
    }

    fn checked_add(&self, other: &Self) -> Result<Self, PolicyError> {
        Ok(Self {
            max_wall_time_ms: self
                .max_wall_time_ms
                .checked_add(other.max_wall_time_ms)
                .ok_or_else(|| {
                    PolicyError::BudgetOverrun("wall-time allocation overflow".into())
                })?,
            max_output_bytes: self
                .max_output_bytes
                .checked_add(other.max_output_bytes)
                .ok_or_else(|| PolicyError::BudgetOverrun("output allocation overflow".into()))?,
            max_artifact_bytes: self
                .max_artifact_bytes
                .checked_add(other.max_artifact_bytes)
                .ok_or_else(|| PolicyError::BudgetOverrun("artifact allocation overflow".into()))?,
        })
    }

    fn zero() -> Self {
        Self {
            max_wall_time_ms: 0,
            max_output_bytes: 0,
            max_artifact_bytes: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableAuthorityV1 {
    pub role: String,
    pub path: String,
    pub descriptor_identity: String,
    pub byte_digest: ContentDigest,
    pub byte_length: u64,
    pub owner: u32,
    pub mode: u32,
    pub read_only_filesystem: bool,
}

impl ExecutableAuthorityV1 {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.role.is_empty()
            || !Path::new(&self.path).is_absolute()
            || self.descriptor_identity.is_empty()
            || self.byte_length == 0
            || self.mode & 0o111 == 0
            || self.mode & 0o022 != 0
            || (self.owner != 0 && !self.read_only_filesystem)
        {
            return Err(PolicyError::InvalidLease(
                "executable authority is not a trusted immutable source".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedActionV1 {
    pub tool: String,
    pub action_digest: ContentDigest,
    pub args_digest: ContentDigest,
    pub effect: EffectScopeV1,
    pub effect_digest: ContentDigest,
    pub executable_authority: Vec<ExecutableAuthorityV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationTransitionV1 {
    ControlToEffect,
    ControlToControl,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationCeilingV1 {
    pub actor: ActorPrincipalV1,
    pub policy_version: String,
    pub run_id: CurrentRunId,
    pub transition: DelegationTransitionV1,
    /// Canonical, closed audience set for the next delegation edge.
    pub audiences: Vec<String>,
    pub actions: Vec<DelegatedActionV1>,
    pub budget: PermitBudgetV1,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl DelegationCeilingV1 {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.policy_version.is_empty()
            || self.actions.is_empty()
            || self.audiences.is_empty()
            || self.not_before >= self.expires_at
            || self.budget.max_wall_time_ms == 0
            || self.budget.max_output_bytes == 0
            || self.budget.max_artifact_bytes == 0
        {
            return Err(PolicyError::InvalidLease(
                "invalid delegation ceiling".into(),
            ));
        }
        let mut prior_audience: Option<&str> = None;
        for audience in &self.audiences {
            if audience.is_empty()
                || audience.chars().any(char::is_control)
                || prior_audience.is_some_and(|prior| prior >= audience.as_str())
            {
                return Err(PolicyError::InvalidLease(
                    "delegation audiences must be nonempty, unique, and sorted".into(),
                ));
            }
            prior_audience = Some(audience);
        }
        let mut prior_action: Option<String> = None;
        for action in &self.actions {
            if action.tool.is_empty()
                || action.effect.scope_name.is_empty()
                || action.effect.network_allowed
                || action.effect_digest != content_digest(&action.effect)?
            {
                return Err(PolicyError::InvalidLease(
                    "delegation ceiling contains an invalid action".into(),
                ));
            }
            for executable in &action.executable_authority {
                executable.validate()?;
            }
            let action_key = content_digest(action)?.hex().to_owned();
            if prior_action
                .as_ref()
                .is_some_and(|prior| prior >= &action_key)
            {
                return Err(PolicyError::InvalidLease(
                    "delegation actions must be unique and canonically sorted".into(),
                ));
            }
            prior_action = Some(action_key);
        }
        Ok(())
    }
}

/// Every authority, effect, budget, temporal, lineage, and invocation field
/// that must still match immediately before effect dispatch.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermitBindingV1 {
    pub actor: ActorPrincipalV1,
    pub action_digest: ContentDigest,
    pub effect: EffectScopeV1,
    pub effect_digest: ContentDigest,
    pub budget: PermitBudgetV1,
    pub policy_version: String,
    pub parent_permit_id: Option<CurrentPermitId>,
    pub parent_operation_id: Option<CurrentRunId>,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub run_id: CurrentRunId,
    pub step_id: CurrentStepId,
    pub tool: String,
    pub args_digest: ContentDigest,
}

impl PermitBindingV1 {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.policy_version.is_empty() || self.tool.is_empty() {
            return Err(PolicyError::InvalidLease(
                "policy version and tool must be nonempty".into(),
            ));
        }
        if self.effect.scope_name.is_empty()
            || self.effect.scope_name.chars().any(char::is_control)
            || self
                .effect
                .read_roots
                .iter()
                .chain(self.effect.write_roots.iter())
                .any(|path| {
                    !Path::new(path).is_absolute()
                        || path.chars().any(char::is_control)
                        || Path::new(path)
                            .components()
                            .any(|component| matches!(component, std::path::Component::ParentDir))
                })
        {
            return Err(PolicyError::InvalidLease("invalid effect scope".into()));
        }
        if self.effect.network_allowed {
            return Err(PolicyError::NetworkUnavailable);
        }
        if self.issued_at > self.not_before || self.not_before >= self.expires_at {
            return Err(PolicyError::InvalidLease(
                "lease times must satisfy issued <= not-before < expiry".into(),
            ));
        }
        if content_digest(&self.effect).map_err(PolicyError::Contract)? != self.effect_digest {
            return Err(PolicyError::InvalidLease(
                "effect digest does not bind the complete effect scope".into(),
            ));
        }
        if self.budget.max_wall_time_ms == 0
            || self.budget.max_output_bytes == 0
            || self.budget.max_artifact_bytes == 0
        {
            return Err(PolicyError::InvalidLease(
                "lease budgets must be nonzero".into(),
            ));
        }
        Ok(())
    }

    pub fn identity_material(&self) -> Result<PermitIdentityMaterialV1, PolicyError> {
        #[derive(serde::Serialize)]
        struct NonTemporalBinding<'a> {
            actor: &'a ActorPrincipalV1,
            action_digest: &'a ContentDigest,
            effect: &'a EffectScopeV1,
            effect_digest: &'a ContentDigest,
            budget: &'a PermitBudgetV1,
            policy_version: &'a str,
            parent_permit_id: &'a Option<CurrentPermitId>,
            parent_operation_id: &'a Option<CurrentRunId>,
            run_id: &'a CurrentRunId,
            step_id: &'a CurrentStepId,
            tool: &'a str,
            args_digest: &'a ContentDigest,
        }
        let delay = self.not_before.signed_duration_since(self.issued_at);
        let validity = self.expires_at.signed_duration_since(self.not_before);
        let requested_not_before_delay_ms = u64::try_from(delay.num_milliseconds())
            .map_err(|_| PolicyError::InvalidLease("negative permit start delay".into()))?;
        let requested_validity_ms = u64::try_from(validity.num_milliseconds())
            .map_err(|_| PolicyError::InvalidLease("negative permit validity".into()))?;
        Ok(PermitIdentityMaterialV1 {
            binding_digest: content_digest(&NonTemporalBinding {
                actor: &self.actor,
                action_digest: &self.action_digest,
                effect: &self.effect,
                effect_digest: &self.effect_digest,
                budget: &self.budget,
                policy_version: &self.policy_version,
                parent_permit_id: &self.parent_permit_id,
                parent_operation_id: &self.parent_operation_id,
                run_id: &self.run_id,
                step_id: &self.step_id,
                tool: &self.tool,
                args_digest: &self.args_digest,
            })?,
            requested_not_before_delay_ms,
            requested_validity_ms,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPermitV1 {
    pub permit_id: CurrentPermitId,
    pub binding: PermitBindingV1,
    pub purpose: PermitPurposeV1,
    pub delegation_ceiling: Option<DelegationCeilingV1>,
    /// Immutable derivation proof for a delegated effect permit.
    pub delegation_identity: Option<DelegationIdentityV1>,
    pub executable_authority: Vec<ExecutableAuthorityV1>,
}

impl ExecutionPermitV1 {
    pub fn control(
        binding: PermitBindingV1,
        delegation_ceiling: DelegationCeilingV1,
    ) -> Result<Self, PolicyError> {
        if binding.parent_permit_id.is_some() {
            return Err(PolicyError::InvalidLease(
                "delegated controls must be issued through DurablePermitStore".into(),
            ));
        }
        delegation_ceiling.validate()?;
        let purpose = PermitPurposeV1::Control;
        let delegation_ceiling = Some(delegation_ceiling);
        let delegation_identity = None;
        let executable_authority = Vec::new();
        let permit_id = derive_permit_id(&execution_identity_material(
            &binding,
            purpose,
            &delegation_ceiling,
            &delegation_identity,
            &executable_authority,
        )?)?;
        Ok(Self {
            permit_id,
            binding,
            purpose,
            delegation_ceiling,
            delegation_identity,
            executable_authority,
        })
    }

    pub fn effect(
        binding: PermitBindingV1,
        executable_authority: Vec<ExecutableAuthorityV1>,
    ) -> Result<Self, PolicyError> {
        if binding.parent_permit_id.is_some() {
            return Err(PolicyError::InvalidLease(
                "delegated effects must be issued through DurablePermitStore".into(),
            ));
        }
        let purpose = PermitPurposeV1::Effect;
        let delegation_ceiling = None;
        let delegation_identity = None;
        let permit_id = derive_permit_id(&execution_identity_material(
            &binding,
            purpose,
            &delegation_ceiling,
            &delegation_identity,
            &executable_authority,
        )?)?;
        Ok(Self {
            permit_id,
            binding,
            purpose,
            delegation_ceiling,
            delegation_identity,
            executable_authority,
        })
    }

    fn identity_material(&self) -> Result<PermitIdentityMaterialV1, PolicyError> {
        execution_identity_material(
            &self.binding,
            self.purpose,
            &self.delegation_ceiling,
            &self.delegation_identity,
            &self.executable_authority,
        )
    }
}

fn execution_identity_material(
    binding: &PermitBindingV1,
    purpose: PermitPurposeV1,
    delegation_ceiling: &Option<DelegationCeilingV1>,
    delegation_identity: &Option<DelegationIdentityV1>,
    executable_authority: &[ExecutableAuthorityV1],
) -> Result<PermitIdentityMaterialV1, PolicyError> {
    #[derive(serde::Serialize)]
    struct AuthorityMaterial<'a> {
        binding: &'a PermitIdentityMaterialV1,
        purpose: PermitPurposeV1,
        delegation_ceiling: Option<DelegationCeilingIdentity<'a>>,
        delegation_identity: &'a Option<DelegationIdentityV1>,
        executable_authority: &'a [ExecutableAuthorityV1],
    }
    #[derive(serde::Serialize)]
    struct DelegationCeilingIdentity<'a> {
        actor: &'a ActorPrincipalV1,
        policy_version: &'a str,
        run_id: &'a CurrentRunId,
        transition: DelegationTransitionV1,
        audiences: &'a [String],
        actions: &'a [DelegatedActionV1],
        budget: &'a PermitBudgetV1,
        requested_not_before_delay_ms: u64,
        requested_validity_ms: u64,
    }
    let temporal = binding.identity_material()?;
    let ceiling_identity = delegation_ceiling
        .as_ref()
        .map(
            |ceiling| -> Result<DelegationCeilingIdentity<'_>, PolicyError> {
                let delay = ceiling.not_before.signed_duration_since(binding.issued_at);
                let validity = ceiling.expires_at.signed_duration_since(ceiling.not_before);
                Ok(DelegationCeilingIdentity {
                    actor: &ceiling.actor,
                    policy_version: &ceiling.policy_version,
                    run_id: &ceiling.run_id,
                    transition: ceiling.transition,
                    audiences: &ceiling.audiences,
                    actions: &ceiling.actions,
                    budget: &ceiling.budget,
                    requested_not_before_delay_ms: u64::try_from(delay.num_milliseconds())
                        .map_err(|_| {
                            PolicyError::InvalidLease("negative delegation start delay".into())
                        })?,
                    requested_validity_ms: u64::try_from(validity.num_milliseconds()).map_err(
                        |_| PolicyError::InvalidLease("negative delegation validity".into()),
                    )?,
                })
            },
        )
        .transpose()?;
    Ok(PermitIdentityMaterialV1 {
        binding_digest: content_digest(&AuthorityMaterial {
            binding: &temporal,
            purpose,
            delegation_ceiling: ceiling_identity,
            delegation_identity,
            executable_authority,
        })?,
        requested_not_before_delay_ms: temporal.requested_not_before_delay_ms,
        requested_validity_ms: temporal.requested_validity_ms,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermitRevocationReasonV1 {
    Operator,
    ParentRevoked,
    PolicySuperseded,
    OperationCancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum PermitStateV1 {
    Issued,
    Consumed {
        consumed_at: DateTime<Utc>,
    },
    Revoked {
        revoked_at: DateTime<Utc>,
        reason: PermitRevocationReasonV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermitRecordV1 {
    pub permit: ExecutionPermitV1,
    pub state: PermitStateV1,
    #[serde(default)]
    pub child_allocations: std::collections::BTreeMap<CurrentPermitId, PermitBudgetV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum PermitEvidenceStateV1 {
    Issued,
    Consumed {
        at: DateTime<Utc>,
    },
    Rejected {
        at: DateTime<Utc>,
        reason: PermitRejectionReasonV1,
    },
    Revoked {
        at: DateTime<Utc>,
        reason: PermitRevocationReasonV1,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermitPurposeV1 {
    Effect,
    Control,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermitEvidenceV1 {
    pub permit_id: CurrentPermitId,
    pub binding: PermitBindingV1,
    pub binding_digest: ContentDigest,
    pub purpose: PermitPurposeV1,
    pub delegation_ceiling: Option<DelegationCeilingV1>,
    pub delegation_identity: Option<DelegationIdentityV1>,
    pub executable_authority: Vec<ExecutableAuthorityV1>,
    pub child_allocations: std::collections::BTreeMap<CurrentPermitId, PermitBudgetV1>,
    pub state: PermitEvidenceStateV1,
}

impl PermitEvidenceV1 {
    pub fn from_record(record: &PermitRecordV1) -> Result<Self, PolicyError> {
        let state = match &record.state {
            PermitStateV1::Issued => PermitEvidenceStateV1::Issued,
            PermitStateV1::Consumed { consumed_at } => {
                PermitEvidenceStateV1::Consumed { at: *consumed_at }
            }
            PermitStateV1::Revoked { revoked_at, reason } => PermitEvidenceStateV1::Revoked {
                at: *revoked_at,
                reason: reason.clone(),
            },
        };
        let evidence = Self {
            permit_id: record.permit.permit_id.clone(),
            binding: record.permit.binding.clone(),
            binding_digest: content_digest(&record.permit.binding)?,
            purpose: record.permit.purpose,
            delegation_ceiling: record.permit.delegation_ceiling.clone(),
            delegation_identity: record.permit.delegation_identity.clone(),
            executable_authority: record.permit.executable_authority.clone(),
            child_allocations: record.child_allocations.clone(),
            state,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn rejected(
        permit: &ExecutionPermitV1,
        at: DateTime<Utc>,
        reason: PermitRejectionReasonV1,
    ) -> Result<Self, PolicyError> {
        let evidence = Self {
            permit_id: permit.permit_id.clone(),
            binding: permit.binding.clone(),
            binding_digest: content_digest(&permit.binding)?,
            purpose: permit.purpose,
            delegation_ceiling: permit.delegation_ceiling.clone(),
            delegation_identity: permit.delegation_identity.clone(),
            executable_authority: permit.executable_authority.clone(),
            child_allocations: std::collections::BTreeMap::new(),
            state: PermitEvidenceStateV1::Rejected { at, reason },
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        self.binding.validate()?;
        let permit = ExecutionPermitV1 {
            permit_id: self.permit_id.clone(),
            binding: self.binding.clone(),
            purpose: self.purpose,
            delegation_ceiling: self.delegation_ceiling.clone(),
            delegation_identity: self.delegation_identity.clone(),
            executable_authority: self.executable_authority.clone(),
        };
        if self.binding_digest != content_digest(&self.binding)?
            || self.permit_id != derive_permit_id(&permit.identity_material()?)?
        {
            return Err(PolicyError::InvalidLease(
                "permit evidence identity or binding digest mismatch".into(),
            ));
        }
        match self.purpose {
            PermitPurposeV1::Control => {
                let ceiling = self.delegation_ceiling.as_ref().ok_or_else(|| {
                    PolicyError::InvalidLease("control evidence lacks a delegation ceiling".into())
                })?;
                ceiling.validate()?;
                if !self.executable_authority.is_empty()
                    || ceiling.actor != self.binding.actor
                    || ceiling.policy_version != self.binding.policy_version
                    || ceiling.run_id != self.binding.run_id
                    || ceiling.not_before < self.binding.not_before
                    || ceiling.expires_at > self.binding.expires_at
                    || ceiling.budget != self.binding.budget
                {
                    return Err(PolicyError::InvalidLease(
                        "control permit does not bind its delegation ceiling".into(),
                    ));
                }
                match (&self.binding.parent_permit_id, &self.delegation_identity) {
                    (Some(_), Some(identity)) => identity.validate()?,
                    (Some(_), None) => {
                        return Err(PolicyError::InvalidLease(
                            "delegated control permit lacks a derivation proof".into(),
                        ));
                    }
                    (None, Some(_)) => {
                        return Err(PolicyError::InvalidLease(
                            "root control permit carries a delegation proof".into(),
                        ));
                    }
                    (None, None) => {}
                }
            }
            PermitPurposeV1::Effect => {
                if self.delegation_ceiling.is_some() {
                    return Err(PolicyError::InvalidLease(
                        "effect permit carries a control delegation ceiling".into(),
                    ));
                }
                match (&self.binding.parent_permit_id, &self.delegation_identity) {
                    (Some(_), Some(identity)) => identity.validate()?,
                    (Some(_), None) => {
                        return Err(PolicyError::InvalidLease(
                            "delegated effect permit lacks a derivation proof".into(),
                        ));
                    }
                    (None, Some(_)) => {
                        return Err(PolicyError::InvalidLease(
                            "root effect permit carries a delegation proof".into(),
                        ));
                    }
                    (None, None) => {}
                }
                for executable in &self.executable_authority {
                    executable.validate()?;
                }
            }
        }
        match self.state {
            PermitEvidenceStateV1::Issued => {}
            PermitEvidenceStateV1::Consumed { at } => {
                if at < self.binding.issued_at
                    || at < self.binding.not_before
                    || at >= self.binding.expires_at
                {
                    return Err(PolicyError::InvalidLease(
                        "permit consumption time is outside its validity window".into(),
                    ));
                }
            }
            PermitEvidenceStateV1::Rejected { at, .. }
            | PermitEvidenceStateV1::Revoked { at, .. } => {
                if at < self.binding.issued_at {
                    return Err(PolicyError::InvalidLease(
                        "permit terminal evidence precedes issuance".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn validate_consumed_call(&self, call: &ToolCallSpecV1) -> Result<(), PolicyError> {
        self.validate()?;
        if !matches!(self.state, PermitEvidenceStateV1::Consumed { .. }) {
            return Err(rejected(
                &self.permit_id,
                PermitRejectionReasonV1::StateCorrupted,
            ));
        }
        if self.binding.tool != call.tool {
            return Err(rejected(
                &self.permit_id,
                PermitRejectionReasonV1::WrongTool,
            ));
        }
        if self.binding.action_digest != content_digest(call)? {
            return Err(rejected(
                &self.permit_id,
                PermitRejectionReasonV1::WrongAction,
            ));
        }
        if self.binding.args_digest != content_digest(&call.args)? {
            return Err(rejected(
                &self.permit_id,
                PermitRejectionReasonV1::WrongArguments,
            ));
        }
        Ok(())
    }

    pub fn enforce_observation_bounds(
        &self,
        output_bytes: u64,
        artifact_bytes: u64,
    ) -> Result<(), PolicyError> {
        if output_bytes > self.binding.budget.max_output_bytes
            || artifact_bytes > self.binding.budget.max_artifact_bytes
        {
            return Err(PolicyError::BudgetOverrun(
                "authorized output or artifact budget exceeded".into(),
            ));
        }
        Ok(())
    }

    pub fn authorized_context_evidence(&self) -> Result<AuthorizedContextEvidenceV1, PolicyError> {
        self.validate()?;
        Ok(AuthorizedContextEvidenceV1 {
            permit_id: self.permit_id.clone(),
            binding_digest: self.binding_digest.clone(),
            actor: self.binding.actor.clone(),
            run_id: self.binding.run_id.clone(),
            step_id: self.binding.step_id.clone(),
            tool: self.binding.tool.clone(),
            effect_digest: self.binding.effect_digest.clone(),
            budget: self.binding.budget.clone(),
            parent_permit_id: self.binding.parent_permit_id.clone(),
            executable_authority: self.executable_authority.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedContextEvidenceV1 {
    pub permit_id: CurrentPermitId,
    pub binding_digest: ContentDigest,
    pub actor: ActorPrincipalV1,
    pub run_id: CurrentRunId,
    pub step_id: CurrentStepId,
    pub tool: String,
    pub effect_digest: ContentDigest,
    pub budget: PermitBudgetV1,
    pub parent_permit_id: Option<CurrentPermitId>,
    pub executable_authority: Vec<ExecutableAuthorityV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermitRejectionReasonV1 {
    NotIssued,
    AlreadyConsumed,
    Revoked,
    Expired,
    NotYetValid,
    WrongActor,
    WrongAction,
    ChangedEffect,
    BudgetExceeded,
    WrongParent,
    WrongPolicy,
    WrongOperation,
    WrongStep,
    WrongTool,
    WrongArguments,
    StateCorrupted,
}

impl std::fmt::Display for PermitRejectionReasonV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("tool not in allowlist: {0}")]
    ToolNotAllowed(String),
    #[error("args exceed max bytes: {0} > {1}")]
    ArgsTooLarge(usize, usize),
    #[error("contract error: {0}")]
    Contract(#[from] ContractError),
    #[error("tool {0} requires frozen_clock; got None")]
    FrozenClockRequired(String),
    #[error("invalid capability lease: {0}")]
    InvalidLease(String),
    #[error("permit rejected: {reason}")]
    PermitRejected {
        permit_id: CurrentPermitId,
        reason: PermitRejectionReasonV1,
    },
    #[error("permit state conflicts with an existing durable record")]
    PermitStateConflict,
    #[error("permit root is unsafe: {0}")]
    UnsafePermitRoot(String),
    #[error("permit store io: {0}")]
    Io(#[from] std::io::Error),
    #[error("permit store json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("injected permit transition interruption after {0:?}")]
    InjectedInterruption(PermitTransitionStage),
    #[error("execution budget overrun: {0}")]
    BudgetOverrun(String),
    #[error("network effects are unavailable in Phase 1")]
    NetworkUnavailable,
    #[error("submitted policy version {submitted} does not match active version {active}")]
    PolicyVersionMismatch { submitted: String, active: String },
}

const FAMILY_STATE_NAME: &str = "family-authority.json";
const FAMILY_LOCK_NAME: &str = ".family-authority.lock";
const MAX_FAMILY_STATE_BYTES: u64 = 1024 * 1024;

/// The child-control power held by one admitted root operation. It is distinct
/// from the root's normal effect ceiling: allocating a child must not spend or
/// widen the parent's independent effect budget.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildRunCeilingV1 {
    pub max_depth: u32,
    pub max_children: u32,
    pub family_budget: PermitBudgetV1,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl ChildRunCeilingV1 {
    fn validate(&self) -> Result<(), PolicyError> {
        if self.max_depth == 0
            || self.max_children == 0
            || self.not_before >= self.expires_at
            || self.family_budget.max_wall_time_ms == 0
            || self.family_budget.max_output_bytes == 0
            || self.family_budget.max_artifact_bytes == 0
        {
            return Err(PolicyError::InvalidLease(
                "invalid child-run family ceiling".into(),
            ));
        }
        Ok(())
    }
}

/// The one root-family grant material owned by the family authority store.
/// `parent_control_permit_id` is an already-admitted parent authority reference;
/// Phase 7.2B verifies its ledger/permit evidence before opening this store.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyRootGrantV1 {
    pub root_operation_id: CurrentRunId,
    pub parent_control_permit_id: CurrentPermitId,
    pub actor: ActorPrincipalV1,
    pub policy_version: String,
    pub effect_budget: PermitBudgetV1,
    pub child_run_ceiling: ChildRunCeilingV1,
}

impl FamilyRootGrantV1 {
    fn validate(&self) -> Result<(), PolicyError> {
        if self.policy_version.is_empty()
            || self.effect_budget.max_wall_time_ms == 0
            || self.effect_budget.max_output_bytes == 0
            || self.effect_budget.max_artifact_bytes == 0
        {
            return Err(PolicyError::InvalidLease(
                "invalid root family control grant".into(),
            ));
        }
        self.child_run_ceiling.validate()
    }
}

/// The exact child proposal that may receive one family-scoped child-control
/// permit. The parent receipt ID is deliberately opaque here: the policy store
/// prevents budget/lineage widening, while the runner/ledger owner must verify
/// that referenced receipt before this request reaches the store.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyChildRequestV1 {
    pub child_run_id: CurrentRunId,
    pub parent_operation_id: CurrentRunId,
    pub root_operation_id: CurrentRunId,
    pub parent_control_permit_id: CurrentPermitId,
    pub parent_admission_receipt_id: recursive_agent_contracts::CurrentReceiptId,
    pub requested_budget: PermitBudgetV1,
    pub child_operation_digest: ContentDigest,
    pub depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FamilyChildPermitStateV1 {
    Issued,
    Revoked {
        revoked_at: DateTime<Utc>,
        reason: PermitRevocationReasonV1,
    },
}

/// Persisted child-control permit. It is intentionally not an
/// `ExecutionPermitV1`: existing V1 permits are single-run and must never be
/// widened into cross-run authority.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyChildControlPermitV1 {
    pub child_control_permit_id: CurrentPermitId,
    pub request: FamilyChildRequestV1,
    pub state: FamilyChildPermitStateV1,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FamilyAuthorityStateV1 {
    grant: FamilyRootGrantV1,
    parent_revoked_at: Option<DateTime<Utc>>,
    children: std::collections::BTreeMap<CurrentRunId, FamilyChildControlPermitV1>,
}

/// Descriptor-rooted authoritative allocation store for one causal family.
/// This is deliberately separate from `DurablePermitStore`, whose one-run
/// binding must remain fail-closed for child-run proposals.
#[derive(Debug, Clone)]
pub struct FamilyAuthorityStore {
    root: Arc<File>,
    lock: Arc<File>,
    gate: Arc<Mutex<()>>,
    root_device: u64,
    root_inode: u64,
}

impl FamilyAuthorityStore {
    /// Open or atomically initialize a store rooted at the runtime-selected
    /// deterministic family directory. A conflicting root grant is rejected;
    /// callers cannot overwrite authority after initialization.
    pub fn from_dir_fd(root: &File, grant: FamilyRootGrantV1) -> Result<Self, PolicyError> {
        grant.validate()?;
        let identity = directory_identity(root)?;
        let root = Arc::new(root.try_clone()?);
        let lock = File::from(secure_open_at(
            &root,
            FAMILY_LOCK_NAME,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?);
        if !lock.metadata()?.is_file() {
            return Err(PolicyError::UnsafePermitRoot(
                "family authority lock must be a regular file".into(),
            ));
        }
        let store = Self {
            root,
            lock: Arc::new(lock),
            gate: Arc::new(Mutex::new(())),
            root_device: identity.0,
            root_inode: identity.1,
        };
        store.with_lock(|| match store.read_state() {
            Ok(existing) if existing.grant == grant => Ok(()),
            Ok(_) => Err(PolicyError::PermitStateConflict),
            Err(PolicyError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => store
                .write_state(&FamilyAuthorityStateV1 {
                    grant,
                    parent_revoked_at: None,
                    children: std::collections::BTreeMap::new(),
                }),
            Err(error) => Err(error),
        })?;
        Ok(store)
    }

    /// Atomically reserve exactly one attenuated child-control allocation.
    /// Repeating the identical request returns the original permit without
    /// double-counting. A conflicting request for the same child run rejects.
    pub fn reserve_child(
        &self,
        request: &FamilyChildRequestV1,
        trusted_now: DateTime<Utc>,
    ) -> Result<FamilyChildControlPermitV1, PolicyError> {
        self.with_lock(|| {
            let mut state = self.read_state()?;
            validate_family_request(&state, request, trusted_now)?;
            if let Some(existing) = state.children.get(&request.child_run_id) {
                if existing.request == *request
                    && matches!(existing.state, FamilyChildPermitStateV1::Issued)
                {
                    return Ok(existing.clone());
                }
                return Err(PolicyError::PermitStateConflict);
            }
            let max_children = usize::try_from(state.grant.child_run_ceiling.max_children)
                .map_err(|_| {
                    PolicyError::InvalidLease("family child count does not fit usize".into())
                })?;
            if state.children.len() >= max_children {
                return Err(PolicyError::BudgetOverrun(
                    "child allocation exceeds family child-count ceiling".into(),
                ));
            }
            let allocated = state
                .children
                .values()
                .try_fold(PermitBudgetV1::zero(), |total, child| {
                    total.checked_add(&child.request.requested_budget)
                })?
                .checked_add(&request.requested_budget)?;
            if !allocated.is_within(&state.grant.child_run_ceiling.family_budget) {
                return Err(PolicyError::BudgetOverrun(
                    "child allocation exceeds cumulative family budget".into(),
                ));
            }
            let permit = FamilyChildControlPermitV1 {
                child_control_permit_id: derive_family_child_permit_id(request, &state.grant)?,
                request: request.clone(),
                state: FamilyChildPermitStateV1::Issued,
            };
            state
                .children
                .insert(request.child_run_id.clone(), permit.clone());
            self.write_state(&state)?;
            Ok(permit)
        })
    }

    /// Record parent cancellation/revocation before dispatch. Existing permits
    /// are preserved as evidence but all future reservations fail closed.
    pub fn revoke_parent(&self, trusted_now: DateTime<Utc>) -> Result<(), PolicyError> {
        self.with_lock(|| {
            let mut state = self.read_state()?;
            if state.parent_revoked_at.is_none() {
                state.parent_revoked_at = Some(trusted_now);
                self.write_state(&state)?;
            }
            Ok(())
        })
    }

    /// Check the family authority immediately around one child effect.
    ///
    /// This deliberately reads the durable family state for both checks: a
    /// cancellation that races an already-reserved child must prevent a later
    /// dispatch, and must also prevent that effect from being reported as a
    /// success after it returns.
    pub fn guard_child_dispatch(
        &self,
        child_run_id: &CurrentRunId,
        child_control_permit_id: &CurrentPermitId,
        trusted_now: DateTime<Utc>,
    ) -> Result<(), PolicyError> {
        self.with_lock(|| {
            let state = self.read_state()?;
            let ceiling = &state.grant.child_run_ceiling;
            let child = state.children.get(child_run_id).ok_or_else(|| {
                PolicyError::InvalidLease("child dispatch has no family reservation".into())
            })?;
            if state.parent_revoked_at.is_some()
                || trusted_now < ceiling.not_before
                || trusted_now >= ceiling.expires_at
                || !matches!(child.state, FamilyChildPermitStateV1::Issued)
                || child.child_control_permit_id != *child_control_permit_id
            {
                return Err(PolicyError::InvalidLease(
                    "child dispatch is no longer authorized by its family".into(),
                ));
            }
            Ok(())
        })
    }

    /// Whether this family has been durably revoked by its live parent.
    pub fn parent_is_revoked(&self) -> Result<bool, PolicyError> {
        self.with_lock(|| Ok(self.read_state()?.parent_revoked_at.is_some()))
    }

    /// The root effect power is immutable and separate from child reservations.
    pub fn effect_budget(&self) -> Result<PermitBudgetV1, PolicyError> {
        self.with_lock(|| Ok(self.read_state()?.grant.effect_budget))
    }

    /// Sum of durable child allocations, not an inferred scheduler projection.
    pub fn reserved_budget(&self) -> Result<PermitBudgetV1, PolicyError> {
        self.with_lock(|| {
            self.read_state()?
                .children
                .values()
                .try_fold(PermitBudgetV1::zero(), |total, child| {
                    total.checked_add(&child.request.requested_budget)
                })
        })
    }

    pub fn root_identity(&self) -> (u64, u64) {
        (self.root_device, self.root_inode)
    }

    fn with_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, PolicyError>,
    ) -> Result<T, PolicyError> {
        let _thread_guard = self
            .gate
            .lock()
            .map_err(|_| PolicyError::PermitStateConflict)?;
        rustix::fs::flock(self.lock.as_fd(), FlockOperation::LockExclusive)
            .map_err(std::io::Error::from)?;
        let result = operation();
        let unlock = rustix::fs::flock(self.lock.as_fd(), FlockOperation::Unlock);
        match (result, unlock) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(PolicyError::Io(error.into())),
        }
    }

    fn read_state(&self) -> Result<FamilyAuthorityStateV1, PolicyError> {
        let fd = secure_open_at(
            &self.root,
            FAMILY_STATE_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?;
        let file = File::from(fd);
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_FAMILY_STATE_BYTES {
            return Err(PolicyError::UnsafePermitRoot(
                "family authority state is not a bounded regular file".into(),
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_FAMILY_STATE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_FAMILY_STATE_BYTES {
            return Err(PolicyError::UnsafePermitRoot(
                "family authority state exceeds its byte limit".into(),
            ));
        }
        let state: FamilyAuthorityStateV1 = serde_json::from_slice(&bytes)?;
        state.grant.validate()?;
        Ok(state)
    }

    fn write_state(&self, state: &FamilyAuthorityStateV1) -> Result<(), PolicyError> {
        let (temp_name, mut file) = create_unique_temp(&self.root, ".family-authority.tmp")?;
        file.write_all(&jcs_canonical(state)?)?;
        file.sync_all()?;
        rustix::fs::renameat(
            self.root.as_fd(),
            &temp_name,
            self.root.as_fd(),
            FAMILY_STATE_NAME,
        )
        .map_err(std::io::Error::from)?;
        self.root.sync_all()?;
        Ok(())
    }
}

fn validate_family_request(
    state: &FamilyAuthorityStateV1,
    request: &FamilyChildRequestV1,
    trusted_now: DateTime<Utc>,
) -> Result<(), PolicyError> {
    let ceiling = &state.grant.child_run_ceiling;
    if state.parent_revoked_at.is_some()
        || trusted_now < ceiling.not_before
        || trusted_now >= ceiling.expires_at
        || request.root_operation_id != state.grant.root_operation_id
        || request.child_run_id == request.parent_operation_id
        || request.child_run_id == request.root_operation_id
        || request.depth == 0
        || request.depth > ceiling.max_depth
        || !request.requested_budget.is_within(&ceiling.family_budget)
    {
        return Err(PolicyError::InvalidLease(
            "child request violates family authority or attenuation".into(),
        ));
    }
    if request.parent_operation_id == state.grant.root_operation_id {
        if request.parent_control_permit_id != state.grant.parent_control_permit_id
            || request.depth != 1
        {
            return Err(PolicyError::InvalidLease(
                "child request does not bind the root parent control grant".into(),
            ));
        }
        return Ok(());
    }
    let parent = state
        .children
        .get(&request.parent_operation_id)
        .ok_or_else(|| {
            PolicyError::InvalidLease("child request parent is not an admitted family child".into())
        })?;
    let expected_depth = parent
        .request
        .depth
        .checked_add(1)
        .ok_or_else(|| PolicyError::InvalidLease("family depth overflow".into()))?;
    if !matches!(parent.state, FamilyChildPermitStateV1::Issued)
        || request.parent_control_permit_id != parent.child_control_permit_id
        || request.depth != expected_depth
    {
        return Err(PolicyError::InvalidLease(
            "child request does not attenuate from its admitted parent child-control permit".into(),
        ));
    }
    Ok(())
}

fn derive_family_child_permit_id(
    request: &FamilyChildRequestV1,
    grant: &FamilyRootGrantV1,
) -> Result<CurrentPermitId, PolicyError> {
    let validity = grant
        .child_run_ceiling
        .expires_at
        .signed_duration_since(grant.child_run_ceiling.not_before);
    let requested_validity_ms = u64::try_from(validity.num_milliseconds())
        .map_err(|_| PolicyError::InvalidLease("negative family child validity".into()))?;
    derive_permit_id(&PermitIdentityMaterialV1 {
        binding_digest: content_digest(request)?,
        requested_not_before_delay_ms: 0,
        requested_validity_ms,
    })
    .map_err(PolicyError::Contract)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermitTransitionStage {
    TempWrite,
    TempFsync,
    Rename,
    DirectoryFsync,
}

#[derive(Debug, Clone)]
pub struct DurablePermitStore {
    root: Arc<File>,
    lock: Arc<File>,
    gate: Arc<Mutex<()>>,
    run_root_device: u64,
    run_root_inode: u64,
    permit_root_device: u64,
    permit_root_inode: u64,
}

impl DurablePermitStore {
    pub fn from_run_root_fd(run_root: &File) -> Result<Self, PolicyError> {
        let run_identity = directory_identity(run_root)?;
        let permit_root = open_permit_child(run_root)?;
        let permit_identity = directory_identity(&permit_root)?;
        if permit_identity.2 != run_identity.2 {
            return Err(PolicyError::UnsafePermitRoot(
                "permit root owner differs from pinned run root".into(),
            ));
        }
        Self::from_root_file(permit_root, run_identity, permit_identity)
    }

    pub fn from_dir_fd(root: &File) -> Result<Self, PolicyError> {
        let identity = directory_identity(root)?;
        Self::from_root_file(root.try_clone()?, identity, identity)
    }

    fn from_root_file(
        root_file: File,
        run_identity: (u64, u64, u32),
        permit_identity: (u64, u64, u32),
    ) -> Result<Self, PolicyError> {
        let root_file = Arc::new(root_file);
        let lock_fd = secure_open_at(
            &root_file,
            ".permit.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        let lock_file = File::from(lock_fd);
        if !lock_file.metadata()?.is_file() {
            return Err(PolicyError::UnsafePermitRoot(
                "permit lock must be a regular file".into(),
            ));
        }
        Ok(Self {
            root: root_file,
            lock: Arc::new(lock_file),
            gate: Arc::new(Mutex::new(())),
            run_root_device: run_identity.0,
            run_root_inode: run_identity.1,
            permit_root_device: permit_identity.0,
            permit_root_inode: permit_identity.1,
        })
    }

    pub fn issue(
        &self,
        binding: &PermitBindingV1,
        trusted_now: DateTime<Utc>,
    ) -> Result<ExecutionPermitV1, PolicyError> {
        if binding.parent_permit_id.is_some() {
            return Err(PolicyError::InvalidLease(
                "child effect issuance requires explicit executable authority".into(),
            ));
        }
        self.issue_authority(
            binding,
            PermitPurposeV1::Effect,
            None,
            Vec::new(),
            trusted_now,
        )
    }

    pub fn issue_control(
        &self,
        binding: &PermitBindingV1,
        ceiling: DelegationCeilingV1,
        trusted_now: DateTime<Utc>,
    ) -> Result<ExecutionPermitV1, PolicyError> {
        self.issue_authority(
            binding,
            PermitPurposeV1::Control,
            Some(ceiling),
            Vec::new(),
            trusted_now,
        )
    }

    pub fn issue_effect(
        &self,
        binding: &PermitBindingV1,
        executable_authority: Vec<ExecutableAuthorityV1>,
        trusted_now: DateTime<Utc>,
    ) -> Result<ExecutionPermitV1, PolicyError> {
        if binding.parent_permit_id.is_none() {
            return Err(PolicyError::InvalidLease(
                "delegated effect permit requires a control parent".into(),
            ));
        }
        self.issue_authority(
            binding,
            PermitPurposeV1::Effect,
            None,
            executable_authority,
            trusted_now,
        )
    }

    fn issue_authority(
        &self,
        binding: &PermitBindingV1,
        purpose: PermitPurposeV1,
        delegation_ceiling: Option<DelegationCeilingV1>,
        executable_authority: Vec<ExecutableAuthorityV1>,
        trusted_now: DateTime<Utc>,
    ) -> Result<ExecutionPermitV1, PolicyError> {
        binding.validate()?;
        if let Some(ceiling) = &delegation_ceiling {
            ceiling.validate()?;
        }
        for executable in &executable_authority {
            executable.validate()?;
        }
        if binding.issued_at != trusted_now {
            return Err(PolicyError::InvalidLease(
                "issued_at must come from the trusted clock".into(),
            ));
        }
        let maximum_expiry = trusted_now
            .checked_add_signed(chrono::TimeDelta::milliseconds(MAX_LIVE_LEASE_MILLISECONDS))
            .ok_or_else(|| PolicyError::InvalidLease("lease maximum overflow".into()))?;
        if binding.not_before < trusted_now || binding.expires_at > maximum_expiry {
            return Err(PolicyError::InvalidLease(
                "requested permit validity is outside the trusted policy window".into(),
            ));
        }
        self.with_lock(|| {
            let parent = binding
                .parent_permit_id
                .as_ref()
                .map(|parent_id| {
                    self.read_record(parent_id)
                        .map_err(|_| rejected(parent_id, PermitRejectionReasonV1::WrongParent))
                })
                .transpose()?;
            let delegation_identity = parent
                .as_ref()
                .map(|parent| derive_delegation_identity(&parent.permit, binding))
                .transpose()?;
            let permit_id = derive_permit_id(&execution_identity_material(
                binding,
                purpose,
                &delegation_ceiling,
                &delegation_identity,
                &executable_authority,
            )?)?;
            let permit = ExecutionPermitV1 {
                permit_id,
                binding: binding.clone(),
                purpose,
                delegation_ceiling: delegation_ceiling.clone(),
                delegation_identity,
                executable_authority: executable_authority.clone(),
            };
            PermitEvidenceV1::from_record(&PermitRecordV1 {
                permit: permit.clone(),
                state: PermitStateV1::Issued,
                child_allocations: std::collections::BTreeMap::new(),
            })?;
            let record = PermitRecordV1 {
                permit: permit.clone(),
                state: PermitStateV1::Issued,
                child_allocations: std::collections::BTreeMap::new(),
            };
            let existing_child = match self.read_record(&permit.permit_id) {
                Ok(existing) if existing == record => Some(existing),
                Ok(_) => return Err(PolicyError::PermitStateConflict),
                Err(PolicyError::Io(ref error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    None
                }
                Err(error) => return Err(error),
            };
            if let Some(mut parent) = parent {
                validate_parent_binding(&permit, &parent, trusted_now)?;

                // Treat the parent allocation map as the durable reservation
                // journal. Replacing the same child id is idempotent, so a
                // crash after reserving parent budget but before writing the
                // child record can be retried without double-counting.
                if let Some(previous) = parent
                    .child_allocations
                    .insert(permit.permit_id.clone(), binding.budget.clone())
                {
                    if previous != binding.budget {
                        return Err(PolicyError::PermitStateConflict);
                    }
                }
                let allocated = parent
                    .child_allocations
                    .values()
                    .try_fold(PermitBudgetV1::zero(), |total, budget| {
                        total.checked_add(budget)
                    })?;
                let ceiling = parent.permit.delegation_ceiling.as_ref().ok_or_else(|| {
                    rejected(&permit.permit_id, PermitRejectionReasonV1::WrongParent)
                })?;
                if !allocated.is_within(&ceiling.budget) {
                    return Err(rejected(
                        &permit.permit_id,
                        PermitRejectionReasonV1::BudgetExceeded,
                    ));
                }
                self.replace_record(&parent, None)?;
            }
            if existing_child.is_some() {
                return Ok(permit);
            }
            self.replace_record(&record, None)?;
            Ok(permit)
        })
    }

    pub fn consume(
        &self,
        permit_id: &CurrentPermitId,
        dispatch: &PermitBindingV1,
        trusted_now: DateTime<Utc>,
    ) -> Result<PermitEvidenceV1, PolicyError> {
        let record = self.consume_with_interruption(permit_id, dispatch, trusted_now, None)?;
        PermitEvidenceV1::from_record(&record)
    }

    pub fn consume_with_interruption(
        &self,
        permit_id: &CurrentPermitId,
        dispatch: &PermitBindingV1,
        trusted_now: DateTime<Utc>,
        interrupt_after: Option<PermitTransitionStage>,
    ) -> Result<PermitRecordV1, PolicyError> {
        dispatch.validate()?;
        self.with_lock(|| {
            let mut record = self.read_record_or_reject(permit_id)?;
            validate_dispatch(permit_id, &record, dispatch, trusted_now)?;
            if let Some(parent_id) = &record.permit.binding.parent_permit_id {
                let parent = self
                    .read_record(parent_id)
                    .map_err(|_| rejected(permit_id, PermitRejectionReasonV1::WrongParent))?;
                validate_parent_binding(&record.permit, &parent, trusted_now)?;
            }
            record.state = PermitStateV1::Consumed {
                consumed_at: trusted_now,
            };
            self.replace_record(&record, interrupt_after)?;
            Ok(record)
        })
    }

    pub fn revoke(
        &self,
        permit_id: &CurrentPermitId,
        reason: PermitRevocationReasonV1,
        trusted_now: DateTime<Utc>,
    ) -> Result<PermitRecordV1, PolicyError> {
        self.revoke_with_interruption(permit_id, reason, trusted_now, None)
    }

    pub fn revoke_with_interruption(
        &self,
        permit_id: &CurrentPermitId,
        reason: PermitRevocationReasonV1,
        trusted_now: DateTime<Utc>,
        interrupt_after: Option<PermitTransitionStage>,
    ) -> Result<PermitRecordV1, PolicyError> {
        self.with_lock(|| {
            let mut record = self.read_record_or_reject(permit_id)?;
            if trusted_now < record.permit.binding.issued_at {
                return Err(rejected(permit_id, PermitRejectionReasonV1::NotYetValid));
            }
            match record.state {
                PermitStateV1::Issued => {}
                PermitStateV1::Consumed { .. } => {
                    return Err(rejected(
                        permit_id,
                        PermitRejectionReasonV1::AlreadyConsumed,
                    ));
                }
                PermitStateV1::Revoked { .. } => {
                    return Err(rejected(permit_id, PermitRejectionReasonV1::Revoked));
                }
            }
            record.state = PermitStateV1::Revoked {
                revoked_at: trusted_now,
                reason,
            };
            self.replace_record(&record, interrupt_after)?;
            Ok(record)
        })
    }

    pub fn state(&self, permit_id: &CurrentPermitId) -> Result<PermitRecordV1, PolicyError> {
        self.with_lock(|| self.read_record_or_reject(permit_id))
    }

    pub fn validate_parent_authority(
        &self,
        child_permit_id: &CurrentPermitId,
        trusted_now: DateTime<Utc>,
    ) -> Result<PermitEvidenceV1, PolicyError> {
        self.with_lock(|| {
            let child = self.read_record_or_reject(child_permit_id)?;
            let parent_id = child
                .permit
                .binding
                .parent_permit_id
                .as_ref()
                .ok_or_else(|| rejected(child_permit_id, PermitRejectionReasonV1::WrongParent))?;
            let parent = self
                .read_record(parent_id)
                .map_err(|_| rejected(child_permit_id, PermitRejectionReasonV1::WrongParent))?;
            validate_parent_binding(&child.permit, &parent, trusted_now)?;
            PermitEvidenceV1::from_record(&parent)
        })
    }

    fn with_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, PolicyError>,
    ) -> Result<T, PolicyError> {
        let _thread_guard = self
            .gate
            .lock()
            .map_err(|_| PolicyError::PermitStateConflict)?;
        rustix::fs::flock(self.lock.as_fd(), FlockOperation::LockExclusive)
            .map_err(std::io::Error::from)?;
        let result = operation();
        let unlock = rustix::fs::flock(self.lock.as_fd(), FlockOperation::Unlock);
        match (result, unlock) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(PolicyError::Io(error.into())),
        }
    }

    fn read_record_or_reject(
        &self,
        permit_id: &CurrentPermitId,
    ) -> Result<PermitRecordV1, PolicyError> {
        self.read_record(permit_id).map_err(|error| match error {
            PolicyError::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound => {
                rejected(permit_id, PermitRejectionReasonV1::NotIssued)
            }
            other => other,
        })
    }

    fn read_record(&self, permit_id: &CurrentPermitId) -> Result<PermitRecordV1, PolicyError> {
        let name = state_name(permit_id)?;
        let fd = secure_open_at(
            &self.root,
            &name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?;
        let file = File::from(fd);
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_PERMIT_RECORD_BYTES {
            return Err(rejected(permit_id, PermitRejectionReasonV1::StateCorrupted));
        }
        let mut bytes = Vec::new();
        file.take(MAX_PERMIT_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_PERMIT_RECORD_BYTES {
            return Err(rejected(permit_id, PermitRejectionReasonV1::StateCorrupted));
        }
        let record: PermitRecordV1 = serde_json::from_slice(&bytes)?;
        if record.permit.permit_id != *permit_id
            || derive_permit_id(&record.permit.identity_material()?)? != *permit_id
        {
            return Err(rejected(permit_id, PermitRejectionReasonV1::StateCorrupted));
        }
        Ok(record)
    }

    fn replace_record(
        &self,
        record: &PermitRecordV1,
        interrupt_after: Option<PermitTransitionStage>,
    ) -> Result<(), PolicyError> {
        let (temp_name, mut file) = create_unique_temp(&self.root, ".permit.tmp")?;
        file.write_all(&jcs_canonical(record)?)?;
        if interrupt_after == Some(PermitTransitionStage::TempWrite) {
            return Err(PolicyError::InjectedInterruption(
                PermitTransitionStage::TempWrite,
            ));
        }
        file.sync_all()?;
        if interrupt_after == Some(PermitTransitionStage::TempFsync) {
            return Err(PolicyError::InjectedInterruption(
                PermitTransitionStage::TempFsync,
            ));
        }
        rustix::fs::renameat(
            self.root.as_fd(),
            &temp_name,
            self.root.as_fd(),
            state_name(&record.permit.permit_id)?,
        )
        .map_err(std::io::Error::from)?;
        if interrupt_after == Some(PermitTransitionStage::Rename) {
            return Err(PolicyError::InjectedInterruption(
                PermitTransitionStage::Rename,
            ));
        }
        self.root.sync_all()?;
        if interrupt_after == Some(PermitTransitionStage::DirectoryFsync) {
            return Err(PolicyError::InjectedInterruption(
                PermitTransitionStage::DirectoryFsync,
            ));
        }
        Ok(())
    }

    pub fn run_root_identity(&self) -> (u64, u64) {
        (self.run_root_device, self.run_root_inode)
    }

    pub fn permit_root_identity(&self) -> (u64, u64) {
        (self.permit_root_device, self.permit_root_inode)
    }
}

fn open_permit_child(run_root: &File) -> Result<File, PolicyError> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match secure_open_at(run_root, "permits", flags, Mode::empty()) {
        Ok(fd) => Ok(File::from(fd)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match rustix::fs::mkdirat(
                run_root.as_fd(),
                "permits",
                Mode::RUSR | Mode::WUSR | Mode::XUSR,
            ) {
                Ok(()) => {}
                Err(error)
                    if std::io::Error::from(error).kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
            Ok(File::from(secure_open_at(
                run_root,
                "permits",
                flags,
                Mode::empty(),
            )?))
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn directory_identity(directory: &File) -> Result<(u64, u64, u32), PolicyError> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.mode() & 0o022 != 0 {
        return Err(PolicyError::UnsafePermitRoot(
            "permit directory must be a non-group/world-writable directory".into(),
        ));
    }
    Ok((metadata.dev(), metadata.ino(), metadata.uid()))
}

fn validate_dispatch(
    permit_id: &CurrentPermitId,
    record: &PermitRecordV1,
    dispatch: &PermitBindingV1,
    now: DateTime<Utc>,
) -> Result<(), PolicyError> {
    match record.state {
        PermitStateV1::Consumed { .. } => {
            return Err(rejected(
                permit_id,
                PermitRejectionReasonV1::AlreadyConsumed,
            ));
        }
        PermitStateV1::Revoked { .. } => {
            return Err(rejected(permit_id, PermitRejectionReasonV1::Revoked));
        }
        PermitStateV1::Issued => {}
    }
    let authorized = &record.permit.binding;
    if now < authorized.not_before {
        return Err(rejected(permit_id, PermitRejectionReasonV1::NotYetValid));
    }
    if now >= authorized.expires_at {
        return Err(rejected(permit_id, PermitRejectionReasonV1::Expired));
    }
    macro_rules! same {
        ($field:ident, $reason:ident) => {
            if dispatch.$field != authorized.$field {
                return Err(rejected(permit_id, PermitRejectionReasonV1::$reason));
            }
        };
    }
    same!(actor, WrongActor);
    same!(action_digest, WrongAction);
    if dispatch.effect != authorized.effect || dispatch.effect_digest != authorized.effect_digest {
        return Err(rejected(permit_id, PermitRejectionReasonV1::ChangedEffect));
    }
    if !dispatch.budget.is_within(&authorized.budget) {
        return Err(rejected(permit_id, PermitRejectionReasonV1::BudgetExceeded));
    }
    same!(parent_permit_id, WrongParent);
    same!(parent_operation_id, WrongParent);
    same!(policy_version, WrongPolicy);
    same!(run_id, WrongOperation);
    same!(step_id, WrongStep);
    same!(tool, WrongTool);
    same!(args_digest, WrongArguments);
    if dispatch.issued_at != authorized.issued_at
        || dispatch.not_before != authorized.not_before
        || dispatch.expires_at != authorized.expires_at
    {
        return Err(rejected(permit_id, PermitRejectionReasonV1::WrongAction));
    }
    Ok(())
}

fn derive_delegation_identity(
    parent: &ExecutionPermitV1,
    child_binding: &PermitBindingV1,
) -> Result<DelegationIdentityV1, PolicyError> {
    let parent_depth = parent
        .delegation_identity
        .as_ref()
        .map_or(0, |identity| identity.depth);
    let identity = DelegationIdentityV1 {
        actor: parent.binding.actor.clone(),
        delegate: child_binding.actor.clone(),
        audience: child_binding.tool.clone(),
        depth: parent_depth
            .checked_add(1)
            .ok_or_else(|| PolicyError::InvalidLease("delegation depth overflow".into()))?,
    };
    identity.validate()?;
    Ok(identity)
}

fn validate_parent_binding(
    child: &ExecutionPermitV1,
    parent: &PermitRecordV1,
    now: DateTime<Utc>,
) -> Result<(), PolicyError> {
    validate_parent_permits(
        child,
        &parent.permit,
        matches!(parent.state, PermitStateV1::Issued),
        now,
    )
}

fn validate_parent_permits(
    child: &ExecutionPermitV1,
    parent: &ExecutionPermitV1,
    parent_is_active: bool,
    now: DateTime<Utc>,
) -> Result<(), PolicyError> {
    let child_id = &child.permit_id;
    let child_binding = &child.binding;
    let parent_binding = &parent.binding;
    let ceiling = parent
        .delegation_ceiling
        .as_ref()
        .ok_or_else(|| rejected(child_id, PermitRejectionReasonV1::WrongParent))?;
    let roots_subset = |child_roots: &[String], parent_roots: &[String]| {
        child_roots.iter().all(|root| parent_roots.contains(root))
    };
    let expected_identity = derive_delegation_identity(parent, child_binding)?;
    if !parent_is_active
        || parent.purpose != PermitPurposeV1::Control
        || child.delegation_identity.as_ref() != Some(&expected_identity)
        || now < parent_binding.not_before
        || now >= parent_binding.expires_at
        || now < ceiling.not_before
        || now >= ceiling.expires_at
        || child_binding.parent_permit_id.as_ref() != Some(&parent.permit_id)
        || child_binding.parent_operation_id.as_ref() != Some(&parent_binding.run_id)
        || child_binding.run_id != parent_binding.run_id
        || child_binding.run_id != ceiling.run_id
        || child_binding.actor != parent_binding.actor
        || child_binding.actor != ceiling.actor
        || child_binding.policy_version != parent_binding.policy_version
        || child_binding.policy_version != ceiling.policy_version
        || child_binding.not_before < parent_binding.not_before
        || child_binding.not_before < ceiling.not_before
        || child_binding.expires_at > parent_binding.expires_at
        || child_binding.expires_at > ceiling.expires_at
        || !child_binding.budget.is_within(&ceiling.budget)
    {
        return Err(rejected(child_id, PermitRejectionReasonV1::WrongParent));
    }
    match child.purpose {
        PermitPurposeV1::Effect => {
            let action = ceiling.actions.iter().find(|action| {
                action.tool == child_binding.tool
                    && action.action_digest == child_binding.action_digest
                    && action.args_digest == child_binding.args_digest
            });
            let Some(action) = action else {
                return Err(rejected(child_id, PermitRejectionReasonV1::WrongAction));
            };
            if !matches!(ceiling.transition, DelegationTransitionV1::ControlToEffect)
                || child.delegation_ceiling.is_some()
                || !ceiling.audiences.contains(&child_binding.tool)
                || child_binding.effect.scope_name != action.effect.scope_name
                || child_binding.effect.network_allowed != action.effect.network_allowed
                || !roots_subset(&child_binding.effect.read_roots, &action.effect.read_roots)
                || !roots_subset(
                    &child_binding.effect.write_roots,
                    &action.effect.write_roots,
                )
                || child_binding.effect_digest != content_digest(&child_binding.effect)?
                || child.executable_authority != action.executable_authority
            {
                return Err(rejected(child_id, PermitRejectionReasonV1::WrongParent));
            }
        }
        PermitPurposeV1::Control => {
            let child_ceiling = child
                .delegation_ceiling
                .as_ref()
                .ok_or_else(|| rejected(child_id, PermitRejectionReasonV1::WrongParent))?;
            child_ceiling.validate()?;
            let actions_within_parent = child_ceiling.actions.iter().all(|child_action| {
                ceiling.actions.iter().any(|parent_action| {
                    child_action.tool == parent_action.tool
                        && child_action.action_digest == parent_action.action_digest
                        && child_action.args_digest == parent_action.args_digest
                        && child_action.effect == parent_action.effect
                        && child_action.effect_digest == parent_action.effect_digest
                        && child_action.executable_authority == parent_action.executable_authority
                })
            });
            let audiences_within_parent = child_ceiling.audiences.iter().all(|child_audience| {
                ceiling
                    .actions
                    .iter()
                    .any(|parent_action| parent_action.tool == *child_audience)
            });
            let strict_subset = child_ceiling.actions.len() < ceiling.actions.len()
                || child_ceiling.budget != ceiling.budget
                || child_ceiling.not_before > ceiling.not_before
                || child_ceiling.expires_at < ceiling.expires_at;
            if !matches!(ceiling.transition, DelegationTransitionV1::ControlToControl)
                || !ceiling.audiences.contains(&child_binding.tool)
                || child_ceiling.actor != child_binding.actor
                || child_ceiling.policy_version != child_binding.policy_version
                || child_ceiling.run_id != child_binding.run_id
                || child_ceiling.not_before < ceiling.not_before
                || child_ceiling.expires_at > ceiling.expires_at
                || !child_ceiling.budget.is_within(&ceiling.budget)
                || !actions_within_parent
                || !audiences_within_parent
                || !strict_subset
            {
                return Err(rejected(child_id, PermitRejectionReasonV1::WrongParent));
            }
        }
    }
    Ok(())
}

pub fn validate_delegation_evidence(
    parent: &PermitEvidenceV1,
    child: &PermitEvidenceV1,
    at: DateTime<Utc>,
) -> Result<(), PolicyError> {
    parent.validate()?;
    child.validate()?;
    let parent_permit = ExecutionPermitV1 {
        permit_id: parent.permit_id.clone(),
        binding: parent.binding.clone(),
        purpose: parent.purpose,
        delegation_ceiling: parent.delegation_ceiling.clone(),
        delegation_identity: parent.delegation_identity.clone(),
        executable_authority: parent.executable_authority.clone(),
    };
    let child_permit = ExecutionPermitV1 {
        permit_id: child.permit_id.clone(),
        binding: child.binding.clone(),
        purpose: child.purpose,
        delegation_ceiling: child.delegation_ceiling.clone(),
        delegation_identity: child.delegation_identity.clone(),
        executable_authority: child.executable_authority.clone(),
    };
    validate_parent_permits(
        &child_permit,
        &parent_permit,
        matches!(parent.state, PermitEvidenceStateV1::Issued),
        at,
    )
}

/// Validate one persisted attenuation edge without creating a second authority store.
/// The durable `DurablePermitStore::issue_effect` path derives and records the
/// proof under its lock, so callers cannot supply an alternate identity or depth.
pub fn validate_delegation_attenuation(
    parent: &PermitEvidenceV1,
    child: &PermitEvidenceV1,
    at: DateTime<Utc>,
) -> Result<(), PolicyError> {
    validate_delegation_evidence(parent, child, at)
}

fn rejected(permit_id: &CurrentPermitId, reason: PermitRejectionReasonV1) -> PolicyError {
    PolicyError::PermitRejected {
        permit_id: permit_id.clone(),
        reason,
    }
}

fn state_name(permit_id: &CurrentPermitId) -> Result<String, PolicyError> {
    Ok(format!("permit-{}.json", content_digest(permit_id)?.hex()))
}

fn create_unique_temp(root: &File, prefix: &str) -> Result<(String, File), PolicyError> {
    for _ in 0..1024 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!("{prefix}.{}.{}", std::process::id(), sequence);
        match secure_open_at(
            root,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => return Ok((name, File::from(fd))),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(PolicyError::PermitStateConflict)
}

#[cfg(target_os = "linux")]
fn secure_open_at(
    directory: &File,
    name: &str,
    flags: OFlags,
    mode: Mode,
) -> std::io::Result<std::os::fd::OwnedFd> {
    Ok(rustix::fs::openat2(
        directory.as_fd(),
        name,
        flags,
        mode,
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?)
}

#[cfg(not(target_os = "linux"))]
fn secure_open_at(
    directory: &File,
    name: &str,
    flags: OFlags,
    mode: Mode,
) -> std::io::Result<std::os::fd::OwnedFd> {
    if name.contains('/') || name == "." || name == ".." {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "permit file name is not a single component",
        ));
    }
    Ok(rustix::fs::openat(
        directory.as_fd(),
        name,
        flags | OFlags::NOFOLLOW,
        mode,
    )?)
}

#[derive(Debug, Clone)]
pub struct Allowlist {
    pub allowed: BTreeSet<String>,
    pub max_arg_bytes: usize,
    pub policy_version: String,
}

impl Default for Allowlist {
    fn default() -> Self {
        Self {
            allowed: BTreeSet::from(["echo".into(), "time_now".into(), "shell".into()]),
            max_arg_bytes: 16 * 1024,
            policy_version: "m0-2".into(),
        }
    }
}

impl Allowlist {
    pub fn version(&self) -> &str {
        &self.policy_version
    }

    pub fn validate_policy_version(&self, submitted: &str) -> Result<(), PolicyError> {
        if submitted != self.policy_version {
            return Err(PolicyError::PolicyVersionMismatch {
                submitted: submitted.into(),
                active: self.policy_version.clone(),
            });
        }
        Ok(())
    }

    pub fn validate_phase_one_boundary(&self, spec: &RunSpecV1) -> Result<(), PolicyError> {
        self.validate_policy_version(&spec.policy_version)?;
        if spec.steps.iter().any(|step| {
            step.call
                .args
                .get("allow_network")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
        }) {
            return Err(PolicyError::NetworkUnavailable);
        }
        Ok(())
    }

    pub fn authorize(
        &self,
        spec: &RunSpecV1,
        step_name: &str,
        call: &ToolCallSpecV1,
    ) -> Result<(), PolicyError> {
        self.validate_policy_version(&spec.policy_version)?;
        if !self.allowed.contains(&call.tool) {
            return Err(PolicyError::ToolNotAllowed(call.tool.clone()));
        }
        let arg_bytes = serde_json::to_vec(&call.args)
            .map_err(|error| ContractError::Malformed(format!("args: {error}")))?;
        if arg_bytes.len() > self.max_arg_bytes {
            return Err(PolicyError::ArgsTooLarge(
                arg_bytes.len(),
                self.max_arg_bytes,
            ));
        }
        if call.tool == "time_now" && call.frozen_clock.is_none() && spec.frozen_clock.is_none() {
            return Err(PolicyError::FrozenClockRequired(call.tool.clone()));
        }
        if call
            .args
            .get("allow_network")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            return Err(PolicyError::NetworkUnavailable);
        }
        let _ = step_name;
        Ok(())
    }
}

pub fn build_lineage(
    permit_id: &CurrentPermitId,
    policy_version: &str,
) -> Vec<AuthorityLineageEntryV1> {
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
            permit_id: Some(permit_id.clone()),
            policy_version: policy_version.to_string(),
        },
        AuthorityLineageEntryV1 {
            origin: LineageOrigin::Tool,
            principal: principal.clone(),
            permit_id: Some(permit_id.clone()),
            policy_version: policy_version.to_string(),
        },
        AuthorityLineageEntryV1 {
            origin: LineageOrigin::Effect,
            principal,
            permit_id: Some(permit_id.clone()),
            policy_version: policy_version.to_string(),
        },
    ]
}

pub fn assert_lineage_for_receipt(receipt: &ReceiptV1) -> Result<(), PolicyError> {
    receipt.validate_material().map_err(PolicyError::Contract)
}
