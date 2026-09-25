//! Scoped external-effect authority, owned by the existing permit store.
//!
//! The operator enrolls a controller for one store/profile/root. Controller
//! signatures bind context and transitions; they never approve an effect.
//! Every mutation is one bounded, fsynced replacement under `.permit.lock`.
//! Legacy permit bytes stay unchanged and cannot bypass an enrolled namespace.

use super::*;
use serde::{Deserialize, Serialize};

const STATE_FILE: &str = "context-authority-v1.json";
const MAX_STATE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_PERMITS: usize = 1024;
const MAX_TRANSITIONS: usize = 4096;
const MAX_SCOPES: usize = 256;

fn denied(message: &str) -> PolicyError {
    PolicyError::InvalidLease(format!("context authority: {message}"))
}

fn identifier(value: &str) -> Result<(), PolicyError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(denied("invalid identifier"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextAuthoritySchemaV1 {
    #[serde(rename = "recursive-agent.context-authority/v1")]
    V1,
}

/// Stable identity explicitly approved in the operator's startup enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextScopeV1 {
    pub store: ContentDigest,
    pub profile: String,
    pub root: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextAdmissionModeV1 {
    Sealed,
    Active,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextHeadV1 {
    pub context: String,
    pub generation: u64,
    pub mode: ContextAdmissionModeV1,
}

impl ContextHeadV1 {
    fn validate(&self) -> Result<(), PolicyError> {
        identifier(&self.context)?;
        if self.generation == 0 || self.generation > i64::MAX as u64 {
            return Err(denied("invalid generation"));
        }
        Ok(())
    }
}

/// Closed, operator-owned grant. Not an IPC enrollment request. Supersession
/// retains all prior charges and outstanding effects; caps cannot increase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextScopeGrantV1 {
    pub scope: ContextScopeV1,
    pub controller_public_key: [u8; 32],
    pub actor: ActorPrincipalV1,
    pub policy_version: String,
    pub policy_digest: ContentDigest,
    pub write_root: String,
    pub initial_head: ContextHeadV1,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_effects: u64,
    pub max_transitions: u64,
    pub previous_grant: Option<ContentDigest>,
}

impl ContextScopeGrantV1 {
    fn validate(&self) -> Result<(), PolicyError> {
        identifier(&self.scope.profile)?;
        identifier(&self.scope.root)?;
        identifier(&self.policy_version)?;
        self.initial_head.validate()?;
        ed25519_dalek::VerifyingKey::from_bytes(&self.controller_public_key)
            .map_err(|_| denied("invalid controller public key"))?;
        let root = Path::new(&self.write_root);
        if self.not_before >= self.expires_at
            || self.max_effects == 0
            || self.max_effects > MAX_PERMITS as u64
            || self.max_transitions == 0
            || self.max_transitions > MAX_TRANSITIONS as u64
            || !root.is_absolute()
            || root == Path::new("/")
            || root
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(denied("invalid grant bounds"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextAuthorityConfigurationV1 {
    pub schema: ContextAuthoritySchemaV1,
    pub incarnation: ContentDigest,
    pub revision: u64,
    pub approval_verifier: ContentDigest,
    pub grants: Vec<ContextScopeGrantV1>,
}

/// Non-serializable startup capability. A stale daemon cannot use a newer
/// configuration or restore its old configuration after another daemon starts.
#[derive(Clone)]
pub struct ContextAuthorityAccess {
    incarnation: ContentDigest,
    configuration_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextAuthorityBindingV1 {
    pub incarnation: ContentDigest,
    pub scope: ContextScopeV1,
    pub grant_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub head: ContextHeadV1,
}

/// Controller signature domain is distinct from transition and effect approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextCallBindingV1 {
    pub authority: ContextAuthorityBindingV1,
    pub witness_digest: ContentDigest,
    pub signature: Vec<u8>,
}

impl ContextCallBindingV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, PolicyError> {
        Ok(jcs_canonical(&(
            "recursive-agent.context-call/v1",
            &self.authority,
            &self.witness_digest,
        ))?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContextTransitionActionV1 {
    /// Retires the current generation and reserves the exact successor sealed.
    /// Also used to return to a parent after a prepublication failure, always
    /// at a higher generation; no retired token is reopened.
    Retire { successor_context: String },
    /// Exact sealed successor becomes active. No generation increment.
    Activate { retirement_digest: ContentDigest },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextTransitionRequestV1 {
    pub authority: ContextAuthorityBindingV1,
    pub transition: ContentDigest,
    pub action: ContextTransitionActionV1,
    pub signature: Vec<u8>,
}

impl ContextTransitionRequestV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, PolicyError> {
        Ok(jcs_canonical(&(
            "recursive-agent.context-transition/v1",
            &self.authority,
            &self.transition,
            &self.action,
        ))?)
    }
}

/// Pure typed bytes from the canonical boundary owner. No authority is minted.
pub fn prepare_context_call(
    authority: &ContextAuthorityBindingV1,
    witness: &ProductionApprovalWitnessV1,
) -> Result<ContextCallBindingV1, PolicyError> {
    authority.head.validate()?;
    Ok(ContextCallBindingV1 {
        authority: authority.clone(),
        witness_digest: content_digest(witness)?,
        signature: Vec::new(),
    })
}

pub fn prepare_context_transition(
    authority: &ContextAuthorityBindingV1,
    transition_ref: &str,
    action: &ContextTransitionActionV1,
) -> Result<ContextTransitionRequestV1, PolicyError> {
    identifier(transition_ref)?;
    authority.head.validate()?;
    Ok(ContextTransitionRequestV1 {
        authority: authority.clone(),
        transition: content_digest(&(
            "recursive-agent.context-transition-ref/v1",
            &authority.incarnation,
            &authority.scope,
            transition_ref,
        ))?,
        action: action.clone(),
        signature: Vec::new(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedExecutionPermitV1 {
    pub permit_id: CurrentPermitId,
    pub effect: ExecutionPermitV1,
    pub approval_verifier: ContentDigest,
    pub context: ContextCallBindingV1,
}

impl ScopedExecutionPermitV1 {
    fn derive_id(
        effect: &ExecutionPermitV1,
        context: &ContextCallBindingV1,
        approval_verifier: &ContentDigest,
    ) -> Result<CurrentPermitId, PolicyError> {
        let mut material = effect.binding.identity_material()?;
        material.binding_digest = content_digest(&(
            "recursive-agent.scoped-external-permit/v1",
            effect,
            context,
            approval_verifier,
        ))?;
        Ok(derive_permit_id(&material)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedPermitPreflightV1 {
    pub permit: ScopedExecutionPermitV1,
    pub recorded_at: DateTime<Utc>,
    pub receipt_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedPermitRecordV1 {
    pub permit: ScopedExecutionPermitV1,
    pub preflight: Option<ScopedPermitPreflightV1>,
    pub outcome: Option<PermitOutcomeReceiptV1>,
}

/// Bounded receipt reference. Full historical evidence is fetched by exact
/// permit readback; transition responses stay below the existing IPC frame cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedEffectObligationV1 {
    pub permit_id: CurrentPermitId,
    pub preflight_receipt_digest: ContentDigest,
    pub outcome_receipt_digest: Option<ContentDigest>,
    pub reported_state: Option<ReportedEffectStateV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextTransitionReceiptV1 {
    pub request: ContextTransitionRequestV1,
    pub successor: ContextHeadV1,
    /// Exact consumed obligations at retirement/activation. A reported result
    /// is not external confirmation; entries are never silently dropped.
    pub consumed: Vec<ScopedEffectObligationV1>,
    pub recorded_at: DateTime<Utc>,
    pub receipt_digest: ContentDigest,
}

/// Observation only. It is neither a controller capability nor effect approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextAuthoritySnapshotV1 {
    pub authority: ContextAuthorityBindingV1,
    pub grant: ContextScopeGrantV1,
    pub approval_verifier: ContentDigest,
    pub configuration_revision: u64,
    pub enrolled: bool,
    pub effects_charged: u64,
    pub transitions_charged: u64,
    pub consumed: Vec<ScopedEffectObligationV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeState {
    grant: ContextScopeGrantV1,
    head: ContextHeadV1,
    active: bool,
    effects: u64,
    transitions: u64,
    retirement_digest: Option<ContentDigest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "event",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum AuthorityEvent {
    Enrollment(ContextAuthorityConfigurationV1),
    Transition(ContentDigest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityState {
    journal: Vec<AuthorityEvent>,
    schema: ContextAuthoritySchemaV1,
    incarnation: ContentDigest,
    root_identity: (u64, u64),
    configuration: Option<ContextAuthorityConfigurationV1>,
    scopes: BTreeMap<ContentDigest, ScopeState>,
    permits: BTreeMap<CurrentPermitId, ScopedPermitRecordV1>,
    /// Immutable reservation across scope, generation, policy and key changes.
    approvals: BTreeMap<CurrentPermitId, CurrentPermitId>,
    receipts: BTreeMap<ContentDigest, ContextTransitionReceiptV1>,
}

fn approval_verifier_digest(
    verifier: &ProductionApprovalVerifierV1,
) -> Result<ContentDigest, PolicyError> {
    Ok(content_digest(&(
        "recursive-agent.production-verifier/v1",
        &verifier.key_id,
        verifier.public_key.to_bytes(),
        &verifier.target_root,
    ))?)
}

impl ProductionApprovalVerifierV1 {
    /// Public enrollment provenance, never private signing material.
    pub fn context_authority_digest(&self) -> Result<ContentDigest, PolicyError> {
        approval_verifier_digest(self)
    }
}

fn verify(key: &[u8; 32], bytes: &[u8], signature: &[u8]) -> Result<(), PolicyError> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(key)
        .map_err(|_| denied("invalid controller key"))?;
    let signature = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|_| denied("invalid controller signature"))?;
    key.verify_strict(bytes, &signature)
        .map_err(|_| denied("controller signature rejected"))
}

impl AuthorityState {
    fn access(&self, access: &ContextAuthorityAccess) -> Result<(), PolicyError> {
        let configuration = self
            .configuration
            .as_ref()
            .ok_or_else(|| denied("not enrolled"))?;
        if self.incarnation != access.incarnation
            || content_digest(configuration)? != access.configuration_digest
        {
            return Err(denied("stale configuration or incarnation"));
        }
        Ok(())
    }

    fn current(
        &self,
        binding: &ContextAuthorityBindingV1,
        now: DateTime<Utc>,
    ) -> Result<&ScopeState, PolicyError> {
        binding.head.validate()?;
        let scope = self
            .scopes
            .get(&content_digest(&binding.scope)?)
            .ok_or_else(|| denied("scope not enrolled"))?;
        if self.incarnation != binding.incarnation
            || !scope.active
            || scope.grant.scope != binding.scope
            || content_digest(&scope.grant)? != binding.grant_digest
            || scope.grant.policy_digest != binding.policy_digest
            || scope.head != binding.head
            || now < scope.grant.not_before
            || now >= scope.grant.expires_at
        {
            return Err(denied("scope, policy, generation or validity changed"));
        }
        Ok(scope)
    }

    fn consumed(&self, scope: &ContextScopeV1) -> Vec<ScopedEffectObligationV1> {
        self.permits
            .values()
            .filter_map(|record| {
                if record.permit.context.authority.scope != *scope {
                    return None;
                }
                record
                    .preflight
                    .as_ref()
                    .map(|preflight| ScopedEffectObligationV1 {
                        permit_id: record.permit.permit_id.clone(),
                        preflight_receipt_digest: preflight.receipt_digest.clone(),
                        outcome_receipt_digest: record
                            .outcome
                            .as_ref()
                            .map(|outcome| outcome.receipt_digest.clone()),
                        reported_state: record
                            .outcome
                            .as_ref()
                            .map(|outcome| outcome.reported.state),
                    })
            })
            .collect()
    }
}

fn apply_configuration(
    state: &mut AuthorityState,
    configuration: &ContextAuthorityConfigurationV1,
) -> Result<(), PolicyError> {
    if configuration.incarnation != state.incarnation
        || configuration.revision == 0
        || configuration.grants.len() > MAX_SCOPES
        || state
            .configuration
            .as_ref()
            .is_some_and(|old| configuration.revision <= old.revision)
    {
        return Err(denied("configuration identity or revision rejected"));
    }
    let mut admitted = BTreeSet::new();
    for grant in &configuration.grants {
        grant.validate()?;
        let key = content_digest(&grant.scope)?;
        if !admitted.insert(key.clone()) {
            return Err(denied("duplicate scope"));
        }
        if let Some(previous) = state.scopes.get_mut(&key) {
            if previous.grant != *grant {
                if grant.previous_grant != Some(content_digest(&previous.grant)?)
                    || grant.initial_head != previous.head
                    || grant.max_effects > previous.grant.max_effects
                    || grant.max_transitions > previous.grant.max_transitions
                    || grant.write_root != previous.grant.write_root
                    || grant.actor != previous.grant.actor
                {
                    return Err(denied("grant supersession would reset or widen authority"));
                }
                previous.grant = grant.clone();
            } else if !previous.active {
                return Err(denied("revoked grant requires explicit supersession"));
            }
            previous.active = true;
        } else {
            if grant.previous_grant.is_some() || state.scopes.len() >= MAX_SCOPES {
                return Err(denied("unknown predecessor or exhausted scope inventory"));
            }
            state.scopes.insert(
                key,
                ScopeState {
                    grant: grant.clone(),
                    head: grant.initial_head.clone(),
                    active: true,
                    effects: 0,
                    transitions: 0,
                    retirement_digest: None,
                },
            );
        }
    }
    for (key, scope) in &mut state.scopes {
        if !admitted.contains(key) {
            scope.active = false;
        }
    }
    state.configuration = Some(configuration.clone());
    Ok(())
}

impl DurablePermitStore {
    pub fn read_context_authority(
        &self,
        incarnation: &ContentDigest,
        scope: &ContextScopeV1,
    ) -> Result<ContextAuthoritySnapshotV1, PolicyError> {
        self.with_lock(|| {
            let state = self.context_state()?;
            if state.incarnation != *incarnation {
                return Err(denied("incarnation changed"));
            }
            let current = state
                .scopes
                .get(&content_digest(scope)?)
                .ok_or_else(|| denied("scope absent"))?;
            let configuration = state
                .configuration
                .as_ref()
                .ok_or_else(|| denied("not enrolled"))?;
            Ok(ContextAuthoritySnapshotV1 {
                grant: current.grant.clone(),
                approval_verifier: configuration.approval_verifier.clone(),
                authority: ContextAuthorityBindingV1 {
                    incarnation: incarnation.clone(),
                    scope: scope.clone(),
                    grant_digest: content_digest(&current.grant)?,
                    policy_digest: current.grant.policy_digest.clone(),
                    head: current.head.clone(),
                },
                configuration_revision: configuration.revision,
                enrolled: current.active,
                effects_charged: current.effects,
                transitions_charged: current.transitions,
                consumed: state.consumed(scope),
            })
        })
    }

    pub fn read_context_transition(
        &self,
        request: &ContextTransitionRequestV1,
    ) -> Result<Option<ContextTransitionReceiptV1>, PolicyError> {
        self.with_lock(|| {
            let state = self.context_state()?;
            if state.incarnation != request.authority.incarnation {
                return Err(denied("incarnation changed"));
            }
            let Some(receipt) = state.receipts.get(&request.transition) else {
                return Ok(None);
            };
            if receipt.request != *request {
                return Err(denied("transition readback identity changed"));
            }
            Ok(Some(receipt.clone()))
        })
    }

    /// Explicit operator action. Initialization permanently fences the legacy
    /// namespace, even when later startup omits enrollment. OS randomness is a
    /// nonce; the material identity is derived by the stack-ids digest owner.
    pub fn initialize_context_authority(&self) -> Result<ContentDigest, PolicyError> {
        self.with_lock(|| {
            if let Some(existing) = self.read_context_state()? {
                return Ok(existing.incarnation);
            }
            self.assert_no_legacy_consumption()?;
            let mut nonce = [0_u8; 32];
            File::open("/dev/urandom")?.read_exact(&mut nonce)?;
            let incarnation = content_digest(&(
                "recursive-agent.context-incarnation/v1",
                nonce,
                self.permit_root_identity(),
            ))?;
            let state = AuthorityState {
                schema: ContextAuthoritySchemaV1::V1,
                incarnation: incarnation.clone(),
                root_identity: self.permit_root_identity(),
                configuration: None,
                journal: Vec::new(),
                scopes: BTreeMap::new(),
                permits: BTreeMap::new(),
                approvals: BTreeMap::new(),
                receipts: BTreeMap::new(),
            };
            self.replace_context_state(&state, None)?;
            Ok(incarnation)
        })
    }

    /// Trusted startup only. No IPC route accepts a grant or replaces a key.
    pub fn enroll_context_authority(
        &self,
        configuration: &ContextAuthorityConfigurationV1,
    ) -> Result<ContextAuthorityAccess, PolicyError> {
        self.with_lock(|| {
            let mut state = self.context_state()?;
            if configuration.incarnation != state.incarnation
                || configuration.revision == 0
                || configuration.grants.len() > MAX_SCOPES
            {
                return Err(denied("configuration identity or bounds rejected"));
            }
            let digest = content_digest(configuration)?;
            let access = ContextAuthorityAccess {
                incarnation: state.incarnation.clone(),
                configuration_digest: digest.clone(),
            };
            if let Some(existing) = &state.configuration {
                if content_digest(existing)? == digest {
                    return Ok(access);
                }
                if configuration.revision <= existing.revision {
                    return Err(denied("configuration rollback"));
                }
            }
            apply_configuration(&mut state, configuration)?;
            state
                .journal
                .push(AuthorityEvent::Enrollment(configuration.clone()));
            self.replace_context_state(&state, None)?;
            Ok(access)
        })
    }

    pub fn issue_scoped_external_permit(
        &self,
        access: &ContextAuthorityAccess,
        verifier: &ProductionApprovalVerifierV1,
        witness: &ProductionApprovalWitnessV1,
        context: &ContextCallBindingV1,
        clock: impl Fn() -> DateTime<Utc>,
    ) -> Result<ScopedExecutionPermitV1, PolicyError> {
        self.with_lock(|| {
            let mut state = self.context_state()?;
            state.access(access)?;
            if state.configuration.as_ref().map(|c| &c.approval_verifier)
                != Some(&approval_verifier_digest(verifier)?)
            {
                return Err(denied("approval verifier differs from current enrollment"));
            }
            let now = clock();
            let scope = state.current(&context.authority, now)?;
            verify(
                &scope.grant.controller_public_key,
                &context.signing_bytes()?,
                &context.signature,
            )?;
            if context.witness_digest != content_digest(witness)?
                || scope.head.mode != ContextAdmissionModeV1::Active
            {
                return Err(denied("call binding or admission mode rejected"));
            }
            let binding = verifier.verify_and_build_binding(witness, now)?;
            if binding.actor != scope.grant.actor
                || binding.policy_version != scope.grant.policy_version
                || binding.effect.write_roots != vec![scope.grant.write_root.clone()]
                || binding.expires_at > scope.grant.expires_at
            {
                return Err(denied("effect outside enrolled scope"));
            }
            let effect = ExecutionPermitV1::effect(binding, Vec::new())?;
            let approval_verifier = approval_verifier_digest(verifier)?;
            let permit = ScopedExecutionPermitV1 {
                permit_id: ScopedExecutionPermitV1::derive_id(
                    &effect,
                    context,
                    &approval_verifier,
                )?,
                effect,
                approval_verifier,
                context: context.clone(),
            };
            if let Some(reserved) = state.approvals.get(&permit.effect.permit_id) {
                let record = state
                    .permits
                    .get(reserved)
                    .ok_or_else(|| denied("approval reservation corrupted"))?;
                return if record.permit == permit {
                    Ok(record.permit.clone())
                } else {
                    Err(denied("effect approval already bound"))
                };
            }
            // An approval used by V1 before enrollment stays spent. Neither a
            // legacy issued record nor a missing ACK authorizes a V2 wrapper.
            match self.read_record(&permit.effect.permit_id) {
                Ok(_) => return Err(denied("effect approval already used by legacy namespace")),
                Err(PolicyError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            if scope.effects >= scope.grant.max_effects || state.permits.len() >= MAX_PERMITS {
                return Err(denied("effect budget exhausted"));
            }
            let final_now = clock();
            if final_now < now {
                return Err(denied("clock regressed"));
            }
            state.current(&context.authority, final_now)?;
            verifier.verify_and_build_binding(witness, final_now)?;
            state
                .scopes
                .get_mut(&content_digest(&context.authority.scope)?)
                .ok_or_else(|| denied("scope absent"))?
                .effects += 1;
            state
                .approvals
                .insert(permit.effect.permit_id.clone(), permit.permit_id.clone());
            state.permits.insert(
                permit.permit_id.clone(),
                ScopedPermitRecordV1 {
                    permit: permit.clone(),
                    preflight: None,
                    outcome: None,
                },
            );
            self.replace_context_state(&state, None)?;
            Ok(permit)
        })
    }

    pub fn consume_scoped_external_permit(
        &self,
        access: &ContextAuthorityAccess,
        verifier: &ProductionApprovalVerifierV1,
        permit: &ScopedExecutionPermitV1,
        call: &ToolCallSpecV1,
        clock: impl Fn() -> DateTime<Utc>,
    ) -> Result<ScopedPermitPreflightV1, PolicyError> {
        self.with_lock(|| {
            let mut state = self.context_state()?;
            state.access(access)?;
            if state.configuration.as_ref().map(|c| &c.approval_verifier)
                != Some(&approval_verifier_digest(verifier)?)
            {
                return Err(denied("approval verifier differs from current enrollment"));
            }
            let now = clock();
            let scope = state.current(&permit.context.authority, now)?;
            verify(
                &scope.grant.controller_public_key,
                &permit.context.signing_bytes()?,
                &permit.context.signature,
            )?;
            let record = state
                .permits
                .get(&permit.permit_id)
                .ok_or_else(|| denied("permit not issued"))?;
            if permit.approval_verifier != approval_verifier_digest(verifier)?
                || record.permit != *permit
                || record.preflight.is_some()
                || scope.head.mode != ContextAdmissionModeV1::Active
            {
                return Err(denied("permit changed, consumed or sealed"));
            }
            let binding = &permit.effect.binding;
            if binding.tool != call.tool
                || binding.action_digest != content_digest(call)?
                || binding.args_digest != content_digest(&call.args)?
                || binding.policy_version != scope.grant.policy_version
                || binding.actor != scope.grant.actor
            {
                return Err(denied("dispatch differs from approved call"));
            }
            let final_now = clock();
            state.current(&permit.context.authority, final_now)?;
            if final_now < now || final_now < binding.not_before || final_now >= binding.expires_at
            {
                return Err(denied("call validity changed"));
            }
            let preflight = ScopedPermitPreflightV1 {
                permit: permit.clone(),
                recorded_at: final_now,
                receipt_digest: content_digest(&(
                    "recursive-agent.scoped-external-preflight/v1",
                    permit,
                    final_now,
                ))?,
            };
            state
                .permits
                .get_mut(&permit.permit_id)
                .ok_or_else(|| denied("permit absent"))?
                .preflight = Some(preflight.clone());
            self.replace_context_state(&state, None)?;
            Ok(preflight)
        })
    }

    pub fn transition_context_authority(
        &self,
        access: &ContextAuthorityAccess,
        request: &ContextTransitionRequestV1,
        clock: impl Fn() -> DateTime<Utc>,
        interrupt_after: Option<PermitTransitionStage>,
    ) -> Result<ContextTransitionReceiptV1, PolicyError> {
        self.with_lock(|| {
            let mut state = self.context_state()?;
            state.access(access)?;
            // Readback after lost ACK returns the immutable original operation,
            // even when its predecessor is no longer current. It grants no call.
            if let Some(receipt) = state.receipts.get(&request.transition) {
                return if receipt.request == *request {
                    Ok(receipt.clone())
                } else {
                    Err(denied("conflicting transition identity"))
                };
            }
            let now = clock();
            let scope = state.current(&request.authority, now)?;
            verify(
                &scope.grant.controller_public_key,
                &request.signing_bytes()?,
                &request.signature,
            )?;
            if scope.transitions >= scope.grant.max_transitions
                || state.receipts.len() >= MAX_TRANSITIONS
            {
                return Err(denied("transition budget exhausted"));
            }
            let successor = match &request.action {
                ContextTransitionActionV1::Retire { successor_context } => {
                    identifier(successor_context)?;
                    ContextHeadV1 {
                        context: successor_context.clone(),
                        generation: scope
                            .head
                            .generation
                            .checked_add(1)
                            .ok_or_else(|| denied("generation exhausted"))?,
                        mode: ContextAdmissionModeV1::Sealed,
                    }
                }
                ContextTransitionActionV1::Activate { retirement_digest } => {
                    if scope.head.mode != ContextAdmissionModeV1::Sealed
                        || scope.retirement_digest.as_ref() != Some(retirement_digest)
                    {
                        return Err(denied("activation does not bind current retirement"));
                    }
                    ContextHeadV1 {
                        mode: ContextAdmissionModeV1::Active,
                        ..scope.head.clone()
                    }
                }
            };
            successor.validate()?;
            let final_now = clock();
            if final_now < now {
                return Err(denied("clock regressed"));
            }
            state.current(&request.authority, final_now)?;
            let consumed = state.consumed(&request.authority.scope);
            let receipt = ContextTransitionReceiptV1 {
                request: request.clone(),
                successor: successor.clone(),
                consumed: consumed.clone(),
                recorded_at: final_now,
                receipt_digest: content_digest(&(
                    "recursive-agent.context-transition-receipt/v1",
                    request,
                    &successor,
                    &consumed,
                    final_now,
                ))?,
            };
            let scope = state
                .scopes
                .get_mut(&content_digest(&request.authority.scope)?)
                .ok_or_else(|| denied("scope absent"))?;
            scope.head = successor;
            scope.transitions += 1;
            if matches!(request.action, ContextTransitionActionV1::Retire { .. }) {
                scope.retirement_digest = Some(receipt.receipt_digest.clone());
            }
            state
                .receipts
                .insert(request.transition.clone(), receipt.clone());
            state
                .journal
                .push(AuthorityEvent::Transition(request.transition.clone()));
            self.replace_context_state(&state, interrupt_after)?;
            Ok(receipt)
        })
    }

    /// Historical readback requires exact full permit identity, never current
    /// admission. Revocation must not erase a consumed effect's settlement path.
    pub fn read_scoped_external_permit(
        &self,
        permit: &ScopedExecutionPermitV1,
    ) -> Result<ScopedPermitRecordV1, PolicyError> {
        self.with_lock(|| {
            let state = self.context_state()?;
            let record = state
                .permits
                .get(&permit.permit_id)
                .ok_or_else(|| denied("permit absent"))?;
            if record.permit != *permit {
                return Err(denied("readback binding changed"));
            }
            Ok(record.clone())
        })
    }

    pub fn settle_scoped_external_permit(
        &self,
        permit: &ScopedExecutionPermitV1,
        preflight_digest: &ContentDigest,
        reported: ReportedEffectOutcomeV1,
        clock: impl Fn() -> DateTime<Utc>,
    ) -> Result<PermitOutcomeReceiptV1, PolicyError> {
        reported.validate()?;
        self.with_lock(|| {
            let mut state = self.context_state()?;
            let record = state
                .permits
                .get_mut(&permit.permit_id)
                .ok_or_else(|| denied("permit absent"))?;
            if record.permit != *permit {
                return Err(denied("settlement binding changed"));
            }
            let preflight = record
                .preflight
                .as_ref()
                .ok_or_else(|| denied("permit not consumed"))?;
            let now = clock();
            if preflight.receipt_digest != *preflight_digest || now < preflight.recorded_at {
                return Err(denied("settlement preflight changed"));
            }
            if let Some(existing) = &record.outcome {
                return if existing.reported == reported {
                    Ok(existing.clone())
                } else {
                    Err(denied("conflicting outcome"))
                };
            }
            let outcome = PermitOutcomeReceiptV1::create(
                permit.permit_id.clone(),
                preflight_digest.clone(),
                reported,
                now,
            )?;
            record.outcome = Some(outcome.clone());
            self.replace_context_state(&state, None)?;
            Ok(outcome)
        })
    }

    // Called only while the existing lock is held by a legacy mutation.
    pub(super) fn reject_legacy_context_admission(&self) -> Result<(), PolicyError> {
        if self.read_context_state()?.is_some() {
            return Err(denied("legacy admission fenced"));
        }
        Ok(())
    }

    fn context_state(&self) -> Result<AuthorityState, PolicyError> {
        self.read_context_state()?
            .ok_or_else(|| denied("authority not initialized"))
    }

    fn assert_no_legacy_consumption(&self) -> Result<(), PolicyError> {
        let entries =
            rustix::fs::Dir::read_from(self.root.as_fd()).map_err(std::io::Error::from)?;
        for (index, entry) in entries.enumerate() {
            if index >= MAX_PERMITS {
                return Err(denied("legacy inventory exceeds enrollment bound"));
            }
            let entry = entry.map_err(std::io::Error::from)?;
            let name = entry.file_name().to_bytes();
            if !name.starts_with(b"permit-") || !name.ends_with(b".json") {
                continue;
            }
            let name =
                std::str::from_utf8(name).map_err(|_| denied("invalid legacy record name"))?;
            let fd = secure_open_at(
                &self.root,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )?;
            let file = File::from(fd);
            if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_PERMIT_RECORD_BYTES {
                return Err(denied("invalid legacy record"));
            }
            let mut bytes = Vec::new();
            file.take(MAX_PERMIT_RECORD_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_PERMIT_RECORD_BYTES {
                return Err(denied("legacy record exceeds bound"));
            }
            let record: PermitRecordV1 = serde_json::from_slice(&bytes)?;
            if state_name(&record.permit.permit_id)? != name {
                return Err(denied("legacy record identity changed"));
            }
            let checked = self.read_record(&record.permit.permit_id)?;
            // V1 has no scope or independently confirmed external settlement.
            // Do not fabricate a migration or lose an already-admitted effect.
            if matches!(checked.state, PermitStateV1::Consumed { .. }) {
                return Err(denied(
                    "legacy consumed effects require explicit owner migration",
                ));
            }
        }
        Ok(())
    }

    /// Validate the durable projection by replaying its authenticated history.
    /// This detects inconsistent/corrupted projections; it is not a claim of
    /// isolation from an operator replacing the entire store and all history.
    fn validate_context_history(&self, state: &AuthorityState) -> Result<(), PolicyError> {
        if state.journal.len() > MAX_TRANSITIONS * 2 {
            return Err(denied("authority history exceeds bound"));
        }
        let mut replay = AuthorityState {
            schema: ContextAuthoritySchemaV1::V1,
            incarnation: state.incarnation.clone(),
            root_identity: state.root_identity,
            configuration: None,
            scopes: BTreeMap::new(),
            permits: BTreeMap::new(),
            approvals: BTreeMap::new(),
            receipts: BTreeMap::new(),
            journal: Vec::new(),
        };
        let mut seen = BTreeSet::new();
        let mut grants = BTreeMap::new();
        let mut admitted_heads = BTreeSet::new();
        for event in &state.journal {
            match event {
                AuthorityEvent::Enrollment(configuration) => {
                    apply_configuration(&mut replay, configuration)?;
                    for grant in &configuration.grants {
                        grants.insert(content_digest(grant)?, grant);
                    }
                }
                AuthorityEvent::Transition(key) => {
                    if !seen.insert(key.clone()) {
                        return Err(denied("duplicate historical transition"));
                    }
                    let receipt = state
                        .receipts
                        .get(key)
                        .ok_or_else(|| denied("historical transition missing"))?;
                    let request = &receipt.request;
                    let scope = replay.current(&request.authority, receipt.recorded_at)?;
                    verify(
                        &scope.grant.controller_public_key,
                        &request.signing_bytes()?,
                        &request.signature,
                    )?;
                    if scope.transitions >= scope.grant.max_transitions {
                        return Err(denied("historical transition exceeds grant"));
                    }
                    let successor = match &request.action {
                        ContextTransitionActionV1::Retire { successor_context } => ContextHeadV1 {
                            context: successor_context.clone(),
                            generation: scope
                                .head
                                .generation
                                .checked_add(1)
                                .ok_or_else(|| denied("historical generation overflow"))?,
                            mode: ContextAdmissionModeV1::Sealed,
                        },
                        ContextTransitionActionV1::Activate { retirement_digest } => {
                            if scope.head.mode != ContextAdmissionModeV1::Sealed
                                || scope.retirement_digest.as_ref() != Some(retirement_digest)
                            {
                                return Err(denied("historical activation mismatch"));
                            }
                            ContextHeadV1 {
                                mode: ContextAdmissionModeV1::Active,
                                ..scope.head.clone()
                            }
                        }
                    };
                    if successor != receipt.successor {
                        return Err(denied("historical successor mismatch"));
                    }
                    let expected_ids: BTreeSet<_> = state
                        .permits
                        .iter()
                        .filter(|(_, r)| {
                            r.permit.context.authority.scope == request.authority.scope
                                && r.preflight.is_some()
                                && r.permit.context.authority.head.generation < successor.generation
                        })
                        .map(|(id, _)| id.clone())
                        .collect();
                    let actual_ids: BTreeSet<_> = receipt
                        .consumed
                        .iter()
                        .map(|r| r.permit_id.clone())
                        .collect();
                    if expected_ids != actual_ids || actual_ids.len() != receipt.consumed.len() {
                        return Err(denied("historical obligation inventory mismatch"));
                    }
                    for historical in &receipt.consumed {
                        let current = state
                            .permits
                            .get(&historical.permit_id)
                            .ok_or_else(|| denied("historical obligation absent"))?;
                        let preflight = current
                            .preflight
                            .as_ref()
                            .ok_or_else(|| denied("historical consumption absent"))?;
                        if historical.preflight_receipt_digest != preflight.receipt_digest
                            || preflight.recorded_at > receipt.recorded_at
                            || historical.outcome_receipt_digest.is_some()
                                != historical.reported_state.is_some()
                        {
                            return Err(denied("historical obligation binding mismatch"));
                        }
                        if let Some(digest) = &historical.outcome_receipt_digest {
                            let outcome = current
                                .outcome
                                .as_ref()
                                .ok_or_else(|| denied("historical outcome absent"))?;
                            if outcome.receipt_digest != *digest
                                || Some(outcome.reported.state) != historical.reported_state
                                || outcome.recorded_at > receipt.recorded_at
                            {
                                return Err(denied("historical outcome mismatch"));
                            }
                        }
                    }
                    let scope = replay
                        .scopes
                        .get_mut(&content_digest(&request.authority.scope)?)
                        .ok_or_else(|| denied("historical scope missing"))?;
                    scope.head = successor;
                    scope.transitions += 1;
                    if matches!(request.action, ContextTransitionActionV1::Retire { .. }) {
                        scope.retirement_digest = Some(receipt.receipt_digest.clone());
                    }
                }
            }
            for scope in replay
                .scopes
                .values()
                .filter(|s| s.active && s.head.mode == ContextAdmissionModeV1::Active)
            {
                let authority = ContextAuthorityBindingV1 {
                    incarnation: state.incarnation.clone(),
                    scope: scope.grant.scope.clone(),
                    grant_digest: content_digest(&scope.grant)?,
                    policy_digest: scope.grant.policy_digest.clone(),
                    head: scope.head.clone(),
                };
                let config = replay
                    .configuration
                    .as_ref()
                    .ok_or_else(|| denied("historical configuration absent"))?;
                admitted_heads.insert(content_digest(&(&authority, &config.approval_verifier))?);
            }
        }
        if seen.len() != state.receipts.len()
            || replay.configuration != state.configuration
            || replay.scopes.len() != state.scopes.len()
        {
            return Err(denied("authority projection differs from history"));
        }
        for (key, actual) in &state.scopes {
            let projected = replay
                .scopes
                .get_mut(key)
                .ok_or_else(|| denied("scope projection absent"))?;
            projected.effects = state
                .permits
                .values()
                .filter(|r| r.permit.context.authority.scope == actual.grant.scope)
                .count() as u64;
            if projected != actual {
                return Err(denied("scope projection differs from history"));
            }
        }
        for record in state.permits.values() {
            let permit = &record.permit;
            let authority = &permit.context.authority;
            let grant = grants
                .get(&authority.grant_digest)
                .ok_or_else(|| denied("historical grant absent"))?;
            if !admitted_heads.contains(&content_digest(&(authority, &permit.approval_verifier))?)
                || grant.scope != authority.scope
                || grant.policy_digest != authority.policy_digest
                || grant.policy_version != permit.effect.binding.policy_version
                || grant.actor != permit.effect.binding.actor
                || permit.effect.binding.effect.write_roots != vec![grant.write_root.clone()]
                || permit.effect.binding.expires_at > grant.expires_at
            {
                return Err(denied("historical effect outside grant"));
            }
            verify(
                &grant.controller_public_key,
                &permit.context.signing_bytes()?,
                &permit.context.signature,
            )?;
        }
        Ok(())
    }

    fn read_context_state(&self) -> Result<Option<AuthorityState>, PolicyError> {
        let fd = match secure_open_at(
            &self.root,
            STATE_FILE,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let file = File::from(fd);
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_STATE_BYTES {
            return Err(denied("invalid state file"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(denied("state exceeds bound"));
        }
        let state: AuthorityState = serde_json::from_slice(&bytes)?;
        // Canonical equality also rejects duplicate object keys on disk.
        if jcs_canonical(&state)? != bytes || state.root_identity != self.permit_root_identity() {
            return Err(denied("noncanonical or substituted authority store"));
        }
        self.validate_context_state(&state)?;
        Ok(Some(state))
    }

    fn validate_context_state(&self, state: &AuthorityState) -> Result<(), PolicyError> {
        self.validate_context_history(state)?;
        if state.scopes.len() > MAX_SCOPES
            || state.permits.len() > MAX_PERMITS
            || state.receipts.len() > MAX_TRANSITIONS
            || state.approvals.len() != state.permits.len()
        {
            return Err(denied("invalid state inventory"));
        }
        for (key, scope) in &state.scopes {
            scope.grant.validate()?;
            scope.head.validate()?;
            if content_digest(&scope.grant.scope)? != *key {
                return Err(denied("scope identity corrupted"));
            }
            let effects = state
                .permits
                .values()
                .filter(|r| r.permit.context.authority.scope == scope.grant.scope)
                .count() as u64;
            let transitions = state
                .receipts
                .values()
                .filter(|r| r.request.authority.scope == scope.grant.scope)
                .count() as u64;
            if scope.effects != effects || scope.transitions != transitions {
                return Err(denied("scope charges corrupted"));
            }
        }
        for (key, record) in &state.permits {
            let permit = &record.permit;
            permit.effect.binding.validate()?;
            if permit.permit_id != *key
                || ScopedExecutionPermitV1::derive_id(
                    &permit.effect,
                    &permit.context,
                    &permit.approval_verifier,
                )? != *key
                || derive_permit_id(&permit.effect.identity_material()?)? != permit.effect.permit_id
                || state.approvals.get(&permit.effect.permit_id) != Some(key)
                || permit.context.authority.incarnation != state.incarnation
                || !state
                    .scopes
                    .contains_key(&content_digest(&permit.context.authority.scope)?)
            {
                return Err(denied("permit identity corrupted"));
            }
            if let Some(preflight) = &record.preflight {
                if preflight.permit != *permit
                    || preflight.receipt_digest
                        != content_digest(&(
                            "recursive-agent.scoped-external-preflight/v1",
                            permit,
                            preflight.recorded_at,
                        ))?
                    || preflight.recorded_at < permit.effect.binding.not_before
                    || preflight.recorded_at >= permit.effect.binding.expires_at
                {
                    return Err(denied("preflight corrupted"));
                }
                if let Some(outcome) = &record.outcome {
                    outcome.validate()?;
                    if outcome.permit_id != *key
                        || outcome.preflight_receipt_digest != preflight.receipt_digest
                        || outcome.recorded_at < preflight.recorded_at
                    {
                        return Err(denied("outcome binding corrupted"));
                    }
                }
            } else if record.outcome.is_some() {
                return Err(denied("outcome without consumption"));
            }
        }
        for (key, receipt) in &state.receipts {
            if *key != receipt.request.transition
                || receipt.receipt_digest
                    != content_digest(&(
                        "recursive-agent.context-transition-receipt/v1",
                        &receipt.request,
                        &receipt.successor,
                        &receipt.consumed,
                        receipt.recorded_at,
                    ))?
            {
                return Err(denied("transition receipt corrupted"));
            }
        }
        Ok(())
    }

    fn replace_context_state(
        &self,
        state: &AuthorityState,
        interrupt_after: Option<PermitTransitionStage>,
    ) -> Result<(), PolicyError> {
        self.validate_context_state(state)?;
        let bytes = jcs_canonical(state)?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(denied("state capacity exhausted"));
        }
        let (temp, mut file) = create_unique_temp(&self.root, ".context-authority.tmp")?;
        file.write_all(&bytes)?;
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
        rustix::fs::renameat(self.root.as_fd(), &temp, self.root.as_fd(), STATE_FILE)
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
}
