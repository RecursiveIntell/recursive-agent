//! Conservative inference reservations owned by the native family store.
//!
//! This opt-in companion record does not reinterpret V1 effect-byte budgets.
//! Its initializer is a trusted root-policy composition seam, not a remote
//! grant verifier. Neither serialized records nor budget tickets authorize
//! provider access. The physical-send owner must separately validate/consume
//! its execution permit, enforce the frozen request bounds, and call begin
//! exactly once per physical attempt. That integration is not supplied here.
//! Reservations never refund: absent/uncertain usage stays fully charged.
use super::*;
#[path = "inference_terms.rs"]
mod terms;
pub use terms::*;
#[path = "campaign_inference.rs"]
mod campaign;
pub use campaign::*;

// One record/accounting validator for both explicit bank versions.
struct InferenceRecordBounds<'a> {
    limits: InferenceBudgetLimitsV1,
    provider: &'a str,
    model: &'a str,
    reasoning_effort: &'a str,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}
fn validate_inference_records(
    bounds: &InferenceRecordBounds<'_>,
    sends: &BTreeMap<CurrentPermitId, InferenceSendRecordV1>,
) -> Result<InferenceBudgetStatusV1, PolicyError> {
    let limits = &bounds.limits;
    let n = u64::try_from(sends.len()).map_err(|_| overrun())?;
    let mut status = InferenceBudgetStatusV1 {
        reserved_sends: n,
        reserved_input_tokens: n
            .checked_mul(limits.max_input_tokens_per_send)
            .ok_or_else(overrun)?,
        reserved_output_tokens: n
            .checked_mul(limits.max_output_tokens_per_send)
            .ok_or_else(overrun)?,
        reserved_nanodollars: n
            .checked_mul(limits.quote_nanodollars()?)
            .ok_or_else(overrun)?,
        ..Default::default()
    };
    if status.reserved_sends > limits.max_sends
        || status.reserved_input_tokens > limits.max_total_input_tokens
        || status.reserved_output_tokens > limits.max_total_output_tokens
        || status.reserved_nanodollars > limits.max_total_nanodollars
    {
        return Err(overrun());
    }
    for (id, record) in sends {
        if *id != record.request.permit_id
            || record.request.provider != bounds.provider
            || record.request.model != bounds.model
            || record.request.reasoning_effort != bounds.reasoning_effort
            || record.reserved_at < bounds.not_before
            || record.reserved_at >= bounds.expires_at
        {
            return Err(invalid());
        }
        if let Some(start) = record.dispatched_at {
            if start < record.reserved_at || start >= bounds.expires_at {
                return Err(invalid());
            }
            if record.settlement.is_none() {
                status.unsettled_dispatches += 1;
            }
        } else if record.settlement.is_some() {
            return Err(invalid());
        }
        match &record.settlement {
            Some(InferenceSettlementV1::Observed {
                input_tokens,
                output_tokens,
                ..
            }) => {
                if *input_tokens > limits.max_input_tokens_per_send
                    || *output_tokens > limits.max_output_tokens_per_send
                {
                    return Err(overrun());
                }
                status.settled_sends += 1;
            }
            Some(InferenceSettlementV1::Unknown { .. }) => status.unknown_sends += 1,
            None => {}
        }
    }
    Ok(status)
}

const SCHEMA: &str = "recursive-agent.inference-budget/v1";
const STATE_NAME: &str = "inference-budget.v1.json";
const BINDING_NAME: &str = "inference-budget.v1.binding";
const MAX_BYTES: u64 = 1024 * 1024;

/// Immutable, trusted-root-selected equivalent tariff and campaign bounds.
/// Nanodollars avoid floating-point rounding; one dollar is 1_000_000_000.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceBudgetGrantV1 {
    pub schema: String,
    pub root_operation_id: CurrentRunId,
    pub parent_control_permit_id: CurrentPermitId,
    pub policy_version: String,
    pub provider: String,
    pub model: String,
    pub reasoning_effort: String,
    pub tariff_digest: ContentDigest,
    pub input_nanodollars_per_token: u64,
    pub output_nanodollars_per_token: u64,
    pub max_input_tokens_per_send: u64,
    pub max_output_tokens_per_send: u64,
    pub max_total_input_tokens: u64,
    pub max_total_output_tokens: u64,
    pub max_sends: u64,
    pub max_total_nanodollars: u64,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

fn invalid() -> PolicyError {
    PolicyError::InvalidLease("inference budget identity, shape or bounds rejected".into())
}
fn overrun() -> PolicyError {
    PolicyError::BudgetOverrun("inference campaign reservation ceiling exceeded".into())
}
impl InferenceBudgetGrantV1 {
    /// Projection only: serialized V1 grants retain their original flat fields.
    pub fn limits(&self) -> InferenceBudgetLimitsV1 {
        InferenceBudgetLimitsV1 {
            input_nanodollars_per_token: self.input_nanodollars_per_token,
            output_nanodollars_per_token: self.output_nanodollars_per_token,
            max_input_tokens_per_send: self.max_input_tokens_per_send,
            max_output_tokens_per_send: self.max_output_tokens_per_send,
            max_total_input_tokens: self.max_total_input_tokens,
            max_total_output_tokens: self.max_total_output_tokens,
            max_sends: self.max_sends,
            max_total_nanodollars: self.max_total_nanodollars,
        }
    }
    fn quote(&self) -> Result<u64, PolicyError> {
        self.limits().quote_nanodollars()
    }
    fn validate(&self, family: &FamilyAuthorityStateV1) -> Result<(), PolicyError> {
        let ceiling = &family.grant.child_run_ceiling;
        if self.schema != SCHEMA
            || self.root_operation_id != family.grant.root_operation_id
            || self.parent_control_permit_id != family.grant.parent_control_permit_id
            || self.policy_version != family.grant.policy_version
            || self.not_before < ceiling.not_before
            || self.expires_at > ceiling.expires_at
            || self.expires_at <= self.not_before
        {
            return Err(invalid());
        }
        for value in [
            &self.policy_version,
            &self.provider,
            &self.model,
            &self.reasoning_effort,
        ] {
            if value.is_empty()
                || value.len() > 256
                || value.chars().any(char::is_control)
                || looks_like_credential_material(value)
            {
                return Err(invalid());
            }
        }
        self.quote()?;
        Ok(())
    }
    fn admits_route(&self, request: &InferenceSendRequestV1) -> bool {
        self.provider == request.provider
            && self.model == request.model
            && self.reasoning_effort == request.reasoning_effort
    }
}

/// Exact physical-attempt identity. It is not itself an execution capability.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceSendRequestV1 {
    pub permit_id: CurrentPermitId,
    pub request_digest: ContentDigest,
    pub provider: String,
    pub model: String,
    pub reasoning_effort: String,
}

/// Observed usage is evidence only and never refunds the reserved upper bound.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum InferenceSettlementV1 {
    Observed {
        response_digest: ContentDigest,
        input_tokens: u64,
        output_tokens: u64,
    },
    Unknown {
        evidence_digest: ContentDigest,
    },
}

/// Persisted, nonauthorizing transition evidence. Every field is write-once.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceSendRecordV1 {
    pub request: InferenceSendRequestV1,
    pub reserved_at: DateTime<Utc>,
    pub dispatched_at: Option<DateTime<Utc>>,
    pub settlement: Option<InferenceSettlementV1>,
}

/// Runtime-only settlement handle, not provider authority. Not Clone or serde.
///
/// ```compile_fail
/// use recursive_agent_policy::InferenceBudgetTicketV1;
/// let forged: InferenceBudgetTicketV1 = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug)]
pub struct InferenceBudgetTicketV1 {
    store_identity: (u64, u64),
    // Pin the directory inode for the ticket lifetime; path replacement cannot
    // recycle its identity into a different campaign store.
    family_root: Arc<File>,
    grant_digest: ContentDigest,
    request: InferenceSendRequestV1,
}

/// Rebuildable projection of retained reservations, not a second budget bank.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct InferenceBudgetStatusV1 {
    pub reserved_sends: u64,
    pub reserved_input_tokens: u64,
    pub reserved_output_tokens: u64,
    pub reserved_nanodollars: u64,
    pub settled_sends: u64,
    pub unknown_sends: u64,
    pub unsettled_dispatches: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InferenceBudgetStateV1 {
    family_grant_digest: ContentDigest,
    grant: InferenceBudgetGrantV1,
    sends: BTreeMap<CurrentPermitId, InferenceSendRecordV1>,
}
impl InferenceBudgetStateV1 {
    fn validate(
        &self,
        family: &FamilyAuthorityStateV1,
    ) -> Result<InferenceBudgetStatusV1, PolicyError> {
        self.grant.validate(family)?;
        if self.family_grant_digest != content_digest(&family.grant)? {
            return Err(invalid());
        }
        validate_inference_records(
            &InferenceRecordBounds {
                limits: self.grant.limits(),
                provider: &self.grant.provider,
                model: &self.grant.model,
                reasoning_effort: &self.grant.reasoning_effort,
                not_before: self.grant.not_before,
                expires_at: self.grant.expires_at,
            },
            &self.sends,
        )
    }
}

impl FamilyAuthorityStore {
    /// Bind one immutable opt-in tariff/ceiling under this existing root owner.
    /// Trusted composition must authorize this initialization; serialized input
    /// is not remotely admitted by this API. Existing V1 stores are unchanged.
    pub fn bind_inference_budget(&self, grant: InferenceBudgetGrantV1) -> Result<(), PolicyError> {
        self.with_lock(|| {
            if self.inference_path_exists(campaign::STATE_V2)? {
                return Err(PolicyError::PermitStateConflict);
            }
            let family = self.read_state()?;
            grant.validate(&family)?;
            if family.parent_revoked_at.is_some() {
                return Err(invalid());
            }
            match self.read_inference_state(&family) {
                Ok(state) if state.grant == grant => Ok(()),
                Ok(_) => Err(PolicyError::PermitStateConflict),
                Err(PolicyError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    // A write-once initialization marker distinguishes a new
                    // budget from lost/corrupt charged state. If initialization
                    // crashes, recovery blocks instead of replenishing money.
                    let state = InferenceBudgetStateV1 {
                        family_grant_digest: content_digest(&family.grant)?,
                        grant,
                        sends: BTreeMap::new(),
                    };
                    let mut marker = File::from(secure_open_at(
                        &self.root,
                        BINDING_NAME,
                        OFlags::WRONLY
                            | OFlags::CREATE
                            | OFlags::EXCL
                            | OFlags::NOFOLLOW
                            | OFlags::CLOEXEC,
                        Mode::RUSR | Mode::WUSR,
                    )?);
                    marker.write_all(&Self::inference_binding_bytes(&state)?)?;
                    marker.sync_all()?;
                    self.root.sync_all()?;
                    self.write_inference_state(&state, &family)
                }
                Err(error) => Err(error),
            }
        })
    }

    /// Reserve the full frozen per-attempt bound before any possible send.
    /// Identical retries only read the same reservation; begin is separately once.
    pub fn reserve_inference(
        &self,
        request: &InferenceSendRequestV1,
        mut trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<InferenceSendRecordV1, PolicyError> {
        self.with_lock(|| {
            let started = trusted_clock();
            let family = self.read_state()?;
            let mut state = self.read_inference_state(&family)?;
            Self::guard_inference(&family, &state.grant, started)?;
            let now = trusted_clock();
            if now < started {
                return Err(invalid());
            }
            Self::guard_inference(&family, &state.grant, now)?;
            if !state.grant.admits_route(request) {
                return Err(invalid());
            }
            if let Some(record) = state.sends.get(&request.permit_id) {
                return if record.request == *request {
                    Ok(record.clone())
                } else {
                    Err(PolicyError::PermitStateConflict)
                };
            }
            let record = InferenceSendRecordV1 {
                request: request.clone(),
                reserved_at: now,
                dispatched_at: None,
                settlement: None,
            };
            state
                .sends
                .insert(request.permit_id.clone(), record.clone());
            self.write_inference_state(&state, &family)?;
            Ok(record)
        })
    }

    /// Durably record once-only dispatch *before* handing control to a send.
    /// A crash after this transition is unknown, never permission to resend.
    pub fn begin_inference(
        &self,
        permit_id: &CurrentPermitId,
        request_digest: &ContentDigest,
        mut trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<InferenceBudgetTicketV1, PolicyError> {
        self.with_lock(|| {
            let started = trusted_clock();
            let family = self.read_state()?;
            let mut state = self.read_inference_state(&family)?;
            Self::guard_inference(&family, &state.grant, started)?;
            let now = trusted_clock();
            if now < started {
                return Err(invalid());
            }
            Self::guard_inference(&family, &state.grant, now)?;
            let record = state.sends.get_mut(permit_id).ok_or_else(invalid)?;
            if record.request.request_digest != *request_digest || record.dispatched_at.is_some() {
                return Err(PolicyError::PermitStateConflict);
            }
            record.dispatched_at = Some(now);
            let request = record.request.clone();
            self.write_inference_state(&state, &family)?;
            Ok(InferenceBudgetTicketV1 {
                store_identity: self.root_identity(),
                family_root: Arc::clone(&self.root),
                grant_digest: content_digest(&state.grant)?,
                request,
            })
        })
    }

    /// Record immutable terminal evidence, including after expiry/revocation.
    /// Outstanding and unknown attempts retain their entire original charge.
    pub fn settle_inference(
        &self,
        ticket: &InferenceBudgetTicketV1,
        outcome: InferenceSettlementV1,
    ) -> Result<(), PolicyError> {
        self.with_lock(|| {
            let pinned = directory_identity(&ticket.family_root)?;
            if ticket.store_identity != self.root_identity()
                || (pinned.0, pinned.1) != ticket.store_identity
            {
                return Err(invalid());
            }
            let family = self.read_state()?;
            let mut state = self.read_inference_state(&family)?;
            if ticket.grant_digest != content_digest(&state.grant)? {
                return Err(invalid());
            }
            let record = state
                .sends
                .get_mut(&ticket.request.permit_id)
                .ok_or_else(invalid)?;
            if record.request != ticket.request || record.dispatched_at.is_none() {
                return Err(invalid());
            }
            if let Some(existing) = &record.settlement {
                return if *existing == outcome {
                    Ok(())
                } else {
                    Err(PolicyError::PermitStateConflict)
                };
            }
            record.settlement = Some(outcome);
            self.write_inference_state(&state, &family)
        })
    }

    /// Read exact retained attempt evidence without granting execution or retry.
    ///
    /// Expiry and revocation do not hide historical state. This method does not
    /// call admission, reserve funds, reconstruct a runtime ticket, settle an
    /// unknown dispatch, or initialize absent state. A started attempt without
    /// settlement remains unknown; callers must never use readback to resend.
    pub fn read_inference(
        &self,
        request: &InferenceSendRequestV1,
    ) -> Result<InferenceSendRecordV1, PolicyError> {
        self.with_lock(|| {
            let family = self.read_state()?;
            let state = self.read_inference_state(&family)?;
            let record = state.sends.get(&request.permit_id).ok_or_else(invalid)?;
            if record.request != *request {
                return Err(PolicyError::PermitStateConflict);
            }
            Ok(record.clone())
        })
    }

    pub fn inference_budget_status(&self) -> Result<InferenceBudgetStatusV1, PolicyError> {
        self.with_lock(|| {
            let family = self.read_state()?;
            self.read_inference_state(&family)?.validate(&family)
        })
    }

    fn guard_inference(
        family: &FamilyAuthorityStateV1,
        grant: &InferenceBudgetGrantV1,
        now: DateTime<Utc>,
    ) -> Result<(), PolicyError> {
        if family.parent_revoked_at.is_some() || now < grant.not_before || now >= grant.expires_at {
            return Err(invalid());
        }
        Ok(())
    }
    fn read_inference_state(
        &self,
        family: &FamilyAuthorityStateV1,
    ) -> Result<InferenceBudgetStateV1, PolicyError> {
        if self.inference_path_exists(campaign::STATE_V2)? {
            return Err(PolicyError::PermitStateConflict);
        }
        let fd = secure_open_at(
            &self.root,
            STATE_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?;
        let file = File::from(fd);
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_BYTES {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(invalid());
        }
        let state: InferenceBudgetStateV1 = serde_json::from_slice(&bytes)?;
        // Reject duplicate keys, alternate encodings and unknown fields rather
        // than silently normalizing an authoritative record during recovery.
        if jcs_canonical(&state)? != bytes {
            return Err(PolicyError::PermitStateConflict);
        }
        state.validate(family)?;
        self.validate_inference_binding(&state)?;
        Ok(state)
    }
    fn inference_binding_bytes(state: &InferenceBudgetStateV1) -> Result<Vec<u8>, PolicyError> {
        Ok(jcs_canonical(&(
            &state.family_grant_digest,
            content_digest(&state.grant)?,
        ))?)
    }
    fn validate_inference_binding(
        &self,
        state: &InferenceBudgetStateV1,
    ) -> Result<(), PolicyError> {
        let fd = secure_open_at(
            &self.root,
            BINDING_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| PolicyError::PermitStateConflict)?;
        let file = File::from(fd);
        if !file.metadata()?.is_file() {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        file.take(4097).read_to_end(&mut bytes)?;
        if bytes != Self::inference_binding_bytes(state)? {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(())
    }
    fn write_inference_state(
        &self,
        state: &InferenceBudgetStateV1,
        family: &FamilyAuthorityStateV1,
    ) -> Result<(), PolicyError> {
        state.validate(family)?;
        self.validate_inference_binding(state)?;
        let bytes = jcs_canonical(state)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(invalid());
        }
        let (name, mut file) = create_unique_temp(&self.root, ".inference-budget.tmp")?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        rustix::fs::renameat(self.root.as_fd(), &name, self.root.as_fd(), STATE_NAME)
            .map_err(std::io::Error::from)?;
        self.root.sync_all()?;
        Ok(())
    }
}
