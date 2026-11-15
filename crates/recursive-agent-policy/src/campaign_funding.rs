//! Startup-only funding authorization, distinct from short execution permits.
//!
//! This owner stores immutable enrollment metadata, NOT balances or send state.
//! Trusted startup expectations are comparisons, not mission/task verification.
//! Family monetary accounting, root composition and physical egress remain
//! separate gates. No method here can reserve money or authorize a send.
use super::*;
use recursive_agent_contracts::{content_digest, ContentDigest};
use std::io::Write;
#[path = "campaign_root.rs"]
mod campaign_root;
pub use campaign_root::*;

fn validate_campaign_terms(
    grant: &CampaignFundingGrantV1,
    terms: &InferenceBudgetTermsV1,
) -> Result<(), PolicyError> {
    let digest = terms.computed_digest()?;
    if digest != grant.budget_terms_digest
        || terms.provider != grant.provider_identity
        || terms.model != grant.model_ref
        || terms.api_mode != grant.api_mode
        || terms.reasoning_effort != grant.reasoning_effort
        || terms.limits.max_total_nanodollars != grant.max_total_nanodollars
    {
        return Err(funding_denied());
    }
    Ok(())
}

const FUNDING_SCHEMA: &str = "recursive-agent.campaign-funding-grant/v1";
const ENROLLMENT_SCHEMA: &str = "recursive-agent.campaign-funding-enrollment/v1";
const ENROLLMENT: &str = "campaign-funding.enrollment.v1.json";
const ANCHOR: &str = ".campaign-funding.enrolled.v1";

fn funding_denied() -> PolicyError {
    PolicyError::InvalidLease(
        "campaign funding policy, binding or current authority rejected".into(),
    )
}

/// Operator-owned startup policy. Deserialization alone grants no capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignFundingGrantV1 {
    pub schema: String,
    pub mission_contract_ref: String,
    pub mission_contract_digest: String,
    pub kanban_root_task_ref: String,
    pub ares_home_digest: String,
    pub egress_policy_digest: String,
    pub provider_identity: String,
    pub model_ref: String,
    pub api_mode: String,
    pub reasoning_effort: String,
    /// Exact canonical monetary-terms artifact, not an adapter's estimate.
    /// Its existence/semantics require separate owner composition.
    pub budget_terms_digest: ContentDigest,
    pub max_total_nanodollars: u64,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub policy_digest: String,
}
impl CampaignFundingGrantV1 {
    /// SHA-256 over owner JCS of all fields except policy_digest, as for the
    /// existing normal-chat operator grant. The schema separates domains.
    pub fn computed_policy_digest(&self) -> Result<String, PolicyError> {
        operator_policy_digest(self)
    }
    fn validate_structure(&self) -> Result<(), PolicyError> {
        if self.schema != FUNDING_SCHEMA
            || self.expires_at <= self.not_before
            || self.max_total_nanodollars == 0
            || self.max_total_nanodollars > (1_u64 << 53) - 1
        {
            return Err(funding_denied());
        }
        for (name, value) in [
            ("mission_contract_ref", &self.mission_contract_ref),
            ("kanban_root_task_ref", &self.kanban_root_task_ref),
            ("provider_identity", &self.provider_identity),
            ("model_ref", &self.model_ref),
            ("api_mode", &self.api_mode),
            ("reasoning_effort", &self.reasoning_effort),
        ] {
            validate_grant_reference(name, value)?;
            if looks_like_credential_material(value) {
                return Err(funding_denied());
            }
        }
        for (name, value) in [
            ("mission_contract_digest", &self.mission_contract_digest),
            ("ares_home_digest", &self.ares_home_digest),
            ("egress_policy_digest", &self.egress_policy_digest),
            ("policy_digest", &self.policy_digest),
        ] {
            validate_sha256_digest(name, value)?;
        }
        let mission = self
            .mission_contract_digest
            .strip_prefix("sha256:")
            .ok_or_else(funding_denied)?;
        if self.mission_contract_ref != format!("contract:{mission}")
            || self.policy_digest != self.computed_policy_digest()?
        {
            return Err(funding_denied());
        }
        Ok(())
    }
    fn matches(&self, expected: &CampaignFundingExpectationV1) -> bool {
        self.mission_contract_ref == expected.mission_contract_ref
            && self.kanban_root_task_ref == expected.kanban_root_task_ref
            && self.ares_home_digest == expected.ares_home_digest
            && self.provider_identity == expected.provider_identity
            && self.model_ref == expected.model_ref
            && self.api_mode == expected.api_mode
            && self.reasoning_effort == expected.reasoning_effort
            && self.budget_terms_digest == expected.budget_terms_digest
            && self.max_total_nanodollars == expected.max_total_nanodollars
    }
}

/// Exact trusted-startup comparisons, never IPC enrollment or proof that the
/// referenced mission/task/terms artifact is admitted by its canonical owner.
#[derive(Debug, Clone)]
pub struct CampaignFundingExpectationV1 {
    pub mission_contract_ref: String,
    pub kanban_root_task_ref: String,
    pub ares_home_digest: String,
    pub provider_identity: String,
    pub model_ref: String,
    pub api_mode: String,
    pub reasoning_effort: String,
    pub budget_terms_digest: ContentDigest,
    pub max_total_nanodollars: u64,
}

/// Historical immutable enrollment projection. Never accepted as a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignFundingEnrollmentV1 {
    pub schema: String,
    pub grant: CampaignFundingGrantV1,
    pub enrolled_at: DateTime<Utc>,
    pub authority_root_device: u64,
    pub authority_root_inode: u64,
}

/// Native startup capability only. It cannot issue permits, reserve money,
/// select a funding root or release a provider send. Recheck at composition.
///
/// ```compile_fail
/// use recursive_agent_policy::CampaignFundingAuthorityV1;
/// let _ = serde_json::from_str::<CampaignFundingAuthorityV1>("{}");
/// ```
/// ```compile_fail
/// use recursive_agent_policy::CampaignFundingAuthorityV1;
/// fn copy(v: CampaignFundingAuthorityV1) { let _ = v.clone(); }
/// ```
#[derive(Debug)]
pub struct CampaignFundingAuthorityV1 {
    enrollment: CampaignFundingEnrollmentV1,
    root: File,
    loaded_at: DateTime<Utc>,
}
impl CampaignFundingAuthorityV1 {
    pub fn grant(&self) -> &CampaignFundingGrantV1 {
        &self.enrollment.grant
    }
    pub fn loaded_at(&self) -> DateTime<Utc> {
        self.loaded_at
    }
}

impl NormalChatEgressGrantStore {
    /// Explicit trusted bootstrap only. No daemon-start implicit enrollment.
    /// One enrollment per authority directory in this version. This publishes
    /// no runtime capability; partial publication remains fenced by its anchor.
    pub fn initialize_campaign_funding_from_path(
        &self,
        path: &Path,
        authority: &NormalChatGrantAuthorityV1,
        expected: &CampaignFundingExpectationV1,
        mut trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<CampaignFundingEnrollmentV1, PolicyError> {
        let grant: CampaignFundingGrantV1 = read_operator_policy_file(path)?;
        self.with_lock(|| {
            let started = trusted_clock();
            self.check_funding_grant(&grant, authority, Some(expected), started)?;
            if self.campaign_entry_exists(ANCHOR)? || self.campaign_entry_exists(ENROLLMENT)? {
                return Err(PolicyError::PermitStateConflict);
            }
            let now = trusted_clock();
            if now < started {
                return Err(funding_denied());
            }
            self.check_funding_grant(&grant, authority, Some(expected), now)?;
            let enrollment = CampaignFundingEnrollmentV1 {
                schema: ENROLLMENT_SCHEMA.into(),
                grant,
                enrolled_at: now,
                authority_root_device: self.root_device,
                authority_root_inode: self.root_inode,
            };
            // Never recreate a missing enrollment once its anchor exists. If
            // either publication fails, preserve that uncertainty, not cleanup.
            self.write_campaign_entry(ANCHOR, &jcs_canonical(&content_digest(&enrollment)?)?)?;
            self.write_campaign_entry(ENROLLMENT, &jcs_canonical(&enrollment)?)?;
            let final_now = trusted_clock();
            if final_now < now {
                return Err(funding_denied());
            }
            self.check_funding_grant(&enrollment.grant, authority, Some(expected), final_now)?;
            if self.read_campaign_enrollment_locked()? != enrollment {
                return Err(PolicyError::PermitStateConflict);
            }
            Ok(enrollment)
        })
    }

    /// Require exact already-enrolled operator policy. Missing/corrupt state
    /// never initializes itself. Funding expiry is not a V1 execution lease.
    pub fn load_campaign_funding_from_path(
        &self,
        path: &Path,
        authority: &NormalChatGrantAuthorityV1,
        expected: &CampaignFundingExpectationV1,
        mut trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<CampaignFundingAuthorityV1, PolicyError> {
        let grant: CampaignFundingGrantV1 = read_operator_policy_file(path)?;
        self.with_lock(|| {
            let started = trusted_clock();
            self.check_funding_grant(&grant, authority, Some(expected), started)?;
            let enrollment = self.read_campaign_enrollment_locked()?;
            if enrollment.grant != grant || started < enrollment.enrolled_at {
                return Err(PolicyError::PermitStateConflict);
            }
            let now = trusted_clock();
            if now < started {
                return Err(funding_denied());
            }
            self.check_funding_grant(&grant, authority, Some(expected), now)?;
            self.check_root_identity()?;
            Ok(CampaignFundingAuthorityV1 {
                enrollment,
                root: self.root.try_clone()?,
                loaded_at: now,
            })
        })
    }

    /// Recheck the native capability and latest egress head; no serde report or
    /// copied directory may replace the pinned enrollment. No effect follows.
    pub fn check_campaign_funding_current(
        &self,
        funding: &CampaignFundingAuthorityV1,
        authority: &NormalChatGrantAuthorityV1,
        trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<(), PolicyError> {
        self.with_current_campaign_funding(funding, authority, trusted_clock, |_, _| Ok(()))
    }

    /// Validate the exact retained monetary-terms material against already loaded
    /// funding eligibility under the same current-head/time lock. Does not select
    /// a root, initialize a budget, reserve money or release any provider effect.
    /// The tariff digest and declared bounds still require external qualification.
    pub fn check_campaign_inference_terms(
        &self,
        funding: &CampaignFundingAuthorityV1,
        authority: &NormalChatGrantAuthorityV1,
        terms: &InferenceBudgetTermsV1,
        trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<(), PolicyError> {
        self.with_current_campaign_funding(funding, authority, trusted_clock, |grant, _| {
            validate_campaign_terms(grant, terms)
        })
    }

    fn with_current_campaign_funding<T>(
        &self,
        funding: &CampaignFundingAuthorityV1,
        authority: &NormalChatGrantAuthorityV1,
        mut trusted_clock: impl FnMut() -> DateTime<Utc>,
        check: impl FnOnce(&CampaignFundingGrantV1, DateTime<Utc>) -> Result<T, PolicyError>,
    ) -> Result<T, PolicyError> {
        self.with_lock(|| {
            let metadata = funding.root.metadata()?;
            if metadata.dev() != self.root_device || metadata.ino() != self.root_inode {
                return Err(PolicyError::PermitStateConflict);
            }
            let started = trusted_clock();
            if started < funding.loaded_at {
                return Err(funding_denied());
            }
            self.check_funding_grant(funding.grant(), authority, None, started)?;
            if self.read_campaign_enrollment_locked()? != funding.enrollment {
                return Err(PolicyError::PermitStateConflict);
            }
            let result = check(funding.grant(), started)?;
            let now = trusted_clock();
            if now < started {
                return Err(funding_denied());
            }
            self.check_funding_grant(funding.grant(), authority, None, now)?;
            Ok(result)
        })
    }

    /// History after expiry/policy change; no authority, repair or initialization.
    pub fn read_campaign_funding_enrollment(
        &self,
    ) -> Result<CampaignFundingEnrollmentV1, PolicyError> {
        self.with_lock(|| self.read_campaign_enrollment_locked())
    }

    fn check_funding_grant(
        &self,
        grant: &CampaignFundingGrantV1,
        authority: &NormalChatGrantAuthorityV1,
        expected: Option<&CampaignFundingExpectationV1>,
        now: DateTime<Utc>,
    ) -> Result<(), PolicyError> {
        grant.validate_structure()?;
        let normal = authority.grant();
        normal.validate_structure()?;
        let head = self.read_head()?.ok_or_else(funding_denied)?;
        if normal.mode != NormalChatEgressModeV1::Enforce
            || head.revision != normal.revision
            || head.policy_digest != normal.policy_digest
            || grant.egress_policy_digest != normal.policy_digest
            || grant.ares_home_digest != normal.ares_home_digest
            || !normal.permits_route(&grant.provider_identity, &grant.model_ref, &grant.api_mode)
            || grant.expires_at > normal.expires_at
            || now < authority.loaded_at()
            || now < grant.not_before
            || now >= grant.expires_at
            || expected.is_some_and(|e| !grant.matches(e))
        {
            return Err(funding_denied());
        }
        Ok(())
    }

    fn campaign_entry_exists(&self, name: &str) -> Result<bool, PolicyError> {
        match self.read_campaign_entry(name) {
            Ok(_) => Ok(true),
            Err(PolicyError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
    fn read_campaign_entry(&self, name: &str) -> Result<Vec<u8>, PolicyError> {
        let fd = secure_open_at(
            &self.root,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?;
        let file = File::from(fd);
        validate_private_regular_file(&file, 0o600, MAX_NORMAL_CHAT_GRANT_BYTES)?;
        read_bounded(&file, MAX_NORMAL_CHAT_GRANT_BYTES)
    }
    fn write_campaign_entry(&self, name: &str, bytes: &[u8]) -> Result<(), PolicyError> {
        if bytes.len() as u64 > MAX_NORMAL_CHAT_GRANT_BYTES {
            return Err(funding_denied());
        }
        let fd = secure_open_at(
            &self.root,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        let mut file = File::from(fd);
        file.write_all(bytes)?;
        file.sync_all()?;
        self.root.sync_all()?;
        Ok(())
    }
    fn read_campaign_enrollment_locked(&self) -> Result<CampaignFundingEnrollmentV1, PolicyError> {
        let bytes = self.read_campaign_entry(ENROLLMENT)?;
        let value = recursive_agent_contracts::parse_strict_json_value(&bytes)
            .map_err(|_| funding_denied())?;
        let record: CampaignFundingEnrollmentV1 = serde_json::from_value(value)?;
        record.grant.validate_structure()?;
        if record.schema != ENROLLMENT_SCHEMA
            || record.authority_root_device != self.root_device
            || record.authority_root_inode != self.root_inode
            || record.enrolled_at < record.grant.not_before
            || record.enrolled_at >= record.grant.expires_at
            || jcs_canonical(&record)? != bytes
            || self.read_campaign_entry(ANCHOR)? != jcs_canonical(&content_digest(&record)?)?
        {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(record)
    }
}
