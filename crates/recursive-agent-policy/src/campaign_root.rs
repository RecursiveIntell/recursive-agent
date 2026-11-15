//! One immutable funding-to-real-family association. No money ledger or egress.
use super::*;
use recursive_agent_contracts::NormalChatSessionV1;
use std::cell::Cell;

const ROOT_SCHEMA: &str = "recursive-agent.campaign-monetary-root/v1";
const ROOT_RECORD: &str = "campaign-monetary-root.v1.json";
const ROOT_ANCHOR: &str = ".campaign-monetary-root.enrolled.v1";

/// Owner-derived identity of an already issued normal-chat family. Historical
/// projection only; cannot instantiate a controlled family or execution permit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignFamilyAnchorV1 {
    pub family_grant: FamilyRootGrantV1,
    pub session: NormalChatSessionV1,
    pub family_root_device: u64,
    pub family_root_inode: u64,
    pub permit_root_device: u64,
    pub permit_root_inode: u64,
}

/// Exact retained topology, not a monetary reservation or long-lived control.
/// The original short execution lease remains unchanged.
///
/// ```compile_fail
/// use recursive_agent_policy::CampaignMonetaryRootAssociationV1;
/// fn send(record: CampaignMonetaryRootAssociationV1) { record.begin_inference(); }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignMonetaryRootAssociationV1 {
    pub schema: String,
    pub funding_enrollment_digest: ContentDigest,
    pub terms_digest: ContentDigest,
    pub root: CampaignFamilyAnchorV1,
    pub bound_at: DateTime<Utc>,
}

impl NormalChatEgressGrantStore {
    /// Native accounting composition, called only beneath the family lock.
    pub(crate) fn with_campaign_root_current<T>(
        &self,
        context: &CampaignInferenceContextV2<'_>,
        clock: impl FnMut() -> DateTime<Utc>,
        inspect: impl FnOnce(
            &CampaignMonetaryRootAssociationV1,
            &CampaignFundingGrantV1,
            DateTime<Utc>,
        ) -> Result<T, PolicyError>,
    ) -> Result<T, PolicyError> {
        // The context cannot redirect a receiver to another authority owner.
        if self.root_device != context.grants.root_device
            || self.root_inode != context.grants.root_inode
        {
            return Err(PolicyError::PermitStateConflict);
        }
        self.with_current_campaign_funding(
            context.funding,
            context.authority,
            clock,
            |grant, at| {
                validate_campaign_terms(grant, context.terms)?;
                let association = self.read_campaign_root_locked()?;
                if at < association.bound_at {
                    return Err(funding_denied());
                }
                inspect(&association, grant, at)
            },
        )
    }
    /// Historical composition never reloads authority or initializes state.
    pub(crate) fn with_campaign_root_history<T>(
        &self,
        terms: &InferenceBudgetTermsV1,
        inspect: impl FnOnce(
            &CampaignMonetaryRootAssociationV1,
            &CampaignFundingGrantV1,
        ) -> Result<T, PolicyError>,
    ) -> Result<T, PolicyError> {
        self.with_lock(|| {
            let association = self.read_campaign_root_locked()?;
            let enrollment = self.read_campaign_enrollment_locked()?;
            validate_campaign_terms(&enrollment.grant, terms)?;
            inspect(&association, &enrollment.grant)
        })
    }

    /// Explicit trusted composition only. The controlled family proves its real
    /// native-issued control and pinned stores. Serialized grants/IDs cannot be
    /// supplied in its place. Lock order: family -> permit -> funding grant.
    /// No bank is initialized and no execution or network capability is returned.
    pub fn bind_campaign_monetary_root(
        &self,
        funding: &CampaignFundingAuthorityV1,
        authority: &NormalChatGrantAuthorityV1,
        terms: &InferenceBudgetTermsV1,
        family: &NormalChatControlledFamilyV1,
        mut trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<CampaignMonetaryRootAssociationV1, PolicyError> {
        let previous = Cell::new(None);
        let regressed = Cell::new(false);
        let mut clock = || {
            let now = trusted_clock();
            if previous.get().is_some_and(|last| now < last) {
                regressed.set(true);
            }
            previous.set(Some(now));
            now
        };
        let mut result = None;
        family.with_campaign_root_witness(authority, &mut clock, |root, clock| {
            self.with_current_campaign_funding(funding, authority, clock, |grant, at| {
                if regressed.get() {
                    return Err(funding_denied());
                }
                validate_campaign_terms(grant, terms)?;
                let enrollment = self.read_campaign_enrollment_locked()?;
                let funding_enrollment_digest = content_digest(&enrollment)?;
                if self.campaign_entry_exists(ROOT_RECORD)?
                    || self.campaign_entry_exists(ROOT_ANCHOR)?
                {
                    let existing = self.read_campaign_root_locked()?;
                    if existing.root != root
                        || existing.funding_enrollment_digest != funding_enrollment_digest
                        || existing.terms_digest != terms.computed_digest()?
                        || existing.bound_at > at
                    {
                        return Err(PolicyError::PermitStateConflict);
                    }
                    result = Some(existing);
                    return Ok(());
                }
                let record = CampaignMonetaryRootAssociationV1 {
                    schema: ROOT_SCHEMA.into(),
                    funding_enrollment_digest,
                    terms_digest: terms.computed_digest()?,
                    root,
                    bound_at: at,
                };
                // The write-once fence is durable first. Missing/partial history
                // never authorizes another root or automatic initialization.
                self.write_campaign_entry(ROOT_ANCHOR, &jcs_canonical(&content_digest(&record)?)?)?;
                self.write_campaign_entry(ROOT_RECORD, &jcs_canonical(&record)?)?;
                if self.read_campaign_root_locked()? != record {
                    return Err(PolicyError::PermitStateConflict);
                }
                result = Some(record);
                Ok(())
            })
        })?;
        if regressed.get() {
            return Err(funding_denied());
        }
        result.ok_or_else(funding_denied)
    }

    /// Read exact topology after expiry/revision change; never checks a fresh
    /// execution lease, loads a balance, initializes absent state or issues a
    /// capability. This alone does not prove the family directory still exists.
    pub fn read_campaign_monetary_root(
        &self,
    ) -> Result<CampaignMonetaryRootAssociationV1, PolicyError> {
        self.with_lock(|| self.read_campaign_root_locked())
    }

    fn read_campaign_root_locked(&self) -> Result<CampaignMonetaryRootAssociationV1, PolicyError> {
        let enrollment = self.read_campaign_enrollment_locked()?;
        let bytes = self.read_campaign_entry(ROOT_RECORD)?;
        let value = recursive_agent_contracts::parse_strict_json_value(&bytes)
            .map_err(|_| funding_denied())?;
        let record: CampaignMonetaryRootAssociationV1 = serde_json::from_value(value)?;
        record.root.family_grant.validate()?;
        record.root.session.validate()?;
        let grant = &enrollment.grant;
        let ceiling = &record.root.family_grant.child_run_ceiling;
        if record.schema != ROOT_SCHEMA
            || record.funding_enrollment_digest != content_digest(&enrollment)?
            || record.terms_digest != grant.budget_terms_digest
            || record.root.session.ares_home_digest != grant.ares_home_digest
            || record.root.session.policy_basis_digest != grant.egress_policy_digest
            || record.root.family_grant.root_operation_id != record.root.session.run_id()?
            || record.root.family_grant.policy_version
                != format!(
                    "normal-chat-grant:revision-{}",
                    record.root.session.grant_revision
                )
            || record.bound_at < enrollment.enrolled_at
            || record.bound_at >= grant.expires_at
            || record.bound_at < ceiling.not_before
            || record.bound_at >= ceiling.expires_at
            || jcs_canonical(&record)? != bytes
            || self.read_campaign_entry(ROOT_ANCHOR)? != jcs_canonical(&content_digest(&record)?)?
        {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(record)
    }
}
