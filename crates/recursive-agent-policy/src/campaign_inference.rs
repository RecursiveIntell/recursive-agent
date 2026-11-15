//! Explicit V2 monetary accounting at the enrolled original family. No egress.
use super::*;
const SCHEMA_V2: &str = "recursive-agent.campaign-inference-budget/v2";
pub(super) const STATE_V2: &str = "inference-budget.v2.json";

/// Borrowed owner composition input, not a serialized grant or send capability.
/// The referenced native funding capability and exact owners are checked afresh.
pub struct CampaignInferenceContextV2<'a> {
    pub grants: &'a NormalChatEgressGrantStore,
    pub funding: &'a CampaignFundingAuthorityV1,
    pub authority: &'a NormalChatGrantAuthorityV1,
    pub terms: &'a InferenceBudgetTermsV1,
}
/// Runtime-only settlement handle. Never permission to send or retry.
/// ```compile_fail
/// use recursive_agent_policy::CampaignInferenceTicketV2;
/// let _ = serde_json::from_str::<CampaignInferenceTicketV2>("{}");
/// ```
/// ```compile_fail
/// use recursive_agent_policy::CampaignInferenceTicketV2;
/// fn duplicate(ticket: CampaignInferenceTicketV2) { let _ = ticket.clone(); }
/// ```
#[derive(Debug)]
pub struct CampaignInferenceTicketV2 {
    root: Arc<File>,
    association_digest: ContentDigest,
    request: InferenceSendRequestV1,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignInferenceStateV2 {
    schema: String,
    association_digest: ContentDigest,
    terms: InferenceBudgetTermsV1,
    sends: BTreeMap<CurrentPermitId, InferenceSendRecordV1>,
}
impl CampaignInferenceStateV2 {
    fn validate(
        &self,
        association: &CampaignMonetaryRootAssociationV1,
        grant: &CampaignFundingGrantV1,
    ) -> Result<InferenceBudgetStatusV1, PolicyError> {
        self.terms.validate()?;
        if self.schema != SCHEMA_V2
            || self.association_digest != content_digest(association)?
            || self.terms.computed_digest()? != association.terms_digest
        {
            return Err(invalid());
        }
        validate_inference_records(
            &InferenceRecordBounds {
                limits: self.terms.limits.clone(),
                provider: &self.terms.provider,
                model: &self.terms.model,
                reasoning_effort: &self.terms.reasoning_effort,
                not_before: association.bound_at,
                expires_at: grant.expires_at,
            },
            &self.sends,
        )
    }
    fn guard_time(&self, at: DateTime<Utc>) -> Result<(), PolicyError> {
        if self.sends.values().any(|record| {
            at < record.reserved_at || record.dispatched_at.is_some_and(|sent| at < sent)
        }) {
            return Err(invalid());
        }
        Ok(())
    }
    fn binding_bytes(&self) -> Result<Vec<u8>, PolicyError> {
        Ok(jcs_canonical(&(
            SCHEMA_V2,
            &self.association_digest,
            self.terms.computed_digest()?,
        ))?)
    }
}
impl FamilyAuthorityStore {
    pub(super) fn inference_path_exists(&self, name: &str) -> Result<bool, PolicyError> {
        match secure_open_at(
            &self.root,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    fn check_campaign_bank_root(
        &self,
        association: &CampaignMonetaryRootAssociationV1,
    ) -> Result<(), PolicyError> {
        let state = self.read_state()?;
        let permits = File::from(secure_open_at(
            &self.root,
            "permits",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let identity = directory_identity(&permits)?;
        let root = &association.root;
        if self.root_identity() != (root.family_root_device, root.family_root_inode)
            || (identity.0, identity.1) != (root.permit_root_device, root.permit_root_inode)
            || state.grant != root.family_grant
            || state.normal_chat_session.is_none()
        {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(())
    }
    fn with_campaign_current<T>(
        &self,
        context: &CampaignInferenceContextV2<'_>,
        clock: impl FnMut() -> DateTime<Utc>,
        inspect: impl FnOnce(
            &CampaignMonetaryRootAssociationV1,
            &CampaignFundingGrantV1,
            DateTime<Utc>,
        ) -> Result<T, PolicyError>,
    ) -> Result<T, PolicyError> {
        self.with_lock(|| {
            let (result, association) = context.grants.with_campaign_root_current(
                context,
                clock,
                |association, grant, at| {
                    self.check_campaign_bank_root(association)?;
                    Ok((inspect(association, grant, at)?, association.clone()))
                },
            )?;
            self.check_campaign_bank_root(&association)?;
            Ok(result)
        })
    }
    fn with_campaign_history<T>(
        &self,
        grants: &NormalChatEgressGrantStore,
        inspect: impl FnOnce(
            CampaignInferenceStateV2,
            &CampaignMonetaryRootAssociationV1,
            &CampaignFundingGrantV1,
        ) -> Result<T, PolicyError>,
    ) -> Result<T, PolicyError> {
        self.with_lock(|| {
            let state = self.read_campaign_bank()?;
            grants.with_campaign_root_history(&state.terms, |association, grant| {
                self.check_campaign_bank_root(association)?;
                state.validate(association, grant)?;
                inspect(state.clone(), association, grant)
            })
        })
    }
    /// Explicit one-time native accounting initialization, never startup fallback.
    /// Uses the same initialization fence as V1. No automatic migration/upgrade.
    pub fn bind_campaign_inference_budget(
        &self,
        context: &CampaignInferenceContextV2<'_>,
        clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<(), PolicyError> {
        self.with_campaign_current(context, clock, |association, grant, at| {
            if self.inference_path_exists(STATE_NAME)? {
                return Err(PolicyError::PermitStateConflict);
            }
            if self.inference_path_exists(STATE_V2)? {
                let state = self.read_campaign_bank()?;
                state.validate(association, grant)?;
                state.guard_time(at)?;
                return if state.terms == *context.terms {
                    Ok(())
                } else {
                    Err(PolicyError::PermitStateConflict)
                };
            }
            let state = CampaignInferenceStateV2 {
                schema: SCHEMA_V2.into(),
                association_digest: content_digest(association)?,
                terms: context.terms.clone(),
                sends: BTreeMap::new(),
            };
            state.validate(association, grant)?;
            let mut marker = File::from(secure_open_at(
                &self.root,
                BINDING_NAME,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )?);
            marker.write_all(&state.binding_bytes()?)?;
            marker.sync_all()?;
            self.root.sync_all()?;
            self.write_campaign_bank(&state, association, grant)
        })
    }
    /// Full conservative reservation; records are physical-attempt identities
    /// supplied by trusted native composition, NOT evidence of an issued permit.
    pub fn reserve_campaign_inference(
        &self,
        context: &CampaignInferenceContextV2<'_>,
        request: &InferenceSendRequestV1,
        clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<InferenceSendRecordV1, PolicyError> {
        self.with_campaign_current(context, clock, |association, grant, at| {
            let mut state = self.read_campaign_bank()?;
            state.validate(association, grant)?;
            state.guard_time(at)?;
            if let Some(existing) = state.sends.get(&request.permit_id) {
                return if existing.request == *request {
                    Ok(existing.clone())
                } else {
                    Err(PolicyError::PermitStateConflict)
                };
            }
            let record = InferenceSendRecordV1 {
                request: request.clone(),
                reserved_at: at,
                dispatched_at: None,
                settlement: None,
            };
            state
                .sends
                .insert(request.permit_id.clone(), record.clone());
            self.write_campaign_bank(&state, association, grant)?;
            Ok(record)
        })
    }
    /// Persist once-only budget handoff before control may reach a real send.
    /// This ticket is settlement-only; independent effect/ledger gates remain.
    pub fn begin_campaign_inference(
        &self,
        context: &CampaignInferenceContextV2<'_>,
        request: &InferenceSendRequestV1,
        clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<CampaignInferenceTicketV2, PolicyError> {
        self.with_campaign_current(context, clock, |association, grant, at| {
            let mut state = self.read_campaign_bank()?;
            state.validate(association, grant)?;
            state.guard_time(at)?;
            let record = state
                .sends
                .get_mut(&request.permit_id)
                .ok_or_else(invalid)?;
            if record.request != *request || record.dispatched_at.is_some() {
                return Err(PolicyError::PermitStateConflict);
            }
            record.dispatched_at = Some(at);
            self.write_campaign_bank(&state, association, grant)?;
            Ok(CampaignInferenceTicketV2 {
                root: Arc::clone(&self.root),
                association_digest: content_digest(association)?,
                request: request.clone(),
            })
        })
    }
    /// Immutable evidence only, permitted after funding expiry or revocation.
    pub fn settle_campaign_inference(
        &self,
        grants: &NormalChatEgressGrantStore,
        ticket: &CampaignInferenceTicketV2,
        outcome: InferenceSettlementV1,
    ) -> Result<(), PolicyError> {
        self.with_campaign_history(grants, |mut state, association, grant| {
            let identity = directory_identity(&ticket.root)?;
            if (identity.0, identity.1) != self.root_identity()
                || ticket.association_digest != state.association_digest
            {
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
            self.write_campaign_bank(&state, association, grant)
        })
    }
    /// Exact nonauthorizing readback. Never initializes state or recreates tickets.
    pub fn read_campaign_inference(
        &self,
        grants: &NormalChatEgressGrantStore,
        request: &InferenceSendRequestV1,
    ) -> Result<InferenceSendRecordV1, PolicyError> {
        self.with_campaign_history(grants, |state, _, _| {
            let record = state.sends.get(&request.permit_id).ok_or_else(invalid)?;
            if record.request != *request {
                return Err(PolicyError::PermitStateConflict);
            }
            Ok(record.clone())
        })
    }
    pub fn campaign_inference_status(
        &self,
        grants: &NormalChatEgressGrantStore,
    ) -> Result<InferenceBudgetStatusV1, PolicyError> {
        self.with_campaign_history(grants, |state, association, grant| {
            state.validate(association, grant)
        })
    }
    fn read_campaign_file(&self, name: &str) -> Result<Vec<u8>, PolicyError> {
        let file = File::from(secure_open_at(
            &self.root,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.len() > MAX_BYTES
            || metadata.mode() & 0o777 != 0o600
            || metadata.uid() != self.root.metadata()?.uid()
            || metadata.nlink() != 1
        {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(invalid());
        }
        Ok(bytes)
    }
    fn read_campaign_bank(&self) -> Result<CampaignInferenceStateV2, PolicyError> {
        if self.inference_path_exists(STATE_NAME)? {
            return Err(PolicyError::PermitStateConflict);
        }
        let bytes = self.read_campaign_file(STATE_V2)?;
        let state: CampaignInferenceStateV2 = serde_json::from_slice(&bytes)?;
        if jcs_canonical(&state)? != bytes
            || self.read_campaign_file(BINDING_NAME)? != state.binding_bytes()?
        {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(state)
    }
    fn write_campaign_bank(
        &self,
        state: &CampaignInferenceStateV2,
        association: &CampaignMonetaryRootAssociationV1,
        grant: &CampaignFundingGrantV1,
    ) -> Result<(), PolicyError> {
        state.validate(association, grant)?;
        if self.inference_path_exists(STATE_NAME)?
            || self.read_campaign_file(BINDING_NAME)? != state.binding_bytes()?
        {
            return Err(PolicyError::PermitStateConflict);
        }
        let bytes = jcs_canonical(state)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(invalid());
        }
        let (name, mut file) = create_unique_temp(&self.root, ".campaign-inference.tmp")?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        rustix::fs::renameat(self.root.as_fd(), &name, self.root.as_fd(), STATE_V2)
            .map_err(std::io::Error::from)?;
        self.root.sync_all()?;
        Ok(())
    }
}
