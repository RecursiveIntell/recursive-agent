//! Guard-bound source projection and one-shot owned terminal publication.
//! No grant/native transition or send; interrupted suffix recovery is separate.
use super::*;
use crate::{NormalChatSessionGateErrorV1, NormalChatSessionGateV1};
use recursive_agent_contracts::{
    derive_receipt_id, NormalChatDegradedChildRefV1, NormalChatSessionDegradationSchemaV1,
    NormalChatSessionDegradationV1, NormalChatUnknownSourceRefV1, ReceiptIdentityMaterialV1,
    NORMAL_CHAT_CHILD_OUTCOME_UNKNOWN_REASON_V1, NORMAL_CHAT_SESSION_CANCELLED_REASON_V1,
};
use recursive_agent_policy::{
    NormalChatSessionCloseV2, PermitRevocationReasonV1, PermitStateV1, PolicyError,
};
use thiserror::Error;
#[derive(Debug, Error)]
pub enum NormalChatSessionDegradationPreparationErrorV1 {
    #[error("degradation source: {0}")]
    Ledger(#[from] LedgerError),
    #[error("degradation gate: {0}")]
    Gate(#[from] NormalChatSessionGateErrorV1),
    #[error("degradation native pair: {0}")]
    Policy(#[from] PolicyError),
    #[error("degradation contract: {0}")]
    Contract(#[from] ContractError),
    #[error("degradation io: {0}")]
    Io(#[from] std::io::Error),
    #[error("degradation preparation rejected: {0}")]
    Invalid(&'static str),
}
type ErrorV1 = NormalChatSessionDegradationPreparationErrorV1;
/// Verified source projection before publication, not a finalized session or
/// send continuation. No native stores/files/family proof are exposed.
///
/// ```compile_fail
/// use recursive_agent_ledger::PreparedNormalChatSessionDegradationV1;
/// fn forge<'a>()->PreparedNormalChatSessionDegradationV1<'a>{PreparedNormalChatSessionDegradationV1{}}
/// ```
/// ```compile_fail
/// use recursive_agent_ledger::PreparedNormalChatSessionDegradationV1;
/// fn duplicate(p:PreparedNormalChatSessionDegradationV1<'_>){let _=p.clone();}
/// ```
/// ```compile_fail
/// use std::fs::File;
/// use recursive_agent_contracts::CurrentRunId;
/// use recursive_agent_ledger::{NormalChatSessionGateV1,prepare_normal_chat_session_degradation_from_runtime_root_fd};
/// fn release_early(out:&File,id:&CurrentRunId,gate:NormalChatSessionGateV1)->Result<(),Box<dyn std::error::Error>> {
/// let plan=prepare_normal_chat_session_degradation_from_runtime_root_fd(out,id,&gate)?;
/// gate.unlock()?;let _=plan.marker();Ok(())
/// }
/// ```
pub struct PreparedNormalChatSessionDegradationV1<'gate> {
    pub(super) family: VerifiedNormalChatClosedFamilyV1,
    gate: &'gate NormalChatSessionGateV1,
    closed: NormalChatSessionCloseV2,
    marker: NormalChatSessionDegradationV1,
    marker_bytes: Vec<u8>,
    marker_descriptor: ArtifactDescriptorV1,
    root_bytes: Vec<u8>,
    root_descriptor: ArtifactDescriptorV1,
    root_at: DateTime<Utc>,
    outcome: ReceiptOutcomeV1,
    projected_bytes: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalChatSessionPublicationInterruptionV1 {
    AfterRootArtifact,
    AfterMarkerArtifact,
    Receipt { ordinal: usize, stage: AppendStage },
}

impl<'gate> PreparedNormalChatSessionDegradationV1<'gate> {
    /// Publish this exact closed-source projection once. No grant, native
    /// transition, clock or send is created. Interrupted prefixes are retained
    /// and require separate scoped recovery; this initial API never repairs.
    pub fn publish(self) -> Result<super::VerifiedNormalChatDegradedSessionV1<'gate>, ErrorV1> {
        self.publish_with_interruption(None)
    }

    #[doc(hidden)]
    pub fn publish_with_interruption(
        self,
        fault: Option<NormalChatSessionPublicationInterruptionV1>,
    ) -> Result<super::VerifiedNormalChatDegradedSessionV1<'gate>, ErrorV1> {
        use NormalChatSessionPublicationInterruptionV1 as F;
        if matches!(
            fault,
            Some(
                F::Receipt { ordinal: 3.., .. }
                    | F::Receipt {
                        stage: AppendStage::ArtifactWrite,
                        ..
                    }
            )
        ) {
            return Err(ErrorV1::Invalid("invalid publication interruption"));
        }
        // Lock order: caller-held session gate -> short canonical native/child
        // reads (released) -> parent flock. Never invoke a family verifier or
        // native policy operation while holding the parent append flock.
        self.recheck()?;
        let store = &self.family.parent_store;
        if store.put(self.root_revocation_bytes(), "application/json", None)?
            != *self.root_revocation_descriptor()
        {
            return Err(ErrorV1::Invalid("published root descriptor differs"));
        }
        if fault == Some(F::AfterRootArtifact) {
            return Err(ErrorV1::Invalid(
                "publication interrupted after root artifact",
            ));
        }
        if store.put(self.marker_bytes(), "application/json", None)? != *self.marker_descriptor() {
            return Err(ErrorV1::Invalid("published marker descriptor differs"));
        }
        if fault == Some(F::AfterMarkerArtifact) {
            return Err(ErrorV1::Invalid(
                "publication interrupted after marker artifact",
            ));
        }
        let mut inventory = self.family.inventory.clone();
        inventory.extend([self.root_descriptor.clone(), self.marker_descriptor.clone()]);
        store.require_exact_inventory(&inventory)?;
        store.require_locator_matches(&self.family.parent.root)?;
        with_exclusive_lock(&self.family.parent.root, |root| {
            self.gate
                .check(root)
                .map_err(|e| invalid(&format!("publication gate changed: {e}")))?;
            let (mut scan, created_at) = reconcile_locked(root)?;
            if scan.receipts.as_slice() != self.family.parent_snapshot.receipts() {
                return Err(invalid("publication prefix changed"));
            }
            let mut drafts = vec![self.root_revocation_draft()];
            let mut marker = self.root_revocation_draft();
            marker.kind = ReceiptKindV1::NormalChatSessionDegradedV1;
            marker.valid_time = self.marker.finalized_at;
            marker.outcome = self.outcome.clone();
            marker.artifact_refs = vec![self.marker_descriptor.clone()];
            let mut final_row = self.root_revocation_draft();
            final_row.kind = ReceiptKindV1::RunFinalized;
            final_row.valid_time = self.marker.finalized_at;
            final_row.outcome = self.outcome.clone();
            final_row.artifact_refs.clear();
            drafts.extend([marker, final_row]);
            let mut head = scan.head.clone();
            let mut suffix = Vec::new();
            for draft in drafts {
                let row = make_receipt(draft, head)?;
                head = chain_digest_from_raw(&row.prev_chain_digest, &row.canonical_bytes()?)?;
                suffix.push(row);
            }
            if suffix[0].receipt_id != self.marker.root_revocation_receipt_id {
                return Err(invalid("publication root receipt differs"));
            }
            let mut proposed = scan.receipts.clone();
            proposed.extend(suffix.clone());
            // Private local validation is permitted only for the source-owned
            // projection, never a caller-authored receipt or skip-proof flag.
            validate_local_authoritative_sequence(
                root,
                &proposed,
                LifecycleValidationMode::StrictCurrent,
            )?;
            for (ordinal, row) in suffix.into_iter().enumerate() {
                let interrupt = match fault {
                    Some(F::Receipt {
                        ordinal: selected,
                        stage,
                    }) if selected == ordinal => Some(stage),
                    _ => None,
                };
                scan = persist_validated_receipt_locked(root, scan, row, created_at, interrupt)?;
            }
            Ok(())
        })?;
        // Return only a newly joined strict native-family proof. An append or
        // fsync acknowledgement alone is not terminal acceptance.
        super::verify_degraded_normal_chat_session_from_runtime_root_fd(
            &self.family.output,
            self.family.parent_run_id(),
            self.gate,
        )
    }

    pub fn marker(&self) -> &NormalChatSessionDegradationV1 {
        &self.marker
    }
    pub fn marker_bytes(&self) -> &[u8] {
        &self.marker_bytes
    }
    pub fn marker_descriptor(&self) -> &ArtifactDescriptorV1 {
        &self.marker_descriptor
    }
    pub fn root_revocation_bytes(&self) -> &[u8] {
        &self.root_bytes
    }
    pub fn root_revocation_descriptor(&self) -> &ArtifactDescriptorV1 {
        &self.root_descriptor
    }
    pub fn outcome(&self) -> &ReceiptOutcomeV1 {
        &self.outcome
    }
    pub fn projected_artifact_bytes(&self) -> u64 {
        self.projected_bytes
    }
    pub fn artifact_ceiling(&self) -> u64 {
        self.family
            .root_record
            .permit
            .binding
            .budget
            .max_artifact_bytes
    }
    pub fn root_revocation_draft(&self) -> ReceiptDraftV1 {
        root_draft(&self.family, self.root_at, self.root_descriptor.clone())
    }
    /// No clock/create/repair of authority; appendable source checks can still
    /// reconcile ledger metadata. This is not forensic byte immutability.
    pub fn recheck(&self) -> Result<(), ErrorV1> {
        self.gate.check(&self.family.parent.root)?;
        self.family.recheck()?;
        if self
            .family
            .parent_policy
            .confirm_closed_normal_chat_session_v2(
                &self.family.family,
                &self.family.context,
                &self.closed,
            )?
            != self.closed
        {
            return Err(ErrorV1::Invalid("closed pair changed"));
        }
        self.gate.check(&self.family.parent.root)?;
        self.family.parent.check(&self.family.output)?;
        Ok(())
    }
}
fn root_draft(
    family: &VerifiedNormalChatClosedFamilyV1,
    at: DateTime<Utc>,
    descriptor: ArtifactDescriptorV1,
) -> ReceiptDraftV1 {
    let root = &family.root_record.permit;
    ReceiptDraftV1 {
        run_id: root.binding.run_id.clone(),
        step_id: root.binding.step_id.clone(),
        kind: ReceiptKindV1::PermitRevoked,
        valid_time: at,
        lineage: build_lineage(&root.permit_id, &root.binding.policy_version),
        spec_digest: root.binding.action_digest.clone(),
        args_digest: root.binding.args_digest.clone(),
        artifact_refs: vec![descriptor],
        outcome: ReceiptOutcomeV1::Ok,
    }
}
fn aggregate<'a>(
    descriptors: impl IntoIterator<Item = &'a ArtifactDescriptorV1>,
    ceiling: u64,
) -> Result<u64, ErrorV1> {
    let mut unique = BTreeMap::new();
    for d in descriptors {
        if let Some(prior) = unique.insert(d.digest.clone(), d) {
            if prior != d {
                return Err(ErrorV1::Invalid("conflicting duplicate descriptor"));
            }
        }
    }
    let total = unique
        .values()
        .try_fold(0u64, |n, d| n.checked_add(d.byte_length))
        .ok_or(ErrorV1::Invalid("artifact byte overflow"))?;
    if total > ceiling {
        return Err(ErrorV1::Invalid("parent artifact ceiling exceeded"));
    }
    Ok(total)
}
pub fn prepare_normal_chat_session_degradation_from_runtime_root_fd<'g>(
    output: &File,
    parent_id: &CurrentRunId,
    gate: &'g NormalChatSessionGateV1,
) -> Result<PreparedNormalChatSessionDegradationV1<'g>, ErrorV1> {
    prepare_normal_chat_session_degradation_from_runtime_root_fd_with_observer(
        output,
        parent_id,
        gate,
        || {},
    )
}
#[doc(hidden)]
pub fn prepare_normal_chat_session_degradation_from_runtime_root_fd_with_observer<'g>(
    output: &File,
    parent_id: &CurrentRunId,
    gate: &'g NormalChatSessionGateV1,
    before_return: impl FnOnce(),
) -> Result<PreparedNormalChatSessionDegradationV1<'g>, ErrorV1> {
    let output = output.try_clone()?;
    let identity = run_root_identity(&output)?;
    let parent = RunPin::open(&output, parent_id)?;
    gate.check(&parent.root)?;
    let family = verify_family_from_pins(
        output,
        identity,
        parent,
        parent_id,
        ParentReadV1::Pristine,
        |root| {
            gate.check(root)
                .map_err(|e| invalid(&format!("borrowed gate changed: {e}")))
        },
        before_return,
    )?;
    prepare_verified_family(family, gate)
}
// Private owner composition, never a public candidate/checked override.
pub(super) fn prepare_verified_family<'g>(
    family: VerifiedNormalChatClosedFamilyV1,
    gate: &'g NormalChatSessionGateV1,
) -> Result<PreparedNormalChatSessionDegradationV1<'g>, ErrorV1> {
    gate.check(&family.parent.root)?;
    if family.unknown_child_count() == 0 && family.interrupted_child_count() == 0 {
        return Err(ErrorV1::Invalid("no actual unknown child"));
    }
    let closed = NormalChatSessionCloseV2 {
        snapshot: family.native_snapshot.clone(),
        root_control: family.root_record.clone(),
    };
    family.parent_policy.confirm_closed_normal_chat_session_v2(
        &family.family,
        &family.context,
        &closed,
    )?;
    let (root_at, reason) = match &family.root_record.state {
        PermitStateV1::Revoked { revoked_at, reason } => (*revoked_at, reason),
        _ => return Err(ErrorV1::Invalid("native root not closed")),
    };
    let outcome = if family.native_snapshot.admission.parent_revoked_at.is_some()
        || matches!(
            reason,
            PermitRevocationReasonV1::ParentRevoked | PermitRevocationReasonV1::OperationCancelled
        ) {
        ReceiptOutcomeV1::Cancelled {
            reason: NORMAL_CHAT_SESSION_CANCELLED_REASON_V1.into(),
        }
    } else if *reason == PermitRevocationReasonV1::PolicySuperseded {
        ReceiptOutcomeV1::Denied
    } else {
        ReceiptOutcomeV1::Failed {
            reason: if family.unknown_child_count() > 0 {
                NORMAL_CHAT_CHILD_OUTCOME_UNKNOWN_REASON_V1
            } else {
                recursive_agent_contracts::NORMAL_CHAT_CHILD_ADMISSION_INTERRUPTED_REASON_V1
            }
            .into(),
        }
    };
    let root_bytes = jcs_canonical(&PermitEvidenceV1::from_record(&family.root_record)?)?;
    let root_descriptor = describe(&root_bytes)?;
    let draft = root_draft(&family, root_at, root_descriptor.clone());
    let predecessor = ContentDigest::from_hex(family.parent_chain_head())
        .map_err(|_| ErrorV1::Invalid("invalid verified prefix head"))?;
    let revoke_id = derive_receipt_id(&ReceiptIdentityMaterialV1 {
        run_id: &draft.run_id,
        step_id: &draft.step_id,
        kind: &draft.kind,
        lineage: &draft.lineage,
        spec_digest: &draft.spec_digest,
        args_digest: &draft.args_digest,
        outcome: &draft.outcome,
        artifact_refs: &draft.artifact_refs,
        predecessor_chain_digest: &predecessor,
    })?;
    let family_closed_at = family
        .native_snapshot
        .admission
        .closed_at
        .ok_or(ErrorV1::Invalid("native family not closed"))?;
    let mut at = std::cmp::max(root_at, family_closed_at);
    if let Some(t) = family.native_snapshot.admission.parent_revoked_at {
        at = std::cmp::max(at, t);
    }
    let mut children = Vec::new();
    for (group, child) in family.parent_snapshot.receipts()[3..]
        .chunks_exact(3)
        .zip(&family.children)
    {
        at = std::cmp::max(at, child.terminal_receipt().valid_time);
        let unknown_source = match child.disposition() {
            VerifiedNormalChatDispositionV1::MissingExecutorOutcome => {
                Some(NormalChatUnknownSourceRefV1::MissingExecutorOutcomeV1 {
                    evidence: child.source_artifacts()[0].clone(),
                })
            }
            VerifiedNormalChatDispositionV1::Reported(
                NormalChatReportedStateV2::OutcomeUnknown,
            ) => Some(NormalChatUnknownSourceRefV1::ReportedUnknownV2 {
                evidence: child.source_artifacts().to_vec(),
            }),
            VerifiedNormalChatDispositionV1::AdmissionInterruptedBeforeRelease => Some(
                NormalChatUnknownSourceRefV1::ConsumedAdmissionInterruptedV2 {
                    evidence: child.source_artifacts()[0].clone(),
                },
            ),
            VerifiedNormalChatDispositionV1::UnconsumedAdmissionInterrupted => Some(
                NormalChatUnknownSourceRefV1::UnconsumedAdmissionInterruptedV1 {
                    evidence: child.source_artifacts()[0].clone(),
                },
            ),
            VerifiedNormalChatDispositionV1::PreparedAdmissionInterrupted => Some(
                NormalChatUnknownSourceRefV1::PreparedAdmissionInterruptedV1 {
                    evidence: child.source_artifacts()[0].clone(),
                },
            ),
            _ => None,
        };
        children.push(NormalChatDegradedChildRefV1 {
            prepared_receipt_id: group[0].receipt_id.clone(),
            linked_receipt_id: group[1].receipt_id.clone(),
            closed_receipt_id: group[2].receipt_id.clone(),
            child_run_id: child.run_id().clone(),
            child_terminal_receipt_id: child.terminal_receipt().receipt_id.clone(),
            child_chain_head: ContentDigest::from_hex(child.chain_head())
                .map_err(|_| ErrorV1::Invalid("invalid verified child head"))?,
            child_closed_artifact: group[2].artifact_refs[0].clone(),
            unknown_source,
        });
    }
    let root = &family.root_record.permit;
    let marker = NormalChatSessionDegradationV1 {
        schema: if family.unknown_child_count() > 0 {
            NormalChatSessionDegradationSchemaV1::V1
        } else {
            NormalChatSessionDegradationSchemaV1::KnownInterruptedV1
        },
        parent_run_id: root.binding.run_id.clone(),
        root_step_id: root.binding.step_id.clone(),
        root_permit_id: root.permit_id.clone(),
        root_revocation_receipt_id: revoke_id,
        root_revocation_evidence: root_descriptor.clone(),
        family_closed_at,
        family_parent_revoked_at: family.native_snapshot.admission.parent_revoked_at,
        finalized_at: at,
        children,
    };
    marker.validate()?;
    let marker_bytes = jcs_canonical(&marker)?;
    let marker_descriptor = describe(&marker_bytes)?;
    let projected_bytes = aggregate(
        family
            .inventory
            .iter()
            .chain([&root_descriptor, &marker_descriptor]),
        root.binding.budget.max_artifact_bytes,
    )?;
    let plan = PreparedNormalChatSessionDegradationV1 {
        family,
        gate,
        closed,
        marker,
        marker_bytes,
        marker_descriptor,
        root_bytes,
        root_descriptor,
        root_at,
        outcome,
        projected_bytes,
    };
    plan.recheck()?;
    Ok(plan)
}
#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn aggregate_counts_unique_payloads_and_exact_ceiling() -> TestResult {
        let a = describe(b"abc")?;
        let b = describe(b"de")?;
        assert_eq!(aggregate([&a, &a, &b], 5)?, 5);
        assert!(matches!(
            aggregate([&a, &b], 4),
            Err(ErrorV1::Invalid("parent artifact ceiling exceeded"))
        ));
        Ok(())
    }
    #[test]
    fn aggregate_rejects_conflicting_duplicate_sizes_and_checked_overflow() -> TestResult {
        let a = describe(b"a")?;
        let mut changed = a.clone();
        changed.byte_length += 1;
        assert!(matches!(
            aggregate([&a, &changed], u64::MAX),
            Err(ErrorV1::Invalid("conflicting duplicate descriptor"))
        ));
        let mut huge = describe(b"b")?;
        huge.byte_length = u64::MAX;
        assert!(matches!(
            aggregate([&a, &huge], u64::MAX),
            Err(ErrorV1::Invalid("artifact byte overflow"))
        ));
        Ok(())
    }
}
