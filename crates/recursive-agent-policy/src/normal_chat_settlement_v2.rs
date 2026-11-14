//! Atomic digest-only executor reports for already-consumed V2 attempts.
//!
//! These are local reported observations, not provider confirmation, replay,
//! ledger finalization, or permission to send. RuntimeService must persist the
//! canonical settlement as a metadata artifact and compose the ledger. Reported
//! unknown outcomes and violations close canonical admission before publication; a
//! failed close is not a confirmed fence and must quarantine the runtime lane.
use super::*;
use recursive_agent_contracts::{NormalChatAttemptIdV2, NormalChatAttemptV2};
use serde::{Deserialize, Serialize};

const MAX_EXECUTOR_REPORT_BYTES_V2: usize = 16_384;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatExecutorReportSchemaV2 {
    #[serde(rename = "recursive-agent.normal-chat-executor-report/v2")]
    V2,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalChatReportedStateV2 {
    Succeeded,
    Failed,
    Cancelled,
    Interrupted,
    TimedOut,
    NotSent,
    OutcomeUnknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatResponseProjectionV2 {
    #[serde(rename = "ares-response-json-sorted-v1")]
    AresResponseJsonSortedV1,
    /// SHA-256 of observed raw transport bytes before content decoding. This
    /// carries no sorted-JSON, provider-confirmation or response-replay claim.
    #[serde(rename = "ares.transport-response-body/v1")]
    AresTransportResponseBodyV1,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatResponseDigestV2 {
    pub projection_schema: NormalChatResponseProjectionV2,
    pub digest: String,
    pub byte_length: u64,
    pub complete: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatUsageSourceV2 {
    #[serde(rename = "provider_reported")]
    ProviderReported,
}
/// Unverified telemetry, never billing or independent token-count evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatUsageV2 {
    pub source: NormalChatUsageSourceV2,
    pub input_tokens: u32,
    pub output_tokens: u32,
}
/// Bounded metadata only; arbitrary error messages and raw content are absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatExecutorReportV2 {
    pub schema: NormalChatExecutorReportSchemaV2,
    pub state: NormalChatReportedStateV2,
    pub duration_ms: u64,
    pub response: Option<NormalChatResponseDigestV2>,
    pub usage: Option<NormalChatUsageV2>,
}
impl NormalChatExecutorReportV2 {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if let Some(response) = &self.response {
            let Some(hex) = response.digest.strip_prefix("sha256:") else {
                return Err(NormalChatEgressDenialV1::Malformed.into());
            };
            if hex.len() != 64
                || !hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || (response.byte_length == 0
                    && response.projection_schema
                        == NormalChatResponseProjectionV2::AresResponseJsonSortedV1)
            {
                return Err(NormalChatEgressDenialV1::Malformed.into());
            }
        }
        if self.state == NormalChatReportedStateV2::Succeeded
            && !self
                .response
                .as_ref()
                .is_some_and(|response| response.complete)
        {
            return Err(NormalChatEgressDenialV1::Malformed.into());
        }
        if self.state == NormalChatReportedStateV2::NotSent
            && (self.response.is_some() || self.usage.is_some() || self.duration_ms != 0)
        {
            return Err(NormalChatEgressDenialV1::Malformed.into());
        }
        // Exercise the canonical numeric boundary even for native constructors.
        let bytes = jcs_canonical(self)?;
        if bytes.len() > MAX_EXECUTOR_REPORT_BYTES_V2 {
            return Err(NormalChatEgressDenialV1::Malformed.into());
        }
        Ok(())
    }
    fn violations(&self, attempt: &NormalChatAttemptV2) -> Vec<NormalChatBoundViolationV2> {
        let mut violations = Vec::new();
        if self.duration_ms > attempt.operation.budget.max_wall_time_ms {
            violations.push(NormalChatBoundViolationV2::WallTime);
        }
        if self
            .usage
            .as_ref()
            .is_some_and(|usage| usage.output_tokens > attempt.operation.budget.output_reserve)
        {
            violations.push(NormalChatBoundViolationV2::OutputTokens);
        }
        violations
    }
    fn reported_effect(
        &self,
        violations: &[NormalChatBoundViolationV2],
    ) -> ReportedEffectOutcomeV1 {
        use NormalChatReportedStateV2 as S;
        let (state, error_type) = match self.state {
            S::OutcomeUnknown => (
                ReportedEffectStateV1::OutcomeAmbiguous,
                Some("NORMAL_CHAT_OUTCOME_UNKNOWN"),
            ),
            _ if !violations.is_empty() => (
                ReportedEffectStateV1::Failed,
                Some("NORMAL_CHAT_BOUND_EXCEEDED"),
            ),
            S::Succeeded => (ReportedEffectStateV1::Succeeded, None),
            S::Failed => (ReportedEffectStateV1::Failed, Some("NORMAL_CHAT_FAILED")),
            S::Cancelled => (ReportedEffectStateV1::Failed, Some("NORMAL_CHAT_CANCELLED")),
            S::Interrupted => (
                ReportedEffectStateV1::Failed,
                Some("NORMAL_CHAT_INTERRUPTED"),
            ),
            S::TimedOut => (ReportedEffectStateV1::Failed, Some("NORMAL_CHAT_TIMED_OUT")),
            S::NotSent => (ReportedEffectStateV1::Failed, Some("NORMAL_CHAT_NOT_SENT")),
        };
        ReportedEffectOutcomeV1 {
            state,
            duration_ms: self.duration_ms,
            error_type: error_type.map(str::to_owned),
        }
    }
}
/// Parse untrusted bytes without duplicate keys, unknown fields, or V1 fallback.
pub fn parse_normal_chat_executor_report_v2_bytes(
    input: &[u8],
) -> Result<NormalChatExecutorReportV2, PolicyError> {
    if input.len() > MAX_EXECUTOR_REPORT_BYTES_V2 {
        return Err(NormalChatEgressDenialV1::Malformed.into());
    }
    let value = recursive_agent_contracts::parse_strict_json_value(input)
        .map_err(|_| NormalChatEgressDenialV1::Malformed)?;
    jcs_canonical(&value)?;
    let report: NormalChatExecutorReportV2 = serde_json::from_value(value)?;
    report.validate()?;
    Ok(report)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalChatBoundViolationV2 {
    WallTime,
    OutputTokens,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatSettlementSchemaV2 {
    #[serde(rename = "recursive-agent.normal-chat-settlement/v2")]
    V2,
}
/// Canonical, secret-free metadata to be materialized by RuntimeService's
/// ArtifactStore. No descriptor or successful ledger claim is manufactured here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatSettlementV2 {
    pub schema: NormalChatSettlementSchemaV2,
    pub attempt_id: NormalChatAttemptIdV2,
    pub report: NormalChatExecutorReportV2,
    pub violations: Vec<NormalChatBoundViolationV2>,
    pub outcome: PermitOutcomeReceiptV1,
    pub settlement_digest: ContentDigest,
}
impl NormalChatSettlementV2 {
    /// The same durable fence is required for an explicit ambiguous outcome
    /// and for a reported bound violation. This does not synthesize recovery.
    fn requires_admission_fence(&self) -> bool {
        self.report.state == NormalChatReportedStateV2::OutcomeUnknown
            || !self.violations.is_empty()
    }

    fn computed_digest(&self) -> Result<ContentDigest, PolicyError> {
        Ok(content_digest(&(
            self.schema,
            &self.attempt_id,
            &self.report,
            &self.violations,
            &self.outcome,
        ))?)
    }
    pub(super) fn validate_for_attempt(
        &self,
        attempt: &NormalChatAttemptV2,
    ) -> Result<(), PolicyError> {
        self.report.validate()?;
        self.outcome.validate()?;
        let violations = self.report.violations(attempt);
        if self.attempt_id != attempt.attempt_id
            || self.violations != violations
            || self.outcome.reported != self.report.reported_effect(&violations)
            || self.settlement_digest != self.computed_digest()?
        {
            return Err(PolicyError::PermitStateConflict);
        }
        Ok(())
    }
}

/// Test interruptions for the two distinct durable owners. These hooks only
/// interrupt transitions; they cannot skip a required close or relax admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalChatSettlementInterruptionV2 {
    FamilyClose(PermitTransitionStage),
    ChildOutcome(PermitTransitionStage),
}

fn ensure_report_admission_fence(
    family: &FamilyAuthorityStore,
    settlement: &NormalChatSettlementV2,
    trusted_clock: &mut dyn FnMut() -> DateTime<Utc>,
    interrupt_after: Option<NormalChatSettlementInterruptionV2>,
) -> Result<(), PolicyError> {
    if !settlement.requires_admission_fence() {
        return Ok(());
    }
    let close_fault = match interrupt_after {
        Some(NormalChatSettlementInterruptionV2::FamilyClose(stage)) => Some(stage),
        _ => None,
    };
    family.close_normal_chat_session_for_report_v2(
        settlement.outcome.recorded_at,
        trusted_clock,
        close_fault,
    )
}

impl DurablePermitStore {
    /// Confirm only an exact existing settlement and its required durable
    /// admission fence. This historical path neither closes missing authority
    /// nor samples/assigns a new policy time. It is not runtime finalization.
    pub fn confirm_normal_chat_settlement_v2(
        &self,
        family: &FamilyAuthorityStore,
        intent: &str,
        preflight_digest: &ContentDigest,
        report: &NormalChatExecutorReportV2,
    ) -> Result<NormalChatSettlementV2, PolicyError> {
        report.validate()?;
        let reservation = family
            .read_normal_chat_reservation(intent)?
            .ok_or(NormalChatEgressDenialV1::Malformed)?;
        self.with_lock(|| {
            let view = self.read_normal_chat_attempt_snapshot_v2(&reservation)?;
            if view.state == NormalChatAttemptPolicyStateV2::RecoveredUnknown {
                return Err(PolicyError::PermitStateConflict);
            }
            let preflight = view
                .preflight
                .as_ref()
                .ok_or(PolicyError::PermitStateConflict)?;
            let existing = view
                .settlement
                .as_ref()
                .ok_or(PolicyError::PermitStateConflict)?;
            if preflight.receipt_digest != *preflight_digest || existing.report != *report {
                return Err(PolicyError::PermitStateConflict);
            }
            if existing.requires_admission_fence() {
                family.confirm_normal_chat_report_closed_v2()?;
            }
            self.root.sync_all()?;
            if self.read_normal_chat_attempt_snapshot_v2(&reservation)? != view {
                return Err(PolicyError::PermitStateConflict);
            }
            self.validate_v2_child_locator()?;
            Ok(existing.clone())
        })
    }

    /// Record an executor's report after consumption, even if authority is now
    /// expired/revoked. No fresh authority, refund, or transport continuation is
    /// produced. Runtime recovery must use its own distinct degradation record.
    pub fn settle_normal_chat_attempt_v2(
        &self,
        family: &FamilyAuthorityStore,
        intent: &str,
        preflight_digest: &ContentDigest,
        report: &NormalChatExecutorReportV2,
        trusted_clock: impl FnMut() -> DateTime<Utc>,
    ) -> Result<NormalChatSettlementV2, PolicyError> {
        self.settle_normal_chat_attempt_v2_with_interruption(
            family,
            intent,
            preflight_digest,
            report,
            trusted_clock,
            None,
        )
    }
    #[doc(hidden)]
    pub fn settle_normal_chat_attempt_v2_with_interruption(
        &self,
        family: &FamilyAuthorityStore,
        intent: &str,
        preflight_digest: &ContentDigest,
        report: &NormalChatExecutorReportV2,
        mut trusted_clock: impl FnMut() -> DateTime<Utc>,
        interrupt_after: Option<NormalChatSettlementInterruptionV2>,
    ) -> Result<NormalChatSettlementV2, PolicyError> {
        report.validate()?;
        let reservation = family
            .read_normal_chat_reservation(intent)?
            .ok_or(NormalChatEgressDenialV1::Malformed)?;
        self.with_lock(|| {
            let view = self.read_normal_chat_attempt_snapshot_v2(&reservation)?;
            if view.state == NormalChatAttemptPolicyStateV2::RecoveredUnknown {
                return Err(PolicyError::PermitStateConflict);
            }
            let preflight = view
                .preflight
                .as_ref()
                .ok_or(PolicyError::PermitStateConflict)?;
            if preflight.receipt_digest != *preflight_digest {
                return Err(PolicyError::PermitStateConflict);
            }
            if let Some(existing) = view.settlement {
                if existing.report != *report {
                    return Err(PolicyError::PermitStateConflict);
                }
                ensure_report_admission_fence(
                    family,
                    &existing,
                    &mut trusted_clock,
                    interrupt_after,
                )?;
                // Exact retry completes the durability fence after uncertain ACK.
                self.root.sync_all()?;
                self.validate_v2_child_locator()?;
                return Ok(existing);
            }
            let now = trusted_clock();
            if now < preflight.recorded_at {
                return Err(NormalChatEgressDenialV1::Malformed.into());
            }
            let mut record = self.read_record_or_reject(&preflight.permit_id)?;
            let violations = report.violations(&reservation.attempt);
            let outcome = PermitOutcomeReceiptV1::create(
                preflight.permit_id.clone(),
                preflight_digest.clone(),
                report.reported_effect(&violations),
                now,
            )?;
            let settlement_digest = content_digest(&(
                NormalChatSettlementSchemaV2::V2,
                &reservation.attempt.attempt_id,
                report,
                &violations,
                &outcome,
            ))?;
            let settlement = NormalChatSettlementV2 {
                schema: NormalChatSettlementSchemaV2::V2,
                attempt_id: reservation.attempt.attempt_id.clone(),
                report: report.clone(),
                violations,
                outcome: outcome.clone(),
                settlement_digest,
            };
            record.outcome_receipt = Some(outcome);
            record.normal_chat_attempt_v2 = Some(NormalChatAttemptRecordV2::Effect {
                settlement: Some(Box::new(settlement.clone())),
            });
            // Validate the complete candidate before any narrowing mutation.
            self.validate_record_bindings(&record)?;
            self.validate_v2_child_locator()?;
            // Child -> family lock order, matching Begin. Closure remains
            // durable if later child publication fails; never reopen/refund.
            ensure_report_admission_fence(
                family,
                &settlement,
                &mut trusted_clock,
                interrupt_after,
            )?;
            self.validate_v2_child_locator()?;
            let child_fault = match interrupt_after {
                Some(NormalChatSettlementInterruptionV2::ChildOutcome(stage)) => Some(stage),
                _ => None,
            };
            self.replace_record(&record, child_fault)?;
            let final_view = self.read_normal_chat_attempt_snapshot_v2(&reservation)?;
            if final_view.settlement.as_ref() != Some(&settlement) {
                return Err(PolicyError::PermitStateConflict);
            }
            self.validate_v2_child_locator()?;
            Ok(settlement)
        })
    }
}
