//! Candidate native conversation executor. Not registered with the daemon or
//! host. This records observed backend outcomes, not a full terminal run chain.
#[cfg(test)]
mod publication_tests;

use crate::Clock;
use recursive_agent_contracts::{
    content_digest, ArtifactDescriptorV1, CurrentPermitId, ToolCallSpecV1,
};
use recursive_agent_ledger::{ArtifactStore, LedgerError};
use recursive_agent_policy::{
    DurablePermitStore, NormalChatAdmissionVerifier, PermitOutcomeReceiptV1, PolicyError,
    ReportedEffectOutcomeV1, ReportedEffectStateV1, ValidatedNormalChatAdmissionV1,
};
use recursive_agent_provider::{
    CompletionBackend, ConversationRequestV1, ConversationRequestV2, ProviderError, ProviderSpecV1,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NativeNormalChatError {
    #[error("normal-chat request does not match admitted provider material")]
    RequestMismatch,
    #[error("normal-chat stores do not share one pinned run root")]
    StoreMismatch,
    #[error("normal-chat policy: {0}")]
    Policy(#[from] PolicyError),
    #[error("normal-chat artifact: {0}")]
    Artifact(#[from] LedgerError),
    #[error("normal-chat encoding failed")]
    Encoding,
    #[error("normal-chat publication binding invalid; consumed permit must not be retried")]
    PublicationInvalid,
    #[error("backend was invoked; settlement persistence failed; do not re-execute this permit")]
    SettlementPersistenceFailed(#[source] Box<PolicyError>),
    #[error("backend outcome is ambiguous; permit outcome retained")]
    BackendAmbiguous,
    #[error("observation publication failed; response and backend outcome retained; do not re-execute this permit")]
    ObservationPublicationFailed {
        response_artifact: Box<ArtifactDescriptorV1>,
        outcome: Box<PermitOutcomeReceiptV1>,
        #[source]
        source: Box<LedgerError>,
    },
    #[error("observation publication exceeds combined artifact budget: {required_bytes} > {maximum_bytes}; backend outcome retained")]
    ObservationBudgetExceeded {
        response_artifact: Box<ArtifactDescriptorV1>,
        outcome: Box<PermitOutcomeReceiptV1>,
        required_bytes: u64,
        maximum_bytes: u64,
    },
    #[error("backend was invoked; outcome persistence failed; do not re-execute this permit")]
    OutcomePersistenceFailed {
        permit_id: CurrentPermitId,
        preflight_receipt_digest: recursive_agent_contracts::ContentDigest,
        #[source]
        source: Box<PolicyError>,
    },
}

// Versioned data-plane record, not replay authority. Policy binds descriptors;
// no public historical loader is exposed. Legacy untagged artifacts are denied.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedNormalChatResponseV1 {
    schema: RecordedNormalChatResponseSchemaV1,
    attempt_id: recursive_agent_contracts::NormalChatAttemptId,
    permit_id: CurrentPermitId,
    preflight_receipt_digest: recursive_agent_contracts::ContentDigest,
    response: recursive_agent_provider::CompletionResponseV1,
}

#[derive(serde::Serialize, serde::Deserialize)]
enum RecordedNormalChatResponseSchemaV1 {
    #[serde(rename = "recursive-agent.normal-chat-recorded-response/v1")]
    V1,
}

#[derive(serde::Serialize, serde::Deserialize)]
enum RecordedNormalChatObservationSchemaV1 {
    #[serde(rename = "recursive-agent.normal-chat-observation/v1")]
    V1,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedNormalChatObservationV1 {
    schema: RecordedNormalChatObservationSchemaV1,
    attempt: recursive_agent_contracts::NormalChatAttemptId,
    response: ArtifactDescriptorV1,
    preflight: recursive_agent_policy::PermitPreflightReceiptV1,
    outcome: PermitOutcomeReceiptV1,
}

pub struct NativeNormalChatObservation {
    pub response_artifact: ArtifactDescriptorV1,
    pub outcome: PermitOutcomeReceiptV1,
    pub observation_artifact: ArtifactDescriptorV1,
}

/// Versioned provider requests that may enter the already-admitted native
/// normal-chat lifecycle. Request validation and provider/model binding stay
/// in the provider owner; this adapter only binds exact serialized arguments to
/// the existing policy and artifact owners.
trait BoundConversationRequest: serde::Serialize {
    fn validate(&self) -> Result<(), ProviderError>;
    fn provider(&self) -> &ProviderSpecV1;
    fn max_tokens(&self) -> Option<u32>;
}

impl BoundConversationRequest for ConversationRequestV1 {
    fn validate(&self) -> Result<(), ProviderError> {
        Self::validate(self)
    }

    fn provider(&self) -> &ProviderSpecV1 {
        &self.provider
    }

    fn max_tokens(&self) -> Option<u32> {
        self.max_tokens
    }
}

impl BoundConversationRequest for ConversationRequestV2 {
    fn validate(&self) -> Result<(), ProviderError> {
        Self::validate(self)
    }

    fn provider(&self) -> &ProviderSpecV1 {
        &self.provider
    }

    fn max_tokens(&self) -> Option<u32> {
        self.max_tokens
    }
}

/// Explicit composition only: no default provider, current-policy owner or store.
/// The backend must opt into structured conversations; default backends deny.
pub struct NativeNormalChatExecutor<'a, B> {
    permits: &'a DurablePermitStore,
    artifacts: &'a ArtifactStore,
    verifier: &'a dyn NormalChatAdmissionVerifier,
    clock: &'a dyn Clock,
    backend: &'a B,
}

impl<'a, B: CompletionBackend> NativeNormalChatExecutor<'a, B> {
    pub fn new(
        permits: &'a DurablePermitStore,
        artifacts: &'a ArtifactStore,
        verifier: &'a dyn NormalChatAdmissionVerifier,
        clock: &'a dyn Clock,
        backend: &'a B,
    ) -> Self {
        Self {
            permits,
            artifacts,
            verifier,
            clock,
            backend,
        }
    }

    // This adapter classifies a failed owner call; it does not manufacture a
    // receipt or recover/reissue authority when durability is unknown.
    fn record_post_backend_outcome(
        &self,
        permit_id: &CurrentPermitId,
        preflight_receipt_digest: &recursive_agent_contracts::ContentDigest,
        reported: ReportedEffectOutcomeV1,
        recorded_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<PermitOutcomeReceiptV1, NativeNormalChatError> {
        self.permits
            .record_reported_outcome(permit_id, preflight_receipt_digest, reported, recorded_at)
            .map_err(|source| NativeNormalChatError::OutcomePersistenceFailed {
                permit_id: permit_id.clone(),
                preflight_receipt_digest: preflight_receipt_digest.clone(),
                source: Box::new(source),
            })
    }

    pub fn execute(
        &self,
        permit_id: &CurrentPermitId,
        admission: &ValidatedNormalChatAdmissionV1,
        request: &ConversationRequestV1,
    ) -> Result<NativeNormalChatObservation, NativeNormalChatError> {
        self.execute_bound(permit_id, admission, request, |backend, request| {
            backend.complete_conversation(request)
        })
    }

    /// Execute the closed V2 structured conversation only through the same
    /// already-admitted normal-chat lifecycle. V2 is an explicit entry point:
    /// it never falls back to V1, and legacy backends remain fail-closed unless
    /// they opt into `CompletionBackend::complete_conversation_v2`.
    pub fn execute_v2(
        &self,
        permit_id: &CurrentPermitId,
        admission: &ValidatedNormalChatAdmissionV1,
        request: &ConversationRequestV2,
    ) -> Result<NativeNormalChatObservation, NativeNormalChatError> {
        self.execute_bound(permit_id, admission, request, |backend, request| {
            backend.complete_conversation_v2(request)
        })
    }

    fn execute_bound<R>(
        &self,
        permit_id: &CurrentPermitId,
        admission: &ValidatedNormalChatAdmissionV1,
        request: &R,
        dispatch: impl FnOnce(
            &B,
            &R,
        )
            -> Result<recursive_agent_provider::CompletionResponseV1, ProviderError>,
    ) -> Result<NativeNormalChatObservation, NativeNormalChatError>
    where
        R: BoundConversationRequest,
    {
        let artifact_root = self.artifacts.run_root_identity();
        if self.permits.run_root_identity() != (artifact_root.device, artifact_root.inode) {
            return Err(NativeNormalChatError::StoreMismatch);
        }
        request
            .validate()
            .map_err(|_| NativeNormalChatError::RequestMismatch)?;
        let attempt = admission.attempt();
        if content_digest(request).map_err(|_| NativeNormalChatError::Encoding)?
            != attempt.provider_request_digest
            || !request.provider().matches_egress_binding(
                &attempt.operation.provider_identity,
                &attempt.operation.model_ref,
            )
            || request.max_tokens() != Some(attempt.operation.budget.output_reserve)
        {
            return Err(NativeNormalChatError::RequestMismatch);
        }
        let call = ToolCallSpecV1 {
            tool: "normal_chat".into(),
            args: serde_json::json!({"attempt": attempt, "request": request}),
            frozen_clock: None,
        };
        let (evidence, continuation) = self.permits.consume_normal_chat_for_execution(
            permit_id,
            admission,
            &call,
            self.verifier,
            || self.clock.now(),
        )?;
        let preflight = self.permits.normal_chat_preflight(permit_id)?;
        let start = std::time::Instant::now();
        let response = dispatch(self.backend, request);
        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let response = match response {
            Ok(value) => value,
            Err(_) => {
                self.record_post_backend_outcome(
                    permit_id,
                    &preflight.receipt_digest,
                    ReportedEffectOutcomeV1 {
                        state: ReportedEffectStateV1::OutcomeAmbiguous,
                        duration_ms,
                        error_type: Some("conversation_backend_error".into()),
                    },
                    self.clock.now(),
                )?;
                return Err(NativeNormalChatError::BackendAmbiguous);
            }
        };
        let recorded_response = RecordedNormalChatResponseV1 {
            schema: RecordedNormalChatResponseSchemaV1::V1,
            attempt_id: attempt.attempt_id.clone(),
            permit_id: permit_id.clone(),
            preflight_receipt_digest: preflight.receipt_digest.clone(),
            response: response.clone(),
        };
        let encoded = recursive_agent_contracts::jcs_canonical(&recorded_response)
            .map_err(|_| NativeNormalChatError::Encoding)?;
        if u64::try_from(encoded.len()).unwrap_or(u64::MAX)
            > evidence.binding.budget.max_artifact_bytes
            || u64::try_from(response.text.len()).unwrap_or(u64::MAX)
                > evidence.binding.budget.max_output_bytes
            || duration_ms > evidence.binding.budget.max_wall_time_ms
        {
            self.record_post_backend_outcome(
                permit_id,
                &preflight.receipt_digest,
                ReportedEffectOutcomeV1 {
                    state: ReportedEffectStateV1::OutcomeAmbiguous,
                    duration_ms,
                    error_type: Some("conversation_result_budget_exceeded".into()),
                },
                self.clock.now(),
            )?;
            return Err(NativeNormalChatError::BackendAmbiguous);
        }
        let response_artifact = match self.artifacts.put(&encoded, "application/json", None) {
            Ok(artifact) => artifact,
            Err(error) => {
                // The backend already ran. Failure to retain its response is
                // not evidence of no effect and must never authorize a retry.
                self.record_post_backend_outcome(
                    permit_id,
                    &preflight.receipt_digest,
                    ReportedEffectOutcomeV1 {
                        state: ReportedEffectStateV1::OutcomeAmbiguous,
                        duration_ms,
                        error_type: Some("conversation_response_storage_failed".into()),
                    },
                    self.clock.now(),
                )?;
                return Err(NativeNormalChatError::Artifact(error));
            }
        };
        let outcome = self.record_post_backend_outcome(
            permit_id,
            &preflight.receipt_digest,
            ReportedEffectOutcomeV1 {
                state: ReportedEffectStateV1::Succeeded,
                duration_ms,
                error_type: None,
            },
            self.clock.now(),
        )?;
        let observation = RecordedNormalChatObservationV1 {
            schema: RecordedNormalChatObservationSchemaV1::V1,
            attempt: attempt.attempt_id.clone(),
            response: response_artifact.clone(),
            preflight,
            outcome: outcome.clone(),
        };
        let encoded_observation = recursive_agent_contracts::jcs_canonical(&observation)
            .map_err(|_| NativeNormalChatError::Encoding)?;
        let required_bytes = response_artifact
            .byte_length
            .checked_add(u64::try_from(encoded_observation.len()).unwrap_or(u64::MAX));
        let maximum_bytes = evidence.binding.budget.max_artifact_bytes;
        if required_bytes.map_or(true, |required| required > maximum_bytes) {
            return Err(NativeNormalChatError::ObservationBudgetExceeded {
                response_artifact: Box::new(response_artifact),
                outcome: Box::new(outcome),
                required_bytes: required_bytes.unwrap_or(u64::MAX),
                maximum_bytes,
            });
        }
        let observation_artifact =
            match self
                .artifacts
                .put(&encoded_observation, "application/json", None)
            {
                Ok(artifact) => artifact,
                Err(source) => {
                    return Err(NativeNormalChatError::ObservationPublicationFailed {
                        response_artifact: Box::new(response_artifact),
                        outcome: Box::new(outcome),
                        source: Box::new(source),
                    });
                }
            };
        validate_publication(
            self.permits,
            self.artifacts,
            permit_id,
            &response_artifact,
            &observation_artifact,
        )?;
        self.permits
            .settle_normal_chat(&continuation, &response_artifact, &observation_artifact)
            .map_err(|e| NativeNormalChatError::SettlementPersistenceFailed(Box::new(e)))?;
        load_live_settlement(self.permits, self.artifacts, permit_id)
    }
}

// Private live readback only. A future historical access API needs its own
// owner authorization; neither settlement nor an artifact hash grants that.
fn load_live_settlement(
    permits: &DurablePermitStore,
    artifacts: &ArtifactStore,
    permit_id: &CurrentPermitId,
) -> Result<NativeNormalChatObservation, NativeNormalChatError> {
    let record = permits.state(permit_id)?;
    let settlement = record
        .normal_chat_settlement
        .ok_or(NativeNormalChatError::PublicationInvalid)?;
    validate_publication(
        permits,
        artifacts,
        permit_id,
        &settlement.response,
        &settlement.observation,
    )
}

fn decode_record<T: serde::de::DeserializeOwned + serde::Serialize>(
    bytes: &[u8],
) -> Result<T, NativeNormalChatError> {
    let value = recursive_agent_contracts::parse_strict_json_value(bytes)
        .map_err(|_| NativeNormalChatError::PublicationInvalid)?;
    let decoded: T =
        serde_json::from_value(value).map_err(|_| NativeNormalChatError::PublicationInvalid)?;
    if recursive_agent_contracts::jcs_canonical(&decoded)
        .map_err(|_| NativeNormalChatError::PublicationInvalid)?
        != bytes
    {
        return Err(NativeNormalChatError::PublicationInvalid);
    }
    Ok(decoded)
}

// Caller descriptors occur only on the just-executed native publication path.
// Live readback above supplies descriptors solely from the policy record.
fn validate_publication(
    permits: &DurablePermitStore,
    artifacts: &ArtifactStore,
    permit_id: &CurrentPermitId,
    response_descriptor: &ArtifactDescriptorV1,
    observation_descriptor: &ArtifactDescriptorV1,
) -> Result<NativeNormalChatObservation, NativeNormalChatError> {
    let root = artifacts.run_root_identity();
    if permits.run_root_identity() != (root.device, root.inode) {
        return Err(NativeNormalChatError::StoreMismatch);
    }
    let invalid = || NativeNormalChatError::PublicationInvalid;
    let record = permits.state(permit_id)?;
    let admission = record
        .retained_normal_chat_admission
        .as_ref()
        .ok_or_else(invalid)?;
    let preflight = record.preflight_receipt.as_ref().ok_or_else(invalid)?;
    let outcome = record.outcome_receipt.as_ref().ok_or_else(invalid)?;
    let budget = &record.permit.binding.budget;
    if outcome.reported.state != ReportedEffectStateV1::Succeeded
        || outcome.reported.duration_ms > budget.max_wall_time_ms
        || response_descriptor
            .byte_length
            .checked_add(observation_descriptor.byte_length)
            .map_or(true, |bytes| bytes > budget.max_artifact_bytes)
    {
        return Err(invalid());
    }
    for descriptor in [response_descriptor, observation_descriptor] {
        if descriptor.media_type != "application/json" || descriptor.encoding.is_some() {
            return Err(invalid());
        }
    }
    let response: RecordedNormalChatResponseV1 =
        decode_record(&artifacts.get(response_descriptor)?)?;
    let observation: RecordedNormalChatObservationV1 =
        decode_record(&artifacts.get(observation_descriptor)?)?;
    if response.permit_id != *permit_id
        || response.attempt_id != admission.attempt.attempt_id
        || response.preflight_receipt_digest != preflight.receipt_digest
        || response.response.text.len() as u64 > budget.max_output_bytes
        || observation.attempt != admission.attempt.attempt_id
        || observation.response != *response_descriptor
        || observation.preflight != *preflight
        || observation.outcome != *outcome
    {
        return Err(invalid());
    }
    Ok(NativeNormalChatObservation {
        response_artifact: response_descriptor.clone(),
        observation_artifact: observation_descriptor.clone(),
        outcome: outcome.clone(),
    })
}
