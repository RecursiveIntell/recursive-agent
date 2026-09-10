//! Candidate native conversation executor. Not registered with the daemon or
//! host. This records observed backend outcomes, not a full terminal run chain.
use crate::Clock;
use recursive_agent_contracts::{
    content_digest, ArtifactDescriptorV1, ContentDigest, CurrentPermitId, NormalChatAttemptId,
    ToolCallSpecV1,
};
use recursive_agent_ledger::{ArtifactStore, LedgerError};
use recursive_agent_policy::{
    DurablePermitStore, NormalChatAdmissionVerifier, PermitOutcomeReceiptV1,
    PermitPreflightReceiptV1, PolicyError, ReportedEffectOutcomeV1, ReportedEffectStateV1,
    ValidatedNormalChatAdmissionV1,
};
use recursive_agent_provider::{CompletionBackend, CompletionResponseV1, ConversationRequestV1};
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
    #[error("recorded normal-chat replay material is malformed or noncanonical")]
    ReplayMalformed,
    #[error("recorded normal-chat replay material does not bind durable execution evidence")]
    ReplayBindingMismatch,
    #[error("recorded normal-chat replay requires a durably reported successful outcome")]
    ReplayOutcomeNotSucceeded,
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

// Versioned data-plane record, not replay authority. The native ledger must
// still anchor its descriptor before a recovery path may select it. Legacy
// untagged response artifacts are not reinterpreted as this schema.
#[derive(serde::Serialize)]
struct RecordedNormalChatResponseV1<'a> {
    schema: RecordedNormalChatResponseSchemaV1,
    attempt_id: &'a recursive_agent_contracts::NormalChatAttemptId,
    permit_id: &'a CurrentPermitId,
    preflight_receipt_digest: &'a recursive_agent_contracts::ContentDigest,
    response: &'a recursive_agent_provider::CompletionResponseV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum RecordedNormalChatResponseSchemaV1 {
    #[serde(rename = "recursive-agent.normal-chat-recorded-response/v1")]
    V1,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedNormalChatResponseReplayV1 {
    schema: RecordedNormalChatResponseSchemaV1,
    attempt_id: NormalChatAttemptId,
    permit_id: CurrentPermitId,
    preflight_receipt_digest: ContentDigest,
    response: CompletionResponseV1,
}

#[derive(serde::Serialize)]
struct RecordedNormalChatObservationV1<'a> {
    schema: &'static str,
    attempt: &'a NormalChatAttemptId,
    response: &'a ArtifactDescriptorV1,
    preflight: &'a PermitPreflightReceiptV1,
    outcome: &'a PermitOutcomeReceiptV1,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedNormalChatObservationReplayV1 {
    schema: String,
    attempt: NormalChatAttemptId,
    response: ArtifactDescriptorV1,
    preflight: PermitPreflightReceiptV1,
    outcome: PermitOutcomeReceiptV1,
}

pub struct NativeNormalChatObservation {
    pub response_artifact: ArtifactDescriptorV1,
    pub outcome: PermitOutcomeReceiptV1,
    pub observation_artifact: ArtifactDescriptorV1,
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

    /// Replay one caller-selected recorded response without invoking the backend.
    /// The observation descriptor must itself come from an external durable/
    /// trusted evidence reference; this method verifies it but does not discover
    /// replay authority from unanchored artifacts.
    pub fn replay_recorded(
        &self,
        observation_artifact: &ArtifactDescriptorV1,
    ) -> Result<CompletionResponseV1, NativeNormalChatError> {
        let artifact_root = self.artifacts.run_root_identity();
        if self.permits.run_root_identity() != (artifact_root.device, artifact_root.inode) {
            return Err(NativeNormalChatError::StoreMismatch);
        }
        let observation_bytes = self.artifacts.get(observation_artifact)?;
        let observation: RecordedNormalChatObservationReplayV1 =
            serde_json::from_slice(&observation_bytes)
                .map_err(|_| NativeNormalChatError::ReplayMalformed)?;
        let canonical_observation = recursive_agent_contracts::jcs_canonical(&observation)
            .map_err(|_| NativeNormalChatError::ReplayMalformed)?;
        if canonical_observation != observation_bytes
            || observation.schema != "recursive-agent.normal-chat-observation/v1"
        {
            return Err(NativeNormalChatError::ReplayMalformed);
        }
        observation.preflight.validate()?;
        observation.outcome.validate()?;
        if observation.preflight.permit_id != observation.outcome.permit_id
            || observation.outcome.preflight_receipt_digest
                != observation.preflight.receipt_digest
        {
            return Err(NativeNormalChatError::ReplayBindingMismatch);
        }
        let permit_id = &observation.outcome.permit_id;
        let persisted_preflight = self.permits.normal_chat_preflight(permit_id)?;
        let persisted_outcome = self.permits.normal_chat_outcome(permit_id)?;
        let persisted_attempt = self.permits.normal_chat_attempt_for_permit(permit_id)?;
        if persisted_preflight != observation.preflight
            || persisted_outcome != observation.outcome
            || persisted_attempt != observation.attempt
        {
            return Err(NativeNormalChatError::ReplayBindingMismatch);
        }
        if persisted_outcome.reported.state != ReportedEffectStateV1::Succeeded {
            return Err(NativeNormalChatError::ReplayOutcomeNotSucceeded);
        }
        let response_bytes = self.artifacts.get(&observation.response)?;
        let recorded: RecordedNormalChatResponseReplayV1 =
            serde_json::from_slice(&response_bytes)
                .map_err(|_| NativeNormalChatError::ReplayMalformed)?;
        let canonical_response = recursive_agent_contracts::jcs_canonical(&recorded)
            .map_err(|_| NativeNormalChatError::ReplayMalformed)?;
        if canonical_response != response_bytes {
            return Err(NativeNormalChatError::ReplayMalformed);
        }
        if recorded.schema != RecordedNormalChatResponseSchemaV1::V1
            || recorded.attempt_id != observation.attempt
            || recorded.permit_id != *permit_id
            || recorded.preflight_receipt_digest != persisted_preflight.receipt_digest
        {
            return Err(NativeNormalChatError::ReplayBindingMismatch);
        }
        Ok(recorded.response)
    }

    pub fn execute(
        &self,
        permit_id: &CurrentPermitId,
        admission: &ValidatedNormalChatAdmissionV1,
        request: &ConversationRequestV1,
    ) -> Result<NativeNormalChatObservation, NativeNormalChatError> {
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
            || !request.provider.matches_egress_binding(
                &attempt.operation.provider_identity,
                &attempt.operation.model_ref,
            )
            || request.max_tokens != Some(attempt.operation.budget.output_reserve)
        {
            return Err(NativeNormalChatError::RequestMismatch);
        }
        let call = ToolCallSpecV1 {
            tool: "normal_chat".into(),
            args: serde_json::json!({"attempt": attempt, "request": request}),
            frozen_clock: None,
        };
        let evidence =
            self.permits
                .consume_normal_chat(permit_id, admission, &call, self.verifier, || {
                    self.clock.now()
                })?;
        let preflight = self.permits.normal_chat_preflight(permit_id)?;
        let start = std::time::Instant::now();
        let response = self.backend.complete_conversation(request);
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
            attempt_id: &attempt.attempt_id,
            permit_id,
            preflight_receipt_digest: &preflight.receipt_digest,
            response: &response,
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
            schema: "recursive-agent.normal-chat-observation/v1",
            attempt: &attempt.attempt_id,
            response: &response_artifact,
            preflight: &preflight,
            outcome: &outcome,
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
        Ok(NativeNormalChatObservation {
            response_artifact,
            outcome,
            observation_artifact,
        })
    }
}
