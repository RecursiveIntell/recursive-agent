//! Candidate-only admission contract for the sealed provider-egress lane.
//!
//! This test intentionally uses no provider backend. It proves that default
//! policy denies the exact sealed request before any executor can be reached.

use chrono::{TimeZone, Utc};
use recursive_agent_contracts::{
    ContentDigest, ProviderEgressBindingMaterialV1, ProviderEgressBindingV1,
};
use recursive_agent_policy::{
    authorize_provider_egress, DenyProviderEgressAdmission, PolicyError,
    ProviderEgressAdmissionRequestV1, ProviderEgressAdmissionVerifier,
    ValidatedProviderEgressAdmissionV1,
};
use std::sync::atomic::{AtomicUsize, Ordering};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn now() -> Result<chrono::DateTime<Utc>, Box<dyn std::error::Error>> {
    Utc.with_ymd_and_hms(2026, 9, 5, 0, 0, 0)
        .single()
        .ok_or_else(|| "fixture time is invalid".into())
}

fn binding() -> Result<ProviderEgressBindingV1, Box<dyn std::error::Error>> {
    Ok(ProviderEgressBindingV1::seal(
        ProviderEgressBindingMaterialV1 {
            policy_basis_ref: "policy:fixture".into(),
            policy_basis_digest: format!("sha256:{}", "a".repeat(64)),
            context_digest: format!("sha256:{}", "b".repeat(64)),
            source_revision: "source:fixture".into(),
            graph_obligation_ref: "graph-obligation:node-1".into(),
            graph_obligation_digest: format!("blake3:{}", "c".repeat(64)),
            route_class: "candidate".into(),
            provider_identity: "ollama:http://127.0.0.1:11434".into(),
            model_ref: "model:fixture".into(),
            input_tokens: 4,
            output_reserve: 8,
            request_digest: ContentDigest::compute(b"exact-provider-request"),
            not_after: Utc
                .with_ymd_and_hms(2030, 1, 1, 0, 0, 0)
                .single()
                .ok_or("fixture expiry is invalid")?,
        },
    )?)
}

struct FixtureCurrentPolicy {
    calls: AtomicUsize,
}

impl ProviderEgressAdmissionVerifier for FixtureCurrentPolicy {
    fn authorize(
        &self,
        _admission: &ValidatedProviderEgressAdmissionV1,
    ) -> Result<(), PolicyError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[test]
fn default_policy_denies_the_only_supported_sealed_egress_lane_before_execution() -> TestResult {
    let binding = binding()?;
    let request = ProviderEgressAdmissionRequestV1::new(
        "sealed_completion",
        binding.clone(),
        binding.request_digest.clone(),
        ContentDigest::compute(b"sealed-completion-tool-arguments"),
    )?;
    request.validate_at(now()?)?;

    let error = authorize_provider_egress(&DenyProviderEgressAdmission, &request, now()?)
        .err()
        .ok_or("default provider-egress policy unexpectedly authorized execution")?;
    assert!(matches!(error, PolicyError::NetworkUnavailable));
    Ok(())
}

#[test]
fn admission_request_rejects_a_mutated_or_expired_binding_before_a_verifier_can_observe_it(
) -> TestResult {
    let binding = binding()?;
    let mut request = ProviderEgressAdmissionRequestV1::new(
        "sealed_completion",
        binding.clone(),
        binding.request_digest.clone(),
        ContentDigest::compute(b"sealed-completion-tool-arguments"),
    )?;
    request.binding.model_ref = "model:mutated".into();
    assert!(request.validate_at(now()?).is_err());

    let expired = ProviderEgressBindingV1::seal(ProviderEgressBindingMaterialV1 {
        not_after: now()?,
        ..ProviderEgressBindingMaterialV1 {
            policy_basis_ref: "policy:fixture".into(),
            policy_basis_digest: format!("sha256:{}", "a".repeat(64)),
            context_digest: format!("sha256:{}", "b".repeat(64)),
            source_revision: "source:fixture".into(),
            graph_obligation_ref: "graph-obligation:node-1".into(),
            graph_obligation_digest: format!("blake3:{}", "c".repeat(64)),
            route_class: "candidate".into(),
            provider_identity: "ollama:http://127.0.0.1:11434".into(),
            model_ref: "model:fixture".into(),
            input_tokens: 4,
            output_reserve: 8,
            request_digest: binding.request_digest.clone(),
            not_after: Utc
                .with_ymd_and_hms(2030, 1, 1, 0, 0, 0)
                .single()
                .ok_or("fixture expiry is invalid")?,
        }
    })?;
    let expired_request = ProviderEgressAdmissionRequestV1::new(
        "sealed_completion",
        expired.clone(),
        expired.request_digest.clone(),
        ContentDigest::compute(b"sealed-completion-tool-arguments"),
    )?;
    assert!(expired_request.validate_at(now()?).is_err());
    Ok(())
}

#[test]
fn policy_gate_validates_before_an_injected_current_verifier_runs() -> TestResult {
    let binding = binding()?;
    let valid = ProviderEgressAdmissionRequestV1::new(
        "sealed_completion",
        binding.clone(),
        binding.request_digest.clone(),
        ContentDigest::compute(b"sealed-completion-tool-arguments"),
    )?;
    let verifier = FixtureCurrentPolicy {
        calls: AtomicUsize::new(0),
    };
    authorize_provider_egress(&verifier, &valid, now()?)?;
    assert_eq!(verifier.calls.load(Ordering::Relaxed), 1);

    let mut tampered = valid;
    tampered.request_digest = ContentDigest::compute(b"changed-after-admission");
    assert!(authorize_provider_egress(&verifier, &tampered, now()?).is_err());
    assert_eq!(
        verifier.calls.load(Ordering::Relaxed),
        1,
        "the verifier observed unvalidated egress material"
    );
    Ok(())
}
