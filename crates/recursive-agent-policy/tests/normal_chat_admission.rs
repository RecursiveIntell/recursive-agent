//! Candidate normal-chat admission contract. No provider backend is used.

use chrono::{TimeZone, Utc};
use recursive_agent_contracts::{
    ContentDigest, NormalChatAttemptV1, NormalChatBudgetV1, NormalChatOperationSchemaV1,
    NormalChatOperationV1, NormalChatReplayV1, ProvenanceRefV1,
};
use recursive_agent_policy::{
    authorize_normal_chat, reauthorize_normal_chat, DenyNormalChatAdmission,
    NormalChatAdmissionRequestV1, NormalChatAdmissionVerifier, NormalChatPolicyValidityV1,
    PolicyError, ValidatedNormalChatAdmissionV1,
};
use std::sync::atomic::{AtomicUsize, Ordering};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn now() -> Result<chrono::DateTime<Utc>, Box<dyn std::error::Error>> {
    Utc.with_ymd_and_hms(2026, 9, 6, 0, 0, 0)
        .single()
        .ok_or_else(|| "fixture time is invalid".into())
}

fn attempt() -> Result<NormalChatAttemptV1, Box<dyn std::error::Error>> {
    NormalChatAttemptV1::new(
        NormalChatOperationV1 {
            schema: NormalChatOperationSchemaV1::V1,
            conversation_ref: "conversation:policy-fixture".into(),
            parent_run_id: None,
            materialization_ref: "materialization:policy-fixture".into(),
            materialization_digest: format!("sha256:{}", "a".repeat(64)),
            policy_basis_ref: "policy-basis:fixture".into(),
            policy_basis_digest: format!("blake3:{}", "b".repeat(64)),
            source_revision: "source:fixture".into(),
            route_class: "managed_local".into(),
            provider_identity: "openai_compatible:https://provider.test/v1".into(),
            model_ref: "model:fixture".into(),
            request_digest: format!("sha256:{}", "c".repeat(64)),
            budget: NormalChatBudgetV1 {
                max_attempts: 2,
                input_tokens: 10,
                output_reserve: 20,
                max_wall_time_ms: 1_000,
            },
            replay: NormalChatReplayV1::RecordedResponseOnly,
            provenance: vec![ProvenanceRefV1 {
                source: "urn:test:normal-chat-admission".into(),
                digest: ContentDigest::compute(b"normal-chat-admission"),
            }],
        },
        1,
        ContentDigest::compute(b"native-conversation-request"),
    )
    .map_err(Into::into)
}

struct FixtureCurrentPolicy {
    calls: AtomicUsize,
}

impl NormalChatAdmissionVerifier for FixtureCurrentPolicy {
    fn authorize(
        &self,
        admission: &ValidatedNormalChatAdmissionV1,
    ) -> Result<NormalChatPolicyValidityV1, PolicyError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(NormalChatPolicyValidityV1 {
            not_before: admission.verified_at(),
            not_after: admission.verified_at() + chrono::Duration::seconds(1),
        })
    }
}

struct RevocablePolicy {
    revoked: std::sync::atomic::AtomicBool,
    calls: AtomicUsize,
}
impl NormalChatAdmissionVerifier for RevocablePolicy {
    fn authorize(
        &self,
        admission: &ValidatedNormalChatAdmissionV1,
    ) -> Result<NormalChatPolicyValidityV1, PolicyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.revoked.load(Ordering::SeqCst) {
            return Err(PolicyError::NetworkUnavailable);
        }
        Ok(NormalChatPolicyValidityV1 {
            not_before: admission.verified_at(),
            not_after: admission.verified_at() + chrono::Duration::seconds(1),
        })
    }
}

#[test]
fn reauthorization_checks_current_revocation_and_never_extends_old_admission() -> TestResult {
    let time = now()?;
    let request = NormalChatAdmissionRequestV1::new(
        "normal_chat",
        attempt()?,
        ContentDigest::compute(b"reauth-args"),
    )?;
    let verifier = RevocablePolicy {
        revoked: std::sync::atomic::AtomicBool::new(false),
        calls: AtomicUsize::new(0),
    };
    let admitted = authorize_normal_chat(&verifier, &request, time)?;
    let rechecked = reauthorize_normal_chat(
        &verifier,
        &admitted,
        &request,
        time + chrono::Duration::milliseconds(500),
    )?;
    assert_eq!(rechecked.expires_at(), admitted.expires_at());
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 2);
    verifier.revoked.store(true, Ordering::SeqCst);
    assert!(reauthorize_normal_chat(&verifier, &admitted, &request, time).is_err());
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 3);
    Ok(())
}

#[test]
fn reauthorization_rejects_expired_rewound_or_changed_request_before_verifier() -> TestResult {
    let time = now()?;
    let request = NormalChatAdmissionRequestV1::new(
        "normal_chat",
        attempt()?,
        ContentDigest::compute(b"reauth-args"),
    )?;
    let verifier = FixtureCurrentPolicy {
        calls: AtomicUsize::new(0),
    };
    let admitted = authorize_normal_chat(&verifier, &request, time)?;
    for checked_at in [
        time - chrono::Duration::nanoseconds(1),
        admitted.expires_at(),
    ] {
        assert!(reauthorize_normal_chat(&verifier, &admitted, &request, checked_at).is_err());
    }
    let mut changed = request.clone();
    changed.tool_arguments_digest = ContentDigest::compute(b"substitution");
    assert!(reauthorize_normal_chat(&verifier, &admitted, &changed, time).is_err());
    assert_eq!(verifier.calls.load(Ordering::Relaxed), 1);
    Ok(())
}

struct FixedWindow(NormalChatPolicyValidityV1);

impl NormalChatAdmissionVerifier for FixedWindow {
    fn authorize(
        &self,
        _: &ValidatedNormalChatAdmissionV1,
    ) -> Result<NormalChatPolicyValidityV1, PolicyError> {
        Ok(self.0.clone())
    }
}

#[test]
fn normal_chat_policy_window_is_half_open_and_bounded() -> TestResult {
    let time = now()?;
    let request = NormalChatAdmissionRequestV1::new(
        "normal_chat",
        attempt()?,
        ContentDigest::compute(b"args"),
    )?;
    for (start, end) in [(1, 2), (-2, 0), (0, 0), (2, 1), (0, 301)] {
        let verifier = FixedWindow(NormalChatPolicyValidityV1 {
            not_before: time + chrono::Duration::seconds(start),
            not_after: time + chrono::Duration::seconds(end),
        });
        assert!(
            authorize_normal_chat(&verifier, &request, time).is_err(),
            "invalid window {start}..{end}"
        );
    }
    let verifier = FixedWindow(NormalChatPolicyValidityV1 {
        not_before: time,
        not_after: time + chrono::Duration::seconds(1),
    });
    let admitted = authorize_normal_chat(&verifier, &request, time)?;
    assert_eq!(admitted.expires_at(), time + chrono::Duration::seconds(1));
    assert!(authorize_normal_chat(&verifier, &request, admitted.expires_at()).is_err());
    Ok(())
}

#[test]
fn default_policy_denies_normal_chat_before_any_runtime_consumer() -> TestResult {
    let attempt = attempt()?;
    let request = NormalChatAdmissionRequestV1::new(
        "normal_chat",
        attempt,
        ContentDigest::compute(b"normal-chat-tool-arguments"),
    )?;
    let error = authorize_normal_chat(&DenyNormalChatAdmission, &request, now()?)
        .err()
        .ok_or("default normal-chat policy unexpectedly authorized execution")?;
    assert!(matches!(error, PolicyError::NetworkUnavailable));
    Ok(())
}

#[test]
fn normal_chat_admission_validates_attempt_before_current_policy_observes_it() -> TestResult {
    let attempt = attempt()?;
    let valid = NormalChatAdmissionRequestV1::new(
        "normal_chat",
        attempt,
        ContentDigest::compute(b"normal-chat-tool-arguments"),
    )?;
    let verifier = FixtureCurrentPolicy {
        calls: AtomicUsize::new(0),
    };
    authorize_normal_chat(&verifier, &valid, now()?)?;
    assert_eq!(verifier.calls.load(Ordering::Relaxed), 1);

    let mut tampered = valid;
    tampered.attempt.provider_request_digest = ContentDigest::compute(b"changed-after-admission");
    assert!(authorize_normal_chat(&verifier, &tampered, now()?).is_err());
    assert_eq!(verifier.calls.load(Ordering::Relaxed), 1);
    Ok(())
}
