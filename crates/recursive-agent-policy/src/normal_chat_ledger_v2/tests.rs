use super::*;
use recursive_agent_contracts::{CurrentReceiptId, NormalChatAttemptV2};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn historical(
    actor: &str,
) -> Result<NormalChatLedgerAdmissionEvidenceV2, Box<dyn std::error::Error>> {
    let now = DateTime::<Utc>::UNIX_EPOCH + chrono::TimeDelta::seconds(1_792_008_000);
    let home = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut grant: NormalChatEgressGrantV1 = serde_json::from_value(json!({
        "schema":"recursive-agent.normal-chat-egress-grant/v1", "revision":1, "ares_home_digest":home,
        "mode":"enforce", "any_route":false,
        "routes":[{"provider_identity":"provider:fixture","model_ref":"model:fixture","api_mode":"chat_completions"}],
        "caps":{"max_attempts":3,"max_output_tokens":100,"max_wall_time_ms":1000,"max_request_bytes":4096},
        "expires_at":now+chrono::TimeDelta::seconds(600),"content_retention":"digest_only","policy_digest":home,
    }))?;
    grant.policy_digest = grant.computed_policy_digest()?;
    let session = NormalChatSessionV1 {
        schema: recursive_agent_contracts::NormalChatSessionSchemaV1::V1,
        conversation_ref: "conversation:fixture".into(),
        parent_session_run_id: None,
        ares_home_digest: home.into(),
        grant_revision: 1,
        policy_basis_digest: grant.policy_digest.clone(),
    };
    let (root, family) = normal_chat_session_control::expected_session_control(
        &grant,
        &session,
        now,
        ActorPrincipalV1::try_new(actor)?,
    )?;
    let operation = recursive_agent_contracts::parse_normal_chat_operation_v2_bytes(
        &serde_json::to_vec(&json!({
            "schema":"recursive-agent.normal-chat/v2","conversation_ref":session.conversation_ref,"parent_run_id":session.run_id()?,
            "materialization_ref":"materialization:fixture","materialization_digest":home,"policy_basis_ref":"normal-chat-grant:revision-1","policy_basis_digest":grant.policy_digest,
            "source_revision":"source:fixture","route_class":"conversation","provider_identity":"provider:fixture","model_ref":"model:fixture","api_mode":"chat_completions",
            "request_digest":home,"request_projection_schema":"ares-json-sorted-v1","budget":{"output_reserve":10,"max_wall_time_ms":1000,"max_request_bytes":4096},
            "replay":"unavailable","provenance":[{"source":"urn:test:fixture","digest":content_digest(&"fixture")?}],
        }))?,
    )?;
    let attempt = NormalChatAttemptV2::new(
        operation,
        1,
        ContentDigest::compute(b"body"),
        4,
        "intent:fixture".into(),
        session.run_id()?,
    )?;
    let request = FamilyChildRequestV1 {
        child_run_id: attempt.run_id()?,
        parent_operation_id: session.run_id()?,
        root_operation_id: session.run_id()?,
        parent_control_permit_id: root.permit_id.clone(),
        parent_admission_receipt_id: CurrentReceiptId::try_new(format!(
            "v1:recursive-agent/receipt/v1:det:{}",
            "c".repeat(64)
        ))?,
        requested_budget: PermitBudgetV1 {
            max_wall_time_ms: 1000,
            max_output_bytes: 1024 * 1024,
            max_artifact_bytes: 1024 * 1024,
        },
        child_operation_digest: content_digest(&attempt)?,
        depth: 1,
    };
    let child = FamilyChildControlPermitV1 {
        child_control_permit_id: derive_family_child_permit_id(&request, &family)?,
        request,
        state: FamilyChildPermitStateV1::Issued,
    };
    let admission = NormalChatRetainedAdmissionV2 {
        schema: NormalChatRetainedAdmissionSchemaV2::V2,
        reservation: NormalChatFamilyReservationV2 {
            attempt,
            child_control: child,
            reserved_at: now,
        },
        context: NormalChatGrantContextV2 {
            grant,
            session,
            root_control: root,
        },
    };
    let (_, effect) = normal_chat_attempt_v2::build_attempt_permits(&admission)?;
    let preflight = PermitPreflightReceiptV1::create(
        effect_evidence(&effect, PermitStateV1::Consumed { consumed_at: now })?,
        now,
    )?;
    Ok(NormalChatLedgerAdmissionEvidenceV2 {
        schema: NormalChatLedgerAdmissionSchemaV2::V2,
        admission,
        preflight,
    })
}

#[test]
fn offline_expected_identity_uses_recorded_uid_not_verifier_uid() -> TestResult {
    let local = rustix::process::getuid().as_raw();
    let foreign: u32 = if local == 4_000_000_000 {
        4_000_000_001
    } else {
        4_000_000_000
    };
    let actor = format!("ares:uid:{foreign}");
    let proof = historical(&actor)?;
    proof.validate()?;
    assert_ne!(actor, format!("ares:uid:{local}"));
    assert_eq!(proof.preflight.evidence.binding.actor.as_str(), actor);
    assert_eq!(
        parse_normal_chat_ledger_admission_v2_bytes(&jcs_canonical(&proof)?)?,
        proof
    );
    Ok(())
}

#[test]
fn malformed_recorded_actor_is_rejected_without_normalization() -> TestResult {
    for actor in [
        "ares:uid:01",
        "ares:uid:-1",
        "ares:uid:+1",
        "ares:uid:4294967296",
        "ares:uid:1 ",
        "ares:uid:١",
        "actor:other",
    ] {
        assert!(historical(actor).is_err(), "{actor}");
    }
    Ok(())
}

#[test]
fn generic_self_valid_preflight_is_insufficient_without_exact_consumed_state_and_time() -> TestResult
{
    let proof = historical("ares:uid:4000000000")?;
    let (_, effect) = normal_chat_attempt_v2::build_attempt_permits(&proof.admission)?;
    for mode in ["issued", "time"] {
        let mut altered = proof.clone();
        let state = if mode == "issued" {
            PermitStateV1::Issued
        } else {
            PermitStateV1::Consumed {
                consumed_at: proof.preflight.recorded_at,
            }
        };
        let recorded_at = proof.preflight.recorded_at
            + if mode == "time" {
                chrono::TimeDelta::milliseconds(1)
            } else {
                chrono::TimeDelta::zero()
            };
        altered.preflight =
            PermitPreflightReceiptV1::create(effect_evidence(&effect, state)?, recorded_at)?;
        altered.preflight.validate()?;
        assert!(altered.validate().is_err(), "{mode}");
    }
    Ok(())
}
