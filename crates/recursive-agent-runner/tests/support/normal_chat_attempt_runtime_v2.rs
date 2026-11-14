use super::*;
#[path = "normal_chat_family_runtime_v2.rs"]
mod family;
#[path = "normal_chat_attempt_runtime_hostile.rs"]
mod hostile;
#[path = "normal_chat_recovery_inspection.rs"]
mod inspection;
#[path = "normal_chat_partial_admission_recovery.rs"]
mod partial_admission_recovery;
#[path = "normal_chat_response_release.rs"]
mod response_release;
#[path = "normal_chat_runtime_readback.rs"]
mod runtime_readback;
#[path = "normal_chat_shared_gate_runtime.rs"]
mod shared_gate;
#[path = "normal_chat_terminal_runtime_v2.rs"]
mod terminal;
use recursive_agent_contracts::{
    parse_normal_chat_call_request_v2_bytes, ContentDigest, NormalChatCallRequestV2,
};
use recursive_agent_policy::NormalChatAttemptPolicyStateV2;
use recursive_agent_runner::{NormalChatAttemptInterruptionV2 as Stop, RuntimeNormalChatBeginV2};

fn request(
    fx: &Fixture,
    session: &recursive_agent_runner::RuntimeNormalChatSessionV1,
    intent: &str,
) -> Result<NormalChatCallRequestV2, Box<dyn std::error::Error>> {
    Ok(parse_normal_chat_call_request_v2_bytes(
        &serde_json::to_vec(&json!({
            "schema":"recursive-agent.normal-chat-call-request/v2",
            "operation":{
                "schema":"recursive-agent.normal-chat/v2","conversation_ref":"conversation:fixture","parent_run_id":session.run_id(),
                "materialization_ref":"materialization:fixture","materialization_digest":HOME,
                "policy_basis_ref":"normal-chat-grant:revision-1","policy_basis_digest":fx.authority.grant().policy_digest,
                "source_revision":"source:fixture","route_class":"conversation",
                "provider_identity":"openai_compatible:https://provider.test/v1","model_ref":"model:fixture","api_mode":"chat_completions",
                "request_digest":HOME,"request_projection_schema":"ares-json-sorted-v1",
                "budget":{"output_reserve":10,"max_wall_time_ms":1000,"max_request_bytes":4096},
                "replay":"unavailable","provenance":[{"source":"urn:test:fixture","digest":content_digest(&"fixture")?}]
            },
            "provider_request_digest":ContentDigest::compute(b"physical-body"),
            "provider_request_bytes":b"physical-body".len(), "dispatch_intent_ref":intent
        }))?,
    )?)
}

#[test]
fn fresh_runtime_admission_has_verified_parent_link_and_exact_child_preflight() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:one")?;
    let fresh = match service.begin_normal_chat_attempt(&session, &req)? {
        RuntimeNormalChatBeginV2::Fresh(fresh) => fresh,
        RuntimeNormalChatBeginV2::Existing(_) => {
            return Err("fresh admission returned status".into())
        }
    };
    let parent = appendable_snapshot_expected_run_from_dir_fd(
        &File::open(session.run_dir())?,
        session.run_id(),
    )?;
    assert_eq!(parent.receipts().len(), 5);
    assert_eq!(
        parent.receipts()[3].kind,
        ReceiptKindV1::ChildAdmissionPrepared
    );
    assert_eq!(parent.receipts()[4].kind, ReceiptKindV1::ChildLinked);
    let child = appendable_snapshot_expected_run_from_dir_fd(
        &File::open(fresh.child_run_dir())?,
        &fresh.attempt().run_id()?,
    )?;
    assert_eq!(child.receipts().len(), 7);
    assert_eq!(
        child.receipts()[4].kind,
        ReceiptKindV1::NormalChatAttemptAdmittedV2
    );
    assert_eq!(child.receipts()[6].kind, ReceiptKindV1::PermitConsumed);
    assert_eq!(
        fresh.parent_chain_head().to_string(),
        parent.verification().final_head
    );
    assert_eq!(
        fresh.child_chain_head().to_string(),
        child.verification().final_head
    );
    assert!(fresh.expires_at() > fx.clock.now());
    Ok(())
}

#[test]
fn exact_retry_is_status_only_and_conflicting_or_unsettled_next_intent_never_mints() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:one")?;
    assert!(matches!(
        service.begin_normal_chat_attempt(&session, &req)?,
        RuntimeNormalChatBeginV2::Fresh(_)
    ));
    let retry = match service.begin_normal_chat_attempt(&session, &req)? {
        RuntimeNormalChatBeginV2::Existing(existing) => existing,
        RuntimeNormalChatBeginV2::Fresh(_) => return Err("retry restored a continuation".into()),
    };
    assert_eq!(
        retry.child_policy.ok_or("missing child status")?.state,
        NormalChatAttemptPolicyStateV2::Consumed
    );
    let mut conflict = req.clone();
    conflict.provider_request_digest = ContentDigest::compute(b"other-body");
    assert!(service
        .begin_normal_chat_attempt(&session, &conflict)
        .is_err());
    assert!(service
        .begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:two")?)
        .is_err());
    Ok(())
}

#[test]
fn interrupted_after_preparation_never_resumes_a_fresh_send() -> TestResult {
    for stop in [
        Stop::AfterPreparation,
        Stop::AfterReservation,
        Stop::AfterLink,
        Stop::AfterPolicyConsume,
        Stop::BeforeRelease,
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req = request(&fx, &session, "intent:one")?;
        assert!(service
            .begin_normal_chat_attempt_with_interruption(&session, &req, Some(stop))
            .is_err());
        assert!(
            !matches!(
                service.begin_normal_chat_attempt(&session, &req),
                Ok(RuntimeNormalChatBeginV2::Fresh(_))
            ),
            "{stop:?}"
        );
        assert!(
            !matches!(
                service.begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:two")?),
                Ok(RuntimeNormalChatBeginV2::Fresh(_))
            ),
            "{stop:?}"
        );
    }
    Ok(())
}
