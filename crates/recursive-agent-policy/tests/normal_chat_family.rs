use chrono::{DateTime, TimeDelta, Utc};
use recursive_agent_contracts::{
    parse_normal_chat_operation_v2_bytes, ContentDigest, CurrentPermitId, CurrentReceiptId,
    CurrentRunId,
};
use recursive_agent_policy::{
    ActorPrincipalV1, ChildRunCeilingV1, FamilyAuthorityStore, FamilyRootGrantV1,
    NormalChatEgressDenialV1, NormalChatEgressGrantStore, NormalChatFamilyReservationRequestV2,
    NormalChatGrantAuthorityV1, PermitBudgetV1, PolicyError,
};
use serde_json::json;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const HOME: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn now() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_792_008_000)
}
fn family_grant() -> Result<FamilyRootGrantV1, Box<dyn std::error::Error>> {
    Ok(FamilyRootGrantV1 {
        root_operation_id: CurrentRunId::try_new(format!(
            "v1:recursive-agent/run/v1:det:{}",
            "a".repeat(64)
        ))?,
        parent_control_permit_id: CurrentPermitId::try_new(format!(
            "v1:recursive-agent/permit/v1:det:{}",
            "b".repeat(64)
        ))?,
        actor: ActorPrincipalV1::try_new("actor:fixture")?,
        policy_version: "normal-chat-grant:revision-1".into(),
        effect_budget: budget(),
        child_run_ceiling: ChildRunCeilingV1 {
            max_depth: 1,
            max_children: 3,
            family_budget: PermitBudgetV1 {
                max_wall_time_ms: 3000,
                max_output_bytes: 3 * 1024 * 1024,
                max_artifact_bytes: 3 * 1024 * 1024,
            },
            not_before: now(),
            expires_at: now() + TimeDelta::seconds(60),
        },
    })
}
fn budget() -> PermitBudgetV1 {
    PermitBudgetV1 {
        max_wall_time_ms: 1000,
        max_output_bytes: 1024 * 1024,
        max_artifact_bytes: 1024 * 1024,
    }
}
fn authority(
    root: &std::path::Path,
) -> Result<NormalChatGrantAuthorityV1, Box<dyn std::error::Error>> {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let mut grant: recursive_agent_policy::NormalChatEgressGrantV1 = serde_json::from_value(
        json!({
            "schema": "recursive-agent.normal-chat-egress-grant/v1", "revision": 1,
            "ares_home_digest": HOME, "mode": "enforce", "any_route": false,
            "routes": [{"provider_identity": "openai_compatible:https://provider.test/v1", "model_ref": "model:fixture", "api_mode": "chat_completions"}],
            "caps": {"max_attempts": 3, "max_output_tokens": 100, "max_wall_time_ms": 1000, "max_request_bytes": 4096},
            "expires_at": now() + TimeDelta::seconds(60), "content_retention": "digest_only", "policy_digest": HOME,
        }),
    )?;
    grant.policy_digest = grant.computed_policy_digest()?;
    let path = root.join("grant.json");
    fs::write(&path, serde_json::to_vec(&grant)?)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(
        NormalChatEgressGrantStore::from_dir_fd(&File::open(root)?)?.load_from_path(
            &path,
            HOME,
            now(),
        )?,
    )
}
fn request(
    authority: &NormalChatGrantAuthorityV1,
    intent: &str,
    reserve: u32,
) -> Result<NormalChatFamilyReservationRequestV2, Box<dyn std::error::Error>> {
    let family = family_grant()?;
    let operation = parse_normal_chat_operation_v2_bytes(&serde_json::to_vec(&json!({
        "schema": "recursive-agent.normal-chat/v2", "conversation_ref": "conversation:fixture",
        "parent_run_id": family.root_operation_id,
        "materialization_ref": "materialization:fixture", "materialization_digest": HOME,
        "policy_basis_ref": family.policy_version, "policy_basis_digest": authority.grant().policy_digest,
        "source_revision": "source:fixture", "route_class": "conversation",
        "provider_identity": "openai_compatible:https://provider.test/v1", "model_ref": "model:fixture", "api_mode": "chat_completions",
        "request_digest": HOME, "request_projection_schema": "ares-json-sorted-v1",
        "budget": {"output_reserve": reserve, "max_wall_time_ms": 1000, "max_request_bytes": 4096},
        "replay": "unavailable", "provenance": [{"source": "urn:test:fixture", "digest": ContentDigest::compute(b"fixture")}],
    }))?)?;
    Ok(NormalChatFamilyReservationRequestV2 {
        operation,
        provider_request_digest: ContentDigest::compute(b"physical-body"),
        provider_request_bytes: b"physical-body".len() as u64,
        dispatch_intent_ref: intent.into(),
        parent_admission_receipt_id: CurrentReceiptId::try_new(format!(
            "v1:recursive-agent/receipt/v1:det:{}",
            "c".repeat(64)
        ))?,
        requested_budget: budget(),
    })
}
fn store(
    root: &std::path::Path,
    authority: &NormalChatGrantAuthorityV1,
) -> Result<FamilyAuthorityStore, Box<dyn std::error::Error>> {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    Ok(FamilyAuthorityStore::open_normal_chat_session_from_grant(
        &File::open(root)?,
        family_grant()?,
        authority,
        "conversation:fixture",
        now(),
    )?)
}
fn denied<T>(result: Result<T, PolicyError>, expected: NormalChatEgressDenialV1) -> TestResult {
    match result {
        Err(PolicyError::NormalChatEgressDenied(actual)) => assert_eq!(actual, expected),
        Err(error) => return Err(format!("wrong error: {error}").into()),
        Ok(_) => return Err("expected rejection".into()),
    }
    Ok(())
}

fn call(
    req: &NormalChatFamilyReservationRequestV2,
) -> recursive_agent_contracts::NormalChatCallRequestV2 {
    recursive_agent_contracts::NormalChatCallRequestV2 {
        schema: recursive_agent_contracts::NormalChatCallRequestSchemaV2::V2,
        operation: req.operation.clone(),
        provider_request_digest: req.provider_request_digest.clone(),
        provider_request_bytes: req.provider_request_bytes,
        dispatch_intent_ref: req.dispatch_intent_ref.clone(),
    }
}
#[test]
fn dry_check_uses_canonical_budget_without_allocating_or_advancing_ordinals() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let auth = authority(auth_dir.path())?;
    let root = tempfile::tempdir()?;
    let family = store(root.path(), &auth)?;
    let first = request(&auth, "intent:first", 60)?;
    let before = fs::read(root.path().join("family-authority.json"))?;
    family.check_new_normal_chat_call(&auth, &call(&first), now)?;
    family.check_new_normal_chat_call(&auth, &call(&first), now)?;
    assert_eq!(fs::read(root.path().join("family-authority.json"))?, before);
    assert!(family
        .read_normal_chat_session_snapshot_v2()?
        .reservations
        .is_empty());
    let admitted = family.reserve_normal_chat_attempt(&auth, &first, now())?;
    assert_eq!(admitted.attempt.attempt_number, 1);
    let large = request(&auth, "intent:large", 50)?;
    let charged = fs::read(root.path().join("family-authority.json"))?;
    denied(
        family.check_new_normal_chat_call(&auth, &call(&large), now),
        NormalChatEgressDenialV1::CapExhaustedOutputTokens,
    )?;
    assert_eq!(
        fs::read(root.path().join("family-authority.json"))?,
        charged
    );
    let exact = request(&auth, "intent:exact", 40)?;
    family.check_new_normal_chat_call(&auth, &call(&exact), now)?;
    family.reserve_normal_chat_attempt(&auth, &exact, now())?;
    denied(
        family.check_new_normal_chat_call(&auth, &call(&first), now),
        NormalChatEgressDenialV1::IntentConflict,
    )?;
    denied(
        family.check_new_normal_chat_call(&auth, &call(&request(&auth, "intent:excess", 1)?), now),
        NormalChatEgressDenialV1::CapExhaustedOutputTokens,
    )?;
    Ok(())
}
#[test]
fn dry_check_rejects_attempt_exhaustion_expiry_and_closed_family_without_mutation() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let auth = authority(auth_dir.path())?;
    let root = tempfile::tempdir()?;
    let family = store(root.path(), &auth)?;
    for index in 0..3 {
        family.reserve_normal_chat_attempt(
            &auth,
            &request(&auth, &format!("intent:{index}"), 10)?,
            now(),
        )?;
    }
    let next = call(&request(&auth, "intent:next", 10)?);
    let before = fs::read(root.path().join("family-authority.json"))?;
    denied(
        family.check_new_normal_chat_call(&auth, &next, now),
        NormalChatEgressDenialV1::CapExhaustedAttempts,
    )?;
    denied(
        family.check_new_normal_chat_call(&auth, &next, || now() + TimeDelta::seconds(60)),
        NormalChatEgressDenialV1::GrantExpired,
    )?;
    assert_eq!(fs::read(root.path().join("family-authority.json"))?, before);
    family.close_normal_chat_session(now())?;
    denied(
        family.check_new_normal_chat_call(&auth, &next, now),
        NormalChatEgressDenialV1::RunClosed,
    )?;
    Ok(())
}

#[test]
fn reservation_is_exact_idempotent_and_durable_across_reopen() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path())?;
    let root = tempfile::tempdir()?;
    let store_one = store(root.path(), &authority)?;
    let req = request(&authority, "intent:first", 60)?;
    let first = store_one.reserve_normal_chat_attempt(&authority, &req, now())?;
    assert_eq!(first.attempt.attempt_number, 1);
    assert_eq!(
        first.attempt.run_id()?,
        first.child_control.request.child_run_id
    );
    let retry = store_one.reserve_normal_chat_attempt(&authority, &req, now())?;
    assert_eq!(retry, first);
    drop(store_one);
    let reopened = store(root.path(), &authority)?;
    assert_eq!(
        reopened.read_normal_chat_reservation("intent:first")?,
        Some(first.clone())
    );
    assert_eq!(reopened.reserved_budget()?, budget());
    let mut conflict = req;
    conflict.provider_request_digest = ContentDigest::compute(b"changed-body");
    denied(
        reopened.reserve_normal_chat_attempt(&authority, &conflict, now()),
        NormalChatEgressDenialV1::IntentConflict,
    )?;
    let mut conflict = request(&authority, "intent:first", 60)?;
    conflict.requested_budget.max_output_bytes -= 1;
    denied(
        reopened.reserve_normal_chat_attempt(&authority, &conflict, now()),
        NormalChatEgressDenialV1::IntentConflict,
    )?;
    assert_eq!(
        reopened.read_normal_chat_reservation("intent:first")?,
        Some(first)
    );
    Ok(())
}

#[test]
fn reservations_enforce_cumulative_output_and_attempt_caps_across_calls() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path())?;
    let root = tempfile::tempdir()?;
    let store = store(root.path(), &authority)?;
    store.reserve_normal_chat_attempt(
        &authority,
        &request(&authority, "intent:one", 60)?,
        now(),
    )?;
    let mut other_call = request(&authority, "intent:two", 41)?;
    other_call.operation.materialization_ref = "materialization:second".into();
    denied(
        store.reserve_normal_chat_attempt(&authority, &other_call, now()),
        NormalChatEgressDenialV1::CapExhaustedOutputTokens,
    )?;
    assert_eq!(store.read_normal_chat_reservation("intent:two")?, None);
    let second = store.reserve_normal_chat_attempt(
        &authority,
        &request(&authority, "intent:two", 20)?,
        now(),
    )?;
    assert_eq!(second.attempt.attempt_number, 2);
    let third = store.reserve_normal_chat_attempt(
        &authority,
        &request(&authority, "intent:three", 20)?,
        now(),
    )?;
    assert_eq!(third.attempt.attempt_number, 3);
    denied(
        store.reserve_normal_chat_attempt(
            &authority,
            &request(&authority, "intent:four", 1)?,
            now(),
        ),
        NormalChatEgressDenialV1::CapExhaustedAttempts,
    )?;
    assert_eq!(store.reserved_budget()?.max_output_bytes, 3 * 1024 * 1024);
    Ok(())
}

#[test]
fn independent_open_handles_cannot_concurrently_overspend() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path())?;
    let root = tempfile::tempdir()?;
    let first = store(root.path(), &authority)?;
    let second = store(root.path(), &authority)?;
    let req_one = request(&authority, "intent:one", 60)?;
    let req_two = request(&authority, "intent:two", 60)?;
    let auth_one = authority.clone();
    let auth_two = authority.clone();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let other_barrier = barrier.clone();
    let one = std::thread::spawn(move || {
        barrier.wait();
        first.reserve_normal_chat_attempt(&auth_one, &req_one, now())
    });
    let two = std::thread::spawn(move || {
        other_barrier.wait();
        second.reserve_normal_chat_attempt(&auth_two, &req_two, now())
    });
    let results = [
        one.join().map_err(|_| "first worker panicked")?,
        two.join().map_err(|_| "second worker panicked")?,
    ];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let loser = results
        .into_iter()
        .find(|result| result.is_err())
        .ok_or("missing rejected reservation")?;
    denied(loser, NormalChatEgressDenialV1::CapExhaustedOutputTokens)?;
    assert_eq!(store(root.path(), &authority)?.reserved_budget()?, budget());
    Ok(())
}

#[test]
fn closing_or_revoking_session_never_refunds_reservations() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path())?;
    let root = tempfile::tempdir()?;
    let active = store(root.path(), &authority)?;
    let req = request(&authority, "intent:first", 60)?;
    let first = active.reserve_normal_chat_attempt(&authority, &req, now())?;
    active.close_normal_chat_session(now())?;
    active.close_normal_chat_session(now())?;
    denied(
        active.reserve_normal_chat_attempt(
            &authority,
            &request(&authority, "intent:later", 1)?,
            now(),
        ),
        NormalChatEgressDenialV1::RunClosed,
    )?;
    assert_eq!(
        active.read_normal_chat_reservation("intent:first")?,
        Some(first)
    );
    assert_eq!(active.reserved_budget()?, budget());
    let reopened = store(root.path(), &authority)?;
    denied(
        reopened.reserve_normal_chat_attempt(&authority, &req, now()),
        NormalChatEgressDenialV1::RunClosed,
    )?;
    let other_root = tempfile::tempdir()?;
    let revoked = store(other_root.path(), &authority)?;
    revoked.revoke_parent(now())?;
    denied(
        revoked.reserve_normal_chat_attempt(&authority, &req, now()),
        NormalChatEgressDenialV1::RunClosed,
    )?;
    Ok(())
}

#[test]
fn closed_accounting_fences_already_reserved_child_dispatch() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path())?;
    let root = tempfile::tempdir()?;
    let active = store(root.path(), &authority)?;
    let first = active.reserve_normal_chat_attempt(
        &authority,
        &request(&authority, "intent:first", 10)?,
        now(),
    )?;
    active.guard_child_dispatch(
        &first.child_control.request.child_run_id,
        &first.child_control.child_control_permit_id,
        now(),
    )?;
    active.close_normal_chat_session(now())?;
    assert!(
        active
            .guard_child_dispatch(
                &first.child_control.request.child_run_id,
                &first.child_control.child_control_permit_id,
                now()
            )
            .is_err(),
        "closed session must fence its allocated children"
    );
    Ok(())
}

#[test]
fn session_attempt_clock_cannot_regress_between_reservations() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path())?;
    let root = tempfile::tempdir()?;
    let active = store(root.path(), &authority)?;
    active.reserve_normal_chat_attempt(
        &authority,
        &request(&authority, "intent:first", 10)?,
        now() + TimeDelta::seconds(2),
    )?;
    denied(
        active.reserve_normal_chat_attempt(
            &authority,
            &request(&authority, "intent:second", 10)?,
            now() + TimeDelta::seconds(1),
        ),
        NormalChatEgressDenialV1::Malformed,
    )?;
    assert_eq!(active.read_normal_chat_reservation("intent:second")?, None);
    Ok(())
}

#[test]
fn new_logical_calls_reset_ordinal_but_keep_session_charges() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path())?;
    let root = tempfile::tempdir()?;
    let active = store(root.path(), &authority)?;
    active.reserve_normal_chat_attempt(
        &authority,
        &request(&authority, "intent:first", 60)?,
        now(),
    )?;
    let mut other = request(&authority, "intent:second", 40)?;
    other.operation.materialization_ref = "materialization:second".into();
    assert_eq!(
        active
            .reserve_normal_chat_attempt(&authority, &other, now())?
            .attempt
            .attempt_number,
        1
    );
    let mut third = request(&authority, "intent:third", 1)?;
    third.operation.materialization_ref = "materialization:third".into();
    denied(
        active.reserve_normal_chat_attempt(&authority, &third, now()),
        NormalChatEgressDenialV1::CapExhaustedOutputTokens,
    )?;
    Ok(())
}

#[test]
fn corrupted_or_duplicate_key_family_state_never_becomes_readback() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path())?;
    for damage in ["binding", "missing_child", "duplicate_key"] {
        let root = tempfile::tempdir()?;
        let active = store(root.path(), &authority)?;
        active.reserve_normal_chat_attempt(
            &authority,
            &request(&authority, "intent:first", 10)?,
            now(),
        )?;
        let path = root.path().join("family-authority.json");
        let bytes = fs::read(&path)?;
        let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
        let changed = match damage {
            "binding" => {
                value["normal_chat_session"]["reservations"]["intent:first"]["attempt"]
                    ["operation"]["budget"]["output_reserve"] = json!(1);
                serde_json::to_vec(&value)?
            }
            "missing_child" => {
                value["children"] = json!({});
                serde_json::to_vec(&value)?
            }
            _ => {
                let text = String::from_utf8(bytes)?;
                text.replacen(
                    "\"parent_revoked_at\":null",
                    "\"parent_revoked_at\":null,\"parent_revoked_at\":null",
                    1,
                )
                .into_bytes()
            }
        };
        fs::write(path, changed)?;
        assert!(
            active.read_normal_chat_reservation("intent:first").is_err(),
            "{damage}"
        );
        assert!(
            active
                .reserve_normal_chat_attempt(
                    &authority,
                    &request(&authority, "intent:next", 1)?,
                    now()
                )
                .is_err(),
            "{damage}"
        );
    }
    Ok(())
}

#[test]
fn reservation_write_interruptions_reconcile_without_double_charge() -> TestResult {
    use recursive_agent_policy::PermitTransitionStage as Stage;
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path())?;
    for stage in [
        Stage::TempWrite,
        Stage::TempFsync,
        Stage::Rename,
        Stage::DirectoryFsync,
    ] {
        let root = tempfile::tempdir()?;
        let active = store(root.path(), &authority)?;
        let req = request(&authority, "intent:first", 60)?;
        assert!(
            matches!(active.reserve_normal_chat_attempt_with_interruption(&authority, &req, now(), Some(stage)), Err(PolicyError::InjectedInterruption(actual)) if actual == stage)
        );
        drop(active);
        let reopened = store(root.path(), &authority)?;
        let visible = reopened.read_normal_chat_reservation("intent:first")?;
        assert_eq!(
            visible.is_some(),
            matches!(stage, Stage::Rename | Stage::DirectoryFsync)
        );
        let resumed = reopened.reserve_normal_chat_attempt(&authority, &req, now())?;
        assert_eq!(resumed.attempt.attempt_number, 1);
        if let Some(existing) = visible {
            assert_eq!(resumed, existing);
        }
        assert_eq!(reopened.reserved_budget()?, budget());
        assert_eq!(
            fs::read_dir(root.path())?
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".family-authority.tmp"))
                .count(),
            0
        );
    }
    Ok(())
}

#[test]
fn physical_request_length_is_charged_and_part_of_exact_intent() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path())?;
    let root = tempfile::tempdir()?;
    let active = store(root.path(), &authority)?;
    let mut oversized = request(&authority, "intent:oversized", 10)?;
    oversized.provider_request_bytes = 4097;
    denied(
        active.reserve_normal_chat_attempt(&authority, &oversized, now()),
        NormalChatEgressDenialV1::CapExhaustedRequestBytes,
    )?;
    assert_eq!(
        active.read_normal_chat_reservation("intent:oversized")?,
        None
    );
    let req = request(&authority, "intent:one", 10)?;
    let first = active.reserve_normal_chat_attempt(&authority, &req, now())?;
    assert_eq!(
        first.attempt.provider_request_bytes,
        b"physical-body".len() as u64
    );
    let mut conflict = req;
    conflict.provider_request_bytes += 1;
    denied(
        active.reserve_normal_chat_attempt(&authority, &conflict, now()),
        NormalChatEgressDenialV1::IntentConflict,
    )?;
    assert_eq!(active.reserved_budget()?, budget());
    Ok(())
}

#[test]
fn normal_chat_session_rejects_generic_child_allocation_and_bad_route() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path())?;
    let root = tempfile::tempdir()?;
    let store = store(root.path(), &authority)?;
    let req = request(&authority, "intent:one", 10)?;
    let reserved = store.reserve_normal_chat_attempt(&authority, &req, now())?;
    assert!(store
        .reserve_child(&reserved.child_control.request, now())
        .is_err());
    let mut wrong_route = request(&authority, "intent:bad", 10)?;
    wrong_route.operation.api_mode = "responses".into();
    denied(
        store.reserve_normal_chat_attempt(&authority, &wrong_route, now()),
        NormalChatEgressDenialV1::RouteNotAllowed,
    )?;
    assert_eq!(store.read_normal_chat_reservation("intent:bad")?, None);
    let mut wrong_session = request(&authority, "intent:other", 10)?;
    wrong_session.operation.conversation_ref = "conversation:other".into();
    denied(
        store.reserve_normal_chat_attempt(&authority, &wrong_session, now()),
        NormalChatEgressDenialV1::Malformed,
    )?;
    assert_eq!(store.reserved_budget()?, budget());
    Ok(())
}
