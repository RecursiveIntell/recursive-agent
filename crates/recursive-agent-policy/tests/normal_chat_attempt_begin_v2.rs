use chrono::{DateTime, TimeDelta, Utc};
use recursive_agent_contracts::{
    content_digest, parse_normal_chat_operation_v2_bytes, ContentDigest, CurrentReceiptId,
};
use recursive_agent_policy::{
    DurablePermitStore, FamilyAuthorityStore, NormalChatAttemptBeginV2,
    NormalChatAttemptConsumptionV2, NormalChatAttemptPolicyStateV2, NormalChatBeginInterruptionV2,
    NormalChatControlledFamilyV1, NormalChatEgressGrantStore, NormalChatEgressGrantV1,
    NormalChatFamilyReservationRequestV2, NormalChatFamilyReservationV2,
    NormalChatGrantAuthorityV1, PermitBudgetV1, PermitPurposeV1, PermitRevocationReasonV1,
    PermitStateV1, PermitTransitionStage, ReportedEffectOutcomeV1, ReportedEffectStateV1,
    ValidatedNormalChatSessionControlV1,
};
use serde_json::json;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

type TestResult = Result<(), Box<dyn std::error::Error>>;
#[path = "support/normal_chat_ledger_projection_v2.rs"]
mod ledger_projection;
#[path = "support/normal_chat_expired_recovery_v1.rs"]
mod recovery;
#[path = "support/normal_chat_settlement_v2.rs"]
mod settlement;
const HOME: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn now() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_792_008_000)
}
fn store(root: &Path) -> Result<DurablePermitStore, Box<dyn std::error::Error>> {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    Ok(DurablePermitStore::from_run_root_fd(&File::open(root)?)?)
}
struct Fixture {
    _auth_root: tempfile::TempDir,
    _parent_root: tempfile::TempDir,
    child_root: tempfile::TempDir,
    authority: NormalChatGrantAuthorityV1,
    parent_store: DurablePermitStore,
    control: ValidatedNormalChatSessionControlV1,
    family: NormalChatControlledFamilyV1,
    reservation: NormalChatFamilyReservationV2,
    child_store: DurablePermitStore,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let auth_root = tempfile::tempdir()?;
        fs::set_permissions(auth_root.path(), fs::Permissions::from_mode(0o700))?;
        let mut grant: NormalChatEgressGrantV1 = serde_json::from_value(json!({
            "schema": "recursive-agent.normal-chat-egress-grant/v1", "revision": 1,
            "ares_home_digest": HOME, "mode": "enforce", "any_route": false,
            "routes": [{"provider_identity": "openai_compatible:https://provider.test/v1", "model_ref": "model:fixture", "api_mode": "chat_completions"}],
            "caps": {"max_attempts": 3, "max_output_tokens": 100, "max_wall_time_ms": 1000, "max_request_bytes": 4096},
            "expires_at": now() + TimeDelta::seconds(600), "content_retention": "digest_only", "policy_digest": HOME,
        }))?;
        grant.policy_digest = grant.computed_policy_digest()?;
        let path = auth_root.path().join("grant.json");
        fs::write(&path, serde_json::to_vec(&grant)?)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let authority = NormalChatEgressGrantStore::from_dir_fd(&File::open(auth_root.path())?)?
            .load_from_path(&path, HOME, now())?;
        let parent_root = tempfile::tempdir()?;
        let parent_store = store(parent_root.path())?;
        let control = parent_store.open_normal_chat_session_control(
            &authority,
            "conversation:fixture",
            None,
            now,
        )?;
        let family = FamilyAuthorityStore::from_normal_chat_session_control(
            &File::open(parent_root.path())?,
            &authority,
            &control,
            now,
        )?;
        let session = control.session();
        let operation = parse_normal_chat_operation_v2_bytes(&serde_json::to_vec(&json!({
            "schema": "recursive-agent.normal-chat/v2", "conversation_ref": session.conversation_ref,
            "parent_run_id": session.run_id()?, "materialization_ref": "materialization:fixture", "materialization_digest": HOME,
            "policy_basis_ref": "normal-chat-grant:revision-1", "policy_basis_digest": grant.policy_digest,
            "source_revision": "source:fixture", "route_class": "conversation", "provider_identity": "openai_compatible:https://provider.test/v1", "model_ref": "model:fixture", "api_mode": "chat_completions",
            "request_digest": HOME, "request_projection_schema": "ares-json-sorted-v1", "budget": {"output_reserve": 10, "max_wall_time_ms": 1000, "max_request_bytes": 4096},
            "replay": "unavailable", "provenance": [{"source": "urn:test:fixture", "digest": content_digest(&"fixture")?}],
        }))?)?;
        let request = NormalChatFamilyReservationRequestV2 {
            operation,
            provider_request_digest: ContentDigest::compute(b"physical-body"),
            provider_request_bytes: b"physical-body".len() as u64,
            dispatch_intent_ref: "intent:first".into(),
            parent_admission_receipt_id: CurrentReceiptId::try_new(format!(
                "v1:recursive-agent/receipt/v1:det:{}",
                "c".repeat(64)
            ))?,
            requested_budget: PermitBudgetV1 {
                max_wall_time_ms: 1000,
                max_output_bytes: 1024 * 1024,
                max_artifact_bytes: 1024 * 1024,
            },
        };
        let reservation = family.reserve_normal_chat_attempt(&authority, &request, now)?;
        let child_root = tempfile::tempdir()?;
        let child_store = store(child_root.path())?;
        Ok(Self {
            _auth_root: auth_root,
            _parent_root: parent_root,
            child_root,
            authority,
            parent_store,
            control,
            family,
            reservation,
            child_store,
        })
    }
    fn begin(&self) -> Result<NormalChatAttemptBeginV2, recursive_agent_policy::PolicyError> {
        self.child_store.begin_normal_chat_attempt_v2(
            &self.authority,
            &self.family,
            "intent:first",
            now,
        )
    }
}
fn fresh(
    result: NormalChatAttemptBeginV2,
) -> Result<NormalChatAttemptConsumptionV2, Box<dyn std::error::Error>> {
    match result {
        NormalChatAttemptBeginV2::Consumed(cap) => Ok(*cap),
        NormalChatAttemptBeginV2::Existing(_) => {
            Err("expected first policy consumption, not readback".into())
        }
    }
}
fn permit_paths(root: &Path) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(root.join("permits"))? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with("permit-") {
            paths.push(entry.path());
        }
    }
    Ok(paths)
}

#[test]
fn locator_replacement_after_snapshot_is_rejected_for_every_prefix() -> TestResult {
    for prefix in ["unbegun", "prepared", "consumed"] {
        let fx = Fixture::new()?;
        if prefix == "prepared" {
            assert!(fx
                .child_store
                .begin_normal_chat_attempt_v2_with_interruption(
                    &fx.authority,
                    &fx.family,
                    "intent:first",
                    now,
                    Some(NormalChatBeginInterruptionV2::Control(
                        PermitTransitionStage::DirectoryFsync
                    )),
                )
                .is_err());
        } else if prefix == "consumed" {
            fresh(fx.begin()?)?;
        }
        let historical = FamilyAuthorityStore::from_dir_fd(
            &File::open(fx._parent_root.path())?,
            fx.control.family_grant(),
        )?;
        let swap = std::cell::RefCell::new(Ok::<(), std::io::Error>(()));
        let result = fx.child_store.read_normal_chat_attempt_v2_with_observer(
            &historical,
            "intent:first",
            || {
                *swap.borrow_mut() = (|| {
                    fs::rename(
                        fx.child_root.path().join("permits"),
                        fx.child_root.path().join("detached"),
                    )?;
                    fs::create_dir(fx.child_root.path().join("permits"))
                })();
            },
        );
        swap.into_inner()?;
        assert!(
            result.is_err(),
            "{prefix} detached snapshot escaped its locator fence"
        );
    }
    Ok(())
}

#[test]
fn v2_effect_role_has_a_closed_wire_shape() -> TestResult {
    use recursive_agent_policy::NormalChatAttemptRecordV2;
    let valid: NormalChatAttemptRecordV2 = serde_json::from_value(json!({"role":"effect"}))?;
    assert_eq!(serde_json::to_value(valid)?, json!({"role":"effect"}));
    assert!(serde_json::from_value::<NormalChatAttemptRecordV2>(
        json!({"role":"effect","admission":{}})
    )
    .is_err());
    assert!(serde_json::from_value::<NormalChatAttemptRecordV2>(json!({"role":"future"})).is_err());
    Ok(())
}
#[test]
fn native_release_fence_rejects_current_revocation_close_expiry_and_regression() -> TestResult {
    for event in [
        "root",
        "family",
        "closed",
        "local",
        "expired",
        "regressed",
        "settled",
        "ok",
    ] {
        let fx = Fixture::new()?;
        let cap = fresh(fx.begin()?)?;
        match event {
            "root" => {
                fx.parent_store.revoke(
                    &fx.control.permit().permit_id,
                    PermitRevocationReasonV1::Operator,
                    now(),
                )?;
            }
            "family" => FamilyAuthorityStore::from_dir_fd(
                &File::open(fx._parent_root.path())?,
                fx.control.family_grant(),
            )?
            .revoke_parent(now())?,
            "closed" => FamilyAuthorityStore::from_dir_fd(
                &File::open(fx._parent_root.path())?,
                fx.control.family_grant(),
            )?
            .close_normal_chat_session(now())?,
            "local" => {
                fx.child_store.revoke(
                    &cap.control_permit().permit_id,
                    PermitRevocationReasonV1::Operator,
                    now(),
                )?;
            }
            "settled" => {
                fx.child_store.settle_normal_chat_attempt_v2(
                    &settlement::historical(&fx)?,
                    "intent:first",
                    &cap.preflight().receipt_digest,
                    &settlement::report()?,
                    now,
                )?;
            }
            _ => {}
        }
        let clock_now = if event == "expired" {
            now() + TimeDelta::seconds(2)
        } else {
            now()
        };
        let floor = if event == "regressed" {
            now() + TimeDelta::milliseconds(1)
        } else {
            now()
        };
        let result = cap.check_runtime_release_v2(
            &fx.authority,
            &fx.family,
            floor,
            &fx.family.read_normal_chat_session_snapshot_v2()?,
            || clock_now,
        );
        assert_eq!(result.is_ok(), event == "ok", "{event}");
        assert!(fx
            .family
            .read_normal_chat_reservation("intent:first")?
            .is_some());
    }
    Ok(())
}

#[test]
fn generic_issuers_stay_network_denied_and_v2_scope_is_exact() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let mut root_effect = cap.effect_permit().binding.clone();
    root_effect.parent_permit_id = None;
    root_effect.parent_operation_id = None;
    assert!(fx.child_store.issue(&root_effect, now()).is_err());
    assert!(fx
        .child_store
        .issue_effect(&cap.effect_permit().binding, Vec::new(), now())
        .is_err());
    let ceiling = cap
        .control_permit()
        .delegation_ceiling
        .clone()
        .ok_or("no ceiling")?;
    assert!(fx
        .child_store
        .issue_control(&cap.control_permit().binding, ceiling, now())
        .is_err());
    for (tool, scope, root) in [
        ("normal_chat", "native-normal-chat-v2", false),
        ("normal_chat_v2", "other-scope", false),
        ("normal_chat_v2", "native-normal-chat-v2", true),
    ] {
        let mut changed = root_effect.clone();
        changed.tool = tool.into();
        changed.effect.scope_name = scope.into();
        if root {
            changed.effect.read_roots = vec!["/tmp".into()];
        }
        changed.effect_digest = content_digest(&changed.effect)?;
        assert!(changed.validate().is_err());
    }
    Ok(())
}
#[test]
fn expiry_before_first_child_write_keeps_only_parent_reservation() -> TestResult {
    let fx = Fixture::new()?;
    assert!(fx
        .child_store
        .begin_normal_chat_attempt_v2(&fx.authority, &fx.family, "intent:first", || now()
            + TimeDelta::seconds(2))
        .is_err());
    assert!(permit_paths(fx.child_root.path())?.is_empty());
    assert_eq!(
        fx.family.read_normal_chat_reservation("intent:first")?,
        Some(fx.reservation.clone())
    );
    Ok(())
}
#[test]
fn readback_resolves_canonical_identity_without_accepting_altered_copies() -> TestResult {
    let fx = Fixture::new()?;
    let mut altered_copy = fx.reservation.clone();
    altered_copy
        .child_control
        .request
        .requested_budget
        .max_artifact_bytes += 1;
    let empty = fx
        .family
        .read_child_policy_v2(&fx.child_store, "intent:first")?;
    assert_eq!(empty.state, NormalChatAttemptPolicyStateV2::Unbegun);
    assert_eq!(empty.attempt, fx.reservation.attempt);
    assert_ne!(altered_copy, fx.reservation);
    assert!(fx
        .family
        .read_child_policy_v2(&fx.child_store, "intent:unreserved")
        .is_err());
    fresh(fx.begin()?)?;
    assert_eq!(
        fx.family.read_normal_chat_reservation("intent:first")?,
        Some(fx.reservation.clone())
    );
    assert!(matches!(fx.begin()?, NormalChatAttemptBeginV2::Existing(_)));
    Ok(())
}

#[test]
fn final_clock_sample_controls_native_consumption_release() -> TestResult {
    use std::cell::Cell;
    let baseline = Fixture::new()?;
    let reads = Cell::new(0_u32);
    fresh(baseline.child_store.begin_normal_chat_attempt_v2(
        &baseline.authority,
        &baseline.family,
        "intent:first",
        || {
            reads.set(reads.get() + 1);
            now()
        },
    )?)?;
    let final_read = reads.get();
    assert!(final_read > 1);
    for final_time in [
        now() + TimeDelta::seconds(2),
        now() - TimeDelta::milliseconds(1),
    ] {
        let fx = Fixture::new()?;
        let called = Cell::new(0_u32);
        let result = fx.child_store.begin_normal_chat_attempt_v2(
            &fx.authority,
            &fx.family,
            "intent:first",
            || {
                called.set(called.get() + 1);
                if called.get() >= final_read {
                    final_time
                } else {
                    now()
                }
            },
        );
        assert!(result.is_err(), "last clock value must not be ignored");
        assert_eq!(
            fx.family
                .read_child_policy_v2(&fx.child_store, "intent:first")?
                .state,
            NormalChatAttemptPolicyStateV2::Consumed
        );
    }
    Ok(())
}

#[test]
fn empty_child_readback_rejects_an_intent_without_a_canonical_reservation() -> TestResult {
    let fx = Fixture::new()?;
    assert!(fx
        .family
        .read_child_policy_v2(&fx.child_store, "intent:never-reserved")
        .is_err());
    let canonical = fx
        .family
        .read_child_policy_v2(&fx.child_store, "intent:first")?;
    assert_eq!(canonical.attempt, fx.reservation.attempt);
    assert_eq!(canonical.state, NormalChatAttemptPolicyStateV2::Unbegun);
    Ok(())
}

#[test]
fn replaced_child_permit_directory_fences_begin_and_readback() -> TestResult {
    let fx = Fixture::new()?;
    fs::rename(
        fx.child_root.path().join("permits"),
        fx.child_root.path().join("old-permits"),
    )?;
    fs::create_dir(fx.child_root.path().join("permits"))?;
    fs::set_permissions(
        fx.child_root.path().join("permits"),
        fs::Permissions::from_mode(0o700),
    )?;
    assert!(fx.begin().is_err());
    assert!(fx
        .family
        .read_child_policy_v2(&fx.child_store, "intent:first")
        .is_err());
    Ok(())
}
#[test]
fn child_directory_swap_during_control_publication_never_releases_continuation() -> TestResult {
    use std::cell::Cell;
    let fx = Fixture::new()?;
    let swapped = Cell::new(false);
    let mut io_error = None;
    let root = fx.child_root.path();
    let result = fx.child_store.begin_normal_chat_attempt_v2(
        &fx.authority,
        &fx.family,
        "intent:first",
        || {
            let published = permit_paths(root).is_ok_and(|paths| !paths.is_empty());
            if published && !swapped.get() {
                swapped.set(true);
                let action = (|| -> std::io::Result<()> {
                    fs::rename(root.join("permits"), root.join("old-permits"))?;
                    fs::create_dir(root.join("permits"))?;
                    fs::set_permissions(root.join("permits"), fs::Permissions::from_mode(0o700))
                })();
                if let Err(error) = action {
                    io_error = Some(error);
                }
            }
            now()
        },
    );
    if let Some(error) = io_error {
        return Err(error.into());
    }
    assert!(swapped.get(), "did not reach published-control boundary");
    assert!(result.is_err());
    Ok(())
}

#[test]
fn canonical_readback_after_revocation_does_not_require_fresh_authority() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let expected = cap.preflight().clone();
    fx.parent_store.revoke(
        &fx.control.permit().permit_id,
        PermitRevocationReasonV1::Operator,
        now(),
    )?;
    let historical_family = FamilyAuthorityStore::from_dir_fd(
        &File::open(fx._parent_root.path())?,
        fx.control.family_grant(),
    )?;
    let reopened_child = store(fx.child_root.path())?;
    let view = reopened_child.read_normal_chat_attempt_v2(&historical_family, "intent:first")?;
    assert_eq!(view.state, NormalChatAttemptPolicyStateV2::Consumed);
    assert_eq!(view.preflight.as_ref(), Some(&expected));
    assert!(matches!(
        reopened_child.begin_normal_chat_attempt_v2(
            &fx.authority,
            &fx.family,
            "intent:first",
            || now() + TimeDelta::seconds(302)
        )?,
        NormalChatAttemptBeginV2::Existing(_)
    ));
    assert!(historical_family
        .read_normal_chat_reservation("intent:first")?
        .is_some());
    Ok(())
}

#[test]
fn begin_writes_exact_control_and_consumed_effect_with_bound_preflight() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    assert_eq!(cap.attempt(), &fx.reservation.attempt);
    let preflight = cap.preflight();
    preflight.validate()?;
    assert_eq!(cap.effect_permit().purpose, PermitPurposeV1::Effect);
    assert_eq!(cap.effect_permit().binding.tool, "normal_chat_v2");
    assert!(cap.effect_permit().binding.effect.network_allowed);
    assert!(!cap.control_permit().binding.effect.network_allowed);
    let ceiling = cap
        .control_permit()
        .delegation_ceiling
        .as_ref()
        .ok_or("missing exact ceiling")?;
    assert_eq!(ceiling.actions.len(), 1);
    assert_eq!(
        ceiling.actions[0].action_digest,
        cap.effect_permit().binding.action_digest
    );
    assert_eq!(
        ceiling.actions[0].args_digest,
        cap.effect_permit().binding.args_digest
    );
    let stored = fx.child_store.state(&cap.effect_permit().permit_id)?;
    assert!(matches!(stored.state, PermitStateV1::Consumed { .. }));
    assert_eq!(stored.preflight_receipt.as_ref(), Some(preflight));
    assert_eq!(permit_paths(fx.child_root.path())?.len(), 2);
    let readback = fx
        .family
        .read_child_policy_v2(&fx.child_store, "intent:first")?;
    assert_eq!(readback.state, NormalChatAttemptPolicyStateV2::Consumed);
    assert_eq!(readback.preflight.as_ref(), Some(preflight));
    Ok(())
}
#[test]
fn begin_retry_and_lost_ack_are_status_only_and_never_mint_another_continuation() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let expected = cap.preflight().clone();
    drop(cap);
    let reopened = store(fx.child_root.path())?;
    let readback = fx.family.read_child_policy_v2(&reopened, "intent:first")?;
    assert_eq!(readback.preflight.as_ref(), Some(&expected));
    match reopened.begin_normal_chat_attempt_v2(&fx.authority, &fx.family, "intent:first", now)? {
        NormalChatAttemptBeginV2::Existing(old) => {
            assert_eq!(old.preflight.as_ref(), Some(&expected))
        }
        NormalChatAttemptBeginV2::Consumed(_) => {
            return Err("retry minted another continuation".into())
        }
    }
    assert_eq!(permit_paths(fx.child_root.path())?.len(), 2);
    Ok(())
}
#[test]
fn simultaneous_begin_on_independent_handles_consumes_exactly_once() -> TestResult {
    let fx = Fixture::new()?;
    let mut workers = Vec::new();
    for _ in 0..4 {
        let local = store(fx.child_root.path())?;
        let authority = fx.authority.clone();
        let family = fx.family.clone();
        workers.push(std::thread::spawn(move || {
            local.begin_normal_chat_attempt_v2(&authority, &family, "intent:first", now)
        }));
    }
    let mut fresh_count = 0;
    for worker in workers {
        if matches!(
            worker.join().map_err(|_| "worker panicked")??,
            NormalChatAttemptBeginV2::Consumed(_)
        ) {
            fresh_count += 1;
        }
    }
    assert_eq!(fresh_count, 1);
    assert_eq!(permit_paths(fx.child_root.path())?.len(), 2);
    Ok(())
}
#[test]
fn revoked_parent_missing_intent_and_parent_child_root_alias_never_issue_effect() -> TestResult {
    let fx = Fixture::new()?;
    assert!(fx
        .child_store
        .begin_normal_chat_attempt_v2(&fx.authority, &fx.family, "intent:missing", now)
        .is_err());
    assert!(fx
        .parent_store
        .begin_normal_chat_attempt_v2(&fx.authority, &fx.family, "intent:first", now)
        .is_err());
    fx.parent_store.revoke(
        &fx.control.permit().permit_id,
        PermitRevocationReasonV1::Operator,
        now(),
    )?;
    assert!(fx.begin().is_err());
    assert!(permit_paths(fx.child_root.path())?.is_empty());
    Ok(())
}
#[test]
fn different_attempt_cannot_reuse_an_admitted_child_root() -> TestResult {
    let fx = Fixture::new()?;
    fresh(fx.begin()?)?;
    let mut request = NormalChatFamilyReservationRequestV2 {
        operation: fx.reservation.attempt.operation.clone(),
        provider_request_digest: ContentDigest::compute(b"other-body"),
        provider_request_bytes: b"other-body".len() as u64,
        dispatch_intent_ref: "intent:second".into(),
        parent_admission_receipt_id: fx
            .reservation
            .child_control
            .request
            .parent_admission_receipt_id
            .clone(),
        requested_budget: fx
            .reservation
            .child_control
            .request
            .requested_budget
            .clone(),
    };
    request.operation.materialization_ref = "materialization:other".into();
    let _second = fx
        .family
        .reserve_normal_chat_attempt(&fx.authority, &request, now)?;
    assert!(fx
        .child_store
        .begin_normal_chat_attempt_v2(&fx.authority, &fx.family, "intent:second", now)
        .is_err());
    assert!(fx
        .family
        .read_child_policy_v2(&fx.child_store, "intent:second")
        .is_err());
    assert_eq!(permit_paths(fx.child_root.path())?.len(), 2);
    Ok(())
}
#[test]
fn generic_apis_cannot_reconsume_or_report_v2_outcomes() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let effect = cap.effect_permit();
    assert!(fx
        .child_store
        .consume(&effect.permit_id, &effect.binding, now())
        .is_err());
    assert!(fx
        .child_store
        .consume_with_preflight(&effect.permit_id, &effect.binding, now)
        .is_err());
    assert!(fx
        .child_store
        .read_external_permit(&effect.permit_id, &effect.binding, None)
        .is_err());
    assert!(fx
        .child_store
        .record_reported_outcome(
            &effect.permit_id,
            &cap.preflight().receipt_digest,
            ReportedEffectOutcomeV1 {
                state: ReportedEffectStateV1::Succeeded,
                duration_ms: 1,
                error_type: None
            },
            now()
        )
        .is_err());
    assert!(fx
        .child_store
        .state(&effect.permit_id)?
        .outcome_receipt
        .is_none());
    Ok(())
}
#[test]
fn control_only_partial_prefix_is_readback_only_after_reopen() -> TestResult {
    for stage in [
        PermitTransitionStage::TempWrite,
        PermitTransitionStage::TempFsync,
        PermitTransitionStage::Rename,
        PermitTransitionStage::DirectoryFsync,
    ] {
        let fx = Fixture::new()?;
        assert!(fx
            .child_store
            .begin_normal_chat_attempt_v2_with_interruption(
                &fx.authority,
                &fx.family,
                "intent:first",
                now,
                Some(NormalChatBeginInterruptionV2::Control(stage))
            )
            .is_err());
        let reopened = store(fx.child_root.path())?;
        let readback = fx.family.read_child_policy_v2(&reopened, "intent:first")?;
        if matches!(
            stage,
            PermitTransitionStage::Rename | PermitTransitionStage::DirectoryFsync
        ) {
            assert_eq!(readback.state, NormalChatAttemptPolicyStateV2::Prepared);
            assert!(matches!(
                reopened.begin_normal_chat_attempt_v2(
                    &fx.authority,
                    &fx.family,
                    "intent:first",
                    now
                )?,
                NormalChatAttemptBeginV2::Existing(_)
            ));
        } else {
            assert_eq!(readback.state, NormalChatAttemptPolicyStateV2::Unbegun);
        }
    }
    Ok(())
}
#[test]
fn consumed_effect_after_lost_write_ack_is_never_a_new_begin() -> TestResult {
    for stage in [
        PermitTransitionStage::TempWrite,
        PermitTransitionStage::TempFsync,
        PermitTransitionStage::Rename,
        PermitTransitionStage::DirectoryFsync,
    ] {
        let fx = Fixture::new()?;
        assert!(fx
            .child_store
            .begin_normal_chat_attempt_v2_with_interruption(
                &fx.authority,
                &fx.family,
                "intent:first",
                now,
                Some(NormalChatBeginInterruptionV2::Effect(stage))
            )
            .is_err());
        let reopened = store(fx.child_root.path())?;
        let old = fx.family.read_child_policy_v2(&reopened, "intent:first")?;
        assert_eq!(
            old.state,
            if matches!(
                stage,
                PermitTransitionStage::Rename | PermitTransitionStage::DirectoryFsync
            ) {
                NormalChatAttemptPolicyStateV2::Consumed
            } else {
                NormalChatAttemptPolicyStateV2::Prepared
            }
        );
        assert!(matches!(
            reopened.begin_normal_chat_attempt_v2(
                &fx.authority,
                &fx.family,
                "intent:first",
                now
            )?,
            NormalChatAttemptBeginV2::Existing(_)
        ));
    }
    Ok(())
}
#[test]
fn post_publish_expiry_returns_no_continuation_but_preserves_consumed_evidence() -> TestResult {
    let fx = Fixture::new()?;
    let path = fx.child_root.path().join("permits");
    let result = fx.child_store.begin_normal_chat_attempt_v2(
        &fx.authority,
        &fx.family,
        "intent:first",
        || {
            let effect_present = fs::read_dir(&path)
                .ok()
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .any(|entry| {
                    fs::read(entry.path())
                        .ok()
                        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                        .is_some_and(|v| v["permit"]["binding"]["tool"] == "normal_chat_v2")
                });
            if effect_present {
                now() + TimeDelta::seconds(2)
            } else {
                now()
            }
        },
    );
    assert!(result.is_err());
    assert_eq!(
        fx.family
            .read_child_policy_v2(&fx.child_store, "intent:first")?
            .state,
        NormalChatAttemptPolicyStateV2::Consumed
    );
    Ok(())
}
#[test]
fn stripping_v2_role_does_not_downgrade_to_legacy_records() -> TestResult {
    let fx = Fixture::new()?;
    fresh(fx.begin()?)?;
    let paths = permit_paths(fx.child_root.path())?;
    let path = paths
        .iter()
        .find(|p| {
            fs::read(p)
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .is_some_and(|v| v["permit"]["binding"]["tool"] == "normal_chat_v2")
        })
        .ok_or("missing effect")?;
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    assert!(value
        .as_object_mut()
        .ok_or("not object")?
        .remove("normal_chat_attempt_v2")
        .is_some());
    fs::write(path, serde_json::to_vec(&value)?)?;
    assert!(fx
        .family
        .read_child_policy_v2(&fx.child_store, "intent:first")
        .is_err());
    Ok(())
}
