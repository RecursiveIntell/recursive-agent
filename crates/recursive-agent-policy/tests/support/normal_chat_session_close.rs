use super::*;
#[path = "normal_chat_session_close_confirmation.rs"]
mod confirmation;
use recursive_agent_policy::{
    NormalChatGrantContextV2, NormalChatSessionCloseInterruptionV2 as Stop, PermitTransitionStage,
};
use std::cell::Cell;

struct Fixture {
    _auth: tempfile::TempDir,
    root: tempfile::TempDir,
    authority: NormalChatGrantAuthorityV1,
    store: DurablePermitStore,
    family: FamilyAuthorityStore,
    control: recursive_agent_policy::ValidatedNormalChatSessionControlV1,
    context: NormalChatGrantContextV2,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let auth = tempfile::tempdir()?;
        let authority = authority(auth.path(), 1)?;
        let root = tempfile::tempdir()?;
        let store = store(root.path())?;
        let control = store.open_normal_chat_session_control(
            &authority,
            "conversation:fixture",
            None,
            now,
        )?;
        FamilyAuthorityStore::from_normal_chat_session_control(
            &File::open(root.path())?,
            &authority,
            &control,
            now,
        )?;
        let context = NormalChatGrantContextV2 {
            grant: authority.grant().clone(),
            session: control.session().clone(),
            root_control: control.permit().clone(),
        };
        let family = FamilyAuthorityStore::require_existing_from_dir_fd(
            &File::open(root.path())?,
            context.session_family_grant_v2()?,
        )?;
        Ok(Self {
            _auth: auth,
            root,
            authority,
            store,
            family,
            control,
            context,
        })
    }
    fn record(&self) -> Result<recursive_agent_policy::PermitRecordV1, Box<dyn std::error::Error>> {
        Ok(self
            .store
            .read_normal_chat_session_control_record()?
            .ok_or("control missing")?)
    }
}
#[test]
fn native_session_close_preserves_all_charges_and_fences_cached_controls() -> TestResult {
    let fx = Fixture::new()?;
    let guarded = FamilyAuthorityStore::require_existing_normal_chat_session_family(
        &File::open(fx.root.path())?,
        &fx.authority,
        &fx.control,
        now,
    )?;
    let charge = guarded.reserve_normal_chat_attempt(
        &fx.authority,
        &attempt_request(&fx.control, "intent:first")?,
        now,
    )?;
    let before = fx.family.read_normal_chat_session_snapshot_v2()?;
    let closed =
        fx.store
            .close_normal_chat_session_v2(&fx.family, &fx.context, &before, now(), || {
                now() + TimeDelta::milliseconds(10)
            })?;
    assert_eq!(closed.snapshot.reservations, before.reservations);
    assert_eq!(
        closed.snapshot.admission.closed_at,
        Some(now() + TimeDelta::milliseconds(10))
    );
    assert!(matches!(
        closed.root_control.state,
        PermitStateV1::Revoked {
            reason: PermitRevocationReasonV1::Operator,
            ..
        }
    ));
    assert_eq!(closed.root_control.permit, fx.context.root_control);
    assert!(guarded
        .guard_child_dispatch(
            &fx.authority,
            &charge.child_control.request.child_run_id,
            &charge.child_control.child_control_permit_id,
            now
        )
        .is_err());
    assert!(guarded
        .reserve_normal_chat_attempt(
            &fx.authority,
            &attempt_request(&fx.control, "intent:later")?,
            now
        )
        .is_err());
    assert!(fx
        .store
        .require_existing_normal_chat_session_control(
            &fx.authority,
            "conversation:fixture",
            None,
            &fx.record()?,
            now
        )
        .is_err());
    Ok(())
}
#[test]
fn close_is_narrowing_after_expiry_and_exact_historical_retry_needs_no_clock() -> TestResult {
    let fx = Fixture::new()?;
    let before = fx.family.read_normal_chat_session_snapshot_v2()?;
    let expiry = fx.context.root_control.binding.expires_at;
    let closed =
        fx.store
            .close_normal_chat_session_v2(&fx.family, &fx.context, &before, now(), || {
                now() + TimeDelta::seconds(700)
            })?;
    assert_eq!(closed.root_control.permit.binding.expires_at, expiry);
    let bytes = fs::read(fx.root.path().join("family-authority.json"))?;
    let calls = Cell::new(0);
    let again = fx.store.close_normal_chat_session_v2(
        &fx.family,
        &fx.context,
        &closed.snapshot,
        now() + TimeDelta::seconds(800),
        || {
            calls.set(calls.get() + 1);
            now() - TimeDelta::seconds(1)
        },
    )?;
    assert_eq!(calls.get(), 0);
    assert_eq!(again, closed);
    assert_eq!(
        bytes,
        fs::read(fx.root.path().join("family-authority.json"))?
    );
    Ok(())
}
#[test]
fn existing_root_revocation_reason_and_time_are_never_overwritten() -> TestResult {
    for reason in [
        PermitRevocationReasonV1::Operator,
        PermitRevocationReasonV1::ParentRevoked,
        PermitRevocationReasonV1::PolicySuperseded,
        PermitRevocationReasonV1::OperationCancelled,
    ] {
        let fx = Fixture::new()?;
        let old = fx.store.revoke(
            &fx.context.root_control.permit_id,
            reason,
            now() + TimeDelta::milliseconds(5),
        )?;
        let before = fx.family.read_normal_chat_session_snapshot_v2()?;
        let closed = fx.store.close_normal_chat_session_v2(
            &fx.family,
            &fx.context,
            &before,
            now() + TimeDelta::milliseconds(6),
            || now() + TimeDelta::milliseconds(10),
        )?;
        assert_eq!(closed.root_control, old);
    }
    let fx = Fixture::new()?;
    fx.family.revoke_parent(now())?;
    let before = fx.family.read_normal_chat_session_snapshot_v2()?;
    let closed =
        fx.store
            .close_normal_chat_session_v2(&fx.family, &fx.context, &before, now(), now)?;
    assert!(matches!(
        closed.root_control.state,
        PermitStateV1::Revoked {
            reason: PermitRevocationReasonV1::ParentRevoked,
            ..
        }
    ));
    assert_eq!(
        closed.snapshot.admission.parent_revoked_at,
        before.admission.parent_revoked_at
    );
    Ok(())
}
#[test]
fn stale_snapshot_cross_root_and_wrong_context_reject_without_closing() -> TestResult {
    let fx = Fixture::new()?;
    let before = fx.family.read_normal_chat_session_snapshot_v2()?;
    fx.family.reserve_normal_chat_attempt(
        &fx.authority,
        &attempt_request(&fx.control, "intent:first")?,
        now(),
    )?;
    let bytes = fs::read(fx.root.path().join("family-authority.json"))?;
    let record = fx.record()?;
    assert!(fx
        .store
        .close_normal_chat_session_v2(&fx.family, &fx.context, &before, now(), now)
        .is_err());
    let current = fx.family.read_normal_chat_session_snapshot_v2()?;
    let other = Fixture::new()?;
    assert!(other
        .store
        .close_normal_chat_session_v2(&fx.family, &fx.context, &current, now(), now)
        .is_err());
    let mut wrong = fx.context.clone();
    wrong.session.conversation_ref = "conversation:wrong".into();
    assert!(fx
        .store
        .close_normal_chat_session_v2(&fx.family, &wrong, &current, now(), now)
        .is_err());
    assert_eq!(
        bytes,
        fs::read(fx.root.path().join("family-authority.json"))?
    );
    assert_eq!(fx.record()?, record);
    Ok(())
}
#[test]
fn native_close_fault_matrix_preserves_uncertain_commits_without_refunds() -> TestResult {
    for root_fault in [false, true] {
        for stage in [
            PermitTransitionStage::TempWrite,
            PermitTransitionStage::TempFsync,
            PermitTransitionStage::Rename,
            PermitTransitionStage::DirectoryFsync,
        ] {
            let fx = Fixture::new()?;
            fx.family.reserve_normal_chat_attempt(
                &fx.authority,
                &attempt_request(&fx.control, "intent:first")?,
                now(),
            )?;
            let before = fx.family.read_normal_chat_session_snapshot_v2()?;
            let stop = if root_fault {
                Stop::RootClose(stage)
            } else {
                Stop::FamilyClose(stage)
            };
            assert!(fx
                .store
                .close_normal_chat_session_v2_with_interruption(
                    &fx.family,
                    &fx.context,
                    &before,
                    now(),
                    || now() + TimeDelta::milliseconds(10),
                    Some(stop)
                )
                .is_err());
            let after = fx.family.read_normal_chat_session_snapshot_v2()?;
            assert_eq!(after.reservations, before.reservations);
            let committed = matches!(
                stage,
                PermitTransitionStage::Rename | PermitTransitionStage::DirectoryFsync
            );
            assert_eq!(after.admission.closed_at.is_some(), root_fault || committed);
            let old = fx.record()?;
            assert_eq!(
                matches!(old.state, PermitStateV1::Revoked { .. }),
                root_fault && committed
            );
            let done = fx.store.close_normal_chat_session_v2(
                &fx.family,
                &fx.context,
                &after,
                now(),
                || now() + TimeDelta::milliseconds(20),
            )?;
            assert_eq!(done.snapshot.reservations, before.reservations);
            if after.admission.closed_at.is_some() {
                assert_eq!(done.snapshot.admission.closed_at, after.admission.closed_at);
            }
            if matches!(old.state, PermitStateV1::Revoked { .. }) {
                assert_eq!(done.root_control, old);
            }
        }
    }
    Ok(())
}
#[test]
fn regressed_clock_rejects_missing_transition_and_retains_first_close() -> TestResult {
    let fx = Fixture::new()?;
    let before = fx.family.read_normal_chat_session_snapshot_v2()?;
    assert!(fx
        .store
        .close_normal_chat_session_v2(
            &fx.family,
            &fx.context,
            &before,
            now() + TimeDelta::milliseconds(10),
            now
        )
        .is_err());
    assert_eq!(fx.family.read_normal_chat_session_snapshot_v2()?, before);
    assert!(fx
        .store
        .close_normal_chat_session_v2_with_interruption(
            &fx.family,
            &fx.context,
            &before,
            now(),
            || now() + TimeDelta::milliseconds(10),
            Some(Stop::RootClose(PermitTransitionStage::TempWrite))
        )
        .is_err());
    let partial = fx.family.read_normal_chat_session_snapshot_v2()?;
    let bytes = fs::read(fx.root.path().join("family-authority.json"))?;
    assert!(fx
        .store
        .close_normal_chat_session_v2(&fx.family, &fx.context, &partial, now(), || now()
            + TimeDelta::milliseconds(5))
        .is_err());
    assert_eq!(
        bytes,
        fs::read(fx.root.path().join("family-authority.json"))?
    );
    assert!(matches!(fx.record()?.state, PermitStateV1::Issued));
    Ok(())
}

fn record_path(fx: &Fixture) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    Ok(fs::read_dir(fx.root.path().join("permits"))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("permit-"))
                && p.extension().is_some_and(|x| x == "json")
        })
        .ok_or("permit path absent")?)
}
#[test]
fn missing_native_authority_or_locks_are_never_recreated_by_close() -> TestResult {
    for missing in [
        "record",
        "family-authority.json",
        ".family-authority.lock",
        "permits",
        "permit-lock",
    ] {
        let fx = Fixture::new()?;
        let expected = fx.family.read_normal_chat_session_snapshot_v2()?;
        let path = match missing {
            "record" => record_path(&fx)?,
            "permit-lock" => fx.root.path().join("permits/.permit.lock"),
            _ => fx.root.path().join(missing),
        };
        fs::rename(&path, fx.root.path().join(format!("removed-{missing}")))?;
        assert!(
            fx.store
                .close_normal_chat_session_v2(&fx.family, &fx.context, &expected, now(), now)
                .is_err(),
            "{missing}"
        );
        assert!(!path.exists(), "close recreated {missing}");
    }
    Ok(())
}
#[test]
fn deleting_root_authority_during_each_timed_transition_never_recreates_it() -> TestResult {
    for sample in [1, 2] {
        let fx = Fixture::new()?;
        let expected = fx.family.read_normal_chat_session_snapshot_v2()?;
        let path = record_path(&fx)?;
        let count = Cell::new(0);
        let failure = std::cell::RefCell::new(None);
        let result = fx.store.close_normal_chat_session_v2(
            &fx.family,
            &fx.context,
            &expected,
            now(),
            || {
                count.set(count.get() + 1);
                if count.get() == sample {
                    if let Err(e) = fs::remove_file(&path) {
                        *failure.borrow_mut() = Some(e);
                    }
                }
                now() + TimeDelta::milliseconds(10)
            },
        );
        if let Some(e) = failure.into_inner() {
            return Err(e.into());
        }
        assert!(count.get() >= sample, "clock seam was not reached");
        assert!(result.is_err(), "missing root accepted at sample {sample}");
        assert!(!path.exists(), "root was recreated at sample {sample}");
        let state = fx.family.read_normal_chat_session_snapshot_v2()?;
        assert_eq!(state.admission.closed_at.is_some(), sample == 2);
    }
    Ok(())
}
#[test]
fn concurrent_reservation_and_close_cannot_both_commit_against_empty_snapshot() -> TestResult {
    let fx = Fixture::new()?;
    let expected = fx.family.read_normal_chat_session_snapshot_v2()?;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let closed = std::thread::scope(|scope| {
        let next = attempt_request(&fx.control, "intent:raced")?;
        let current = &fx;
        let a = barrier.clone();
        let reserve = scope.spawn(move || -> bool {
            a.wait();
            current
                .family
                .reserve_normal_chat_attempt(&current.authority, &next, now())
                .is_ok()
        });
        let b = barrier.clone();
        let close = scope.spawn(move || -> bool {
            b.wait();
            current
                .store
                .close_normal_chat_session_v2(
                    &current.family,
                    &current.context,
                    &expected,
                    now(),
                    now,
                )
                .is_ok()
        });
        Ok::<_, Box<dyn std::error::Error>>((
            reserve.join().map_err(|_| "reserve panicked")?,
            close.join().map_err(|_| "close panicked")?,
        ))
    })?;
    assert_ne!(closed.0, closed.1);
    let after = fx.family.read_normal_chat_session_snapshot_v2()?;
    assert_eq!(after.reservations.len(), usize::from(closed.0));
    fx.store
        .close_normal_chat_session_v2(&fx.family, &fx.context, &after, now(), now)?;
    Ok(())
}

#[test]
fn cross_root_rejection_does_not_wait_for_a_held_family_lock() -> TestResult {
    use rustix::fs::{flock, FlockOperation};
    let fx = Fixture::new()?;
    let other = Fixture::new()?;
    let expected = fx.family.read_normal_chat_session_snapshot_v2()?;
    let lock = File::open(fx.root.path().join(".family-authority.lock"))?;
    flock(&lock, FlockOperation::LockExclusive)?;
    std::thread::scope(|scope| -> TestResult {
        let (sender, receiver) = std::sync::mpsc::channel();
        let fx = &fx;
        let other = &other;
        let expected = &expected;
        let worker = scope.spawn(move || {
            let result = other.store.close_normal_chat_session_v2(
                &fx.family,
                &fx.context,
                expected,
                now(),
                now,
            );
            let _ = sender.send(result.is_err());
        });
        let received = receiver.recv_timeout(std::time::Duration::from_secs(2));
        flock(&lock, FlockOperation::Unlock)?;
        worker.join().map_err(|_| "close thread panicked")?;
        assert_eq!(
            received,
            Ok(true),
            "cross-root close waited on unrelated authority"
        );
        Ok(())
    })?;
    Ok(())
}
#[test]
fn independent_native_close_handles_have_one_immutable_winner() -> TestResult {
    let fx = Fixture::new()?;
    let expected = fx.family.read_normal_chat_session_snapshot_v2()?;
    let mut pairs = Vec::new();
    for _ in 0..3 {
        pairs.push((
            DurablePermitStore::require_existing_from_run_root_fd(&File::open(fx.root.path())?)?,
            FamilyAuthorityStore::require_existing_from_dir_fd(
                &File::open(fx.root.path())?,
                fx.context.session_family_grant_v2()?,
            )?,
        ));
    }
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let count = std::thread::scope(|scope| -> Result<usize, Box<dyn std::error::Error>> {
        let mut workers = Vec::new();
        for (store, family) in pairs {
            let b = barrier.clone();
            let ctx = &fx.context;
            let expected = &expected;
            workers.push(scope.spawn(move || {
                b.wait();
                store
                    .close_normal_chat_session_v2(&family, ctx, expected, now(), now)
                    .is_ok()
            }));
        }
        let mut count = 0;
        for worker in workers {
            count += usize::from(worker.join().map_err(|_| "close worker panicked")?);
        }
        Ok(count)
    })?;
    assert_eq!(count, 1);
    let current = fx.family.read_normal_chat_session_snapshot_v2()?;
    let before = fx.record()?;
    let again =
        fx.store
            .close_normal_chat_session_v2(&fx.family, &fx.context, &current, now(), || {
                now() - TimeDelta::seconds(1)
            })?;
    assert_eq!(again.root_control, before);
    Ok(())
}
#[test]
fn historical_close_confirmation_still_requires_both_durability_barriers() -> TestResult {
    let fx = Fixture::new()?;
    let expected = fx.family.read_normal_chat_session_snapshot_v2()?;
    let closed =
        fx.store
            .close_normal_chat_session_v2(&fx.family, &fx.context, &expected, now(), now)?;
    let family_bytes = fs::read(fx.root.path().join("family-authority.json"))?;
    let record_bytes = fs::read(record_path(&fx)?)?;
    for stop in [
        Stop::FamilyClose(PermitTransitionStage::DirectoryFsync),
        Stop::RootClose(PermitTransitionStage::DirectoryFsync),
    ] {
        let count = Cell::new(0);
        assert!(fx
            .store
            .close_normal_chat_session_v2_with_interruption(
                &fx.family,
                &fx.context,
                &closed.snapshot,
                now(),
                || {
                    count.set(count.get() + 1);
                    now()
                },
                Some(stop)
            )
            .is_err());
        assert_eq!(count.get(), 0);
        assert_eq!(
            family_bytes,
            fs::read(fx.root.path().join("family-authority.json"))?
        );
        assert_eq!(record_bytes, fs::read(record_path(&fx)?)?);
    }
    assert_eq!(
        fx.store.close_normal_chat_session_v2(
            &fx.family,
            &fx.context,
            &closed.snapshot,
            now(),
            now
        )?,
        closed
    );
    Ok(())
}
#[test]
fn extra_root_record_or_changed_original_fields_reject_without_closing() -> TestResult {
    for extra in [true, false] {
        let fx = Fixture::new()?;
        let expected = fx.family.read_normal_chat_session_snapshot_v2()?;
        let path = record_path(&fx)?;
        if extra {
            fs::copy(&path, fx.root.path().join("permits/permit-extra.json"))?;
        } else {
            let mut record = fx.record()?;
            let id = recursive_agent_contracts::CurrentPermitId::try_new(format!(
                "v1:recursive-agent/permit/v1:det:{}",
                "e".repeat(64)
            ))?;
            record.child_allocations.insert(
                id,
                recursive_agent_policy::PermitBudgetV1 {
                    max_wall_time_ms: 1,
                    max_output_bytes: 1,
                    max_artifact_bytes: 1,
                },
            );
            fs::write(&path, recursive_agent_contracts::jcs_canonical(&record)?)?;
        }
        let family_bytes = fs::read(fx.root.path().join("family-authority.json"))?;
        let record_bytes = fs::read(&path)?;
        assert!(fx
            .store
            .close_normal_chat_session_v2(&fx.family, &fx.context, &expected, now(), now)
            .is_err());
        assert_eq!(
            family_bytes,
            fs::read(fx.root.path().join("family-authority.json"))?
        );
        assert_eq!(record_bytes, fs::read(&path)?);
    }
    Ok(())
}
#[test]
fn native_close_rechecks_lock_and_permit_locators_after_each_clock_sample() -> TestResult {
    for sample in [1, 2] {
        for part in ["permits", "permit-lock", "family-lock"] {
            let fx = Fixture::new()?;
            let expected = fx.family.read_normal_chat_session_snapshot_v2()?;
            let count = Cell::new(0);
            let failure = std::cell::RefCell::new(None);
            let result = fx.store.close_normal_chat_session_v2(
                &fx.family,
                &fx.context,
                &expected,
                now(),
                || {
                    count.set(count.get() + 1);
                    if count.get() == sample {
                        let result = (|| -> std::io::Result<()> {
                            let path = match part {
                                "permits" => fx.root.path().join("permits"),
                                "permit-lock" => fx.root.path().join("permits/.permit.lock"),
                                _ => fx.root.path().join(".family-authority.lock"),
                            };
                            fs::rename(&path, fx.root.path().join(format!("detached-{part}")))?;
                            if part == "permits" {
                                fs::create_dir(&path)?;
                                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                            } else {
                                fs::write(&path, b"")?;
                                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
                            }
                            Ok(())
                        })();
                        if let Err(e) = result {
                            *failure.borrow_mut() = Some(e);
                        }
                    }
                    now() + TimeDelta::milliseconds(10)
                },
            );
            if let Some(e) = failure.into_inner() {
                return Err(e.into());
            }
            assert!(count.get() >= sample);
            assert!(result.is_err(), "{part} swap at sample {sample} accepted");
            let bytes = fs::read(fx.root.path().join("family-authority.json"))?;
            let state: serde_json::Value = serde_json::from_slice(&bytes)?;
            assert_eq!(
                !state["normal_chat_session"]["closed_at"].is_null(),
                sample == 2
            );
        }
    }
    Ok(())
}
