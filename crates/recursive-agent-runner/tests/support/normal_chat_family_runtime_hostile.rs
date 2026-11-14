use super::*;
use recursive_agent_contracts::ReceiptV1;
use recursive_agent_ledger::{chain_digest_from_raw, make_receipt, ArtifactStore, ReceiptDraftV1};
use recursive_agent_policy::NormalChatFamilyReservationRequestV2;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn tree(path: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, Box<dyn std::error::Error>> {
    fn visit(base: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) -> TestResult {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                visit(base, &entry.path(), out)?;
            } else {
                out.insert(
                    entry.path().strip_prefix(base)?.to_path_buf(),
                    fs::read(entry.path())?,
                );
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    visit(path, path, &mut out)?;
    Ok(out)
}
fn child_path(
    fx: &Fixture,
    session: &recursive_agent_runner::RuntimeNormalChatSessionV1,
    intent: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let r = family(fx, session)?
        .read_normal_chat_reservation(intent)?
        .ok_or("reservation absent")?;
    Ok(fx
        .root
        .path()
        .join(content_digest(&r.attempt.run_id()?)?.to_string()))
}
fn first(
    fx: &Fixture,
    service: &RuntimeService,
    session: &recursive_agent_runner::RuntimeNormalChatSessionV1,
) -> Result<(NormalChatCallRequestV2, ContentDigest), Box<dyn std::error::Error>> {
    call(
        fx,
        service,
        session,
        "intent:first",
        "materialization:first",
        NormalChatReportedStateV2::NotSent,
    )
}
fn copy_tree(source: &Path, dest: &Path) -> std::io::Result<()> {
    fs::create_dir(dest)?;
    fs::set_permissions(dest, fs::Permissions::from_mode(0o700))?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &dest.join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dest.join(entry.file_name()))?;
        }
    }
    Ok(())
}
#[test]
fn old_closed_retries_preserve_complete_tree_and_conflict_cannot_touch_newer_history() -> TestResult
{
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (old, digest) = first(&fx, &service, &session)?;
    let next = request(&fx, &session, "intent:second")?;
    let cap = match service.begin_normal_chat_attempt(&session, &next)? {
        RuntimeNormalChatBeginV2::Fresh(value) => value,
        _ => return Err("second not Fresh".into()),
    };
    for close in [false, true] {
        if close {
            service.settle_normal_chat_attempt(
                &session,
                &next,
                cap.preflight_digest(),
                &super::super::terminal::report(NormalChatReportedStateV2::Succeeded)?,
            )?;
        }
        let before = tree(fx.root.path())?;
        assert!(matches!(
            service.begin_normal_chat_attempt(&session, &old)?,
            RuntimeNormalChatBeginV2::Existing(_)
        ));
        service.settle_normal_chat_attempt(
            &session,
            &old,
            &digest,
            &super::super::terminal::report(NormalChatReportedStateV2::NotSent)?,
        )?;
        assert!(service
            .settle_normal_chat_attempt(
                &session,
                &old,
                &digest,
                &super::super::terminal::report(NormalChatReportedStateV2::Failed)?
            )
            .is_err());
        assert_eq!(before, tree(fx.root.path())?);
    }
    Ok(())
}
#[test]
fn prior_sibling_substitution_content_and_extra_inventory_never_release_second_fresh() -> TestResult
{
    for event in [
        "root",
        "permits",
        "permit-lock",
        "artifacts",
        "head",
        "orphan",
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        first(&fx, &service, &session)?;
        let old = child_path(&fx, &session, "intent:first")?;
        let next = request(&fx, &session, "intent:second")?;
        let action = std::cell::RefCell::new(Ok::<(), Box<dyn std::error::Error>>(()));
        let result = service.begin_normal_chat_attempt_with_observer(&session, &next, None, || {
            *action.borrow_mut() = (|| -> TestResult {
                match event {
                    "head" => {
                        let data = fs::read_to_string(old.join("receipts.ndjson"))?;
                        let mut rows: Vec<ReceiptV1> = data
                            .lines()
                            .map(serde_json::from_str)
                            .collect::<Result<_, _>>()?;
                        rows.last_mut().ok_or("terminal absent")?.recorded_time +=
                            TimeDelta::milliseconds(1);
                        let mut changed = Vec::new();
                        for row in rows {
                            changed.extend(row.canonical_bytes()?);
                            changed.push(b'\n');
                        }
                        fs::write(old.join("receipts.ndjson"), changed)?;
                    }
                    "orphan" => {
                        ArtifactStore::from_run_root_fd(&File::open(&old)?, false)?.put(
                            b"unreferenced",
                            "application/json",
                            None,
                        )?;
                    }
                    "permit-lock" => {
                        let path = old.join("permits/.permit.lock");
                        fs::rename(&path, old.join("detached-permit-lock"))?;
                        fs::write(&path, b"")?;
                        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                    }
                    _ => {
                        let path = if event == "root" {
                            old.clone()
                        } else {
                            old.join(event)
                        };
                        let detached = if event == "root" {
                            fx.root.path().join("detached-first")
                        } else {
                            old.join(format!("detached-{event}"))
                        };
                        fs::rename(&path, &detached)?;
                        // Byte-identical replacement still has a different owner locator.
                        copy_tree(&detached, &path)?;
                    }
                }
                Ok(())
            })();
        });
        action.into_inner()?;
        assert!(result.is_err(), "{event} escaped prior-sibling fence");
        assert_eq!(
            family(&fx, &session)?
                .read_normal_chat_session_snapshot_v2()?
                .reservations
                .len(),
            2
        );
        assert!(
            !matches!(
                service.begin_normal_chat_attempt(&session, &next),
                Ok(RuntimeNormalChatBeginV2::Fresh(_))
            ),
            "{event} retry restored Fresh"
        );
    }
    Ok(())
}
#[test]
fn missing_closed_sibling_or_resume_authority_never_recreates_storage() -> TestResult {
    for missing in [
        "root",
        "permits",
        "artifacts",
        "parent-permits",
        "family-authority.json",
        ".family-authority.lock",
        ".normal-chat-runtime.lock",
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        first(&fx, &service, &session)?;
        let child = child_path(&fx, &session, "intent:first")?;
        let path = match missing {
            "root" => child,
            "permits" | "artifacts" => child.join(missing),
            "parent-permits" => session.run_dir().join("permits"),
            _ => session.run_dir().join(missing),
        };
        fs::rename(&path, fx.root.path().join(format!("detached-{missing}")))?;
        assert!(
            fx.service()?
                .resume_normal_chat_session("conversation:fixture")
                .is_err(),
            "{missing}"
        );
        assert!(!path.exists(), "resume recreated {missing}");
    }
    Ok(())
}
#[test]
fn parent_group_corruption_extra_reservation_and_orphan_preparation_block_without_refunds(
) -> TestResult {
    for event in [
        "closure-spec",
        "closure-time",
        "closure-lineage",
        "duplicate",
        "reordered",
        "reserved-only",
        "prepared-only",
        "unknown-artifact",
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        first(&fx, &service, &session)?;
        let state = family(&fx, &session)?;
        let snapshot = appendable_snapshot_expected_run_from_dir_fd(
            &File::open(session.run_dir())?,
            session.run_id(),
        )?;
        let mut rows = snapshot.receipts().to_vec();
        match event {
            "reserved-only" => {
                let req = request(&fx, &session, "intent:unlinked")?;
                state.reserve_normal_chat_attempt(
                    &fx.authority,
                    &NormalChatFamilyReservationRequestV2::from_prepared_call(
                        &req,
                        rows[3].receipt_id.clone(),
                    )?,
                    start(),
                )?;
            }
            "prepared-only" => {
                assert!(service
                    .begin_normal_chat_attempt_with_interruption(
                        &session,
                        &request(&fx, &session, "intent:partial")?,
                        Some(Stop::AfterPreparation)
                    )
                    .is_err());
            }
            "unknown-artifact" => {
                ArtifactStore::from_run_root_fd(&File::open(session.run_dir())?, false)?.put(
                    b"orphan",
                    "application/json",
                    None,
                )?;
            }
            _ => {
                match event {
                    "closure-spec" => rows[5].spec_digest = ContentDigest::compute(b"wrong"),
                    "closure-time" => rows[5].valid_time += TimeDelta::milliseconds(1),
                    "closure-lineage" => rows[5].lineage[0].principal = "altered-principal".into(),
                    "duplicate" => rows.extend_from_within(3..6),
                    _ => rows.swap(3, 4),
                }
                // Rechain exact canonical records: not merely a broken checksum.
                let mut previous = rows[0].prev_chain_digest.clone();
                let mut bytes = Vec::new();
                for old in rows {
                    let mut row = make_receipt(
                        ReceiptDraftV1 {
                            run_id: old.run_id,
                            step_id: old.step_id,
                            kind: old.kind,
                            valid_time: old.valid_time,
                            lineage: old.lineage,
                            spec_digest: old.spec_digest,
                            args_digest: old.args_digest,
                            artifact_refs: old.artifact_refs,
                            outcome: old.outcome,
                        },
                        previous,
                    )?;
                    row.recorded_time = old.recorded_time;
                    previous =
                        chain_digest_from_raw(&row.prev_chain_digest, &row.canonical_bytes()?)?;
                    bytes.extend(row.canonical_bytes()?);
                    bytes.push(b'\n');
                }
                fs::write(session.run_dir().join("receipts.ndjson"), bytes)?;
            }
        }
        let charge = fs::read(session.run_dir().join("family-authority.json"))?;
        assert!(
            service
                .begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:next")?)
                .is_err(),
            "{event}"
        );
        assert!(
            service
                .resume_normal_chat_session("conversation:fixture")
                .is_err(),
            "{event}"
        );
        assert_eq!(
            charge,
            fs::read(session.run_dir().join("family-authority.json"))?,
            "{event} changed charges"
        );
    }
    Ok(())
}

#[test]
fn regressed_missing_terminal_transition_rejects_without_mutation_equal_time_recovers() -> TestResult
{
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:first")?;
    let cap = match service.begin_normal_chat_attempt(&session, &req)? {
        RuntimeNormalChatBeginV2::Fresh(value) => value,
        _ => return Err("first not Fresh".into()),
    };
    let report = super::super::terminal::report(NormalChatReportedStateV2::NotSent)?;
    fx.clock.0.store(200, Ordering::SeqCst);
    assert!(service
        .settle_normal_chat_attempt_with_interruption(
            &session,
            &req,
            cap.preflight_digest(),
            &report,
            Some(recursive_agent_runner::NormalChatTerminalInterruptionV2::AfterPolicy)
        )
        .is_err());
    let before = tree(fx.root.path())?;
    fx.clock.0.store(100, Ordering::SeqCst);
    assert!(
        service
            .settle_normal_chat_attempt(&session, &req, cap.preflight_digest(), &report)
            .is_err(),
        "regressed control closure accepted"
    );
    assert_eq!(before, tree(fx.root.path())?);
    fx.clock.0.store(200, Ordering::SeqCst);
    service.settle_normal_chat_attempt(&session, &req, cap.preflight_digest(), &report)?;
    // Fully closed historical comparison needs no new policy timestamp.
    fx.clock.0.store(0, Ordering::SeqCst);
    let closed = tree(fx.root.path())?;
    service.settle_normal_chat_attempt(&session, &req, cap.preflight_digest(), &report)?;
    assert_eq!(closed, tree(fx.root.path())?);
    Ok(())
}
#[test]
fn latest_exact_orphan_closure_does_not_block_old_retries_or_admit_new_send() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (old, digest) = first(&fx, &service, &session)?;
    let next = request(&fx, &session, "intent:second")?;
    let cap = match service.begin_normal_chat_attempt(&session, &next)? {
        RuntimeNormalChatBeginV2::Fresh(value) => value,
        _ => return Err("second not Fresh".into()),
    };
    let report = super::super::terminal::report(NormalChatReportedStateV2::NotSent)?;
    assert!(service
        .settle_normal_chat_attempt_with_interruption(
            &session,
            &next,
            cap.preflight_digest(),
            &report,
            Some(recursive_agent_runner::NormalChatTerminalInterruptionV2::ParentArtifact)
        )
        .is_err());
    let before = tree(fx.root.path())?;
    assert!(matches!(
        service.begin_normal_chat_attempt(&session, &old)?,
        RuntimeNormalChatBeginV2::Existing(_)
    ));
    service.settle_normal_chat_attempt(&session, &old, &digest, &report)?;
    assert!(service
        .begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:third")?)
        .is_err());
    assert!(service
        .resume_normal_chat_session("conversation:fixture")
        .is_err());
    assert_eq!(before, tree(fx.root.path())?);
    service.settle_normal_chat_attempt(&session, &next, cap.preflight_digest(), &report)?;
    assert!(matches!(
        service.begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:third")?)?,
        RuntimeNormalChatBeginV2::Fresh(_)
    ));
    Ok(())
}

// Clock callback after the observer's first post-history sample reaches the
// native release fence. The mutation is test-only; it cannot issue authority.
struct SwapClock {
    base: Arc<TestClock>,
    remaining: std::sync::atomic::AtomicUsize,
    path: PathBuf,
    failed: std::sync::atomic::AtomicBool,
}
impl Clock for SwapClock {
    fn now(&self) -> DateTime<Utc> {
        if self
            .remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
            .ok()
            == Some(1)
        {
            let detached = self.path.with_extension("detached");
            let result =
                fs::rename(&self.path, &detached).and_then(|()| copy_tree(&detached, &self.path));
            self.failed.store(result.is_err(), Ordering::SeqCst);
        }
        self.base.now()
    }
}
#[test]
fn prior_sibling_locator_replacement_during_native_clock_fence_never_escapes() -> TestResult {
    for part in ["artifacts", "permits"] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        first(&fx, &service, &session)?;
        let clock = Arc::new(SwapClock {
            base: fx.clock.clone(),
            remaining: std::sync::atomic::AtomicUsize::new(0),
            path: child_path(&fx, &session, "intent:first")?.join(part),
            failed: std::sync::atomic::AtomicBool::new(false),
        });
        let service = runtime(fx.root.path(), clock.clone())?
            .with_normal_chat_egress_grant(fx.authority.clone());
        let req = request(&fx, &session, "intent:second")?;
        let result = service.begin_normal_chat_attempt_with_observer(&session, &req, None, || {
            clock.remaining.store(2, Ordering::SeqCst);
        });
        assert_eq!(clock.remaining.load(Ordering::SeqCst), 0);
        assert!(!clock.failed.load(Ordering::SeqCst));
        assert!(result.is_err(), "native fence missed sibling {part}");
        assert_eq!(
            family(&fx, &session)?
                .read_normal_chat_session_snapshot_v2()?
                .reservations
                .len(),
            2
        );
    }
    Ok(())
}
#[test]
fn second_call_interruption_retains_both_charges_and_cannot_be_retried_as_fresh() -> TestResult {
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
        first(&fx, &service, &session)?;
        let req = request(&fx, &session, "intent:second")?;
        assert!(service
            .begin_normal_chat_attempt_with_interruption(&session, &req, Some(stop))
            .is_err());
        let charge = fs::read(session.run_dir().join("family-authority.json"))?;
        assert!(!matches!(
            service.begin_normal_chat_attempt(&session, &req),
            Ok(RuntimeNormalChatBeginV2::Fresh(_))
        ));
        assert!(service
            .begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:third")?)
            .is_err());
        assert!(service
            .resume_normal_chat_session("conversation:fixture")
            .is_err());
        assert_eq!(
            charge,
            fs::read(session.run_dir().join("family-authority.json"))?
        );
    }
    Ok(())
}
#[test]
fn concurrent_successors_after_closed_history_have_one_fresh_winner() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = Arc::new(service.open_normal_chat_session("conversation:fixture")?);
    first(&fx, &service, &session)?;
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for i in 0..3 {
        let service = fx.service()?;
        let req = request(&fx, &session, &format!("intent:next-{i}"))?;
        let session = session.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            matches!(
                service.begin_normal_chat_attempt(&session, &req),
                Ok(RuntimeNormalChatBeginV2::Fresh(_))
            )
        }));
    }
    let mut fresh = 0;
    for worker in workers {
        fresh += usize::from(worker.join().map_err(|_| "worker panicked")?);
    }
    assert_eq!(fresh, 1);
    assert_eq!(
        family(&fx, &session)?
            .read_normal_chat_session_snapshot_v2()?
            .reservations
            .len(),
        2
    );
    Ok(())
}

#[test]
fn resume_requires_current_authority_and_native_settlement_alone_never_closes_history() -> TestResult
{
    for event in ["expired", "closed", "revoked", "native-settled"] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        first(&fx, &service, &session)?;
        let native = family(&fx, &session)?;
        match event {
            "expired" => fx.clock.0.store(300_000, Ordering::SeqCst),
            "closed" => native.close_normal_chat_session(start())?,
            "revoked" => native.revoke_parent(start())?,
            _ => {
                let req = request(&fx, &session, "intent:second")?;
                let cap = match service.begin_normal_chat_attempt(&session, &req)? {
                    RuntimeNormalChatBeginV2::Fresh(value) => value,
                    _ => return Err("second not Fresh".into()),
                };
                let path = child_path(&fx, &session, "intent:second")?;
                let policy =
                    DurablePermitStore::require_existing_from_run_root_fd(&File::open(&path)?)?;
                policy.settle_normal_chat_attempt_v2(
                    &native,
                    "intent:second",
                    cap.preflight_digest(),
                    &super::super::terminal::report(NormalChatReportedStateV2::Succeeded)?,
                    || fx.clock.now(),
                )?;
            }
        }
        let before = tree(fx.root.path())?;
        assert!(
            fx.service()?
                .resume_normal_chat_session("conversation:fixture")
                .is_err(),
            "{event}"
        );
        assert!(
            service
                .begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:next")?)
                .is_err(),
            "{event}"
        );
        assert_eq!(
            before,
            tree(fx.root.path())?,
            "{event} recreated/renewed state"
        );
    }
    Ok(())
}
#[test]
fn latest_orphan_allowance_does_not_accept_unrelated_artifacts() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let (old, digest) = first(&fx, &service, &session)?;
    let next = request(&fx, &session, "intent:second")?;
    let cap = match service.begin_normal_chat_attempt(&session, &next)? {
        RuntimeNormalChatBeginV2::Fresh(value) => value,
        _ => return Err("second not Fresh".into()),
    };
    let report = super::super::terminal::report(NormalChatReportedStateV2::NotSent)?;
    assert!(service
        .settle_normal_chat_attempt_with_interruption(
            &session,
            &next,
            cap.preflight_digest(),
            &report,
            Some(recursive_agent_runner::NormalChatTerminalInterruptionV2::ParentArtifact)
        )
        .is_err());
    ArtifactStore::from_run_root_fd(&File::open(session.run_dir())?, false)?.put(
        b"unrelated",
        "application/json",
        None,
    )?;
    let before = tree(fx.root.path())?;
    assert!(service.begin_normal_chat_attempt(&session, &old).is_err());
    assert!(service
        .settle_normal_chat_attempt(&session, &old, &digest, &report)
        .is_err());
    assert!(service
        .settle_normal_chat_attempt(&session, &next, cap.preflight_digest(), &report)
        .is_err());
    assert_eq!(before, tree(fx.root.path())?);
    Ok(())
}

#[test]
fn fully_closed_overrun_retry_is_historical_at_regressed_clock() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:overrun")?;
    let cap = match service.begin_normal_chat_attempt(&session, &req)? {
        RuntimeNormalChatBeginV2::Fresh(value) => value,
        _ => return Err("not Fresh".into()),
    };
    let mut report = super::super::terminal::report(NormalChatReportedStateV2::Failed)?;
    report.duration_ms = 2000;
    fx.clock.0.store(200, Ordering::SeqCst);
    service.settle_normal_chat_attempt(&session, &req, cap.preflight_digest(), &report)?;
    let before = tree(fx.root.path())?;
    fx.clock.0.store(0, Ordering::SeqCst);
    service.settle_normal_chat_attempt(&session, &req, cap.preflight_digest(), &report)?;
    assert!(service
        .resume_normal_chat_session("conversation:fixture")
        .is_err());
    assert!(service
        .begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:next")?)
        .is_err());
    assert_eq!(before, tree(fx.root.path())?);
    // Corrupt only the required durable family fence. Historical confirmation
    // must reject rather than repair it by invoking a fresh close transition.
    let path = session.run_dir().join("family-authority.json");
    let mut state: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    state["normal_chat_session"]["closed_at"] = serde_json::Value::Null;
    fs::write(&path, serde_json::to_vec(&state)?)?;
    fx.clock.0.store(300, Ordering::SeqCst);
    let broken = tree(fx.root.path())?;
    assert!(service
        .settle_normal_chat_attempt(&session, &req, cap.preflight_digest(), &report)
        .is_err());
    assert_eq!(broken, tree(fx.root.path())?);
    Ok(())
}
