use super::*;
use recursive_agent_ledger::AppendStage;
use recursive_agent_policy::{
    FamilyAuthorityStore, NormalChatFamilyReservationRequestV2, NormalChatGrantContextV2,
    PermitRevocationReasonV1,
};

#[test]
fn every_child_append_boundary_and_orphan_artifact_blocks_retry_without_refund() -> TestResult {
    let mut stops = vec![Stop::AfterRequestArtifact, Stop::AfterLinkArtifact];
    for ordinal in 0..7 {
        for stage in [
            AppendStage::PartialRecord,
            AppendStage::FullReceiptAppend,
            AppendStage::LogFsync,
            AppendStage::MetadataTempWrite,
            AppendStage::MetadataFsync,
            AppendStage::MetadataRename,
            AppendStage::DirectoryFsync,
        ] {
            stops.push(Stop::ChildReceipt { ordinal, stage });
        }
    }
    for stop in stops {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req = request(&fx, &session, "intent:one")?;
        assert!(
            service
                .begin_normal_chat_attempt_with_interruption(&session, &req, Some(stop))
                .is_err(),
            "{stop:?}"
        );
        let family_before = fs::read(session.run_dir().join("family-authority.json"))?;
        for req in [req, request(&fx, &session, "intent:two")?] {
            assert!(
                !matches!(
                    service.begin_normal_chat_attempt(&session, &req),
                    Ok(RuntimeNormalChatBeginV2::Fresh(_))
                ),
                "{stop:?}"
            );
        }
        assert_eq!(
            fs::read(session.run_dir().join("family-authority.json"))?,
            family_before,
            "{stop:?}"
        );
    }
    Ok(())
}

#[test]
fn missing_accounting_or_permit_storage_is_never_recreated_by_begin() -> TestResult {
    for missing in ["family-authority.json", ".family-authority.lock", "permits"] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let target = session.run_dir().join(missing);
        if target.is_dir() {
            fs::rename(&target, session.run_dir().join("detached-permits"))?;
        } else {
            fs::remove_file(&target)?;
        }
        assert!(
            service
                .begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:one")?)
                .is_err(),
            "{missing}"
        );
        assert!(!target.exists(), "{missing} was recreated");
    }
    Ok(())
}

#[test]
fn attenuated_metadata_capacity_retains_consumption_without_child_payload_publication() -> TestResult
{
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:one")?;
    assert!(service
        .begin_normal_chat_attempt_with_interruption(&session, &req, Some(Stop::MetadataCapacity))
        .is_err());
    let status = match service.begin_normal_chat_attempt(&session, &req)? {
        RuntimeNormalChatBeginV2::Existing(status) => status,
        RuntimeNormalChatBeginV2::Fresh(_) => {
            return Err("capacity rejection restored Fresh".into())
        }
    };
    assert_eq!(
        status.child_policy.ok_or("child policy absent")?.state,
        NormalChatAttemptPolicyStateV2::Consumed
    );
    let child_dir = fx
        .root
        .path()
        .join(content_digest(&status.reservation.attempt.run_id()?)?.to_string());
    assert_eq!(fs::read_dir(child_dir.join("artifacts"))?.count(), 0);
    // The ledger owner creates chain.meta for the empty prefix; its log is
    // allowed to remain absent until the first append.
    let meta: serde_json::Value = serde_json::from_slice(&fs::read(child_dir.join("chain.meta"))?)?;
    assert_eq!(meta["length"], json!(0));
    assert!(service
        .begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:two")?)
        .is_err());
    Ok(())
}

#[test]
fn denied_route_leaves_no_preparation_or_unreferenced_request_artifact() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let mut req = request(&fx, &session, "intent:denied")?;
    req.operation.model_ref = "model:not-granted".into();
    let before = fs::read(session.run_dir().join("receipts.ndjson"))?;
    let artifacts = fs::read_dir(session.run_dir().join("artifacts"))?.count();
    assert!(service.begin_normal_chat_attempt(&session, &req).is_err());
    assert_eq!(before, fs::read(session.run_dir().join("receipts.ndjson"))?);
    assert_eq!(
        artifacts,
        fs::read_dir(session.run_dir().join("artifacts"))?.count()
    );
    assert!(matches!(
        service.begin_normal_chat_attempt(&session, &request(&fx, &session, "intent:valid")?)?,
        RuntimeNormalChatBeginV2::Fresh(_)
    ));
    Ok(())
}

#[test]
fn late_revocation_expiry_clock_regression_extra_reservation_and_locator_swaps_never_escape(
) -> TestResult {
    for event in [
        "root",
        "family",
        "closed",
        "local",
        "expired",
        "regressed",
        "extra",
        "child-permits",
        "family-lock",
        "root-permit-lock",
        "session-lock",
        "parent-artifacts",
        "child-artifacts",
    ] {
        let fx = Fixture::new()?;
        let service = fx.service()?;
        let session = service.open_normal_chat_session("conversation:fixture")?;
        let req = request(&fx, &session, "intent:one")?;
        let action = std::cell::RefCell::new(Ok::<(), Box<dyn std::error::Error>>(()));
        let result = service.begin_normal_chat_attempt_with_observer(&session, &req, None, || {
            *action.borrow_mut() = (|| -> TestResult {
                let root = File::open(session.run_dir())?;
                let parent = DurablePermitStore::require_existing_from_run_root_fd(&root)?;
                let record = parent
                    .read_normal_chat_session_control_record()?
                    .ok_or("root control absent")?;
                let context = NormalChatGrantContextV2 {
                    grant: fx.authority.grant().clone(),
                    session: session.session().clone(),
                    root_control: record.permit.clone(),
                };
                let family = FamilyAuthorityStore::require_existing_from_dir_fd(
                    &root,
                    context.session_family_grant_v2()?,
                )?;
                let reservation = family
                    .read_normal_chat_reservation("intent:one")?
                    .ok_or("reservation absent")?;
                let child_dir = fx
                    .root
                    .path()
                    .join(content_digest(&reservation.attempt.run_id()?)?.to_string());
                match event {
                    "root" => {
                        parent.revoke(
                            &record.permit.permit_id,
                            PermitRevocationReasonV1::Operator,
                            start(),
                        )?;
                    }
                    "family" => family.revoke_parent(start())?,
                    "closed" => family.close_normal_chat_session(start())?,
                    "local" => {
                        let child = DurablePermitStore::require_existing_from_run_root_fd(
                            &File::open(&child_dir)?,
                        )?;
                        let view = child.read_normal_chat_attempt_v2(&family, "intent:one")?;
                        child.revoke(
                            &view.local_control.ok_or("local control absent")?.permit_id,
                            PermitRevocationReasonV1::Operator,
                            start(),
                        )?;
                    }
                    "expired" => fx.clock.0.store(2000, Ordering::SeqCst),
                    "regressed" => fx.clock.0.store(-1, Ordering::SeqCst),
                    "extra" => {
                        let sibling = request(&fx, &session, "intent:unlinked")?;
                        family.reserve_normal_chat_attempt(
                            &fx.authority,
                            &NormalChatFamilyReservationRequestV2::from_prepared_call(
                                &sibling,
                                reservation
                                    .child_control
                                    .request
                                    .parent_admission_receipt_id,
                            )?,
                            start(),
                        )?;
                    }
                    "parent-artifacts" | "child-artifacts" => {
                        let base = if event == "parent-artifacts" {
                            session.run_dir()
                        } else {
                            child_dir.as_path()
                        };
                        fs::rename(base.join("artifacts"), base.join("detached-artifacts"))?;
                        fs::create_dir(base.join("artifacts"))?;
                        fs::set_permissions(
                            base.join("artifacts"),
                            fs::Permissions::from_mode(0o700),
                        )?;
                    }
                    "child-permits" => {
                        fs::rename(
                            child_dir.join("permits"),
                            child_dir.join("detached-permits"),
                        )?;
                        fs::create_dir(child_dir.join("permits"))?;
                        fs::set_permissions(
                            child_dir.join("permits"),
                            fs::Permissions::from_mode(0o700),
                        )?;
                    }
                    _ => {
                        let name = match event {
                            "family-lock" => ".family-authority.lock",
                            "root-permit-lock" => "permits/.permit.lock",
                            _ => ".normal-chat-runtime.lock",
                        };
                        let path = session.run_dir().join(name);
                        fs::rename(&path, session.run_dir().join(format!("detached-{event}")))?;
                        fs::write(&path, b"")?;
                        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                    }
                }
                Ok(())
            })();
        });
        action.into_inner()?;
        assert!(result.is_err(), "late {event} escaped release fence");
        let state: serde_json::Value =
            serde_json::from_slice(&fs::read(session.run_dir().join("family-authority.json"))?)?;
        assert!(
            state["normal_chat_session"]["reservations"]
                .get("intent:one")
                .is_some(),
            "{event} refunded charge"
        );
        assert!(
            !matches!(
                service.begin_normal_chat_attempt(&session, &req),
                Ok(RuntimeNormalChatBeginV2::Fresh(_))
            ),
            "{event} retry restored Fresh"
        );
    }
    Ok(())
}

#[test]
fn existing_status_remains_readable_after_expiry_and_root_revocation() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let session = service.open_normal_chat_session("conversation:fixture")?;
    let req = request(&fx, &session, "intent:one")?;
    assert!(matches!(
        service.begin_normal_chat_attempt(&session, &req)?,
        RuntimeNormalChatBeginV2::Fresh(_)
    ));
    let parent =
        DurablePermitStore::require_existing_from_run_root_fd(&File::open(session.run_dir())?)?;
    let record = parent
        .read_normal_chat_session_control_record()?
        .ok_or("root control absent")?;
    parent.revoke(
        &record.permit.permit_id,
        PermitRevocationReasonV1::Operator,
        start(),
    )?;
    fx.clock.0.store(400_000, Ordering::SeqCst);
    assert!(matches!(
        service.begin_normal_chat_attempt(&session, &req)?,
        RuntimeNormalChatBeginV2::Existing(_)
    ));
    Ok(())
}

#[test]
fn independent_runtime_handles_cannot_release_two_fresh_continuations() -> TestResult {
    let fx = Fixture::new()?;
    let session = Arc::new(
        fx.service()?
            .open_normal_chat_session("conversation:fixture")?,
    );
    let barrier = Arc::new(std::sync::Barrier::new(4));
    let mut workers = Vec::new();
    for index in 0..4 {
        let service = fx.service()?;
        let req = request(&fx, &session, &format!("intent:{index}"))?;
        let current = session.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            matches!(
                service.begin_normal_chat_attempt(&current, &req),
                Ok(RuntimeNormalChatBeginV2::Fresh(_))
            )
        }));
    }
    let mut fresh = 0;
    for worker in workers {
        fresh += usize::from(worker.join().map_err(|_| "worker panicked")?);
    }
    assert_eq!(fresh, 1);
    Ok(())
}
