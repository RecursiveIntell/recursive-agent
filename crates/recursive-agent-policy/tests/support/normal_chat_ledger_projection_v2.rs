use super::*;

fn historical(fx: &Fixture) -> Result<FamilyAuthorityStore, Box<dyn std::error::Error>> {
    Ok(FamilyAuthorityStore::from_dir_fd(
        &File::open(fx._parent_root.path())?,
        fx.control.family_grant(),
    )?)
}

#[test]
fn unbegun_and_prepared_records_cannot_fabricate_consumed_ledger_evidence() -> TestResult {
    let fx = Fixture::new()?;
    let family = historical(&fx)?;
    assert!(fx
        .child_store
        .read_normal_chat_ledger_admission_v2(&family, "intent:first")?
        .is_none());
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
    assert_eq!(
        fx.family
            .read_child_policy_v2(&fx.child_store, "intent:first")?
            .state,
        NormalChatAttemptPolicyStateV2::Prepared
    );
    assert!(fx
        .child_store
        .read_normal_chat_ledger_admission_v2(&family, "intent:first")?
        .is_none());
    assert!(matches!(fx.begin()?, NormalChatAttemptBeginV2::Existing(_)));
    Ok(())
}

#[test]
fn missing_required_context_fails_closed_without_reissue_or_tolerant_upgrade() -> TestResult {
    let fx = Fixture::new()?;
    fresh(fx.begin()?)?;
    for path in permit_paths(fx.child_root.path())? {
        let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        if value["normal_chat_attempt_v2"]["role"] == "control" {
            value["normal_chat_attempt_v2"]["admission"]
                .as_object_mut()
                .ok_or("admission absent")?
                .remove("context");
            value["normal_chat_attempt_v2"]["admission"]["session_control_expires_at"] =
                json!(now() + TimeDelta::seconds(300));
            fs::write(path, serde_json::to_vec(&value)?)?;
        }
    }
    let before = permit_paths(fx.child_root.path())?
        .into_iter()
        .map(|path| Ok((path.clone(), fs::read(path)?)))
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    assert!(fx.begin().is_err());
    assert!(fx
        .child_store
        .read_normal_chat_ledger_admission_v2(&historical(&fx)?, "intent:first")
        .is_err());
    assert_eq!(permit_paths(fx.child_root.path())?.len(), before.len());
    for (path, bytes) in before {
        assert_eq!(fs::read(path)?, bytes);
    }
    Ok(())
}

#[test]
fn governed_issued_record_unknown_members_are_not_silently_discarded() -> TestResult {
    for session in [false, true] {
        let fx = Fixture::new()?;
        let cap = fresh(fx.begin()?)?;
        let proof = cap.ledger_evidence()?;
        let root = if session {
            fx._parent_root.path()
        } else {
            fx.child_root.path()
        };
        let target = if session {
            proof.admission.context.root_control.permit_id.clone()
        } else {
            proof.control_evidence()?.permit_id
        };
        for path in permit_paths(root)? {
            let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
            if raw["permit"]["permit_id"] == serde_json::to_value(&target)? {
                raw["state"] = json!({"state":"issued","unexpected":"must-reject"});
                fs::write(path, recursive_agent_contracts::jcs_canonical(&raw)?)?;
            }
        }
        let store = if session {
            &fx.parent_store
        } else {
            &fx.child_store
        };
        assert!(
            store.state(&target).is_err(),
            "record ingress session={session}"
        );
        if session {
            assert!(store.read_normal_chat_session_control_record().is_err());
        } else {
            assert!(store
                .read_normal_chat_ledger_admission_v2(&historical(&fx)?, "intent:first")
                .is_err());
        }
    }
    Ok(())
}

#[test]
fn fresh_native_context_retains_current_uid_and_canonical_original_metadata() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let native = cap.ledger_evidence()?;
    assert_eq!(
        native.admission.context.root_control.binding.actor.as_str(),
        format!("ares:uid:{}", rustix::process::getuid().as_raw())
    );
    assert_eq!(
        fx.child_store
            .read_normal_chat_ledger_admission_v2(&historical(&fx)?, "intent:first")?,
        Some(native)
    );
    Ok(())
}
