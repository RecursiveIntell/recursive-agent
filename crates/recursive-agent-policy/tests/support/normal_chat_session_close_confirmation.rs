use super::*;
use recursive_agent_policy::NormalChatSessionCloseV2;
use std::collections::BTreeMap;
fn bytes(fx: &Fixture) -> Result<BTreeMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
    let mut map = BTreeMap::new();
    map.insert(
        "family".into(),
        fs::read(fx.root.path().join("family-authority.json"))?,
    );
    for e in fs::read_dir(fx.root.path().join("permits"))? {
        let e = e?;
        if e.file_type()?.is_file() {
            map.insert(
                e.file_name().to_string_lossy().into_owned(),
                fs::read(e.path())?,
            );
        }
    }
    Ok(map)
}
fn close(fx: &Fixture) -> Result<NormalChatSessionCloseV2, Box<dyn std::error::Error>> {
    Ok(fx.store.close_normal_chat_session_v2(
        &fx.family,
        &fx.context,
        &fx.family.read_normal_chat_session_snapshot_v2()?,
        now(),
        || now() + TimeDelta::seconds(700),
    )?)
}
fn root_path(fx: &Fixture) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    for e in fs::read_dir(fx.root.path().join("permits"))? {
        let e = e?;
        if e.path().extension().is_some_and(|x| x == "json") {
            return Ok(e.path());
        }
    }
    Err("root record absent".into())
}
#[test]
fn exact_closed_pair_confirmation_is_existing_only_and_preserves_all_prior_reasons() -> TestResult {
    for reason in [
        PermitRevocationReasonV1::Operator,
        PermitRevocationReasonV1::ParentRevoked,
        PermitRevocationReasonV1::PolicySuperseded,
        PermitRevocationReasonV1::OperationCancelled,
    ] {
        let fx = Fixture::new()?;
        fx.store.revoke(
            &fx.context.root_control.permit_id,
            reason,
            now() + TimeDelta::seconds(1),
        )?;
        let expected = close(&fx)?;
        let before = bytes(&fx)?;
        assert_eq!(
            fx.store
                .confirm_closed_normal_chat_session_v2(&fx.family, &fx.context, &expected)?,
            expected
        );
        assert_eq!(bytes(&fx)?, before);
        assert_eq!(
            fx.store
                .confirm_closed_normal_chat_session_v2(&fx.family, &fx.context, &expected)?,
            expected
        );
        assert_eq!(bytes(&fx)?, before);
    }
    Ok(())
}
#[test]
fn exact_but_impossible_native_revocation_time_is_not_confirmed() -> TestResult {
    let fx = Fixture::new()?;
    let mut expected = close(&fx)?;
    let path = root_path(&fx)?;
    let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    raw["state"] = json!({"state":"revoked","revoked_at":now()-TimeDelta::milliseconds(1),"reason":"operator"});
    expected.root_control = serde_json::from_value(raw.clone())?;
    fs::write(&path, recursive_agent_contracts::jcs_canonical(&raw)?)?;
    let before = bytes(&fx)?;
    assert!(fx
        .store
        .confirm_closed_normal_chat_session_v2(&fx.family, &fx.context, &expected)
        .is_err());
    assert_eq!(bytes(&fx)?, before);
    Ok(())
}
#[test]
fn issued_root_is_not_revoked_or_repaired_by_historical_confirmation() -> TestResult {
    let fx = Fixture::new()?;
    let expected = close(&fx)?;
    let p = root_path(&fx)?;
    let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&p)?)?;
    raw["state"] = json!({"state":"issued"});
    fs::write(&p, recursive_agent_contracts::jcs_canonical(&raw)?)?;
    let before = bytes(&fx)?;
    assert!(fx
        .store
        .confirm_closed_normal_chat_session_v2(&fx.family, &fx.context, &expected)
        .is_err());
    assert_eq!(bytes(&fx)?, before);
    assert!(matches!(fx.record()?.state, PermitStateV1::Issued));
    Ok(())
}
#[test]
fn open_family_or_inexact_expected_pair_is_not_repaired() -> TestResult {
    for mode in [
        "open-family",
        "wrong-time",
        "wrong-reason",
        "wrong-snapshot",
        "expected-issued",
    ] {
        let fx = Fixture::new()?;
        let mut expected = close(&fx)?;
        match mode {
            "open-family" => {
                let p = fx.root.path().join("family-authority.json");
                let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&p)?)?;
                raw["normal_chat_session"]["closed_at"] = json!(null);
                fs::write(&p, recursive_agent_contracts::jcs_canonical(&raw)?)?;
            }
            "wrong-time" => {
                expected.root_control.state = PermitStateV1::Revoked {
                    revoked_at: now() + TimeDelta::seconds(701),
                    reason: PermitRevocationReasonV1::Operator,
                }
            }
            "wrong-reason" => {
                expected.root_control.state = PermitStateV1::Revoked {
                    revoked_at: now() + TimeDelta::seconds(700),
                    reason: PermitRevocationReasonV1::PolicySuperseded,
                }
            }
            "wrong-snapshot" => expected.snapshot.admission.closed_at = Some(now()),
            _ => expected.root_control.state = PermitStateV1::Issued,
        }
        let before = bytes(&fx)?;
        assert!(
            fx.store
                .confirm_closed_normal_chat_session_v2(&fx.family, &fx.context, &expected)
                .is_err(),
            "{mode}"
        );
        assert_eq!(bytes(&fx)?, before);
    }
    Ok(())
}
#[test]
fn missing_native_authority_and_cross_root_pairs_cannot_be_recreated_or_confirmed() -> TestResult {
    for mode in ["record", "family", "foreign-root", "permits"] {
        let fx = Fixture::new()?;
        let expected = close(&fx)?;
        let other = Fixture::new()?;
        if mode == "foreign-root" {
            assert!(fx
                .store
                .confirm_closed_normal_chat_session_v2(&other.family, &fx.context, &expected)
                .is_err());
            continue;
        }
        let p = match mode {
            "record" => root_path(&fx)?,
            "family" => fx.root.path().join("family-authority.json"),
            _ => fx.root.path().join("permits"),
        };
        let detached = fx._auth.path().join("detached-native");
        fs::rename(&p, detached)?;
        assert!(fx
            .store
            .confirm_closed_normal_chat_session_v2(&fx.family, &fx.context, &expected)
            .is_err());
        assert!(!p.exists(), "{mode} recreated");
    }
    Ok(())
}
#[test]
fn both_owner_durability_barriers_remain_required_and_invalid_write_faults_reject() -> TestResult {
    for point in [
        Stop::FamilyClose(PermitTransitionStage::DirectoryFsync),
        Stop::RootClose(PermitTransitionStage::DirectoryFsync),
        Stop::RootClose(PermitTransitionStage::TempWrite),
    ] {
        let fx = Fixture::new()?;
        let expected = close(&fx)?;
        let before = bytes(&fx)?;
        assert!(fx
            .store
            .confirm_closed_normal_chat_session_v2_with_interruption(
                &fx.family,
                &fx.context,
                &expected,
                Some(point)
            )
            .is_err());
        assert_eq!(bytes(&fx)?, before);
        assert_eq!(
            fx.store
                .confirm_closed_normal_chat_session_v2(&fx.family, &fx.context, &expected)?,
            expected
        );
    }
    Ok(())
}
