use super::*;
type NativeBytes = (Vec<u8>, Vec<(String, Vec<u8>)>);
fn bytes(fx: &Fixture) -> Result<NativeBytes, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(fx.child_root.path().join("permits"))? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            files.push((
                entry.file_name().to_string_lossy().into_owned(),
                fs::read(entry.path())?,
            ));
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok((
        fs::read(fx._parent_root.path().join("family-authority.json"))?,
        files,
    ))
}
#[test]
fn confirm_recovery_is_existing_only_and_preserves_original_record_and_bytes() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    let record = fx.child_store.recover_expired_normal_chat_attempt_v1(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        || cap.effect_permit().binding.expires_at,
    )?;
    let before = bytes(&fx)?;
    assert_eq!(
        fx.child_store.confirm_normal_chat_recovery_v1(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest
        )?,
        record
    );
    assert_eq!(bytes(&fx)?, before);
    Ok(())
}
#[test]
fn missing_or_sdk_reported_recovery_is_not_created_by_confirmation() -> TestResult {
    for sdk in [false, true] {
        let fx = Fixture::new()?;
        let cap = fresh(fx.begin()?)?;
        let family = historical(&fx)?;
        if sdk {
            fx.child_store.settle_normal_chat_attempt_v2(
                &family,
                "intent:first",
                &cap.preflight().receipt_digest,
                &report()?,
                || cap.effect_permit().binding.expires_at,
            )?;
        }
        let before = bytes(&fx)?;
        assert!(fx
            .child_store
            .confirm_normal_chat_recovery_v1(
                &family,
                "intent:first",
                &cap.preflight().receipt_digest
            )
            .is_err());
        assert_eq!(bytes(&fx)?, before);
        assert!(fx
            .child_store
            .read_normal_chat_recovery_v1(&family, "intent:first")?
            .is_none());
    }
    Ok(())
}
#[test]
fn downgraded_recovered_role_is_rejected_not_reobserved_or_republished() -> TestResult {
    let fx = Fixture::new()?;
    let cap = fresh(fx.begin()?)?;
    let family = historical(&fx)?;
    fx.child_store.recover_expired_normal_chat_attempt_v1(
        &family,
        "intent:first",
        &cap.preflight().receipt_digest,
        || cap.effect_permit().binding.expires_at,
    )?;
    for entry in fs::read_dir(fx.child_root.path().join("permits"))? {
        let entry = entry?;
        if entry.path().extension().is_some_and(|e| e == "json") {
            let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(entry.path())?)?;
            if raw["permit"]["permit_id"] == serde_json::to_value(&cap.effect_permit().permit_id)? {
                raw["normal_chat_attempt_v2"] = json!({"role":"effect"});
                fs::write(
                    entry.path(),
                    recursive_agent_contracts::jcs_canonical(&raw)?,
                )?;
            }
        }
    }
    let before = bytes(&fx)?;
    assert!(fx
        .child_store
        .confirm_normal_chat_recovery_v1(&family, "intent:first", &cap.preflight().receipt_digest)
        .is_err());
    assert_eq!(bytes(&fx)?, before);
    assert!(fx
        .child_store
        .read_normal_chat_recovery_v1(&family, "intent:first")?
        .is_none());
    Ok(())
}
#[test]
fn missing_historical_fence_or_wrong_preflight_reject_without_repair() -> TestResult {
    for missing in [false, true] {
        let fx = Fixture::new()?;
        let cap = fresh(fx.begin()?)?;
        let family = historical(&fx)?;
        fx.child_store.recover_expired_normal_chat_attempt_v1(
            &family,
            "intent:first",
            &cap.preflight().receipt_digest,
            || cap.effect_permit().binding.expires_at,
        )?;
        let preflight = if missing {
            let p = fx._parent_root.path().join("family-authority.json");
            let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&p)?)?;
            raw["normal_chat_session"]["closed_at"] = json!(null);
            fs::write(p, recursive_agent_contracts::jcs_canonical(&raw)?)?;
            cap.preflight().receipt_digest.clone()
        } else {
            ContentDigest::compute(b"wrong-preflight")
        };
        let before = bytes(&fx)?;
        assert!(fx
            .child_store
            .confirm_normal_chat_recovery_v1(&family, "intent:first", &preflight)
            .is_err());
        assert_eq!(bytes(&fx)?, before);
    }
    Ok(())
}
