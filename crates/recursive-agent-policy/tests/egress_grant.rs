use chrono::{TimeZone, Utc};
use recursive_agent_contracts::{
    jcs_canonical, parse_normal_chat_operation_v2_bytes, ContentDigest, NormalChatAttemptV2,
};
use recursive_agent_policy::{NormalChatEgressGrantStore, NormalChatGrantAuthorityV1};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ARES_HOME_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn now() -> Result<chrono::DateTime<Utc>, Box<dyn std::error::Error>> {
    Utc.with_ymd_and_hms(2026, 10, 14, 12, 0, 0)
        .single()
        .ok_or_else(|| "fixture time is invalid".into())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn grant_fixture(revision: u64) -> Result<Value, Box<dyn std::error::Error>> {
    let mut grant = json!({
        "schema": "recursive-agent.normal-chat-egress-grant/v1",
        "revision": revision,
        "ares_home_digest": ARES_HOME_DIGEST,
        "mode": "observe",
        "any_route": true,
        "routes": [],
        "caps": {
            "max_attempts": 20,
            "max_output_tokens": 8192,
            "max_wall_time_ms": 120000,
            "max_request_bytes": 1048576
        },
        "expires_at": "2027-01-01T00:00:00Z",
        "content_retention": "digest_only",
        "policy_digest": "sha256:pending"
    });
    let mut material = grant.clone();
    material
        .as_object_mut()
        .ok_or("grant fixture is not an object")?
        .remove("policy_digest");
    let canonical = jcs_canonical(&material)?;
    grant["policy_digest"] = json!(format!("sha256:{}", sha256_hex(&canonical)));
    Ok(grant)
}

fn write_grant(path: &Path, grant: &Value, mode: u32) -> TestResult {
    fs::write(path, serde_json::to_vec(grant)?)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn grant_store(root: &Path) -> Result<NormalChatEgressGrantStore, Box<dyn std::error::Error>> {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    Ok(NormalChatEgressGrantStore::from_dir_fd(&File::open(root)?)?)
}

fn fixture_paths() -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let grant_path = root.path().join("egress-grant.json");
    Ok((root, grant_path))
}

#[test]
fn egress_grant_requires_owned_mode_0600_file() -> TestResult {
    let (root, path) = fixture_paths()?;
    write_grant(&path, &grant_fixture(1)?, 0o644)?;
    assert!(grant_store(root.path())?
        .load_from_path(&path, ARES_HOME_DIGEST, now()?)
        .is_err());

    write_grant(&path, &grant_fixture(1)?, 0o600)?;
    assert!(grant_store(root.path())?
        .load_from_path(&path, ARES_HOME_DIGEST, now()?)
        .is_ok());
    Ok(())
}

#[test]
fn egress_grant_rejects_expiry_wrong_home_and_open_route_in_enforce() -> TestResult {
    let (root, path) = fixture_paths()?;
    let mut expired = grant_fixture(1)?;
    expired["expires_at"] = json!("2026-10-14T11:59:59Z");
    write_grant(&path, &grant_fixture(1)?, 0o600)?;
    let mut expired_material = expired.clone();
    expired_material
        .as_object_mut()
        .ok_or("expired fixture is not an object")?
        .remove("policy_digest");
    expired["policy_digest"] = json!(format!(
        "sha256:{}",
        sha256_hex(&jcs_canonical(&expired_material)?)
    ));
    write_grant(&path, &expired, 0o600)?;
    assert!(grant_store(root.path())?
        .load_from_path(&path, ARES_HOME_DIGEST, now()?)
        .is_err());

    write_grant(&path, &grant_fixture(2)?, 0o600)?;
    assert!(grant_store(root.path())?
        .load_from_path(
            &path,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            now()?
        )
        .is_err());

    let mut open_enforce = grant_fixture(2)?;
    open_enforce["mode"] = json!("enforce");
    let mut material = open_enforce.clone();
    material
        .as_object_mut()
        .ok_or("enforce fixture is not an object")?
        .remove("policy_digest");
    open_enforce["policy_digest"] =
        json!(format!("sha256:{}", sha256_hex(&jcs_canonical(&material)?)));
    write_grant(&path, &open_enforce, 0o600)?;
    assert!(grant_store(root.path())?
        .load_from_path(&path, ARES_HOME_DIGEST, now()?)
        .is_err());
    Ok(())
}

#[test]
fn egress_grant_revision_head_survives_reopen_and_rejects_rollback() -> TestResult {
    let (root, path) = fixture_paths()?;
    write_grant(&path, &grant_fixture(2)?, 0o600)?;
    grant_store(root.path())?.load_from_path(&path, ARES_HOME_DIGEST, now()?)?;

    write_grant(&path, &grant_fixture(1)?, 0o600)?;
    let reopened = grant_store(root.path())?;
    assert!(reopened
        .load_from_path(&path, ARES_HOME_DIGEST, now()?)
        .is_err());
    Ok(())
}

#[test]
fn egress_grant_rejects_unbounded_caps_and_symlink_inputs() -> TestResult {
    let (root, path) = fixture_paths()?;
    let mut excessive_caps = grant_fixture(1)?;
    excessive_caps["caps"]["max_request_bytes"] = json!(u64::MAX);
    let mut material = excessive_caps.clone();
    material
        .as_object_mut()
        .ok_or("caps fixture is not an object")?
        .remove("policy_digest");
    excessive_caps["policy_digest"] =
        json!(format!("sha256:{}", sha256_hex(&jcs_canonical(&material)?)));
    write_grant(&path, &excessive_caps, 0o600)?;
    assert!(grant_store(root.path())?
        .load_from_path(&path, ARES_HOME_DIGEST, now()?)
        .is_err());

    let valid_path = root.path().join("valid-grant.json");
    write_grant(&valid_path, &grant_fixture(1)?, 0o600)?;
    let symlink_path = root.path().join("grant-link.json");
    std::os::unix::fs::symlink(&valid_path, &symlink_path)?;
    assert!(grant_store(root.path())?
        .load_from_path(&symlink_path, ARES_HOME_DIGEST, now()?)
        .is_err());
    Ok(())
}

fn enforce_grant_fixture(revision: u64) -> Result<Value, Box<dyn std::error::Error>> {
    let mut grant = grant_fixture(revision)?;
    grant["mode"] = json!("enforce");
    grant["any_route"] = json!(false);
    grant["routes"] = json!([{
        "provider_identity": "openai_compatible:https://provider.test/v1",
        "model_ref": "model:fixture",
        "api_mode": "chat_completions"
    }]);
    grant["caps"]["max_request_bytes"] = json!(65536);
    let mut material = grant.clone();
    material
        .as_object_mut()
        .ok_or("enforce grant is not an object")?
        .remove("policy_digest");
    grant["policy_digest"] = json!(format!("sha256:{}", sha256_hex(&jcs_canonical(&material)?)));
    Ok(grant)
}

fn attempt_for_grant(
    grant: &NormalChatGrantAuthorityV1,
    attempt_number: u32,
    route: (&str, &str, &str),
    budget: (u32, u64, u64),
) -> Result<NormalChatAttemptV2, Box<dyn std::error::Error>> {
    let (provider_identity, model_ref, api_mode) = route;
    let (output_reserve, max_wall_time_ms, max_request_bytes) = budget;
    let grant = grant.grant();
    let operation = json!({
        "schema": "recursive-agent.normal-chat/v2",
        "conversation_ref": "conversation:fixture-1",
        "parent_run_id": format!("v1:recursive-agent/run/v1:det:{}", "a".repeat(64)),
        "materialization_ref": "materialization:fixture-1",
        "materialization_digest": format!("sha256:{}", "b".repeat(64)),
        "policy_basis_ref": format!("normal-chat-grant:revision-{}", grant.revision),
        "policy_basis_digest": grant.policy_digest,
        "source_revision": "source:fixture-1",
        "route_class": "conversation",
        "provider_identity": provider_identity,
        "model_ref": model_ref,
        "api_mode": api_mode,
        "request_digest": format!("sha256:{}", "d".repeat(64)),
        "request_projection_schema": "ares-json-sorted-v1",
        "budget": {
            "output_reserve": output_reserve,
            "max_wall_time_ms": max_wall_time_ms,
            "max_request_bytes": max_request_bytes
        },
        "replay": "unavailable",
        "provenance": [{
            "source": "urn:test:normal-chat",
            "digest": ContentDigest::compute(b"normal-chat-provenance")
        }]
    });
    let operation = parse_normal_chat_operation_v2_bytes(&serde_json::to_vec(&operation)?)?;
    let session_run_id = operation.parent_run_id.clone();
    Ok(NormalChatAttemptV2::new(
        operation,
        attempt_number,
        ContentDigest::compute(b"provider-body"),
        b"provider-body".len() as u64,
        format!("ares-dispatch-intent:{attempt_number}"),
        session_run_id,
    )?)
}

#[test]
fn normal_chat_grant_check_binds_route_and_caps_before_permit() -> TestResult {
    let (root, path) = fixture_paths()?;
    let grant_json = enforce_grant_fixture(1)?;
    write_grant(&path, &grant_json, 0o600)?;
    let grant = grant_store(root.path())?.load_from_path(&path, ARES_HOME_DIGEST, now()?)?;

    let allowed = attempt_for_grant(
        &grant,
        1,
        (
            "openai_compatible:https://provider.test/v1",
            "model:fixture",
            "chat_completions",
        ),
        (1024, 60_000, 16_384),
    )?;
    assert!(grant.check_attempt(&allowed, now()?).is_ok());

    let wrong_api_mode = attempt_for_grant(
        &grant,
        1,
        (
            "openai_compatible:https://provider.test/v1",
            "model:fixture",
            "responses",
        ),
        (1024, 60_000, 16_384),
    )?;
    assert!(grant.check_attempt(&wrong_api_mode, now()?).is_err());

    let excessive_output = attempt_for_grant(
        &grant,
        1,
        (
            "openai_compatible:https://provider.test/v1",
            "model:fixture",
            "chat_completions",
        ),
        (8193, 60_000, 16_384),
    )?;
    assert!(grant.check_attempt(&excessive_output, now()?).is_err());

    let excessive_request = attempt_for_grant(
        &grant,
        1,
        (
            "openai_compatible:https://provider.test/v1",
            "model:fixture",
            "chat_completions",
        ),
        (1024, 60_000, 65_537),
    )?;
    assert!(grant.check_attempt(&excessive_request, now()?).is_err());

    let excessive_attempt = attempt_for_grant(
        &grant,
        21,
        (
            "openai_compatible:https://provider.test/v1",
            "model:fixture",
            "chat_completions",
        ),
        (1024, 60_000, 16_384),
    )?;
    assert!(grant.check_attempt(&excessive_attempt, now()?).is_err());
    Ok(())
}

fn allowed_attempt(
    grant: &NormalChatGrantAuthorityV1,
) -> Result<NormalChatAttemptV2, Box<dyn std::error::Error>> {
    attempt_for_grant(
        grant,
        1,
        (
            "openai_compatible:https://provider.test/v1",
            "model:fixture",
            "chat_completions",
        ),
        (1024, 60_000, 16_384),
    )
}

fn rederive(
    attempt: NormalChatAttemptV2,
) -> Result<NormalChatAttemptV2, Box<dyn std::error::Error>> {
    Ok(NormalChatAttemptV2::new(
        attempt.operation,
        attempt.attempt_number,
        attempt.provider_request_digest,
        attempt.provider_request_bytes,
        attempt.dispatch_intent_ref,
        attempt.session_run_id,
    )?)
}

#[test]
fn grant_attempt_check_reports_typed_denials_and_exact_boundaries() -> TestResult {
    use recursive_agent_policy::NormalChatEgressDenialV1 as Denial;
    let (root, path) = fixture_paths()?;
    write_grant(&path, &enforce_grant_fixture(1)?, 0o600)?;
    let grant = grant_store(root.path())?.load_from_path(&path, ARES_HOME_DIGEST, now()?)?;
    let base = allowed_attempt(&grant)?;
    for (field, value, expected) in [
        (
            "provider_identity",
            json!("openai_compatible:https://other.test/v1"),
            Denial::RouteNotAllowed,
        ),
        ("model_ref", json!("model:other"), Denial::RouteNotAllowed),
        ("api_mode", json!("responses"), Denial::RouteNotAllowed),
        (
            "policy_basis_ref",
            json!("normal-chat-grant:revision-2"),
            Denial::Malformed,
        ),
        (
            "policy_basis_digest",
            json!(format!("sha256:{}", "c".repeat(64))),
            Denial::Malformed,
        ),
    ] {
        let mut operation = serde_json::to_value(&base.operation)?;
        operation[field] = value;
        let mut changed = base.clone();
        changed.operation = parse_normal_chat_operation_v2_bytes(&serde_json::to_vec(&operation)?)?;
        assert_eq!(
            grant.check_attempt(&rederive(changed)?, now()?),
            Err(expected)
        );
    }
    for (budget, expected) in [
        ((8193, 120_000, 65_536), Denial::CapExhaustedOutputTokens),
        ((8192, 120_001, 65_536), Denial::CapExhaustedWallTimeMs),
        ((8192, 120_000, 65_537), Denial::CapExhaustedRequestBytes),
    ] {
        let mut changed = base.clone();
        changed.operation.budget.output_reserve = budget.0;
        changed.operation.budget.max_wall_time_ms = budget.1;
        changed.operation.budget.max_request_bytes = budget.2;
        assert_eq!(
            grant.check_attempt(&rederive(changed)?, now()?),
            Err(expected)
        );
    }
    let mut edge = base.clone();
    edge.operation.budget.output_reserve = 8192;
    edge.operation.budget.max_wall_time_ms = 120_000;
    edge.operation.budget.max_request_bytes = 65_536;
    edge.attempt_number = 20;
    assert_eq!(grant.check_attempt(&rederive(edge)?, now()?), Ok(()));
    assert_eq!(
        grant.check_attempt(&base, grant.grant().expires_at),
        Err(Denial::GrantExpired)
    );
    assert_eq!(
        grant.check_attempt(&base, now()? - chrono::TimeDelta::milliseconds(1)),
        Err(Denial::Malformed)
    );
    let mut forged = base;
    forged.attempt_number = 2;
    assert_eq!(grant.check_attempt(&forged, now()?), Err(Denial::Malformed));
    Ok(())
}

#[test]
fn normal_chat_denial_wire_codes_are_closed() -> TestResult {
    use recursive_agent_policy::NormalChatEgressDenialV1 as Denial;
    let cases = [
        Denial::GrantMissing,
        Denial::GrantExpired,
        Denial::RouteNotAllowed,
        Denial::CapExhaustedAttempts,
        Denial::CapExhaustedOutputTokens,
        Denial::CapExhaustedWallTimeMs,
        Denial::CapExhaustedRequestBytes,
        Denial::RunClosed,
        Denial::IntentConflict,
        Denial::MaterializationUnavailable,
        Denial::SourceRevisionUnavailable,
        Denial::Malformed,
        Denial::DaemonOverloaded,
    ];
    for code in cases {
        assert_eq!(serde_json::to_value(code)?, json!(code.to_string()));
        assert_eq!(
            serde_json::from_value::<Denial>(json!(code.to_string()))?,
            code
        );
    }
    assert!(serde_json::from_value::<Denial>(json!("ALLOW_ANYWAY")).is_err());
    Ok(())
}
