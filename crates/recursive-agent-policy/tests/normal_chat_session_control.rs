#[path = "support/normal_chat_session_close.rs"]
mod close;
use chrono::{DateTime, TimeDelta, Utc};
use recursive_agent_contracts::{content_digest, NormalChatSessionV1};
use recursive_agent_policy::{
    DurablePermitStore, FamilyAuthorityStore, NormalChatEgressDenialV1, NormalChatEgressGrantStore,
    NormalChatEgressGrantV1, NormalChatGrantAuthorityV1, PermitPurposeV1, PermitRevocationReasonV1,
    PermitStateV1, PolicyError,
};
use serde_json::json;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const HOME: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn now() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_792_008_000)
}
fn authority(
    root: &Path,
    revision: u64,
) -> Result<NormalChatGrantAuthorityV1, Box<dyn std::error::Error>> {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let mut grant: NormalChatEgressGrantV1 = serde_json::from_value(json!({
        "schema": "recursive-agent.normal-chat-egress-grant/v1", "revision": revision,
        "ares_home_digest": HOME, "mode": "enforce", "any_route": false,
        "routes": [{"provider_identity": "openai_compatible:https://provider.test/v1", "model_ref": "model:fixture", "api_mode": "chat_completions"}],
        "caps": {"max_attempts": 3, "max_output_tokens": 100, "max_wall_time_ms": 1000, "max_request_bytes": 4096},
        "expires_at": now() + TimeDelta::seconds(600), "content_retention": "digest_only", "policy_digest": HOME,
    }))?;
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
fn store(root: &Path) -> Result<DurablePermitStore, Box<dyn std::error::Error>> {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    Ok(DurablePermitStore::from_run_root_fd(&File::open(root)?)?)
}
fn session(
    authority: &NormalChatGrantAuthorityV1,
) -> Result<NormalChatSessionV1, Box<dyn std::error::Error>> {
    Ok(authority.normal_chat_session("conversation:fixture", None)?)
}
fn attempt_request(
    control: &recursive_agent_policy::ValidatedNormalChatSessionControlV1,
    intent: &str,
) -> Result<recursive_agent_policy::NormalChatFamilyReservationRequestV2, Box<dyn std::error::Error>>
{
    let session = control.session();
    let operation = recursive_agent_contracts::parse_normal_chat_operation_v2_bytes(
        &serde_json::to_vec(&json!({
            "schema": "recursive-agent.normal-chat/v2", "conversation_ref": session.conversation_ref,
            "parent_run_id": session.run_id()?, "materialization_ref": "materialization:fixture", "materialization_digest": HOME,
            "policy_basis_ref": format!("normal-chat-grant:revision-{}", session.grant_revision), "policy_basis_digest": session.policy_basis_digest,
            "source_revision": "source:fixture", "route_class": "conversation", "provider_identity": "openai_compatible:https://provider.test/v1", "model_ref": "model:fixture", "api_mode": "chat_completions",
            "request_digest": HOME, "request_projection_schema": "ares-json-sorted-v1", "budget": {"output_reserve": 10, "max_wall_time_ms": 1000, "max_request_bytes": 4096},
            "replay": "unavailable", "provenance": [{"source": "urn:test:fixture", "digest": content_digest(&"fixture")?}],
        }))?,
    )?;
    Ok(
        recursive_agent_policy::NormalChatFamilyReservationRequestV2 {
            operation,
            provider_request_digest: recursive_agent_contracts::ContentDigest::compute(b"body"),
            provider_request_bytes: b"body".len() as u64,
            dispatch_intent_ref: intent.into(),
            parent_admission_receipt_id: recursive_agent_contracts::CurrentReceiptId::try_new(
                format!("v1:recursive-agent/receipt/v1:det:{}", "c".repeat(64)),
            )?,
            requested_budget: recursive_agent_policy::PermitBudgetV1 {
                max_wall_time_ms: 1000,
                max_output_bytes: 1024 * 1024,
                max_artifact_bytes: 1024 * 1024,
            },
        },
    )
}

#[test]
fn require_existing_family_never_recreates_missing_or_unbound_accounting() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path(), 1)?;
    let root = tempfile::tempdir()?;
    let store = store(root.path())?;
    let control =
        store.open_normal_chat_session_control(&authority, "conversation:fixture", None, now)?;
    assert!(
        FamilyAuthorityStore::require_existing_normal_chat_session_family(
            &File::open(root.path())?,
            &authority,
            &control,
            now
        )
        .is_err()
    );
    assert!(!root.path().join("family-authority.json").exists());
    let family = FamilyAuthorityStore::from_normal_chat_session_control(
        &File::open(root.path())?,
        &authority,
        &control,
        now,
    )?;
    let one = family.reserve_normal_chat_attempt(
        &authority,
        &attempt_request(&control, "intent:first")?,
        now,
    )?;
    let two = family.reserve_normal_chat_attempt(
        &authority,
        &attempt_request(&control, "intent:second")?,
        now,
    )?;
    let reopened = FamilyAuthorityStore::require_existing_normal_chat_session_family(
        &File::open(root.path())?,
        &authority,
        &control,
        now,
    )?;
    let snapshot = reopened.read_normal_chat_session_snapshot_v2()?;
    assert_eq!(snapshot.reservations, vec![one, two]);
    assert_eq!(snapshot.admission.reservation_count, 2);
    fs::remove_file(root.path().join("family-authority.json"))?;
    assert!(
        FamilyAuthorityStore::require_existing_normal_chat_session_family(
            &File::open(root.path())?,
            &authority,
            &control,
            now
        )
        .is_err()
    );
    assert!(!root.path().join("family-authority.json").exists());
    assert!(family.read_normal_chat_session_snapshot_v2().is_err());
    Ok(())
}

#[test]
fn controlled_family_rechecks_revocation_and_keeps_historical_charges() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path(), 1)?;
    let root = tempfile::tempdir()?;
    let store = store(root.path())?;
    let control =
        store.open_normal_chat_session_control(&authority, "conversation:fixture", None, now)?;
    let family = FamilyAuthorityStore::from_normal_chat_session_control(
        &File::open(root.path())?,
        &authority,
        &control,
        now,
    )?;
    let first = family.reserve_normal_chat_attempt(
        &authority,
        &attempt_request(&control, "intent:first")?,
        now,
    )?;
    family.guard_child_dispatch(
        &authority,
        &first.child_control.request.child_run_id,
        &first.child_control.child_control_permit_id,
        now,
    )?;
    store.revoke(
        &control.permit().permit_id,
        PermitRevocationReasonV1::Operator,
        now(),
    )?;
    assert!(family
        .reserve_normal_chat_attempt(&authority, &attempt_request(&control, "intent:later")?, now)
        .is_err());
    assert!(family
        .guard_child_dispatch(
            &authority,
            &first.child_control.request.child_run_id,
            &first.child_control.child_control_permit_id,
            now
        )
        .is_err());
    assert_eq!(
        family.read_normal_chat_reservation("intent:first")?,
        Some(first)
    );
    assert_eq!(family.read_normal_chat_reservation("intent:later")?, None);
    Ok(())
}

#[test]
fn controlled_family_rejects_permit_directory_replacement() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path(), 1)?;
    let root = tempfile::tempdir()?;
    let store = store(root.path())?;
    let control =
        store.open_normal_chat_session_control(&authority, "conversation:fixture", None, now)?;
    let family = FamilyAuthorityStore::from_normal_chat_session_control(
        &File::open(root.path())?,
        &authority,
        &control,
        now,
    )?;
    fs::rename(root.path().join("permits"), root.path().join("permits-old"))?;
    fs::create_dir(root.path().join("permits"))?;
    fs::set_permissions(
        root.path().join("permits"),
        fs::Permissions::from_mode(0o700),
    )?;
    assert!(family
        .reserve_normal_chat_attempt(
            &authority,
            &attempt_request(&control, "intent:after-swap")?,
            now
        )
        .is_err());
    assert_eq!(
        family.read_normal_chat_reservation("intent:after-swap")?,
        None
    );
    Ok(())
}

#[test]
fn session_control_rechecks_clock_after_durable_publication() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path(), 1)?;
    let root = tempfile::tempdir()?;
    let store = store(root.path())?;
    let mut reads = 0;
    let result =
        store.open_normal_chat_session_control(&authority, "conversation:fixture", None, || {
            reads += 1;
            if reads < 3 {
                now()
            } else {
                now() + TimeDelta::milliseconds(300_000)
            }
        });
    assert!(matches!(
        result,
        Err(PolicyError::NormalChatEgressDenied(
            NormalChatEgressDenialV1::GrantExpired
        ))
    ));
    assert!(store
        .open_normal_chat_session_control(&authority, "conversation:fixture", None, || now()
            + TimeDelta::milliseconds(300_000))
        .is_err());
    Ok(())
}

#[test]
fn controlled_family_expiry_after_reservation_preserves_charge_without_success() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path(), 1)?;
    let root = tempfile::tempdir()?;
    let store = store(root.path())?;
    let control =
        store.open_normal_chat_session_control(&authority, "conversation:fixture", None, now)?;
    let family = FamilyAuthorityStore::from_normal_chat_session_control(
        &File::open(root.path())?,
        &authority,
        &control,
        now,
    )?;
    let mut reads = 0;
    let result = family.reserve_normal_chat_attempt(
        &authority,
        &attempt_request(&control, "intent:ambiguous-reserve")?,
        || {
            reads += 1;
            if reads <= 2 {
                now()
            } else {
                now() + TimeDelta::milliseconds(300_000)
            }
        },
    );
    assert!(matches!(
        result,
        Err(PolicyError::NormalChatEgressDenied(
            NormalChatEgressDenialV1::GrantExpired
        ))
    ));
    assert!(family
        .read_normal_chat_reservation("intent:ambiguous-reserve")?
        .is_some());
    assert!(family
        .reserve_normal_chat_attempt(
            &authority,
            &attempt_request(&control, "intent:ambiguous-reserve")?,
            || now() + TimeDelta::milliseconds(300_000)
        )
        .is_err());
    Ok(())
}

#[test]
fn concurrent_session_open_has_one_canonical_root_control() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path(), 1)?;
    let root = tempfile::tempdir()?;
    let mut workers = Vec::new();
    for _ in 0..4 {
        let handle = store(root.path())?;
        let current_authority = authority.clone();
        workers.push(std::thread::spawn(move || {
            handle
                .open_normal_chat_session_control(
                    &current_authority,
                    "conversation:fixture",
                    None,
                    now,
                )
                .map(|cap| cap.permit().clone())
        }));
    }
    let mut returned = Vec::new();
    for worker in workers {
        returned.push(worker.join().map_err(|_| "open worker panicked")??);
    }
    assert!(returned.iter().all(|permit| permit == &returned[0]));
    let count = fs::read_dir(root.path().join("permits"))?
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("permit-"))
        .count();
    assert_eq!(count, 1);
    Ok(())
}

#[test]
fn session_control_is_grant_bound_and_entirely_network_denied() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path(), 1)?;
    let root = tempfile::tempdir()?;
    let store = store(root.path())?;
    let control =
        store.open_normal_chat_session_control(&authority, "conversation:fixture", None, now)?;
    assert_eq!(control.session(), &session(&authority)?);
    let permit = control.permit();
    assert_eq!(permit.binding.run_id, session(&authority)?.run_id()?);
    assert_eq!(permit.purpose, PermitPurposeV1::Control);
    assert!(!permit.binding.effect.network_allowed);
    assert!(permit.binding.effect.read_roots.is_empty());
    assert!(permit.binding.effect.write_roots.is_empty());
    let ceiling = permit
        .delegation_ceiling
        .as_ref()
        .ok_or("missing ceiling")?;
    assert_eq!(ceiling.audiences, vec!["normal_chat"]);
    assert!(ceiling
        .actions
        .iter()
        .all(|action| !action.effect.network_allowed));
    assert_eq!(store.state(&permit.permit_id)?.permit, *permit);
    assert_eq!(store.state(&permit.permit_id)?.state, PermitStateV1::Issued);
    let grant = control.family_grant();
    assert_eq!(grant.root_operation_id, permit.binding.run_id);
    assert_eq!(grant.parent_control_permit_id, permit.permit_id);
    assert_eq!(
        grant.child_run_ceiling.max_children,
        authority.grant().caps.max_attempts
    );
    Ok(())
}
#[test]
fn reopened_control_preserves_identity_times_and_revocation() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path(), 1)?;
    let root = tempfile::tempdir()?;
    let first_store = store(root.path())?;
    let first = first_store.open_normal_chat_session_control(
        &authority,
        "conversation:fixture",
        None,
        now,
    )?;
    let expected = first.permit().clone();
    drop(first_store);
    let reopened = store(root.path())?;
    let repeat = reopened.open_normal_chat_session_control(
        &authority,
        "conversation:fixture",
        None,
        || now() + TimeDelta::seconds(1),
    )?;
    assert_eq!(repeat.permit(), &expected);
    reopened.revoke(
        &expected.permit_id,
        PermitRevocationReasonV1::Operator,
        now() + TimeDelta::seconds(2),
    )?;
    assert!(matches!(
        reopened.open_normal_chat_session_control(
            &authority,
            "conversation:fixture",
            None,
            || now() + TimeDelta::seconds(3)
        ),
        Err(PolicyError::NormalChatEgressDenied(
            NormalChatEgressDenialV1::RunClosed
        ))
    ));
    assert!(matches!(
        reopened.state(&expected.permit_id)?.state,
        PermitStateV1::Revoked { .. }
    ));
    Ok(())
}
#[test]
fn session_control_preserves_existing_v1_lease_limit_and_never_renews() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path(), 1)?;
    let root = tempfile::tempdir()?;
    let store = store(root.path())?;
    let first =
        store.open_normal_chat_session_control(&authority, "conversation:fixture", None, now)?;
    assert_eq!(
        first.permit().binding.expires_at,
        now() + TimeDelta::milliseconds(300_000)
    );
    assert!(matches!(
        store.open_normal_chat_session_control(&authority, "conversation:fixture", None, || now()
            + TimeDelta::milliseconds(300_000)),
        Err(PolicyError::NormalChatEgressDenied(
            NormalChatEgressDenialV1::GrantExpired
        ))
    ));
    assert_eq!(
        store.state(&first.permit().permit_id)?.permit,
        *first.permit()
    );
    Ok(())
}
#[test]
fn one_run_root_cannot_be_rebound_to_other_session_or_grant() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let first_authority = authority(auth_dir.path(), 1)?;
    let root = tempfile::tempdir()?;
    let store = store(root.path())?;
    store.open_normal_chat_session_control(&first_authority, "conversation:fixture", None, now)?;
    assert!(store
        .open_normal_chat_session_control(&first_authority, "conversation:other", None, now)
        .is_err());
    let newer = authority(auth_dir.path(), 2)?;
    assert!(store
        .open_normal_chat_session_control(&newer, "conversation:fixture", None, now)
        .is_err());
    Ok(())
}
#[test]
fn validated_control_binds_family_to_same_pinned_root_and_grant() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path(), 1)?;
    let root = tempfile::tempdir()?;
    let store = store(root.path())?;
    let control =
        store.open_normal_chat_session_control(&authority, "conversation:fixture", None, now)?;
    let family = FamilyAuthorityStore::from_normal_chat_session_control(
        &File::open(root.path())?,
        &authority,
        &control,
        now,
    )?;
    assert_eq!(
        family.effect_budget()?,
        control.family_grant().effect_budget
    );
    let other_root = tempfile::tempdir()?;
    assert!(FamilyAuthorityStore::from_normal_chat_session_control(
        &File::open(other_root.path())?,
        &authority,
        &control,
        now
    )
    .is_err());
    store.revoke(
        &control.permit().permit_id,
        PermitRevocationReasonV1::Operator,
        now() + TimeDelta::seconds(1),
    )?;
    assert!(
        FamilyAuthorityStore::from_normal_chat_session_control(
            &File::open(root.path())?,
            &authority,
            &control,
            || now() + TimeDelta::seconds(1)
        )
        .is_err(),
        "cached capability must recheck durable revocation"
    );
    Ok(())
}
#[test]
fn corrupt_control_reopen_is_rejected_without_issuing_replacement() -> TestResult {
    let auth_dir = tempfile::tempdir()?;
    let authority = authority(auth_dir.path(), 1)?;
    let root = tempfile::tempdir()?;
    let store = store(root.path())?;
    let control =
        store.open_normal_chat_session_control(&authority, "conversation:fixture", None, now)?;
    let permit_dir = root.path().join("permits");
    let files = fs::read_dir(&permit_dir)?.collect::<Result<Vec<_>, _>>()?;
    let path = files
        .iter()
        .find(|entry| entry.file_name().to_string_lossy().starts_with("permit-"))
        .ok_or("missing permit record")?
        .path();
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    value["permit"]["binding"]["args_digest"] = json!(content_digest(&"tampered")?);
    fs::write(&path, serde_json::to_vec(&value)?)?;
    assert!(store
        .open_normal_chat_session_control(&authority, "conversation:fixture", None, now)
        .is_err());
    assert!(store.state(&control.permit().permit_id).is_err());
    assert_eq!(
        fs::read_dir(&permit_dir)?
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("permit-"))
            .count(),
        1
    );
    Ok(())
}
