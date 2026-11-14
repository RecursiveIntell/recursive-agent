//! Durable, conservative monetary reservations under the native family owner.
//! No provider is called and no reservation grants effect authority.
use chrono::{DateTime, TimeDelta, Utc};
use recursive_agent_contracts::{ContentDigest, CurrentPermitId, CurrentRunId};
use recursive_agent_policy::{
    ActorPrincipalV1, ChildRunCeilingV1, FamilyAuthorityStore, FamilyRootGrantV1,
    InferenceBudgetGrantV1, InferenceSendRequestV1, InferenceSettlementV1, PermitBudgetV1,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn now() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_700_000_000)
}
fn run_id(c: char) -> Result<CurrentRunId, Box<dyn std::error::Error>> {
    Ok(CurrentRunId::try_new(format!(
        "v1:recursive-agent/run/v1:det:{}",
        c.to_string().repeat(64)
    ))?)
}
fn permit_id(c: char) -> Result<CurrentPermitId, Box<dyn std::error::Error>> {
    Ok(CurrentPermitId::try_new(format!(
        "v1:recursive-agent/permit/v1:det:{}",
        c.to_string().repeat(64)
    ))?)
}
fn root() -> Result<FamilyRootGrantV1, Box<dyn std::error::Error>> {
    let b = PermitBudgetV1 {
        max_wall_time_ms: 1000,
        max_output_bytes: 1000,
        max_artifact_bytes: 1000,
    };
    Ok(FamilyRootGrantV1 {
        root_operation_id: run_id('a')?,
        parent_control_permit_id: permit_id('b')?,
        actor: ActorPrincipalV1::try_new("actor:budget-test")?,
        policy_version: "policy:budget-test".into(),
        effect_budget: b.clone(),
        child_run_ceiling: ChildRunCeilingV1 {
            max_depth: 2,
            max_children: 4,
            family_budget: b,
            not_before: now(),
            expires_at: now() + TimeDelta::seconds(100),
        },
    })
}
fn grant(root: &FamilyRootGrantV1) -> InferenceBudgetGrantV1 {
    InferenceBudgetGrantV1 {
        schema: "recursive-agent.inference-budget/v1".into(),
        root_operation_id: root.root_operation_id.clone(),
        parent_control_permit_id: root.parent_control_permit_id.clone(),
        policy_version: root.policy_version.clone(),
        provider: "openai-codex".into(),
        model: "gpt-6-luna".into(),
        reasoning_effort: "xhigh".into(),
        tariff_digest: ContentDigest::compute(b"trusted-fixture-tariff"),
        input_nanodollars_per_token: 100,
        output_nanodollars_per_token: 500,
        max_input_tokens_per_send: 100,
        max_output_tokens_per_send: 20,
        max_total_input_tokens: 500,
        max_total_output_tokens: 100,
        max_sends: 4,
        max_total_nanodollars: 40_000,
        not_before: now(),
        expires_at: now() + TimeDelta::seconds(60),
    }
}
fn request(mark: char) -> Result<InferenceSendRequestV1, Box<dyn std::error::Error>> {
    Ok(InferenceSendRequestV1 {
        permit_id: permit_id(mark)?,
        request_digest: ContentDigest::compute(mark.to_string().as_bytes()),
        provider: "openai-codex".into(),
        model: "gpt-6-luna".into(),
        reasoning_effort: "xhigh".into(),
    })
}
#[test]
fn reservations_are_idempotent_immutable_and_survive_reopen() -> TestResult {
    let temp = tempfile::tempdir()?;
    let dir = std::fs::File::open(temp.path())?;
    let root = root()?;
    let store = FamilyAuthorityStore::from_dir_fd(&dir, root.clone())?;
    let budget = grant(&root);
    store.bind_inference_budget(budget.clone())?;
    store.bind_inference_budget(budget.clone())?;
    let first = request('c')?;
    assert_eq!(
        store.reserve_inference(&first, now)?,
        store.reserve_inference(&first, now)?
    );
    let reopened = FamilyAuthorityStore::from_dir_fd(&dir, root.clone())?;
    assert_eq!(reopened.inference_budget_status()?.reserved_sends, 1);
    let mut changed = budget;
    changed.max_total_nanodollars += 1;
    assert!(reopened.bind_inference_budget(changed).is_err());
    let mut replaced = first;
    replaced.request_digest = ContentDigest::compute(b"substituted request");
    assert!(reopened.reserve_inference(&replaced, now).is_err());
    reopened.reserve_inference(&request('d')?, now)?;
    assert!(reopened.reserve_inference(&request('e')?, now).is_err());
    assert_eq!(
        reopened.inference_budget_status()?.reserved_nanodollars,
        40_000
    );
    Ok(())
}
#[test]
fn dispatch_is_once_settlement_is_immutable_and_never_refunds() -> TestResult {
    let temp = tempfile::tempdir()?;
    let dir = std::fs::File::open(temp.path())?;
    let root = root()?;
    let store = FamilyAuthorityStore::from_dir_fd(&dir, root.clone())?;
    store.bind_inference_budget(grant(&root))?;
    let req = request('c')?;
    assert!(store
        .begin_inference(&req.permit_id, &req.request_digest, now)
        .is_err());
    store.reserve_inference(&req, now)?;
    assert!(store
        .begin_inference(&req.permit_id, &ContentDigest::compute(b"wrong"), now)
        .is_err());
    let ticket = store.begin_inference(&req.permit_id, &req.request_digest, now)?;
    let reopened = FamilyAuthorityStore::from_dir_fd(&dir, root)?;
    assert!(reopened
        .begin_inference(&req.permit_id, &req.request_digest, now)
        .is_err());
    let outcome = InferenceSettlementV1::Observed {
        response_digest: ContentDigest::compute(b"observed response"),
        input_tokens: 2,
        output_tokens: 3,
    };
    store.settle_inference(&ticket, outcome.clone())?;
    reopened.settle_inference(&ticket, outcome)?;
    assert!(store
        .settle_inference(
            &ticket,
            InferenceSettlementV1::Unknown {
                evidence_digest: ContentDigest::compute(b"different")
            }
        )
        .is_err());
    let status = store.inference_budget_status()?;
    assert_eq!(status.settled_sends, 1);
    assert_eq!(status.reserved_nanodollars, 20_000);
    store.reserve_inference(&request('d')?, now)?;
    assert!(store.reserve_inference(&request('e')?, now).is_err());
    Ok(())
}
#[test]
fn uncertain_effect_and_crash_before_settlement_remain_charged() -> TestResult {
    let temp = tempfile::tempdir()?;
    let dir = std::fs::File::open(temp.path())?;
    let root = root()?;
    let store = FamilyAuthorityStore::from_dir_fd(&dir, root.clone())?;
    store.bind_inference_budget(grant(&root))?;
    let a = request('c')?;
    let b = request('d')?;
    store.reserve_inference(&a, now)?;
    store.reserve_inference(&b, now)?;
    let ticket = store.begin_inference(&a.permit_id, &a.request_digest, now)?;
    store.settle_inference(
        &ticket,
        InferenceSettlementV1::Unknown {
            evidence_digest: ContentDigest::compute(b"transport interrupted"),
        },
    )?;
    let _outstanding = store.begin_inference(&b.permit_id, &b.request_digest, now)?;
    drop(store);
    let reopened = FamilyAuthorityStore::from_dir_fd(&dir, root)?;
    let status = reopened.inference_budget_status()?;
    assert_eq!(status.unknown_sends, 1);
    assert_eq!(status.unsettled_dispatches, 1);
    assert_eq!(status.reserved_nanodollars, 40_000);
    assert!(reopened.reserve_inference(&request('e')?, now).is_err());
    assert!(reopened
        .begin_inference(&b.permit_id, &b.request_digest, now)
        .is_err());
    Ok(())
}
#[test]
fn wrong_route_expiry_revocation_and_foreign_store_tickets_refuse() -> TestResult {
    let temp = tempfile::tempdir()?;
    let dir = std::fs::File::open(temp.path())?;
    let root = root()?;
    let store = FamilyAuthorityStore::from_dir_fd(&dir, root.clone())?;
    store.bind_inference_budget(grant(&root))?;
    let mut wrong = request('c')?;
    wrong.model = "not-authorized".into();
    assert!(store.reserve_inference(&wrong, now).is_err());
    let req = request('c')?;
    assert!(store
        .reserve_inference(&req, || now() + TimeDelta::seconds(60))
        .is_err());
    assert!(store
        .reserve_inference(&req, || now() - TimeDelta::seconds(1))
        .is_err());
    store.reserve_inference(&req, now)?;
    let ticket = store.begin_inference(&req.permit_id, &req.request_digest, now)?;
    let other = tempfile::tempdir()?;
    let foreign = FamilyAuthorityStore::from_dir_fd(&std::fs::File::open(other.path())?, root)?;
    assert!(foreign
        .settle_inference(
            &ticket,
            InferenceSettlementV1::Unknown {
                evidence_digest: ContentDigest::compute(b"foreign")
            }
        )
        .is_err());
    store.revoke_parent(now())?;
    assert!(store.reserve_inference(&request('d')?, now).is_err());
    store.settle_inference(
        &ticket,
        InferenceSettlementV1::Unknown {
            evidence_digest: ContentDigest::compute(b"revoked while in flight"),
        },
    )?;
    Ok(())
}
#[test]
fn independent_store_handles_do_not_overreserve_under_race() -> TestResult {
    let temp = tempfile::tempdir()?;
    let dir = std::fs::File::open(temp.path())?;
    let root = root()?;
    let store = FamilyAuthorityStore::from_dir_fd(&dir, root.clone())?;
    let mut budget = grant(&root);
    budget.max_total_nanodollars = 20_000;
    store.bind_inference_budget(budget)?;
    let other = FamilyAuthorityStore::from_dir_fd(&dir, root)?;
    let a = request('c')?;
    let b = request('d')?;
    let (one, two) = std::thread::scope(|scope| {
        let one = scope.spawn(|| store.reserve_inference(&a, now));
        let two = scope.spawn(|| other.reserve_inference(&b, now));
        (one.join(), two.join())
    });
    let admitted = usize::from(one.map_err(|_| "first reservation panicked")?.is_ok())
        + usize::from(two.map_err(|_| "second reservation panicked")?.is_ok());
    assert_eq!(admitted, 1);
    assert_eq!(store.inference_budget_status()?.reserved_sends, 1);
    Ok(())
}
#[test]
fn missing_budget_state_cannot_reinitialize_and_replenish() -> TestResult {
    let temp = tempfile::tempdir()?;
    let dir = std::fs::File::open(temp.path())?;
    let root = root()?;
    let store = FamilyAuthorityStore::from_dir_fd(&dir, root.clone())?;
    let budget = grant(&root);
    store.bind_inference_budget(budget.clone())?;
    store.reserve_inference(&request('c')?, now)?;
    std::fs::remove_file(temp.path().join("inference-budget.v1.json"))?;
    assert!(
        store.bind_inference_budget(budget).is_err(),
        "missing charged state was silently reinitialized"
    );
    Ok(())
}

#[test]
#[ignore = "subprocess entrypoint exercised by the crash-parent test"]
fn process_crash_child_entry() -> TestResult {
    let Some(path) = std::env::var_os("RI_BUDGET_CRASH_FIXTURE_DIR") else {
        return Ok(());
    };
    let dir = std::fs::File::open(path)?;
    let root = root()?;
    let store = FamilyAuthorityStore::from_dir_fd(&dir, root.clone())?;
    store.bind_inference_budget(grant(&root))?;
    let request = request('c')?;
    store.reserve_inference(&request, now)?;
    let _ticket = store.begin_inference(&request.permit_id, &request.request_digest, now)?;
    std::process::exit(73);
}

#[test]
fn real_process_exit_after_dispatch_cannot_replay_or_refund() -> TestResult {
    let temp = tempfile::tempdir()?;
    let child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "process_crash_child_entry",
            "--ignored",
            "--test-threads=1",
        ])
        .env("RI_BUDGET_CRASH_FIXTURE_DIR", temp.path())
        .output()?;
    assert_eq!(
        child.status.code(),
        Some(73),
        "child must reach post-dispatch exit"
    );
    let store = FamilyAuthorityStore::from_dir_fd(&std::fs::File::open(temp.path())?, root()?)?;
    let request = request('c')?;
    let before = std::fs::read(temp.path().join("inference-budget.v1.json"))?;
    let readback = store.read_inference(&request)?;
    assert_eq!(readback.request, request);
    assert_eq!(readback.dispatched_at, Some(now()));
    assert!(readback.settlement.is_none());
    assert_eq!(
        std::fs::read(temp.path().join("inference-budget.v1.json"))?,
        before
    );
    assert_eq!(store.inference_budget_status()?.unsettled_dispatches, 1);
    assert_eq!(
        store.inference_budget_status()?.reserved_nanodollars,
        20_000
    );
    assert!(store
        .begin_inference(&request.permit_id, &request.request_digest, now)
        .is_err());
    Ok(())
}

#[test]
fn missing_binding_does_not_manufacture_a_fresh_budget() -> TestResult {
    let temp = tempfile::tempdir()?;
    let root = root()?;
    let store =
        FamilyAuthorityStore::from_dir_fd(&std::fs::File::open(temp.path())?, root.clone())?;
    let budget = grant(&root);
    store.bind_inference_budget(budget.clone())?;
    store.reserve_inference(&request('c')?, now)?;
    std::fs::remove_file(temp.path().join("inference-budget.v1.binding"))?;
    assert!(store.bind_inference_budget(budget).is_err());
    assert!(store.inference_budget_status().is_err());
    Ok(())
}

#[test]
fn token_ceiling_and_oversized_settlement_cannot_widen_reservations() -> TestResult {
    let temp = tempfile::tempdir()?;
    let root = root()?;
    let store =
        FamilyAuthorityStore::from_dir_fd(&std::fs::File::open(temp.path())?, root.clone())?;
    let mut budget = grant(&root);
    budget.max_total_input_tokens = budget.max_input_tokens_per_send;
    store.bind_inference_budget(budget)?;
    let req = request('c')?;
    store.reserve_inference(&req, now)?;
    assert!(store.reserve_inference(&request('d')?, now).is_err());
    let ticket = store.begin_inference(&req.permit_id, &req.request_digest, now)?;
    assert!(store
        .settle_inference(
            &ticket,
            InferenceSettlementV1::Observed {
                response_digest: ContentDigest::compute(b"overrun"),
                input_tokens: 101,
                output_tokens: 1,
            }
        )
        .is_err());
    assert_eq!(store.inference_budget_status()?.unsettled_dispatches, 1);
    Ok(())
}

#[test]
fn five_dollar_equivalent_fixture_caps_worst_case_token_reservations() -> TestResult {
    let temp = tempfile::tempdir()?;
    let root = root()?;
    let store =
        FamilyAuthorityStore::from_dir_fd(&std::fs::File::open(temp.path())?, root.clone())?;
    let mut budget = grant(&root);
    // Frozen text-only worst-case tariff including long-input, Fast, regional
    // and cache-write premiums. Not a live operator grant or provider invoice.
    budget.input_nanodollars_per_token = 550;
    budget.output_nanodollars_per_token = 1650;
    budget.max_input_tokens_per_send = 922_000;
    budget.max_output_tokens_per_send = 128_000;
    budget.max_total_input_tokens = 8 * budget.max_input_tokens_per_send;
    budget.max_total_output_tokens = 8 * budget.max_output_tokens_per_send;
    budget.max_sends = 8;
    budget.max_total_nanodollars = 5_000_000_000;
    store.bind_inference_budget(budget)?;
    for mark in ['c', 'd', 'e', 'f', '1', '2'] {
        store.reserve_inference(&request(mark)?, now)?;
    }
    assert!(store.reserve_inference(&request('3')?, now).is_err());
    let status = store.inference_budget_status()?;
    assert_eq!(status.reserved_sends, 6);
    assert!(status.reserved_nanodollars <= 5_000_000_000);
    println!(
        "five-dollar fixture reserved_nanodollars={}",
        status.reserved_nanodollars
    );
    Ok(())
}

#[test]
fn final_clock_expiry_or_regression_leaves_dispatch_unconsumed() -> TestResult {
    let temp = tempfile::tempdir()?;
    let root = root()?;
    let store =
        FamilyAuthorityStore::from_dir_fd(&std::fs::File::open(temp.path())?, root.clone())?;
    store.bind_inference_budget(grant(&root))?;
    let req = request('c')?;
    for end in [
        now() + TimeDelta::seconds(60),
        now() - TimeDelta::seconds(1),
    ] {
        let mut count = 0;
        assert!(store
            .reserve_inference(&req, || {
                count += 1;
                if count == 1 {
                    now()
                } else {
                    end
                }
            })
            .is_err());
        assert_eq!(store.inference_budget_status()?.reserved_sends, 0);
    }
    store.reserve_inference(&req, now)?;
    for end in [
        now() + TimeDelta::seconds(60),
        now() - TimeDelta::seconds(1),
    ] {
        let mut count = 0;
        assert!(store
            .begin_inference(&req.permit_id, &req.request_digest, || {
                count += 1;
                if count == 1 {
                    now()
                } else {
                    end
                }
            })
            .is_err());
        assert_eq!(store.inference_budget_status()?.unsettled_dispatches, 0);
    }
    let _ticket = store.begin_inference(&req.permit_id, &req.request_digest, now)?;
    assert_eq!(store.inference_budget_status()?.unsettled_dispatches, 1);
    Ok(())
}

#[test]
fn readback_tracks_exact_lifecycle_without_mutating_or_reauthorizing() -> TestResult {
    let temp = tempfile::tempdir()?;
    let dir = std::fs::File::open(temp.path())?;
    let root = root()?;
    let store = FamilyAuthorityStore::from_dir_fd(&dir, root.clone())?;
    store.bind_inference_budget(grant(&root))?;
    let req = request('c')?;
    let reserved = store.reserve_inference(&req, now)?;
    let state_path = temp.path().join("inference-budget.v1.json");
    let before = std::fs::read(&state_path)?;
    assert_eq!(store.read_inference(&req)?, reserved);
    assert_eq!(std::fs::read(&state_path)?, before);
    let ticket = store.begin_inference(&req.permit_id, &req.request_digest, now)?;
    let reopened = FamilyAuthorityStore::from_dir_fd(&dir, root)?;
    let dispatched = reopened.read_inference(&req)?;
    assert_eq!(dispatched.dispatched_at, Some(now()));
    assert!(dispatched.settlement.is_none());
    assert!(reopened
        .begin_inference(&req.permit_id, &req.request_digest, now)
        .is_err());
    let outcome = InferenceSettlementV1::Unknown {
        evidence_digest: ContentDigest::compute(b"lost transport acknowledgement"),
    };
    reopened.settle_inference(&ticket, outcome.clone())?;
    let before = std::fs::read(&state_path)?;
    let retained = reopened.read_inference(&req)?;
    assert_eq!(retained.settlement, Some(outcome));
    let projection: recursive_agent_policy::InferenceSendRecordV1 =
        serde_json::from_slice(&serde_json::to_vec(&retained)?)?;
    assert_eq!(projection, retained);
    assert_eq!(std::fs::read(&state_path)?, before);
    assert_eq!(
        reopened.inference_budget_status()?.reserved_nanodollars,
        20_000
    );
    assert!(reopened
        .begin_inference(&req.permit_id, &req.request_digest, now)
        .is_err());
    Ok(())
}

#[test]
fn readback_rejects_each_substituted_request_coordinate() -> TestResult {
    let temp = tempfile::tempdir()?;
    let root = root()?;
    let store =
        FamilyAuthorityStore::from_dir_fd(&std::fs::File::open(temp.path())?, root.clone())?;
    store.bind_inference_budget(grant(&root))?;
    let req = request('c')?;
    let reserved = store.reserve_inference(&req, now)?;
    let state_path = temp.path().join("inference-budget.v1.json");
    let before = std::fs::read(&state_path)?;
    let mut replacements = vec![req.clone(); 5];
    replacements[0].permit_id = permit_id('d')?;
    replacements[1].request_digest = ContentDigest::compute(b"substituted body");
    replacements[2].provider = "other-provider".into();
    replacements[3].model = "other-model".into();
    replacements[4].reasoning_effort = "low".into();
    for changed in replacements {
        assert!(store.read_inference(&changed).is_err());
    }
    assert_eq!(store.read_inference(&req)?, reserved);
    assert_eq!(std::fs::read(&state_path)?, before);
    Ok(())
}

#[test]
fn readback_of_missing_state_or_attempt_cannot_initialize_or_reserve() -> TestResult {
    let temp = tempfile::tempdir()?;
    let root = root()?;
    let store =
        FamilyAuthorityStore::from_dir_fd(&std::fs::File::open(temp.path())?, root.clone())?;
    let req = request('c')?;
    let state_path = temp.path().join("inference-budget.v1.json");
    let binding_path = temp.path().join("inference-budget.v1.binding");
    assert!(store.read_inference(&req).is_err());
    assert!(!state_path.exists());
    assert!(!binding_path.exists());
    store.bind_inference_budget(grant(&root))?;
    let before = std::fs::read(&state_path)?;
    assert!(store.read_inference(&req).is_err());
    assert_eq!(std::fs::read(&state_path)?, before);
    assert_eq!(store.inference_budget_status()?.reserved_sends, 0);
    Ok(())
}

#[test]
fn readback_after_expiry_and_revocation_preserves_unknown_charge_without_dispatch() -> TestResult {
    let temp = tempfile::tempdir()?;
    let dir = std::fs::File::open(temp.path())?;
    let root = root()?;
    let store = FamilyAuthorityStore::from_dir_fd(&dir, root.clone())?;
    store.bind_inference_budget(grant(&root))?;
    let req = request('c')?;
    store.reserve_inference(&req, now)?;
    let _ticket = store.begin_inference(&req.permit_id, &req.request_digest, now)?;
    store.revoke_parent(now() + TimeDelta::seconds(61))?;
    let reopened = FamilyAuthorityStore::from_dir_fd(&dir, root)?;
    let before = std::fs::read(temp.path().join("inference-budget.v1.json"))?;
    let record = reopened.read_inference(&req)?;
    assert!(record.dispatched_at.is_some());
    assert!(record.settlement.is_none());
    assert_eq!(
        std::fs::read(temp.path().join("inference-budget.v1.json"))?,
        before
    );
    assert!(reopened
        .begin_inference(&req.permit_id, &req.request_digest, || now()
            + TimeDelta::seconds(61))
        .is_err());
    assert!(reopened.reserve_inference(&request('d')?, now).is_err());
    let status = reopened.inference_budget_status()?;
    assert_eq!(status.unsettled_dispatches, 1);
    assert_eq!(status.reserved_nanodollars, 20_000);
    Ok(())
}

#[test]
fn readback_refuses_corrupt_or_missing_binding_without_repairing_authority() -> TestResult {
    for corrupt_binding in [false, true] {
        let temp = tempfile::tempdir()?;
        let root = root()?;
        let store =
            FamilyAuthorityStore::from_dir_fd(&std::fs::File::open(temp.path())?, root.clone())?;
        store.bind_inference_budget(grant(&root))?;
        let req = request('c')?;
        store.reserve_inference(&req, now)?;
        let state_path = temp.path().join("inference-budget.v1.json");
        let binding_path = temp.path().join("inference-budget.v1.binding");
        if corrupt_binding {
            std::fs::write(&binding_path, b"wrong binding")?;
        } else {
            std::fs::remove_file(&binding_path)?;
        }
        let before = std::fs::read(&state_path)?;
        assert!(store.read_inference(&req).is_err());
        assert_eq!(std::fs::read(&state_path)?, before);
        assert_eq!(binding_path.exists(), corrupt_binding);
    }
    Ok(())
}

#[test]
fn grant_overflow_wrong_parent_and_noncanonical_state_fail_closed() -> TestResult {
    let temp = tempfile::tempdir()?;
    let dir = std::fs::File::open(temp.path())?;
    let root = root()?;
    let store = FamilyAuthorityStore::from_dir_fd(&dir, root.clone())?;
    let mut overflow = grant(&root);
    overflow.input_nanodollars_per_token = u64::MAX;
    assert!(store.bind_inference_budget(overflow).is_err());
    let mut wrong = grant(&root);
    wrong.parent_control_permit_id = permit_id('e')?;
    assert!(store.bind_inference_budget(wrong).is_err());
    store.bind_inference_budget(grant(&root))?;
    let file = temp.path().join("inference-budget.v1.json");
    let bytes = std::fs::read(&file)?;
    let mut extra: serde_json::Value = serde_json::from_slice(&bytes)?;
    extra["unexpected"] = true.into();
    std::fs::write(&file, serde_json::to_vec(&extra)?)?;
    assert!(store.reserve_inference(&request('c')?, now).is_err());
    Ok(())
}
