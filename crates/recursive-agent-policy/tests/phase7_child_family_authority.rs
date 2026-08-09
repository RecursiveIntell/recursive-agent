use chrono::{DateTime, TimeDelta, Utc};
use recursive_agent_contracts::{ContentDigest, CurrentPermitId, CurrentReceiptId, CurrentRunId};
use recursive_agent_policy::{
    ActorPrincipalV1, ChildRunCeilingV1, FamilyAuthorityStore, FamilyChildRequestV1,
    FamilyRootGrantV1, PermitBudgetV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn now() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_700_000_000)
}

fn run_id(mark: char) -> Result<CurrentRunId, Box<dyn std::error::Error>> {
    Ok(CurrentRunId::try_new(format!(
        "v1:recursive-agent/run/v1:det:{}",
        mark.to_string().repeat(64)
    ))?)
}

fn permit_id(mark: char) -> Result<CurrentPermitId, Box<dyn std::error::Error>> {
    Ok(CurrentPermitId::try_new(format!(
        "v1:recursive-agent/permit/v1:det:{}",
        mark.to_string().repeat(64)
    ))?)
}

fn receipt_id(mark: char) -> Result<CurrentReceiptId, Box<dyn std::error::Error>> {
    Ok(CurrentReceiptId::try_new(format!(
        "v1:recursive-agent/receipt/v1:det:{}",
        mark.to_string().repeat(64)
    ))?)
}

fn budget(output: u64) -> PermitBudgetV1 {
    PermitBudgetV1 {
        max_wall_time_ms: output,
        max_output_bytes: output,
        max_artifact_bytes: output,
    }
}

fn grant() -> Result<FamilyRootGrantV1, Box<dyn std::error::Error>> {
    let root = run_id('a')?;
    Ok(FamilyRootGrantV1 {
        root_operation_id: root,
        parent_control_permit_id: permit_id('b')?,
        actor: ActorPrincipalV1::try_new("actor:phase7")?,
        policy_version: "policy-v1".into(),
        effect_budget: budget(100),
        child_run_ceiling: ChildRunCeilingV1 {
            max_depth: 2,
            max_children: 2,
            family_budget: budget(100),
            not_before: now(),
            expires_at: now() + TimeDelta::seconds(10),
        },
    })
}

fn request(
    grant: &FamilyRootGrantV1,
    child_mark: char,
    output: u64,
) -> Result<FamilyChildRequestV1, Box<dyn std::error::Error>> {
    Ok(FamilyChildRequestV1 {
        child_run_id: run_id(child_mark)?,
        parent_operation_id: grant.root_operation_id.clone(),
        root_operation_id: grant.root_operation_id.clone(),
        parent_control_permit_id: grant.parent_control_permit_id.clone(),
        parent_admission_receipt_id: receipt_id('c')?,
        requested_budget: budget(output),
        child_operation_digest: ContentDigest::compute(child_mark.to_string().as_bytes()),
        depth: 1,
    })
}

#[test]
fn family_store_reserves_one_cross_run_child_without_spending_parent_effect_budget() -> TestResult {
    let temp = tempfile::tempdir()?;
    let root_file = std::fs::File::open(temp.path())?;
    let grant = grant()?;
    let store = FamilyAuthorityStore::from_dir_fd(&root_file, grant.clone())?;
    let child = request(&grant, 'd', 60)?;

    let issued = store.reserve_child(&child, now())?;
    assert_eq!(issued.request, child);
    assert_eq!(store.effect_budget()?, grant.effect_budget);
    assert_eq!(store.reserved_budget()?.max_output_bytes, 60);

    let old_store = recursive_agent_policy::DurablePermitStore::from_dir_fd(&root_file)?;
    assert!(
        old_store.state(&issued.child_control_permit_id).is_err(),
        "the single-run permit store must not become a cross-run family authority"
    );
    Ok(())
}

#[test]
fn family_store_rejects_widening_overreservation_and_parent_revocation() -> TestResult {
    let temp = tempfile::tempdir()?;
    let root_file = std::fs::File::open(temp.path())?;
    let grant = grant()?;
    let store = FamilyAuthorityStore::from_dir_fd(&root_file, grant.clone())?;

    let first = request(&grant, 'd', 60)?;
    store.reserve_child(&first, now())?;
    let second = request(&grant, 'e', 60)?;
    assert!(store.reserve_child(&second, now()).is_err());

    let mut widened = request(&grant, 'f', 1)?;
    widened.root_operation_id = run_id('f')?;
    assert!(store.reserve_child(&widened, now()).is_err());

    store.revoke_parent(now())?;
    let after_revoke = request(&grant, '1', 1)?;
    assert!(store.reserve_child(&after_revoke, now()).is_err());
    Ok(())
}

#[test]
fn retry_is_idempotent_and_concurrent_overreservation_admits_at_most_one() -> TestResult {
    let temp = tempfile::tempdir()?;
    let root_file = std::fs::File::open(temp.path())?;
    let grant = grant()?;
    let store = FamilyAuthorityStore::from_dir_fd(&root_file, grant.clone())?;
    let retry = request(&grant, 'd', 50)?;
    let first = store.reserve_child(&retry, now())?;
    let second = store.reserve_child(&retry, now())?;
    assert_eq!(first, second);
    assert_eq!(store.reserved_budget()?.max_output_bytes, 50);

    let child_one = request(&grant, 'e', 50)?;
    let child_two = request(&grant, 'f', 50)?;
    let one_store = store.clone();
    let two_store = store.clone();
    let one = std::thread::spawn(move || one_store.reserve_child(&child_one, now()));
    let two = std::thread::spawn(move || two_store.reserve_child(&child_two, now()));
    let admitted = usize::from(one.join().map_err(|_| "first thread panicked")?.is_ok())
        + usize::from(two.join().map_err(|_| "second thread panicked")?.is_ok());
    assert_eq!(admitted, 1);
    assert_eq!(store.reserved_budget()?.max_output_bytes, 100);
    Ok(())
}
