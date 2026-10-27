//! Real scheduler-owner regressions required before context handoff.
//! These exercise the existing public API; they do not claim policy admission
//! or exactly-once external effects. All targets are disposable local files.

use std::sync::{Arc, Barrier};

use recursive_agent_runner::{ProjectedState, SchedulerStore};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn same_operation_cannot_change_its_idempotency_binding() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("scheduler.json");
    let mut store = SchedulerStore::open(&path)?;
    let original = store.admit("op-1", "key-a")?;
    assert!(store.admit("op-1", "key-b").is_err());
    assert_eq!(store.get("op-1"), Some(&original));
    let disk = SchedulerStore::open(&path)?;
    assert_eq!(disk.get("op-1"), Some(&original));
    Ok(())
}

#[test]
fn one_key_cannot_admit_two_different_operations() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let mut store = SchedulerStore::open(tmp.path().join("scheduler.json"))?;
    store.admit("op-1", "key-a")?;
    assert!(store.admit("op-2", "key-a").is_err());
    assert_eq!(store.live_rows().len(), 1);
    Ok(())
}

#[test]
fn quarantine_retains_operation_and_key_tombstones_after_reopen() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("scheduler.json");
    let mut store = SchedulerStore::open(&path)?;
    store.admit("op-1", "key-a")?;
    store.quarantine("op-1")?;
    drop(store);
    let mut store = SchedulerStore::open(&path)?;
    assert!(store.admit("op-1", "key-a").is_err());
    assert!(store.admit("op-1", "key-b").is_err());
    assert!(store.admit("op-2", "key-a").is_err());
    assert!(store.live_rows().is_empty());
    assert_eq!(store.quarantined().len(), 1);
    Ok(())
}

#[test]
fn terminal_operation_cannot_reacquire_a_lease() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let mut store = SchedulerStore::open(tmp.path().join("scheduler.json"))?;
    store.admit("op-1", "key-a")?;
    let grant = store.acquire_lease("op-1", "worker-a")?;
    store.set_terminal("op-1")?;
    assert!(store.acquire_lease("op-1", "worker-a").is_err());
    assert!(store.authorize_effect_start(&grant).is_err());
    assert_eq!(
        store.get("op-1").ok_or("row missing")?.state,
        ProjectedState::Terminal
    );
    Ok(())
}

#[test]
fn cancellation_cannot_be_turned_into_an_authorized_row() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let mut store = SchedulerStore::open(tmp.path().join("scheduler.json"))?;
    store.admit("op-1", "key-a")?;
    let grant = store.acquire_lease("op-1", "worker-a")?;
    store.request_cancel("op-1")?;
    assert!(store.acquire_lease("op-1", "worker-a").is_err());
    assert!(store.transfer_lease(&grant, "worker-b").is_err());
    assert_eq!(
        store.get("op-1").ok_or("row missing")?.state,
        ProjectedState::Cancelling
    );
    Ok(())
}

#[test]
fn a_late_cancel_does_not_erase_terminal_projection() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let mut store = SchedulerStore::open(tmp.path().join("scheduler.json"))?;
    store.admit("op-1", "key-a")?;
    store.set_terminal("op-1")?;
    store.request_cancel("op-1")?;
    assert_eq!(
        store.get("op-1").ok_or("row missing")?.state,
        ProjectedState::Terminal
    );
    assert!(store.get("op-1").ok_or("row missing")?.cancel_requested);
    Ok(())
}

#[test]
fn stale_instance_cannot_authorize_a_transferred_grant() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("scheduler.json");
    let mut first = SchedulerStore::open(&path)?;
    first.admit("op-1", "key-a")?;
    let old = first.acquire_lease("op-1", "worker-a")?;
    let mut second = SchedulerStore::open(&path)?;
    let new = second.transfer_lease(&old, "worker-b")?;
    assert!(first.authorize_effect_start(&old).is_err());
    assert!(first.authorize_publish(&old).is_err());
    first.authorize_effect_start(&new)?;
    Ok(())
}

#[test]
fn stale_instance_update_preserves_other_committed_rows() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("scheduler.json");
    let mut first = SchedulerStore::open(&path)?;
    let mut second = SchedulerStore::open(&path)?;
    first.admit("op-1", "key-a")?;
    second.admit("op-2", "key-b")?;
    let disk = SchedulerStore::open(&path)?;
    assert_eq!(disk.live_rows().len(), 2);
    assert!(disk.get("op-1").is_some());
    assert!(disk.get("op-2").is_some());
    Ok(())
}

#[test]
fn concurrent_instances_cannot_double_bind_a_key() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("scheduler.json");
    let ready = Arc::new(Barrier::new(2));
    let mut joins = Vec::new();
    for n in 0..2 {
        let path = path.clone();
        let ready = Arc::clone(&ready);
        joins.push(std::thread::spawn(move || -> Result<bool, String> {
            let mut store = SchedulerStore::open(path).map_err(|e| e.to_string())?;
            ready.wait();
            Ok(store.admit(format!("op-{n}"), "shared-key").is_ok())
        }));
    }
    let mut admitted = 0;
    for join in joins {
        admitted += usize::from(join.join().map_err(|_| "thread panicked")??);
    }
    assert_eq!(admitted, 1);
    assert_eq!(SchedulerStore::open(path)?.live_rows().len(), 1);
    Ok(())
}

#[test]
fn failed_mutation_cannot_publish_an_in_memory_grant() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("scheduler.json");
    let backup = tmp.path().join("saved.json");
    let mut store = SchedulerStore::open(&path)?;
    store.admit("op-1", "key-a")?;
    let old = store.acquire_lease("op-1", "worker-a")?;
    let before = store.get("op-1").ok_or("row missing")?.clone();
    std::fs::rename(&path, &backup)?;
    std::fs::create_dir(&path)?;
    assert!(store.transfer_lease(&old, "worker-b").is_err());
    assert_eq!(store.get("op-1"), Some(&before));
    std::fs::remove_dir(&path)?;
    std::fs::rename(&backup, &path)?;
    assert!(store.authorize_effect_start(&old).is_err());
    assert!(store.admit("op-2", "key-b").is_err());
    let recovered = SchedulerStore::open(&path)?;
    recovered.authorize_effect_start(&old)?;
    Ok(())
}

#[test]
fn a_missing_committed_store_is_not_reinitialized() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("scheduler.json");
    let mut store = SchedulerStore::open(&path)?;
    store.admit("op-1", "key-a")?;
    std::fs::remove_file(&path)?;
    assert!(store.admit("op-2", "key-b").is_err());
    drop(store);
    assert!(SchedulerStore::open(&path).is_err());
    assert!(!path.exists());
    Ok(())
}

#[test]
fn duplicated_row_keys_are_not_collapsed_before_validation() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("scheduler.json");
    let mut store = SchedulerStore::open(&path)?;
    let row = store.admit("op-1", "key-a")?;
    drop(store);
    let row_json = serde_json::to_string(&row)?;
    std::fs::write(
        &path,
        format!(r#"{{"rows":{{"op-1":{row_json},"op-1":{row_json}}},"quarantined":[]}}"#),
    )?;
    assert!(SchedulerStore::open(&path).is_err());
    Ok(())
}

#[test]
fn predictable_legacy_temporary_symlink_does_not_overwrite_another_file() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("scheduler.json");
    let sentinel = tmp.path().join("sentinel.txt");
    std::fs::write(&sentinel, "unchanged")?;
    std::os::unix::fs::symlink(&sentinel, path.with_extension("tmp"))?;
    let mut store = SchedulerStore::open(&path)?;
    store.admit("op-1", "key-a")?;
    assert_eq!(std::fs::read_to_string(sentinel)?, "unchanged");
    Ok(())
}

#[test]
fn projection_cannot_reparent_a_child_or_make_a_self_edge() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let mut store = SchedulerStore::open(tmp.path().join("scheduler.json"))?;
    store.admit("parent-1", "key-1")?;
    store.admit("parent-2", "key-2")?;
    store.admit("child", "key-3")?;
    store.project_child("parent-1", "root", "child")?;
    assert!(store.project_child("parent-2", "root", "child").is_err());
    assert!(store.project_child("parent-1", "root", "parent-1").is_err());
    assert_eq!(
        store
            .get("child")
            .ok_or("child missing")?
            .parent_operation_id
            .as_deref(),
        Some("parent-1")
    );
    Ok(())
}
