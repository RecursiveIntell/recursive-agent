//! Task 5.1 — durable scheduler store restart recovery across real process
//! boundaries.
//!
//! A child process admits operations, acquires leases, requests cancellation,
//! and advances cursors against a durable projection, then aborts. The parent
//! reopens the store and asserts the projection recovered exactly — no lost
//! rows, no silent duplicate admission.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use recursive_agent_runner::{ProjectedState, SchedulerStore};

#[test]
fn scheduler_projection_survives_process_restart_without_duplication(
) -> Result<(), Box<dyn std::error::Error>> {
    // Child branch: mutate the store then abort (real process boundary).
    if std::env::var_os("RA_SCHED_RESTART_CHILD").is_some() {
        let path = std::path::PathBuf::from(std::env::var("RA_SCHED_STORE")?);
        let mut store = SchedulerStore::open(&path)?;
        store.admit("op-1", "digest-a")?;
        store.admit("op-2", "digest-b")?;
        store.acquire_lease("op-1", "worker-a")?;
        store.acquire_lease("op-2", "worker-a")?;
        store.request_cancel("op-2")?;
        store.advance_cursor("op-1", 3)?;
        store.advance_cursor("op-2", 5)?;
        // op-3 is only admitted (never leased) to prove submitted rows persist.
        store.admit("op-3", "digest-c")?;
        std::process::abort();
    }

    let tmp = tempfile::tempdir()?;
    let store_path = tmp.path().join("scheduler.json");
    let executable = std::env::current_exe()?;

    let mut child = std::process::Command::new(&executable)
        .args([
            "--exact",
            "scheduler_projection_survives_process_restart_without_duplication",
            "--nocapture",
        ])
        .env("RA_SCHED_RESTART_CHILD", "1")
        .env("RA_SCHED_STORE", &store_path)
        .spawn()?;
    let status = child.wait()?;
    assert!(!status.success(), "child must have aborted");

    // Reopen in the parent and assert the projection recovered exactly.
    let store = SchedulerStore::open(&store_path)?;
    let live = store.live_rows();
    assert_eq!(live.len(), 3, "all admitted rows must survive");

    let op1 = store.get("op-1").expect("op-1 present");
    assert_eq!(op1.state, ProjectedState::Authorized);
    assert_eq!(op1.lease_holder.as_deref(), Some("worker-a"));
    assert_eq!(op1.projection_cursor, 3);

    let op2 = store.get("op-2").expect("op-2 present");
    assert!(op2.cancel_requested);
    assert_eq!(op2.state, ProjectedState::Cancelling);
    assert_eq!(op2.projection_cursor, 5);

    let op3 = store.get("op-3").expect("op-3 present");
    assert_eq!(op3.state, ProjectedState::Submitted);

    // Exact duplicate admission after restart must not duplicate the row.
    let mut store = store;
    store.admit("op-1", "digest-a")?;
    assert_eq!(
        store.live_rows().len(),
        3,
        "no silent duplicate after restart"
    );
    Ok(())
}
