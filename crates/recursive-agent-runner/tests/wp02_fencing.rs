use std::sync::atomic::{AtomicUsize, Ordering};

use recursive_agent_runner::{LeaseGrantV1, SchedulerStore, SchedulerStoreError};

#[test]
fn kern_05_transferred_generation_fences_old_worker_effects_and_publication(
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let mut owner = SchedulerStore::open(tmp.path().join("scheduler.json"))?;
    owner.admit("op-1", "digest-a")?;

    let first = owner.acquire_lease("op-1", "worker-a")?;
    let started_effects = AtomicUsize::new(0);
    let published = AtomicUsize::new(0);

    owner.authorize_effect_start(&first)?;
    started_effects.fetch_add(1, Ordering::SeqCst);

    // The original worker is now paused with one already-started, potentially
    // ambiguous effect. The owner explicitly transfers the generation.
    let second = owner.transfer_lease(&first, "worker-b")?;
    assert!(second.generation() > first.generation());

    let stale_effect = owner.authorize_effect_start(&first);
    assert!(matches!(
        stale_effect,
        Err(SchedulerStoreError::LeaseFenced { .. })
    ));
    let stale_publish = owner.authorize_publish(&first);
    assert!(matches!(
        stale_publish,
        Err(SchedulerStoreError::LeaseFenced { .. })
    ));
    assert_eq!(started_effects.load(Ordering::SeqCst), 1);
    assert_eq!(published.load(Ordering::SeqCst), 0);

    owner.authorize_effect_start(&second)?;
    started_effects.fetch_add(1, Ordering::SeqCst);
    owner.authorize_publish(&second)?;
    published.fetch_add(1, Ordering::SeqCst);

    assert_eq!(started_effects.load(Ordering::SeqCst), 2);
    assert_eq!(published.load(Ordering::SeqCst), 1);
    assert_eq!(
        owner.get("op-1").ok_or("row missing")?.lease_generation,
        second.generation()
    );
    Ok(())
}

#[test]
fn kern_05_cancel_and_terminal_state_fence_the_current_generation(
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let mut owner = SchedulerStore::open(tmp.path().join("scheduler.json"))?;
    owner.admit("op-cancel", "digest-cancel")?;
    let cancel_grant: LeaseGrantV1 = owner.acquire_lease("op-cancel", "worker")?;
    owner.request_cancel("op-cancel")?;
    assert!(matches!(
        owner.authorize_effect_start(&cancel_grant),
        Err(SchedulerStoreError::LeaseFenced { .. })
    ));

    owner.admit("op-terminal", "digest-terminal")?;
    let terminal_grant = owner.acquire_lease("op-terminal", "worker")?;
    owner.set_terminal("op-terminal")?;
    assert!(matches!(
        owner.authorize_publish(&terminal_grant),
        Err(SchedulerStoreError::LeaseFenced { .. })
    ));
    Ok(())
}
