use recursive_agent_ledger::{
    NormalChatSessionGateErrorV1 as Error, NormalChatSessionGateV1 as Gate,
};
use std::{
    fs::{self, File},
    os::unix::fs::PermissionsExt,
    time::{Duration, Instant},
};
const NAME: &str = ".normal-chat-runtime.lock";
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn bootstrap_and_require_existing_share_one_private_nonreentrant_guard() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = File::open(dir.path())?;
    assert!(
        matches!(Gate::acquire_existing(&root),Err(Error::Io(ref e)) if e.kind()==std::io::ErrorKind::NotFound)
    );
    assert!(!dir.path().join(NAME).exists());
    let held = Gate::acquire(&root)?;
    held.check(&File::open(dir.path())?)?;
    assert_eq!(
        fs::metadata(dir.path().join(NAME))?.permissions().mode() & 0o777,
        0o600
    );
    let start = Instant::now();
    assert!(matches!(Gate::acquire_existing(&root), Err(Error::Busy)));
    assert!(start.elapsed() < Duration::from_secs(1));
    held.unlock()?;
    // Immediate reacquisition requires explicit unlock: a parallel fork may
    // temporarily inherit a description even though CLOEXEC closes it at exec.
    // Deterministic unit witnesses cover the exact plain-drop/dup semantics.
    Gate::acquire_existing(&root)?.unlock()?;
    Gate::acquire_existing(&root)?.unlock()?;
    Ok(())
}
#[test]
fn independent_roots_are_independent_but_a_guard_never_matches_the_other_root() -> TestResult {
    let a = tempfile::tempdir()?;
    let b = tempfile::tempdir()?;
    let ar = File::open(a.path())?;
    let br = File::open(b.path())?;
    let held = Gate::acquire(&ar)?;
    let other = Gate::acquire(&br)?;
    assert!(matches!(held.check(&br), Err(Error::RootMismatch)));
    held.check(&ar)?;
    other.check(&br)?;
    Ok(())
}
#[test]
fn moving_the_exact_gate_inode_cannot_retarget_the_public_root_capability() -> TestResult {
    let a = tempfile::tempdir()?;
    let b = tempfile::tempdir()?;
    let ar = File::open(a.path())?;
    let br = File::open(b.path())?;
    let held = Gate::acquire(&ar)?;
    fs::rename(a.path().join(NAME), b.path().join(NAME))?;
    assert!(matches!(held.check(&br), Err(Error::RootMismatch)));
    assert!(held.check(&ar).is_err());
    assert!(!a.path().join(NAME).exists());
    held.unlock()?;
    Gate::acquire_existing(&br)?.unlock()?;
    Ok(())
}
#[test]
fn existing_unsafe_gate_material_is_rejected_without_repair() -> TestResult {
    for kind in ["mode", "hardlink", "symlink", "directory", "socket"] {
        let dir = tempfile::tempdir()?;
        let root = File::open(dir.path())?;
        let path = dir.path().join(NAME);
        let mut listener = None;
        match kind {
            "directory" => fs::create_dir(&path)?,
            "symlink" => std::os::unix::fs::symlink("missing-target", &path)?,
            "socket" => listener = Some(std::os::unix::net::UnixListener::bind(&path)?),
            _ => {
                fs::write(&path, b"preserve")?;
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(if kind == "mode" { 0o644 } else { 0o600 }),
                )?;
                if kind == "hardlink" {
                    fs::hard_link(&path, dir.path().join("alias"))?;
                }
            }
        }
        assert!(Gate::acquire_existing(&root).is_err(), "{kind}");
        if matches!(kind, "mode" | "hardlink") {
            assert_eq!(fs::read(&path)?, b"preserve");
        }
        if kind == "symlink" {
            assert_eq!(
                fs::read_link(&path)?,
                std::path::Path::new("missing-target")
            );
            assert!(!dir.path().join("missing-target").exists());
        }
        drop(listener);
    }
    Ok(())
}
#[test]
fn canonical_root_law_applies_before_creation_and_on_late_check() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = File::open(dir.path())?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o770))?;
    assert!(matches!(Gate::acquire(&root), Err(Error::Root(_))));
    assert!(!dir.path().join(NAME).exists());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
    let held = Gate::acquire(&root)?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o770))?;
    assert!(held.check(&root).is_err());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
    held.check(&root)?;
    Ok(())
}
#[test]
fn post_flock_fence_rejects_replacement_and_releases_detached_file_on_error() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = File::open(dir.path())?;
    Gate::acquire(&root)?.unlock()?;
    let mut changed = Ok(());
    let mut observed = false;
    let result = Gate::acquire_existing_with_observer(&root, || {
        observed = true;
        changed = (|| -> std::io::Result<()> {
            fs::rename(dir.path().join(NAME), dir.path().join("detached"))?;
            fs::write(dir.path().join(NAME), b"")?;
            fs::set_permissions(dir.path().join(NAME), fs::Permissions::from_mode(0o600))?;
            Ok(())
        })();
    });
    changed?;
    assert!(observed);
    assert!(matches!(result, Err(Error::LocatorChanged)));
    let detached = File::open(dir.path().join("detached"))?;
    rustix::fs::flock(
        &detached,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )?;
    rustix::fs::flock(&detached, rustix::fs::FlockOperation::Unlock)?;
    Gate::acquire_existing(&root)?.unlock()?;
    Ok(())
}
#[test]
fn gate_owner_does_not_take_the_ledger_directory_lock() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = File::open(dir.path())?;
    rustix::fs::flock(&root, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
    let gate = Gate::acquire(&root)?;
    gate.check(&root)?;
    gate.unlock()?;
    rustix::fs::flock(&root, rustix::fs::FlockOperation::Unlock)?;
    Ok(())
}
#[test]
fn a_missing_or_downgraded_held_locator_never_recreates_a_gate() -> TestResult {
    for mode in ["missing", "permissions", "hardlink"] {
        let dir = tempfile::tempdir()?;
        let root = File::open(dir.path())?;
        let gate = Gate::acquire(&root)?;
        let path = dir.path().join(NAME);
        match mode {
            "missing" => fs::remove_file(&path)?,
            "permissions" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?,
            _ => fs::hard_link(&path, dir.path().join("alias"))?,
        };
        assert!(gate.check(&root).is_err(), "{mode}");
        if mode == "missing" {
            assert!(!path.exists());
        }
        gate.unlock()?;
    }
    Ok(())
}
#[test]
fn gate_process_child() -> TestResult {
    let Some(root) = std::env::var_os("RA_GATE_TEST_ROOT") else {
        return Ok(());
    };
    let mode = std::env::var("RA_GATE_TEST_EXPECT")?;
    match (mode.as_str(), Gate::acquire_existing(&File::open(root)?)) {
        ("busy", Err(Error::Busy)) => println!("GATE_TEST_OBSERVATION:busy"),
        ("acquired", Ok(gate)) => {
            gate.unlock()?;
            println!("GATE_TEST_OBSERVATION:acquired");
        }
        _ => return Err("wrong independent-process gate result".into()),
    }
    Ok(())
}
fn peer(root: &std::path::Path, expected: &str) -> TestResult {
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", "gate_process_child", "--nocapture"])
        .env("RA_GATE_TEST_ROOT", root)
        .env("RA_GATE_TEST_EXPECT", expected)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let start = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if start.elapsed() > Duration::from_secs(5) {
            child.kill()?;
            child.wait()?;
            return Err("nonblocking peer exceeded 5s".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let out = child.wait_with_output()?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8(out.stdout)?.contains(&format!("GATE_TEST_OBSERVATION:{expected}")));
    Ok(())
}
#[test]
fn independent_process_observes_busy_then_release_on_the_same_gate() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = File::open(dir.path())?;
    let held = Gate::acquire(&root)?;
    peer(dir.path(), "busy")?;
    held.unlock()?;
    peer(dir.path(), "acquired")?;
    Ok(())
}
