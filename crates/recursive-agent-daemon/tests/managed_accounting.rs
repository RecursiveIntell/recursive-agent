#![allow(clippy::unwrap_used, clippy::expect_used)]

use llm_tool_runtime::{ToolRegistry, ToolRuntime};
use recursive_agent_daemon::{bind_private_socket, serve};
use recursive_agent_runner::{
    Clock, ManagedAdmissionDomain, ManagedAdmissionRequestV1, ManagedBudgetV1, RuntimeDependencies,
    RuntimeLedgerDependencyV1, RuntimePolicyDependencyV1, RuntimeProviderDependencyV1,
    RuntimeSandboxDependencyV1, RuntimeService, RuntimeStoreDependencyV1,
};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::UNIX_EPOCH
    }

    fn monotonic_now(&self) -> Duration {
        Duration::ZERO
    }
}

fn service(
    root: &std::path::Path,
    owner: ManagedAdmissionDomain,
) -> Result<RuntimeService, Box<dyn std::error::Error>> {
    let dependencies = RuntimeDependencies::builder()
        .policy(RuntimePolicyDependencyV1::Native)
        .sandbox(RuntimeSandboxDependencyV1::Native)
        .tool_runtime(Arc::new(ToolRuntime::new(ToolRegistry::new())))
        .provider(RuntimeProviderDependencyV1::Disabled)
        .ledger(RuntimeLedgerDependencyV1::Native)
        .clock(Arc::new(FixedClock))
        .store(RuntimeStoreDependencyV1::Native)
        .output_root(root)
        .build()?;
    Ok(RuntimeService::new_with_managed_admission(
        dependencies,
        owner,
    ))
}

fn wait_until(runtime: &RuntimeService, expected_connections: usize) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let snapshot = runtime.managed_admission_snapshot().unwrap();
        if snapshot.open_ipc_connections == expected_connections {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "connection accounting timed out: {snapshot:?}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn kern_10_real_daemon_connections_are_independent_from_managed_leaves(
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("runs");
    std::fs::create_dir(&root)?;
    let owner = ManagedAdmissionDomain::from_global(10);
    let runtime = Arc::new(service(&root, owner.clone())?);
    let (listener, socket_path) = bind_private_socket(tmp.path(), "accounting.sock")?;
    let server_runtime = Arc::clone(&runtime);
    std::thread::spawn(move || {
        let _ = serve(listener, server_runtime, 4);
    });

    let mut clients = Vec::new();
    for _ in 0..4 {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match UnixStream::connect(&socket_path) {
                Ok(stream) => {
                    clients.push(stream);
                    break;
                }
                Err(error) => {
                    assert!(
                        Instant::now() < deadline,
                        "daemon connection failed: {error}"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }
    wait_until(&runtime, 4);

    let mut reservations = Vec::new();
    for index in 0..10 {
        reservations.push(owner.reserve(ManagedAdmissionRequestV1::provider(
            format!("physical-leaf-{index}"),
            "model:fixture",
            ManagedBudgetV1::default(),
        ))?);
    }
    let snapshot = runtime.managed_admission_snapshot()?;
    assert_eq!(snapshot.open_ipc_connections, 4);
    assert_eq!(snapshot.active.len(), 10);
    assert_ne!(snapshot.open_ipc_connections, snapshot.active.len());

    drop(reservations);
    drop(clients);
    wait_until(&runtime, 0);
    Ok(())
}
