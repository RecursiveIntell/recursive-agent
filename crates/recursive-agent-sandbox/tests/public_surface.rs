use recursive_agent_sandbox::{validate_plan, SandboxSpec};

#[test]
fn downstream_public_api_is_plan_only() {
    let plan = SandboxSpec {
        command: "/usr/bin/printf".into(),
        args: vec!["plan-only".into()],
        allowed_read_paths: Vec::new(),
        allowed_write_paths: Vec::new(),
        allow_network: false,
        timeout_ms: 1_000,
        max_output_bytes: 1_024,
    };
    assert!(validate_plan(&plan).is_ok());
}
