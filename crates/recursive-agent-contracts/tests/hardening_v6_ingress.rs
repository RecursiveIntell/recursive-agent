use recursive_agent_contracts::{parse_run_spec_bytes, RunSpecIngressError};

fn base() -> serde_json::Value {
    serde_json::json!({
        "name": "bounded-run",
        "policy_version": "m0-2",
        "steps": [{
            "name": "echo-one",
            "call": {"tool": "echo", "args": {"text": "ok"}}
        }]
    })
}

fn parse(
    value: &serde_json::Value,
) -> Result<recursive_agent_contracts::RunSpecV1, RunSpecIngressError> {
    let bytes = serde_json::to_vec(value).map_err(|_| RunSpecIngressError::Malformed)?;
    parse_run_spec_bytes(&bytes)
}

#[test]
fn valid_multi_step_sibling_objects_reuse_field_names() -> Result<(), Box<dyn std::error::Error>> {
    let value = serde_json::json!({
        "name": "two-valid-steps",
        "policy_version": "m0-2",
        "steps": [
            {"name": "one", "call": {"tool": "echo", "args": {"text": "first"}}},
            {"name": "two", "call": {"tool": "echo", "args": {"text": "second"}}}
        ]
    });
    let parsed = parse(&value)?;
    assert_eq!(parsed.steps.len(), 2);
    Ok(())
}

#[test]
fn empty_and_duplicate_step_names_are_rejected() {
    let mut empty = base();
    empty["steps"] = serde_json::json!([]);
    assert!(parse(&empty).is_err());

    let mut duplicate = base();
    duplicate["steps"] = serde_json::json!([
        {"name": "same", "call": {"tool": "echo", "args": {"text": "one"}}},
        {"name": "same", "call": {"tool": "echo", "args": {"text": "two"}}}
    ]);
    assert!(parse(&duplicate).is_err());
}

#[test]
fn identifiers_and_text_have_explicit_byte_ceilings() -> Result<(), Box<dyn std::error::Error>> {
    for (pointer, oversized) in [
        ("/name", "n".repeat(257)),
        ("/policy_version", "p".repeat(65)),
        ("/steps/0/name", "s".repeat(257)),
        ("/steps/0/call/tool", "t".repeat(65)),
        ("/steps/0/call/args/text", "x".repeat(65_537)),
    ] {
        let mut value = base();
        let Some(slot) = value.pointer_mut(pointer) else {
            return Err(format!("test pointer is unavailable: {pointer}").into());
        };
        *slot = oversized.into();
        assert!(parse(&value).is_err(), "accepted oversized field {pointer}");
    }
    let mut control = base();
    control["name"] = "bad\nname".into();
    assert!(parse(&control).is_err());
    Ok(())
}

#[test]
fn shell_collections_paths_and_budgets_have_explicit_ceilings() {
    let shell = || {
        serde_json::json!({
            "name": "shell-bounds",
            "policy_version": "m0-2",
            "steps": [{"name": "shell", "call": {"tool": "shell", "args": {
                "command": "/usr/bin/printf",
                "args": ["ok"],
                "allowed_read_paths": [],
                "allowed_write_paths": [],
                "allow_network": false,
                "timeout_ms": 1000,
                "max_output_bytes": 1024
            }}}]
        })
    };

    let mut value = shell();
    value["steps"][0]["call"]["args"]["args"] =
        serde_json::Value::Array((0..65).map(|_| "x".into()).collect());
    assert!(parse(&value).is_err());

    let mut value = shell();
    value["steps"][0]["call"]["args"]["args"][0] = "x".repeat(16_385).into();
    assert!(parse(&value).is_err());

    let mut value = shell();
    value["steps"][0]["call"]["args"]["allowed_read_paths"] = serde_json::Value::Array(
        (0..33)
            .map(|index| format!("/tmp/r{index}").into())
            .collect(),
    );
    assert!(parse(&value).is_err());

    let mut value = shell();
    value["steps"][0]["call"]["args"]["allowed_write_paths"] = serde_json::Value::Array(
        (0..33)
            .map(|index| format!("/tmp/w{index}").into())
            .collect(),
    );
    assert!(parse(&value).is_err());

    for (field, invalid) in [
        ("command", serde_json::json!("relative-command")),
        (
            "command",
            serde_json::json!(format!("/{}", "x".repeat(4097))),
        ),
        ("timeout_ms", serde_json::json!(300_001)),
        ("max_output_bytes", serde_json::json!(65_537)),
    ] {
        let mut value = shell();
        value["steps"][0]["call"]["args"][field] = invalid;
        assert!(
            parse(&value).is_err(),
            "accepted invalid shell field {field}"
        );
    }
}

#[test]
fn time_label_has_an_explicit_byte_ceiling() {
    let value = serde_json::json!({
        "name": "time-bounds",
        "policy_version": "m0-2",
        "steps": [{
            "name": "time",
            "call": {"tool": "time_now", "args": {"label": "x".repeat(257)}}
        }]
    });
    assert!(parse(&value).is_err());
}
