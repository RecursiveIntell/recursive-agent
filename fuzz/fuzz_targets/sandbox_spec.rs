//! Fuzz the strict sandbox-spec JSON ingress. Invalid input must remain a
//! rejection at the boundary and must never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _: Result<recursive_agent_sandbox::SandboxSpec, _> = serde_json::from_str(text);
    }
});
