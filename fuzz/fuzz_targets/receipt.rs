//! Fuzz the strict receipt JSON ingress. Malformed bytes must return a typed
//! parse/validation error and must never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _: Result<recursive_agent_contracts::ReceiptV1, _> = serde_json::from_str(text);
    }
});
