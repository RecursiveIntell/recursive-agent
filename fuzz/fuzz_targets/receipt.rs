//! Fuzz targets for recursive-agent crates.
//! Run with: cargo fuzz run <target> -- -max_total_time=60

// Contracts: fuzz ReceiptV1 JSON parsing
pub mod receipt_deserialize {
    use libfuzzer_sys::fuzz_target;
    fuzz_target!(|data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            let _: Result<recursive_agent_contracts::ReceiptV1, _> = serde_json::from_str(s);
        }
    });
}

// Contracts: fuzz lineage validation
pub mod lineage_validate {
    // Placeholder — requires structured input generation
}

// Sandbox: fuzz SandboxSpec deserialization
pub mod sandbox_spec {
    use libfuzzer_sys::fuzz_target;
    fuzz_target!(|data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            let _: Result<recursive_agent_sandbox::SandboxSpec, _> = serde_json::from_str(s);
        }
    });
}
