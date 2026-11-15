//! Explicit read-only CLI composition over the canonical native family verifier.
//! This never relaxes ordinary verification or creates a missing gate/store.
use recursive_agent_contracts::{
    content_digest, jcs_canonical, parse_strict_json_value, ReceiptV1,
};
use recursive_agent_ledger::{
    verify_degraded_normal_chat_session_from_runtime_root_fd, ChainVerification,
    NormalChatSessionGateV1,
};
use rustix::fs::{Mode, OFlags};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

type Error = Box<dyn std::error::Error>;

pub(crate) struct NativeVerificationSummary {
    pub verification: ChainVerification,
    pub attempts: usize,
    pub unknown_attempts: usize,
}

fn directory(path: &Path) -> Result<File, Error> {
    Ok(File::from(rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}

fn unchanged(path: &Path, pinned: &File) -> Result<(), Error> {
    let observed = directory(path)?.metadata()?;
    let original = pinned.metadata()?;
    if (observed.dev(), observed.ino()) != (original.dev(), original.ino()) {
        return Err("native verification locator changed".into());
    }
    Ok(())
}

pub(crate) fn verify_native_family(
    run: &Path,
    runtime_root: &Path,
) -> Result<NativeVerificationSummary, Error> {
    let runtime_path = runtime_root.canonicalize()?;
    let run_path = run.canonicalize()?;
    if run_path.parent() != Some(runtime_path.as_path()) {
        return Err("run is not an immediate child of the explicit runtime root".into());
    }
    let output = directory(&runtime_path)?;
    let parent = directory(&run_path)?;
    let receipts = File::from(rustix::fs::openat(
        &parent,
        "receipts.ndjson",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    if !receipts.metadata()?.is_file() {
        return Err("native verification receipt input is not regular".into());
    }
    // This bounded first-row decode selects an ID only. It proves nothing;
    // the native owner below reopens and verifies the complete source family.
    let mut prefix = Vec::new();
    receipts.take(1_048_577).read_to_end(&mut prefix)?;
    let end = prefix
        .iter()
        .position(|b| *b == b'\n')
        .ok_or("bounded canonical first receipt absent")?;
    let bytes = &prefix[..end];
    let value = parse_strict_json_value(bytes)?;
    let first: ReceiptV1 = serde_json::from_value(value)?;
    if jcs_canonical(&first)? != bytes {
        return Err("first receipt is not closed canonical JSON".into());
    }
    let key = content_digest(&first.run_id)?.to_string();
    if run_path.file_name().and_then(|v| v.to_str()) != Some(key.as_str()) {
        return Err("run directory does not match owner-derived run ID".into());
    }
    let gate = NormalChatSessionGateV1::acquire_existing(&parent)?;
    let result = (|| -> Result<NativeVerificationSummary, Error> {
        let proof = verify_degraded_normal_chat_session_from_runtime_root_fd(
            &output,
            &first.run_id,
            &gate,
        )?;
        proof.recheck()?;
        unchanged(&runtime_path, &output)?;
        unchanged(&run_path, &parent)?;
        gate.check(&parent)?;
        Ok(NativeVerificationSummary {
            verification: proof.verification().clone(),
            attempts: proof.child_count(),
            unknown_attempts: proof.unknown_child_count(),
        })
    })();
    let unlock = gate.unlock();
    match (result, unlock) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
    }
}
