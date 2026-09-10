from pathlib import Path

path = Path("crates/recursive-agent-runner/src/sandbox_engine.rs")
text = path.read_text()

old_const = "const VERSION_OUTPUT_LIMIT: usize = 4 * 1024;\nconst MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;"
new_const = "const VERSION_OUTPUT_LIMIT: usize = 4 * 1024;\nconst MAX_SECCOMP_BPF_BYTES: u64 = 64 * 1024;\nconst MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;"
if text.count(old_const) != 1:
    raise SystemExit("expected seccomp constant anchor exactly once")
text = text.replace(old_const, new_const)

old = """    let bytes = filter
        .export_bpf_mem()
        .map_err(|error| SandboxError::Io(format!(\"seccomp export: {error}\")))?;
    let digest = recursive_agent_contracts::ContentDigest::compute(&bytes).to_string();
    let mut file = tempfile::tempfile().map_err(|error| SandboxError::Io(error.to_string()))?;
    file.write_all(&bytes)
        .map_err(|error| SandboxError::Io(error.to_string()))?;
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|error| SandboxError::Io(error.to_string()))?;
"""
new = """    let mut file = tempfile::tempfile().map_err(|error| SandboxError::Io(error.to_string()))?;
    filter
        .export_bpf(&file)
        .map_err(|error| SandboxError::Io(format!(\"seccomp export: {error}\")))?;
    let byte_length = file
        .metadata()
        .map_err(|error| SandboxError::Io(error.to_string()))?
        .len();
    if byte_length == 0 || byte_length > MAX_SECCOMP_BPF_BYTES {
        return Err(SandboxError::Io(format!(
            \"seccomp export length out of bounds: {byte_length}\"
        )));
    }
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|error| SandboxError::Io(error.to_string()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| SandboxError::Io(error.to_string()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != byte_length {
        return Err(SandboxError::Io(
            \"seccomp export length changed while reading\".into(),
        ));
    }
    let digest = recursive_agent_contracts::ContentDigest::compute(&bytes).to_string();
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|error| SandboxError::Io(error.to_string()))?;
"""
if text.count(old) != 1:
    raise SystemExit("expected export_bpf_mem block exactly once")
path.write_text(text.replace(old, new))
