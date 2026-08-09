//! Runner-private, one-shot Bubblewrap/Bash/seccomp dispatch engine.

use recursive_agent_contracts::ToolCallSpecV1;
use recursive_agent_policy::{
    AuthorizedContextEvidenceV1, DurablePermitStore, ExecutableAuthorityV1, PermitEvidenceStateV1,
    PermitEvidenceV1,
};
use recursive_agent_sandbox::{
    EnforcementOutcome, EnforcementRecord, OperationRootEvidence, SandboxError,
    SandboxFailureReason, SandboxMechanism, SandboxResult, SandboxSpec,
};
use serde::Serialize;
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::os::fd::{AsFd, AsRawFd};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
#[cfg(test)]
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const DEFAULT_LAUNCHER: &str = "/usr/bin/bwrap";
const BASH_TRAMPOLINE: &str = "/usr/bin/bash";
const FD_HYGIENE_SCRIPT: &str = r#"set -eu
preserved_fds=$1
bwrap_fd=$2
shift 2
for fd_path in /proc/self/fd/*; do
    fd_name=${fd_path##*/}
    case "$fd_name" in
        ''|*[!0-9]*) exit 126 ;;
    esac
    case ",$preserved_fds," in
        *,"$fd_name",*) ;;
        *)
            if [ "$fd_name" -gt 2 ]; then
                eval "exec ${fd_name}>&-"
            fi
            ;;
    esac
done
exec "/proc/self/fd/$bwrap_fd" "$@"
"#;
const OUTPUT_LIMIT_BYTES: usize = 64 * 1024;
const VERSION_OUTPUT_LIMIT: usize = 4 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
const RUNTIME_ROOTS: &[&str] = &["/usr", "/etc/ld.so.cache"];
const NETWORK_SYSCALLS: &[&str] = &[
    "socket",
    "socketpair",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "sendto",
    "sendmsg",
    "sendmmsg",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
    "shutdown",
    "getsockname",
    "getpeername",
    "setsockopt",
    "getsockopt",
    "socketcall",
    "io_uring_setup",
];

#[derive(Debug)]
pub(super) struct DispatchToken {
    evidence: PermitEvidenceV1,
    started: Instant,
    trusted_started_at: chrono::DateTime<chrono::Utc>,
    parent_store: DurablePermitStore,
    parent_monotonic_deadline: Instant,
}

impl DispatchToken {
    pub(super) fn from_consumed(
        evidence: PermitEvidenceV1,
        parent_store: DurablePermitStore,
        parent_monotonic_deadline: Instant,
    ) -> Result<Self, SandboxError> {
        evidence
            .validate()
            .map_err(|error| SandboxError::AuthorizationDenied(error.to_string()))?;
        let trusted_started_at = match &evidence.state {
            PermitEvidenceStateV1::Consumed { at } => *at,
            _ => {
                return Err(SandboxError::AuthorizationDenied(
                    "runner dispatch requires durable consumed permit evidence".into(),
                ));
            }
        };
        Ok(Self {
            evidence,
            started: Instant::now(),
            trusted_started_at,
            parent_store,
            parent_monotonic_deadline,
        })
    }

    fn binding(&self) -> &recursive_agent_policy::PermitBindingV1 {
        &self.evidence.binding
    }

    fn validate_call(&self, call: &ToolCallSpecV1) -> Result<(), SandboxError> {
        let binding = self.binding();
        if binding.tool != call.tool
            || binding.action_digest
                != recursive_agent_contracts::content_digest(call)
                    .map_err(|error| SandboxError::AuthorizationDenied(error.to_string()))?
            || binding.args_digest
                != recursive_agent_contracts::content_digest(&call.args)
                    .map_err(|error| SandboxError::AuthorizationDenied(error.to_string()))?
        {
            return Err(SandboxError::AuthorizationDenied(
                "consumed permit does not bind the dispatched call".into(),
            ));
        }
        Ok(())
    }

    fn validate_shell_dispatch(
        &self,
        call: &ToolCallSpecV1,
        read_roots: &[String],
        write_roots: &[String],
        network_allowed: bool,
        timeout_ms: u64,
        max_output_bytes: u64,
    ) -> Result<(), SandboxError> {
        self.validate_call(call)?;
        let binding = self.binding();
        if call.tool != "shell"
            || binding.effect.scope_name != "shell"
            || binding.effect.read_roots != read_roots
            || binding.effect.write_roots != write_roots
            || binding.effect.network_allowed != network_allowed
        {
            return Err(SandboxError::AuthorizationDenied(
                "consumed permit effect binding changed before dispatch".into(),
            ));
        }
        if network_allowed {
            return Err(SandboxError::NetworkForbidden);
        }
        if timeout_ms == 0
            || timeout_ms > binding.budget.max_wall_time_ms
            || max_output_bytes == 0
            || max_output_bytes > binding.budget.max_output_bytes
        {
            return Err(SandboxError::AuthorizationDenied(
                "dispatch exceeds consumed permit budget".into(),
            ));
        }
        Ok(())
    }

    fn remaining_wall_time(&self) -> Result<Duration, SandboxError> {
        let child_remaining = Duration::from_millis(self.binding().budget.max_wall_time_ms)
            .checked_sub(self.started.elapsed())
            .ok_or_else(|| {
                SandboxError::AuthorizationDenied("authorized wall-time budget is exhausted".into())
            })?;
        let parent_remaining = self
            .parent_monotonic_deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                SandboxError::AuthorizationDenied("parent monotonic authority is exhausted".into())
            })?;
        Ok(child_remaining.min(parent_remaining))
    }

    fn validate_parent(&self) -> Result<(), SandboxError> {
        if Instant::now() >= self.parent_monotonic_deadline {
            return Err(SandboxError::AuthorizationDenied(
                "parent monotonic authority is exhausted".into(),
            ));
        }
        let trusted_elapsed =
            chrono::TimeDelta::from_std(self.started.elapsed()).map_err(|_| {
                SandboxError::AuthorizationDenied("trusted dispatch time overflow".into())
            })?;
        let trusted_now = self
            .trusted_started_at
            .checked_add_signed(trusted_elapsed)
            .ok_or_else(|| {
                SandboxError::AuthorizationDenied("trusted dispatch deadline overflow".into())
            })?;
        self.parent_store
            .validate_parent_authority(&self.evidence.permit_id, trusted_now)
            .map(|_| ())
            .map_err(|error| SandboxError::AuthorizationDenied(error.to_string()))
    }

    fn evidence(&self) -> Result<AuthorizedContextEvidenceV1, SandboxError> {
        let binding = self.binding();
        Ok(AuthorizedContextEvidenceV1 {
            permit_id: self.evidence.permit_id.clone(),
            binding_digest: self.evidence.binding_digest.clone(),
            actor: binding.actor.clone(),
            run_id: binding.run_id.clone(),
            step_id: binding.step_id.clone(),
            tool: binding.tool.clone(),
            effect_digest: binding.effect_digest.clone(),
            budget: binding.budget.clone(),
            parent_permit_id: binding.parent_permit_id.clone(),
            executable_authority: self.evidence.executable_authority.clone(),
        })
    }
}

#[cfg(test)]
type PostSpawnTestHook = Box<dyn FnOnce(&DispatchToken)>;

#[cfg(test)]
thread_local! {
    static POST_SPAWN_TEST_HOOK: std::cell::RefCell<Option<PostSpawnTestHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn install_post_spawn_test_hook(hook: impl FnOnce(&DispatchToken) + 'static) {
    POST_SPAWN_TEST_HOOK.with(|slot| {
        slot.replace(Some(Box::new(hook)));
    });
}

#[cfg(test)]
fn run_post_spawn_test_hook(context: &DispatchToken) {
    POST_SPAWN_TEST_HOOK.with(|slot| {
        if let Some(hook) = slot.take() {
            hook(context);
        }
    });
}

#[derive(Debug)]
struct PreparedSpec {
    command: PinnedSource,
    read_roots: Vec<PinnedSource>,
    write_roots: Vec<PinnedSource>,
    runtime_roots: Vec<PinnedSource>,
    policy_digest: String,
}

#[derive(Debug)]
pub(super) struct PreparedDispatch {
    prepared: PreparedSpec,
    launcher: PinnedSource,
    bash: PinnedSource,
}

impl PreparedDispatch {
    pub(super) fn executable_authority(&self) -> Vec<ExecutableAuthorityV1> {
        [&self.launcher, &self.bash, &self.prepared.command]
            .into_iter()
            .filter_map(|source| source.executable_authority.clone())
            .collect()
    }
}

#[derive(Debug)]
struct PinnedSource {
    destination: PathBuf,
    file: File,
    identity: String,
    executable_authority: Option<ExecutableAuthorityV1>,
}

#[derive(Debug)]
struct BoundedOutput {
    bytes: Vec<u8>,
    dropped: u64,
}

#[derive(Debug)]
struct ChildOutput {
    status: ExitStatus,
    stdout: BoundedOutput,
    stderr: BoundedOutput,
    timed_out: bool,
    authority_terminated: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
enum SpawnedProcess {
    Posix(nix::unistd::Pid),
    #[cfg(test)]
    Std(Child),
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct SpawnedChild {
    process: SpawnedProcess,
    stdout: Option<File>,
    stderr: Option<File>,
}

#[cfg(target_os = "linux")]
impl SpawnedChild {
    fn from_posix(pid: nix::unistd::Pid, stdout: File, stderr: File) -> Self {
        Self {
            process: SpawnedProcess::Posix(pid),
            stdout: Some(stdout),
            stderr: Some(stderr),
        }
    }

    #[cfg(test)]
    fn from_std(child: Child) -> Self {
        Self {
            stdout: None,
            stderr: None,
            process: SpawnedProcess::Std(child),
        }
    }

    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        match &mut self.process {
            SpawnedProcess::Posix(pid) => posix_try_wait(*pid),
            #[cfg(test)]
            SpawnedProcess::Std(child) => child.try_wait(),
        }
    }

    fn kill(&mut self) -> std::io::Result<()> {
        match &mut self.process {
            SpawnedProcess::Posix(pid) => {
                // The child is its own process-group leader (set via
                // `posix_spawnattr_setpgroup(0)`), so a negative PID kills the
                // whole launcher tree (bubblewrap + bash trampoline + command)
                // rather than only the direct child.
                nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid.as_raw()),
                    nix::sys::signal::Signal::SIGKILL,
                )
                .or_else(|_| {
                    // Fall back to the direct PID if the group is gone.
                    nix::sys::signal::kill(*pid, nix::sys::signal::Signal::SIGKILL)
                })
                .map_err(nix_io_error)
            }
            #[cfg(test)]
            SpawnedProcess::Std(child) => child.kill(),
        }
    }

    fn wait(&mut self) -> std::io::Result<ExitStatus> {
        match &mut self.process {
            SpawnedProcess::Posix(pid) => posix_wait(*pid),
            #[cfg(test)]
            SpawnedProcess::Std(child) => child.wait(),
        }
    }
}

#[cfg(target_os = "linux")]
fn nix_io_error(error: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error as i32)
}

#[cfg(target_os = "linux")]
fn wait_status(status: nix::sys::wait::WaitStatus) -> Option<ExitStatus> {
    match status {
        nix::sys::wait::WaitStatus::Exited(_, code) => Some(ExitStatus::from_raw(code << 8)),
        nix::sys::wait::WaitStatus::Signaled(_, signal, core_dumped) => Some(ExitStatus::from_raw(
            signal as i32 | if core_dumped { 0x80 } else { 0 },
        )),
        nix::sys::wait::WaitStatus::StillAlive
        | nix::sys::wait::WaitStatus::Stopped(_, _)
        | nix::sys::wait::WaitStatus::Continued(_)
        | nix::sys::wait::WaitStatus::PtraceEvent(_, _, _)
        | nix::sys::wait::WaitStatus::PtraceSyscall(_) => None,
    }
}

#[cfg(target_os = "linux")]
fn posix_try_wait(pid: nix::unistd::Pid) -> std::io::Result<Option<ExitStatus>> {
    loop {
        match nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Ok(status) => return Ok(wait_status(status)),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(nix_io_error(error)),
        }
    }
}

#[cfg(target_os = "linux")]
fn posix_wait(pid: nix::unistd::Pid) -> std::io::Result<ExitStatus> {
    loop {
        let status = match nix::sys::wait::waitpid(pid, None) {
            Ok(status) => status,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(nix_io_error(error)),
        };
        if let Some(status) = wait_status(status) {
            return Ok(status);
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct ChildGuard {
    child: Option<SpawnedChild>,
}

#[cfg(target_os = "linux")]
impl ChildGuard {
    fn new(child: SpawnedChild) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> Result<&mut SpawnedChild, SandboxError> {
        self.child
            .as_mut()
            .ok_or_else(|| SandboxError::Wait("child is no longer supervised".into()))
    }

    fn disarm(&mut self) {
        self.child.take();
    }
}

#[cfg(target_os = "linux")]
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if !matches!(child.try_wait(), Ok(Some(_))) {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

pub(super) fn execute(
    spec: &SandboxSpec,
    call: &ToolCallSpecV1,
    context: DispatchToken,
    prepared: PreparedDispatch,
) -> Result<SandboxResult, SandboxError> {
    validate_timeout_and_command(spec)?;
    context
        .validate_shell_dispatch(
            call,
            &spec.allowed_read_paths,
            &spec.allowed_write_paths,
            spec.allow_network,
            spec.timeout_ms,
            spec.max_output_bytes,
        )
        .map_err(|error| SandboxError::AuthorizationDenied(error.to_string()))?;
    if spec.allow_network {
        return Err(SandboxError::NetworkForbidden);
    }
    if prepared.executable_authority() != context.evidence.executable_authority {
        return Err(SandboxError::AuthorizationDenied(
            "prepared executable bytes differ from consumed authority".into(),
        ));
    }
    context.validate_parent()?;
    let remaining = context
        .remaining_wall_time()
        .map_err(|error| SandboxError::AuthorizationDenied(error.to_string()))?;
    let remaining_ms = u64::try_from(remaining.as_millis())
        .map_err(|_| SandboxError::AuthorizationDenied("remaining wall time overflow".into()))?;
    if remaining_ms == 0 {
        return Err(SandboxError::AuthorizationDenied(
            "authorized wall time is exhausted".into(),
        ));
    }
    let mut effective = spec.clone();
    effective.timeout_ms = effective.timeout_ms.min(remaining_ms);
    execute_prepared_runtime(&effective, prepared, context)
}

fn execute_prepared_runtime(
    spec: &SandboxSpec,
    dispatch: PreparedDispatch,
    context: DispatchToken,
) -> Result<SandboxResult, SandboxError> {
    #[cfg(not(target_os = "linux"))]
    let launcher = Path::new(DEFAULT_LAUNCHER);
    let start = Instant::now();
    validate_timeout_and_command(spec)?;
    let authorization = context.evidence()?;
    let PreparedDispatch {
        prepared,
        launcher: pinned_launcher,
        bash,
    } = dispatch;
    #[cfg(not(target_os = "linux"))]
    {
        let enforcement = failed_record(
            &prepared,
            launcher,
            None,
            Vec::new(),
            SandboxFailureReason::UnsupportedPlatform,
            EnforcementOutcome::Unavailable,
        );
        return Err(SandboxError::UnsupportedPlatform {
            enforcement: Box::new(enforcement),
        });
    }
    #[cfg(target_os = "linux")]
    {
        execute_linux(
            spec,
            prepared,
            pinned_launcher,
            bash,
            start,
            authorization,
            context,
        )
    }
}

fn validate_timeout_and_command(spec: &SandboxSpec) -> Result<(), SandboxError> {
    if spec.command.trim().is_empty() {
        return Err(SandboxError::EmptyCommand);
    }
    if spec.timeout_ms == 0 {
        return Err(SandboxError::InvalidTimeout(0));
    }
    if spec.max_output_bytes == 0 {
        return Err(SandboxError::InvalidOutputLimit(0));
    }
    if spec.allow_network {
        return Err(SandboxError::NetworkForbidden);
    }
    Ok(())
}

pub(super) fn prepare_authority(spec: &SandboxSpec) -> Result<PreparedDispatch, SandboxError> {
    validate_timeout_and_command(spec)?;
    let prepared = prepare(spec)?;
    let launcher = pin_trusted_executable(Path::new(DEFAULT_LAUNCHER), "bubblewrap")?;
    let bash = pin_trusted_executable(Path::new(BASH_TRAMPOLINE), "bash_trampoline")?;
    Ok(PreparedDispatch {
        prepared,
        launcher,
        bash,
    })
}

fn prepare(spec: &SandboxSpec) -> Result<PreparedSpec, SandboxError> {
    let command = pin_source(Path::new(&spec.command), Some("command"))?;
    let read_roots = pin_roots(&spec.allowed_read_paths, false)?;
    let write_roots = pin_roots(&spec.allowed_write_paths, false)?;
    for root in &write_roots {
        if RUNTIME_ROOTS.iter().any(|runtime| {
            root.destination.starts_with(runtime)
                || Path::new(runtime).starts_with(&root.destination)
        }) {
            return Err(SandboxError::InvalidPath(
                root.destination.display().to_string(),
            ));
        }
    }
    let runtime_roots = RUNTIME_ROOTS
        .iter()
        .filter(|path| Path::new(path).exists())
        .map(|path| pin_source(Path::new(path), None))
        .collect::<Result<Vec<_>, _>>()?;
    let policy_digest = recursive_agent_contracts::content_digest(spec)
        .map_err(|error| SandboxError::Io(error.to_string()))?
        .to_string();
    Ok(PreparedSpec {
        command,
        read_roots,
        write_roots,
        runtime_roots,
        policy_digest,
    })
}

fn pin_roots(raw: &[String], executable: bool) -> Result<Vec<PinnedSource>, SandboxError> {
    let mut roots = BTreeSet::new();
    for value in raw {
        let path = PathBuf::from(value);
        if path == Path::new("/") || !roots.insert(path) {
            if value == "/" {
                return Err(SandboxError::InvalidPath(value.clone()));
            }
            continue;
        }
    }
    roots
        .iter()
        .map(|path| pin_source(path, executable.then_some("operation_root")))
        .collect()
}

#[cfg(target_os = "linux")]
fn pin_source(path: &Path, executable_role: Option<&str>) -> Result<PinnedSource, SandboxError> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};

    if !path.is_absolute() || path == Path::new("/") {
        return Err(SandboxError::InvalidPath(path.display().to_string()));
    }
    let start = rustix::fs::open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| SandboxError::Io(error.to_string()))?;
    let mut current = File::from(start);
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(value) => components.push(value),
            std::path::Component::CurDir
            | std::path::Component::ParentDir
            | std::path::Component::Prefix(_) => {
                return Err(SandboxError::InvalidPath(path.display().to_string()));
            }
        }
    }
    if components.is_empty() {
        return Err(SandboxError::InvalidPath(path.display().to_string()));
    }
    for (index, component) in components.iter().enumerate() {
        let name = component
            .to_str()
            .ok_or_else(|| SandboxError::InvalidPath("non-UTF-8 path".into()))?;
        let final_component = index + 1 == components.len();
        let mut flags = OFlags::NOFOLLOW | OFlags::CLOEXEC;
        if !final_component {
            flags |= OFlags::PATH | OFlags::DIRECTORY;
        } else if executable_role.is_none() {
            flags |= OFlags::PATH;
        } else {
            flags |= OFlags::RDONLY;
        }
        let fd = rustix::fs::openat2(
            current.as_fd(),
            name,
            flags,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|error| {
            let io = std::io::Error::from(error);
            if io.kind() == std::io::ErrorKind::NotFound {
                SandboxError::MissingAllowPath(path.display().to_string())
            } else {
                SandboxError::InvalidPath(path.display().to_string())
            }
        })?;
        current = File::from(fd);
    }
    let metadata = current
        .metadata()
        .map_err(|error| SandboxError::Io(error.to_string()))?;
    if !(metadata.is_file() || metadata.is_dir())
        || (executable_role.is_some() && (!metadata.is_file() || metadata.mode() & 0o111 == 0))
    {
        return Err(SandboxError::InvalidPath(path.display().to_string()));
    }
    #[derive(Serialize)]
    struct Identity<'a> {
        path: &'a str,
        device: u64,
        inode: u64,
        owner: u32,
        mode: u32,
        kind: &'a str,
    }
    let path_text = path_to_string(path)?;
    let identity = recursive_agent_contracts::content_digest(&Identity {
        path: &path_text,
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode(),
        kind: if metadata.is_dir() {
            "directory"
        } else {
            "regular_file"
        },
    })
    .map_err(|error| SandboxError::Io(error.to_string()))?
    .to_string();
    let executable_authority = if let Some(role) = executable_role {
        let filesystem =
            rustix::fs::fstatvfs(&current).map_err(|error| SandboxError::Io(error.to_string()))?;
        let read_only_filesystem = filesystem
            .f_flag
            .contains(rustix::fs::StatVfsMountFlags::RDONLY);
        if metadata.len() == 0
            || metadata.len() > MAX_EXECUTABLE_BYTES
            || metadata.mode() & 0o022 != 0
            || (metadata.uid() != 0 && !read_only_filesystem)
        {
            return Err(SandboxError::InvalidPath(path.display().to_string()));
        }
        let byte_digest = hash_executable(&mut current, metadata.len())?;
        Some(ExecutableAuthorityV1 {
            role: role.into(),
            path: path_text.clone(),
            descriptor_identity: identity.clone(),
            byte_digest,
            byte_length: metadata.len(),
            owner: metadata.uid(),
            mode: metadata.mode(),
            read_only_filesystem,
        })
    } else {
        None
    };
    Ok(PinnedSource {
        destination: path.to_path_buf(),
        file: current,
        identity,
        executable_authority,
    })
}

#[cfg(not(target_os = "linux"))]
fn pin_source(path: &Path, executable_role: Option<&str>) -> Result<PinnedSource, SandboxError> {
    if !path.is_absolute() {
        return Err(SandboxError::InvalidPath(path.display().to_string()));
    }
    let file = File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            SandboxError::MissingAllowPath(path.display().to_string())
        } else {
            SandboxError::InvalidPath(path.display().to_string())
        }
    })?;
    Ok(PinnedSource {
        destination: path.into(),
        file,
        identity: "unsupported-platform".into(),
        executable_authority: executable_role.map(|role| ExecutableAuthorityV1 {
            role: role.into(),
            path: path.display().to_string(),
            descriptor_identity: "unsupported-platform".into(),
            byte_digest: recursive_agent_contracts::ContentDigest::compute(b"unsupported"),
            byte_length: 0,
            owner: u32::MAX,
            mode: 0,
            read_only_filesystem: false,
        }),
    })
}

#[cfg(target_os = "linux")]
fn hash_executable(
    file: &mut File,
    expected_length: u64,
) -> Result<recursive_agent_contracts::ContentDigest, SandboxError> {
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|error| SandboxError::Io(error.to_string()))?;
    let mut hasher = blake3::Hasher::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| SandboxError::Io(error.to_string()))?;
        if count == 0 {
            break;
        }
        observed = observed.saturating_add(count as u64);
        if observed > MAX_EXECUTABLE_BYTES || observed > expected_length {
            return Err(SandboxError::InvalidPath(
                "executable exceeds byte bound".into(),
            ));
        }
        hasher.update(&buffer[..count]);
    }
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|error| SandboxError::Io(error.to_string()))?;
    if observed != expected_length {
        return Err(SandboxError::InvalidPath(
            "executable length changed".into(),
        ));
    }
    recursive_agent_contracts::ContentDigest::from_hex(hasher.finalize().to_hex().as_str())
        .map_err(|error| SandboxError::Io(format!("executable digest: {error:?}")))
}

#[cfg(target_os = "linux")]
fn execute_linux(
    spec: &SandboxSpec,
    mut prepared: PreparedSpec,
    bwrap: PinnedSource,
    init: PinnedSource,
    start: Instant,
    authorization: AuthorizedContextEvidenceV1,
    context: DispatchToken,
) -> Result<SandboxResult, SandboxError> {
    let launcher = Path::new(DEFAULT_LAUNCHER);
    let deadline = start + Duration::from_millis(spec.timeout_ms);
    context.validate_parent()?;
    for source in [&bwrap, &init, &prepared.command] {
        validate_source_still_named(source)?;
    }
    let version = probe_version(&init, &bwrap, deadline).map_err(|reason| {
        let outcome = if matches!(reason, SandboxFailureReason::LauncherMissing) {
            EnforcementOutcome::Unavailable
        } else {
            EnforcementOutcome::Failed
        };
        SandboxError::SetupFailed {
            enforcement: Box::new(failed_record(
                &prepared,
                launcher,
                None,
                vec!["--version".into()],
                reason,
                outcome,
            )),
        }
    })?;
    let seccomp = Some(
        build_network_seccomp().map_err(|_| SandboxError::SetupFailed {
            enforcement: Box::new(failed_record(
                &prepared,
                launcher,
                Some(version.clone()),
                Vec::new(),
                SandboxFailureReason::SeccompGenerationFailed,
                EnforcementOutcome::Failed,
            )),
        })?,
    );
    let nonce = setup_nonce()?;
    let argv = build_argv(spec, &prepared, &init, seccomp.as_ref(), &nonce)?;
    #[derive(Serialize)]
    struct EffectivePolicy<'a> {
        declared: &'a SandboxSpec,
        operation_roots: Vec<(&'a str, &'a str, &'a str)>,
        runtime_roots: Vec<(&'a str, &'a str)>,
        command_identity: &'a str,
        command_byte_digest: &'a recursive_agent_contracts::ContentDigest,
        bash_trampoline_identity: &'a str,
        bash_trampoline_byte_digest: &'a recursive_agent_contracts::ContentDigest,
        launcher_identity: &'a str,
        launcher_byte_digest: &'a recursive_agent_contracts::ContentDigest,
        network_mechanism: &'a str,
        seccomp_policy_digest: Option<&'a str>,
        authorization_binding_digest: &'a recursive_agent_contracts::ContentDigest,
        setup_proof_digest: recursive_agent_contracts::ContentDigest,
    }
    let read_root_material = prepared
        .read_roots
        .iter()
        .map(|root| {
            Ok((
                path_to_string(&root.destination)?,
                root.identity.as_str(),
                "read",
            ))
        })
        .collect::<Result<Vec<_>, SandboxError>>()?;
    let write_root_material = prepared
        .write_roots
        .iter()
        .map(|root| {
            Ok((
                path_to_string(&root.destination)?,
                root.identity.as_str(),
                "write",
            ))
        })
        .collect::<Result<Vec<_>, SandboxError>>()?;
    let runtime_root_material = prepared
        .runtime_roots
        .iter()
        .map(|root| Ok((path_to_string(&root.destination)?, root.identity.as_str())))
        .collect::<Result<Vec<_>, SandboxError>>()?;
    let command_authority = executable_authority(&prepared.command)?;
    let bash_authority = executable_authority(&init)?;
    let launcher_authority = executable_authority(&bwrap)?;
    prepared.policy_digest = recursive_agent_contracts::content_digest(&EffectivePolicy {
        declared: spec,
        operation_roots: read_root_material
            .iter()
            .chain(write_root_material.iter())
            .map(|(path, identity, mode)| (path.as_str(), *identity, *mode))
            .collect(),
        runtime_roots: runtime_root_material
            .iter()
            .map(|(path, identity)| (path.as_str(), *identity))
            .collect(),
        command_identity: &prepared.command.identity,
        command_byte_digest: &command_authority.byte_digest,
        bash_trampoline_identity: &init.identity,
        bash_trampoline_byte_digest: &bash_authority.byte_digest,
        launcher_identity: &bwrap.identity,
        launcher_byte_digest: &launcher_authority.byte_digest,
        network_mechanism: "shared_host_network_seccomp_socket_denial",
        seccomp_policy_digest: seccomp.as_ref().map(|policy| policy.digest.as_str()),
        authorization_binding_digest: &authorization.binding_digest,
        setup_proof_digest: recursive_agent_contracts::ContentDigest::compute(nonce.as_bytes()),
    })
    .map_err(|error| SandboxError::Io(error.to_string()))?
    .to_string();
    if Instant::now() >= deadline {
        return Err(SandboxError::SetupFailed {
            enforcement: Box::new(failed_record(
                &prepared,
                launcher,
                Some(version),
                argv,
                SandboxFailureReason::LauncherTimedOut,
                EnforcementOutcome::Failed,
            )),
        });
    }
    for source in prepared
        .runtime_roots
        .iter()
        .chain(prepared.read_roots.iter())
        .chain(prepared.write_roots.iter())
        .chain(std::iter::once(&prepared.command))
        .chain(std::iter::once(&init))
        .chain(std::iter::once(&bwrap))
    {
        validate_source_still_named(source).map_err(|_| SandboxError::SetupFailed {
            enforcement: Box::new(failed_record(
                &prepared,
                launcher,
                Some(version.clone()),
                argv.clone(),
                SandboxFailureReason::DescriptorTransferFailed,
                EnforcementOutcome::Failed,
            )),
        })?;
    }
    let mut preserved = prepared
        .runtime_roots
        .iter()
        .chain(prepared.read_roots.iter())
        .chain(prepared.write_roots.iter())
        .map(|source| &source.file)
        .collect::<Vec<_>>();
    preserved.push(&prepared.command.file);
    preserved.push(&init.file);
    if let Some(policy) = &seccomp {
        preserved.push(&policy.file);
    }
    let child = spawn_bash_trampoline(&init, &bwrap, &preserved, &argv).map_err(|_| {
        SandboxError::SetupFailed {
            enforcement: Box::new(failed_record(
                &prepared,
                launcher,
                Some(version.clone()),
                argv.clone(),
                SandboxFailureReason::LauncherSetupFailed,
                EnforcementOutcome::Failed,
            )),
        }
    })?;
    #[cfg(test)]
    run_post_spawn_test_hook(&context);
    let output_limit = usize::try_from(spec.max_output_bytes)
        .map_err(|_| SandboxError::InvalidOutputLimit(spec.max_output_bytes))?
        .min(OUTPUT_LIMIT_BYTES);
    let stderr_limit = output_limit
        .checked_add(nonce.len() + 1)
        .ok_or(SandboxError::InvalidOutputLimit(spec.max_output_bytes))?;
    context
        .validate_parent()
        .map_err(|_| SandboxError::SetupFailed {
            enforcement: Box::new(failed_record(
                &prepared,
                launcher,
                Some(version.clone()),
                argv.clone(),
                SandboxFailureReason::AuthorizationExpired,
                EnforcementOutcome::Failed,
            )),
        })?;
    let mut output = match supervise(child, deadline, output_limit, stderr_limit, Some(&context)) {
        Ok(output) => output,
        Err(_) => {
            return Err(SandboxError::SetupFailed {
                enforcement: Box::new(failed_record(
                    &prepared,
                    launcher,
                    Some(version),
                    argv,
                    SandboxFailureReason::LauncherTimedOut,
                    EnforcementOutcome::Failed,
                )),
            });
        }
    };
    if !consume_setup_proof(&mut output.stderr.bytes, &nonce) {
        return Err(SandboxError::SetupFailed {
            enforcement: Box::new(failed_record(
                &prepared,
                launcher,
                Some(version),
                argv,
                if output.timed_out {
                    SandboxFailureReason::LauncherTimedOut
                } else {
                    SandboxFailureReason::LauncherSetupFailed
                },
                EnforcementOutcome::Failed,
            )),
        });
    }
    enforce_retained_limit(&mut output.stderr, output_limit);
    let enforcement = EnforcementRecord {
        mechanism: SandboxMechanism::Bubblewrap,
        outcome: EnforcementOutcome::Enforced,
        policy_digest: prepared.policy_digest,
        launcher_path: DEFAULT_LAUNCHER.into(),
        launcher_version: Some(version),
        bash_trampoline_path: Some(BASH_TRAMPOLINE.into()),
        launcher_argv: argv,
        private_pid_namespace: true,
        parent_death_control: true,
        network_isolated: seccomp.is_some(),
        network_mechanism: Some("shared_host_network_seccomp_socket_denial".into()),
        seccomp_policy_digest: seccomp.as_ref().map(|policy| policy.digest.clone()),
        denied_network_syscalls: seccomp
            .as_ref()
            .map_or_else(Vec::new, |policy| policy.denied_syscalls.clone()),
        effective_operation_roots: prepared
            .read_roots
            .iter()
            .map(|root| OperationRootEvidence {
                path: root.destination.display().to_string(),
                descriptor_identity: root.identity.clone(),
                access_mode: "read".into(),
            })
            .chain(
                prepared
                    .write_roots
                    .iter()
                    .map(|root| OperationRootEvidence {
                        path: root.destination.display().to_string(),
                        descriptor_identity: root.identity.clone(),
                        access_mode: "write".into(),
                    }),
            )
            .collect(),
        effective_runtime_read_roots: prepared
            .runtime_roots
            .iter()
            .map(|root| root.destination.display().to_string())
            .collect(),
        trusted_executables: [&bwrap, &init, &prepared.command]
            .into_iter()
            .filter_map(|source| source.executable_authority.clone())
            .collect(),
        authorization: Some(authorization),
        setup_proof_digest: Some(
            recursive_agent_contracts::ContentDigest::compute(nonce.as_bytes()).to_string(),
        ),
        setup_proof_verified: true,
        reason_code: None,
    };
    let wall_time_ms = u64::try_from(start.elapsed().as_millis())
        .map_err(|_| SandboxError::Wait("wall-time observation overflow".into()))?;
    Ok(SandboxResult {
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout.bytes).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr.bytes).into_owned(),
        stdout_truncated: output.stdout.dropped > 0,
        stderr_truncated: output.stderr.dropped > 0,
        stdout_dropped_bytes: output.stdout.dropped,
        stderr_dropped_bytes: output.stderr.dropped,
        timed_out: output.timed_out,
        authority_terminated: output.authority_terminated,
        wall_time_ms,
        enforcement,
    })
}

#[cfg(target_os = "linux")]
fn probe_version(
    bash: &PinnedSource,
    launcher: &PinnedSource,
    deadline: Instant,
) -> Result<String, SandboxFailureReason> {
    let child = spawn_bash_trampoline(bash, launcher, &[], &["--version".into()])
        .map_err(|_| SandboxFailureReason::DescriptorTransferFailed)?;
    let output = supervise(
        child,
        deadline,
        VERSION_OUTPUT_LIMIT,
        VERSION_OUTPUT_LIMIT,
        None,
    )
    .map_err(|_| SandboxFailureReason::LauncherProbeFailed)?;
    if output.timed_out {
        return Err(SandboxFailureReason::LauncherTimedOut);
    }
    if !output.status.success() {
        return Err(SandboxFailureReason::LauncherProbeFailed);
    }
    let version = String::from_utf8_lossy(&output.stdout.bytes)
        .trim()
        .to_string();
    if version.is_empty() || version.chars().any(char::is_control) {
        return Err(SandboxFailureReason::LauncherProbeFailed);
    }
    Ok(version)
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct SeccompPolicy {
    file: File,
    digest: String,
    denied_syscalls: Vec<String>,
}

#[cfg(target_os = "linux")]
fn build_network_seccomp() -> Result<SeccompPolicy, SandboxError> {
    use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

    let mut filter = ScmpFilterContext::new(ScmpAction::Allow)
        .map_err(|error| SandboxError::Io(format!("seccomp context: {error}")))?;
    let mut denied_syscalls = Vec::new();
    for name in NETWORK_SYSCALLS {
        if let Ok(syscall) = ScmpSyscall::from_name(name) {
            filter
                .add_rule(ScmpAction::Errno(nix::libc::EPERM), syscall)
                .map_err(|error| SandboxError::Io(format!("seccomp rule: {error}")))?;
            denied_syscalls.push((*name).to_string());
        }
    }
    for required in [
        "socket",
        "socketpair",
        "connect",
        "bind",
        "listen",
        "accept",
        "sendto",
        "sendmsg",
        "recvfrom",
        "recvmsg",
        "shutdown",
        "io_uring_setup",
    ] {
        if ScmpSyscall::from_name(required).is_ok()
            && !denied_syscalls.iter().any(|name| name == required)
        {
            return Err(SandboxError::Io(format!(
                "required native network syscall missing from filter: {required}"
            )));
        }
    }
    let bytes = filter
        .export_bpf_mem()
        .map_err(|error| SandboxError::Io(format!("seccomp export: {error}")))?;
    let digest = recursive_agent_contracts::ContentDigest::compute(&bytes).to_string();
    let mut file = tempfile::tempfile().map_err(|error| SandboxError::Io(error.to_string()))?;
    file.write_all(&bytes)
        .map_err(|error| SandboxError::Io(error.to_string()))?;
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|error| SandboxError::Io(error.to_string()))?;
    Ok(SeccompPolicy {
        file,
        digest,
        denied_syscalls,
    })
}

#[cfg(target_os = "linux")]
fn pin_trusted_executable(path: &Path, role: &str) -> Result<PinnedSource, SandboxError> {
    pin_source(path, Some(role))
}

fn executable_authority(source: &PinnedSource) -> Result<&ExecutableAuthorityV1, SandboxError> {
    source.executable_authority.as_ref().ok_or_else(|| {
        SandboxError::AuthorizationDenied("executable byte authority is unavailable".into())
    })
}

#[cfg(target_os = "linux")]
fn validate_source_still_named(source: &PinnedSource) -> Result<(), SandboxError> {
    let role = source
        .executable_authority
        .as_ref()
        .map(|authority| authority.role.as_str());
    let reopened = pin_source(&source.destination, role)?;
    if reopened.identity != source.identity
        || reopened.executable_authority != source.executable_authority
    {
        return Err(SandboxError::InvalidPath(
            source.destination.display().to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn spawn_bash_trampoline(
    bash: &PinnedSource,
    launcher: &PinnedSource,
    preserved: &[&File],
    argv: &[String],
) -> Result<ChildGuard, SandboxError> {
    use nix::fcntl::OFlag;
    use nix::spawn::{self, PosixSpawnAttr, PosixSpawnFileActions};

    let (stdout_read, stdout_write) = nix::unistd::pipe2(OFlag::O_CLOEXEC)
        .map_err(|error| SandboxError::Io(error.to_string()))?;
    let (stderr_read, stderr_write) = nix::unistd::pipe2(OFlag::O_CLOEXEC)
        .map_err(|error| SandboxError::Io(error.to_string()))?;
    let null = rustix::fs::open(
        "/dev/null",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| SandboxError::Io(error.to_string()))?;
    let mut actions =
        PosixSpawnFileActions::init().map_err(|error| SandboxError::Io(error.to_string()))?;
    actions
        .add_dup2(null.as_raw_fd(), 0)
        .and_then(|()| actions.add_dup2(stdout_write.as_raw_fd(), 1))
        .and_then(|()| actions.add_dup2(stderr_write.as_raw_fd(), 2))
        .map_err(|error| SandboxError::Io(error.to_string()))?;

    let mut transferred = preserved
        .iter()
        .map(|file| file.as_raw_fd())
        .chain([bash.file.as_raw_fd(), launcher.file.as_raw_fd()])
        .collect::<Vec<_>>();
    transferred.sort_unstable();
    transferred.dedup();
    if transferred.iter().any(|fd| *fd <= 2) {
        return Err(SandboxError::Io(
            "authority descriptor collides with standard streams".into(),
        ));
    }
    for fd in &transferred {
        // Austin Group Issue 411 requires a same-FD adddup2 spawn action to
        // clear FD_CLOEXEC in the child even though raw dup2(fd, fd) would not.
        // The parent descriptor flags are never modified.
        actions
            .add_dup2(*fd, *fd)
            .map_err(|error| SandboxError::Io(error.to_string()))?;
    }

    let mut keep = preserved
        .iter()
        .map(|file| file.as_raw_fd())
        .chain(std::iter::once(launcher.file.as_raw_fd()))
        .collect::<Vec<_>>();
    keep.sort_unstable();
    keep.dedup();
    let preserved_literal = keep
        .iter()
        .map(i32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut raw_args = vec![
        "recursive-agent-trampoline".to_owned(),
        "--noprofile".to_owned(),
        "--norc".to_owned(),
        "-c".to_owned(),
        FD_HYGIENE_SCRIPT.to_owned(),
        "--".to_owned(),
        preserved_literal,
        launcher.file.as_raw_fd().to_string(),
    ];
    raw_args.extend(argv.iter().cloned());
    let args = raw_args
        .iter()
        .map(|value| CString::new(value.as_str()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SandboxError::Io("launcher argument contains NUL".into()))?;
    let env = ["PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"]
        .into_iter()
        .map(CString::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SandboxError::Io("fixed launcher environment contains NUL".into()))?;
    let path = CString::new(format!("/proc/self/fd/{}", bash.file.as_raw_fd()))
        .map_err(|_| SandboxError::Io("launcher path contains NUL".into()))?;
    let mut attributes =
        PosixSpawnAttr::init().map_err(|error| SandboxError::Io(error.to_string()))?;
    // Make the child a process-group leader so cancellation can reach the
    // whole launcher tree (bubblewrap + bash trampoline + command) with a
    // single killpg, rather than only the direct child PID.
    attributes
        .set_pgroup(nix::unistd::Pid::from_raw(0))
        .map_err(|error| SandboxError::Io(error.to_string()))?;
    let pid = spawn::posix_spawn(path.as_c_str(), &actions, &attributes, &args, &env)
        .map_err(|error| SandboxError::Io(error.to_string()))?;
    drop(stdout_write);
    drop(stderr_write);
    Ok(ChildGuard::new(SpawnedChild::from_posix(
        pid,
        File::from(stdout_read),
        File::from(stderr_read),
    )))
}

fn setup_nonce() -> Result<String, SandboxError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| SandboxError::Io(error.to_string()))?;
    Ok(format!("recursive-agent-setup-v2:{}", hex::encode(bytes)))
}

fn consume_setup_proof(bytes: &mut Vec<u8>, nonce: &str) -> bool {
    let proof = format!("{nonce}\n");
    if !bytes.starts_with(proof.as_bytes()) {
        return false;
    }
    bytes.drain(..proof.len());
    true
}

#[cfg(target_os = "linux")]
fn build_argv(
    spec: &SandboxSpec,
    prepared: &PreparedSpec,
    init: &PinnedSource,
    seccomp: Option<&SeccompPolicy>,
    nonce: &str,
) -> Result<Vec<String>, SandboxError> {
    let mut argv = vec![
        "--unshare-all".into(),
        "--share-net".into(),
        "--die-with-parent".into(),
        "--new-session".into(),
        "--clearenv".into(),
        "--setenv".into(),
        "PATH".into(),
        "/usr/bin".into(),
        "--tmpfs".into(),
        "/".into(),
        "--dir".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--symlink".into(),
        "usr/bin".into(),
        "/bin".into(),
        "--symlink".into(),
        "usr/lib".into(),
        "/lib".into(),
        "--symlink".into(),
        "usr/lib64".into(),
        "/lib64".into(),
    ];
    let mut parents = BTreeSet::new();
    for source in prepared
        .read_roots
        .iter()
        .chain(prepared.write_roots.iter())
        .chain(prepared.runtime_roots.iter())
        .chain(std::iter::once(&prepared.command))
        .chain(std::iter::once(init))
    {
        collect_mount_parents(&source.destination, &mut parents);
    }
    for parent in parents {
        if !matches!(
            parent.as_str(),
            "/" | "/usr" | "/bin" | "/lib" | "/lib64" | "/tmp" | "/proc" | "/dev" | "/etc"
        ) {
            argv.extend(["--dir".into(), parent]);
        }
    }
    for source in &prepared.runtime_roots {
        argv.extend([
            "--ro-bind-fd".into(),
            source.file.as_raw_fd().to_string(),
            path_to_string(&source.destination)?,
        ]);
    }
    for source in &prepared.read_roots {
        argv.extend([
            "--ro-bind-fd".into(),
            source.file.as_raw_fd().to_string(),
            path_to_string(&source.destination)?,
        ]);
    }
    for source in &prepared.write_roots {
        argv.extend([
            "--bind-fd".into(),
            source.file.as_raw_fd().to_string(),
            path_to_string(&source.destination)?,
        ]);
    }
    for source in [&prepared.command, init] {
        argv.extend([
            "--ro-bind-fd".into(),
            source.file.as_raw_fd().to_string(),
            path_to_string(&source.destination)?,
        ]);
    }
    if let Some(policy) = seccomp {
        argv.extend(["--seccomp".into(), policy.file.as_raw_fd().to_string()]);
    }
    argv.push("--".into());
    argv.push(path_to_string(&init.destination)?);
    argv.push("-c".into());
    argv.push("printf '%s\\n' \"$1\" >&2; shift; exec \"$@\"".into());
    argv.push("recursive-agent-sandbox-init".into());
    argv.push(nonce.into());
    argv.push(path_to_string(&prepared.command.destination)?);
    argv.extend(spec.args.clone());
    Ok(argv)
}

#[cfg(target_os = "linux")]
fn collect_mount_parents(path: &Path, output: &mut BTreeSet<String>) {
    let mut current = path.parent();
    while let Some(parent) = current {
        output.insert(parent.display().to_string());
        current = parent.parent();
    }
}

fn path_to_string(path: &Path) -> Result<String, SandboxError> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| SandboxError::InvalidPath("non-utf8 path".into()))
}

fn failed_record(
    prepared: &PreparedSpec,
    launcher: &Path,
    version: Option<String>,
    argv: Vec<String>,
    reason: SandboxFailureReason,
    outcome: EnforcementOutcome,
) -> EnforcementRecord {
    EnforcementRecord {
        mechanism: SandboxMechanism::Bubblewrap,
        outcome,
        policy_digest: prepared.policy_digest.clone(),
        launcher_path: launcher.display().to_string(),
        launcher_version: version,
        bash_trampoline_path: None,
        launcher_argv: argv,
        private_pid_namespace: false,
        parent_death_control: false,
        network_isolated: false,
        network_mechanism: None,
        seccomp_policy_digest: None,
        denied_network_syscalls: Vec::new(),
        effective_operation_roots: prepared
            .read_roots
            .iter()
            .map(|root| OperationRootEvidence {
                path: root.destination.display().to_string(),
                descriptor_identity: root.identity.clone(),
                access_mode: "read".into(),
            })
            .chain(
                prepared
                    .write_roots
                    .iter()
                    .map(|root| OperationRootEvidence {
                        path: root.destination.display().to_string(),
                        descriptor_identity: root.identity.clone(),
                        access_mode: "write".into(),
                    }),
            )
            .collect(),
        effective_runtime_read_roots: prepared
            .runtime_roots
            .iter()
            .map(|root| root.destination.display().to_string())
            .collect(),
        trusted_executables: Vec::new(),
        authorization: None,
        setup_proof_digest: None,
        setup_proof_verified: false,
        reason_code: Some(reason),
    }
}

fn supervise(
    mut child: ChildGuard,
    deadline: Instant,
    stdout_limit: usize,
    stderr_limit: usize,
    context: Option<&DispatchToken>,
) -> Result<ChildOutput, SandboxError> {
    let stdout = child
        .child_mut()?
        .stdout
        .take()
        .ok_or_else(|| SandboxError::Io("stdout pipe unavailable".into()))?;
    let stderr = child
        .child_mut()?
        .stderr
        .take()
        .ok_or_else(|| SandboxError::Io("stderr pipe unavailable".into()))?;
    let (stdout_sender, stdout_receiver) = mpsc::sync_channel(1);
    let (stderr_sender, stderr_receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = stdout_sender.send(read_bounded(stdout, stdout_limit));
    });
    std::thread::spawn(move || {
        let _ = stderr_sender.send(read_bounded(stderr, stderr_limit));
    });
    let mut timed_out = false;
    let mut authority_terminated = false;
    let status = loop {
        if context.is_some_and(|token| token.validate_parent().is_err()) {
            authority_terminated = true;
            match child.child_mut()?.kill() {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {}
                Err(error) => return Err(SandboxError::Wait(error.to_string())),
            }
            break child
                .child_mut()?
                .wait()
                .map_err(|error| SandboxError::Wait(error.to_string()))?;
        }
        match child
            .child_mut()?
            .try_wait()
            .map_err(|error| SandboxError::Wait(error.to_string()))?
        {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                timed_out = true;
                match child.child_mut()?.kill() {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {}
                    Err(error) => return Err(SandboxError::Wait(error.to_string())),
                }
                break child
                    .child_mut()?
                    .wait()
                    .map_err(|error| SandboxError::Wait(error.to_string()))?;
            }
            None => std::thread::sleep(Duration::from_millis(2)),
        }
    };
    child.disarm();
    let reader_grace = Duration::from_millis(100);
    let stdout = receive_output(stdout_receiver, reader_grace, "stdout")?;
    let stderr = receive_output(stderr_receiver, reader_grace, "stderr")?;
    Ok(ChildOutput {
        status,
        stdout,
        stderr,
        timed_out,
        authority_terminated,
    })
}

fn enforce_retained_limit(output: &mut BoundedOutput, limit: usize) {
    if output.bytes.len() > limit {
        let excess = output.bytes.len() - limit;
        output.bytes.truncate(limit);
        output.dropped = output.dropped.saturating_add(excess as u64);
    }
}

fn receive_output(
    receiver: mpsc::Receiver<std::io::Result<BoundedOutput>>,
    timeout: Duration,
    stream: &str,
) -> Result<BoundedOutput, SandboxError> {
    match receiver.recv_timeout(timeout) {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(error)) => Err(SandboxError::Io(error.to_string())),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(SandboxError::Io(format!(
            "{stream} reader did not close after launcher teardown"
        ))),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(SandboxError::Io(format!("{stream} reader disconnected")))
        }
    }
}

fn read_bounded(mut reader: impl Read, limit: usize) -> std::io::Result<BoundedOutput> {
    let mut retained = Vec::with_capacity(limit);
    let mut dropped = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let available = limit.saturating_sub(retained.len());
        let keep = available.min(read);
        retained.extend_from_slice(&buffer[..keep]);
        dropped = dropped.saturating_add((read - keep) as u64);
    }
    Ok(BoundedOutput {
        bytes: retained,
        dropped,
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn payload_marker_suffix_cannot_satisfy_setup_proof() {
        let nonce = "recursive-agent-setup-v2:nonce";
        let mut forged = format!("payload-first\n{nonce}\n").into_bytes();
        assert!(!consume_setup_proof(&mut forged, nonce));
    }

    #[test]
    fn fake_launcher_is_rejected_before_payload_dispatch() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let fake = root.path().join("fake-bwrap");
        std::fs::write(
            &fake,
            b"#!/usr/bin/bash\nprintf forged >&2\ntouch payload-ran\n",
        )?;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o700))?;
        assert!(pin_trusted_executable(&fake, "test").is_err());
        assert!(!root.path().join("payload-ran").exists());
        Ok(())
    }

    #[test]
    fn post_spawn_parent_revocation_kills_and_reaps_before_effect(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let output = tempfile::tempdir()?;
        let writable = tempfile::tempdir()?;
        let marker = writable.path().join("revoked-parent-effect");
        let revoked = Arc::new(AtomicBool::new(false));
        let hook_revoked = Arc::clone(&revoked);
        install_post_spawn_test_hook(move |context| {
            let parent = context.binding().parent_permit_id.as_ref();
            let did_revoke = parent.is_some_and(|permit_id| {
                context
                    .parent_store
                    .revoke(
                        permit_id,
                        recursive_agent_policy::PermitRevocationReasonV1::Operator,
                        chrono::Utc::now(),
                    )
                    .is_ok()
            });
            hook_revoked.store(did_revoke, Ordering::SeqCst);
        });
        let run = recursive_agent_contracts::RunSpecV1 {
            name: "post-spawn-parent-revocation".into(),
            steps: vec![recursive_agent_contracts::StepSpecV1 {
                name: "delayed-effect".into(),
                call: recursive_agent_contracts::ToolCallSpecV1 {
                    tool: "shell".into(),
                    args: serde_json::json!({
                        "command": "/usr/bin/bash",
                        "args": ["-c", format!("sleep 0.2; printf escaped > {}", marker.display())],
                        "allowed_read_paths": [],
                        "allowed_write_paths": [writable.path()],
                        "allow_network": false,
                        "timeout_ms": 2_000,
                        "max_output_bytes": 1_024
                    }),
                    frozen_clock: None,
                },
            }],
            frozen_clock: None,
            policy_version: "m0-2".into(),
        };

        let result = crate::run_spec_internal(
            &run,
            output.path(),
            &crate::SystemClock,
            &crate::NoopRunnerHook,
        );
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            revoked.load(Ordering::SeqCst),
            "post-spawn hook did not revoke parent"
        );
        assert!(result.is_err(), "revoked run returned a successful summary");
        assert!(
            !marker.exists(),
            "revoked post-spawn child completed its effect"
        );
        Ok(())
    }

    #[test]
    fn authority_descriptors_remain_cloexec_and_do_not_leak_to_siblings(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bash = pin_trusted_executable(Path::new(BASH_TRAMPOLINE), "bash_trampoline")?;
        let launcher = pin_trusted_executable(Path::new(DEFAULT_LAUNCHER), "bubblewrap")?;
        let bash_fd = bash.file.as_raw_fd();
        let launcher_fd = launcher.file.as_raw_fd();
        let child = spawn_bash_trampoline(&bash, &launcher, &[], &["--version".into()])?;

        for source in [&bash, &launcher] {
            let flags = rustix::io::fcntl_getfd(source.file.as_fd())?;
            assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
        }
        for _ in 0..32 {
            let probe = Command::new("/usr/bin/bash")
                .args([
                    "--noprofile",
                    "--norc",
                    "-c",
                    &format!(
                        "readlink /proc/self/fd/{bash_fd} 2>/dev/null; readlink /proc/self/fd/{launcher_fd} 2>/dev/null"
                    ),
                ])
                .env_clear()
                .output()?;
            let observed = String::from_utf8_lossy(&probe.stdout);
            assert!(!observed.contains(BASH_TRAMPOLINE));
            assert!(!observed.contains(DEFAULT_LAUNCHER));
        }
        let output = supervise(
            child,
            Instant::now() + Duration::from_secs(2),
            VERSION_OUTPUT_LIMIT,
            VERSION_OUTPUT_LIMIT,
            None,
        )?;
        assert!(output.status.success());
        Ok(())
    }

    #[test]
    fn child_guard_kills_and_reaps_on_early_return() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let marker = root.path().join("orphan-effect");
        let child = Command::new("/usr/bin/bash")
            .args([
                "--noprofile",
                "--norc",
                "-c",
                &format!("sleep 0.2; printf orphan > {}", marker.display()),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id())?);
        drop(ChildGuard::new(SpawnedChild::from_std(child)));
        std::thread::sleep(Duration::from_millis(300));

        assert!(!marker.exists(), "dropped child survived an early return");
        assert!(matches!(
            nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)),
            Err(nix::errno::Errno::ECHILD)
        ));
        Ok(())
    }
}
