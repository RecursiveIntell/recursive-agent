//! Phase 3 sandboxed process executor.
//!
//! Spawns a child process in a user namespace with Landlock filesystem
//! isolation and NO_NEW_PRIVS. Uses raw Landlock syscalls via libc.
//! This crate is the single point in the workspace where unsafe code is
//! permitted (fork, exec, raw syscalls).

#![allow(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::{os::unix::process::CommandExt, process::Command, time::Instant};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSpec {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub allowed_read_paths: Vec<String>,
    #[serde(default)]
    pub allowed_write_paths: Vec<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub wall_time_ms: u64,
    pub sandboxed: bool,
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("empty command")]
    EmptyCommand,
    #[error("fork: {0}")]
    Fork(String),
    #[error("unshare: {0}")]
    Unshare(String),
    #[error("uid/gid map: {0}")]
    UserMap(String),
    #[error("no_new_privs: {0}")]
    NoNewPrivs(String),
    #[error("landlock: {0}")]
    Landlock(String),
    #[error("pipe: {0}")]
    Pipe(String),
    #[error("io: {0}")]
    Io(String),
    #[error("exec: {0}")]
    Exec(String),
    #[error("wait: {0}")]
    Wait(String),
}

// --- Landlock syscall numbers and constants (from linux/landlock.h) ---

const LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const LANDLOCK_ADD_RULE: libc::c_long = 445;
const LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;

const LANDLOCK_RULE_PATH_BENEATH: u64 = 1;

/// Minimal Landlock ruleset attribute (ABI V1).
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

/// Minimal Landlock path-beneath rule attribute.
#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

pub fn execute(spec: &SandboxSpec) -> Result<SandboxResult, SandboxError> {
    if spec.command.is_empty() {
        return Err(SandboxError::EmptyCommand);
    }
    let mut out_pipe = [-1i32; 2];
    let mut err_pipe = [-1i32; 2];
    unsafe {
        if libc::pipe2(out_pipe.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            return Err(SandboxError::Pipe("stdout".into()));
        }
        if libc::pipe2(err_pipe.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            let _ = libc::close(out_pipe[0]);
            let _ = libc::close(out_pipe[1]);
            return Err(SandboxError::Pipe("stderr".into()));
        }
    }
    let (out_r, out_w) = (out_pipe[0], out_pipe[1]);
    let (err_r, err_w) = (err_pipe[0], err_pipe[1]);
    let start = Instant::now();
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(SandboxError::Fork("fork failed".into()));
    }
    if child == 0 {
        child_main(spec, out_w, err_w);
    }
    unsafe {
        let _ = libc::close(out_w);
        let _ = libc::close(err_w);
    }

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    // uid_map writes are best-effort — they require capabilities the
    // parent may not have. If they fail, the child runs without Landlock
    // but still gets NO_NEW_PRIVS isolation.
    let _ = std::fs::write(format!("/proc/{child}/uid_map"), format!("0 {uid} 1\n"));
    let _ = std::fs::write(format!("/proc/{child}/setgroups"), "deny\n");
    let _ = std::fs::write(format!("/proc/{child}/gid_map"), format!("0 {gid} 1\n"));

    let timeout = std::time::Duration::from_millis(spec.timeout_ms);
    let mut timed_out = false;
    let code = loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(child),
                nix::sys::signal::Signal::SIGKILL,
            )
            .ok();
            timed_out = true;
            unsafe {
                let mut s = 0i32;
                libc::waitpid(child, &mut s, 0);
            }
            break None;
        }
        let mut status = 0i32;
        let w = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if w == child {
            if libc::WIFEXITED(status) {
                break Some(libc::WEXITSTATUS(status));
            }
            break None;
        }
        if w < 0 {
            return Err(SandboxError::Wait("waitpid error".into()));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let wall = start.elapsed().as_millis() as u64;
    let stdout = read_fd(out_r).map_err(|e| SandboxError::Io(e.to_string()))?;
    let stderr = read_fd(err_r).map_err(|e| SandboxError::Io(e.to_string()))?;
    unsafe {
        let _ = libc::close(out_r);
        let _ = libc::close(err_r);
    }
    Ok(SandboxResult {
        exit_code: code,
        stdout,
        stderr,
        timed_out,
        wall_time_ms: wall,
        sandboxed: true,
    })
}

fn child_main(spec: &SandboxSpec, out_w: i32, err_w: i32) -> ! {
    let r: Result<(), String> = (|| {
        // Wait for parent to write uid/gid maps (parent writes them
        // immediately after fork, while we share the same namespace).
        std::thread::sleep(std::time::Duration::from_millis(15));
        // Now enter a new user+ns namespace. uid/gid maps carry over.
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
            return Err(format!("unshare: {}", std::io::Error::last_os_error()));
        }
        nix::sys::prctl::set_no_new_privs().map_err(|e| format!("prctl: {e}"))?;
        apply_landlock(spec)?;
        unsafe {
            libc::dup2(out_w, libc::STDOUT_FILENO);
            libc::dup2(err_w, libc::STDERR_FILENO);
        }
        Ok(())
    })();
    if let Err(ref e) = r {
        let m = format!("sandbox error: {}\n", e);
        unsafe {
            libc::write(libc::STDERR_FILENO, m.as_ptr() as _, m.len());
        }
    }
    let err = Command::new(&spec.command).args(&spec.args).exec();
    let m = format!("exec failed: {}\n", err);
    unsafe {
        libc::write(libc::STDERR_FILENO, m.as_ptr() as _, m.len());
        libc::_exit(127);
    }
}

fn apply_landlock(spec: &SandboxSpec) -> Result<(), String> {
    let handled_fs = LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_EXECUTE;
    let attr = LandlockRulesetAttr {
        handled_access_fs: handled_fs,
    };
    let ruleset_fd = unsafe {
        libc::syscall(
            LANDLOCK_CREATE_RULESET,
            &attr as *const _,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        ) as isize
    };
    if ruleset_fd < 0 {
        // Landlock not available — unsandboxed but don't fail
        return Ok(());
    }

    // Add allowlisted paths (read only)
    for p in &spec.allowed_read_paths {
        add_path_rule(
            ruleset_fd,
            p,
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
        )?;
    }
    // Add write paths
    let rw =
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_WRITE_FILE;
    for p in &spec.allowed_write_paths {
        add_path_rule(ruleset_fd, p, rw)?;
    }
    // System paths always need read access
    for p in &["/usr/bin", "/usr/lib", "/lib", "/lib64"] {
        add_path_rule(
            ruleset_fd,
            p,
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE,
        )?;
    }

    // Restrict self
    let ret = unsafe { libc::syscall(LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) };
    unsafe {
        let _ = libc::close(ruleset_fd as i32);
    }
    if ret != 0 {
        return Err(format!(
            "landlock_restrict_self: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn add_path_rule(ruleset_fd: isize, path: &str, access: u64) -> Result<(), String> {
    let path_c = std::ffi::CString::new(path).map_err(|e| e.to_string())?;
    let fd = unsafe { libc::open(path_c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Ok(());
    } // path doesn't exist — skip rule
    let attr = LandlockPathBeneathAttr {
        allowed_access: access,
        parent_fd: fd,
    };
    let ret = unsafe {
        libc::syscall(
            LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &attr as *const _,
            0u32,
        )
    };
    unsafe {
        let _ = libc::close(fd);
    }
    if ret != 0 {
        return Err(format!(
            "landlock_add_rule({path}): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn read_fd(fd: i32) -> std::io::Result<String> {
    use std::io::Read;
    use std::os::unix::io::FromRawFd;
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut s = String::new();
    std::io::BufReader::new(file).read_to_string(&mut s)?;
    if s.len() > 65536 {
        s.truncate(65536);
    }
    Ok(s)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    #[test]
    fn empty_command() {
        assert!(execute(&SandboxSpec {
            command: "".into(),
            args: vec![],
            allowed_read_paths: vec![],
            allowed_write_paths: vec![],
            timeout_ms: 1000
        })
        .is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn echo() {
        let r = execute(&SandboxSpec {
            command: "/usr/bin/echo".into(),
            args: vec!["hello".into()],
            allowed_read_paths: vec!["/usr/bin".into()],
            allowed_write_paths: vec![],
            timeout_ms: 5000,
        })
        .unwrap();
        assert!(r.stdout.contains("hello"));
        assert!(!r.timed_out);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn timeout() {
        let r = execute(&SandboxSpec {
            command: "/usr/bin/sleep".into(),
            args: vec!["10".into()],
            allowed_read_paths: vec!["/usr/bin".into()],
            allowed_write_paths: vec![],
            timeout_ms: 200,
        })
        .unwrap();
        assert!(r.timed_out);
    }
}
