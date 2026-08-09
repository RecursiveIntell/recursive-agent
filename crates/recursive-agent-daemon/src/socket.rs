//! Socket ownership, peer identity, and single-instance safety for the daemon.
//!
//! The daemon binds only a validated private socket under an owned runtime
//! directory. Startup refuses to unlink a non-socket or foreign-owned node,
//! rejects unsafe parents, and derives the local peer principal from the
//! kernel `SO_PEERCRED` credential (via `nix`) rather than trusting any
//! client-claimed text.

use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use nix::sys::socket::getsockopt;
use nix::sys::socket::sockopt::PeerCredentials;
use thiserror::Error;

/// Errors from socket binding and peer authentication. All typed; no panic.
#[derive(Debug, Error)]
pub enum SocketError {
    #[error("runtime root is not a directory: {0}")]
    RootNotDirectory(String),
    #[error("unsafe runtime parent: {0}")]
    UnsafeParent(String),
    #[error("existing path is not a socket and was not unlinked: {0}")]
    ExistingNotSocket(String),
    #[error("existing socket is owned by uid {owner}, expected {expected}")]
    ForeignOwnedSocket { owner: u32, expected: u32 },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("peer credential unavailable: {0}")]
    PeerCredential(String),
}

/// The peer principal authenticated by the kernel for one accepted connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPrincipal {
    /// Effective UID reported by `SO_PEERCRED`.
    pub uid: u32,
    /// Effective GID reported by `SO_PEERCRED`.
    pub gid: u32,
    /// Process ID reported by `SO_PEERCRED`.
    pub pid: i32,
}

fn current_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Validate that `root` is a directory owned by the current UID and not
/// group/other writable.
fn validate_runtime_root(root: &Path) -> Result<(), SocketError> {
    let meta = fs::metadata(root)
        .map_err(|_| SocketError::RootNotDirectory(root.display().to_string()))?;
    if !meta.is_dir() {
        return Err(SocketError::RootNotDirectory(root.display().to_string()));
    }
    let uid = current_uid();
    if meta.uid() != uid {
        return Err(SocketError::UnsafeParent(format!(
            "runtime root owner {} != current {uid}",
            meta.uid()
        )));
    }
    let mode = meta.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(SocketError::UnsafeParent(format!(
            "runtime root is group/other writable (mode {mode:o})"
        )));
    }
    Ok(())
}

/// Bind one private Unix socket under an owned runtime directory.
///
/// - Refuses a non-directory runtime root or an unsafe (foreign/writable) root.
/// - If `<root>/<socket_name>` exists: unlinks it only when it is a socket and
///   owned by the current UID; otherwise returns a typed refusal.
/// - Binds the socket with mode `0600`.
pub fn bind_private_socket(
    root: &Path,
    socket_name: &str,
) -> Result<(UnixListener, PathBuf), SocketError> {
    validate_runtime_root(root)?;

    let socket_path = root.join(socket_name);
    let uid = current_uid();
    if let Ok(meta) = fs::symlink_metadata(&socket_path) {
        if meta.file_type().is_socket() {
            if meta.uid() != uid {
                return Err(SocketError::ForeignOwnedSocket {
                    owner: meta.uid(),
                    expected: uid,
                });
            }
            // Remove our own stale socket before re-binding.
            fs::remove_file(&socket_path)?;
        } else {
            return Err(SocketError::ExistingNotSocket(
                socket_path.display().to_string(),
            ));
        }
    }

    // `UnixListener::bind` creates the socket node atomically inside our
    // private, validated root. No placeholder or unsafe close is needed.
    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    Ok((listener, socket_path))
}

/// Read the kernel-authenticated peer principal for an accepted stream.
///
/// Uses `getsockopt(SOL_SOCKET, SO_PEERCRED)`, which the kernel populates from
/// the connecting process and which no client can forge.
pub fn peer_principal(
    stream: &std::os::unix::net::UnixStream,
) -> Result<PeerPrincipal, SocketError> {
    let cred = getsockopt(stream, PeerCredentials)
        .map_err(|error| SocketError::PeerCredential(error.to_string()))?;
    Ok(PeerPrincipal {
        uid: cred.uid() as u32,
        gid: cred.gid() as u32,
        pid: cred.pid() as i32,
    })
}
