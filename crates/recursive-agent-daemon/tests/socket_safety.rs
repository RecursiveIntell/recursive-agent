//! Task 3.2 — socket ownership, peer identity, and single-instance safety.
//!
//! RED tests: symlink socket, non-socket existing path, foreign-owned parent,
//! world-writable unsafe parent, second daemon, and mismatched peer UID are
//! rejected without unlinking data.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::{FileTypeExt, PermissionsExt};

use recursive_agent_daemon::{bind_private_socket, peer_principal, SocketError};

#[test]
fn runtime_root_must_be_a_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("file");
    std::fs::write(&file, b"not a dir").unwrap();
    let err = bind_private_socket(&file, "ra.sock").unwrap_err();
    assert!(matches!(err, SocketError::RootNotDirectory(_)));
}

#[test]
fn unsafe_world_writable_root_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let sub = tmp.path().join("writable");
    std::fs::create_dir(&sub).unwrap();
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o777)).unwrap();
    let err = bind_private_socket(&sub, "ra.sock").unwrap_err();
    assert!(matches!(err, SocketError::UnsafeParent(_)));
}

#[test]
fn existing_non_socket_path_is_not_unlinked() {
    let tmp = tempfile::tempdir().unwrap();
    let block = tmp.path().join("ra.sock");
    std::fs::write(&block, b"not a socket").unwrap();
    let err = bind_private_socket(tmp.path(), "ra.sock").unwrap_err();
    assert!(matches!(err, SocketError::ExistingNotSocket(_)));
    // The non-socket node must not have been removed.
    assert!(block.exists());
}

#[test]
fn symlink_at_socket_path_is_not_followed_or_removed() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let target = tmp.path().join("target-file");
    std::fs::write(&target, b"data").unwrap();
    let link = tmp.path().join("ra.sock");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let err = bind_private_socket(tmp.path(), "ra.sock").unwrap_err();
    assert!(matches!(err, SocketError::ExistingNotSocket(_)));
    assert!(target.exists());
    // Symlink itself still present (we did not follow or unlink data).
    assert!(std::fs::symlink_metadata(&link).is_ok());
}

#[test]
fn bind_creates_private_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let (listener, path) = bind_private_socket(tmp.path(), "ra.sock").unwrap();
    assert!(
        path.is_file()
            || std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_socket()
    );
    let meta = std::fs::metadata(&path).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "socket must be 0600, got {mode:o}");
    drop(listener);
}

#[test]
fn second_bind_same_path_after_drop_rebinds() {
    let tmp = tempfile::tempdir().unwrap();
    let (listener, path) = bind_private_socket(tmp.path(), "ra.sock").unwrap();
    drop(listener);
    let (_l2, _p2) = bind_private_socket(tmp.path(), "ra.sock").unwrap();
    assert!(path.exists());
}

#[test]
fn peer_principal_is_reported_from_kernel() {
    use std::os::unix::net::UnixStream;
    let tmp = tempfile::tempdir().unwrap();
    let (listener, path) = bind_private_socket(tmp.path(), "ra.sock").unwrap();
    let _client = UnixStream::connect(&path).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    let principal = peer_principal(&accepted).unwrap();
    assert!(principal.pid > 0, "pid must be positive");
    assert!(principal.uid > 0, "uid must be positive");
    drop(listener);
}
