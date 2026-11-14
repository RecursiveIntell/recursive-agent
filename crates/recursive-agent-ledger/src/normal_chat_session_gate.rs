//! Shared outer coordination for normal-chat runtime and ledger owners.
//! This is not a permit, grant, terminal proof, lease or send continuation.
use super::{run_root_identity, LedgerError, RunRootIdentity};
use rustix::fs::{FlockOperation, Mode, OFlags};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
};
use thiserror::Error;
const NAME: &str = ".normal-chat-runtime.lock";
#[derive(Debug, Error)]
pub enum NormalChatSessionGateErrorV1 {
    #[error("normal-chat session coordination is busy")]
    Busy,
    #[error("unsafe normal-chat session gate")]
    Unsafe,
    #[error("normal-chat session gate locator changed")]
    LocatorChanged,
    #[error("normal-chat session gate root differs")]
    RootMismatch,
    #[error("normal-chat session gate root: {0}")]
    Root(#[source] LedgerError),
    #[error("normal-chat session gate io: {0}")]
    Io(#[from] std::io::Error),
}
/// Live, non-reentrant, descriptor-bound coordination only. Callers must acquire
/// this OUTSIDE native/ledger locks and borrow the same guard for composition.
/// It never acquires those locks and never proves current egress authority.
///
/// ```compile_fail
/// use recursive_agent_ledger::NormalChatSessionGateV1;
/// fn forge()->NormalChatSessionGateV1 {NormalChatSessionGateV1 {}}
/// ```
/// ```compile_fail
/// use recursive_agent_ledger::NormalChatSessionGateV1;
/// fn duplicate(gate:NormalChatSessionGateV1) {let _=gate.clone();}
/// ```
pub struct NormalChatSessionGateV1 {
    file: File,
    root: File,
    root_identity: RunRootIdentity,
    device: u64,
    inode: u64,
}
impl NormalChatSessionGateV1 {
    /// Bootstrap/create-capable path. Does not create native authority/history.
    pub fn acquire(root: &File) -> Result<Self, NormalChatSessionGateErrorV1> {
        Self::acquire_mode(root, true, |_| {})
    }
    /// Historical/recovery writer path: missing coordination fails, never creates.
    pub fn acquire_existing(root: &File) -> Result<Self, NormalChatSessionGateErrorV1> {
        Self::acquire_mode(root, false, |_| {})
    }
    #[doc(hidden)]
    pub fn acquire_existing_with_observer(
        root: &File,
        observer: impl FnOnce(),
    ) -> Result<Self, NormalChatSessionGateErrorV1> {
        Self::acquire_mode(root, false, |_| observer())
    }
    // Public observers deliberately receive no guard/file. This private
    // callback also permits the unit-only duplicate-description witness.
    fn acquire_mode(
        root: &File,
        create: bool,
        observer: impl FnOnce(&Self),
    ) -> Result<Self, NormalChatSessionGateErrorV1> {
        use NormalChatSessionGateErrorV1 as E;
        let root_identity = run_root_identity(root).map_err(E::Root)?;
        let retained = root.try_clone()?;
        let fd = rustix::fs::openat(
            root,
            NAME,
            OFlags::RDWR
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK
                | if create {
                    OFlags::CREATE
                } else {
                    OFlags::empty()
                },
            if create {
                Mode::RUSR | Mode::WUSR
            } else {
                Mode::empty()
            },
        )
        .map_err(std::io::Error::from)?;
        let file = File::from(fd);
        let meta = file.metadata()?;
        if !safe(&meta) {
            return Err(E::Unsafe);
        }
        if let Err(error) =
            rustix::fs::flock(file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        {
            let error = std::io::Error::from(error);
            return if error.kind() == std::io::ErrorKind::WouldBlock {
                Err(E::Busy)
            } else {
                Err(E::Io(error))
            };
        }
        let result = Self {
            device: meta.dev(),
            inode: meta.ino(),
            file,
            root: retained,
            root_identity,
        };
        observer(&result);
        if let Err(error) = result.check(root) {
            // Closing only this descriptor is insufficient when fork/dup has
            // retained the same open description. Explicitly release on failure;
            // a cleanup I/O failure is itself returned, never claimed released.
            result.unlock()?;
            return Err(error);
        }
        Ok(result)
    }
    /// Fence the caller's original descriptor root and current gate locator.
    /// Renaming the root path itself requires the outer pinned run-locator
    /// owner too; this method does not infer authority from an ambient path.
    pub fn check(&self, root: &File) -> Result<(), NormalChatSessionGateErrorV1> {
        use NormalChatSessionGateErrorV1 as E;
        if run_root_identity(root).map_err(E::Root)? != self.root_identity
            || run_root_identity(&self.root).map_err(E::Root)? != self.root_identity
        {
            return Err(E::RootMismatch);
        }
        let fd = rustix::fs::openat(
            root,
            NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        let current = File::from(fd);
        let meta = current.metadata()?;
        if !safe(&meta) || meta.dev() != self.device || meta.ino() != self.inode {
            return Err(E::LocatorChanged);
        }
        Ok(())
    }
    /// Consume the guard and explicitly release its flock, even if its name
    /// was removed. File drop closes this guard's descriptor, but fork/dup
    /// references can retain the open description until exec/close. No native
    /// write occurs; runtime uses this explicit release on normal completion.
    pub fn unlock(self) -> Result<(), NormalChatSessionGateErrorV1> {
        rustix::fs::flock(self.file.as_fd(), FlockOperation::Unlock)
            .map_err(std::io::Error::from)?;
        Ok(())
    }
}
fn safe(meta: &std::fs::Metadata) -> bool {
    meta.is_file()
        && meta.uid() == rustix::process::getuid().as_raw()
        && meta.mode() & 0o777 == 0o600
        && meta.nlink() == 1
}

#[cfg(test)]
mod description_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn failed_post_flock_fence_releases_a_duplicated_open_description() -> TestResult {
        let dir = tempfile::tempdir()?;
        let root = File::open(dir.path())?;
        NormalChatSessionGateV1::acquire(&root)?.unlock()?;
        let mut duplicate = None;
        let mut action = Ok(());
        let outcome = NormalChatSessionGateV1::acquire_mode(&root, false, |held| {
            action = (|| -> std::io::Result<()> {
                // A safe dup models the descriptor reference inherited between
                // fork and CLOEXEC without exposing a held fd in the public API.
                duplicate = Some(held.file.try_clone()?);
                fs::rename(dir.path().join(NAME), dir.path().join("detached"))?;
                fs::write(dir.path().join(NAME), b"")?;
                fs::set_permissions(dir.path().join(NAME), fs::Permissions::from_mode(0o600))?;
                Ok(())
            })();
        });
        action?;
        assert!(matches!(
            outcome,
            Err(NormalChatSessionGateErrorV1::LocatorChanged)
        ));
        let duplicate = duplicate.ok_or("dup did not run")?;
        let detached = File::open(dir.path().join("detached"))?;
        rustix::fs::flock(&detached, FlockOperation::NonBlockingLockExclusive)?;
        rustix::fs::flock(&detached, FlockOperation::Unlock)?;
        drop(duplicate);
        Ok(())
    }
    #[test]
    fn plain_drop_retains_posix_last_description_semantics_until_dup_closes() -> TestResult {
        let dir = tempfile::tempdir()?;
        let root = File::open(dir.path())?;
        let held = NormalChatSessionGateV1::acquire(&root)?;
        let duplicate = held.file.try_clone()?;
        drop(held);
        assert!(matches!(
            NormalChatSessionGateV1::acquire_existing(&root),
            Err(NormalChatSessionGateErrorV1::Busy)
        ));
        drop(duplicate);
        NormalChatSessionGateV1::acquire_existing(&root)?.unlock()?;
        Ok(())
    }
}
