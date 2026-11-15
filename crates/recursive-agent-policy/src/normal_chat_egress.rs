//! Operator-owned normal-chat egress grant and durable revision authority.
//!
//! The grant is loaded only from a bounded, owner-held mode-0600 file. The
//! per-home head prevents a daemon restart from accepting a lower grant
//! revision. Neither this authority nor its head is exposed over IPC.

use super::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Mutex;

#[path = "campaign_funding.rs"]
mod campaign_funding;
pub use campaign_funding::*;

fn operator_policy_digest<T: Serialize>(policy: &T) -> Result<String, PolicyError> {
    let mut material = serde_json::to_value(policy)?;
    material
        .as_object_mut()
        .ok_or_else(|| grant_denied("grant serialization is not an object"))?
        .remove("policy_digest")
        .ok_or_else(|| grant_denied("grant lacks policy_digest"))?;
    let canonical = jcs_canonical(&material)?;
    let digest = Sha256::digest(&canonical);
    let encoded = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("sha256:{encoded}"))
}

const NORMAL_CHAT_GRANT_SCHEMA_V1: &str = "recursive-agent.normal-chat-egress-grant/v1";
const NORMAL_CHAT_GRANT_HEAD_SCHEMA_V1: &str = "recursive-agent.normal-chat-egress-head/v1";
const NORMAL_CHAT_GRANT_HEAD_FILE: &str = "normal-chat-egress-grant-head-v1.json";
const NORMAL_CHAT_GRANT_LOCK_FILE: &str = ".normal-chat-egress-grant.lock";
const MAX_NORMAL_CHAT_GRANT_BYTES: u64 = 1024 * 1024;
const MAX_NORMAL_CHAT_GRANT_HEAD_BYTES: u64 = 4096;
const MAX_NORMAL_CHAT_ROUTES: usize = 256;
const MAX_NORMAL_CHAT_ATTEMPTS: u32 = 1024;
const MAX_NORMAL_CHAT_OUTPUT_TOKENS: u32 = 1_000_000;

/// Hash the resolved Ares-home path bytes. This is correlation, not a grant.
pub fn normal_chat_ares_home_digest(home: &Path) -> Result<String, PolicyError> {
    let path = home.canonicalize()?;
    let bytes = Sha256::digest(path.as_os_str().as_encoded_bytes());
    Ok(format!(
        "sha256:{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

/// Operating mode sealed into the operator grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalChatEgressModeV1 {
    Observe,
    Enforce,
}

/// A single exact provider/model/API-mode route admitted by an enforce grant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatRouteV1 {
    pub provider_identity: String,
    pub model_ref: String,
    pub api_mode: String,
}

/// Closed per-session ceilings. Request bytes and wall time apply per physical
/// provider send; attempts and output reservations accumulate for the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatEgressCapsV1 {
    pub max_attempts: u32,
    pub max_output_tokens: u32,
    pub max_wall_time_ms: u64,
    pub max_request_bytes: u64,
}

/// This grant version supports digest-only observation and no response replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalChatContentRetentionV1 {
    #[serde(rename = "digest_only")]
    DigestOnly,
}

/// Closed operator-owned authority input. It is not accepted over IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalChatEgressGrantV1 {
    pub schema: String,
    pub revision: u64,
    pub ares_home_digest: String,
    pub mode: NormalChatEgressModeV1,
    pub any_route: bool,
    pub routes: Vec<NormalChatRouteV1>,
    pub caps: NormalChatEgressCapsV1,
    pub expires_at: DateTime<Utc>,
    pub content_retention: NormalChatContentRetentionV1,
    pub policy_digest: String,
}

impl NormalChatEgressGrantV1 {
    /// Structural and digest validation independent of wall-clock state.
    pub fn validate_structure(&self) -> Result<(), PolicyError> {
        if self.schema != NORMAL_CHAT_GRANT_SCHEMA_V1 {
            return Err(grant_denied("unsupported grant schema"));
        }
        if self.revision == 0 || self.revision > i64::MAX as u64 {
            return Err(grant_denied("invalid grant revision"));
        }
        validate_sha256_digest("Ares home digest", &self.ares_home_digest)?;
        validate_sha256_digest("policy digest", &self.policy_digest)?;
        if self.caps.max_attempts == 0
            || self.caps.max_attempts > MAX_NORMAL_CHAT_ATTEMPTS
            || self.caps.max_output_tokens == 0
            || self.caps.max_output_tokens > MAX_NORMAL_CHAT_OUTPUT_TOKENS
            || self.caps.max_wall_time_ms == 0
            || self.caps.max_wall_time_ms > MAX_LIVE_LEASE_MILLISECONDS as u64
            || self.caps.max_request_bytes == 0
            || self.caps.max_request_bytes
                > recursive_agent_contracts::MAX_NORMAL_CHAT_REQUEST_BYTES_V2
        {
            return Err(grant_denied("grant caps are zero or exceed a hard bound"));
        }
        if self.routes.len() > MAX_NORMAL_CHAT_ROUTES {
            return Err(grant_denied("route allowlist exceeds its hard bound"));
        }
        let mut routes = BTreeSet::new();
        for route in &self.routes {
            validate_grant_reference("provider_identity", &route.provider_identity)?;
            validate_grant_reference("model_ref", &route.model_ref)?;
            validate_grant_reference("api_mode", &route.api_mode)?;
            if looks_like_credential_material(&route.provider_identity)
                || looks_like_credential_material(&route.model_ref)
                || looks_like_credential_material(&route.api_mode)
            {
                return Err(grant_denied("route contains credential-like material"));
            }
            if !routes.insert(route) {
                return Err(grant_denied("route allowlist contains a duplicate"));
            }
        }
        if self.mode == NormalChatEgressModeV1::Enforce
            && (self.any_route || self.routes.is_empty())
        {
            return Err(grant_denied(
                "enforce mode requires a nonempty explicit route allowlist",
            ));
        }
        let expected = self.computed_policy_digest()?;
        if self.policy_digest != expected {
            return Err(grant_denied("policy digest does not bind the grant fields"));
        }
        Ok(())
    }

    /// Check the active Ares-home binding and expiry against a trusted clock.
    pub fn validate_at(
        &self,
        expected_ares_home_digest: &str,
        trusted_now: DateTime<Utc>,
    ) -> Result<(), PolicyError> {
        self.validate_structure()?;
        if self.ares_home_digest != expected_ares_home_digest {
            return Err(grant_denied("grant is bound to a different Ares home"));
        }
        if self.expires_at <= trusted_now {
            return Err(grant_denied("grant has expired"));
        }
        Ok(())
    }

    /// SHA-256 over JCS of every grant field except `policy_digest` itself.
    pub fn computed_policy_digest(&self) -> Result<String, PolicyError> {
        operator_policy_digest(self)
    }

    pub fn permits_route(&self, provider_identity: &str, model_ref: &str, api_mode: &str) -> bool {
        self.any_route
            || self.routes.iter().any(|route| {
                route.provider_identity == provider_identity
                    && route.model_ref == model_ref
                    && route.api_mode == api_mode
            })
    }
}

/// Closed, secret-free denial codes for governed normal-chat admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NormalChatEgressDenialV1 {
    #[error("GRANT_MISSING")]
    GrantMissing,
    #[error("GRANT_EXPIRED")]
    GrantExpired,
    #[error("ROUTE_NOT_ALLOWED")]
    RouteNotAllowed,
    #[error("CAP_EXHAUSTED_ATTEMPTS")]
    CapExhaustedAttempts,
    #[error("CAP_EXHAUSTED_OUTPUT_TOKENS")]
    CapExhaustedOutputTokens,
    #[error("CAP_EXHAUSTED_WALL_TIME_MS")]
    CapExhaustedWallTimeMs,
    #[error("CAP_EXHAUSTED_REQUEST_BYTES")]
    CapExhaustedRequestBytes,
    #[error("RUN_CLOSED")]
    RunClosed,
    #[error("INTENT_CONFLICT")]
    IntentConflict,
    #[error("MATERIALIZATION_UNAVAILABLE")]
    MaterializationUnavailable,
    #[error("SOURCE_REVISION_UNAVAILABLE")]
    SourceRevisionUnavailable,
    #[error("MALFORMED")]
    Malformed,
    #[error("DAEMON_OVERLOADED")]
    DaemonOverloaded,
}

/// Non-serializable startup capability minted only after file, policy, home,
/// expiry, and durable revision-head validation.
#[derive(Clone)]
pub struct NormalChatGrantAuthorityV1 {
    grant: NormalChatEgressGrantV1,
    loaded_at: DateTime<Utc>,
}

impl NormalChatGrantAuthorityV1 {
    pub fn grant(&self) -> &NormalChatEgressGrantV1 {
        &self.grant
    }

    pub fn loaded_at(&self) -> DateTime<Utc> {
        self.loaded_at
    }

    /// Check a V2 attempt against this startup-loaded grant without issuing a
    /// permit or reserving budget. The family owner must additionally reserve
    /// cumulative attempts/output under its durable lock before admission.
    ///
    /// The ordinal bound here is only a necessary per-attempt check, not a
    /// substitute for counting all reservations across logical calls.
    pub fn check_attempt(
        &self,
        attempt: &recursive_agent_contracts::NormalChatAttemptV2,
        trusted_now: DateTime<Utc>,
    ) -> Result<(), NormalChatEgressDenialV1> {
        use NormalChatEgressDenialV1 as Denial;
        if trusted_now < self.loaded_at {
            return Err(Denial::Malformed);
        }
        check_normal_chat_grant_attempt(&self.grant, attempt, trusted_now)
    }
}

pub(super) fn check_normal_chat_grant_attempt(
    grant: &NormalChatEgressGrantV1,
    attempt: &recursive_agent_contracts::NormalChatAttemptV2,
    trusted_now: DateTime<Utc>,
) -> Result<(), NormalChatEgressDenialV1> {
    use NormalChatEgressDenialV1 as Denial;
    if trusted_now >= grant.expires_at {
        return Err(Denial::GrantExpired);
    }
    attempt.validate().map_err(|_| Denial::Malformed)?;
    let operation = &attempt.operation;
    if operation.policy_basis_ref != format!("normal-chat-grant:revision-{}", grant.revision)
        || operation.policy_basis_digest != grant.policy_digest
    {
        return Err(Denial::Malformed);
    }
    if looks_like_credential_material(&operation.provider_identity)
        || looks_like_credential_material(&operation.model_ref)
        || looks_like_credential_material(&operation.api_mode)
        || !grant.permits_route(
            &operation.provider_identity,
            &operation.model_ref,
            &operation.api_mode,
        )
    {
        return Err(Denial::RouteNotAllowed);
    }
    let caps = &grant.caps;
    if attempt.attempt_number > caps.max_attempts {
        return Err(Denial::CapExhaustedAttempts);
    }
    if operation.budget.output_reserve > caps.max_output_tokens {
        return Err(Denial::CapExhaustedOutputTokens);
    }
    if operation.budget.max_wall_time_ms > caps.max_wall_time_ms {
        return Err(Denial::CapExhaustedWallTimeMs);
    }
    if operation.budget.max_request_bytes > caps.max_request_bytes
        || attempt.provider_request_bytes > operation.budget.max_request_bytes
    {
        return Err(Denial::CapExhaustedRequestBytes);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NormalChatGrantHeadV1 {
    schema: String,
    revision: u64,
    policy_digest: String,
}

/// Policy-owned persistent grant revision head. The head is global to the
/// daemon's dedicated per-home authority directory, not per-session or IPC data.
pub struct NormalChatEgressGrantStore {
    root: File,
    lock: File,
    gate: Mutex<()>,
    root_device: u64,
    root_inode: u64,
    root_uid: u32,
}

impl NormalChatEgressGrantStore {
    pub fn from_dir_fd(root: &File) -> Result<Self, PolicyError> {
        let metadata = root.metadata()?;
        let uid = rustix::process::getuid().as_raw();
        if !metadata.is_dir() {
            return Err(grant_denied("grant authority root is not a directory"));
        }
        if metadata.uid() != uid {
            return Err(grant_denied(
                "grant authority directory has the wrong owner",
            ));
        }
        let permissions = metadata.mode() & 0o777;
        if permissions & 0o077 != 0 || permissions & 0o700 != 0o700 {
            return Err(grant_denied(&format!(
                "grant authority directory must be private mode 0700 or stricter (got {permissions:o})"
            )));
        }
        let root = root.try_clone()?;
        let lock = File::from(secure_open_at(
            &root,
            NORMAL_CHAT_GRANT_LOCK_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?);
        validate_private_regular_file(&lock, 0o600, MAX_NORMAL_CHAT_GRANT_HEAD_BYTES)?;
        Ok(Self {
            root,
            lock,
            gate: Mutex::new(()),
            root_device: metadata.dev(),
            root_inode: metadata.ino(),
            root_uid: metadata.uid(),
        })
    }

    /// Read and validate an operator grant, then durably advance the monotonic
    /// policy head before returning the non-serializable authority capability.
    pub fn load_from_path(
        &self,
        grant_path: &Path,
        expected_ares_home_digest: &str,
        trusted_now: DateTime<Utc>,
    ) -> Result<NormalChatGrantAuthorityV1, PolicyError> {
        let grant = read_operator_grant_file(grant_path)?;
        grant.validate_at(expected_ares_home_digest, trusted_now)?;
        self.with_lock(|| {
            let head = self.read_head()?;
            match head {
                None => self.write_head(&NormalChatGrantHeadV1 {
                    schema: NORMAL_CHAT_GRANT_HEAD_SCHEMA_V1.into(),
                    revision: grant.revision,
                    policy_digest: grant.policy_digest.clone(),
                })?,
                Some(head) if head.schema != NORMAL_CHAT_GRANT_HEAD_SCHEMA_V1 => {
                    return Err(grant_denied("unsupported durable grant-head schema"));
                }
                Some(head)
                    if grant.revision == head.revision
                        && grant.policy_digest == head.policy_digest => {}
                Some(head) if grant.revision > head.revision => {
                    self.write_head(&NormalChatGrantHeadV1 {
                        schema: NORMAL_CHAT_GRANT_HEAD_SCHEMA_V1.into(),
                        revision: grant.revision,
                        policy_digest: grant.policy_digest.clone(),
                    })?;
                }
                Some(_) => return Err(grant_denied("grant revision rollback or conflict")),
            }
            Ok(())
        })?;
        Ok(NormalChatGrantAuthorityV1 {
            grant,
            loaded_at: trusted_now,
        })
    }

    fn with_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, PolicyError>,
    ) -> Result<T, PolicyError> {
        let _thread_guard = self
            .gate
            .lock()
            .map_err(|_| PolicyError::PermitStateConflict)?;
        self.check_root_identity()?;
        rustix::fs::flock(self.lock.as_fd(), FlockOperation::LockExclusive)
            .map_err(std::io::Error::from)?;
        let result = operation();
        let unlock = rustix::fs::flock(self.lock.as_fd(), FlockOperation::Unlock);
        match (result, unlock) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(PolicyError::Io(error.into())),
        }
    }

    fn check_root_identity(&self) -> Result<(), PolicyError> {
        let metadata = self.root.metadata()?;
        if !metadata.is_dir()
            || metadata.dev() != self.root_device
            || metadata.ino() != self.root_inode
            || metadata.uid() != self.root_uid
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(grant_denied("grant authority directory identity changed"));
        }
        Ok(())
    }

    fn read_head(&self) -> Result<Option<NormalChatGrantHeadV1>, PolicyError> {
        let fd = match secure_open_at(
            &self.root,
            NORMAL_CHAT_GRANT_HEAD_FILE,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let file = File::from(fd);
        validate_private_regular_file(&file, 0o600, MAX_NORMAL_CHAT_GRANT_HEAD_BYTES)?;
        let bytes = read_bounded(&file, MAX_NORMAL_CHAT_GRANT_HEAD_BYTES)?;
        let value = recursive_agent_contracts::parse_strict_json_value(&bytes)
            .map_err(|_| grant_denied("durable grant head is malformed or has duplicate keys"))?;
        let head = serde_json::from_value::<NormalChatGrantHeadV1>(value)?;
        if head.schema != NORMAL_CHAT_GRANT_HEAD_SCHEMA_V1
            || head.revision == 0
            || head.revision > i64::MAX as u64
        {
            return Err(grant_denied("durable grant head is invalid"));
        }
        validate_sha256_digest("durable grant-head policy digest", &head.policy_digest)?;
        Ok(Some(head))
    }

    fn write_head(&self, head: &NormalChatGrantHeadV1) -> Result<(), PolicyError> {
        let bytes = jcs_canonical(head)?;
        if bytes.len() as u64 > MAX_NORMAL_CHAT_GRANT_HEAD_BYTES {
            return Err(grant_denied("durable grant head exceeds its hard bound"));
        }
        let (temp, mut file) = create_unique_temp(&self.root, ".normal-chat-grant-head.tmp")?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            rustix::fs::renameat(
                self.root.as_fd(),
                &temp,
                self.root.as_fd(),
                NORMAL_CHAT_GRANT_HEAD_FILE,
            )
            .map_err(std::io::Error::from)?;
            self.root.sync_all()?;
            Ok::<(), PolicyError>(())
        })();
        if result.is_err() {
            let _ = rustix::fs::unlinkat(self.root.as_fd(), &temp, rustix::fs::AtFlags::empty());
        }
        result
    }
}

fn read_operator_grant_file(path: &Path) -> Result<NormalChatEgressGrantV1, PolicyError> {
    read_operator_policy_file(path)
}

fn read_operator_policy_file<T: serde::de::DeserializeOwned>(
    path: &Path,
) -> Result<T, PolicyError> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(fd);
    validate_private_regular_file(&file, 0o600, MAX_NORMAL_CHAT_GRANT_BYTES)?;
    let bytes = read_bounded(&file, MAX_NORMAL_CHAT_GRANT_BYTES)?;
    let value = recursive_agent_contracts::parse_strict_json_value(&bytes)
        .map_err(|_| grant_denied("grant is malformed or contains duplicate keys"))?;
    let grant = serde_json::from_value(value)?;
    Ok(grant)
}

fn validate_private_regular_file(
    file: &File,
    required_mode: u32,
    maximum_bytes: u64,
) -> Result<(), PolicyError> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o777 != required_mode
        || metadata.len() > maximum_bytes
    {
        return Err(grant_denied(
            "file must be owned, regular, bounded, and mode 0600",
        ));
    }
    Ok(())
}

fn read_bounded(file: &File, maximum_bytes: u64) -> Result<Vec<u8>, PolicyError> {
    let mut bytes = Vec::new();
    file.try_clone()?
        .take(maximum_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(grant_denied("file exceeds its hard byte limit"));
    }
    Ok(bytes)
}

fn validate_sha256_digest(name: &str, value: &str) -> Result<(), PolicyError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(grant_denied(&format!("{name} must use sha256")));
    };
    if hex.len() != 64
        || !hex
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        return Err(grant_denied(&format!("{name} is malformed")));
    }
    Ok(())
}

fn validate_grant_reference(name: &str, value: &str) -> Result<(), PolicyError> {
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(grant_denied(&format!("invalid {name}")));
    }
    Ok(())
}

fn grant_denied(message: &str) -> PolicyError {
    PolicyError::InvalidLease(format!("normal-chat egress grant: {message}"))
}
