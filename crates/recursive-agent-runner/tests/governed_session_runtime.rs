use chrono::{DateTime, TimeDelta, Utc};
use llm_tool_runtime::{ToolRegistry, ToolRuntime};
use recursive_agent_contracts::{content_digest, ReceiptKindV1};
use recursive_agent_ledger::appendable_snapshot_expected_run_from_dir_fd;
use recursive_agent_policy::{
    DurablePermitStore, NormalChatEgressGrantStore, NormalChatEgressGrantV1,
    NormalChatGrantAuthorityV1,
};
use recursive_agent_runner::{
    Clock, RuntimeDependencies, RuntimeLedgerDependencyV1, RuntimePolicyDependencyV1,
    RuntimeProviderDependencyV1, RuntimeSandboxDependencyV1, RuntimeService, RuntimeServiceError,
    RuntimeStoreDependencyV1,
};
use serde_json::json;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
#[path = "support/normal_chat_attempt_runtime_v2.rs"]
mod attempts;
#[path = "support/governed_session_bootstrap_hostile.rs"]
mod hostile;
#[path = "support/governed_session_bootstrap_matrix.rs"]
mod matrix;
#[path = "support/normal_chat_parent_recovery_entry.rs"]
mod parent_recovery_entry;
const HOME: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn start() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_792_008_000)
}
#[derive(Default)]
struct TestClock(AtomicI64);
impl Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        start() + TimeDelta::milliseconds(self.0.load(Ordering::SeqCst))
    }
}
struct Fixture {
    _grant_root: tempfile::TempDir,
    root: tempfile::TempDir,
    authority: NormalChatGrantAuthorityV1,
    clock: Arc<TestClock>,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_send_window(1000)
    }
    fn with_send_window(max_wall_time_ms: u64) -> Result<Self, Box<dyn std::error::Error>> {
        let grant_root = tempfile::tempdir()?;
        fs::set_permissions(grant_root.path(), fs::Permissions::from_mode(0o700))?;
        let mut grant: NormalChatEgressGrantV1 = serde_json::from_value(json!({
            "schema":"recursive-agent.normal-chat-egress-grant/v1", "revision":1,
            "ares_home_digest":HOME, "mode":"enforce", "any_route":false,
            "routes":[{"provider_identity":"openai_compatible:https://provider.test/v1", "model_ref":"model:fixture", "api_mode":"chat_completions"}],
            "caps":{"max_attempts":3,"max_output_tokens":100,"max_wall_time_ms":max_wall_time_ms,"max_request_bytes":4096},
            "expires_at":start()+TimeDelta::seconds(600),"content_retention":"digest_only","policy_digest":HOME
        }))?;
        grant.policy_digest = grant.computed_policy_digest()?;
        let grant_path = grant_root.path().join("grant.json");
        fs::write(&grant_path, serde_json::to_vec(&grant)?)?;
        fs::set_permissions(&grant_path, fs::Permissions::from_mode(0o600))?;
        let authority = NormalChatEgressGrantStore::from_dir_fd(&File::open(grant_root.path())?)?
            .load_from_path(&grant_path, HOME, start())?;
        Ok(Self {
            _grant_root: grant_root,
            root: tempfile::tempdir()?,
            authority,
            clock: Arc::new(TestClock::default()),
        })
    }
    fn service(&self) -> Result<RuntimeService, Box<dyn std::error::Error>> {
        Ok(runtime(self.root.path(), self.clock.clone())?
            .with_normal_chat_egress_grant(self.authority.clone()))
    }
    fn run_dir(&self) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let session = self
            .authority
            .normal_chat_session("conversation:fixture", None)?;
        Ok(self
            .root
            .path()
            .join(content_digest(&session.run_id()?)?.to_string()))
    }
}
fn runtime(
    root: &Path,
    clock: Arc<dyn Clock>,
) -> Result<RuntimeService, Box<dyn std::error::Error>> {
    let deps = RuntimeDependencies::builder()
        .policy(RuntimePolicyDependencyV1::Native)
        .sandbox(RuntimeSandboxDependencyV1::Native)
        .tool_runtime(Arc::new(ToolRuntime::new(ToolRegistry::new())))
        .provider(RuntimeProviderDependencyV1::Disabled)
        .ledger(RuntimeLedgerDependencyV1::Native)
        .clock(clock)
        .store(RuntimeStoreDependencyV1::Native)
        .output_root(root)
        .build()?;
    Ok(RuntimeService::new(deps))
}

#[test]
fn normal_chat_session_is_disabled_without_explicit_loaded_grant() -> TestResult {
    let root = tempfile::tempdir()?;
    let service = runtime(root.path(), Arc::new(TestClock::default()))?;
    assert!(matches!(
        service.open_normal_chat_session("conversation:fixture"),
        Err(RuntimeServiceError::NormalChatGovernanceDisabled)
    ));
    assert_eq!(fs::read_dir(root.path())?.count(), 0);
    Ok(())
}

#[test]
fn session_bootstrap_has_real_verified_nonterminal_control_evidence() -> TestResult {
    let fx = Fixture::new()?;
    let service = fx.service()?;
    let opened = service.open_normal_chat_session("conversation:fixture")?;
    let expected = fx
        .authority
        .normal_chat_session("conversation:fixture", None)?;
    assert_eq!(opened.session(), &expected);
    assert_eq!(opened.run_id(), &expected.run_id()?);
    assert_eq!(opened.run_dir(), fx.run_dir()?.as_path());
    let snapshot = appendable_snapshot_expected_run_from_dir_fd(
        &File::open(opened.run_dir())?,
        opened.run_id(),
    )?;
    assert_eq!(
        snapshot
            .receipts()
            .iter()
            .map(|r| r.kind.clone())
            .collect::<Vec<_>>(),
        vec![
            ReceiptKindV1::RunStarted,
            ReceiptKindV1::StepStarted,
            ReceiptKindV1::PermitIssued
        ]
    );
    assert_eq!(
        snapshot.verification().final_head,
        opened.verified_prefix_head().to_string()
    );
    assert!(!snapshot.verification().current_strict_success);
    let permits = DurablePermitStore::from_run_root_fd(&File::open(opened.run_dir())?)?;
    let record = permits
        .read_normal_chat_session_control_record()?
        .ok_or("control absent")?;
    assert!(!record.permit.binding.effect.network_allowed);
    assert!(record
        .permit
        .delegation_ceiling
        .as_ref()
        .ok_or("ceiling absent")?
        .actions
        .iter()
        .all(|action| !action.effect.network_allowed));
    Ok(())
}

#[test]
fn exact_session_reopen_preserves_receipts_family_and_original_control_lease() -> TestResult {
    let fx = Fixture::new()?;
    let one = fx
        .service()?
        .open_normal_chat_session("conversation:fixture")?;
    let receipts = fs::read(one.run_dir().join("receipts.ndjson"))?;
    let family = fs::read(one.run_dir().join("family-authority.json"))?;
    let permits = DurablePermitStore::from_run_root_fd(&File::open(one.run_dir())?)?;
    let record = permits.read_normal_chat_session_control_record()?;
    fx.clock.0.store(100, Ordering::SeqCst);
    let two = fx
        .service()?
        .open_normal_chat_session("conversation:fixture")?;
    assert_eq!(one.verified_prefix_head(), two.verified_prefix_head());
    assert_eq!(record, permits.read_normal_chat_session_control_record()?);
    assert_eq!(fs::read(two.run_dir().join("receipts.ndjson"))?, receipts);
    assert_eq!(
        fs::read(two.run_dir().join("family-authority.json"))?,
        family
    );
    Ok(())
}
