//! Actual daemon process + private framed socket, no provider execution.
use chrono::{TimeDelta, Utc};
use recursive_agent_contracts::ContentDigest;
use recursive_agent_policy::NormalChatEgressGrantV1;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::unix::{fs::PermissionsExt, net::UnixStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Daemon {
    home: tempfile::TempDir,
    grant: NormalChatEgressGrantV1,
    child: Child,
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Daemon {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let home = tempfile::tempdir()?;
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700))?;
        let mut grant: NormalChatEgressGrantV1 = serde_json::from_value(json!({
            "schema":"recursive-agent.normal-chat-egress-grant/v1","revision":1,
            "ares_home_digest":recursive_agent_policy::normal_chat_ares_home_digest(home.path())?,
            "mode":"enforce","any_route":false,
            "routes":[{"provider_identity":"openai_compatible:https://provider.test/v1","model_ref":"model:fixture","api_mode":"chat_completions"}],
            "caps":{"max_attempts":2,"max_output_tokens":20,"max_wall_time_ms":10000,"max_request_bytes":4096},
            "expires_at":Utc::now()+TimeDelta::minutes(10),"content_retention":"digest_only","policy_digest":"sha256:".to_string()+&"a".repeat(64)
        }))?;
        grant.policy_digest = grant.computed_policy_digest()?;
        let file = home.path().join("grant.json");
        std::fs::write(&file, serde_json::to_vec(&grant)?)?;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
        std::fs::create_dir(home.path().join("run"))?;
        std::fs::set_permissions(
            home.path().join("run"),
            std::fs::Permissions::from_mode(0o700),
        )?;
        let child = Command::new(env!("CARGO_BIN_EXE_ra-daemon"))
            .args(["serve", "--root"])
            .arg(home.path().join("runs"))
            .arg("--socket")
            .arg(home.path().join("run/ra.sock"))
            .arg("--ares-home")
            .arg(home.path())
            .arg("--egress-grant-file")
            .arg(&file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(
                home.path().join("daemon-stderr.log"),
            )?)
            .spawn()?;
        let mut daemon = Self { home, grant, child };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if UnixStream::connect(daemon.home.path().join("run/ra.sock")).is_ok() {
                break;
            }
            if let Some(status) = daemon.child.try_wait()? {
                return Err(format!(
                    "daemon exited {status}: {}",
                    std::fs::read_to_string(daemon.home.path().join("daemon-stderr.log"))?
                )
                .into());
            }
            if Instant::now() >= deadline {
                return Err("daemon readiness timeout".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(daemon)
    }
    fn rpc(&self, request: Value) -> Result<Value, Box<dyn std::error::Error>> {
        let mut stream = UnixStream::connect(self.home.path().join("run/ra.sock"))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let bytes = serde_json::to_vec(
            &json!({"schema":"recursive-agent.ipc/request/v2","protocol_version":2,"request_id":"ipc-test","request":request}),
        )?;
        stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
        stream.write_all(&bytes)?;
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix)?;
        let size = u32::from_be_bytes(prefix) as usize;
        assert!(size < recursive_agent_daemon::MAX_FRAME_PAYLOAD_BYTES);
        let mut body = vec![0; size];
        stream.read_exact(&mut body)?;
        let v: Value = serde_json::from_slice(&body)?;
        assert_eq!(v["schema"], "recursive-agent.ipc/response/v2");
        assert_eq!(v["request_id"], "ipc-test");
        Ok(v["result"].clone())
    }
    fn open(&self) -> Result<Value, Box<dyn std::error::Error>> {
        self.rpc(json!({"kind":"normal_chat_session_open","conversation_ref":"conversation:ipc","parent_session_run_id":null}))
    }
    fn call(&self, id: &Value, intent: &str) -> Value {
        json!({"schema":"recursive-agent.normal-chat-call-request/v2","operation":{
            "schema":"recursive-agent.normal-chat/v2","conversation_ref":"conversation:ipc","parent_run_id":id,
            "materialization_ref":"materialization:ipc-fixture","materialization_digest":"sha256:".to_string()+&"a".repeat(64),
            "policy_basis_ref":"normal-chat-grant:revision-1","policy_basis_digest":self.grant.policy_digest,
            "source_revision":"source:explicit-ipc-fixture","route_class":"conversation","provider_identity":"openai_compatible:https://provider.test/v1","model_ref":"model:fixture","api_mode":"chat_completions",
            "request_digest":"sha256:".to_string()+&"b".repeat(64),"request_projection_schema":"ares-json-sorted-v1",
            "budget":{"output_reserve":10,"max_wall_time_ms":10000,"max_request_bytes":4096},"replay":"unavailable",
            "provenance":[{"source":"urn:test:ipc-fixture","digest":ContentDigest::compute(b"ipc-fixture")}]
        },"provider_request_digest":ContentDigest::compute(b"explicit-body"),"provider_request_bytes":13,"dispatch_intent_ref":intent})
    }
}
#[test]
fn native_governed_ipc_begin_readback_settle_close_and_verify() -> TestResult {
    let d = Daemon::new()?;
    let opened = d.open()?;
    assert_eq!(opened["kind"], "normal_chat_session_opened");
    let id = opened["session_run_id"].clone();
    assert_eq!(id, d.open()?["session_run_id"]);
    let call = d.call(&id, "intent:ipc-one");
    let begun =
        d.rpc(json!({"kind":"normal_chat_attempt_begin","session_run_id":id,"call":call}))?;
    assert_eq!(begun["kind"], "normal_chat_attempt_admitted");
    let duplicate =
        d.rpc(json!({"kind":"normal_chat_attempt_begin","session_run_id":id,"call":call}))?;
    assert_eq!(duplicate["kind"], "normal_chat_attempt_existing");
    assert_eq!(duplicate["send_authorized"], false);
    let read=d.rpc(json!({"kind":"normal_chat_attempt_readback","session_run_id":id,"dispatch_intent_ref":"intent:ipc-one"}))?;
    assert_eq!(read["policy"]["state"], "consumed");
    let settle = json!({"kind":"normal_chat_attempt_settle","session_run_id":id,"dispatch_intent_ref":"intent:ipc-one",
        "preflight_receipt_digest":begun["preflight_receipt_digest"],"report":{"schema":"recursive-agent.normal-chat-executor-report/v2","state":"not_sent","duration_ms":0,"response":null,"usage":null}});
    let settled = d.rpc(settle.clone())?;
    assert_eq!(settled["kind"], "normal_chat_attempt_settled");
    assert_eq!(settled, d.rpc(settle)?);
    let read=d.rpc(json!({"kind":"normal_chat_attempt_readback","session_run_id":id,"dispatch_intent_ref":"intent:ipc-one"}))?;
    assert_eq!(read["policy"]["state"], "settled");
    let closed = d.rpc(
        json!({"kind":"normal_chat_run_close","session_run_id":id,"reason":"session_finalized"}),
    )?;
    assert_eq!(closed["kind"], "normal_chat_run_closed");
    let run = recursive_agent_contracts::CurrentRunId::try_new(id.as_str().ok_or("run absent")?)?;
    let root = d
        .home
        .path()
        .join("runs")
        .join(recursive_agent_contracts::content_digest(&run)?.to_string());
    let proof = recursive_agent_ledger::verify_directory_bound(
        &recursive_agent_ledger::RunPaths::new(root),
    )?;
    assert!(proof.ok);
    Ok(())
}
