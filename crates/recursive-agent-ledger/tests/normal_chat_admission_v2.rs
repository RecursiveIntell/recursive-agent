use chrono::{DateTime, TimeDelta, Utc};
use recursive_agent_contracts::{
    content_digest, jcs_canonical, ContentDigest, CurrentReceiptId, ReceiptKindV1, ReceiptOutcomeV1,
};
use recursive_agent_ledger::{
    appendable_snapshot_expected_run_from_dir_fd, make_receipt, open_from_dir_fd, ArtifactStore,
    ChainHandle, ReceiptDraftV1, RunPaths,
};
use recursive_agent_policy::{
    build_lineage, parse_normal_chat_ledger_admission_v2_bytes, DurablePermitStore,
    FamilyAuthorityStore, NormalChatAttemptBeginV2, NormalChatEgressGrantStore,
    NormalChatEgressGrantV1, NormalChatFamilyReservationRequestV2,
    NormalChatLedgerAdmissionEvidenceV2, PermitBudgetV1, PermitEvidenceStateV1, PermitEvidenceV1,
};
use serde_json::json;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
#[path = "support/normal_chat_admission_v2_negatives.rs"]
mod negatives;
#[path = "support/normal_chat_recovery_v1.rs"]
mod recovery;
#[path = "support/normal_chat_terminal_v2.rs"]
mod terminal;
#[path = "support/normal_chat_admission_v2_wire.rs"]
mod wire;
const HOME: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn now() -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_792_008_000)
}
fn private_root() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
    Ok(root)
}
struct Fixture {
    _grant: tempfile::TempDir,
    _parent: tempfile::TempDir,
    child: tempfile::TempDir,
    family: FamilyAuthorityStore,
    permits: DurablePermitStore,
    proof: NormalChatLedgerAdmissionEvidenceV2,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_delay(0)
    }
    fn new_with_delay(delay_ms: i64) -> Result<Self, Box<dyn std::error::Error>> {
        let grant_root = private_root()?;
        let mut grant: NormalChatEgressGrantV1 = serde_json::from_value(json!({
            "schema":"recursive-agent.normal-chat-egress-grant/v1", "revision":1,
            "ares_home_digest":HOME, "mode":"enforce", "any_route":false,
            "routes":[{"provider_identity":"openai_compatible:https://provider.test/v1", "model_ref":"model:fixture", "api_mode":"chat_completions"}],
            "caps":{"max_attempts":3,"max_output_tokens":100,"max_wall_time_ms":1000,"max_request_bytes":4096},
            "expires_at":now()+TimeDelta::seconds(600), "content_retention":"digest_only", "policy_digest":HOME
        }))?;
        grant.policy_digest = grant.computed_policy_digest()?;
        let grant_path = grant_root.path().join("grant.json");
        fs::write(&grant_path, serde_json::to_vec(&grant)?)?;
        fs::set_permissions(&grant_path, fs::Permissions::from_mode(0o600))?;
        let authority = NormalChatEgressGrantStore::from_dir_fd(&File::open(grant_root.path())?)?
            .load_from_path(&grant_path, HOME, now())?;
        let parent = private_root()?;
        let parent_root = File::open(parent.path())?;
        let parent_permits = DurablePermitStore::from_run_root_fd(&parent_root)?;
        let control = parent_permits.open_normal_chat_session_control(
            &authority,
            "conversation:fixture",
            None,
            now,
        )?;
        let guarded = FamilyAuthorityStore::from_normal_chat_session_control(
            &parent_root,
            &authority,
            &control,
            now,
        )?;
        let operation = recursive_agent_contracts::parse_normal_chat_operation_v2_bytes(
            &serde_json::to_vec(&json!({
                "schema":"recursive-agent.normal-chat/v2", "conversation_ref":"conversation:fixture", "parent_run_id":control.session().run_id()?,
                "materialization_ref":"materialization:fixture", "materialization_digest":HOME,
                "policy_basis_ref":"normal-chat-grant:revision-1", "policy_basis_digest":grant.policy_digest,
                "source_revision":"source:fixture", "route_class":"conversation", "provider_identity":"openai_compatible:https://provider.test/v1", "model_ref":"model:fixture", "api_mode":"chat_completions",
                "request_digest":HOME, "request_projection_schema":"ares-json-sorted-v1", "budget":{"output_reserve":10,"max_wall_time_ms":1000,"max_request_bytes":4096}, "replay":"unavailable",
                "provenance":[{"source":"urn:test:fixture", "digest":content_digest(&"fixture")?}]
            }))?,
        )?;
        guarded.reserve_normal_chat_attempt(
            &authority,
            &NormalChatFamilyReservationRequestV2 {
                operation,
                provider_request_digest: ContentDigest::compute(b"physical-body"),
                provider_request_bytes: b"physical-body".len() as u64,
                dispatch_intent_ref: "intent:fixture".into(),
                // Parent receipt correlation only: this fixture verifies a child
                // prefix, not a full parent link or cumulative family ledger.
                parent_admission_receipt_id: CurrentReceiptId::try_new(format!(
                    "v1:recursive-agent/receipt/v1:det:{}",
                    "c".repeat(64)
                ))?,
                requested_budget: PermitBudgetV1 {
                    max_wall_time_ms: 1000,
                    max_output_bytes: 1024 * 1024,
                    max_artifact_bytes: 1024 * 1024,
                },
            },
            now,
        )?;
        let family = FamilyAuthorityStore::from_dir_fd(&parent_root, control.family_grant())?;
        let child = private_root()?;
        let permits = DurablePermitStore::from_run_root_fd(&File::open(child.path())?)?;
        let cap = match permits.begin_normal_chat_attempt_v2(
            &authority,
            &guarded,
            "intent:fixture",
            || now() + TimeDelta::milliseconds(delay_ms),
        )? {
            NormalChatAttemptBeginV2::Consumed(cap) => cap,
            NormalChatAttemptBeginV2::Existing(_) => {
                return Err("expected fresh native consumption".into())
            }
        };
        let proof = cap.ledger_evidence()?;
        Ok(Self {
            _grant: grant_root,
            _parent: parent,
            child,
            family,
            permits,
            proof,
        })
    }
    fn chain(&self) -> Result<ChainHandle, Box<dyn std::error::Error>> {
        Ok(open_from_dir_fd(
            &RunPaths::new(self.child.path()),
            &File::open(self.child.path())?,
        )?)
    }
    fn prefix(&self, with_admission: bool) -> Result<ChainHandle, Box<dyn std::error::Error>> {
        let mut chain = self.chain()?;
        let store = chain.artifact_store()?;
        let control = self.proof.control_evidence()?;
        let effect = self.proof.issued_effect_evidence()?;
        append(&mut chain, &control, ReceiptKindV1::RunStarted, vec![])?;
        append(&mut chain, &control, ReceiptKindV1::StepStarted, vec![])?;
        append(
            &mut chain,
            &control,
            ReceiptKindV1::PermitIssued,
            vec![put(&store, &control)?],
        )?;
        append(&mut chain, &effect, ReceiptKindV1::StepStarted, vec![])?;
        if with_admission {
            admission(&mut chain, &self.proof, put(&store, &self.proof)?)?;
        }
        Ok(chain)
    }
}
fn put<T: serde::Serialize>(
    store: &ArtifactStore,
    value: &T,
) -> Result<recursive_agent_contracts::ArtifactDescriptorV1, Box<dyn std::error::Error>> {
    Ok(store.put(&jcs_canonical(value)?, "application/json", None)?)
}
fn append(
    chain: &mut ChainHandle,
    evidence: &PermitEvidenceV1,
    kind: ReceiptKindV1,
    artifacts: Vec<recursive_agent_contracts::ArtifactDescriptorV1>,
) -> TestResult {
    let time = match evidence.state {
        PermitEvidenceStateV1::Consumed { at }
        | PermitEvidenceStateV1::Revoked { at, .. }
        | PermitEvidenceStateV1::Rejected { at, .. } => at,
        _ => evidence.binding.issued_at,
    };
    let row = make_receipt(
        ReceiptDraftV1 {
            run_id: evidence.binding.run_id.clone(),
            step_id: evidence.binding.step_id.clone(),
            kind,
            valid_time: time,
            lineage: build_lineage(&evidence.permit_id, &evidence.binding.policy_version),
            spec_digest: evidence.binding.action_digest.clone(),
            args_digest: evidence.binding.args_digest.clone(),
            artifact_refs: artifacts,
            outcome: ReceiptOutcomeV1::Ok,
        },
        chain.head().clone(),
    )?;
    chain.append(row)?;
    Ok(())
}
fn admission(
    chain: &mut ChainHandle,
    proof: &NormalChatLedgerAdmissionEvidenceV2,
    descriptor: recursive_agent_contracts::ArtifactDescriptorV1,
) -> TestResult {
    let evidence = &proof.preflight.evidence;
    let row = make_receipt(
        ReceiptDraftV1 {
            run_id: evidence.binding.run_id.clone(),
            step_id: evidence.binding.step_id.clone(),
            kind: ReceiptKindV1::NormalChatAttemptAdmittedV2,
            valid_time: proof.preflight.recorded_at,
            lineage: build_lineage(&evidence.permit_id, &evidence.binding.policy_version),
            spec_digest: evidence.binding.action_digest.clone(),
            args_digest: evidence.binding.args_digest.clone(),
            artifact_refs: vec![descriptor],
            outcome: ReceiptOutcomeV1::Ok,
        },
        chain.head().clone(),
    )?;
    chain.append(row)?;
    Ok(())
}

#[test]
fn real_native_consumption_has_a_strictly_verifiable_v2_child_prefix() -> TestResult {
    let fx = Fixture::new()?;
    let mut chain = fx.prefix(true)?;
    let store = chain.artifact_store()?;
    let issued = fx.proof.issued_effect_evidence()?;
    append(
        &mut chain,
        &issued,
        ReceiptKindV1::PermitIssued,
        vec![put(&store, &issued)?],
    )?;
    append(
        &mut chain,
        &fx.proof.preflight.evidence,
        ReceiptKindV1::PermitConsumed,
        vec![put(&store, &fx.proof.preflight.evidence)?],
    )?;
    let snapshot = appendable_snapshot_expected_run_from_dir_fd(
        &File::open(fx.child.path())?,
        &issued.binding.run_id,
    )?;
    assert_eq!(snapshot.receipts().len(), 7);
    assert!(!snapshot.verification().current_strict_success);
    assert!(matches!(
        recursive_agent_contracts::project_runtime_events(snapshot.receipts())?[4].kind,
        recursive_agent_contracts::RuntimeEventKindV1::NormalChatAttemptAdmittedV2 { .. }
    ));
    assert!(!String::from_utf8(jcs_canonical(&fx.proof)?)?.contains("physical-body"));
    Ok(())
}

#[test]
fn missing_v2_admission_still_denies_network_effect_issuance() -> TestResult {
    let fx = Fixture::new()?;
    let mut chain = fx.prefix(false)?;
    let store = chain.artifact_store()?;
    let issued = fx.proof.issued_effect_evidence()?;
    let before = chain.head().clone();
    assert!(append(
        &mut chain,
        &issued,
        ReceiptKindV1::PermitIssued,
        vec![put(&store, &issued)?]
    )
    .is_err());
    assert_eq!(chain.head(), &before);
    Ok(())
}

#[test]
fn strict_evidence_ingress_and_canonical_historical_readback() -> TestResult {
    let fx = Fixture::new()?;
    let canonical = jcs_canonical(&fx.proof)?;
    assert_eq!(
        parse_normal_chat_ledger_admission_v2_bytes(&canonical)?,
        fx.proof
    );
    assert_eq!(
        fx.permits
            .read_normal_chat_ledger_admission_v2(&fx.family, "intent:fixture")?,
        Some(fx.proof.clone())
    );
    let mut unknown = serde_json::to_value(&fx.proof)?;
    unknown["authority"] = json!("client-granted");
    assert!(parse_normal_chat_ledger_admission_v2_bytes(&serde_json::to_vec(&unknown)?).is_err());
    let duplicate = format!(
        "{{\"schema\":\"duplicate\",{}",
        String::from_utf8(canonical)?[1..].to_owned()
    );
    assert!(parse_normal_chat_ledger_admission_v2_bytes(duplicate.as_bytes()).is_err());
    assert!(parse_normal_chat_ledger_admission_v2_bytes(&vec![b' '; 1_048_577]).is_err());
    Ok(())
}
