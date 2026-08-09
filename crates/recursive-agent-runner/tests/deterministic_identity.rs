mod support;

use recursive_agent_contracts::{
    content_digest, derive_artifact_id, derive_permit_id, ArtifactDescriptorV1,
    AuthorityLineageEntryV1, LineageOrigin, PermitIdentityMaterialV1, ReceiptKindV1,
    ReceiptOutcomeV1, RunSpecV1, StepSpecV1, ToolCallSpecV1,
};
use recursive_agent_runner::Clock;
use support::{run_spec, run_spec_with_clock};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn spec(text: &str) -> RunSpecV1 {
    RunSpecV1 {
        name: "identity".into(),
        steps: vec![StepSpecV1 {
            name: "echo".into(),
            call: ToolCallSpecV1 {
                tool: "echo".into(),
                args: serde_json::json!({"text": text}),
                frozen_clock: None,
            },
        }],
        frozen_clock: None,
        policy_version: "m0-2".into(),
    }
}

fn permit_material(label: &str) -> Result<PermitIdentityMaterialV1, Box<dyn std::error::Error>> {
    Ok(PermitIdentityMaterialV1 {
        binding_digest: content_digest(&label)?,
        requested_not_before_delay_ms: 0,
        requested_validity_ms: 1_000,
    })
}

#[test]
fn ids_are_stable_across_processes() -> TestResult {
    let executable = std::env::current_exe()?;
    let probe = || -> Result<String, Box<dyn std::error::Error>> {
        let output = std::process::Command::new(&executable)
            .args(["--exact", "process_identity_probe", "--nocapture"])
            .env("RECURSIVE_AGENT_ID_PROBE", "1")
            .output()?;
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout)?;
        let identity = stdout
            .lines()
            .find_map(|line| line.strip_prefix("IDENTITY_PROBE="))
            .ok_or("identity probe marker missing")?
            .to_string();
        Ok(identity)
    };
    assert_eq!(probe()?, probe()?);
    Ok(())
}

#[test]
fn process_identity_probe() -> TestResult {
    if std::env::var_os("RECURSIVE_AGENT_ID_PROBE").is_none() {
        return Ok(());
    }
    let run_spec = spec("same");
    let run_id = recursive_agent_contracts::derive_run_id(&run_spec)?;
    let first_step = run_spec.steps.first().ok_or("identity spec has no step")?;
    let step_id =
        recursive_agent_contracts::derive_step_id(&run_id, 0, &first_step.name, &first_step.call)?;
    let predecessor = recursive_agent_contracts::ContentDigest::compute(b"fixed predecessor");
    let permit = derive_permit_id(&permit_material("probe")?)?;
    let lineage = lineage(permit);
    let spec_digest = content_digest(&run_spec)?;
    let args_digest = content_digest(&first_step.call.args)?;
    let receipt_id = recursive_agent_contracts::derive_receipt_id(
        &recursive_agent_contracts::ReceiptIdentityMaterialV1 {
            run_id: &run_id,
            step_id: &step_id,
            kind: &ReceiptKindV1::StepCompleted,
            lineage: &lineage,
            spec_digest: &spec_digest,
            args_digest: &args_digest,
            outcome: &ReceiptOutcomeV1::Ok,
            artifact_refs: &[],
            predecessor_chain_digest: &predecessor,
        },
    )?;
    assert_eq!(
        run_id.as_str(),
        "v1:recursive-agent/run/v1:det:c38abdfd083f535830a6131e7249c9bc1c2f4204ca8629d6784adb0553b3a781"
    );
    assert_eq!(
        step_id.as_str(),
        "v1:recursive-agent/step/v1:det:433ca03f0ccad68c4da232add29e049886a1cb61868cb1ab33f49d6f6604701f"
    );
    assert_eq!(
        receipt_id.as_str(),
        "v1:recursive-agent/receipt/v1:det:717174c5a3bc175818c01a2ed044e05b7aa8735e4fc0afa5b680c21d70fe855e"
    );
    println!(
        "IDENTITY_PROBE={}",
        serde_json::json!({
            "run_id": run_id,
            "step_id": step_id,
            "receipt_id": receipt_id,
        })
    );
    Ok(())
}

fn lineage(permit: recursive_agent_contracts::CurrentPermitId) -> Vec<AuthorityLineageEntryV1> {
    [
        LineageOrigin::Request,
        LineageOrigin::Plan,
        LineageOrigin::Policy,
        LineageOrigin::Tool,
        LineageOrigin::Effect,
    ]
    .into_iter()
    .map(|origin| AuthorityLineageEntryV1 {
        origin,
        principal: "identity-test".into(),
        permit_id: Some(permit.clone()),
        policy_version: "m0-2".into(),
    })
    .collect()
}

#[test]
fn every_semantic_receipt_field_changes_identity() -> TestResult {
    let first_spec = spec("left");
    let second_spec = spec("right");
    let run = recursive_agent_contracts::derive_run_id(&first_spec)?;
    let other_run = recursive_agent_contracts::derive_run_id(&second_spec)?;
    let call = &first_spec.steps[0].call;
    let step = recursive_agent_contracts::derive_step_id(&run, 0, "echo", call)?;
    let other_step = recursive_agent_contracts::derive_step_id(&run, 1, "echo", call)?;
    let permit = derive_permit_id(&permit_material("permit")?)?;
    let base_lineage = lineage(permit);
    let spec_digest = content_digest(&first_spec)?;
    let args_digest = content_digest(&call.args)?;
    let artifact_bytes = b"artifact";
    let artifact = ArtifactDescriptorV1 {
        owner_id: derive_artifact_id(artifact_bytes)?,
        digest: recursive_agent_contracts::ContentDigest::compute(artifact_bytes),
        byte_length: artifact_bytes.len() as u64,
        media_type: "text/plain".into(),
        encoding: Some("utf-8".into()),
    };
    let predecessor = recursive_agent_contracts::ContentDigest::compute(b"predecessor");
    let identity = |run, step, kind, lineage, spec, args, outcome, artifacts, predecessor| {
        recursive_agent_contracts::derive_receipt_id(
            &recursive_agent_contracts::ReceiptIdentityMaterialV1 {
                run_id: run,
                step_id: step,
                kind,
                lineage,
                spec_digest: spec,
                args_digest: args,
                outcome,
                artifact_refs: artifacts,
                predecessor_chain_digest: predecessor,
            },
        )
    };
    let base = identity(
        &run,
        &step,
        &ReceiptKindV1::StepCompleted,
        &base_lineage,
        &spec_digest,
        &args_digest,
        &ReceiptOutcomeV1::Ok,
        std::slice::from_ref(&artifact),
        &predecessor,
    )?;
    let other_spec_digest = content_digest(&second_spec)?;
    let other_args_digest = content_digest(&serde_json::json!({"text": "changed"}))?;
    let other_predecessor = recursive_agent_contracts::ContentDigest::compute(b"other predecessor");
    let mut other_lineage = base_lineage.clone();
    other_lineage[0].principal = "other-principal".into();
    let cases = [
        identity(
            &other_run,
            &step,
            &ReceiptKindV1::StepCompleted,
            &base_lineage,
            &spec_digest,
            &args_digest,
            &ReceiptOutcomeV1::Ok,
            std::slice::from_ref(&artifact),
            &predecessor,
        )?,
        identity(
            &run,
            &other_step,
            &ReceiptKindV1::StepCompleted,
            &base_lineage,
            &spec_digest,
            &args_digest,
            &ReceiptOutcomeV1::Ok,
            std::slice::from_ref(&artifact),
            &predecessor,
        )?,
        identity(
            &run,
            &step,
            &ReceiptKindV1::StepFailed,
            &base_lineage,
            &spec_digest,
            &args_digest,
            &ReceiptOutcomeV1::Ok,
            std::slice::from_ref(&artifact),
            &predecessor,
        )?,
        identity(
            &run,
            &step,
            &ReceiptKindV1::StepCompleted,
            &other_lineage,
            &spec_digest,
            &args_digest,
            &ReceiptOutcomeV1::Ok,
            std::slice::from_ref(&artifact),
            &predecessor,
        )?,
        identity(
            &run,
            &step,
            &ReceiptKindV1::StepCompleted,
            &base_lineage,
            &other_spec_digest,
            &args_digest,
            &ReceiptOutcomeV1::Ok,
            std::slice::from_ref(&artifact),
            &predecessor,
        )?,
        identity(
            &run,
            &step,
            &ReceiptKindV1::StepCompleted,
            &base_lineage,
            &spec_digest,
            &other_args_digest,
            &ReceiptOutcomeV1::Ok,
            std::slice::from_ref(&artifact),
            &predecessor,
        )?,
        identity(
            &run,
            &step,
            &ReceiptKindV1::StepCompleted,
            &base_lineage,
            &spec_digest,
            &args_digest,
            &ReceiptOutcomeV1::Failed { reason: "x".into() },
            std::slice::from_ref(&artifact),
            &predecessor,
        )?,
        identity(
            &run,
            &step,
            &ReceiptKindV1::StepCompleted,
            &base_lineage,
            &spec_digest,
            &args_digest,
            &ReceiptOutcomeV1::Ok,
            &[],
            &predecessor,
        )?,
        identity(
            &run,
            &step,
            &ReceiptKindV1::StepCompleted,
            &base_lineage,
            &spec_digest,
            &args_digest,
            &ReceiptOutcomeV1::Ok,
            std::slice::from_ref(&artifact),
            &other_predecessor,
        )?,
    ];
    assert!(cases.iter().all(|changed| changed != &base));
    Ok(())
}

#[test]
fn changed_material_changes_id() -> TestResult {
    let left = tempfile::tempdir()?;
    let right = tempfile::tempdir()?;
    let first = run_spec(&spec("left"), left.path())?;
    let second = run_spec(&spec("right"), right.path())?;
    assert_ne!(first.run_id, second.run_id);
    Ok(())
}

#[derive(Clone, Copy)]
struct FixedClock(chrono::DateTime<chrono::Utc>);

impl Clock for FixedClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.0
    }
}

#[test]
fn runner_clock_owns_lease_time_while_permit_identity_excludes_live_issue_time() -> TestResult {
    let first_root = tempfile::tempdir()?;
    let second_root = tempfile::tempdir()?;
    let mut request = spec("clock-owned");
    request.frozen_clock = chrono::DateTime::from_timestamp(100, 0);
    let first_now = chrono::DateTime::from_timestamp(1_800_000_000, 0).ok_or("first clock")?;
    let second_now = first_now + chrono::TimeDelta::seconds(10);
    let first = run_spec_with_clock(&request, first_root.path(), FixedClock(first_now))?;
    let second = run_spec_with_clock(&request, second_root.path(), FixedClock(second_now))?;
    let read = |path: &std::path::Path| -> Result<
        Vec<recursive_agent_contracts::ReceiptV1>,
        Box<dyn std::error::Error>,
    > {
        Ok(std::fs::read_to_string(path.join("receipts.ndjson"))?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?)
    };
    let first_receipts = read(&first.run_dir)?;
    let second_receipts = read(&second.run_dir)?;
    assert_eq!(first_receipts[0].valid_time, first_now);
    assert_eq!(second_receipts[0].valid_time, second_now);
    let permit = |receipts: &[recursive_agent_contracts::ReceiptV1]| {
        receipts
            .iter()
            .find(|receipt| matches!(receipt.kind, ReceiptKindV1::PermitIssued))
            .and_then(|receipt| {
                receipt
                    .lineage
                    .iter()
                    .find_map(|entry| entry.permit_id.clone())
            })
    };
    assert_eq!(permit(&first_receipts), permit(&second_receipts));
    Ok(())
}

#[test]
fn production_identity_paths_do_not_invoke_uuid_random_or_time() -> TestResult {
    let runner = include_str!("../src/lib.rs");
    let policy = include_str!("../../recursive-agent-policy/src/lib.rs");
    let contracts = include_str!("../../recursive-agent-contracts/src/lib.rs");
    for source in [runner, policy, contracts] {
        let production = source
            .split("#[cfg(test)]")
            .next()
            .ok_or("production source section missing")?;
        assert!(!production.contains("Uuid::new_v4"));
        assert!(!production.contains("::random("));
        assert!(!production.contains("fn deterministic_suffix"));
    }
    let identity_contracts = contracts
        .split("/// One hop in the request-to-effect authority chain.")
        .next()
        .ok_or("identity contract boundary missing")?;
    assert!(!identity_contracts.contains("Utc::now"));
    let permit_identity = policy
        .split("impl PermitBindingV1")
        .nth(1)
        .and_then(|source| source.split("pub struct ExecutionPermitV1").next())
        .ok_or("permit identity boundary missing")?;
    assert!(!permit_identity.contains("Utc::now"));
    Ok(())
}
