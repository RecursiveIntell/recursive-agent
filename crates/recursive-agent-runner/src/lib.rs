//! M0 runner. Walks the typed run spec, dispatches each step to the
//! tool plane, writes receipts to the chain, and persists results as
//! content-addressed artifacts.

use std::path::Path;

use chrono::Utc;
use recursive_agent_contracts::{
    content_digest, jcs_canonical, ContractError, ReceiptKindV1, ReceiptOutcomeV1, ReceiptV1,
    RunSpecV1, StepSpecV1,
};
use recursive_agent_ledger::{
    ensure_dir, make_receipt, open, put_string, ArtifactStore, ChainHandle, LedgerError, RunPaths,
};
use recursive_agent_policy::{build_lineage, issue_permit, Allowlist, PolicyError};
use recursive_agent_tools::execute as run_tool;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RunError {
    #[error("policy: {0}")]
    Policy(#[from] PolicyError),
    #[error("ledger: {0}")]
    Ledger(#[from] LedgerError),
    #[error("tool: {0}")]
    Tool(#[from] recursive_agent_tools::ToolError),
    #[error("contract: {0}")]
    Contract(#[from] ContractError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// A material run id. Generated once per run; carries the `run:` family
/// prefix. Uses `uuid::Uuid::new_v4()` for the underlying material; the
/// `run:` family is the M0 contract surface.
pub fn generate_run_id() -> String {
    let s = uuid::Uuid::new_v4();
    format!("run:{s}")
}

fn step_id_for(idx: usize, name: &str) -> String {
    // Step ids are family-qualified and per-run unique. They are not
    // material authority IDs, so a UUID v4 is acceptable here.
    let _ = (idx, name);
    let s = uuid::Uuid::new_v4();
    format!("step:{s}")
}

fn digest_receipt_id() -> String {
    // Receipt ids are family-qualified. The chain does not treat the
    // material identity of a receipt as authority; it is a per-process
    // handle. Authority is the `prev_chain_digest` chain and the lineage.
    let s = uuid::Uuid::new_v4();
    format!("rcpt:{s}")
}

/// Run a spec end to end. Returns the run summary.
pub fn run_spec(spec: &RunSpecV1, out_root: &Path) -> Result<RunSummary, RunError> {
    let allowlist = Allowlist::default();
    for step in &spec.steps {
        allowlist.authorize(spec, &step.name, &step.call)?;
    }

    let run_id = generate_run_id();
    let run_id_short = run_id.trim_start_matches("run:").to_string();
    let run_dir = out_root.join(&run_id_short);
    ensure_dir(&run_dir)?;
    let paths = RunPaths::new(run_dir.clone());
    paths.ensure()?;

    let mut chain = open(&paths)?;
    let store = ArtifactStore::new(&paths)?;

    // RunStarted.
    let spec_digest = content_digest(spec)?;
    let permit = issue_permit("run", "graph")?;
    let lineage = build_lineage(&permit, &allowlist.policy_version);
    let mut start = make_receipt(
        &digest_receipt_id(),
        &run_id,
        "step:graph-start",
        ReceiptKindV1::RunStarted,
        lineage,
        spec_digest.clone(),
        spec_digest.clone(),
        vec![],
        ReceiptOutcomeV1::Ok,
    )?;
    start.prev_chain_digest = chain.head().clone();
    chain.append(start)?;

    for (idx, step) in spec.steps.iter().enumerate() {
        run_step(
            &mut chain,
            &store,
            spec,
            &run_id,
            &run_id_short,
            idx,
            step,
            &allowlist,
        )?;
    }

    // RunFinalized.
    let final_digest = spec_digest.clone();
    let lineage = build_lineage(&permit, &allowlist.policy_version);
    let mut end = make_receipt(
        &digest_receipt_id(),
        &run_id,
        "step:graph-end",
        ReceiptKindV1::RunFinalized,
        lineage,
        spec_digest,
        final_digest,
        vec![],
        ReceiptOutcomeV1::Ok,
    )?;
    end.prev_chain_digest = chain.head().clone();
    chain.append(end)?;

    let head = chain.head().to_string();
    let length = chain.length();
    Ok(RunSummary {
        run_id,
        run_dir,
        chain_length: length,
        chain_head: head,
    })
}

#[derive(Debug, Clone)]
pub struct RunSummary {
    pub run_id: String,
    pub run_dir: std::path::PathBuf,
    pub chain_length: u64,
    pub chain_head: String,
}

#[allow(clippy::too_many_arguments)]
fn run_step(
    chain: &mut ChainHandle,
    store: &ArtifactStore,
    spec: &RunSpecV1,
    run_id: &str,
    run_id_short: &str,
    idx: usize,
    step: &StepSpecV1,
    allowlist: &Allowlist,
) -> Result<(), RunError> {
    let spec_digest = content_digest(&step.call)?;
    let permit = issue_permit(run_id_short, &step.call.tool)?;
    let lineage = build_lineage(&permit, &allowlist.policy_version);
    let step_id = step_id_for(idx, &step.name);
    let mut start = make_receipt(
        &digest_receipt_id(),
        run_id,
        &format!("step:{step_id}"),
        ReceiptKindV1::StepStarted,
        lineage,
        spec_digest.clone(),
        content_digest(&step.call.args)?,
        vec![],
        ReceiptOutcomeV1::Ok,
    )?;
    start.prev_chain_digest = chain.head().clone();
    chain.append(start)?;

    let result = run_tool(&step.call);
    match result {
        Ok(body) => {
            let body_text = serde_json::to_string(&body)?;
            let artifact_id = put_string(store, &body_text)?;
            let args_digest = content_digest(&step.call.args)?;
            let lineage = build_lineage(&permit, &allowlist.policy_version);
            let mut done = make_receipt(
                &digest_receipt_id(),
                run_id,
                &format!("step:{step_id}"),
                ReceiptKindV1::StepCompleted,
                lineage,
                spec_digest,
                args_digest,
                vec![artifact_id],
                ReceiptOutcomeV1::Ok,
            )?;
            done.prev_chain_digest = chain.head().clone();
            chain.append(done)?;
        }
        Err(e) => {
            let args_digest = content_digest(&step.call.args)?;
            let lineage = build_lineage(&permit, &allowlist.policy_version);
            let mut failed = make_receipt(
                &digest_receipt_id(),
                run_id,
                &format!("step:{step_id}"),
                ReceiptKindV1::StepFailed,
                lineage,
                spec_digest,
                args_digest,
                vec![],
                ReceiptOutcomeV1::Failed {
                    reason: e.to_string(),
                },
            )?;
            failed.prev_chain_digest = chain.head().clone();
            chain.append(failed)?;
        }
    }
    let _ = spec;
    Ok(())
}

/// Deterministic replay: read all receipts from disk, verify the chain,
/// and re-emit each artifact. The replay never re-executes the tool.
pub fn replay(paths: &RunPaths) -> Result<ReplaySummary, RunError> {
    let v = recursive_agent_ledger::verify(paths)?;
    let text = std::fs::read_to_string(paths.receipts_path())?;
    let mut artifacts = Vec::new();
    let mut step_results = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let r: ReceiptV1 = serde_json::from_str(line)?;
        for a in &r.artifact_refs {
            if !artifacts.contains(a) {
                artifacts.push(a.clone());
            }
        }
        step_results.push(ReplayStep {
            step_id: r.step_id.clone(),
            kind: format!("{:?}", r.kind),
            outcome: format!("{:?}", r.outcome),
            artifact_refs: r.artifact_refs.clone(),
        });
    }
    let _ = jcs_canonical(&Utc::now()); // ensure dep used
    Ok(ReplaySummary {
        ok: v.ok,
        length: v.length,
        final_head: v.final_head,
        step_results,
        artifacts,
    })
}

#[derive(Debug, Clone)]
pub struct ReplaySummary {
    pub ok: bool,
    pub length: u64,
    pub final_head: String,
    pub step_results: Vec<ReplayStep>,
    pub artifacts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ReplayStep {
    pub step_id: String,
    pub kind: String,
    pub outcome: String,
    pub artifact_refs: Vec<String>,
}
