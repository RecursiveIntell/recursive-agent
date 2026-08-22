//! Governed recursive autonomous execution over the native runner boundary.
//!
//! This module deliberately keeps proposal generation separate from execution. A
//! planner may be deterministic or model-backed, but the runner owns budgets,
//! cancellation, lineage, bounded memory/skill access, and an append-only,
//! restart-verifiable autonomy transcript. No provider or network call is made
//! implicitly.

use chrono::{DateTime, Utc};
use recursive_agent_contracts::{content_digest, CurrentReceiptId};
use recursive_agent_mcts::McstSearch;
use recursive_agent_memory::{MemoryEntry, MemoryProvenanceV1, MemoryStore};
use recursive_agent_provider::{CompletionBackend, CompletionRequestV1, ProviderSpecV1};
use recursive_agent_skills::{SkillId, SkillRegistry};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;

const AUTONOMY_DOMAIN: &str = "recursive-agent/autonomy/v1";
const MAX_INPUT_BYTES: usize = 256 * 1024;
const MAX_INTENTS_PER_PLAN: usize = 64;
const MAX_AUTONOMOUS_DEPTH: u32 = 8;
const MAX_AUTONOMOUS_STEPS: u32 = 64;
const MAX_AUTONOMOUS_CHILDREN: u32 = 16;
const MAX_AUTONOMOUS_WALL_TIME_MS: u64 = 300_000;
const MAX_AUTONOMOUS_OUTPUT_BYTES: u64 = 1024 * 1024;
/// Transcript recovery must never read an unbounded stream or an arbitrarily
/// large historical file into memory. Autonomous runs are step-bounded, so a
/// 4 MiB transcript ceiling leaves ample receipt headroom while keeping an
/// invalid device path or concurrent append from exhausting the host.
const MAX_TRANSCRIPT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousBudgetV1 {
    pub max_depth: u32,
    pub max_steps: u32,
    pub max_children: u32,
    pub max_wall_time_ms: u64,
    pub max_output_bytes: u64,
}

impl AutonomousBudgetV1 {
    pub fn validate(&self) -> Result<(), AutonomousError> {
        if self.max_depth == 0
            || self.max_steps == 0
            || self.max_children == 0
            || self.max_wall_time_ms == 0
            || self.max_output_bytes == 0
            || self.max_depth > MAX_AUTONOMOUS_DEPTH
            || self.max_steps > MAX_AUTONOMOUS_STEPS
            || self.max_children > MAX_AUTONOMOUS_CHILDREN
            || self.max_wall_time_ms > MAX_AUTONOMOUS_WALL_TIME_MS
            || self.max_output_bytes > MAX_AUTONOMOUS_OUTPUT_BYTES
        {
            return Err(AutonomousError::InvalidBudget);
        }
        Ok(())
    }

    fn attenuate(self) -> Self {
        Self {
            // The runner tracks aggregate usage globally. Child contexts
            // receive the same explicit operation ceiling so recursion can
            // reach the declared depth without accidentally comparing global
            // counters to a per-child half-budget.
            max_depth: self.max_depth,
            max_steps: self.max_steps,
            max_children: self.max_children,
            max_wall_time_ms: self.max_wall_time_ms,
            max_output_bytes: self.max_output_bytes,
        }
    }
}

#[derive(Debug, Default)]
pub struct AutonomousCancellation(AtomicBool);

impl AutonomousCancellation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomousActionV1 {
    Observe,
    Recall,
    Propose,
    Execute,
    Review,
    Delegate,
    Complete,
    Cancelled,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousIntentV1 {
    pub name: String,
    pub payload: serde_json::Value,
    #[serde(default)]
    pub delegate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousPlanV1 {
    /// Explicit terminal decision. Omission is rejected at the provider JSON
    /// boundary; a plan is never terminal merely because it has no intents.
    pub complete: bool,
    pub intents: Vec<AutonomousIntentV1>,
}

impl AutonomousPlanV1 {
    fn validate(&self) -> Result<(), AutonomousError> {
        match (self.complete, self.intents.is_empty()) {
            (true, true) | (false, false) => Ok(()),
            (true, false) => Err(AutonomousError::InvalidPlan(
                "complete plan must not contain intents".into(),
            )),
            (false, true) => Err(AutonomousError::InvalidPlan(
                "non-complete plan must contain at least one intent".into(),
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousContextV1 {
    pub run_id: String,
    pub parent_run_id: Option<String>,
    pub depth: u32,
    pub budget: AutonomousBudgetV1,
    pub input: serde_json::Value,
    pub recalled: Vec<MemoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousResultV1 {
    pub output: serde_json::Value,
    #[serde(default)]
    pub receipt: Option<CurrentReceiptId>,
}

pub trait AutonomousPlanner {
    fn propose(&self, context: &AutonomousContextV1) -> Result<AutonomousPlanV1, AutonomousError>;

    fn score(&self, _path: &[&str]) -> f64 {
        0.0
    }

    /// Secret-free planner metadata recorded alongside the normalized plan.
    /// Implementations must not return credentials or raw provider payloads.
    fn receipt_context(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
}

/// Model-backed planner boundary. The backend is injected so deterministic
/// tests can exercise malformed, unavailable, and valid model responses without
/// network access. Runtime callers must choose an explicit provider backend.
pub struct ModelAutonomousPlanner<'a, B> {
    backend: &'a B,
    provider: ProviderSpecV1,
    max_tokens: Option<u32>,
    last_model: std::sync::Mutex<Option<String>>,
}

impl<'a, B> ModelAutonomousPlanner<'a, B> {
    pub fn new(backend: &'a B, provider: ProviderSpecV1, max_tokens: Option<u32>) -> Self {
        Self {
            backend,
            provider,
            max_tokens,
            last_model: std::sync::Mutex::new(None),
        }
    }

    fn prompt(context: &AutonomousContextV1) -> Result<String, AutonomousError> {
        let envelope = serde_json::json!({
            "input": context.input,
            "recalled": context.recalled,
            "run_id": context.run_id,
            "parent_run_id": context.parent_run_id,
            "depth": context.depth,
            "budget": context.budget,
            "output_schema": {
                "complete": "boolean; true only when no more intents are required",
                "intents": [{
                    "name": "string",
                    "payload": "object containing a complete native operation envelope",
                    "delegate": "boolean"
                }]
            }
        });
        Ok("Return exactly one JSON plan object and nothing else. The response must have exactly two top-level keys: `complete` and `intents`; do not emit `input`, `recalled`, `run_id`, `parent_run_id`, `depth`, `budget`, `output_schema`, markdown, tool calls, or prose. `complete` is a boolean. If `complete` is true, `intents` must be []. If `complete` is false, `intents` must be a non-empty array of objects with exactly `name`, `payload`, and `delegate`. The JSON below is planner context, not a response template. If no supplied operation is safely executable, return {\"complete\":true,\"intents\":[]}. \nCONTEXT:\n"
            .to_owned()
            + &serde_json::to_string(&envelope)?)
    }
}

impl<B: CompletionBackend> AutonomousPlanner for ModelAutonomousPlanner<'_, B> {
    fn propose(&self, context: &AutonomousContextV1) -> Result<AutonomousPlanV1, AutonomousError> {
        let request = CompletionRequestV1 {
            provider: self.provider.clone(),
            prompt: Self::prompt(context)?,
            max_tokens: self.max_tokens,
        };
        let response = self.backend.complete(&request)?;
        let mut model = self
            .last_model
            .lock()
            .map_err(|_| AutonomousError::Transcript("planner metadata lock poisoned".into()))?;
        *model = Some(response.model);
        serde_json::from_str(response.text.trim()).map_err(|error| {
            AutonomousError::InvalidPlan(format!("model response was not a JSON plan: {error}"))
        })
    }

    fn receipt_context(&self) -> serde_json::Value {
        let model = self.last_model.lock().ok().and_then(|value| value.clone());
        serde_json::json!({
            "kind": "model_planner",
            "provider": &self.provider,
            "model": model,
        })
    }
}

/// Closed JSON planner for callers that want a native, deterministic planning
/// lane without supplying a model callback. The input must contain either an
/// `intents` array or one `operation` object; no implicit tool or provider is
/// selected when the shape is absent.
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonAutonomousPlanner;

impl AutonomousPlanner for JsonAutonomousPlanner {
    fn propose(&self, context: &AutonomousContextV1) -> Result<AutonomousPlanV1, AutonomousError> {
        if let Some(intents) = context.input.get("intents") {
            let intents = serde_json::from_value(intents.clone())?;
            return Ok(AutonomousPlanV1 {
                complete: false,
                intents,
            });
        }
        if context.input.get("operation").is_some() {
            return Ok(AutonomousPlanV1 {
                complete: false,
                intents: vec![AutonomousIntentV1 {
                    name: "native_operation".into(),
                    payload: context.input.clone(),
                    delegate: false,
                }],
            });
        }
        Err(AutonomousError::InvalidPlan(
            "input must contain intents or operation".into(),
        ))
    }

    fn score(&self, _path: &[&str]) -> f64 {
        0.0
    }
}

pub trait AutonomousExecutor {
    fn execute(
        &self,
        context: &AutonomousContextV1,
        intent: &AutonomousIntentV1,
    ) -> Result<AutonomousResultV1, AutonomousError>;
}

#[derive(Debug, Error)]
pub enum AutonomousError {
    #[error("autonomous budget is invalid")]
    InvalidBudget,
    #[error("autonomous input exceeds the bounded material limit")]
    InputTooLarge,
    #[error("autonomous recursion depth or child budget exhausted")]
    RecursionLimit,
    #[error("autonomous step or output budget exhausted")]
    BudgetExceeded,
    #[error("autonomous execution cancelled")]
    Cancelled,
    #[error("autonomous plan is invalid: {0}")]
    InvalidPlan(String),
    #[error("autonomous transcript: {0}")]
    Transcript(String),
    #[error("memory: {0}")]
    Memory(#[from] recursive_agent_memory::MemoryError),
    #[error("contract: {0}")]
    Contract(#[from] recursive_agent_contracts::ContractError),
    #[error("skill: {0}")]
    Skill(#[from] recursive_agent_skills::SkillError),
    #[error("provider: {0}")]
    Provider(#[from] recursive_agent_provider::ProviderError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousReceiptV1 {
    pub sequence: u64,
    pub run_id: String,
    pub parent_run_id: Option<String>,
    pub depth: u32,
    pub action: AutonomousActionV1,
    pub payload_digest: String,
    pub output_digest: Option<String>,
    pub outcome: String,
    pub recorded_at: DateTime<Utc>,
    pub chain_digest: String,
}

#[derive(Debug, Serialize)]
struct ReceiptMaterial<'a> {
    sequence: u64,
    run_id: &'a str,
    parent_run_id: &'a Option<String>,
    depth: u32,
    action: AutonomousActionV1,
    payload_digest: &'a str,
    output_digest: &'a Option<String>,
    outcome: &'a str,
    recorded_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct AutonomousTranscript {
    path: PathBuf,
    file: File,
    next_sequence: u64,
    chain_digest: [u8; 32],
    stored_bytes: u64,
}

impl AutonomousTranscript {
    pub fn open(path: &Path) -> Result<Self, AutonomousError> {
        let mut next_sequence = 0_u64;
        let mut chain = [0_u8; 32];
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            return Err(AutonomousError::Transcript(
                "transcript path is not a regular file".into(),
            ));
        }
        if metadata.len() > MAX_TRANSCRIPT_BYTES {
            return Err(AutonomousError::Transcript(
                "transcript exceeds the recovery byte limit".into(),
            ));
        }
        let capacity = usize::try_from(metadata.len()).map_err(|_| {
            AutonomousError::Transcript(
                "transcript length does not fit memory address space".into(),
            )
        })?;
        let mut bytes = Vec::with_capacity(capacity);
        file.try_clone()?
            .take(MAX_TRANSCRIPT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_TRANSCRIPT_BYTES {
            return Err(AutonomousError::Transcript(
                "transcript exceeds the recovery byte limit".into(),
            ));
        }
        // A process can stop between the receipt write and the newline. Drop
        // only that incomplete final record; a complete, newline-terminated
        // malformed record remains a hard divergence.
        if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
            let truncate_at = bytes
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |index| index + 1);
            file.set_len(truncate_at as u64)?;
            file.sync_data()?;
            bytes.truncate(truncate_at);
        }
        for line in bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let line = std::str::from_utf8(line)
                .map_err(|error| AutonomousError::Transcript(error.to_string()))?;
            let receipt: AutonomousReceiptV1 = serde_json::from_str(line)?;
            if receipt.sequence != next_sequence {
                return Err(AutonomousError::Transcript(
                    "non-contiguous sequence".into(),
                ));
            }
            let expected = receipt_chain(chain, &receipt)?;
            if receipt.chain_digest != hex::encode(expected) {
                return Err(AutonomousError::Transcript("chain divergence".into()));
            }
            chain = expected;
            next_sequence = next_sequence
                .checked_add(1)
                .ok_or_else(|| AutonomousError::Transcript("sequence overflow".into()))?;
        }
        let stored_bytes = u64::try_from(bytes.len()).map_err(|_| {
            AutonomousError::Transcript("transcript length does not fit u64".into())
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            next_sequence,
            chain_digest: chain,
            stored_bytes,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &mut self,
        run_id: String,
        parent_run_id: Option<String>,
        depth: u32,
        action: AutonomousActionV1,
        payload: &serde_json::Value,
        output: Option<&serde_json::Value>,
        outcome: &str,
    ) -> Result<AutonomousReceiptV1, AutonomousError> {
        let payload_digest = content_digest(payload)?.hex().to_owned();
        let output_digest = output
            .map(content_digest)
            .transpose()?
            .map(|digest| digest.hex().to_owned());
        let mut receipt = AutonomousReceiptV1 {
            sequence: self.next_sequence,
            run_id,
            parent_run_id,
            depth,
            action,
            payload_digest,
            output_digest,
            outcome: outcome.to_owned(),
            recorded_at: Utc::now(),
            chain_digest: String::new(),
        };
        let chain = receipt_chain(self.chain_digest, &receipt)?;
        receipt.chain_digest = hex::encode(chain);
        let bytes = serde_json::to_vec(&receipt)?;
        let bytes_with_newline = u64::try_from(bytes.len())
            .map_err(|_| AutonomousError::Transcript("receipt length does not fit u64".into()))?
            .checked_add(1)
            .ok_or_else(|| AutonomousError::Transcript("receipt length overflow".into()))?;
        let next_stored_bytes = self
            .stored_bytes
            .checked_add(bytes_with_newline)
            .ok_or_else(|| AutonomousError::Transcript("transcript length overflow".into()))?;
        if next_stored_bytes > MAX_TRANSCRIPT_BYTES {
            return Err(AutonomousError::Transcript(
                "transcript append exceeds the recovery byte limit".into(),
            ));
        }
        self.file.write_all(&bytes)?;
        self.file.write_all(b"\n")?;
        self.file.sync_data()?;
        self.chain_digest = chain;
        self.stored_bytes = next_stored_bytes;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| AutonomousError::Transcript("sequence overflow".into()))?;
        Ok(receipt)
    }
}

fn receipt_chain(
    previous: [u8; 32],
    receipt: &AutonomousReceiptV1,
) -> Result<[u8; 32], AutonomousError> {
    let material = ReceiptMaterial {
        sequence: receipt.sequence,
        run_id: &receipt.run_id,
        parent_run_id: &receipt.parent_run_id,
        depth: receipt.depth,
        action: receipt.action,
        payload_digest: &receipt.payload_digest,
        output_digest: &receipt.output_digest,
        outcome: &receipt.outcome,
        recorded_at: receipt.recorded_at,
    };
    let canonical = recursive_agent_contracts::jcs_canonical(&material)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&previous);
    hasher.update(&canonical);
    Ok(*hasher.finalize().as_bytes())
}

pub struct AutonomousRunner<'a> {
    memory: &'a MemoryStore,
    skills: Option<&'a SkillRegistry>,
    transcript: AutonomousTranscript,
    budget: AutonomousBudgetV1,
    cancellation: &'a AutonomousCancellation,
    started: Instant,
    steps: u32,
    children: u32,
    output_bytes: u64,
}

impl<'a> AutonomousRunner<'a> {
    pub fn new(
        memory: &'a MemoryStore,
        skills: Option<&'a SkillRegistry>,
        transcript: AutonomousTranscript,
        budget: AutonomousBudgetV1,
        cancellation: &'a AutonomousCancellation,
    ) -> Result<Self, AutonomousError> {
        budget.validate()?;
        Ok(Self {
            memory,
            skills,
            transcript,
            budget,
            cancellation,
            started: Instant::now(),
            steps: 0,
            children: 0,
            output_bytes: 0,
        })
    }

    pub fn transcript(&self) -> &AutonomousTranscript {
        &self.transcript
    }

    pub fn run<P: AutonomousPlanner, E: AutonomousExecutor>(
        &mut self,
        input: serde_json::Value,
        planner: &P,
        executor: &E,
    ) -> Result<AutonomousResultV1, AutonomousError> {
        let bytes = serde_json::to_vec(&input)?;
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(AutonomousError::InputTooLarge);
        }
        self.run_node(input, None, 0, self.budget, planner, executor)
    }

    fn run_node<P: AutonomousPlanner, E: AutonomousExecutor>(
        &mut self,
        input: serde_json::Value,
        parent_run_id: Option<String>,
        depth: u32,
        budget: AutonomousBudgetV1,
        planner: &P,
        executor: &E,
    ) -> Result<AutonomousResultV1, AutonomousError> {
        let run_id = content_digest(&(AUTONOMY_DOMAIN, &parent_run_id, depth, &input))?
            .hex()
            .to_owned();
        let result = self.run_node_inner(
            input,
            parent_run_id.clone(),
            depth,
            budget,
            planner,
            executor,
        );
        if let Err(error) = result {
            let action = if matches!(error, AutonomousError::Cancelled) {
                AutonomousActionV1::Cancelled
            } else {
                AutonomousActionV1::Rejected
            };
            let outcome = error.to_string();
            self.record(
                &run_id,
                parent_run_id,
                depth,
                action,
                &serde_json::Value::Null,
                None,
                &outcome,
            )?;
            return Err(error);
        }
        result
    }

    fn run_node_inner<P: AutonomousPlanner, E: AutonomousExecutor>(
        &mut self,
        input: serde_json::Value,
        parent_run_id: Option<String>,
        depth: u32,
        budget: AutonomousBudgetV1,
        planner: &P,
        executor: &E,
    ) -> Result<AutonomousResultV1, AutonomousError> {
        self.guard(budget, depth)?;
        let run_id = content_digest(&(AUTONOMY_DOMAIN, &parent_run_id, depth, &input))?
            .hex()
            .to_owned();
        self.record(
            &run_id,
            parent_run_id.clone(),
            depth,
            AutonomousActionV1::Observe,
            &input,
            None,
            "accepted",
        )?;
        let mut observed = AutonomousResultV1 {
            output: input.clone(),
            receipt: None,
        };
        loop {
            self.guard(budget, depth)?;
            let recalled = self
                .memory
                .search("autonomous", &observed.output.to_string(), 8)?;
            self.record(
                &run_id,
                parent_run_id.clone(),
                depth,
                AutonomousActionV1::Recall,
                &observed.output,
                None,
                "accepted",
            )?;
            let context = AutonomousContextV1 {
                run_id: run_id.clone(),
                parent_run_id: parent_run_id.clone(),
                depth,
                budget,
                input: observed.output.clone(),
                recalled,
            };
            let plan = planner.propose(&context)?;
            plan.validate()?;
            if plan.intents.len() > MAX_INTENTS_PER_PLAN {
                return Err(AutonomousError::InvalidPlan(
                    "intent count outside bound".into(),
                ));
            }
            let proposal = serde_json::json!({
                "plan": &plan,
                "planner": planner.receipt_context(),
            });
            self.record(
                &run_id,
                parent_run_id.clone(),
                depth,
                AutonomousActionV1::Propose,
                &proposal,
                None,
                "accepted",
            )?;
            if plan.complete {
                self.record(
                    &run_id,
                    parent_run_id,
                    depth,
                    AutonomousActionV1::Complete,
                    &proposal,
                    Some(&observed.output),
                    "succeeded",
                )?;
                let learning = serde_json::to_string(&observed.output)?;
                let provenance = MemoryProvenanceV1 {
                    source: AUTONOMY_DOMAIN.into(),
                    source_receipt: observed.receipt.clone(),
                };
                let _ = self.memory.put_with_provenance(
                    "autonomous",
                    &run_id,
                    &learning,
                    &provenance,
                )?;
                return Ok(observed);
            }
            let candidates = plan
                .intents
                .iter()
                .map(|intent| (intent.name.clone(), serde_json::Value::Null))
                .collect();
            let search = McstSearch::new(candidates)
                .map_err(|error| AutonomousError::InvalidPlan(error.to_string()))?;
            let score_by_name: BTreeMap<String, f64> = plan
                .intents
                .iter()
                .map(|intent| {
                    let score = planner.score(&[intent.name.as_str()]);
                    (intent.name.clone(), score)
                })
                .collect();
            let scorer: recursive_agent_mcts::ScoreFn = Box::new(move |path| {
                path.first()
                    .and_then(|name| score_by_name.get(*name))
                    .copied()
                    .unwrap_or(0.0)
            });
            let selected =
                search.search_bounded(&scorer, budget.max_steps as usize, 1, depth as u64);
            let name = McstSearch::best_path(&selected)
                .into_iter()
                .next()
                .ok_or_else(|| AutonomousError::InvalidPlan("MCTS selected no intent".into()))?;
            let intent = plan
                .intents
                .into_iter()
                .find(|intent| intent.name == name)
                .ok_or_else(|| {
                    AutonomousError::InvalidPlan("MCTS selected an unknown intent".into())
                })?;
            // MCTS selection is an execution decision, not merely a presentation
            // order: only the selected first intent may consume a step or effect.
            self.guard(budget, depth)?;
            self.steps = self
                .steps
                .checked_add(1)
                .ok_or(AutonomousError::BudgetExceeded)?;
            if self.steps > budget.max_steps {
                return Err(AutonomousError::BudgetExceeded);
            }
            if let Some(skill) = self.skills {
                let skill_id = SkillId::try_new(&intent.name).map_err(|_| {
                    AutonomousError::InvalidPlan("intent is not an admitted skill".into())
                })?;
                skill.load(&skill_id)?;
            }
            self.record(
                &run_id,
                parent_run_id.clone(),
                depth,
                AutonomousActionV1::Execute,
                &intent.payload,
                None,
                "accepted",
            )?;
            let mut result = executor.execute(&context, &intent)?;
            let output_len = serde_json::to_vec(&result.output)?.len() as u64;
            self.output_bytes = self.output_bytes.saturating_add(output_len);
            if self.output_bytes > budget.max_output_bytes {
                return Err(AutonomousError::BudgetExceeded);
            }
            self.record(
                &run_id,
                parent_run_id.clone(),
                depth,
                AutonomousActionV1::Review,
                &intent.payload,
                Some(&result.output),
                "accepted",
            )?;
            if intent.delegate {
                if depth >= budget.max_depth || self.children >= budget.max_children {
                    self.record(
                        &run_id,
                        parent_run_id.clone(),
                        depth,
                        AutonomousActionV1::Rejected,
                        &intent.payload,
                        None,
                        "recursion_limit",
                    )?;
                    return Err(AutonomousError::RecursionLimit);
                }
                self.children = self.children.saturating_add(1);
                self.record(
                    &run_id,
                    parent_run_id.clone(),
                    depth,
                    AutonomousActionV1::Delegate,
                    &intent.payload,
                    None,
                    "accepted",
                )?;
                result = self.run_node(
                    result.output,
                    Some(run_id.clone()),
                    depth + 1,
                    budget.attenuate(),
                    planner,
                    executor,
                )?;
            }
            observed = result;
        }
    }

    fn guard(&mut self, budget: AutonomousBudgetV1, depth: u32) -> Result<(), AutonomousError> {
        if self.cancellation.is_cancelled() {
            return Err(AutonomousError::Cancelled);
        }
        if depth > budget.max_depth
            || self.steps >= budget.max_steps
            || self.output_bytes >= budget.max_output_bytes
        {
            return Err(AutonomousError::BudgetExceeded);
        }
        if self.started.elapsed() > Duration::from_millis(budget.max_wall_time_ms) {
            return Err(AutonomousError::BudgetExceeded);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &mut self,
        run_id: &str,
        parent_run_id: Option<String>,
        depth: u32,
        action: AutonomousActionV1,
        payload: &serde_json::Value,
        output: Option<&serde_json::Value>,
        outcome: &str,
    ) -> Result<AutonomousReceiptV1, AutonomousError> {
        self.transcript.append(
            run_id.to_owned(),
            parent_run_id,
            depth,
            action,
            payload,
            output,
            outcome,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use recursive_agent_provider::{CompletionResponseV1, ValidatedEndpoint};
    use std::sync::atomic::AtomicUsize;

    struct CompletionFixture {
        text: String,
        unavailable: bool,
        calls: AtomicUsize,
    }

    impl CompletionBackend for CompletionFixture {
        fn complete(
            &self,
            _request: &CompletionRequestV1,
        ) -> Result<CompletionResponseV1, recursive_agent_provider::ProviderError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.unavailable {
                return Err(recursive_agent_provider::ProviderError::Unavailable);
            }
            Ok(CompletionResponseV1 {
                model: "fixture-model".into(),
                text: self.text.clone(),
                raw: serde_json::json!({"fixture": true}),
            })
        }
    }

    fn model_context() -> AutonomousContextV1 {
        AutonomousContextV1 {
            run_id: "run-model-fixture".into(),
            parent_run_id: None,
            depth: 0,
            budget: budget(),
            input: serde_json::json!({"goal": "run the admitted operation"}),
            recalled: Vec::new(),
        }
    }

    fn model_provider() -> Result<ProviderSpecV1, recursive_agent_provider::ProviderError> {
        Ok(ProviderSpecV1::Ollama {
            base_url: ValidatedEndpoint::try_new("http://127.0.0.1:11434")?,
            model: "fixture-model".into(),
        })
    }

    #[test]
    fn model_planner_parses_strict_json_and_records_secret_free_context(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let backend = CompletionFixture {
            text: serde_json::json!({
                "complete": false,
                "intents": [{
                    "name": "native_operation",
                    "payload": {"operation": {"schema": "recursive-agent.operation/v1"}},
                    "delegate": false
                }]
            })
            .to_string(),
            unavailable: false,
            calls: AtomicUsize::new(0),
        };
        let planner = ModelAutonomousPlanner::new(&backend, model_provider()?, Some(128));
        let plan = planner.propose(&model_context())?;
        assert_eq!(plan.intents.len(), 1);
        assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
        assert_eq!(planner.receipt_context()["model"], "fixture-model");
        assert_eq!(planner.receipt_context()["provider"]["kind"], "ollama");
        Ok(())
    }

    #[test]
    fn model_planner_rejects_malformed_and_unavailable_responses(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let malformed = CompletionFixture {
            text: "not-json".into(),
            unavailable: false,
            calls: AtomicUsize::new(0),
        };
        let planner = ModelAutonomousPlanner::new(&malformed, model_provider()?, None);
        assert!(matches!(
            planner.propose(&model_context()),
            Err(AutonomousError::InvalidPlan(_))
        ));

        let copied_context = CompletionFixture {
            text: serde_json::json!({
                "complete": true,
                "intents": [],
                "budget": budget(),
            })
            .to_string(),
            unavailable: false,
            calls: AtomicUsize::new(0),
        };
        let planner = ModelAutonomousPlanner::new(&copied_context, model_provider()?, None);
        assert!(matches!(
            planner.propose(&model_context()),
            Err(AutonomousError::InvalidPlan(_))
        ));

        let unavailable = CompletionFixture {
            text: String::new(),
            unavailable: true,
            calls: AtomicUsize::new(0),
        };
        let planner = ModelAutonomousPlanner::new(&unavailable, model_provider()?, None);
        assert!(matches!(
            planner.propose(&model_context()),
            Err(AutonomousError::Provider(
                recursive_agent_provider::ProviderError::Unavailable
            ))
        ));
        Ok(())
    }

    struct Planner;
    impl AutonomousPlanner for Planner {
        fn propose(
            &self,
            context: &AutonomousContextV1,
        ) -> Result<AutonomousPlanV1, AutonomousError> {
            if context.input.get("intent").is_some() {
                return Ok(AutonomousPlanV1 {
                    complete: true,
                    intents: Vec::new(),
                });
            }
            Ok(AutonomousPlanV1 {
                complete: false,
                intents: vec![AutonomousIntentV1 {
                    name: "work".into(),
                    payload: serde_json::json!({"x": 1}),
                    delegate: context.depth < 2,
                }],
            })
        }
        fn score(&self, path: &[&str]) -> f64 {
            if path.first() == Some(&"work") {
                1.0
            } else {
                0.0
            }
        }
    }

    struct Executor {
        calls: AtomicUsize,
    }
    impl AutonomousExecutor for Executor {
        fn execute(
            &self,
            _context: &AutonomousContextV1,
            intent: &AutonomousIntentV1,
        ) -> Result<AutonomousResultV1, AutonomousError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(AutonomousResultV1 {
                output: serde_json::json!({"intent": intent.name}),
                receipt: None,
            })
        }
    }

    fn budget() -> AutonomousBudgetV1 {
        AutonomousBudgetV1 {
            max_depth: 2,
            max_steps: 8,
            max_children: 2,
            max_wall_time_ms: 10_000,
            max_output_bytes: 16_384,
        }
    }

    #[test]
    fn autonomous_budget_rejects_every_widened_ceiling() {
        let mut over_depth = budget();
        over_depth.max_depth = MAX_AUTONOMOUS_DEPTH + 1;
        let mut over_steps = budget();
        over_steps.max_steps = MAX_AUTONOMOUS_STEPS + 1;
        let mut over_children = budget();
        over_children.max_children = MAX_AUTONOMOUS_CHILDREN + 1;
        let mut over_wall_time = budget();
        over_wall_time.max_wall_time_ms = MAX_AUTONOMOUS_WALL_TIME_MS + 1;
        let mut over_output = budget();
        over_output.max_output_bytes = MAX_AUTONOMOUS_OUTPUT_BYTES + 1;

        for invalid in [
            over_depth,
            over_steps,
            over_children,
            over_wall_time,
            over_output,
        ] {
            assert!(matches!(
                invalid.validate(),
                Err(AutonomousError::InvalidBudget)
            ));
        }
    }

    #[test]
    fn recursive_child_is_lineaged_and_restart_verifiable() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempfile::tempdir()?;
        let memory = MemoryStore::open(&temp.path().join("memory.db"))?;
        let transcript_path = temp.path().join("autonomy.ndjson");
        let cancellation = AutonomousCancellation::new();
        let executor = Executor {
            calls: AtomicUsize::new(0),
        };
        let mut runner = AutonomousRunner::new(
            &memory,
            None,
            AutonomousTranscript::open(&transcript_path)?,
            budget(),
            &cancellation,
        )?;
        runner.run(serde_json::json!({"goal": "repair"}), &Planner, &executor)?;
        assert_eq!(executor.calls.load(Ordering::Relaxed), 1);
        drop(runner);
        let reopened = AutonomousTranscript::open(&transcript_path)?;
        assert!(reopened.next_sequence > 0);
        let text = std::fs::read_to_string(transcript_path)?;
        assert!(text.contains("delegate"));
        assert!(text.contains("complete"));
        Ok(())
    }

    #[test]
    fn mcts_selection_executes_only_the_highest_scored_intent(
    ) -> Result<(), Box<dyn std::error::Error>> {
        struct SelectionPlanner;
        impl AutonomousPlanner for SelectionPlanner {
            fn propose(
                &self,
                _context: &AutonomousContextV1,
            ) -> Result<AutonomousPlanV1, AutonomousError> {
                if _context.input.get("selected").is_some() {
                    return Ok(AutonomousPlanV1 {
                        complete: true,
                        intents: Vec::new(),
                    });
                }
                Ok(AutonomousPlanV1 {
                    complete: false,
                    intents: vec![
                        AutonomousIntentV1 {
                            name: "low".into(),
                            payload: serde_json::json!({"rank": "low"}),
                            delegate: false,
                        },
                        AutonomousIntentV1 {
                            name: "high".into(),
                            payload: serde_json::json!({"rank": "high"}),
                            delegate: false,
                        },
                    ],
                })
            }

            fn score(&self, path: &[&str]) -> f64 {
                match path.first() {
                    Some(&"high") => 1.0,
                    _ => 0.0,
                }
            }
        }

        struct SelectionExecutor(std::sync::Mutex<Vec<String>>);
        impl AutonomousExecutor for SelectionExecutor {
            fn execute(
                &self,
                _context: &AutonomousContextV1,
                intent: &AutonomousIntentV1,
            ) -> Result<AutonomousResultV1, AutonomousError> {
                self.0
                    .lock()
                    .map_err(|_| {
                        AutonomousError::Transcript("selection fixture lock poisoned".into())
                    })?
                    .push(intent.name.clone());
                Ok(AutonomousResultV1 {
                    output: serde_json::json!({"selected": intent.name}),
                    receipt: None,
                })
            }
        }

        let temp = tempfile::tempdir()?;
        let memory = MemoryStore::open(&temp.path().join("memory.db"))?;
        let cancellation = AutonomousCancellation::new();
        let executor = SelectionExecutor(std::sync::Mutex::new(Vec::new()));
        let mut runner = AutonomousRunner::new(
            &memory,
            None,
            AutonomousTranscript::open(&temp.path().join("selection.ndjson"))?,
            budget(),
            &cancellation,
        )?;

        runner.run(
            serde_json::json!({"goal": "select one"}),
            &SelectionPlanner,
            &executor,
        )?;

        assert_eq!(
            *executor
                .0
                .lock()
                .map_err(|_| std::io::Error::other("selection fixture lock poisoned"))?,
            vec!["high".to_owned()]
        );
        Ok(())
    }

    #[test]
    fn cancellation_is_observed_before_new_child() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let memory = MemoryStore::open(&temp.path().join("memory.db"))?;
        let cancellation = AutonomousCancellation::new();
        cancellation.cancel();
        let mut runner = AutonomousRunner::new(
            &memory,
            None,
            AutonomousTranscript::open(&temp.path().join("a.ndjson"))?,
            budget(),
            &cancellation,
        )?;
        assert!(matches!(
            runner.run(
                serde_json::json!({"goal": "x"}),
                &Planner,
                &Executor {
                    calls: AtomicUsize::new(0)
                }
            ),
            Err(AutonomousError::Cancelled)
        ));
        Ok(())
    }

    #[test]
    fn transcript_open_rejects_a_non_regular_path_before_reading_it(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let error = match AutonomousTranscript::open(temp.path()) {
            Ok(_) => return Err("directory must not be accepted as a transcript".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            AutonomousError::Io(_) | AutonomousError::Transcript(_)
        ));
        Ok(())
    }

    #[test]
    fn transcript_open_and_append_never_exceed_the_recovery_limit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let oversized_path = temp.path().join("oversized.ndjson");
        File::create(&oversized_path)?.set_len(MAX_TRANSCRIPT_BYTES + 1)?;
        assert!(matches!(
            AutonomousTranscript::open(&oversized_path),
            Err(AutonomousError::Transcript(_))
        ));

        let path = temp.path().join("full.ndjson");
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let mut transcript = AutonomousTranscript {
            path,
            file,
            next_sequence: 0,
            chain_digest: [0_u8; 32],
            stored_bytes: MAX_TRANSCRIPT_BYTES,
        };
        assert!(matches!(
            transcript.append(
                "run".into(),
                None,
                0,
                AutonomousActionV1::Observe,
                &serde_json::json!({"bounded": true}),
                None,
                "accepted",
            ),
            Err(AutonomousError::Transcript(_))
        ));
        Ok(())
    }
}
