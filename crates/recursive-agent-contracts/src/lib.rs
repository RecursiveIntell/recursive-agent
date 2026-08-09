//! Typed protocol for the M0 receipt chain.
//!
//! Every payload that crosses a boundary is JCS-canonicalized through
//! `boundary-compiler` and content-hashed through `stack-ids`. The chain
//! is content-addressed at every step. No provider, no `unwrap`, no
//! `panic!` in this crate.

mod event;
mod operation;

pub use event::{
    project_runtime_events, validate_runtime_event_sequence, RuntimeEventKindV1,
    RuntimeEventSchemaV1, RuntimeEventV1,
};
pub use operation::{
    derive_child_operation_id, derive_child_operation_material_digest,
    derive_child_operation_proposal_digest, derive_operation_id,
    parse_child_operation_envelope_v2_bytes, parse_child_operation_proposal_v2_bytes,
    parse_operation_envelope_bytes, ActorAuthorityV1, AuthorityOriginV1, CausalLinkV1,
    ChildOperationEnvelopeV2, ChildOperationProposalV2, ChildRunAuthorityV1, DeclaredEffectsV1,
    OperationBudgetV1, OperationEnvelopeV1, OperationIngressError, OperationSchemaV1,
    ProvenanceRefV1, ReplayClassV1, ReplayIntentV1, ReplaySpecV1,
};

use boundary_compiler::{Canonicalizer, ContentDigest as BoundaryContentDigest, JcsError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
pub use stack_ids::{
    ArtifactId, ContentDigest, ControlReceiptId, EffectIntentId, ExecutionPermitId, KernelRunId,
};
use thiserror::Error;

/// Domain errors that surface as typed rejections, not panics.
#[derive(Debug, Error)]
pub enum ContractError {
    #[error("boundary-compiler rejected input: {0}")]
    Boundary(#[from] JcsError),
    #[error("malformed payload: {0}")]
    Malformed(String),
    #[error("id family mismatch: expected {expected}, got {actual}")]
    IdFamily { expected: String, actual: String },
    #[error("id parse failed: {0}")]
    IdParse(String),
}

const RUN_ID_DOMAIN: &str = "recursive-agent/run/v1";
const STEP_ID_DOMAIN: &str = "recursive-agent/step/v1";
const PERMIT_ID_DOMAIN: &str = "recursive-agent/permit/v1";
const RECEIPT_ID_DOMAIN: &str = "recursive-agent/receipt/v1";
const ARTIFACT_ID_DOMAIN: &str = "recursive-agent/artifact/v1";

/// Canonical JCS bytes for an arbitrary `Serialize` value.
pub fn jcs_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, ContractError> {
    let v = serde_json::to_value(value)
        .map_err(|e| ContractError::Malformed(format!("json encode: {e}")))?;
    let bytes = Canonicalizer::new().canonicalize_bytes(&v)?;
    Ok(bytes)
}

/// BLAKE3 content digest over canonical bytes (default JSON schema).
pub fn content_digest<T: Serialize>(value: &T) -> Result<ContentDigest, ContractError> {
    let v = serde_json::to_value(value)
        .map_err(|e| ContractError::Malformed(format!("json encode: {e}")))?;
    let boundary = BoundaryContentDigest::compute(&v)?;
    // Wrap the boundary digest in a stack-ids content digest with
    // matching metadata so the same value has a stable identity in the
    // stack-ids identity law.
    let hex = boundary.hex();
    ContentDigest::from_hex(hex)
        .map_err(|e| ContractError::Malformed(format!("digest wrap: {e:?}")))
}

fn validate_current_id(value: &str, domain: &str) -> Result<(), ContractError> {
    let prefix = format!("v1:{domain}:det:");
    let digest = value
        .strip_prefix(&prefix)
        .ok_or_else(|| ContractError::IdFamily {
            expected: prefix,
            actual: value.split(':').take(4).collect::<Vec<_>>().join(":"),
        })?;
    if digest.len() != 64
        || !digest
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        return Err(ContractError::IdParse(
            "current deterministic id suffix must be 64 lowercase hexadecimal characters".into(),
        ));
    }
    Ok(())
}

macro_rules! current_id {
    ($name:ident, $owner:ty, $domain:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name($owner);

        impl $name {
            pub fn try_new(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                validate_current_id(&value, $domain)?;
                <$owner>::try_new(value).map(Self).map_err(owner_id_error)
            }

            pub fn from_owner(value: $owner) -> Result<Self, ContractError> {
                validate_current_id(value.as_str(), $domain)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                Self::try_new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

current_id!(CurrentRunId, KernelRunId, RUN_ID_DOMAIN);
current_id!(CurrentStepId, EffectIntentId, STEP_ID_DOMAIN);
current_id!(CurrentPermitId, ExecutionPermitId, PERMIT_ID_DOMAIN);
current_id!(CurrentReceiptId, ControlReceiptId, RECEIPT_ID_DOMAIN);
current_id!(CurrentArtifactId, ArtifactId, ARTIFACT_ID_DOMAIN);

/// Explicitly fenced reader for historical identifiers. A legacy identifier
/// can be inspected but is never accepted by a current V1 material field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct LegacyV1Id(String);

impl LegacyV1Id {
    pub fn parse(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(ContractError::IdParse("invalid legacy identifier".into()));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for LegacyV1Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

fn owner_id_error(error: stack_ids::IdError) -> ContractError {
    ContractError::IdParse(error.to_string())
}

/// Derive the authoritative run identity from the canonical run specification.
pub fn derive_run_id(spec: &RunSpecV1) -> Result<CurrentRunId, ContractError> {
    let digest = content_digest(spec)?;
    let owner = KernelRunId::deterministic(RUN_ID_DOMAIN, digest.hex()).map_err(owner_id_error)?;
    CurrentRunId::from_owner(owner)
}

#[derive(Serialize)]
struct StepIdentityMaterial<'a> {
    run_id: &'a CurrentRunId,
    stable_step_index: usize,
    step_name: &'a str,
    tool_call: &'a ToolCallSpecV1,
}

/// Derive a step identity. `stack-ids` does not currently export a dedicated
/// step ID, so the narrow adapter uses `EffectIntentId` for this concrete
/// effect-intent boundary rather than defining a competing general ID type.
pub fn derive_step_id(
    run_id: &CurrentRunId,
    stable_step_index: usize,
    step_name: &str,
    tool_call: &ToolCallSpecV1,
) -> Result<CurrentStepId, ContractError> {
    let digest = content_digest(&StepIdentityMaterial {
        run_id,
        stable_step_index,
        step_name,
        tool_call,
    })?;
    let owner =
        EffectIntentId::deterministic(STEP_ID_DOMAIN, digest.hex()).map_err(owner_id_error)?;
    CurrentStepId::from_owner(owner)
}

/// The one admitted permit-identity boundary. The binding digest covers all
/// non-temporal authority/action/effect/budget fields; requested validity is
/// explicit. Live issue/recording time is deliberately not identity material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermitIdentityMaterialV1 {
    pub binding_digest: ContentDigest,
    pub requested_not_before_delay_ms: u64,
    pub requested_validity_ms: u64,
}

impl PermitIdentityMaterialV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.requested_validity_ms == 0 {
            return Err(ContractError::Malformed(
                "permit requested validity must be non-empty".into(),
            ));
        }
        Ok(())
    }
}

/// Derive an execution permit ID from exactly one typed complete identity
/// material value.
pub fn derive_permit_id(
    material: &PermitIdentityMaterialV1,
) -> Result<CurrentPermitId, ContractError> {
    material.validate()?;
    let digest = content_digest(material)?;
    let owner =
        ExecutionPermitId::deterministic(PERMIT_ID_DOMAIN, digest.hex()).map_err(owner_id_error)?;
    CurrentPermitId::from_owner(owner)
}

#[derive(Serialize)]
pub struct ReceiptIdentityMaterialV1<'a> {
    pub run_id: &'a CurrentRunId,
    pub step_id: &'a CurrentStepId,
    pub kind: &'a ReceiptKindV1,
    pub lineage: &'a [AuthorityLineageEntryV1],
    pub spec_digest: &'a ContentDigest,
    pub args_digest: &'a ContentDigest,
    pub outcome: &'a ReceiptOutcomeV1,
    pub artifact_refs: &'a [ArtifactDescriptorV1],
    pub predecessor_chain_digest: &'a ContentDigest,
}

/// Derive a receipt ID from stable execution-semantic fields. Live wall-clock
/// observations (`valid_time` and `recorded_time`) are deliberately excluded:
/// they remain verified receipt evidence but cannot perturb material identity.
pub fn derive_receipt_id(
    material: &ReceiptIdentityMaterialV1<'_>,
) -> Result<CurrentReceiptId, ContractError> {
    let digest = content_digest(material)?;
    let owner =
        ControlReceiptId::deterministic(RECEIPT_ID_DOMAIN, digest.hex()).map_err(owner_id_error)?;
    CurrentReceiptId::from_owner(owner)
}

/// Derive a content-addressed artifact ID from the exact stored bytes.
pub fn derive_artifact_id(bytes: &[u8]) -> Result<CurrentArtifactId, ContractError> {
    let digest = ContentDigest::compute(bytes);
    let owner =
        ArtifactId::deterministic(ARTIFACT_ID_DOMAIN, digest.hex()).map_err(owner_id_error)?;
    CurrentArtifactId::from_owner(owner)
}

/// One hop in the request-to-effect authority chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityLineageEntryV1 {
    pub origin: LineageOrigin,
    pub principal: String,
    pub permit_id: Option<CurrentPermitId>,
    pub policy_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageOrigin {
    Request,
    Plan,
    Policy,
    Approval,
    Tool,
    Effect,
}

/// Validate the lineage is non-empty, well-ordered, and has no duplicate
/// origins.
pub fn validate_lineage(chain: &[AuthorityLineageEntryV1]) -> Result<(), ContractError> {
    if chain.is_empty() {
        return Err(ContractError::Malformed("empty lineage".into()));
    }
    let mut seen = std::collections::BTreeSet::new();
    for entry in chain {
        let key = serde_json::to_string(&entry.origin)
            .map_err(|e| ContractError::Malformed(format!("lineage origin: {e}")))?;
        if !seen.insert(key) {
            return Err(ContractError::Malformed("duplicate lineage origin".into()));
        }
    }
    let first = serde_json::to_string(&chain[0].origin)
        .map_err(|e| ContractError::Malformed(format!("lineage origin: {e}")))?;
    if first != "\"request\"" {
        return Err(ContractError::Malformed(
            "lineage must start with request".into(),
        ));
    }
    let last = serde_json::to_string(
        &chain
            .last()
            .ok_or_else(|| ContractError::Malformed("empty lineage".into()))?
            .origin,
    )
    .map_err(|e| ContractError::Malformed(format!("lineage origin: {e}")))?;
    if last != "\"effect\"" {
        return Err(ContractError::Malformed(
            "lineage must end with effect".into(),
        ));
    }
    Ok(())
}

/// A typed tool invocation in the M0 manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCallSpecV1 {
    pub tool: String,
    pub args: serde_json::Value,
    /// Optional frozen clock for tools that read time. Wall-clock tools
    /// must be invoked with this set or be refused by policy.
    pub frozen_clock: Option<DateTime<Utc>>,
}

/// A node in the M0 run graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepSpecV1 {
    pub name: String,
    pub call: ToolCallSpecV1,
}

/// Top-level run spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSpecV1 {
    pub name: String,
    pub steps: Vec<StepSpecV1>,
    pub frozen_clock: Option<DateTime<Utc>>,
    pub policy_version: String,
}

impl RunSpecV1 {
    /// JCS-canonical bytes for this run spec. Used as the spec digest.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        jcs_canonical(self)
    }
}

pub const MAX_RUN_SPEC_INPUT_BYTES: u64 = 1024 * 1024;
pub const MAX_RUN_SPEC_STEPS: usize = 4;
pub const MAX_RUN_SPEC_MATERIAL_BYTES: usize = 512 * 1024;
pub const MAX_RUN_NAME_BYTES: usize = 256;
pub const MAX_STEP_NAME_BYTES: usize = 256;
pub const MAX_POLICY_VERSION_BYTES: usize = 64;
pub const MAX_TOOL_NAME_BYTES: usize = 64;
pub const MAX_ECHO_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_TIME_LABEL_BYTES: usize = 256;
pub const MAX_SHELL_COMMAND_BYTES: usize = 4096;
pub const MAX_SHELL_ARGS: usize = 64;
pub const MAX_SHELL_ARG_BYTES: usize = 16 * 1024;
pub const MAX_SHELL_ROOTS_PER_MODE: usize = 32;
pub const MAX_SHELL_PATH_BYTES: usize = 4096;
pub const MAX_SHELL_TIMEOUT_MS: u64 = 300_000;
pub const MAX_SHELL_OUTPUT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Error)]
pub enum RunSpecIngressError {
    #[error("run spec input exceeds the byte limit of {maximum_bytes}")]
    InputTooLarge { maximum_bytes: u64 },
    #[error("run spec path is not a no-follow regular file")]
    NotRegularFile,
    #[error("run spec input could not be read")]
    Io(#[source] std::io::Error),
    #[error("run spec contains a duplicate object key")]
    DuplicateKey,
    #[error("run spec is malformed or contains an unknown field")]
    Malformed,
    #[error("run spec canonical boundary validation failed")]
    CanonicalBoundary,
    #[error("run spec exceeds the step limit of {maximum_steps}")]
    TooManySteps { maximum_steps: usize },
    #[error("run spec material exceeds the aggregate limit of {maximum_bytes} bytes")]
    MaterialTooLarge { maximum_bytes: usize },
    #[error("run spec field {field} exceeds its byte limit of {maximum_bytes}")]
    FieldTooLarge {
        field: &'static str,
        maximum_bytes: usize,
    },
    #[error("run spec field {field} exceeds its item limit of {maximum_items}")]
    TooManyItems {
        field: &'static str,
        maximum_items: usize,
    },
    #[error("run spec field {field} has invalid semantics")]
    InvalidSemanticField { field: &'static str },
    #[error("run spec contains an unsupported or malformed Phase 1 tool call")]
    InvalidToolArguments,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EchoArgsIngressV1 {
    text: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimeNowArgsIngressV1 {
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShellArgsIngressV1 {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    allowed_read_paths: Vec<String>,
    #[serde(default)]
    allowed_write_paths: Vec<String>,
    #[serde(default)]
    allow_network: bool,
    timeout_ms: u64,
    #[serde(default = "default_ingress_output_limit")]
    max_output_bytes: u64,
}

fn default_ingress_output_limit() -> u64 {
    64 * 1024
}

struct DuplicateSafeValue(serde_json::Value);

/// Typed failures from recursive duplicate-safe JSON parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StrictJsonError {
    /// An object key was repeated at any nesting depth.
    #[error("JSON contains a duplicate object key")]
    DuplicateKey,
    /// The input is not exactly one well-formed JSON value.
    #[error("JSON is malformed")]
    Malformed,
}

impl<'de> Deserialize<'de> for DuplicateSafeValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ValueVisitor;

        impl<'de> serde::de::Visitor<'de> for ValueVisitor {
            type Value = serde_json::Value;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a duplicate-free JSON value")
            }

            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Bool(value))
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(value.into())
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(value.into())
            }

            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(serde_json::Value::Number)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(serde_json::Value::String(value.into()))
            }

            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(serde_json::Value::String(value))
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Null)
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Null)
            }

            fn visit_some<D: Deserializer<'de>>(self, value: D) -> Result<Self::Value, D::Error> {
                DuplicateSafeValue::deserialize(value).map(|parsed| parsed.0)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<DuplicateSafeValue>()? {
                    values.push(value.0);
                }
                Ok(serde_json::Value::Array(values))
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate object key"));
                    }
                    let value = map.next_value::<DuplicateSafeValue>()?;
                    values.insert(key, value.0);
                }
                Ok(serde_json::Value::Object(values))
            }
        }

        deserializer.deserialize_any(ValueVisitor).map(Self)
    }
}

/// Parse exactly one JSON value while rejecting duplicate object keys at every
/// nesting depth before serde can normalize them.
pub fn parse_strict_json_value(input: &[u8]) -> Result<serde_json::Value, StrictJsonError> {
    serde_json::from_slice::<DuplicateSafeValue>(input)
        .map(|value| value.0)
        .map_err(|error| {
            if error.to_string().contains("duplicate object key") {
                StrictJsonError::DuplicateKey
            } else {
                StrictJsonError::Malformed
            }
        })
}

pub fn parse_run_spec_bytes(input: &[u8]) -> Result<RunSpecV1, RunSpecIngressError> {
    if input.len() as u64 > MAX_RUN_SPEC_INPUT_BYTES {
        return Err(RunSpecIngressError::InputTooLarge {
            maximum_bytes: MAX_RUN_SPEC_INPUT_BYTES,
        });
    }
    let parsed = parse_strict_json_value(input).map_err(|error| match error {
        StrictJsonError::DuplicateKey => RunSpecIngressError::DuplicateKey,
        StrictJsonError::Malformed => RunSpecIngressError::Malformed,
    })?;
    // The contract-owned recursive visitor validates duplicate freedom on the
    // original attacker bytes. The admitted boundary owner then supplies the
    // canonical representation; its depth-only duplicate pre-scan is not used.
    let canonical = Canonicalizer::new()
        .canonicalize_bytes(&parsed)
        .map_err(|_| RunSpecIngressError::CanonicalBoundary)?;
    if canonical.len() > MAX_RUN_SPEC_MATERIAL_BYTES {
        return Err(RunSpecIngressError::MaterialTooLarge {
            maximum_bytes: MAX_RUN_SPEC_MATERIAL_BYTES,
        });
    }
    let spec =
        serde_json::from_value::<RunSpecV1>(parsed).map_err(|_| RunSpecIngressError::Malformed)?;
    validate_ingress_spec(&spec)?;
    Ok(spec)
}

pub fn parse_run_spec_file(path: &std::path::Path) -> Result<RunSpecV1, RunSpecIngressError> {
    use std::io::Read;

    let file = open_run_spec_no_follow(path)?;
    let metadata = file.metadata().map_err(RunSpecIngressError::Io)?;
    if !metadata.is_file() {
        return Err(RunSpecIngressError::NotRegularFile);
    }
    if metadata.len() > MAX_RUN_SPEC_INPUT_BYTES {
        return Err(RunSpecIngressError::InputTooLarge {
            maximum_bytes: MAX_RUN_SPEC_INPUT_BYTES,
        });
    }
    let capacity =
        usize::try_from(metadata.len()).map_err(|_| RunSpecIngressError::InputTooLarge {
            maximum_bytes: MAX_RUN_SPEC_INPUT_BYTES,
        })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_RUN_SPEC_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(RunSpecIngressError::Io)?;
    if bytes.len() as u64 > MAX_RUN_SPEC_INPUT_BYTES {
        return Err(RunSpecIngressError::InputTooLarge {
            maximum_bytes: MAX_RUN_SPEC_INPUT_BYTES,
        });
    }
    parse_run_spec_bytes(&bytes)
}

fn validate_ingress_spec(spec: &RunSpecV1) -> Result<(), RunSpecIngressError> {
    validate_identifier(&spec.name, "name", MAX_RUN_NAME_BYTES)?;
    validate_identifier(
        &spec.policy_version,
        "policy_version",
        MAX_POLICY_VERSION_BYTES,
    )?;
    if spec.steps.is_empty() {
        return Err(RunSpecIngressError::InvalidSemanticField { field: "steps" });
    }
    if spec.steps.len() > MAX_RUN_SPEC_STEPS {
        return Err(RunSpecIngressError::TooManySteps {
            maximum_steps: MAX_RUN_SPEC_STEPS,
        });
    }
    let mut step_names = std::collections::BTreeSet::new();
    for step in &spec.steps {
        validate_identifier(&step.name, "steps[].name", MAX_STEP_NAME_BYTES)?;
        if !step_names.insert(step.name.as_str()) {
            return Err(RunSpecIngressError::InvalidSemanticField {
                field: "steps[].name",
            });
        }
        validate_identifier(&step.call.tool, "steps[].call.tool", MAX_TOOL_NAME_BYTES)?;
        let args_bytes =
            jcs_canonical(&step.call.args).map_err(|_| RunSpecIngressError::CanonicalBoundary)?;
        if args_bytes.len() > MAX_RUN_SPEC_MATERIAL_BYTES {
            return Err(RunSpecIngressError::MaterialTooLarge {
                maximum_bytes: MAX_RUN_SPEC_MATERIAL_BYTES,
            });
        }
        match step.call.tool.as_str() {
            "echo" => validate_echo_args(&step.call.args)?,
            "time_now" => validate_time_args(&step.call.args)?,
            "shell" => validate_shell_args(&step.call.args)?,
            _ => return Err(RunSpecIngressError::InvalidToolArguments),
        }
    }
    Ok(())
}

fn validate_identifier(
    value: &str,
    field: &'static str,
    maximum_bytes: usize,
) -> Result<(), RunSpecIngressError> {
    validate_bytes(value, field, maximum_bytes)?;
    if value.is_empty()
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.contains('\0')
    {
        return Err(RunSpecIngressError::InvalidSemanticField { field });
    }
    Ok(())
}

fn validate_bytes(
    value: &str,
    field: &'static str,
    maximum_bytes: usize,
) -> Result<(), RunSpecIngressError> {
    if value.len() > maximum_bytes {
        return Err(RunSpecIngressError::FieldTooLarge {
            field,
            maximum_bytes,
        });
    }
    Ok(())
}

fn validate_item_count(
    actual: usize,
    field: &'static str,
    maximum_items: usize,
) -> Result<(), RunSpecIngressError> {
    if actual > maximum_items {
        return Err(RunSpecIngressError::TooManyItems {
            field,
            maximum_items,
        });
    }
    Ok(())
}

fn validate_echo_args(value: &serde_json::Value) -> Result<(), RunSpecIngressError> {
    let args = serde_json::from_value::<EchoArgsIngressV1>(value.clone())
        .map_err(|_| RunSpecIngressError::InvalidToolArguments)?;
    validate_bytes(&args.text, "echo.text", MAX_ECHO_TEXT_BYTES)
}

fn validate_time_args(value: &serde_json::Value) -> Result<(), RunSpecIngressError> {
    let args = serde_json::from_value::<TimeNowArgsIngressV1>(value.clone())
        .map_err(|_| RunSpecIngressError::InvalidToolArguments)?;
    if let Some(label) = args.label {
        validate_identifier(&label, "time_now.label", MAX_TIME_LABEL_BYTES)?;
    }
    Ok(())
}

fn validate_shell_args(value: &serde_json::Value) -> Result<(), RunSpecIngressError> {
    let args = serde_json::from_value::<ShellArgsIngressV1>(value.clone())
        .map_err(|_| RunSpecIngressError::InvalidToolArguments)?;
    validate_absolute_path(&args.command, "shell.command", MAX_SHELL_COMMAND_BYTES)?;
    validate_item_count(args.args.len(), "shell.args", MAX_SHELL_ARGS)?;
    for argument in &args.args {
        validate_bytes(argument, "shell.args[]", MAX_SHELL_ARG_BYTES)?;
        if argument.contains('\0') {
            return Err(RunSpecIngressError::InvalidSemanticField {
                field: "shell.args[]",
            });
        }
    }
    validate_item_count(
        args.allowed_read_paths.len(),
        "shell.allowed_read_paths",
        MAX_SHELL_ROOTS_PER_MODE,
    )?;
    validate_item_count(
        args.allowed_write_paths.len(),
        "shell.allowed_write_paths",
        MAX_SHELL_ROOTS_PER_MODE,
    )?;
    let mut roots = std::collections::BTreeSet::new();
    for path in args
        .allowed_read_paths
        .iter()
        .chain(args.allowed_write_paths.iter())
    {
        validate_absolute_path(path, "shell.allowed_paths[]", MAX_SHELL_PATH_BYTES)?;
        if !roots.insert(path.as_str()) {
            return Err(RunSpecIngressError::InvalidSemanticField {
                field: "shell.allowed_paths[]",
            });
        }
    }
    if args.allow_network {
        return Err(RunSpecIngressError::InvalidSemanticField {
            field: "shell.allow_network",
        });
    }
    if args.timeout_ms == 0 || args.timeout_ms > MAX_SHELL_TIMEOUT_MS {
        return Err(RunSpecIngressError::InvalidSemanticField {
            field: "shell.timeout_ms",
        });
    }
    if args.max_output_bytes == 0 || args.max_output_bytes > MAX_SHELL_OUTPUT_BYTES {
        return Err(RunSpecIngressError::InvalidSemanticField {
            field: "shell.max_output_bytes",
        });
    }
    Ok(())
}

fn validate_absolute_path(
    value: &str,
    field: &'static str,
    maximum_bytes: usize,
) -> Result<(), RunSpecIngressError> {
    validate_bytes(value, field, maximum_bytes)?;
    let path = std::path::Path::new(value);
    if value.is_empty()
        || value.contains('\0')
        || value.chars().any(char::is_control)
        || !path.is_absolute()
        || path == std::path::Path::new("/")
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir
                    | std::path::Component::ParentDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(RunSpecIngressError::InvalidSemanticField { field });
    }
    Ok(())
}

fn open_run_spec_no_follow(path: &std::path::Path) -> Result<std::fs::File, RunSpecIngressError> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    use std::os::fd::AsFd;

    if path.as_os_str().is_empty() || path == std::path::Path::new("/") {
        return Err(RunSpecIngressError::NotRegularFile);
    }
    let start = if path.is_absolute() { "/" } else { "." };
    let start_fd = rustix::fs::open(
        start,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| RunSpecIngressError::Io(error.into()))?;
    let mut current = std::fs::File::from(start_fd);
    let components = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::RootDir | std::path::Component::CurDir => None,
            std::path::Component::Normal(name) => Some(Ok(name)),
            std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                Some(Err(RunSpecIngressError::NotRegularFile))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (index, component) in components.iter().enumerate() {
        let name = component
            .to_str()
            .ok_or(RunSpecIngressError::NotRegularFile)?;
        let final_component = index + 1 == components.len();
        let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        if !final_component {
            flags |= OFlags::DIRECTORY;
        }
        let fd = rustix::fs::openat2(
            current.as_fd(),
            name,
            flags,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|error| RunSpecIngressError::Io(error.into()))?;
        current = std::fs::File::from(fd);
    }
    Ok(current)
}

/// Complete integrity and interpretation contract for one local artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDescriptorV1 {
    pub owner_id: CurrentArtifactId,
    pub digest: ContentDigest,
    pub byte_length: u64,
    pub media_type: String,
    pub encoding: Option<String>,
}

impl ArtifactDescriptorV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.media_type.is_empty()
            || !self.media_type.contains('/')
            || self.media_type.chars().any(char::is_control)
        {
            return Err(ContractError::Malformed(
                "invalid artifact media type".into(),
            ));
        }
        if self
            .encoding
            .as_ref()
            .is_some_and(|encoding| encoding.is_empty() || encoding.chars().any(char::is_control))
        {
            return Err(ContractError::Malformed("invalid artifact encoding".into()));
        }
        Ok(())
    }
}

/// A receipt written to the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptV1 {
    pub receipt_id: CurrentReceiptId,
    pub run_id: CurrentRunId,
    pub step_id: CurrentStepId,
    pub kind: ReceiptKindV1,
    pub valid_time: DateTime<Utc>,
    pub recorded_time: DateTime<Utc>,
    pub lineage: Vec<AuthorityLineageEntryV1>,
    pub spec_digest: ContentDigest,
    pub args_digest: ContentDigest,
    pub artifact_refs: Vec<ArtifactDescriptorV1>,
    pub outcome: ReceiptOutcomeV1,
    pub prev_chain_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKindV1 {
    RunStarted,
    StepStarted,
    PermitIssued,
    PermitConsumed,
    PermitRejected,
    PermitRevoked,
    ArtifactStored,
    StepCompleted,
    StepFailed,
    /// Parent-side receipt binding one authority-free V2 proposal before any
    /// family reservation or child dispatch.
    ChildAdmissionPrepared,
    /// Parent-side receipt carrying the content-addressed immutable child link.
    ChildLinked,
    /// Parent-side receipt carrying verified terminal closure evidence.
    ChildClosed,
    RunFinalized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOutcomeV1 {
    Ok,
    Denied,
    Failed { reason: String },
    TimedOut { reason: String },
    Cancelled { reason: String },
    SandboxFailed { reason: String },
    Corrupted { reason: String },
    Degraded { reason: String },
}

/// Truthful terminal state exposed by run summaries and final receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunTerminalStateV1 {
    Succeeded,
    Failed,
    Denied,
    TimedOut,
    Cancelled,
    SandboxFailed,
    Corrupted,
    LegacyUnknown,
}

impl RunTerminalStateV1 {
    pub fn permits_successful_finalization(self) -> bool {
        matches!(self, Self::Succeeded)
    }

    pub fn receipt_outcome(self, reason: impl Into<String>) -> ReceiptOutcomeV1 {
        let reason = reason.into();
        match self {
            Self::Succeeded => ReceiptOutcomeV1::Ok,
            Self::Failed => ReceiptOutcomeV1::Failed { reason },
            Self::Denied => ReceiptOutcomeV1::Denied,
            Self::TimedOut => ReceiptOutcomeV1::TimedOut { reason },
            Self::Cancelled => ReceiptOutcomeV1::Cancelled { reason },
            Self::SandboxFailed => ReceiptOutcomeV1::SandboxFailed { reason },
            Self::Corrupted => ReceiptOutcomeV1::Corrupted { reason },
            Self::LegacyUnknown => ReceiptOutcomeV1::Degraded { reason },
        }
    }
}

impl ReceiptOutcomeV1 {
    pub fn terminal_state(&self) -> Option<RunTerminalStateV1> {
        match self {
            Self::Ok => Some(RunTerminalStateV1::Succeeded),
            Self::Denied => Some(RunTerminalStateV1::Denied),
            Self::Failed { .. } => Some(RunTerminalStateV1::Failed),
            Self::TimedOut { .. } => Some(RunTerminalStateV1::TimedOut),
            Self::Cancelled { .. } => Some(RunTerminalStateV1::Cancelled),
            Self::SandboxFailed { .. } => Some(RunTerminalStateV1::SandboxFailed),
            Self::Corrupted { .. } => Some(RunTerminalStateV1::Corrupted),
            Self::Degraded { .. } => None,
        }
    }
}

impl ReceiptV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate_material()?;
        jcs_canonical(self)
    }

    pub fn validate_material(&self) -> Result<(), ContractError> {
        validate_lineage(&self.lineage)?;
        for artifact in &self.artifact_refs {
            artifact.validate()?;
        }
        let expected = derive_receipt_id(&ReceiptIdentityMaterialV1 {
            run_id: &self.run_id,
            step_id: &self.step_id,
            kind: &self.kind,
            lineage: &self.lineage,
            spec_digest: &self.spec_digest,
            args_digest: &self.args_digest,
            outcome: &self.outcome,
            artifact_refs: &self.artifact_refs,
            predecessor_chain_digest: &self.prev_chain_digest,
        })?;
        if expected != self.receipt_id {
            return Err(ContractError::Malformed(
                "receipt identity does not bind all semantic fields".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleValidationMode {
    AppendInProgress,
    StrictCurrent,
    LegacyIntegrityOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleValidation {
    pub run_id: Option<CurrentRunId>,
    pub terminal_state: Option<RunTerminalStateV1>,
    pub finalized: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepLifecycle {
    Started,
    PermitIssued,
    PermitConsumed,
    ArtifactStored,
    Complete,
}

/// Canonical lifecycle validator shared by live append, recovery, strict
/// verification, replay, and existing-run status.
pub fn validate_receipt_sequence(
    receipts: &[ReceiptV1],
    mode: LifecycleValidationMode,
) -> Result<LifecycleValidation, ContractError> {
    if matches!(mode, LifecycleValidationMode::LegacyIntegrityOnly) {
        return Ok(LifecycleValidation {
            run_id: receipts.first().map(|receipt| receipt.run_id.clone()),
            terminal_state: Some(RunTerminalStateV1::LegacyUnknown),
            finalized: receipts
                .iter()
                .any(|receipt| matches!(receipt.kind, ReceiptKindV1::RunFinalized)),
        });
    }
    let mut run_id: Option<CurrentRunId> = None;
    let mut steps = std::collections::BTreeMap::new();
    let mut stored_artifacts: std::collections::BTreeMap<
        CurrentStepId,
        std::collections::BTreeSet<String>,
    > = std::collections::BTreeMap::new();
    let mut terminal = None;
    let mut finalized = false;
    let mut prepared_children = std::collections::BTreeSet::new();
    let mut linked_children = std::collections::BTreeSet::new();
    let mut closed_children = std::collections::BTreeSet::new();
    for (index, receipt) in receipts.iter().enumerate() {
        receipt.validate_material()?;
        if finalized {
            return Err(ContractError::Malformed(format!(
                "receipt {index} occurs after terminal finalization"
            )));
        }
        match &run_id {
            Some(expected) if expected != &receipt.run_id => {
                return Err(ContractError::Malformed(format!(
                    "receipt {index} mixes run identifiers"
                )));
            }
            None => run_id = Some(receipt.run_id.clone()),
            Some(_) => {}
        }
        if index == 0 && !matches!(receipt.kind, ReceiptKindV1::RunStarted) {
            return Err(ContractError::Malformed(
                "current chain must begin with RunStarted".into(),
            ));
        }
        match receipt.kind {
            ReceiptKindV1::RunStarted => {
                if index != 0 || !matches!(receipt.outcome, ReceiptOutcomeV1::Ok) {
                    return Err(ContractError::Malformed(
                        "RunStarted must be the first successful receipt".into(),
                    ));
                }
            }
            ReceiptKindV1::StepStarted => {
                if !matches!(receipt.outcome, ReceiptOutcomeV1::Ok)
                    || terminal.is_some()
                    || steps
                        .insert(receipt.step_id.clone(), StepLifecycle::Started)
                        .is_some()
                {
                    return Err(ContractError::Malformed(
                        "invalid or duplicate StepStarted".into(),
                    ));
                }
            }
            ReceiptKindV1::PermitIssued => {
                if !matches!(receipt.outcome, ReceiptOutcomeV1::Ok) {
                    return Err(ContractError::Malformed(
                        "PermitIssued must be successful".into(),
                    ));
                }
                require_step_state(
                    &steps,
                    &receipt.step_id,
                    StepLifecycle::Started,
                    "PermitIssued",
                )?;
                steps.insert(receipt.step_id.clone(), StepLifecycle::PermitIssued);
            }
            ReceiptKindV1::PermitConsumed => {
                if !matches!(receipt.outcome, ReceiptOutcomeV1::Ok) {
                    return Err(ContractError::Malformed(
                        "PermitConsumed must be successful".into(),
                    ));
                }
                require_step_state(
                    &steps,
                    &receipt.step_id,
                    StepLifecycle::PermitIssued,
                    "PermitConsumed",
                )?;
                steps.insert(receipt.step_id.clone(), StepLifecycle::PermitConsumed);
            }
            ReceiptKindV1::PermitRejected => {
                if !matches!(receipt.outcome, ReceiptOutcomeV1::Denied) {
                    return Err(ContractError::Malformed(
                        "permit rejection must be denied".into(),
                    ));
                }
                require_step_state(
                    &steps,
                    &receipt.step_id,
                    StepLifecycle::PermitIssued,
                    "PermitRejected",
                )?;
                set_terminal(&mut terminal, RunTerminalStateV1::Denied)?;
                steps.insert(receipt.step_id.clone(), StepLifecycle::Complete);
            }
            ReceiptKindV1::PermitRevoked => match receipt.outcome {
                ReceiptOutcomeV1::Ok => {
                    require_step_state(
                        &steps,
                        &receipt.step_id,
                        StepLifecycle::PermitIssued,
                        "PermitRevoked",
                    )?;
                    steps.insert(receipt.step_id.clone(), StepLifecycle::Complete);
                }
                ReceiptOutcomeV1::Denied => {
                    require_step_state(
                        &steps,
                        &receipt.step_id,
                        StepLifecycle::PermitIssued,
                        "PermitRevoked",
                    )?;
                    set_terminal(&mut terminal, RunTerminalStateV1::Denied)?;
                    steps.insert(receipt.step_id.clone(), StepLifecycle::Complete);
                }
                _ => {
                    return Err(ContractError::Malformed(
                        "permit revocation must be an orderly closure or denial".into(),
                    ));
                }
            },
            ReceiptKindV1::ArtifactStored => {
                if !matches!(
                    steps.get(&receipt.step_id),
                    Some(StepLifecycle::PermitConsumed | StepLifecycle::ArtifactStored)
                ) {
                    return Err(ContractError::Malformed(
                        "ArtifactStored violates step ordering".into(),
                    ));
                }
                if !matches!(receipt.outcome, ReceiptOutcomeV1::Ok)
                    || receipt.artifact_refs.is_empty()
                {
                    return Err(ContractError::Malformed(
                        "ArtifactStored requires successful non-empty artifact evidence".into(),
                    ));
                }
                stored_artifacts
                    .entry(receipt.step_id.clone())
                    .or_default()
                    .extend(
                        receipt
                            .artifact_refs
                            .iter()
                            .map(|descriptor| descriptor.owner_id.to_string()),
                    );
                steps.insert(receipt.step_id.clone(), StepLifecycle::ArtifactStored);
            }
            ReceiptKindV1::StepCompleted => {
                require_step_state(
                    &steps,
                    &receipt.step_id,
                    StepLifecycle::ArtifactStored,
                    "StepCompleted",
                )?;
                if !matches!(receipt.outcome, ReceiptOutcomeV1::Ok)
                    || receipt.artifact_refs.is_empty()
                {
                    return Err(ContractError::Malformed(
                        "StepCompleted must be successful and carry observed artifact evidence"
                            .into(),
                    ));
                }
                let observed = stored_artifacts.get(&receipt.step_id).ok_or_else(|| {
                    ContractError::Malformed(
                        "StepCompleted has no preceding artifact for its step".into(),
                    )
                })?;
                if receipt
                    .artifact_refs
                    .iter()
                    .any(|descriptor| !observed.contains(descriptor.owner_id.as_str()))
                {
                    return Err(ContractError::Malformed(
                        "StepCompleted references an artifact not stored for its step".into(),
                    ));
                }
                steps.insert(receipt.step_id.clone(), StepLifecycle::Complete);
            }
            ReceiptKindV1::StepFailed => {
                let state = receipt.outcome.terminal_state().ok_or_else(|| {
                    ContractError::Malformed("StepFailed must carry a terminal failure".into())
                })?;
                if matches!(
                    state,
                    RunTerminalStateV1::Succeeded | RunTerminalStateV1::LegacyUnknown
                ) {
                    return Err(ContractError::Malformed(
                        "StepFailed cannot be successful".into(),
                    ));
                }
                let valid_state = if matches!(state, RunTerminalStateV1::Denied) {
                    matches!(steps.get(&receipt.step_id), Some(StepLifecycle::Started))
                } else {
                    matches!(
                        steps.get(&receipt.step_id),
                        Some(StepLifecycle::PermitConsumed | StepLifecycle::ArtifactStored)
                    )
                };
                if !valid_state {
                    return Err(ContractError::Malformed(
                        "StepFailed violates step ordering".into(),
                    ));
                }
                set_terminal(&mut terminal, state)?;
                steps.insert(receipt.step_id.clone(), StepLifecycle::Complete);
            }
            ReceiptKindV1::ChildAdmissionPrepared => {
                if terminal.is_some()
                    || !matches!(receipt.outcome, ReceiptOutcomeV1::Ok)
                    || !receipt.artifact_refs.is_empty()
                    || !prepared_children.insert(receipt.args_digest.clone())
                {
                    return Err(ContractError::Malformed(
                        "ChildAdmissionPrepared must be one successful proposal binding before terminal state"
                            .into(),
                    ));
                }
            }
            ReceiptKindV1::ChildLinked => {
                if terminal.is_some()
                    || !matches!(receipt.outcome, ReceiptOutcomeV1::Ok)
                    || receipt.artifact_refs.is_empty()
                    || !prepared_children.contains(&receipt.args_digest)
                    || !linked_children.insert(receipt.args_digest.clone())
                {
                    return Err(ContractError::Malformed(
                        "ChildLinked requires one preceding prepared proposal and immutable link evidence"
                            .into(),
                    ));
                }
            }
            ReceiptKindV1::ChildClosed => {
                if terminal.is_some()
                    || !matches!(receipt.outcome, ReceiptOutcomeV1::Ok)
                    || receipt.artifact_refs.is_empty()
                    || !linked_children.contains(&receipt.args_digest)
                    || !closed_children.insert(receipt.args_digest.clone())
                {
                    return Err(ContractError::Malformed(
                        "ChildClosed requires one preceding linked proposal and closure evidence"
                            .into(),
                    ));
                }
            }
            ReceiptKindV1::RunFinalized => {
                if index == 0 {
                    return Err(ContractError::Malformed(
                        "finalization without start".into(),
                    ));
                }
                let observed = receipt.outcome.terminal_state().ok_or_else(|| {
                    ContractError::Malformed("RunFinalized needs a terminal outcome".into())
                })?;
                let expected = terminal.unwrap_or(RunTerminalStateV1::Succeeded);
                if observed != expected {
                    return Err(ContractError::Malformed(
                        "RunFinalized outcome contradicts prior lifecycle".into(),
                    ));
                }
                if steps
                    .values()
                    .any(|state| !matches!(state, StepLifecycle::Complete))
                {
                    return Err(ContractError::Malformed(
                        "RunFinalized has an incomplete step".into(),
                    ));
                }
                if observed == RunTerminalStateV1::Succeeded && prepared_children != closed_children
                {
                    return Err(ContractError::Malformed(
                        "successful RunFinalized has a prepared child without verified closure"
                            .into(),
                    ));
                }
                terminal = Some(observed);
                finalized = true;
            }
        }
    }
    if matches!(mode, LifecycleValidationMode::StrictCurrent) && !finalized {
        return Err(ContractError::Malformed(
            "strict current chain requires exactly one RunFinalized".into(),
        ));
    }
    Ok(LifecycleValidation {
        run_id,
        terminal_state: terminal,
        finalized,
    })
}

fn require_step_state(
    steps: &std::collections::BTreeMap<CurrentStepId, StepLifecycle>,
    step_id: &CurrentStepId,
    expected: StepLifecycle,
    event: &str,
) -> Result<(), ContractError> {
    if steps.get(step_id) != Some(&expected) {
        return Err(ContractError::Malformed(format!(
            "{event} violates step ordering"
        )));
    }
    Ok(())
}

fn set_terminal(
    terminal: &mut Option<RunTerminalStateV1>,
    state: RunTerminalStateV1,
) -> Result<(), ContractError> {
    if terminal.replace(state).is_some() {
        return Err(ContractError::Malformed(
            "multiple terminal causes are not admitted".into(),
        ));
    }
    Ok(())
}

/// Genesis seed for the chain. The chain is bound to the program identity
/// to make a tampered genesis trivially detectable.
pub const GENESIS_SEED: &[u8] = b"recursive-agent-m0-genesis";

/// Final chain digest after all receipts.
pub type ChainDigest = ContentDigest;

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn permit_material(label: &str) -> Result<PermitIdentityMaterialV1, ContractError> {
        Ok(PermitIdentityMaterialV1 {
            binding_digest: content_digest(&label)?,
            requested_not_before_delay_ms: 0,
            requested_validity_ms: 1_000,
        })
    }

    #[test]
    fn legacy_reader_is_explicit() -> TestResult {
        let id = LegacyV1Id::parse("run:abc-123")?;
        assert_eq!(id.as_str(), "run:abc-123");
        Ok(())
    }

    #[test]
    fn current_ids_reject_uuid_and_wrong_family() -> TestResult {
        assert!(CurrentRunId::try_new("550e8400-e29b-41d4-a716-446655440000").is_err());
        let step = EffectIntentId::deterministic(STEP_ID_DOMAIN, "a".repeat(64))?;
        assert!(CurrentRunId::try_new(step.to_string()).is_err());
        Ok(())
    }

    #[test]
    fn current_id_deserialization_rejects_empty_arbitrary_uuid_and_wrong_domain() -> TestResult {
        for value in [
            "",
            "arbitrary",
            "550e8400-e29b-41d4-a716-446655440000",
            "run:legacy",
            "v1:recursive-agent/step/v1:det:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let encoded = serde_json::to_string(value)?;
            assert!(serde_json::from_str::<CurrentRunId>(&encoded).is_err());
        }
        let legacy: LegacyV1Id = serde_json::from_str("\"run:legacy\"")?;
        assert_eq!(legacy.as_str(), "run:legacy");
        Ok(())
    }

    #[test]
    fn jcs_canonical_is_stable_across_reordering() -> TestResult {
        let a = serde_json::json!({"a": 1, "b": 2, "c": 3});
        let b = serde_json::json!({"c": 3, "b": 2, "a": 1});
        let ca = jcs_canonical(&a)?;
        let cb = jcs_canonical(&b)?;
        assert_eq!(ca, cb);
        Ok(())
    }

    #[test]
    fn content_digest_matches_recursive_jcs() -> TestResult {
        let v = serde_json::json!({"hello": "world", "n": 7});
        let d1 = content_digest(&v)?;
        let d2 = content_digest(&v)?;
        assert_eq!(d1, d2);
        Ok(())
    }

    #[test]
    fn id_domains_do_not_collide() -> TestResult {
        let material = permit_material("same material")?;
        let permit = derive_permit_id(&material)?;
        let receipt =
            ControlReceiptId::deterministic(RECEIPT_ID_DOMAIN, content_digest(&material)?.hex())?;
        assert_ne!(permit.as_str(), receipt.as_str());
        Ok(())
    }

    #[test]
    fn terminal_outcomes_match_every_terminal_state() {
        for state in [
            RunTerminalStateV1::Succeeded,
            RunTerminalStateV1::Failed,
            RunTerminalStateV1::Denied,
            RunTerminalStateV1::TimedOut,
            RunTerminalStateV1::Cancelled,
            RunTerminalStateV1::SandboxFailed,
            RunTerminalStateV1::Corrupted,
            RunTerminalStateV1::LegacyUnknown,
        ] {
            let outcome = state.receipt_outcome("test reason");
            if state == RunTerminalStateV1::LegacyUnknown {
                assert_eq!(outcome.terminal_state(), None);
            } else {
                assert_eq!(outcome.terminal_state(), Some(state));
            }
            assert_eq!(
                state.permits_successful_finalization(),
                matches!(outcome, ReceiptOutcomeV1::Ok)
            );
        }
    }

    #[test]
    fn lineage_requires_request_then_effect() -> TestResult {
        let chain = vec![AuthorityLineageEntryV1 {
            origin: LineageOrigin::Request,
            principal: "ra".into(),
            permit_id: None,
            policy_version: "m0".into(),
        }];
        let Err(err) = validate_lineage(&chain) else {
            return Err("incomplete lineage unexpectedly passed".into());
        };
        assert!(matches!(err, ContractError::Malformed(_)));
        Ok(())
    }

    #[test]
    fn lineage_full_chain_passes() -> TestResult {
        let permit = derive_permit_id(&permit_material("lineage")?)?;
        let chain = vec![
            AuthorityLineageEntryV1 {
                origin: LineageOrigin::Request,
                principal: "ra".into(),
                permit_id: None,
                policy_version: "m0".into(),
            },
            AuthorityLineageEntryV1 {
                origin: LineageOrigin::Plan,
                principal: "ra".into(),
                permit_id: None,
                policy_version: "m0".into(),
            },
            AuthorityLineageEntryV1 {
                origin: LineageOrigin::Policy,
                principal: "ra".into(),
                permit_id: Some(permit.clone()),
                policy_version: "m0".into(),
            },
            AuthorityLineageEntryV1 {
                origin: LineageOrigin::Tool,
                principal: "ra".into(),
                permit_id: Some(permit.clone()),
                policy_version: "m0".into(),
            },
            AuthorityLineageEntryV1 {
                origin: LineageOrigin::Effect,
                principal: "ra".into(),
                permit_id: Some(permit),
                policy_version: "m0".into(),
            },
        ];
        validate_lineage(&chain)?;
        Ok(())
    }
}
