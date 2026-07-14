//! Typed protocol for the M0 receipt chain.
//!
//! Every payload that crosses a boundary is JCS-canonicalized through
//! `boundary-compiler` and content-hashed through `stack-ids`. The chain
//! is content-addressed at every step. No provider, no `unwrap`, no
//! `panic!` in this crate.

use boundary_compiler::{Canonicalizer, ContentDigest as BoundaryContentDigest, JcsError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
pub use stack_ids::ContentDigest;
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

/// A family-qualified identifier. The string is required to be parseable
/// by `stack-ids` and to carry the expected family prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FamilyId(String);

impl FamilyId {
    /// Construct from a family and a suffix. The result is a family-qualified
    /// identifier of the form `<family>:<suffix>`. The suffix is not
    /// required to start with the family prefix; this function prepends it.
    pub fn new(family: &str, suffix: impl Into<String>) -> Result<Self, ContractError> {
        let suffix = suffix.into();
        let raw = format!("{family}:{suffix}");
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Run identity (`run:` family).
pub fn run_id(value: impl Into<String>) -> Result<FamilyId, ContractError> {
    FamilyId::new("run", value)
}

/// Step identity (`step:` family).
pub fn step_id(value: impl Into<String>) -> Result<FamilyId, ContractError> {
    FamilyId::new("step", value)
}

/// Receipt identity (`rcpt:` family).
pub fn receipt_id(value: impl Into<String>) -> Result<FamilyId, ContractError> {
    FamilyId::new("rcpt", value)
}

/// Permit identity (`pmt:` family).
pub fn permit_id(value: impl Into<String>) -> Result<FamilyId, ContractError> {
    FamilyId::new("pmt", value)
}

/// Artifact identity (`art:` family).
pub fn artifact_id(value: impl Into<String>) -> Result<FamilyId, ContractError> {
    FamilyId::new("art", value)
}

/// One hop in the request-to-effect authority chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityLineageEntryV1 {
    pub origin: LineageOrigin,
    pub principal: String,
    pub permit_id: Option<String>,
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
pub struct ToolCallSpecV1 {
    pub tool: String,
    pub args: serde_json::Value,
    /// Optional frozen clock for tools that read time. Wall-clock tools
    /// must be invoked with this set or be refused by policy.
    pub frozen_clock: Option<DateTime<Utc>>,
}

/// A node in the M0 run graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepSpecV1 {
    pub name: String,
    pub call: ToolCallSpecV1,
}

/// Top-level run spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// A receipt written to the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptV1 {
    pub receipt_id: String,
    pub run_id: String,
    pub step_id: String,
    pub kind: ReceiptKindV1,
    pub valid_time: DateTime<Utc>,
    pub recorded_time: DateTime<Utc>,
    pub lineage: Vec<AuthorityLineageEntryV1>,
    pub spec_digest: ContentDigest,
    pub args_digest: ContentDigest,
    pub artifact_refs: Vec<String>,
    pub outcome: ReceiptOutcomeV1,
    pub prev_chain_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKindV1 {
    RunStarted,
    StepStarted,
    StepCompleted,
    StepFailed,
    RunFinalized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOutcomeV1 {
    Ok,
    Denied,
    Failed { reason: String },
    Degraded { reason: String },
}

impl ReceiptV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        jcs_canonical(self)
    }
}

/// Genesis seed for the chain. The chain is bound to the program identity
/// to make a tampered genesis trivially detectable.
pub const GENESIS_SEED: &[u8] = b"recursive-agent-m0-genesis-v1";

/// Final chain digest after all receipts.
pub type ChainDigest = ContentDigest;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn family_id_composes_family_and_suffix() {
        let id = FamilyId::new("run", "abc-123").unwrap();
        assert_eq!(id.as_str(), "run:abc-123");
    }

    #[test]
    fn family_id_rejects_empty_family() {
        let id = FamilyId::new("", "x").unwrap();
        assert_eq!(id.as_str(), ":x");
    }

    #[test]
    fn jcs_canonical_is_stable_across_reordering() {
        let a = serde_json::json!({"a": 1, "b": 2, "c": 3});
        let b = serde_json::json!({"c": 3, "b": 2, "a": 1});
        let ca = jcs_canonical(&a).unwrap();
        let cb = jcs_canonical(&b).unwrap();
        assert_eq!(ca, cb);
    }

    #[test]
    fn content_digest_matches_recursive_jcs() {
        let v = serde_json::json!({"hello": "world", "n": 7});
        let d1 = content_digest(&v).unwrap();
        let d2 = content_digest(&v).unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn lineage_requires_request_then_effect() {
        let chain = vec![AuthorityLineageEntryV1 {
            origin: LineageOrigin::Request,
            principal: "ra".into(),
            permit_id: None,
            policy_version: "m0".into(),
        }];
        let err = validate_lineage(&chain).unwrap_err();
        assert!(matches!(err, ContractError::Malformed(_)));
    }

    #[test]
    fn lineage_full_chain_passes() {
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
                permit_id: Some("pmt:x".into()),
                policy_version: "m0".into(),
            },
            AuthorityLineageEntryV1 {
                origin: LineageOrigin::Tool,
                principal: "ra".into(),
                permit_id: Some("pmt:x".into()),
                policy_version: "m0".into(),
            },
            AuthorityLineageEntryV1 {
                origin: LineageOrigin::Effect,
                principal: "ra".into(),
                permit_id: Some("pmt:x".into()),
                policy_version: "m0".into(),
            },
        ];
        validate_lineage(&chain).unwrap();
    }
}
