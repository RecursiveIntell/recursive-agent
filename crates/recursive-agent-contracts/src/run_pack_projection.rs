//! Strict transport contract for a server-side observation of an already
//! verified Recursive Agent Run Pack. This is a projection, never a receipt,
//! authority grant, or substitute for the immutable pack bytes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    content_digest, jcs_canonical, ContentDigest, ContractError, CurrentRunId, RunTerminalStateV1,
};

/// Closed availability state for a vaulted immutable Run Pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunPackRetentionStateV1 {
    Available,
    Quarantined,
    PackUnavailable,
    Tampered,
    Superseded,
}

/// A verification outcome emitted only after a local pack verifier succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunPackVerificationOutcomeV1 {
    Verified,
}

/// Server-derived verification facts. A caller-supplied value is inadmissible
/// until a vault admission boundary independently reruns verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunPackVerificationV1 {
    pub verifier_contract_version: String,
    pub verified_at: DateTime<Utc>,
    pub verification_receipt_digest: ContentDigest,
    pub outcome: RunPackVerificationOutcomeV1,
}

/// Opaque vault location. `relative_ref` is a storage-relative reference, not
/// an operator-supplied filesystem path or a durable execution identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunPackVaultRefV1 {
    pub object_id: String,
    pub relative_ref: String,
    pub retention_state: RunPackRetentionStateV1,
}

/// Bounded origin metadata. It carries no prompt, provider response, secret,
/// executable path, or unbounded event payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunPackProjectionOriginV1 {
    pub operator_adapter: String,
    pub source_device_ref: Option<String>,
    pub observed_at: Option<DateTime<Utc>>,
    pub recorded_at: DateTime<Utc>,
}

/// Receipt-derived execution summary. It is descriptive and cannot replace
/// receipt-chain verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunPackEventSummaryV1 {
    pub terminal_state: RunTerminalStateV1,
    pub receipt_chain_digest: ContentDigest,
    pub artifact_digests: Vec<ContentDigest>,
}

/// Strict V1 projection for an exactly verified portable Run Pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunPackEvidenceProjectionV1 {
    pub schema: String,
    pub projection_id: ContentDigest,
    pub run_id: CurrentRunId,
    pub pack_manifest_digest: ContentDigest,
    pub pack_content_digest: ContentDigest,
    pub verification: RunPackVerificationV1,
    pub vault: RunPackVaultRefV1,
    pub origin: RunPackProjectionOriginV1,
    pub event_summary: RunPackEventSummaryV1,
}

impl RunPackEvidenceProjectionV1 {
    pub const SCHEMA: &'static str = "RunPackEvidenceProjectionV1";

    /// Validate closed schema, bounded strings, safe vault reference, and
    /// sorted unique artifact digest set. No permissive compatibility parsing.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema != Self::SCHEMA {
            return Err(ContractError::Malformed(
                "unsupported run-pack evidence projection schema".into(),
            ));
        }
        validate_bounded_nonempty(
            "verifier contract version",
            &self.verification.verifier_contract_version,
            128,
        )?;
        validate_bounded_nonempty("vault object id", &self.vault.object_id, 256)?;
        validate_safe_relative_ref(&self.vault.relative_ref)?;
        if self.origin.operator_adapter != "hermes-native" {
            return Err(ContractError::Malformed(
                "unsupported operator adapter".into(),
            ));
        }
        if let Some(device_ref) = &self.origin.source_device_ref {
            validate_bounded_nonempty("source device reference", device_ref, 256)?;
        }
        let mut previous = None;
        for digest in &self.event_summary.artifact_digests {
            let value = digest.to_string();
            if previous
                .as_ref()
                .is_some_and(|last: &String| last >= &value)
            {
                return Err(ContractError::Malformed(
                    "artifact digests must be unique and sorted".into(),
                ));
            }
            previous = Some(value);
        }
        let expected_id = self.derived_projection_id()?;
        if self.projection_id != expected_id {
            return Err(ContractError::Malformed(
                "projection id does not bind projection material".into(),
            ));
        }
        Ok(())
    }

    /// Canonical bytes for detached validation and cross-owner fixture reuse.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        jcs_canonical(self)
    }

    /// Derive the domain-bound projection identity from stable evidence fields.
    pub fn derived_projection_id(&self) -> Result<ContentDigest, ContractError> {
        content_digest(&RunPackEvidenceProjectionIdentityMaterialV1 {
            schema: Self::SCHEMA,
            run_id: &self.run_id,
            pack_manifest_digest: &self.pack_manifest_digest,
            pack_content_digest: &self.pack_content_digest,
            verifier_contract_version: &self.verification.verifier_contract_version,
            verification_receipt_digest: &self.verification.verification_receipt_digest,
        })
    }
}

#[derive(Serialize)]
struct RunPackEvidenceProjectionIdentityMaterialV1<'a> {
    schema: &'static str,
    run_id: &'a CurrentRunId,
    pack_manifest_digest: &'a ContentDigest,
    pack_content_digest: &'a ContentDigest,
    verifier_contract_version: &'a str,
    verification_receipt_digest: &'a ContentDigest,
}

fn validate_bounded_nonempty(
    field: &str,
    value: &str,
    maximum: usize,
) -> Result<(), ContractError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(ContractError::Malformed(format!("invalid {field}")));
    }
    Ok(())
}

fn validate_safe_relative_ref(value: &str) -> Result<(), ContractError> {
    validate_bounded_nonempty("vault relative reference", value, 1024)?;
    if value.contains('\\')
        || value.contains(':')
        || value.starts_with('/')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ContractError::Malformed(
            "unsafe vault relative reference".into(),
        ));
    }
    Ok(())
}
