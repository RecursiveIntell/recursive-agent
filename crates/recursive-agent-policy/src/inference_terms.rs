//! Immutable monetary terms, not a bank, tariff oracle or execution capability.
use super::{invalid, overrun};
use crate::{looks_like_credential_material, PolicyError};
use recursive_agent_contracts::{content_digest, parse_strict_json_value, ContentDigest};

/// Shared integer rate/resource semantics consumed by both V1 family grants
/// and campaign terms. Not a reservation, funding enrollment or permission.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceBudgetLimitsV1 {
    pub input_nanodollars_per_token: u64,
    pub output_nanodollars_per_token: u64,
    pub max_input_tokens_per_send: u64,
    pub max_output_tokens_per_send: u64,
    pub max_total_input_tokens: u64,
    pub max_total_output_tokens: u64,
    pub max_sends: u64,
    pub max_total_nanodollars: u64,
}
impl InferenceBudgetLimitsV1 {
    /// The full per-send reservation, not observed usage or expected billing.
    /// Checked integer arithmetic preserves the existing no-refund owner law.
    pub fn quote_nanodollars(&self) -> Result<u64, PolicyError> {
        if self.max_sends == 0
            || self.max_sends > 1024
            || self.input_nanodollars_per_token == 0
            || self.output_nanodollars_per_token == 0
            || self.max_input_tokens_per_send == 0
            || self.max_output_tokens_per_send == 0
            || self.max_input_tokens_per_send > self.max_total_input_tokens
            || self.max_output_tokens_per_send > self.max_total_output_tokens
            || self.max_total_nanodollars == 0
        {
            return Err(invalid());
        }
        let quote = self
            .max_input_tokens_per_send
            .checked_mul(self.input_nanodollars_per_token)
            .and_then(|input| {
                self.max_output_tokens_per_send
                    .checked_mul(self.output_nanodollars_per_token)
                    .and_then(|output| input.checked_add(output))
            })
            .ok_or_else(overrun)?;
        if quote > self.max_total_nanodollars {
            return Err(overrun());
        }
        Ok(quote)
    }
    fn values(&self) -> [u64; 8] {
        [
            self.input_nanodollars_per_token,
            self.output_nanodollars_per_token,
            self.max_input_tokens_per_send,
            self.max_output_tokens_per_send,
            self.max_total_input_tokens,
            self.max_total_output_tokens,
            self.max_sends,
            self.max_total_nanodollars,
        ]
    }
}

/// Closed content-addressed monetary terms. A tariff digest identifies retained
/// evidence; this type does NOT verify the tariff's external truth, tokenizer,
/// hidden retries, physical request bounds, mission/task binding or invoice.
/// Deserialization/comparison grants no money, permit or network authority.
///
/// ```compile_fail
/// use recursive_agent_policy::InferenceBudgetTermsV1;
/// fn send(terms: InferenceBudgetTermsV1) { terms.begin_inference(); }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceBudgetTermsV1 {
    pub schema: String,
    pub provider: String,
    pub model: String,
    pub api_mode: String,
    pub reasoning_effort: String,
    pub tariff_digest: ContentDigest,
    pub limits: InferenceBudgetLimitsV1,
}
impl InferenceBudgetTermsV1 {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.schema != "recursive-agent.inference-budget-terms/v1"
            || self
                .limits
                .values()
                .iter()
                .any(|value| *value > (1_u64 << 53) - 1)
        {
            return Err(invalid());
        }
        for value in [
            &self.provider,
            &self.model,
            &self.api_mode,
            &self.reasoning_effort,
        ] {
            // Same bounded, credential-free route material as the budget owner.
            if value.is_empty()
                || value.len() > 256
                || value.chars().any(char::is_control)
                || looks_like_credential_material(value)
            {
                return Err(invalid());
            }
        }
        self.limits.quote_nanodollars()?;
        Ok(())
    }

    /// Owner content_digest over the entire validated terms object using the
    /// existing canonical serializer; no caller-provided digest is trusted.
    pub fn computed_digest(&self) -> Result<ContentDigest, PolicyError> {
        self.validate()?;
        Ok(content_digest(self)?)
    }

    /// Bounded strict JSON admission; duplicate/unknown fields and non-object
    /// inputs refuse rather than normalizing an untrusted terms artifact.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PolicyError> {
        if bytes.len() > 65_536 {
            return Err(invalid());
        }
        let value = parse_strict_json_value(bytes).map_err(|_| invalid())?;
        let terms: Self = serde_json::from_value(value)?;
        terms.validate()?;
        Ok(terms)
    }
}
