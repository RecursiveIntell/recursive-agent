//! Single owner for strict raw admission and closed native operation-family selection.
use thiserror::Error;

use crate::{
    operation::parse_operation_envelope_value, parse_strict_json_value,
    provider_egress_operation::parse_provider_egress_operation_v3_value, OperationEnvelopeV1,
    OperationIngressError, ProviderEgressOperationEnvelopeV3, ProviderEgressOperationIngressError,
    StrictJsonError, MAX_RUN_SPEC_INPUT_BYTES,
};

/// A strictly admitted native operation; V3 cannot downgrade to V1.
#[derive(Debug)]
pub enum NativeOperation {
    V1(Box<OperationEnvelopeV1>),
    ProviderEgressV3(Box<ProviderEgressOperationEnvelopeV3>),
}

/// Failures before any daemon runtime call; family-specific validation stays with its owner.
#[derive(Debug, Error)]
pub enum NativeOperationIngressError {
    #[error("native operation exceeds the byte limit of {maximum_bytes}")]
    InputTooLarge { maximum_bytes: u64 },
    #[error("native operation contains a duplicate object key")]
    DuplicateKey,
    #[error("native operation JSON is malformed")]
    Malformed,
    #[error("unsupported native operation schema")]
    UnsupportedSchema,
    #[error("V1 operation rejected: {0}")]
    V1(#[source] OperationIngressError),
    #[error("V3 operation rejected: {0}")]
    V3(#[source] ProviderEgressOperationIngressError),
}

/// Parse hostile original bytes once through the Libraries boundary owner,
/// then validate only the selected closed operation family.
pub fn parse_native_operation_bytes(
    input: &[u8],
) -> Result<NativeOperation, NativeOperationIngressError> {
    if input.len() as u64 > MAX_RUN_SPEC_INPUT_BYTES {
        return Err(NativeOperationIngressError::InputTooLarge {
            maximum_bytes: MAX_RUN_SPEC_INPUT_BYTES,
        });
    }
    let value = parse_strict_json_value(input).map_err(|error| match error {
        StrictJsonError::DuplicateKey => NativeOperationIngressError::DuplicateKey,
        StrictJsonError::Malformed => NativeOperationIngressError::Malformed,
    })?;
    match value.get("schema").and_then(serde_json::Value::as_str) {
        Some("recursive-agent.operation/v1") => parse_operation_envelope_value(value)
            .map(|operation| NativeOperation::V1(Box::new(operation)))
            .map_err(NativeOperationIngressError::V1),
        Some("recursive-agent.operation/v3") => parse_provider_egress_operation_v3_value(value)
            .map(|operation| NativeOperation::ProviderEgressV3(Box::new(operation)))
            .map_err(NativeOperationIngressError::V3),
        _ => Err(NativeOperationIngressError::UnsupportedSchema),
    }
}
