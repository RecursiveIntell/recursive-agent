//! Pure future-daemon protocol decoding for the bounded Phase 1 build.
//!
//! This crate owns no listener, filesystem path, runtime, receipt, thread, or
//! effect boundary. A later admitted phase may place transport around these
//! data shapes; Phase 1 only shares the canonical bounded RunSpec decoder.

pub mod protocol;
pub mod server;
pub mod socket;

pub use protocol::{
    decode_frame_payload, decode_request_frame, ConnectionRequestIds, FrameDecodeError,
    IpcDecodeError, IpcRequestEnvelopeV1, IpcRequestV1, FRAME_PREFIX_BYTES,
    IPC_PROTOCOL_VERSION_V1, IPC_REQUEST_SCHEMA_V1, MAX_FRAME_PAYLOAD_BYTES,
    MAX_REQUEST_IDS_PER_CONNECTION,
};
pub use server::{serve, ServerError};
pub use socket::{bind_private_socket, peer_principal, PeerPrincipal, SocketError};

use recursive_agent_contracts::{parse_run_spec_bytes, RunSpecIngressError, RunSpecV1};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DaemonDecodeErrorV1 {
    InputTooLarge,
    DuplicateKey,
    MalformedOrUnknownField,
    CanonicalBoundary,
    TooManySteps,
    MaterialTooLarge,
    FieldTooLarge,
    TooManyItems,
    InvalidSemanticField,
    InvalidToolArguments,
    NonRegularTransportInput,
}

impl From<RunSpecIngressError> for DaemonDecodeErrorV1 {
    fn from(error: RunSpecIngressError) -> Self {
        match error {
            RunSpecIngressError::InputTooLarge { .. } => Self::InputTooLarge,
            RunSpecIngressError::DuplicateKey => Self::DuplicateKey,
            RunSpecIngressError::Malformed => Self::MalformedOrUnknownField,
            RunSpecIngressError::CanonicalBoundary => Self::CanonicalBoundary,
            RunSpecIngressError::TooManySteps { .. } => Self::TooManySteps,
            RunSpecIngressError::MaterialTooLarge { .. } => Self::MaterialTooLarge,
            RunSpecIngressError::FieldTooLarge { .. } => Self::FieldTooLarge,
            RunSpecIngressError::TooManyItems { .. } => Self::TooManyItems,
            RunSpecIngressError::InvalidSemanticField { .. } => Self::InvalidSemanticField,
            RunSpecIngressError::InvalidToolArguments => Self::InvalidToolArguments,
            RunSpecIngressError::NotRegularFile | RunSpecIngressError::Io(_) => {
                Self::NonRegularTransportInput
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodedRunSpecV1 {
    pub spec: RunSpecV1,
}

pub fn decode_run_spec(request: &[u8]) -> Result<DecodedRunSpecV1, DaemonDecodeErrorV1> {
    parse_run_spec_bytes(request)
        .map(|spec| DecodedRunSpecV1 { spec })
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_decoder_accepts_valid_pure_shape() -> Result<(), Box<dyn std::error::Error>> {
        let request = serde_json::to_vec(&serde_json::json!({
            "name": "daemon-decode",
            "policy_version": "m0-2",
            "steps": [{"name": "echo", "call": {"tool": "echo", "args": {"text": "ok"}}}]
        }))?;
        let decoded = decode_run_spec(&request).map_err(|error| format!("{error:?}"))?;
        assert_eq!(decoded.spec.name, "daemon-decode");
        Ok(())
    }

    #[test]
    fn shared_decoder_rejects_duplicates_and_unknown_fields() {
        assert_eq!(
            decode_run_spec(br#"{"name":"a","name":"b","policy_version":"m0-2","steps":[]}"#),
            Err(DaemonDecodeErrorV1::DuplicateKey)
        );
        assert_eq!(
            decode_run_spec(br#"{"name":"a","policy_version":"m0-2","steps":[],"extra":true}"#),
            Err(DaemonDecodeErrorV1::MalformedOrUnknownField)
        );
    }

    #[test]
    fn shared_decoder_preserves_semantic_limit_classes() -> Result<(), Box<dyn std::error::Error>> {
        let oversized_name = serde_json::to_vec(&serde_json::json!({
            "name": "n".repeat(257),
            "policy_version": "m0-2",
            "steps": [{"name": "echo", "call": {"tool": "echo", "args": {"text": "ok"}}}]
        }))?;
        assert_eq!(
            decode_run_spec(&oversized_name),
            Err(DaemonDecodeErrorV1::FieldTooLarge)
        );

        let empty_steps = serde_json::to_vec(&serde_json::json!({
            "name": "daemon-decode",
            "policy_version": "m0-2",
            "steps": []
        }))?;
        assert_eq!(
            decode_run_spec(&empty_steps),
            Err(DaemonDecodeErrorV1::InvalidSemanticField)
        );

        let excessive_args = serde_json::to_vec(&serde_json::json!({
            "name": "daemon-decode",
            "policy_version": "m0-2",
            "steps": [{"name": "shell", "call": {"tool": "shell", "args": {
                "command": "/usr/bin/printf",
                "args": (0..65).map(|_| "x").collect::<Vec<_>>(),
                "timeout_ms": 1000
            }}}]
        }))?;
        assert_eq!(
            decode_run_spec(&excessive_args),
            Err(DaemonDecodeErrorV1::TooManyItems)
        );
        Ok(())
    }
}
