//! Bounded native IPC framing.
//!
//! Framing is deliberately separate from payload decoding so an untrusted
//! length prefix is admitted before any payload allocation or JSON parsing.

use recursive_agent_contracts::{parse_strict_json_value, OperationEnvelopeV1, StrictJsonError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Native IPC request schema identifier.
pub const IPC_REQUEST_SCHEMA_V1: &str = "recursive-agent.ipc/request/v1";

/// Only protocol version admitted by this implementation.
pub const IPC_PROTOCOL_VERSION_V1: u16 = 1;

/// Bytes in the fixed-width big-endian frame-length prefix.
pub const FRAME_PREFIX_BYTES: usize = 4;

/// Maximum admitted payload bytes: the 1 MiB native operation ingress ceiling
/// plus 64 KiB for the closed IPC envelope and response/event metadata.
pub const MAX_FRAME_PAYLOAD_BYTES: usize = (1024 * 1024) + (64 * 1024);

/// Hard per-connection budget of admitted request identifiers. Exceeding this
/// budget is a typed denial; it bounds per-client state before any dispatch.
/// See `ConnectionRequestIds::admit`.
pub const MAX_REQUEST_IDS_PER_CONNECTION: usize = 4096;

/// Typed failures emitted before a frame payload is admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameDecodeError {
    /// The input does not yet contain the complete fixed-width prefix.
    IncompletePrefix {
        /// Prefix bytes currently available.
        received: usize,
    },
    /// The untrusted prefix exceeds the hard payload ceiling.
    DeclaredLengthTooLarge {
        /// Length declared by the untrusted prefix.
        declared: usize,
        /// Hard payload ceiling applied before payload access.
        max: usize,
    },
    /// Fewer payload bytes are available than the admitted prefix declares.
    TruncatedPayload {
        /// Length declared by the admitted prefix.
        declared: usize,
        /// Payload bytes currently available after the prefix.
        received: usize,
    },
    /// More payload bytes are present than the admitted prefix declares.
    TrailingBytes {
        /// Length declared by the admitted prefix.
        declared: usize,
        /// Bytes present after the exact declared payload.
        trailing: usize,
    },
}

/// Decode one bounded frame payload from exact input bytes.
///
/// This initial fail-closed surface recognizes only incomplete prefixes. The
/// next framing gate admits checked lengths before exposing payload bytes.
pub fn decode_frame_payload(input: &[u8]) -> Result<&[u8], FrameDecodeError> {
    if input.len() < FRAME_PREFIX_BYTES {
        return Err(FrameDecodeError::IncompletePrefix {
            received: input.len(),
        });
    }
    let declared = usize::try_from(u32::from_be_bytes([input[0], input[1], input[2], input[3]]))
        .map_err(|_| FrameDecodeError::DeclaredLengthTooLarge {
            declared: usize::MAX,
            max: MAX_FRAME_PAYLOAD_BYTES,
        })?;
    if declared > MAX_FRAME_PAYLOAD_BYTES {
        return Err(FrameDecodeError::DeclaredLengthTooLarge {
            declared,
            max: MAX_FRAME_PAYLOAD_BYTES,
        });
    }
    let received = input.len() - FRAME_PREFIX_BYTES;
    if received < declared {
        return Err(FrameDecodeError::TruncatedPayload { declared, received });
    }
    if received == declared {
        return Ok(&input[FRAME_PREFIX_BYTES..]);
    }
    Err(FrameDecodeError::TrailingBytes {
        declared,
        trailing: received - declared,
    })
}

/// Closed request envelope carried inside one admitted frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcRequestEnvelopeV1 {
    /// Exact wire schema identifier.
    pub schema: String,
    /// Wire protocol version selected by the client.
    pub protocol_version: u16,
    /// Client correlation identifier, scoped to one connection.
    pub request_id: String,
    /// Closed request body.
    pub request: IpcRequestV1,
}

/// Native requests exposed by the protocol while runtime dispatch is still
/// fenced behind later Phase 3 gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IpcRequestV1 {
    /// Read ledger-derived status for an authoritative run identifier.
    Status {
        /// Authoritative run identifier.
        run_id: String,
    },
    /// Submit one canonical native V1 operation for execution.
    Submit {
        /// Complete canonical operation envelope.
        operation: Box<OperationEnvelopeV1>,
    },
}

/// Typed failures from exact frame and request-envelope decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcDecodeError {
    /// Framing failed before payload decoding.
    Frame(FrameDecodeError),
    /// A JSON object key was duplicated at any nesting depth.
    DuplicateKey,
    /// JSON shape, closed fields, or schema identifier was invalid.
    Malformed,
    /// The client requested a protocol version this daemon cannot serve.
    UnsupportedProtocolVersion {
        /// Version supplied by the client.
        received: u16,
        /// Version currently supported by the daemon.
        supported: u16,
    },
    /// A request identifier was already admitted on this connection.
    DuplicateRequestId {
        /// Reused request identifier.
        request_id: String,
    },
    /// The per-connection request-id budget was exhausted.
    RequestIdLimitExceeded {
        /// Hard per-connection budget that was exceeded.
        max: usize,
    },
}

impl From<FrameDecodeError> for IpcDecodeError {
    fn from(error: FrameDecodeError) -> Self {
        Self::Frame(error)
    }
}

/// Connection-local registry that prevents request identifier reuse and bounds
/// admitted identifiers to `MAX_REQUEST_IDS_PER_CONNECTION`.
#[derive(Debug, Default)]
pub struct ConnectionRequestIds {
    admitted: BTreeSet<String>,
}

impl ConnectionRequestIds {
    /// Create an empty per-connection registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a request identifier once for this connection.
    ///
    /// Rejects a reused identifier with [`IpcDecodeError::DuplicateRequestId`]
    /// and an exhausted budget with [`IpcDecodeError::RequestIdLimitExceeded`].
    /// The budget is checked before insertion so an overflow cannot grow the
    /// set beyond the hard ceiling.
    pub fn admit(&mut self, request: &IpcRequestEnvelopeV1) -> Result<(), IpcDecodeError> {
        if self.admitted.contains(&request.request_id) {
            return Err(IpcDecodeError::DuplicateRequestId {
                request_id: request.request_id.clone(),
            });
        }
        if self.admitted.len() >= MAX_REQUEST_IDS_PER_CONNECTION {
            return Err(IpcDecodeError::RequestIdLimitExceeded {
                max: MAX_REQUEST_IDS_PER_CONNECTION,
            });
        }
        self.admitted.insert(request.request_id.clone());
        Ok(())
    }
}

/// Decode one exact framed request without invoking the runtime.
pub fn decode_request_frame(input: &[u8]) -> Result<IpcRequestEnvelopeV1, IpcDecodeError> {
    let payload = decode_frame_payload(input)?;
    let value = parse_strict_json_value(payload).map_err(|error| match error {
        StrictJsonError::DuplicateKey => IpcDecodeError::DuplicateKey,
        StrictJsonError::Malformed => IpcDecodeError::Malformed,
    })?;
    let request: IpcRequestEnvelopeV1 =
        serde_json::from_value(value).map_err(|_| IpcDecodeError::Malformed)?;
    if request.schema != IPC_REQUEST_SCHEMA_V1 {
        return Err(IpcDecodeError::Malformed);
    }
    if request.protocol_version != IPC_PROTOCOL_VERSION_V1 {
        return Err(IpcDecodeError::UnsupportedProtocolVersion {
            received: request.protocol_version,
            supported: IPC_PROTOCOL_VERSION_V1,
        });
    }
    Ok(request)
}
