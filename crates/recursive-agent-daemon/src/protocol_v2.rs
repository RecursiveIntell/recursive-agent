//! Closed normal-chat IPC v2. This module decodes nonauthorizing requests only;
//! no v1 fallback, grant enrollment, caller-selected ordinal or send capability.
use crate::protocol::{decode_frame_payload, IpcDecodeError};
use recursive_agent_contracts::{
    jcs_canonical, parse_normal_chat_call_request_v2_bytes, parse_strict_json_value, ContentDigest,
    CurrentRunId, NormalChatCallRequestV2, StrictJsonError,
};
use recursive_agent_policy::{
    parse_normal_chat_executor_report_v2_bytes, NormalChatExecutorReportV2,
};
use serde::{Deserialize, Serialize};

pub const IPC_REQUEST_SCHEMA_V2: &str = "recursive-agent.ipc/request/v2";
pub const IPC_RESPONSE_SCHEMA_V2: &str = "recursive-agent.ipc/response/v2";
pub const IPC_PROTOCOL_VERSION_V2: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedIpcEnvelopeV2 {
    pub schema: String,
    pub protocol_version: u16,
    pub request_id: String,
    pub request: GovernedIpcRequestV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalChatCloseReasonV2 {
    SessionFinalized,
    SessionReset,
    TtlExpired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GovernedIpcRequestV2 {
    /// Parser/startup metadata only: no session, grant enrollment or send.
    NormalChatCapabilities {},
    NormalChatSessionOpen {
        conversation_ref: String,
        parent_session_run_id: Option<CurrentRunId>,
    },
    NormalChatAttemptBegin {
        session_run_id: CurrentRunId,
        call: Box<NormalChatCallRequestV2>,
    },
    NormalChatAttemptSettle {
        session_run_id: CurrentRunId,
        dispatch_intent_ref: String,
        preflight_receipt_digest: ContentDigest,
        report: Box<NormalChatExecutorReportV2>,
    },
    NormalChatAttemptReadback {
        session_run_id: CurrentRunId,
        dispatch_intent_ref: String,
    },
    NormalChatRunClose {
        session_run_id: CurrentRunId,
        reason: NormalChatCloseReasonV2,
    },
}

fn bounded_ref(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

pub fn decode_governed_request_frame(
    input: &[u8],
) -> Result<GovernedIpcEnvelopeV2, IpcDecodeError> {
    let bytes = decode_frame_payload(input)?;
    let value = parse_strict_json_value(bytes).map_err(|e| match e {
        StrictJsonError::DuplicateKey => IpcDecodeError::DuplicateKey,
        StrictJsonError::Malformed => IpcDecodeError::Malformed,
    })?;
    let canonical = jcs_canonical(&value).map_err(|_| IpcDecodeError::Malformed)?;
    let envelope: GovernedIpcEnvelopeV2 =
        serde_json::from_value(value).map_err(|_| IpcDecodeError::Malformed)?;
    // Reject ignored enum members, inserted Option nulls/defaults or any lossy
    // typed representation; JSON formatting itself need not be canonical on wire.
    if jcs_canonical(&envelope).map_err(|_| IpcDecodeError::Malformed)? != canonical
        || envelope.schema != IPC_REQUEST_SCHEMA_V2
        || !bounded_ref(&envelope.request_id, 256)
    {
        return Err(IpcDecodeError::Malformed);
    }
    if envelope.protocol_version != IPC_PROTOCOL_VERSION_V2 {
        return Err(IpcDecodeError::UnsupportedProtocolVersion {
            received: envelope.protocol_version,
            supported: IPC_PROTOCOL_VERSION_V2,
        });
    }
    match &envelope.request {
        GovernedIpcRequestV2::NormalChatCapabilities {} => {}
        GovernedIpcRequestV2::NormalChatSessionOpen {
            conversation_ref, ..
        } => {
            if !bounded_ref(conversation_ref, 4096) {
                return Err(IpcDecodeError::Malformed);
            }
        }
        GovernedIpcRequestV2::NormalChatAttemptBegin {
            session_run_id,
            call,
        } => {
            parse_normal_chat_call_request_v2_bytes(
                &jcs_canonical(call).map_err(|_| IpcDecodeError::Malformed)?,
            )
            .map_err(|_| IpcDecodeError::Malformed)?;
            if call.operation.parent_run_id != *session_run_id {
                return Err(IpcDecodeError::Malformed);
            }
        }
        GovernedIpcRequestV2::NormalChatAttemptSettle {
            dispatch_intent_ref,
            report,
            ..
        } => {
            NormalChatCallRequestV2::validate_dispatch_intent_ref(dispatch_intent_ref)
                .map_err(|_| IpcDecodeError::Malformed)?;
            parse_normal_chat_executor_report_v2_bytes(
                &jcs_canonical(report).map_err(|_| IpcDecodeError::Malformed)?,
            )
            .map_err(|_| IpcDecodeError::Malformed)?;
        }
        GovernedIpcRequestV2::NormalChatAttemptReadback {
            dispatch_intent_ref,
            ..
        } => {
            NormalChatCallRequestV2::validate_dispatch_intent_ref(dispatch_intent_ref)
                .map_err(|_| IpcDecodeError::Malformed)?;
        }
        GovernedIpcRequestV2::NormalChatRunClose { .. } => {}
    }
    Ok(envelope)
}
