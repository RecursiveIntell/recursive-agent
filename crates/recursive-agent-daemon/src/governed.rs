//! Framing/translation only. Native runtime/policy/ledger own all authority and
//! durable state. No provider execution, IPC grant enrollment or status reissue.
use crate::protocol_v2::{GovernedIpcEnvelopeV2, GovernedIpcRequestV2, IPC_RESPONSE_SCHEMA_V2};
use crate::server::ServerError;
use recursive_agent_policy::PolicyError;
use recursive_agent_runner::{RuntimeNormalChatBeginV2, RuntimeService, RuntimeServiceError};
use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::Instant;

fn denied(error: &RuntimeServiceError) -> Value {
    let code = match error {
        RuntimeServiceError::NormalChatGovernanceDisabled => "GRANT_MISSING".to_string(),
        RuntimeServiceError::NormalChatSessionBusy => "DAEMON_OVERLOADED".to_string(),
        RuntimeServiceError::Policy(PolicyError::NormalChatEgressDenied(code)) => code.to_string(),
        _ => "MALFORMED".to_string(),
    };
    json!({"kind":"denied","code":code,"provider_attempted":false})
}
fn envelope(request: &GovernedIpcEnvelopeV2, result: Value) -> Value {
    json!({"schema":IPC_RESPONSE_SCHEMA_V2,"protocol_version":2,
        "request_id":request.request_id,"result":result})
}
fn bytes(value: &Value) -> std::io::Result<Vec<u8>> {
    let body = serde_json::to_vec(value)?;
    if body.len() > crate::MAX_FRAME_PAYLOAD_BYTES {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut frame = u32::try_from(body.len())
        .map_err(|_| std::io::ErrorKind::InvalidData)?
        .to_be_bytes()
        .to_vec();
    frame.extend(body);
    Ok(frame)
}
/// Each partial write shares the SAME absolute deadline; never write_all with
/// a relative timeout that restarts after every short write. An incomplete frame
/// is a failed publication and never authorizes transport at the client.
fn write_until(out: &mut UnixStream, frame: &[u8], deadline: Instant) -> std::io::Result<()> {
    let mut position = 0;
    while position < frame.len() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(std::io::ErrorKind::TimedOut)?;
        out.set_write_timeout(Some(remaining))?;
        match out.write(&frame[position..]) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => position += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    if Instant::now() >= deadline {
        return Err(std::io::ErrorKind::TimedOut.into());
    }
    Ok(())
}

/// Successful Fresh responses are written INSIDE the consuming native fence.
/// All other values are evidence/denials and are returned for normal framing.
pub(crate) fn dispatch(
    request: &GovernedIpcEnvelopeV2,
    runtime: &RuntimeService,
) -> Result<Option<Value>, ServerError> {
    use GovernedIpcRequestV2 as R;
    let result: Result<Value, RuntimeServiceError> = (|| match &request.request {
        R::NormalChatCapabilities {} => {
            let grant = runtime.normal_chat_egress_policy();
            Ok(
                json!({"kind":"normal_chat_capabilities","grant_loaded":grant.is_some(),
                "grant":grant,"response_projection_schemas":[
                    recursive_agent_policy::NormalChatResponseProjectionV2::AresResponseJsonSortedV1,
                    recursive_agent_policy::NormalChatResponseProjectionV2::AresTransportResponseBodyV1
                ]}),
            )
        }
        R::NormalChatSessionOpen {
            conversation_ref,
            parent_session_run_id,
        } => {
            if parent_session_run_id.is_some() {
                return Err(RuntimeServiceError::NormalChatSessionRecoveryRequired {
                    reason: "subagent session lineage requires canonical composition",
                });
            }
            let session = runtime.open_or_lookup_normal_chat_session(conversation_ref)?;
            let grant = runtime
                .normal_chat_egress_policy()
                .ok_or(RuntimeServiceError::NormalChatGovernanceDisabled)?;
            Ok(
                json!({"kind":"normal_chat_session_opened","session_run_id":session.run_id(),
                    "session":session.session(),"grant":grant,"parent_chain_head":session.verified_prefix_head()}),
            )
        }
        R::NormalChatAttemptBegin { .. } => {
            Err(RuntimeServiceError::NormalChatSessionRecoveryRequired {
                reason: "begin requires consuming publication boundary",
            })
        }
        R::NormalChatAttemptSettle {
            session_run_id,
            dispatch_intent_ref,
            preflight_receipt_digest,
            report,
        } => {
            let historical =
                runtime.read_normal_chat_attempt(session_run_id, dispatch_intent_ref)?;
            let session = runtime.lookup_normal_chat_session(session_run_id)?;
            let settled = runtime.settle_normal_chat_attempt(
                &session,
                historical.request(),
                preflight_receipt_digest,
                report,
            )?;
            Ok(
                json!({"kind":"normal_chat_attempt_settled","settlement":settled.settlement(),
                    "terminal_state":settled.terminal_state(),"child_chain_head":settled.child_chain_head(),
                    "parent_chain_head":settled.parent_chain_head()}),
            )
        }
        R::NormalChatAttemptReadback {
            session_run_id,
            dispatch_intent_ref,
        } => {
            let view = runtime.read_normal_chat_attempt(session_run_id, dispatch_intent_ref)?;
            Ok(
                json!({"kind":"normal_chat_attempt_readback","send_authorized":false,
                    "request":view.request(),"policy":view.policy(),"recovery":view.recovery(),
                    "parent_chain_head":view.parent_chain_head(),"child_chain_head":view.child_chain_head()}),
            )
        }
        R::NormalChatRunClose {
            session_run_id,
            reason: _,
        } => {
            let session = runtime.lookup_normal_chat_session(session_run_id)?;
            let closed = runtime.close_normal_chat_session(&session)?;
            Ok(
                json!({"kind":"normal_chat_run_closed","session_run_id":session_run_id,
                    "terminal_state":closed.terminal_state(),"final_chain_digest":closed.chain_head(),
                    "normal_chat_status":{"state":if closed.all_attempts_reported_success(){"succeeded"}else{"failed"},
                    "outcome_evidence":"executor_reported","attempts_verified":true}}),
            )
        }
    })();
    // Begin is special: never evaluate it twice, and never transform partial
    // publication into an ordinary denial followed by another authorizing frame.
    match result {
        Ok(value) => Ok(Some(envelope(request, value))),
        Err(error) => Ok(Some(envelope(request, denied(&error)))),
    }
}

pub(crate) fn dispatch_begin(
    request: &GovernedIpcEnvelopeV2,
    runtime: &RuntimeService,
    out: &mut UnixStream,
) -> Result<Option<Value>, ServerError> {
    let GovernedIpcRequestV2::NormalChatAttemptBegin {
        session_run_id,
        call,
    } = &request.request
    else {
        return dispatch(request, runtime);
    };
    let begin = (|| {
        let session = runtime.lookup_normal_chat_session(session_run_id)?;
        runtime.begin_normal_chat_attempt(&session, call)
    })();
    match begin {
        Err(error) => Ok(Some(envelope(request, denied(&error)))),
        Ok(RuntimeNormalChatBeginV2::Existing(existing)) => Ok(Some(envelope(
            request,
            json!({
            "kind":"normal_chat_attempt_existing","send_authorized":false,
            "attempt":existing.reservation.attempt,"policy":existing.child_policy}),
        ))),
        Ok(RuntimeNormalChatBeginV2::Fresh(fresh)) => {
            let mut publication_started = false;
            let result=runtime.release_normal_chat_attempt(*fresh,|dispatch| {
                let frame=bytes(&envelope(request,json!({"kind":"normal_chat_attempt_admitted",
                    "send_authorized":true,"attempt":dispatch.attempt(),"permit_id":dispatch.permit_id(),
                    "preflight_receipt_digest":dispatch.preflight_digest(),"expires_at":dispatch.expires_at(),
                    "admitted_at":dispatch.admitted_at(),"parent_chain_head":dispatch.parent_chain_head(),
                    "child_chain_head":dispatch.child_chain_head()})))?;
                publication_started=true;
                write_until(out,&frame,dispatch.publication_deadline())
            });
            match result {
                Ok(()) => Ok(None),
                Err(error) if publication_started => Err(ServerError::Runtime(error)),
                Err(error) => Ok(Some(envelope(request, denied(&error)))),
            }
        }
    }
}
