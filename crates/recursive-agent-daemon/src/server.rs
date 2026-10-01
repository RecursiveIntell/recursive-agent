//! Bounded native IPC server: accept loop, peer authentication, per-connection
//! request correlation, and dispatch to the canonical `RuntimeService`.
//!
//! The daemon owns no execution authority. Every effect is dispatched through
//! `recursive-agent-runner::RuntimeService`, which alone owns operation
//! lifecycle and terminal evidence. This server only translates admitted
//! frames into runtime calls and streams committed results back.

use std::io::{BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use recursive_agent_contracts::{
    parse_native_operation_bytes, CurrentRunId, NativeOperation, MAX_RUN_SPEC_INPUT_BYTES,
};
use recursive_agent_runner::{RuntimeCancelResultV1, RuntimeService, RuntimeStatusV1};
use thiserror::Error;

use crate::protocol::{
    decode_request_frame, ConnectionRequestIds, FrameDecodeError, IpcDecodeError,
    IpcRequestEnvelopeV1, IpcRequestV1, IPC_PROTOCOL_VERSION_V1, IPC_REQUEST_SCHEMA_V1,
};
use crate::socket::peer_principal;

/// Hard bound on concurrent accepted connections handled by one daemon.
pub const DEFAULT_MAX_CONCURRENT: usize = 4;

/// Idle I/O timeout applied to each accepted connection. A peer that connects
/// and sends nothing (or stops reading) is evicted after this duration, so a
/// small number of idle clients cannot exhaust `max_concurrent` forever.
pub const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Errors surfaced by the daemon server.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("socket: {0}")]
    Socket(#[from] crate::socket::SocketError),
    #[error("runtime: {0}")]
    Runtime(#[from] recursive_agent_runner::RuntimeServiceError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("frame: {0:?}")]
    Frame(IpcDecodeError),
    #[error("peer denied: uid {uid} is not the daemon owner")]
    PeerDenied { uid: u32 },
    #[error("peer identity unavailable: {0}")]
    PeerIdentity(String),
    #[error("invalid run id: {0}")]
    InvalidRunId(String),
    #[error("native operation ingress: {0}")]
    NativeIngress(String),
}

fn admit_native_raw(encoded: &str) -> Result<NativeOperation, ServerError> {
    let limit = (MAX_RUN_SPEC_INPUT_BYTES as usize).div_ceil(3) * 4;
    if encoded.len() > limit {
        return Err(ServerError::NativeIngress(
            "operation exceeds byte limit".into(),
        ));
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| ServerError::NativeIngress("invalid base64".into()))?;
    parse_native_operation_bytes(&raw)
        .map_err(|error| ServerError::NativeIngress(error.to_string()))
}

/// A response frame correlated to its request id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusResult {
    /// The request id this response answers.
    pub request_id: String,
    /// Canonical status rendered from the runtime.
    pub status: RuntimeStatusV1,
}

/// Serve requests on `listener` until `shutdown` becomes `true`.
///
/// Each accepted connection is authenticated by kernel peer credentials, then
/// handled in a bounded thread pool. `RuntimeService` is shared and immutable;
/// the service serializes run state internally via its active-operations set.
pub fn serve(
    listener: UnixListener,
    runtime: Arc<RuntimeService>,
    max_concurrent: usize,
) -> Result<(), ServerError> {
    let active = Arc::new(AtomicUsize::new(0));
    let max = max_concurrent.max(1);

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                // A transient accept error (e.g. EMFILE/ENFILE) must not tear
                // down the whole daemon. Log and continue accepting.
                eprintln!("accept error (continuing): {error}");
                continue;
            }
        };
        let active = Arc::clone(&active);
        let runtime = Arc::clone(&runtime);
        // Non-blocking spawn: if at capacity, drop the connection with a typed
        // signal instead of queuing unbounded work.
        if !try_reserve_connection_slot(&active, max) {
            let _ = write_denial(&stream, "daemon at capacity");
            continue;
        }
        std::thread::spawn(move || {
            let _guard = match ActiveGuard::new(&active, &runtime) {
                Ok(guard) => guard,
                Err(error) => {
                    active.fetch_sub(1, Ordering::SeqCst);
                    eprintln!("connection accounting error: {error}");
                    return;
                }
            };
            if let Err(error) = handle_connection(stream, Arc::clone(&runtime)) {
                eprintln!("connection error: {error}");
            }
        });
    }
    Ok(())
}

struct ActiveGuard<'a> {
    active: &'a AtomicUsize,
    runtime: &'a RuntimeService,
}

impl<'a> ActiveGuard<'a> {
    fn new(active: &'a AtomicUsize, runtime: &'a RuntimeService) -> Result<Self, ServerError> {
        runtime.managed_ipc_connection_opened()?;
        Ok(Self { active, runtime })
    }
}

/// Atomically reserve one bounded worker slot. A separate load then increment
/// can oversubscribe `max` when acceptors race.
fn try_reserve_connection_slot(active: &AtomicUsize, max: usize) -> bool {
    let mut observed = active.load(Ordering::SeqCst);
    loop {
        if observed >= max {
            return false;
        }
        match active.compare_exchange_weak(
            observed,
            observed + 1,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => return true,
            Err(current) => observed = current,
        }
    }
}

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        let _ = self.runtime.managed_ipc_connection_closed();
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

fn write_denial(stream: &UnixStream, reason: &str) -> std::io::Result<()> {
    let mut out = stream.try_clone()?;
    let payload = serde_json::json!({
        "schema": IPC_REQUEST_SCHEMA_V1,
        "protocol_version": IPC_PROTOCOL_VERSION_V1,
        "error": reason,
    });
    let bytes = serde_json::to_vec(&payload)?;
    let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&bytes);
    out.write_all(&frame)?;
    out.flush()
}

fn handle_connection(stream: UnixStream, runtime: Arc<RuntimeService>) -> Result<(), ServerError> {
    // Authenticate the local peer by kernel credential, not client text.
    let principal =
        peer_principal(&stream).map_err(|e| ServerError::PeerIdentity(e.to_string()))?;
    let daemon_uid = rustix::process::getuid().as_raw();
    if principal.uid != daemon_uid {
        return Err(ServerError::PeerDenied { uid: principal.uid });
    }

    // F-02: an idle or silent peer must not hold a concurrency slot forever.
    // Apply a read/write timeout on the accepted socket so a stalled
    // connection is evicted and the daemon keeps serving other clients.
    stream.set_read_timeout(Some(CONNECTION_IDLE_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_IDLE_TIMEOUT))?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut out = stream.try_clone()?;
    let mut ids = ConnectionRequestIds::new();

    loop {
        // Read one length-prefixed frame.
        let header = match read_exact_prefix(&mut reader) {
            Ok(Some(h)) => h,
            Ok(None) => break, // EOF after a clean request/response cycle.
            Err(e) => return Err(ServerError::Frame(IpcDecodeError::Frame(e))),
        };
        let declared = u32::from_be_bytes(header) as usize;
        if declared > crate::protocol::MAX_FRAME_PAYLOAD_BYTES {
            return Err(ServerError::Frame(IpcDecodeError::Frame(
                FrameDecodeError::DeclaredLengthTooLarge {
                    declared,
                    max: crate::protocol::MAX_FRAME_PAYLOAD_BYTES,
                },
            )));
        }
        let mut payload = vec![0_u8; declared];
        reader.read_exact(&mut payload)?;
        // `decode_request_frame` expects the full length-prefixed frame, so
        // reconstruct the complete wire frame from the admitted prefix.
        let mut full_frame = header.to_vec();
        full_frame.extend_from_slice(&payload);
        let request = decode_request_frame(&full_frame).map_err(ServerError::Frame)?;
        ids.admit(&request).map_err(ServerError::Frame)?;

        // Dispatch failures are still daemon-owned typed outcomes. Return them
        // on the correlated request instead of dropping the connection and
        // making a transcript/verification failure look like an unavailable
        // daemon to local adapters.
        let response = match dispatch(&request, &runtime) {
            Ok(response) => response,
            Err(error) => serde_json::json!({
                "request_id": request.request_id,
                "error": {
                    "code": "runtime_error",
                    "message": error.to_string(),
                },
            }),
        };
        let resp_bytes = serde_json::to_vec(&response)?;
        let mut frame = (resp_bytes.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&resp_bytes);
        out.write_all(&frame)?;
        out.flush()?;
    }
    Ok(())
}

/// Read exactly the four-byte length prefix, or `None` on clean EOF.
fn read_exact_prefix(
    reader: &mut BufReader<UnixStream>,
) -> Result<Option<[u8; 4]>, FrameDecodeError> {
    let mut header = [0_u8; 4];
    let mut filled = 0;
    while filled < 4 {
        match reader.read(&mut header[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(None);
                }
                return Err(FrameDecodeError::TruncatedPayload {
                    declared: 0,
                    received: filled,
                });
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(FrameDecodeError::IncompletePrefix { received: filled }),
        }
    }
    Ok(Some(header))
}

/// Translate one admitted request into a runtime call and a typed response.
fn dispatch(
    request: &IpcRequestEnvelopeV1,
    runtime: &RuntimeService,
) -> Result<serde_json::Value, ServerError> {
    match &request.request {
        IpcRequestV1::Ping => Ok(serde_json::json!({
            "schema": IPC_REQUEST_SCHEMA_V1,
            "protocol_version": IPC_PROTOCOL_VERSION_V1,
            "request_id": request.request_id,
            "pong": true,
        })),
        IpcRequestV1::Status { run_id } => {
            let run = CurrentRunId::try_new(run_id)
                .map_err(|_| ServerError::InvalidRunId(run_id.clone()))?;
            let status = runtime.status(&run)?;
            // `RuntimeStatusV1` is intentionally not `Serialize`; render the
            // canonical status into an explicit wire shape instead. Terminal
            // state uses the serialized `snake_case` discriminant, not Rust
            // `Debug`, so the wire contract does not depend on a derive repr.
            let status_value = match status {
                RuntimeStatusV1::Active => serde_json::json!({ "state": "active" }),
                RuntimeStatusV1::Terminal { state } => serde_json::json!({
                    "state": "terminal",
                    "terminal_state": serde_json::to_value(state)
                        .map_err(ServerError::Json)?,
                }),
            };
            Ok(serde_json::json!({
                "request_id": request.request_id,
                "run_id": run_id,
                "status": status_value,
            }))
        }
        IpcRequestV1::Verify { run_id } => {
            let run = CurrentRunId::try_new(run_id)
                .map_err(|_| ServerError::InvalidRunId(run_id.clone()))?;
            let verification = runtime.verify(&run)?;
            Ok(serde_json::json!({
                "request_id": request.request_id,
                "run_id": run_id,
                "verification": {
                    "ok": verification.ok,
                    "current_strict_success": verification.current_strict_success,
                    "length": verification.length,
                    "final_head": verification.final_head,
                    "verified_artifacts": verification.verified_artifacts,
                    "terminal_state": serde_json::to_value(verification.terminal_state)
                        .map_err(ServerError::Json)?,
                },
            }))
        }
        IpcRequestV1::Cancel { run_id } => {
            let run = CurrentRunId::try_new(run_id)
                .map_err(|_| ServerError::InvalidRunId(run_id.clone()))?;
            let result = runtime.cancel(&run)?;
            let cancellation = match result {
                RuntimeCancelResultV1::CancellationRequested { run_id } => serde_json::json!({
                    "state": "cancellation_requested", "run_id": run_id
                }),
                RuntimeCancelResultV1::AlreadyTerminal { state } => serde_json::json!({
                    "state": "already_terminal",
                    "terminal_state": serde_json::to_value(state).map_err(ServerError::Json)?
                }),
            };
            Ok(serde_json::json!({
                "request_id": request.request_id, "run_id": run_id, "cancellation": cancellation
            }))
        }
        IpcRequestV1::PermitConsume {
            permit_id,
            binding,
            call,
        } => {
            let preflight = runtime.consume_external_permit(permit_id, binding, call)?;
            Ok(serde_json::json!({
                "request_id": request.request_id,
                "permit_id": permit_id,
                "evidence": preflight.evidence,
                "preflight_artifact": preflight,
                "receipt_artifact": {
                    "kind": "permit_preflight",
                    "receipt_digest": preflight.receipt_digest,
                },
            }))
        }
        IpcRequestV1::PermitIssue {
            request: approval_request,
            approval,
        } => {
            let permit = runtime.issue_approved_echo_permit(approval_request, approval)?;
            Ok(serde_json::json!({
                "request_id": request.request_id,
                "permit_id": permit.permit_id,
                "binding": permit.binding,
                "issuance_evidence": { "state": { "state": "issued" } },
            }))
        }
        IpcRequestV1::PermitIssueProduction { witness } => {
            let permit = runtime.issue_production_permit(witness)?;
            Ok(serde_json::json!({
                "request_id": request.request_id,
                "permit_id": permit.permit_id,
                "binding": permit.binding,
                "issuance_evidence": { "state": { "state": "issued" }, "contract": "production_ed25519_per_call_v1" },
            }))
        }
        IpcRequestV1::PermitOutcomeRecord {
            permit_id,
            preflight_receipt_digest,
            reported,
        } => {
            let outcome = runtime.record_external_permit_outcome(
                permit_id,
                preflight_receipt_digest,
                reported.clone(),
            )?;
            Ok(serde_json::json!({
                "request_id": request.request_id,
                "permit_id": permit_id,
                "outcome_artifact": outcome,
            }))
        }
        IpcRequestV1::ScopedPermitIssue { witness, context } => {
            let permit = runtime.issue_scoped_external_permit(witness, context)?;
            Ok(serde_json::json!({"request_id": request.request_id, "permit": permit}))
        }
        IpcRequestV1::ScopedPermitConsume { permit, call } => {
            let preflight = runtime.consume_scoped_external_permit(permit, call)?;
            Ok(serde_json::json!({"request_id": request.request_id, "preflight": preflight}))
        }
        IpcRequestV1::ScopedPermitReadback { permit } => {
            let record = runtime.read_scoped_external_permit(permit)?;
            Ok(serde_json::json!({"request_id": request.request_id, "record": record}))
        }
        IpcRequestV1::ScopedPermitOutcomeRecord {
            permit,
            preflight_receipt_digest,
            reported,
        } => {
            let outcome = runtime.settle_scoped_external_permit(
                permit,
                preflight_receipt_digest,
                reported.clone(),
            )?;
            Ok(serde_json::json!({"request_id": request.request_id, "outcome": outcome}))
        }
        IpcRequestV1::ContextAuthorityTransition { transition } => {
            let receipt = runtime.transition_context_authority(transition)?;
            Ok(serde_json::json!({"request_id": request.request_id, "receipt": receipt}))
        }
        IpcRequestV1::ContextAuthorityReadback { incarnation, scope } => {
            let snapshot = runtime.read_context_authority(incarnation, scope)?;
            Ok(serde_json::json!({"request_id": request.request_id, "snapshot": snapshot}))
        }
        IpcRequestV1::ContextTransitionReadback { transition } => {
            let receipt = runtime.read_context_transition(transition)?;
            Ok(serde_json::json!({"request_id": request.request_id, "receipt": receipt}))
        }
        IpcRequestV1::ContextStoreIdentity { nonce } => {
            let digest =
                recursive_agent_contracts::content_digest(&("ares.context-store/v1", nonce))
                    .map_err(|e| {
                        ServerError::Runtime(recursive_agent_runner::RuntimeServiceError::Policy(
                            recursive_agent_policy::PolicyError::Contract(e),
                        ))
                    })?;
            Ok(serde_json::json!({"request_id": request.request_id, "store": digest}))
        }
        IpcRequestV1::ContextCallPrepare { authority, witness } => {
            let material = recursive_agent_policy::prepare_context_call(authority, witness)
                .map_err(|e| {
                    ServerError::Runtime(recursive_agent_runner::RuntimeServiceError::Policy(e))
                })?;
            let bytes = material.signing_bytes().map_err(|e| {
                ServerError::Runtime(recursive_agent_runner::RuntimeServiceError::Policy(e))
            })?;
            Ok(
                serde_json::json!({"request_id": request.request_id, "material": material, "signing_bytes": bytes}),
            )
        }
        IpcRequestV1::ContextTransitionPrepare {
            authority,
            transition_ref,
            action,
        } => {
            let material = recursive_agent_policy::prepare_context_transition(
                authority,
                transition_ref,
                action,
            )
            .map_err(|e| {
                ServerError::Runtime(recursive_agent_runner::RuntimeServiceError::Policy(e))
            })?;
            let bytes = material.signing_bytes().map_err(|e| {
                ServerError::Runtime(recursive_agent_runner::RuntimeServiceError::Policy(e))
            })?;
            Ok(
                serde_json::json!({"request_id": request.request_id, "material": material, "signing_bytes": bytes}),
            )
        }
        IpcRequestV1::PermitReadback {
            permit_id,
            binding,
            preflight_receipt_digest,
        } => {
            let readback = runtime.read_external_permit(
                permit_id,
                binding,
                preflight_receipt_digest.as_ref(),
            )?;
            Ok(serde_json::json!({
                "request_id": request.request_id,
                "permit_id": permit_id,
                "readback": readback,
            }))
        }
        IpcRequestV1::Submit { operation } => {
            let handle = runtime.submit(operation)?;
            Ok(serde_json::json!({
                "request_id": request.request_id,
                "run_id": handle.run_id().to_string(),
                "run_dir": handle.run_dir().display().to_string(),
                "submitted": true,
            }))
        }
        IpcRequestV1::SubmitProviderEgressV3 { operation } => {
            let handle = runtime.submit_provider_egress_v3(operation)?;
            Ok(serde_json::json!({
                "request_id": request.request_id,
                "run_id": handle.run_id().to_string(),
                "run_dir": handle.run_dir().display().to_string(),
                "submitted": true,
                "operation_family": "provider_egress_v3",
            }))
        }
        IpcRequestV1::ReadRecordedProviderOutputV3 { operation } => {
            let output = runtime.read_recorded_provider_output_v3(operation)?;
            Ok(serde_json::json!({
                "request_id": request.request_id,
                "output": {"model": output.model, "text": output.text},
            }))
        }
        IpcRequestV1::SubmitNativeRaw { operation_json_b64 } => {
            let operation = admit_native_raw(operation_json_b64)?;
            let (handle, family) = match operation {
                NativeOperation::V1(operation) => (runtime.submit(&operation)?, "v1"),
                NativeOperation::ProviderEgressV3(operation) => (
                    runtime.submit_provider_egress_v3(&operation)?,
                    "provider_egress_v3",
                ),
            };
            Ok(serde_json::json!({
                "request_id": request.request_id,
                "run_id": handle.run_id().to_string(),
                "run_dir": handle.run_dir().display().to_string(),
                "submitted": true,
                "operation_family": family,
            }))
        }
        IpcRequestV1::ReadRecordedProviderOutputNativeRaw { operation_json_b64 } => {
            let NativeOperation::ProviderEgressV3(operation) =
                admit_native_raw(operation_json_b64)?
            else {
                return Err(ServerError::NativeIngress(
                    "recorded output requires V3".into(),
                ));
            };
            let output = runtime.read_recorded_provider_output_v3(&operation)?;
            Ok(serde_json::json!({
                "request_id": request.request_id,
                "output": {"model": output.model, "text": output.text},
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    use super::try_reserve_connection_slot;

    #[test]
    fn concurrent_slot_reservations_never_exceed_the_bound() {
        const CONTENDERS: usize = 32;
        let active = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(CONTENDERS));
        let mut workers = Vec::new();
        for _ in 0..CONTENDERS {
            let active = Arc::clone(&active);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                try_reserve_connection_slot(&active, 1)
            }));
        }
        let outcomes: Vec<_> = workers
            .into_iter()
            .map(|worker| match worker.join() {
                Ok(admitted) => (true, admitted),
                Err(_) => (false, false),
            })
            .collect();
        assert!(outcomes.iter().all(|(joined, _)| *joined));
        let admitted = outcomes.iter().filter(|(_, admitted)| *admitted).count();
        assert_eq!(admitted, 1);
        assert_eq!(active.load(Ordering::SeqCst), 1);
    }
}
