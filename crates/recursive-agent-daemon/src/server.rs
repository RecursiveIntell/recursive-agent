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

use recursive_agent_contracts::CurrentRunId;
use recursive_agent_runner::{RuntimeService, RuntimeStatusV1};
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
            let _guard = ActiveGuard(&active);
            if let Err(error) = handle_connection(stream, runtime) {
                eprintln!("connection error: {error}");
            }
        });
    }
    Ok(())
}

struct ActiveGuard<'a>(&'a AtomicUsize);

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
        self.0.fetch_sub(1, Ordering::SeqCst);
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

        let response = dispatch(&request, &runtime)?;
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
        IpcRequestV1::Submit { operation } => {
            let handle = runtime.submit(operation)?;
            Ok(serde_json::json!({
                "request_id": request.request_id,
                "run_id": handle.run_id().to_string(),
                "run_dir": handle.run_dir().display().to_string(),
                "submitted": true,
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
