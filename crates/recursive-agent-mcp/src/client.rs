//! Strict MCP client correlation and cancellation (Phase 6, Task 6.3).
//!
//! This client never accepts a response that can satisfy the wrong request.
//! It maintains a bounded outstanding-request map keyed by a monotonically
//! typed request id, rejects wrong-id / duplicate / malformed / late responses,
//! propagates cancellation, and cleans up terminal entries.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::protocol::JsonRpcResponse;

/// Typed request id. Monotonically issued by the client; never caller-chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RequestId(pub u64);

/// Cancellation state for an in-flight request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelState {
    Running,
    CancelRequested,
}

/// An in-flight request tracked by the client.
#[derive(Debug, Clone)]
pub struct OutstandingRequest {
    pub id: RequestId,
    pub method: String,
    pub cancel: CancelState,
}

/// Client correlation errors. All typed; no panic.
#[derive(Debug, Error)]
pub enum CorrelationError {
    #[error("response id {id} has no matching outstanding request")]
    UnknownResponseId { id: u64 },
    #[error("response id {id} was already satisfied (duplicate response)")]
    DuplicateResponse { id: u64 },
    #[error("in-flight request limit {limit} reached; cannot issue {id}")]
    InFlightLimitReached { id: u64, limit: usize },
    #[error("cancellation for unknown request id {id}")]
    UnknownCancellation { id: u64 },
    #[error("response for id {id} arrived after it was cancelled (late response)")]
    LateResponse { id: u64 },
    #[error("malformed error envelope for id {id}: {reason}")]
    MalformedErrorEnvelope { id: u64, reason: String },
    #[error("received a response without an id (id-less legacy response)")]
    IdLessResponse,
    #[error("response id {id} mismatches expected method {expected}")]
    MethodMismatch { id: u64, expected: String },
}

/// Strict MCP request/response correlation.
pub struct MpcCorrelator {
    outstanding: BTreeMap<u64, OutstandingRequest>,
    in_flight_limit: usize,
    next_id: u64,
}

impl MpcCorrelator {
    /// Create a correlator with a bounded in-flight limit.
    pub fn new(in_flight_limit: usize) -> Self {
        Self {
            outstanding: BTreeMap::new(),
            in_flight_limit,
            next_id: 0,
        }
    }

    /// Issue a fresh typed request id and track it as outstanding.
    pub fn issue(&mut self, method: &str) -> Result<RequestId, CorrelationError> {
        let id = RequestId(self.next_id);
        self.next_id += 1;
        if self.outstanding.len() >= self.in_flight_limit {
            return Err(CorrelationError::InFlightLimitReached {
                id: id.0,
                limit: self.in_flight_limit,
            });
        }
        self.outstanding.insert(
            id.0,
            OutstandingRequest {
                id,
                method: method.into(),
                cancel: CancelState::Running,
            },
        );
        Ok(id)
    }

    /// Request cancellation for an in-flight request (idempotent).
    pub fn request_cancel(&mut self, id: u64) -> Result<(), CorrelationError> {
        let req = self
            .outstanding
            .get_mut(&id)
            .ok_or(CorrelationError::UnknownCancellation { id })?;
        req.cancel = CancelState::CancelRequested;
        Ok(())
    }

    /// Whether a request is marked cancelled.
    pub fn is_cancelled(&self, id: u64) -> bool {
        self.outstanding
            .get(&id)
            .is_some_and(|r| r.cancel == CancelState::CancelRequested)
    }

    /// Correlate an incoming response with an outstanding request.
    ///
    /// Returns the outstanding request only for a strictly-matching, not-yet-
    /// satisfied, not-cancelled response. Rejects: id-less responses, unknown
    /// ids, duplicates, late (post-cancel) responses, and method mismatches.
    pub fn correlate(
        &mut self,
        response: &JsonRpcResponse,
        expected_method: Option<&str>,
    ) -> Result<OutstandingRequest, CorrelationError> {
        // No permissive acceptance of id-less legacy responses.
        let Some(id) = response.id else {
            return Err(CorrelationError::IdLessResponse);
        };
        if let Some(err) = &response.error {
            if err.code == 0 || err.message.trim().is_empty() {
                return Err(CorrelationError::MalformedErrorEnvelope {
                    id,
                    reason: "error code or message is invalid".into(),
                });
            }
        }
        let req = self
            .outstanding
            .get(&id)
            .ok_or(CorrelationError::UnknownResponseId { id })?;
        if let Some(expected) = expected_method {
            if req.method != expected {
                return Err(CorrelationError::MethodMismatch {
                    id,
                    expected: expected.into(),
                });
            }
        }
        if req.cancel == CancelState::CancelRequested {
            return Err(CorrelationError::LateResponse { id });
        }
        // Remove (terminal cleanup) and return the matched request.
        let req = self
            .outstanding
            .remove(&id)
            .ok_or(CorrelationError::DuplicateResponse { id })?;
        Ok(req)
    }

    /// Current number of outstanding requests.
    pub fn outstanding_len(&self) -> usize {
        self.outstanding.len()
    }

    /// Outstanding request ids (for cancellation propagation / inventory).
    pub fn outstanding_ids(&self) -> BTreeSet<u64> {
        self.outstanding.keys().copied().collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::protocol::{JsonRpcError, JsonRpcResponse};

    fn ok_response(id: u64) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: Some(id),
            result: Some(serde_json::json!({"ok": true})),
            error: None,
        }
    }

    #[test]
    fn wrong_response_id_is_rejected() {
        let mut c = MpcCorrelator::new(4);
        c.issue("tools/call").unwrap();
        let err = c.correlate(&ok_response(99), None).unwrap_err();
        assert!(matches!(
            err,
            CorrelationError::UnknownResponseId { id: 99 }
        ));
    }

    #[test]
    fn duplicate_response_is_rejected() {
        let mut c = MpcCorrelator::new(4);
        let id = c.issue("tools/call").unwrap().0;
        assert!(c.correlate(&ok_response(id), None).is_ok());
        let err = c.correlate(&ok_response(id), None).unwrap_err();
        assert!(matches!(err, CorrelationError::UnknownResponseId { .. }));
    }

    #[test]
    fn id_less_response_is_rejected() {
        let mut c = MpcCorrelator::new(4);
        c.issue("tools/call").unwrap();
        let id_less = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: None,
            result: Some(serde_json::json!({"ok": true})),
            error: None,
        };
        let err = c.correlate(&id_less, None).unwrap_err();
        assert!(matches!(err, CorrelationError::IdLessResponse));
    }

    #[test]
    fn cancellation_race_marks_request_and_late_response_is_rejected() {
        let mut c = MpcCorrelator::new(4);
        let id = c.issue("tools/call").unwrap().0;
        c.request_cancel(id).unwrap();
        assert!(c.is_cancelled(id));
        let err = c.correlate(&ok_response(id), None).unwrap_err();
        assert!(matches!(err, CorrelationError::LateResponse { .. }));
    }

    #[test]
    fn malformed_error_envelope_is_rejected() {
        let mut c = MpcCorrelator::new(4);
        let id = c.issue("tools/call").unwrap().0;
        let malformed = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: Some(id),
            result: None,
            error: Some(JsonRpcError {
                code: 0,
                message: " ".into(),
            }),
        };
        let err = c.correlate(&malformed, None).unwrap_err();
        assert!(matches!(
            err,
            CorrelationError::MalformedErrorEnvelope { .. }
        ));
    }

    #[test]
    fn in_flight_limit_is_bounded() {
        let mut c = MpcCorrelator::new(2);
        c.issue("a").unwrap();
        c.issue("b").unwrap();
        let err = c.issue("c").unwrap_err();
        assert!(matches!(
            err,
            CorrelationError::InFlightLimitReached { limit: 2, .. }
        ));
    }

    #[test]
    fn method_mismatch_is_rejected() {
        let mut c = MpcCorrelator::new(4);
        let id = c.issue("tools/list").unwrap().0;
        let err = c
            .correlate(&ok_response(id), Some("tools/call"))
            .unwrap_err();
        assert!(matches!(err, CorrelationError::MethodMismatch { .. }));
    }

    #[test]
    fn matched_response_performs_terminal_cleanup() {
        let mut c = MpcCorrelator::new(4);
        let id = c.issue("tools/call").unwrap().0;
        assert_eq!(c.outstanding_len(), 1);
        assert!(c.correlate(&ok_response(id), None).is_ok());
        assert_eq!(c.outstanding_len(), 0);
    }
}
