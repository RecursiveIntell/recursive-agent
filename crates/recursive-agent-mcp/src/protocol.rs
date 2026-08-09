//! MCP protocol types — typed JSON-RPC 2.0 messages.
//!
//! Implements the Model Context Protocol wire format: initialize,
//! tools/list, tools/call request/response envelopes. No unsafe, no panic.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// MCP protocol errors.
#[derive(Debug, Error)]
pub enum McpError {
    #[error("io: {0}")]
    Io(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("timeout after {0}ms")]
    Timeout(u64),
    #[error("child process error: {0}")]
    Child(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    /// Response id. `None` represents an id-less (legacy/malformed) response,
    /// which strict correlation must reject.
    pub id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

/// A tool manifest as returned by tools/list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolManifest {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Option<serde_json::Value>,
}

/// MCP initialize result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeResult {
    pub protocol_version: String,
    pub server_info: ServerInfo,
    pub capabilities: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}
