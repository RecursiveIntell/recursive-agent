//! Future MCP protocol data shapes, quarantined from Phase 1 execution.
//!
//! - `protocol`: typed JSON-RPC 2.0 messages
//!
//! Arbitrary-command MCP client spawning is intentionally not compiled into
//! the default production surface before Phase 6.

pub mod client;
pub mod protocol;
pub mod translate;
