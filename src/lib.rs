//! Library surface for embedding the tmux MCP control plane.
//!
//! Modules cover side-channel command tracking, security policy, the tmux process
//! adapter, and shared DTO types. The binary crate owns the stdio MCP server loop
//! (`src/main.rs` + private `server` module) and is not re-exported here.

/// Side-channel command execution tracking across tmux panes.
pub mod commands;
/// Domain errors and the crate-wide `Result` alias.
pub mod errors;
/// Security policy: tool surface, allowlists, command filters, buffer path sandbox.
pub mod security;
/// Local/SSH tmux process adapter, parsers, and buffer search.
pub mod tmux;
/// Shared session/window/pane/buffer/search DTOs used by tools and resources.
pub mod types;

pub mod schema_format;

#[cfg(test)]
mod test_support;
