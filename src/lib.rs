//! Public API surface for the tmux-mcp-rs library.

/// Command execution tracking helpers and markers.
pub mod commands;
/// Error types and Result alias for the library.
pub mod errors;
/// Security policy configuration and enforcement.
pub mod security;
/// Low-level tmux command wrappers and parsers.
pub mod tmux;
/// Shared data types used across tools and responses.
pub mod types;

#[cfg(test)]
mod test_support;
