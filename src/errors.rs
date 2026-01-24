#![allow(dead_code)]

use thiserror::Error;

/// Convenience result type for tmux-mcp-rs operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Error variants returned by tmux-mcp-rs APIs.
#[derive(Debug, Error)]
pub enum Error {
    /// Configuration parsing or IO failure.
    #[error("config error: {message}")]
    Config { message: String },

    /// Security policy denied the requested operation.
    #[error("policy denied: {message}")]
    PolicyDenied { message: String },

    /// tmux command execution failed.
    #[error("tmux error: {message}")]
    Tmux { message: String },

    /// Output parsing failed.
    #[error("parse error: {message}")]
    Parse { message: String },

    /// Invalid arguments were provided.
    #[error("invalid argument: {message}")]
    InvalidArgument { message: String },
}
