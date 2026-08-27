//! Shared DTOs for tmux topology, paste buffers, buffer search, and tracked commands.
//!
//! These types cross the MCP tool/resource boundary as JSON (camelCase fields where
//! noted) and also back in-process tracking state that is not serialized.

#![allow(dead_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Instant;

/// tmux session summary returned by list/find tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Session {
    /// Session target id from tmux (typically `$N`).
    pub id: String,
    /// Display name; `find-session` matches this exactly.
    pub name: String,
    /// True when at least one client is attached.
    pub attached: bool,
    /// Window count currently owned by the session.
    #[schemars(schema_with = "crate::schema_format::u32_schema")]
    pub windows: u32,
}

/// tmux window summary returned by list tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Window {
    /// Window target id from tmux (typically `@N`).
    pub id: String,
    /// Display name shown in the status line / `list-windows`.
    pub name: String,
    /// True when this is the session's current window.
    pub active: bool,
    /// Owning session id (`$N`).
    pub session_id: String,
}

/// tmux pane summary returned by list tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Pane {
    /// Pane target id from tmux (typically `%N`); unique only within one server/socket.
    pub id: String,
    /// Owning window id (`@N`).
    pub window_id: String,
    /// True when this is the window's current pane.
    pub active: bool,
    /// Pane title (`#{pane_title}`), not the shell prompt.
    pub title: String,
}

/// Detailed pane metadata (cwd, command, size, pid) for targeting and layout tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PaneInfo {
    /// Pane target id (`%N`).
    pub id: String,
    /// Owning window id (`@N`).
    pub window_id: String,
    /// Owning session id (`$N`).
    pub session_id: String,
    /// Pane title (`#{pane_title}`).
    pub title: String,
    /// True when this is the window's current pane.
    pub active: bool,
    /// Process cwd for the pane's foreground job (`#{pane_current_path}`).
    pub current_path: String,
    /// Foreground command binary name/path; used to pick marker shell dialect.
    pub current_command: String,
    #[schemars(schema_with = "crate::schema_format::u32_schema")]
    pub width: u32,
    #[schemars(schema_with = "crate::schema_format::u32_schema")]
    pub height: u32,
    /// Pane process pid when tmux reports one.
    #[schemars(schema_with = "crate::schema_format::u32_schema")]
    pub pid: Option<u32>,
    /// True while the pane is in copy-mode or another tmux mode.
    pub in_mode: bool,
}

/// Detailed window metadata (layout, zoom, active pane) for focus and layout tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WindowInfo {
    /// Window target id (`@N`).
    pub id: String,
    pub name: String,
    /// Owning session id (`$N`).
    pub session_id: String,
    /// True when this is the session's current window.
    pub active: bool,
    /// Active layout algorithm string from tmux (`#{window_layout}`).
    pub layout: String,
    /// Pane count in the window.
    #[schemars(schema_with = "crate::schema_format::u32_schema")]
    pub panes: u32,
    #[schemars(schema_with = "crate::schema_format::u32_schema")]
    pub width: u32,
    #[schemars(schema_with = "crate::schema_format::u32_schema")]
    pub height: u32,
    /// True when a pane is zoomed to fill the window.
    pub zoomed: bool,
    /// Currently selected pane id (`%N`).
    pub active_pane_id: String,
}

/// Attached tmux client (TTY/session/pid) used for observer-aware operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientInfo {
    /// Client TTY path used as the detach target.
    pub tty: String,
    /// Client name from tmux.
    pub name: String,
    /// Session the client is attached to (name, not id).
    pub session_name: String,
    /// Client process pid when reported.
    #[schemars(schema_with = "crate::schema_format::u32_schema")]
    pub pid: Option<u32>,
    /// True when the client is currently attached.
    pub attached: bool,
}

/// Paste-buffer listing entry with size and creation metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BufferInfo {
    /// Buffer name (`bufferN` or a custom name).
    pub name: String,
    /// Byte length capped at `u32::MAX` for compact JSON clients.
    #[schemars(schema_with = "crate::schema_format::u32_schema")]
    pub size: u32,
    /// Full byte length without the `u32` cap; prefer for search/page budgets.
    #[serde(rename = "sizeBytes")]
    #[schemars(schema_with = "crate::schema_format::u64_schema")]
    pub size_bytes: u64,
    /// Index in the `list-buffers` response (lower is earlier in that listing).
    #[serde(rename = "orderIndex")]
    #[schemars(schema_with = "crate::schema_format::u32_schema")]
    pub order_index: u32,
    /// Unix epoch seconds from `#{buffer_created}` when present.
    pub created: Option<i64>,
}

/// Match strategy for `search-buffer` / `subsearch-buffer` tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SearchMode {
    /// Substring match of the query as plain text.
    Literal,
    /// Rust regex engine match (invalid patterns become `InvalidArgument`).
    Regex,
}

/// One buffer search hit with byte offsets, context window, and optional similarity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BufferSearchMatch {
    /// Stable id for this hit within the result set (not a tmux identifier).
    #[serde(rename = "matchId")]
    pub match_id: String,
    /// Paste-buffer name that produced the hit.
    pub buffer: String,
    /// Absolute UTF-8 byte offset of the match start inside the buffer.
    #[serde(rename = "offsetBytes")]
    #[schemars(schema_with = "crate::schema_format::u64_schema")]
    pub offset_bytes: u64,
    /// Match span length in UTF-8 bytes.
    #[serde(rename = "matchLen")]
    #[schemars(schema_with = "crate::schema_format::u32_schema")]
    pub match_len: u32,
    /// Inclusive start of the context window in absolute buffer bytes.
    #[serde(rename = "contextStart")]
    #[schemars(schema_with = "crate::schema_format::u64_schema")]
    pub context_start: u64,
    /// Exclusive end of the context window in absolute buffer bytes.
    #[serde(rename = "contextEnd")]
    #[schemars(schema_with = "crate::schema_format::u64_schema")]
    pub context_end: u64,
    /// Context text covering `[context_start, context_end)`.
    pub snippet: String,
    /// Optional fuzzy similarity in `[0.0, 1.0]` when scoring is enabled.
    pub similarity: Option<f32>,
}

/// Structured result of a multi-buffer or anchor-scoped buffer search.
///
/// Includes scan budgets, truncation/resume cursors, and optional fuzzy stats so
/// clients can page large buffers without re-scanning completed ranges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BufferSearchOutput {
    /// Echo of the search query.
    pub query: String,
    /// Match strategy used for this scan.
    pub mode: SearchMode,
    /// Context radius in bytes applied to each snippet.
    #[serde(rename = "contextBytes")]
    #[schemars(schema_with = "crate::schema_format::u32_schema")]
    pub context_bytes: u32,
    /// Match cap that bound this result set.
    #[serde(rename = "maxMatches")]
    #[schemars(schema_with = "crate::schema_format::u32_schema")]
    pub max_matches: u32,
    /// Whether similarity scores were requested.
    #[serde(rename = "includeSimilarity")]
    pub include_similarity: bool,
    /// Whether fuzzy scoring was preferred over exact mode.
    #[serde(rename = "fuzzyMatch")]
    pub fuzzy_match: bool,
    /// Fuzzy score floor when filtering was requested.
    #[serde(rename = "similarityThreshold")]
    pub similarity_threshold: Option<f32>,
    /// Buffer names included in this scan (after alias expansion).
    pub buffers: Vec<String>,
    /// Number of hits returned in `matches` (not a global total beyond the cap).
    #[serde(rename = "totalMatches")]
    #[schemars(schema_with = "crate::schema_format::u32_schema")]
    pub total_matches: u32,
    /// How many buffers were opened for this request.
    #[serde(rename = "buffersScanned")]
    #[schemars(schema_with = "crate::schema_format::u32_schema")]
    pub buffers_scanned: u32,
    /// Aggregate bytes examined across all buffers.
    #[serde(rename = "bytesScannedTotal")]
    #[schemars(schema_with = "crate::schema_format::u64_schema")]
    pub bytes_scanned_total: u64,
    /// Buffers that stopped early due to scan or match budgets.
    #[serde(rename = "truncatedBuffers")]
    pub truncated_buffers: Vec<String>,
    /// Per-buffer absolute byte cursors for the next page.
    #[serde(rename = "resumeFromOffset")]
    #[schemars(schema_with = "crate::schema_format::u64_map_schema")]
    pub resume_from_offset: BTreeMap<String, u64>,
    pub matches: Vec<BufferSearchMatch>,
    /// Highest similarity among scored hits when similarity was enabled.
    #[serde(rename = "maxSimilarity")]
    pub max_similarity: Option<f32>,
    /// Mean similarity among scored hits when similarity was enabled.
    #[serde(rename = "avgSimilarity")]
    pub avg_similarity: Option<f32>,
    /// Lines skipped by fuzzy scoring because they exceeded the line-byte cap.
    #[serde(rename = "fuzzySkippedLines")]
    #[schemars(schema_with = "crate::schema_format::u32_schema")]
    pub fuzzy_skipped_lines: u32,
    /// Total bytes in lines skipped by the fuzzy line-byte cap.
    #[serde(rename = "fuzzySkippedBytes")]
    #[schemars(schema_with = "crate::schema_format::u64_schema")]
    pub fuzzy_skipped_bytes: u64,
}

/// Window node in a session tree snapshot (window plus its panes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WindowTree {
    /// Window summary for this node.
    pub window: Window,
    /// Panes currently in the window (order from `list-panes`).
    pub panes: Vec<Pane>,
}

/// Session tree snapshot used by session resources and multi-pane planning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionTree {
    /// Session root identity and attached/window counts.
    pub session: Session,
    /// Nested windows and panes for the whole session.
    pub windows: Vec<WindowTree>,
}

/// Shell dialect used when wrapping tracked commands with START/DONE markers.
///
/// Affects exit-status expansion (`$?` vs `$status`) inside the tracker epilogue.
/// Pane `current_command` may override the process default at launch time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum ShellType {
    /// Bash-style `$?` exit-status expansion in the tracker epilogue.
    #[default]
    Bash,
    /// Zsh-style `$?` exit-status expansion (same token as bash).
    Zsh,
    /// Fish-style `$status` exit-status expansion.
    Fish,
    /// Treat like bash-style `$?` when the pane shell cannot be identified.
    Unknown,
}

/// Lifecycle status of a tracked command execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CommandStatus {
    /// Accepted but waiting for the pane's tracked-command queue head.
    Queued,
    /// Keys sent / side-channel watcher active (or tracking disabled after send).
    Running,
    /// Side channel reported exit code 0.
    Completed,
    /// Side channel reported non-zero exit code.
    Failed,
    /// Explicitly cancelled or pane purged while active.
    Cancelled,
    /// Side channel lost, send failure after accept, or tracking deadline exceeded.
    TrackingError,
}

impl CommandStatus {
    /// True when the command will not change status further (except eviction).
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::TrackingError
        )
    }

    /// Wire string for tools/resources (lowercase serde name).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TrackingError => "tracking_error",
        }
    }
}

/// Canonical MCP resource URI for a tracked command result.
pub fn command_resource_uri(command_id: &str) -> String {
    format!("tmux://command/{command_id}/result")
}

/// Shared tool/resource snapshot for a tracked command (schemaVersion 1).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CommandSnapshot {
    /// Opaque command id from `execute-command`.
    pub command_id: String,
    /// Canonical `tmux://command/{id}/result` URI.
    pub resource_uri: String,
    pub status: CommandStatus,
    /// Side-channel exit code when terminal with a known code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Original command text as requested by the client.
    pub command: String,
    /// Target pane id (`%N`).
    pub pane_id: String,
    /// Effective socket used for this send after resolve.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket: Option<String>,
    /// Bounded pane text, a tracking-disabled diagnostic, or omitted when marker loss
    /// prevents safe isolation. Diagnostics always pair with `output_truncated = true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    /// True when `output` is unavailable or incomplete within the bounded capture.
    ///
    /// This describes capture completeness, not whether the command lifecycle is terminal.
    pub output_truncated: bool,
    /// Wall time from accept to completion (or now if still running).
    #[schemars(schema_with = "crate::schema_format::u64_schema")]
    pub elapsed_ms: u64,
    /// Explanation for cancelled / tracking_error terminals.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Present on get-command-result when a wait budget expired while still non-terminal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_timed_out: Option<bool>,
    /// Wire schema version (currently [`CommandSnapshot::SCHEMA_VERSION`]).
    #[schemars(schema_with = "crate::schema_format::u32_schema")]
    pub schema_version: u32,
}

impl CommandSnapshot {
    /// Wire schema version embedded in every tool/resource snapshot (currently 1).
    pub const SCHEMA_VERSION: u32 = 1;

    /// Project in-memory tracking state into the shared MCP snapshot shape.
    ///
    /// `wait_timed_out` is set only when `get-command-result` hit its wait budget
    /// while the command was still non-terminal; other callers pass `None`.
    pub fn from_execution(exec: &CommandExecution, wait_timed_out: Option<bool>) -> Self {
        let elapsed = exec
            .completed_at
            .unwrap_or_else(Instant::now)
            .saturating_duration_since(exec.started_at);
        Self {
            command_id: exec.id.clone(),
            resource_uri: command_resource_uri(&exec.id),
            status: exec.status,
            exit_code: exec.exit_code,
            command: exec.command.clone(),
            pane_id: exec.pane_id.clone(),
            socket: exec.socket.clone(),
            output: exec.output.clone(),
            output_truncated: exec.output_truncated,
            elapsed_ms: elapsed.as_millis() as u64,
            reason: exec.reason.clone(),
            wait_timed_out,
            schema_version: Self::SCHEMA_VERSION,
        }
    }
}

/// In-memory record of a command sent to a pane.
///
/// Not serialized on the wire as-is; MCP tools project selected fields into tool output.
/// Side-channel secrets are stored separately and never appear here.
#[derive(Debug, Clone)]
pub struct CommandExecution {
    /// Opaque command id returned by `execute-command` and used in resource URIs.
    pub id: String,
    /// Target pane id (`%N`) for this send.
    pub pane_id: String,
    /// Effective socket path used for this send (after resolve).
    pub socket: Option<String>,
    /// Original command text as requested by the client (not the wrapped form).
    pub command: String,
    pub status: CommandStatus,
    /// Present only after side-channel completion (or tracking_error path).
    pub exit_code: Option<i32>,
    /// Optional bounded partial or final pane text between START/DONE markers.
    /// `Some("")` means the bounded markers prove the command emitted no text;
    /// `None` means no safely isolated output is currently available. Tracking-disabled
    /// records instead carry a diagnostic string and keep `output_truncated = true`.
    pub output: Option<String>,
    /// Whether the bounded pane capture could not recover complete output boundaries.
    /// This is independent of command completion, which is side-channel authoritative.
    pub output_truncated: bool,
    /// Human-readable explanation for cancelled/tracking_error terminals.
    pub reason: Option<String>,
    /// Accept time; used for abandon windows and `elapsed_ms` projection.
    pub started_at: Instant,
    /// Set when status becomes terminal.
    pub completed_at: Option<Instant>,
    /// True when the client requested raw key injection without tracking wrappers.
    pub raw_mode: bool,
    /// True when raw_mode/no_enter skipped side-channel tracking entirely.
    pub tracking_disabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_snapshot_preserves_output_capture_completeness() {
        let now = Instant::now();
        let execution = CommandExecution {
            id: "cmd-1".to_string(),
            pane_id: "%1".to_string(),
            socket: Some("/tmp/tmux.sock".to_string()),
            command: "printf tail".to_string(),
            status: CommandStatus::Completed,
            exit_code: Some(0),
            output: Some("tail".to_string()),
            output_truncated: true,
            reason: None,
            started_at: now,
            completed_at: Some(now),
            raw_mode: false,
            tracking_disabled: false,
        };

        let snapshot = CommandSnapshot::from_execution(&execution, None);
        assert_eq!(snapshot.output.as_deref(), Some("tail"));
        assert!(snapshot.output_truncated);

        let wire = serde_json::to_value(snapshot).expect("serialize command snapshot");
        assert_eq!(wire["output"], "tail");
        assert_eq!(wire["outputTruncated"], true);
    }
}
