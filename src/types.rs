#![allow(dead_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Instant;

/// Summary of a tmux session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Session {
    pub id: String,
    pub name: String,
    pub attached: bool,
    pub windows: u32,
}

/// Summary of a tmux window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Window {
    pub id: String,
    pub name: String,
    pub active: bool,
    pub session_id: String,
}

/// Summary of a tmux pane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Pane {
    pub id: String,
    pub window_id: String,
    pub active: bool,
    pub title: String,
}

/// Detailed metadata for a tmux pane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PaneInfo {
    pub id: String,
    pub window_id: String,
    pub session_id: String,
    pub title: String,
    pub active: bool,
    pub current_path: String,
    pub current_command: String,
    pub width: u32,
    pub height: u32,
    pub pid: Option<u32>,
    pub in_mode: bool,
}

/// Detailed metadata for a tmux window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WindowInfo {
    pub id: String,
    pub name: String,
    pub session_id: String,
    pub active: bool,
    pub layout: String,
    pub panes: u32,
    pub width: u32,
    pub height: u32,
    pub zoomed: bool,
    pub active_pane_id: String,
}

/// Information about an attached tmux client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientInfo {
    pub tty: String,
    pub name: String,
    pub session_name: String,
    pub pid: Option<u32>,
    pub attached: bool,
}

/// Information about a tmux paste buffer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BufferInfo {
    pub name: String,
    pub size: u32,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: u64,
    #[serde(rename = "orderIndex")]
    pub order_index: u32,
    pub created: Option<i64>,
}

/// Search modes for buffer search tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SearchMode {
    Literal,
    Regex,
}

/// A single buffer search match with context.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BufferSearchMatch {
    #[serde(rename = "matchId")]
    pub match_id: String,
    pub buffer: String,
    #[serde(rename = "offsetBytes")]
    pub offset_bytes: u64,
    #[serde(rename = "matchLen")]
    pub match_len: u32,
    #[serde(rename = "contextStart")]
    pub context_start: u64,
    #[serde(rename = "contextEnd")]
    pub context_end: u64,
    pub snippet: String,
    pub similarity: Option<f32>,
}

/// Structured output for search-buffer and subsearch-buffer tools.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BufferSearchOutput {
    pub query: String,
    pub mode: SearchMode,
    #[serde(rename = "contextBytes")]
    pub context_bytes: u32,
    #[serde(rename = "maxMatches")]
    pub max_matches: u32,
    #[serde(rename = "includeSimilarity")]
    pub include_similarity: bool,
    #[serde(rename = "fuzzyMatch")]
    pub fuzzy_match: bool,
    #[serde(rename = "similarityThreshold")]
    pub similarity_threshold: Option<f32>,
    pub buffers: Vec<String>,
    #[serde(rename = "totalMatches")]
    pub total_matches: u32,
    #[serde(rename = "buffersScanned")]
    pub buffers_scanned: u32,
    #[serde(rename = "bytesScannedTotal")]
    pub bytes_scanned_total: u64,
    #[serde(rename = "truncatedBuffers")]
    pub truncated_buffers: Vec<String>,
    #[serde(rename = "resumeFromOffset")]
    pub resume_from_offset: BTreeMap<String, u64>,
    pub matches: Vec<BufferSearchMatch>,
    #[serde(rename = "maxSimilarity")]
    pub max_similarity: Option<f32>,
    #[serde(rename = "avgSimilarity")]
    pub avg_similarity: Option<f32>,
    #[serde(rename = "fuzzySkippedLines")]
    pub fuzzy_skipped_lines: u32,
    #[serde(rename = "fuzzySkippedBytes")]
    pub fuzzy_skipped_bytes: u64,
}

/// Window with its panes for tree snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WindowTree {
    pub window: Window,
    pub panes: Vec<Pane>,
}

/// Session tree with windows and panes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionTree {
    pub session: Session,
    pub windows: Vec<WindowTree>,
}

/// Supported shell types for command tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum ShellType {
    #[default]
    Bash,
    Zsh,
    Fish,
    Unknown,
}

/// Execution status for a tracked command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CommandStatus {
    Pending,
    Completed,
    Error,
}

/// Tracked command execution record.
#[derive(Debug, Clone)]
pub struct CommandExecution {
    pub id: String,
    pub pane_id: String,
    pub socket: Option<String>,
    pub command: String,
    pub status: CommandStatus,
    pub exit_code: Option<i32>,
    pub output: Option<String>,
    pub started_at: Instant,
    pub completed_at: Option<Instant>,
    pub raw_mode: bool,
    pub tracking_disabled: bool,
}
