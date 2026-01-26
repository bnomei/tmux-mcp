//! MCP server implementation for tmux-mcp-rs.
//!
//! This module registers all tools and resources using the rmcp crate.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    Annotated, CallToolResult, Content, RawResource, RawResourceTemplate, Resource,
    ResourceContents, ServerCapabilities, ServerInfo,
};
use rmcp::schemars::JsonSchema;
use rmcp::serde::{Deserialize, Serialize};
use rmcp::serde_json;
use rmcp::tool;
use rmcp::tool_router;
use rmcp::ErrorData as McpError;

use crate::commands::CommandTracker;
use crate::security::SecurityPolicy;
use crate::tmux;
use crate::types::{
    BufferInfo, BufferSearchOutput, ClientInfo, CommandStatus, Pane, SearchMode, Session, Window,
};

/// The main MCP server for tmux operations.
#[derive(Clone)]
pub struct TmuxMcpServer {
    tracker: Arc<CommandTracker>,
    policy: Arc<SecurityPolicy>,
    tool_router: ToolRouter<Self>,
}

fn structured_output<T: Serialize>(value: &T) -> CallToolResult {
    match serde_json::to_value(value) {
        Ok(json) => CallToolResult::structured(json),
        Err(e) => CallToolResult::error(vec![Content::text(format!(
            "Error serializing output: {e}"
        ))]),
    }
}

// ============================================================================
// Tool Output Schemas
// ============================================================================

/// Output payload for the execute-command tool.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ExecuteCommandOutput {
    #[serde(rename = "commandId")]
    pub command_id: String,
    pub status: String,
    pub message: String,
}

/// Output payload for the list-sessions tool.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListSessionsOutput {
    pub sessions: Vec<Session>,
}

/// Output payload for the list-windows tool.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListWindowsOutput {
    pub windows: Vec<Window>,
}

/// Output payload for the list-panes tool.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListPanesOutput {
    pub panes: Vec<Pane>,
}

/// Output payload for the list-clients tool.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListClientsOutput {
    pub clients: Vec<ClientInfo>,
}

/// Output payload for the list-buffers tool.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListBuffersOutput {
    pub buffers: Vec<BufferInfo>,
}

/// Output payload for the get-command-result tool.
#[derive(Debug, Serialize, JsonSchema)]
pub struct GetCommandResultOutput {
    pub status: String,
    #[serde(rename = "exitCode", skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

// ============================================================================
// Tool Input Schemas
// ============================================================================

/// Input parameters for socket-only tools.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SocketInput {
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the socket-for-path tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SocketForPathInput {
    /// Project path to derive a deterministic socket path
    pub path: String,
}

/// Input parameters for the find-session tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindSessionInput {
    /// Name of the tmux session to find
    pub name: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for tools that target a session id.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SessionIdInput {
    /// ID of the tmux session
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for tools that target a window id.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct WindowIdInput {
    /// ID of the tmux window
    #[serde(rename = "windowId")]
    pub window_id: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for tools that target a pane id.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PaneIdInput {
    /// ID of the tmux pane
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the capture-pane tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CapturePaneInput {
    /// ID of the tmux pane
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// Number of lines to capture
    pub lines: Option<u32>,
    /// Include color/escape sequences
    pub colors: Option<bool>,
    /// Start line offset (negative counts from bottom)
    pub start: Option<i32>,
    /// End line offset (negative counts from bottom)
    pub end: Option<i32>,
    /// Join wrapped lines
    pub join: Option<bool>,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the create-session tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateSessionInput {
    /// Name for the new tmux session
    pub name: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the create-window tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateWindowInput {
    /// ID of the tmux session
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// Name for the new window
    pub name: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the split-pane tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SplitPaneInput {
    /// ID of the tmux pane to split
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// Split direction: "horizontal" or "vertical"
    pub direction: Option<String>,
    /// Size percentage for the new pane
    pub size: Option<u32>,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the execute-command tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecuteCommandInput {
    /// ID of the tmux pane
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// Command to execute
    pub command: String,
    /// Send command without tracking markers
    #[serde(rename = "rawMode")]
    pub raw_mode: Option<bool>,
    /// Send keys without pressing Enter
    #[serde(rename = "noEnter")]
    pub no_enter: Option<bool>,
    /// Delay between key transmissions in milliseconds
    #[serde(rename = "delayMs")]
    pub delay_ms: Option<u64>,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the get-command-result tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetCommandResultInput {
    /// ID of the executed command
    #[serde(rename = "commandId")]
    pub command_id: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the rename-window tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameWindowInput {
    /// ID of the tmux window
    #[serde(rename = "windowId")]
    pub window_id: String,
    /// New name for the window
    pub name: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the rename-pane tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenamePaneInput {
    /// ID of the tmux pane
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// New title for the pane
    pub title: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the move-window tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct MoveWindowInput {
    /// ID of the tmux window to move
    #[serde(rename = "windowId")]
    pub window_id: String,
    /// Target session ID
    #[serde(rename = "targetSessionId")]
    pub target_session_id: String,
    /// Target index in the session
    #[serde(rename = "targetIndex")]
    pub target_index: Option<u32>,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the rename-session tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameSessionInput {
    /// ID of the tmux session
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// New name for the session
    pub name: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the resize-pane tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResizePaneInput {
    /// ID of the tmux pane
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// Resize direction: "left", "right", "up", "down"
    pub direction: Option<String>,
    /// Resize amount in cells
    pub amount: Option<u32>,
    /// Absolute width in cells
    pub width: Option<u32>,
    /// Absolute height in cells
    pub height: Option<u32>,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the select-layout tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SelectLayoutInput {
    /// ID of the tmux window
    #[serde(rename = "windowId")]
    pub window_id: String,
    /// Layout name (e.g. even-horizontal, tiled, main-vertical)
    pub layout: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the join-pane tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct JoinPaneInput {
    /// Source pane ID
    #[serde(rename = "sourcePaneId")]
    pub source_pane_id: String,
    /// Target pane ID
    #[serde(rename = "targetPaneId")]
    pub target_pane_id: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the swap-pane tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SwapPaneInput {
    /// Source pane ID
    #[serde(rename = "sourcePaneId")]
    pub source_pane_id: String,
    /// Target pane ID
    #[serde(rename = "targetPaneId")]
    pub target_pane_id: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the break-pane tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct BreakPaneInput {
    /// ID of the tmux pane
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// Optional name for the new window
    pub name: Option<String>,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the set-synchronize-panes tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetSynchronizePanesInput {
    /// ID of the tmux window
    #[serde(rename = "windowId")]
    pub window_id: String,
    /// Whether to enable synchronize-panes
    pub enabled: bool,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the detach-client tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DetachClientInput {
    /// Client tty identifier
    #[serde(rename = "clientTty")]
    pub client_tty: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the show-buffer tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ShowBufferInput {
    /// Buffer name (omit to show the most recent buffer)
    pub name: Option<String>,
    /// Optional offset into the buffer in bytes
    #[serde(rename = "offsetBytes")]
    pub offset_bytes: Option<u64>,
    /// Optional maximum number of bytes to return
    #[serde(rename = "maxBytes")]
    pub max_bytes: Option<u64>,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the save-buffer tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SaveBufferInput {
    /// Buffer name
    pub name: String,
    /// Path to save the buffer contents
    pub path: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the load-buffer tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct LoadBufferInput {
    /// Buffer name
    pub name: String,
    /// Path to load the buffer contents from
    pub path: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the delete-buffer tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteBufferInput {
    /// Buffer name
    pub name: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the set-buffer tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetBufferInput {
    /// Buffer name
    pub name: String,
    /// Buffer content (UTF-8)
    pub content: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the append-buffer tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AppendBufferInput {
    /// Buffer name
    pub name: String,
    /// Content to append (UTF-8)
    pub content: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the rename-buffer tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameBufferInput {
    /// Source buffer name
    pub from: String,
    /// Destination buffer name
    pub to: String,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Search anchor for subsearch-buffer.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchAnchorInput {
    /// Match offset in bytes (UTF-8)
    #[serde(rename = "offsetBytes", alias = "offset_bytes")]
    pub offset_bytes: u64,
    /// Match length in bytes (UTF-8)
    #[serde(rename = "matchLen", alias = "match_len")]
    pub match_len: u32,
    /// Optional buffer name (used if top-level buffer is omitted)
    pub buffer: Option<String>,
}

/// Input parameters for the search-buffer tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchBufferInput {
    /// Optional single buffer name (alias for buffers)
    #[serde(rename = "buffer")]
    pub buffer: Option<String>,
    /// Optional list of buffer names to search (defaults to all buffers)
    pub buffers: Option<Vec<String>>,
    /// Query string
    pub query: String,
    /// Search mode: literal or regex
    pub mode: SearchMode,
    /// Context window size in bytes
    #[serde(rename = "contextBytes")]
    pub context_bytes: Option<u32>,
    /// Max matches to return
    #[serde(rename = "maxMatches")]
    pub max_matches: Option<u32>,
    /// Max bytes to scan per buffer
    #[serde(rename = "maxScanBytes")]
    pub max_scan_bytes: Option<u64>,
    /// Whether to include similarity scores
    #[serde(rename = "includeSimilarity")]
    pub include_similarity: Option<bool>,
    /// Enable fuzzy matching
    #[serde(rename = "fuzzyMatch")]
    pub fuzzy_match: Option<bool>,
    /// Similarity threshold for fuzzy matching (0.0-1.0)
    #[serde(rename = "similarityThreshold")]
    pub similarity_threshold: Option<f32>,
    /// Optional per-buffer resume offset in bytes (UTF-8)
    #[serde(rename = "resumeFromOffset")]
    pub resume_from_offset: Option<BTreeMap<String, u64>>,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the subsearch-buffer tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SubsearchBufferInput {
    /// Buffer name
    pub buffer: Option<String>,
    /// Anchor offset and length from a prior match
    pub anchor: SearchAnchorInput,
    /// Context window size in bytes
    #[serde(rename = "contextBytes", alias = "context_bytes")]
    pub context_bytes: u32,
    /// Optional resume offset in bytes (UTF-8) within the anchor window
    #[serde(rename = "resumeFromOffset")]
    pub resume_from_offset: Option<u64>,
    /// Query string
    pub query: String,
    /// Search mode: literal or regex
    pub mode: SearchMode,
    /// Max matches to return
    #[serde(rename = "maxMatches")]
    pub max_matches: Option<u32>,
    /// Whether to include similarity scores
    #[serde(rename = "includeSimilarity")]
    pub include_similarity: Option<bool>,
    /// Enable fuzzy matching
    #[serde(rename = "fuzzyMatch")]
    pub fuzzy_match: Option<bool>,
    /// Similarity threshold for fuzzy matching (0.0-1.0)
    #[serde(rename = "similarityThreshold")]
    pub similarity_threshold: Option<f32>,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

/// Input parameters for the send-keys tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SendKeysInput {
    /// ID of the tmux pane
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// Keys to send
    pub keys: String,
    /// Send each character individually
    pub literal: Option<bool>,
    /// Number of times to repeat the keys
    pub repeat: Option<u32>,
    /// Delay between key transmissions in milliseconds
    #[serde(rename = "delayMs")]
    pub delay_ms: Option<u64>,
    /// Optional tmux socket path override for this call. Prefer a per-agent isolated socket (unique id, e.g. harness session id).
    pub socket: Option<String>,
}

// ============================================================================
// Tool Router Implementation
// ============================================================================

fn normalize_path_for_socket(path: &str) -> String {
    let mut normalized = path.trim().to_string();
    while normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    normalized
}

fn hash_path_for_socket(path: &str) -> String {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut hash = FNV_OFFSET;
    for byte in path.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{hash:016x}")
}

#[tool_router]
impl TmuxMcpServer {
    /// Create a new MCP server with a command tracker and security policy.
    pub fn new(tracker: CommandTracker, policy: SecurityPolicy) -> Self {
        Self {
            tracker: Arc::new(tracker),
            policy: Arc::new(policy),
            tool_router: Self::tool_router(),
        }
    }

    // Core tools
    #[tool(
        name = "socket-for-path",
        description = "Derive a deterministic tmux socket path for a project directory. Use to pick a per-worktree socket without env vars; returns /tmp/{hash}.sock.",
        annotations(read_only_hint = true, idempotent_hint = true)
    )]
    async fn socket_for_path(
        &self,
        input: Parameters<SocketForPathInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("socket-for-path") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let trimmed = input.0.path.trim();
        if trimmed.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "path is required".to_string(),
            )]));
        }
        let normalized = normalize_path_for_socket(trimmed);
        let hash = hash_path_for_socket(&normalized);
        let socket_path = format!("/tmp/{hash}.sock");
        Ok(CallToolResult::success(vec![Content::text(socket_path)]))
    }

    #[tool(
        name = "list-sessions",
        description = "List all tmux sessions with id, name, attached status, and window count. Returns JSON: { sessions: [{id, name, attached, windows}] }. Use at task start to map the workspace and select safe targets before list-windows/kill-session/rename-session.",
        annotations(read_only_hint = true, idempotent_hint = true),
        output_schema = rmcp::handler::server::common::schema_for_type::<ListSessionsOutput>()
    )]
    async fn list_sessions(
        &self,
        input: Parameters<SocketInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("list-sessions") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::list_sessions(socket.as_deref()).await {
            Ok(sessions) => Ok(structured_output(&ListSessionsOutput { sessions })),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error listing sessions: {e}"
            ))])),
        }
    }

    #[tool(
        name = "find-session",
        description = "Find a tmux session by exact name. Returns JSON: {id, name, attached, windows} or 'Session not found' message. Use when you know a session name and need its ID before targeting windows/panes or renaming.",
        annotations(read_only_hint = true, idempotent_hint = true),
        output_schema = rmcp::handler::server::common::schema_for_type::<crate::types::Session>()
    )]
    async fn find_session(
        &self,
        input: Parameters<FindSessionInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("find-session") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::find_session_by_name(&input.0.name, socket.as_deref()).await {
            Ok(Some(session)) => Ok(structured_output(&session)),
            Ok(None) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Session not found: {}",
                input.0.name
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error finding session: {e}"
            ))])),
        }
    }

    #[tool(
        name = "list-windows",
        description = "List windows in a tmux session. Returns JSON: { windows: [{id, name, active, session_id}] }. Use to plan layouts, select a window, or locate pane IDs before send-keys/capture-pane.",
        annotations(read_only_hint = true, idempotent_hint = true),
        output_schema = rmcp::handler::server::common::schema_for_type::<ListWindowsOutput>()
    )]
    async fn list_windows(
        &self,
        input: Parameters<SessionIdInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("list-windows") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_session(&input.0.session_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::list_windows(&input.0.session_id, socket.as_deref()).await {
            Ok(windows) => Ok(structured_output(&ListWindowsOutput { windows })),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error listing windows: {e}"
            ))])),
        }
    }

    #[tool(
        name = "list-panes",
        description = "List panes in a tmux window. Returns JSON: { panes: [{id, window_id, active, title}] }. Use to target the correct pane before execute-command/send-keys/capture-pane, especially in multi-pane workflows.",
        annotations(read_only_hint = true, idempotent_hint = true),
        output_schema = rmcp::handler::server::common::schema_for_type::<ListPanesOutput>()
    )]
    async fn list_panes(
        &self,
        input: Parameters<WindowIdInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("list-panes") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::list_panes(&input.0.window_id, socket.as_deref()).await {
            Ok(panes) => Ok(structured_output(&ListPanesOutput { panes })),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error listing panes: {e}"
            ))])),
        }
    }

    #[tool(
        name = "list-clients",
        description = "List tmux clients. Returns JSON: { clients: [{tty, name, session_name, pid?, attached}] }. Use to detect observers for handoff, and to avoid detaching active users before disruptive actions.",
        annotations(read_only_hint = true, idempotent_hint = true),
        output_schema = rmcp::handler::server::common::schema_for_type::<ListClientsOutput>()
    )]
    async fn list_clients(
        &self,
        input: Parameters<SocketInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("list-clients") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::list_clients(socket.as_deref()).await {
            Ok(clients) => Ok(structured_output(&ListClientsOutput { clients })),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error listing clients: {e}"
            ))])),
        }
    }

    #[tool(
        name = "list-buffers",
        description = "List tmux paste buffers. Returns JSON: { buffers: [{name, size, created?}] }. Use before show-buffer/save-buffer/delete-buffer to pick the right buffer and avoid losing data.",
        annotations(read_only_hint = true, idempotent_hint = true),
        output_schema = rmcp::handler::server::common::schema_for_type::<ListBuffersOutput>()
    )]
    async fn list_buffers(
        &self,
        input: Parameters<SocketInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("list-buffers") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::list_buffers(socket.as_deref()).await {
            Ok(buffers) => Ok(structured_output(&ListBuffersOutput { buffers })),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error listing buffers: {e}"
            ))])),
        }
    }

    #[tool(
        name = "capture-pane",
        description = "Read screen content and scrollback from a pane. Returns plain text of pane contents. Use to check state, tail logs, or verify interactive steps; avoid send-keys+send-enter+capture-pane for routine command output; prefer execute-command + get-command-result.",
        annotations(read_only_hint = true, idempotent_hint = true)
    )]
    async fn capture_pane(
        &self,
        input: Parameters<CapturePaneInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("capture-pane") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(&input.0.pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::capture_pane(
            &input.0.pane_id,
            input.0.lines,
            input.0.colors.unwrap_or(false),
            input.0.start,
            input.0.end,
            input.0.join.unwrap_or(false),
            socket.as_deref(),
        )
        .await
        {
            Ok(content) => Ok(CallToolResult::success(vec![Content::text(
                if content.is_empty() {
                    "No content captured".into()
                } else {
                    content
                },
            )])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error capturing pane: {e}"
            ))])),
        }
    }

    #[tool(
        name = "show-buffer",
        description = "Show contents of a tmux paste buffer. If name is omitted, shows the most recent buffer. Supports offset/max byte bounds and returns plain text (lossy if needed).",
        annotations(read_only_hint = true, idempotent_hint = true)
    )]
    async fn show_buffer(
        &self,
        input: Parameters<ShowBufferInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("show-buffer") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::show_buffer_slice(
            input.0.name.as_deref(),
            input.0.offset_bytes,
            input.0.max_bytes,
            socket.as_deref(),
        )
        .await
        {
            Ok(content) => Ok(CallToolResult::success(vec![Content::text(content)])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error showing buffer: {e}"
            ))])),
        }
    }

    #[tool(
        name = "save-buffer",
        description = "Save a tmux paste buffer to a file. Use to persist logs or copy-mode selections for audit/review; writes to the filesystem.",
        annotations(open_world_hint = true)
    )]
    async fn save_buffer(
        &self,
        input: Parameters<SaveBufferInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("save-buffer") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::save_buffer(&input.0.name, &input.0.path, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Buffer {} saved to {}",
                input.0.name, input.0.path
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error saving buffer: {e}"
            ))])),
        }
    }

    #[tool(
        name = "load-buffer",
        description = "Load a tmux paste buffer from a file. Use to import local files into tmux buffers for later search or inspection.",
        annotations(open_world_hint = true)
    )]
    async fn load_buffer(
        &self,
        input: Parameters<LoadBufferInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("load-buffer") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::load_buffer(&input.0.name, &input.0.path, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Buffer {} loaded from {}",
                input.0.name, input.0.path
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error loading buffer: {e}"
            ))])),
        }
    }

    #[tool(
        name = "delete-buffer",
        description = "Delete a tmux paste buffer by name. Use to clean up sensitive data or reduce clutter after exporting.",
        annotations(destructive_hint = true)
    )]
    async fn delete_buffer(
        &self,
        input: Parameters<DeleteBufferInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("delete-buffer") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::delete_buffer(&input.0.name, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Buffer {} deleted",
                input.0.name
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error deleting buffer: {e}"
            ))])),
        }
    }

    #[tool(
        name = "set-buffer",
        description = "Create or replace a tmux paste buffer with UTF-8 content.",
        annotations(destructive_hint = true)
    )]
    async fn set_buffer(
        &self,
        input: Parameters<SetBufferInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("set-buffer") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::set_buffer(&input.0.name, &input.0.content, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Buffer {} set",
                input.0.name
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error setting buffer: {e}"
            ))])),
        }
    }

    #[tool(
        name = "append-buffer",
        description = "Append UTF-8 content to an existing tmux paste buffer.",
        annotations(destructive_hint = true)
    )]
    async fn append_buffer(
        &self,
        input: Parameters<AppendBufferInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("append-buffer") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::append_buffer(&input.0.name, &input.0.content, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Buffer {} appended",
                input.0.name
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error appending buffer: {e}"
            ))])),
        }
    }

    #[tool(
        name = "rename-buffer",
        description = "Rename a tmux buffer by copying to a new name and deleting the old buffer.",
        annotations(destructive_hint = true)
    )]
    async fn rename_buffer(
        &self,
        input: Parameters<RenameBufferInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("rename-buffer") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::rename_buffer(&input.0.from, &input.0.to, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Buffer {} renamed to {}",
                input.0.from, input.0.to
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error renaming buffer: {e}"
            ))])),
        }
    }

    #[tool(
        name = "search-buffer",
        description = "Search UTF-8 buffers for a query (literal/regex, optional fuzzy) with structured match metadata; offsets are byte-based; use resumeFromOffset when truncatedBuffers is returned; fuzzy matching skips very long lines.",
        annotations(read_only_hint = true, idempotent_hint = true),
        output_schema = rmcp::handler::server::common::schema_for_type::<BufferSearchOutput>()
    )]
    async fn search_buffer(
        &self,
        input: Parameters<SearchBufferInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("search-buffer") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let include_similarity = input.0.include_similarity.unwrap_or(false);
        let fuzzy_match = input.0.fuzzy_match.unwrap_or(false);
        let buffers = if let Some(buffer) = input.0.buffer.as_deref() {
            Some(vec![buffer.to_string()])
        } else {
            input.0.buffers.clone()
        };
        match tmux::search_buffers(
            buffers,
            &input.0.query,
            input.0.mode,
            input.0.context_bytes,
            input.0.max_matches,
            input.0.max_scan_bytes,
            include_similarity,
            fuzzy_match,
            input.0.similarity_threshold,
            input.0.resume_from_offset,
            socket.as_deref(),
        )
        .await
        {
            Ok(output) => Ok(structured_output(&output)),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error searching buffers: {e}"
            ))])),
        }
    }

    #[tool(
        name = "subsearch-buffer",
        description = "Anchor-scoped follow-up search within a UTF-8 buffer (literal/regex, optional fuzzy); offsets are absolute; resumeFromOffset is relative to the anchor window; fuzzy matching skips very long lines.",
        annotations(read_only_hint = true, idempotent_hint = true),
        output_schema = rmcp::handler::server::common::schema_for_type::<BufferSearchOutput>()
    )]
    async fn subsearch_buffer(
        &self,
        input: Parameters<SubsearchBufferInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("subsearch-buffer") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let include_similarity = input.0.include_similarity.unwrap_or(false);
        let fuzzy_match = input.0.fuzzy_match.unwrap_or(false);
        let buffer = input
            .0
            .buffer
            .as_deref()
            .or(input.0.anchor.buffer.as_deref());
        let Some(buffer) = buffer else {
            return Ok(CallToolResult::error(vec![Content::text(
                "Missing buffer name. Provide top-level 'buffer' or anchor.buffer.".to_string(),
            )]));
        };

        match tmux::subsearch_buffer(
            buffer,
            input.0.anchor.offset_bytes,
            input.0.anchor.match_len,
            input.0.context_bytes,
            input.0.resume_from_offset,
            &input.0.query,
            input.0.mode,
            input.0.max_matches,
            include_similarity,
            fuzzy_match,
            input.0.similarity_threshold,
            socket.as_deref(),
        )
        .await
        {
            Ok(output) => Ok(structured_output(&output)),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error subsearching buffer: {e}"
            ))])),
        }
    }

    #[tool(
        name = "create-session",
        description = "Create a new tmux session with the given name. Use to start an isolated workspace for an agent task, then create-window or use the default window.",
        annotations(read_only_hint = false)
    )]
    async fn create_session(
        &self,
        input: Parameters<CreateSessionInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("create-session") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::create_session(&input.0.name, socket.as_deref()).await {
            Ok(session) => Ok(structured_output(&session)),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error creating session: {e}"
            ))])),
        }
    }

    #[tool(
        name = "create-window",
        description = "Create a new window in a tmux session. Use to separate build/test/log/REPL workspaces; returns the created window with its first pane.",
        annotations(read_only_hint = false)
    )]
    async fn create_window(
        &self,
        input: Parameters<CreateWindowInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("create-window") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_session(&input.0.session_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::create_window(&input.0.session_id, &input.0.name, socket.as_deref()).await {
            Ok(window) => Ok(structured_output(&window)),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error creating window: {e}"
            ))])),
        }
    }

    #[tool(
        name = "split-pane",
        description = "Split a pane horizontally or vertically, optionally with a size percentage. Use to create parallel views (logs + REPL, editor + tests); returns the new pane.",
        annotations(read_only_hint = false)
    )]
    async fn split_pane(
        &self,
        input: Parameters<SplitPaneInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("split-pane") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(&input.0.pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::split_pane(
            &input.0.pane_id,
            input.0.direction.as_deref(),
            input.0.size,
            socket.as_deref(),
        )
        .await
        {
            Ok(pane) => Ok(structured_output(&pane)),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error splitting pane: {e}"
            ))])),
        }
    }

    #[tool(
        name = "kill-session",
        description = "Terminate a tmux session and all its windows/panes. Use for cleanup in isolated agent sessions; avoid in shared sessions.",
        annotations(destructive_hint = true)
    )]
    async fn kill_session(
        &self,
        input: Parameters<SessionIdInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("kill-session") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_session(&input.0.session_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::kill_session(&input.0.session_id, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Session {} has been killed",
                input.0.session_id
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error killing session: {e}"
            ))])),
        }
    }

    #[tool(
        name = "kill-window",
        description = "Close a tmux window and all its panes. Use for cleanup after a task window is done; avoid in shared windows.",
        annotations(destructive_hint = true)
    )]
    async fn kill_window(
        &self,
        input: Parameters<WindowIdInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("kill-window") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::kill_window(&input.0.window_id, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Window {} has been killed",
                input.0.window_id
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error killing window: {e}"
            ))])),
        }
    }

    #[tool(
        name = "kill-pane",
        description = "Close a tmux pane. Use to stop a pane that is no longer needed or to clean up after finishing a task. Note: if this is the last pane in a window, tmux will close that window too.",
        annotations(destructive_hint = true)
    )]
    async fn kill_pane(&self, input: Parameters<PaneIdInput>) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("kill-pane") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(&input.0.pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::kill_pane(&input.0.pane_id, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Pane {} has been killed",
                input.0.pane_id
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error killing pane: {e}"
            ))])),
        }
    }

    #[tool(
        name = "execute-command",
        description = "Run a shell command in a pane with exit-code tracking. Returns JSON: {commandId, status, message}. Preferred for non-interactive commands; for pipes/quotes, wrap with `sh -lc '...'`. Poll with get-command-result, and use capture-pane only if you need live progress. For interactive programs (vim/htop), use send-keys instead.",
        annotations(open_world_hint = true),
        output_schema = rmcp::handler::server::common::schema_for_type::<ExecuteCommandOutput>()
    )]
    async fn execute_command(
        &self,
        input: Parameters<ExecuteCommandInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("execute-command") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(&input.0.pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let raw_mode = input.0.raw_mode.unwrap_or(false);
        if raw_mode {
            if let Err(e) = self.policy.check_raw_mode() {
                return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
            }
        }
        if let Err(e) = self.policy.check_command(&input.0.command) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match self
            .tracker
            .execute_command(
                &input.0.pane_id,
                &input.0.command,
                raw_mode,
                input.0.no_enter.unwrap_or(false),
                input.0.delay_ms,
                socket.clone(),
            )
            .await
        {
            Ok(command_id) => {
                let response = ExecuteCommandOutput {
                    command_id,
                    status: "pending".into(),
                    message: "Command sent to pane".into(),
                };
                Ok(structured_output(&response))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error executing command: {e}"
            ))])),
        }
    }

    #[tool(
        name = "get-command-result",
        description = "Check the status and output of a tracked command by its ID. Returns JSON: {status, exitCode?, command, output?}. Preferred for command output after execute-command; if status stays pending, switch to capture-pane for live output.",
        annotations(read_only_hint = true, idempotent_hint = true),
        output_schema = rmcp::handler::server::common::schema_for_type::<GetCommandResultOutput>()
    )]
    async fn get_command_result(
        &self,
        input: Parameters<GetCommandResultInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("get-command-result") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Some(cmd) = self.tracker.get_command(&input.0.command_id).await {
            if let Some(requested) = socket.as_deref() {
                if let Some(recorded) = cmd.socket.as_deref() {
                    if recorded != requested {
                        return Ok(CallToolResult::error(vec![Content::text(format!(
                            "Socket override does not match recorded socket for command {}",
                            input.0.command_id
                        ))]));
                    }
                }
            }
            if let Err(e) = self.policy.check_pane(&cmd.pane_id) {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Access denied: {e}"
                ))]));
            }
        } else {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Command not found: {}",
                input.0.command_id
            ))]));
        }
        match self
            .tracker
            .check_status(&input.0.command_id, socket.as_deref())
            .await
        {
            Ok(Some(cmd)) => {
                let result = GetCommandResultOutput {
                    status: format!("{:?}", cmd.status).to_lowercase(),
                    exit_code: cmd.exit_code,
                    command: cmd.command.clone(),
                    output: if matches!(cmd.status, CommandStatus::Completed | CommandStatus::Error)
                    {
                        cmd.output.clone()
                    } else {
                        None
                    },
                };
                Ok(structured_output(&result))
            }
            Ok(None) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Command not found: {}",
                input.0.command_id
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error getting command result: {e}"
            ))])),
        }
    }

    // Feature candidate tools
    #[tool(
        name = "get-current-session",
        description = "Get the tmux session this server is running in. Use to anchor actions when the agent is attached to a session and you want to avoid targeting the wrong session.",
        annotations(read_only_hint = true, idempotent_hint = true)
    )]
    async fn get_current_session(
        &self,
        input: Parameters<SocketInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("get-current-session") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::get_current_session(socket.as_deref()).await {
            Ok(session) => Ok(structured_output(&session)),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error getting current session: {e}"
            ))])),
        }
    }

    #[tool(
        name = "rename-session",
        description = "Rename a tmux session. Use to keep session names meaningful for handoff and status tracking during long-running tasks.",
        annotations(idempotent_hint = true)
    )]
    async fn rename_session(
        &self,
        input: Parameters<RenameSessionInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("rename-session") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_session(&input.0.session_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::rename_session(&input.0.session_id, &input.0.name, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Session {} renamed to {}",
                input.0.session_id, input.0.name
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error renaming session: {e}"
            ))])),
        }
    }

    #[tool(
        name = "rename-window",
        description = "Rename a tmux window. Use to give windows meaningful names for log/test/build separation and human handoff.",
        annotations(idempotent_hint = true)
    )]
    async fn rename_window(
        &self,
        input: Parameters<RenameWindowInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("rename-window") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::rename_window(&input.0.window_id, &input.0.name, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Window {} renamed to {}",
                input.0.window_id, input.0.name
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error renaming window: {e}"
            ))])),
        }
    }

    #[tool(
        name = "rename-pane",
        description = "Set the title of a tmux pane. Use to label panes for easier identification (log, REPL, server) and faster targeting later.",
        annotations(idempotent_hint = true)
    )]
    async fn rename_pane(
        &self,
        input: Parameters<RenamePaneInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("rename-pane") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(&input.0.pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::rename_pane(&input.0.pane_id, &input.0.title, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Pane {} title set to {}",
                input.0.pane_id, input.0.title
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error renaming pane: {e}"
            ))])),
        }
    }

    #[tool(
        name = "move-window",
        description = "Move a window to another session, optionally at a specific index. Use to reorganize workspaces after tasks complete or to group related windows.",
        annotations(read_only_hint = false)
    )]
    async fn move_window(
        &self,
        input: Parameters<MoveWindowInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("move-window") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_session(&input.0.target_session_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::move_window(
            &input.0.window_id,
            &input.0.target_session_id,
            input.0.target_index,
            socket.as_deref(),
        )
        .await
        {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Window {} moved to session {}",
                input.0.window_id, input.0.target_session_id
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error moving window: {e}"
            ))])),
        }
    }

    #[tool(
        name = "select-window",
        description = "Select (focus) a tmux window. Use before pane actions when window context matters (layout changes, selection, or synchronized panes)."
    )]
    async fn select_window(
        &self,
        input: Parameters<WindowIdInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("select-window") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::select_window(&input.0.window_id, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Window {} selected",
                input.0.window_id
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error selecting window: {e}"
            ))])),
        }
    }

    #[tool(
        name = "select-pane",
        description = "Select (focus) a tmux pane. Use before send-keys or capture-pane to ensure actions target the intended pane."
    )]
    async fn select_pane(
        &self,
        input: Parameters<PaneIdInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("select-pane") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(&input.0.pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::select_pane(&input.0.pane_id, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Pane {} selected",
                input.0.pane_id
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error selecting pane: {e}"
            ))])),
        }
    }

    #[tool(
        name = "resize-pane",
        description = "Resize a tmux pane by direction/amount or absolute width/height. Use before capture-pane or interactive work to make logs and prompts readable."
    )]
    async fn resize_pane(
        &self,
        input: Parameters<ResizePaneInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("resize-pane") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(&input.0.pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::resize_pane(
            &input.0.pane_id,
            input.0.direction.as_deref(),
            input.0.amount,
            input.0.width,
            input.0.height,
            socket.as_deref(),
        )
        .await
        {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Pane {} resized",
                input.0.pane_id
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error resizing pane: {e}"
            ))])),
        }
    }

    #[tool(
        name = "zoom-pane",
        description = "Toggle zoom for a tmux pane. Use to focus on a single pane for reading logs or driving a TUI, then toggle back."
    )]
    async fn zoom_pane(&self, input: Parameters<PaneIdInput>) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("zoom-pane") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(&input.0.pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::zoom_pane(&input.0.pane_id, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Pane {} zoom toggled",
                input.0.pane_id
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error zooming pane: {e}"
            ))])),
        }
    }

    #[tool(
        name = "select-layout",
        description = "Select a window layout (tiled, even-horizontal, main-vertical, etc.). Use to normalize pane geometry for monitoring or broadcasting.",
        annotations(idempotent_hint = true)
    )]
    async fn select_layout(
        &self,
        input: Parameters<SelectLayoutInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("select-layout") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::select_layout(&input.0.window_id, &input.0.layout, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Window {} layout set to {}",
                input.0.window_id, input.0.layout
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error selecting layout: {e}"
            ))])),
        }
    }

    #[tool(
        name = "join-pane",
        description = "Join a source pane into the target pane's window. Use to consolidate related work (logs + worker) into one window for easier monitoring."
    )]
    async fn join_pane(
        &self,
        input: Parameters<JoinPaneInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("join-pane") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(&input.0.source_pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(&input.0.target_pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::join_pane(
            &input.0.source_pane_id,
            &input.0.target_pane_id,
            socket.as_deref(),
        )
        .await
        {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Pane {} joined into {}",
                input.0.source_pane_id, input.0.target_pane_id
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error joining pane: {e}"
            ))])),
        }
    }

    #[tool(
        name = "break-pane",
        description = "Break a pane out into its own window. Use to isolate a noisy pane or to hand off a focused view; returns the new window.",
        output_schema = rmcp::handler::server::common::schema_for_type::<crate::types::Window>()
    )]
    async fn break_pane(
        &self,
        input: Parameters<BreakPaneInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("break-pane") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(&input.0.pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::break_pane(&input.0.pane_id, input.0.name.as_deref(), socket.as_deref()).await {
            Ok(window) => Ok(structured_output(&window)),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error breaking pane: {e}"
            ))])),
        }
    }

    #[tool(
        name = "swap-pane",
        description = "Swap two panes. Use to reorder panes within or across windows without closing or recreating them."
    )]
    async fn swap_pane(
        &self,
        input: Parameters<SwapPaneInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("swap-pane") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(&input.0.source_pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(&input.0.target_pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::swap_pane(
            &input.0.source_pane_id,
            &input.0.target_pane_id,
            socket.as_deref(),
        )
        .await
        {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Pane {} swapped with {}",
                input.0.source_pane_id, input.0.target_pane_id
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error swapping pane: {e}"
            ))])),
        }
    }

    #[tool(
        name = "set-synchronize-panes",
        description = "Enable or disable synchronize-panes for a window. Use to fan out commands to all panes, then disable to avoid accidental broadcasts.",
        annotations(idempotent_hint = true)
    )]
    async fn set_synchronize_panes(
        &self,
        input: Parameters<SetSynchronizePanesInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("set-synchronize-panes") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::set_synchronize_panes(&input.0.window_id, input.0.enabled, socket.as_deref())
            .await
        {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Window {} synchronize-panes set to {}",
                input.0.window_id, input.0.enabled
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error setting synchronize-panes: {e}"
            ))])),
        }
    }

    #[tool(
        name = "detach-client",
        description = "Detach a tmux client by tty. Use to clean up observers or free a session for layout changes; avoid detaching active users unexpectedly.",
        annotations(destructive_hint = true)
    )]
    async fn detach_client(
        &self,
        input: Parameters<DetachClientInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("detach-client") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::detach_client(&input.0.client_tty, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Client {} detached",
                input.0.client_tty
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error detaching client: {e}"
            ))])),
        }
    }

    // Dedicated terminal interaction tools
    #[tool(
        name = "send-keys",
        description = "Send keystrokes to a pane. Use only for interactive programs (vim/htop/ssh/REPLs); for commands prefer execute-command + get-command-result instead of send-keys+send-enter+capture-pane. Pair with capture-pane in a read-act loop. Use literal=true for exact text, delayMs for slow terminals.",
        annotations(open_world_hint = true)
    )]
    async fn send_keys(
        &self,
        input: Parameters<SendKeysInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("send-keys") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(&input.0.pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let literal = input.0.literal.unwrap_or(false);
        if !literal {
            if let Err(e) = self.policy.check_command(&input.0.keys) {
                return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
            }
        }
        let repeat_count = input.0.repeat.unwrap_or(1).max(1);
        for _ in 0..repeat_count {
            if let Some(delay) = input.0.delay_ms {
                if literal {
                    // Literal mode: send each character individually with delay
                    for ch in input.0.keys.chars() {
                        if let Err(e) = tmux::send_keys(
                            &input.0.pane_id,
                            &ch.to_string(),
                            true,
                            socket.as_deref(),
                        )
                        .await
                        {
                            return Ok(CallToolResult::error(vec![Content::text(format!(
                                "Error sending keys: {e}"
                            ))]));
                        }
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                } else {
                    // Non-literal: send the whole key sequence, then delay
                    // (delay is between repeats, not between characters)
                    if let Err(e) =
                        tmux::send_keys(&input.0.pane_id, &input.0.keys, false, socket.as_deref())
                            .await
                    {
                        return Ok(CallToolResult::error(vec![Content::text(format!(
                            "Error sending keys: {e}"
                        ))]));
                    }
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
            } else if let Err(e) =
                tmux::send_keys(&input.0.pane_id, &input.0.keys, literal, socket.as_deref()).await
            {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error sending keys: {e}"
                ))]));
            }
        }
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Keys sent to pane {}",
            input.0.pane_id
        ))]))
    }

    #[tool(
        name = "send-cancel",
        description = "Send Ctrl+C to interrupt the current process in a pane. Use to stop a stuck command or to abort a prompt during interactive workflows.",
        annotations(open_world_hint = true)
    )]
    async fn send_cancel(
        &self,
        input: Parameters<PaneIdInput>,
    ) -> Result<CallToolResult, McpError> {
        self.send_special_key(
            &input.0.pane_id,
            "C-c",
            "send-cancel",
            input.0.socket.as_deref(),
        )
        .await
    }

    #[tool(
        name = "send-eof",
        description = "Send Ctrl+D (EOF) to a pane. Use to end input streams or exit a shell when a prompt is waiting for EOF.",
        annotations(open_world_hint = true)
    )]
    async fn send_eof(&self, input: Parameters<PaneIdInput>) -> Result<CallToolResult, McpError> {
        self.send_special_key(
            &input.0.pane_id,
            "C-d",
            "send-eof",
            input.0.socket.as_deref(),
        )
        .await
    }

    #[tool(
        name = "send-escape",
        description = "Send Escape key to a pane. Use to exit insert mode, cancel dialogs, or return to normal mode when driving TUIs.",
        annotations(open_world_hint = true)
    )]
    async fn send_escape(
        &self,
        input: Parameters<PaneIdInput>,
    ) -> Result<CallToolResult, McpError> {
        self.send_special_key(
            &input.0.pane_id,
            "Escape",
            "send-escape",
            input.0.socket.as_deref(),
        )
        .await
    }

    #[tool(
        name = "send-enter",
        description = "Send Enter key to a pane. Use to confirm prompts after send-keys in interactive flows; for commands prefer execute-command.",
        annotations(open_world_hint = true)
    )]
    async fn send_enter(&self, input: Parameters<PaneIdInput>) -> Result<CallToolResult, McpError> {
        self.send_special_key(
            &input.0.pane_id,
            "Enter",
            "send-enter",
            input.0.socket.as_deref(),
        )
        .await
    }

    #[tool(
        name = "send-tab",
        description = "Send Tab key to a pane. Use for shell completion or field navigation when automating prompts or TUIs.",
        annotations(open_world_hint = true)
    )]
    async fn send_tab(&self, input: Parameters<PaneIdInput>) -> Result<CallToolResult, McpError> {
        self.send_special_key(
            &input.0.pane_id,
            "Tab",
            "send-tab",
            input.0.socket.as_deref(),
        )
        .await
    }

    #[tool(
        name = "send-backspace",
        description = "Send Backspace key to a pane. Use to correct input while driving prompts or text-based editors.",
        annotations(open_world_hint = true)
    )]
    async fn send_backspace(
        &self,
        input: Parameters<PaneIdInput>,
    ) -> Result<CallToolResult, McpError> {
        self.send_special_key(
            &input.0.pane_id,
            "BSpace",
            "send-backspace",
            input.0.socket.as_deref(),
        )
        .await
    }

    #[tool(
        name = "send-up",
        description = "Send Up arrow to a pane. Use for shell history recall or menu navigation in interactive programs.",
        annotations(open_world_hint = true)
    )]
    async fn send_up(&self, input: Parameters<PaneIdInput>) -> Result<CallToolResult, McpError> {
        self.send_special_key(&input.0.pane_id, "Up", "send-up", input.0.socket.as_deref())
            .await
    }

    #[tool(
        name = "send-down",
        description = "Send Down arrow to a pane. Use for shell history navigation or menu movement in interactive programs.",
        annotations(open_world_hint = true)
    )]
    async fn send_down(&self, input: Parameters<PaneIdInput>) -> Result<CallToolResult, McpError> {
        self.send_special_key(
            &input.0.pane_id,
            "Down",
            "send-down",
            input.0.socket.as_deref(),
        )
        .await
    }

    #[tool(
        name = "send-left",
        description = "Send Left arrow to a pane. Use for cursor movement while editing input in shells or TUIs.",
        annotations(open_world_hint = true)
    )]
    async fn send_left(&self, input: Parameters<PaneIdInput>) -> Result<CallToolResult, McpError> {
        self.send_special_key(
            &input.0.pane_id,
            "Left",
            "send-left",
            input.0.socket.as_deref(),
        )
        .await
    }

    #[tool(
        name = "send-right",
        description = "Send Right arrow to a pane. Use for cursor movement while editing input in shells or TUIs.",
        annotations(open_world_hint = true)
    )]
    async fn send_right(&self, input: Parameters<PaneIdInput>) -> Result<CallToolResult, McpError> {
        self.send_special_key(
            &input.0.pane_id,
            "Right",
            "send-right",
            input.0.socket.as_deref(),
        )
        .await
    }

    #[tool(
        name = "send-page-up",
        description = "Send Page Up to a pane. Use to scroll in pagers or log views when inspecting earlier output.",
        annotations(open_world_hint = true)
    )]
    async fn send_page_up(
        &self,
        input: Parameters<PaneIdInput>,
    ) -> Result<CallToolResult, McpError> {
        self.send_special_key(
            &input.0.pane_id,
            "PPage",
            "send-page-up",
            input.0.socket.as_deref(),
        )
        .await
    }

    #[tool(
        name = "send-page-down",
        description = "Send Page Down to a pane. Use to scroll through pagers or long outputs during inspection.",
        annotations(open_world_hint = true)
    )]
    async fn send_page_down(
        &self,
        input: Parameters<PaneIdInput>,
    ) -> Result<CallToolResult, McpError> {
        self.send_special_key(
            &input.0.pane_id,
            "NPage",
            "send-page-down",
            input.0.socket.as_deref(),
        )
        .await
    }

    #[tool(
        name = "send-home",
        description = "Send Home key to a pane. Use to jump to start of line or top of a view while driving interactive apps.",
        annotations(open_world_hint = true)
    )]
    async fn send_home(&self, input: Parameters<PaneIdInput>) -> Result<CallToolResult, McpError> {
        self.send_special_key(
            &input.0.pane_id,
            "Home",
            "send-home",
            input.0.socket.as_deref(),
        )
        .await
    }

    #[tool(
        name = "send-end",
        description = "Send End key to a pane. Use to jump to end of line or bottom of a view while driving interactive apps.",
        annotations(open_world_hint = true)
    )]
    async fn send_end(&self, input: Parameters<PaneIdInput>) -> Result<CallToolResult, McpError> {
        self.send_special_key(
            &input.0.pane_id,
            "End",
            "send-end",
            input.0.socket.as_deref(),
        )
        .await
    }
}

impl TmuxMcpServer {
    async fn send_special_key(
        &self,
        pane_id: &str,
        key: &str,
        tool_name: &str,
        socket: Option<&str>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool(tool_name) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(socket);
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::send_keys(pane_id, key, false, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "{key} sent to pane {pane_id}"
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error sending {key}: {e}"
            ))])),
        }
    }
}

// ============================================================================
// ServerHandler Implementation
// ============================================================================

#[rmcp::tool_handler]
impl rmcp::ServerHandler for TmuxMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Tmux MCP server for managing tmux sessions, windows, and panes. Prefer per-agent isolated sockets (set TMUX_MCP_SOCKET/--socket to a unique id, e.g. harness session id). Each tool accepts an optional socket override; omit it to use this server's default socket. Resources reflect the default socket only.".into(),
            ),
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
            ..Default::default()
        }
    }

    async fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ListResourcesResult, McpError> {
        let mut resources: Vec<Resource> = Vec::new();

        resources.push(Annotated::new(
            RawResource {
                uri: "tmux://server/info".into(),
                name: "Tmux Server Info".into(),
                title: None,
                description: Some(
                    "Default socket and SSH context for routing tool calls without env vars."
                        .into(),
                ),
                mime_type: Some("application/json".into()),
                size: None,
                icons: None,
                meta: None,
            },
            None,
        ));

        if self.policy.check_tool("list-sessions").is_err() {
            return Ok(rmcp::model::ListResourcesResult {
                resources,
                next_cursor: None,
                meta: None,
            });
        }
        let socket = tmux::resolve_socket(None);
        if let Err(_e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(rmcp::model::ListResourcesResult {
                resources,
                next_cursor: None,
                meta: None,
            });
        }

        // Add pane, window, and session resources dynamically
        let mut has_pane_resources = false;
        if let Ok(sessions) = tmux::list_sessions(socket.as_deref()).await {
            for session in sessions {
                // Skip sessions not allowed by policy
                if self.policy.check_session(&session.id).is_err() {
                    continue;
                }
                let mut session_has_allowed_panes = false;
                if let Ok(windows) = tmux::list_windows(&session.id, socket.as_deref()).await {
                    for window in windows {
                        let mut window_has_allowed_panes = false;
                        if let Ok(panes) = tmux::list_panes(&window.id, socket.as_deref()).await {
                            for pane in panes {
                                // Skip panes not allowed by policy
                                if self.policy.check_pane(&pane.id).is_err() {
                                    continue;
                                }
                                has_pane_resources = true;
                                window_has_allowed_panes = true;
                                session_has_allowed_panes = true;
                                resources.push(Annotated::new(
                                    RawResource {
                                        uri: format!("tmux://pane/{}", pane.id),
                                        name: format!(
                                            "Pane: {} - {} - {}",
                                            session.name, pane.id, pane.title
                                        ),
                                        title: None,
                                        description: Some(format!(
                                            "Pane output for state checks or log monitoring in session {} (pane {}).",
                                            session.name, pane.id
                                        )),
                                        mime_type: Some("text/plain".into()),
                                        size: None,
                                        icons: None,
                                        meta: None,
                                    },
                                    None,
                                ));
                                resources.push(Annotated::new(
                                    RawResource {
                                        uri: format!("tmux://pane/{}/info", pane.id),
                                        name: format!(
                                            "Pane Info: {} - {} - {}",
                                            session.name, pane.id, pane.title
                                        ),
                                        title: None,
                                        description: Some(format!(
                                            "Pane metadata (cwd, command, size) to pick execution targets or layout changes in session {} (pane {}).",
                                            session.name, pane.id
                                        )),
                                        mime_type: Some("application/json".into()),
                                        size: None,
                                        icons: None,
                                        meta: None,
                                    },
                                    None,
                                ));
                            }
                        }
                        if window_has_allowed_panes {
                            resources.push(Annotated::new(
                                RawResource {
                                    uri: format!("tmux://window/{}/info", window.id),
                                    name: format!("Window Info: {} - {}", session.name, window.name),
                                    title: None,
                                    description: Some(format!(
                                        "Window metadata (layout, active pane, size) to decide focus or normalize layout in session {} (window {}).",
                                        session.name, window.name
                                    )),
                                    mime_type: Some("application/json".into()),
                                    size: None,
                                    icons: None,
                                    meta: None,
                                },
                                None,
                            ));
                        }
                    }
                }
                if session_has_allowed_panes {
                    resources.push(Annotated::new(
                        RawResource {
                            uri: format!("tmux://session/{}/tree", session.id),
                            name: format!("Session Tree: {}", session.name),
                            title: None,
                            description: Some(format!(
                                "Session snapshot to plan multi-pane workflows and choose targets in {}.",
                                session.name
                            )),
                            mime_type: Some("application/json".into()),
                            size: None,
                            icons: None,
                            meta: None,
                        },
                        None,
                    ));
                }
            }
        }

        if has_pane_resources && self.policy.check_tool("list-clients").is_ok() {
            resources.push(Annotated::new(
                RawResource {
                    uri: "tmux://clients".into(),
                    name: "Tmux Clients".into(),
                    title: None,
                    description: Some(
                        "Clients list to detect observers before detaching or resizing.".into(),
                    ),
                    mime_type: Some("application/json".into()),
                    size: None,
                    icons: None,
                    meta: None,
                },
                None,
            ));
        }

        // Add command result resources
        if self.policy.check_tool("get-command-result").is_ok() {
            for id in self.tracker.get_active_ids().await {
                if let Some(cmd) = self.tracker.get_command(&id).await {
                    // Skip commands for panes not allowed by policy
                    if self.policy.check_pane(&cmd.pane_id).is_err() {
                        continue;
                    }
                    let truncated_cmd = if cmd.command.len() > 30 {
                        format!("{}...", &cmd.command[..30])
                    } else {
                        cmd.command.clone()
                    };
                    resources.push(Annotated::new(
                        RawResource {
                            uri: format!("tmux://command/{}/result", id),
                            name: format!("Command: {}", truncated_cmd),
                            title: None,
                            description: Some(format!(
                                "Tracked command status: {:?}. Poll to avoid re-running.",
                                cmd.status
                            )),
                            mime_type: Some("text/plain".into()),
                            size: None,
                            icons: None,
                            meta: None,
                        },
                        None,
                    ));
                }
            }
        }

        Ok(rmcp::model::ListResourcesResult {
            resources,
            next_cursor: None,
            meta: None,
        })
    }

    async fn list_resource_templates(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ListResourceTemplatesResult, McpError> {
        Ok(rmcp::model::ListResourceTemplatesResult {
            resource_templates: vec![
                Annotated::new(
                    RawResourceTemplate {
                        uri_template: "tmux://server/info".into(),
                        name: "Tmux Server Info".into(),
                        title: None,
                        description: Some(
                            "Default socket and SSH context for selecting the right tmux target."
                                .into(),
                        ),
                        mime_type: Some("application/json".into()),
                        icons: None,
                    },
                    None,
                ),
                Annotated::new(
                    RawResourceTemplate {
                        uri_template: "tmux://pane/{paneId}".into(),
                        name: "Tmux Pane Content".into(),
                        title: None,
                        description: Some("Capture pane content for state checks or log monitoring; use when polling output without sending input.".into()),
                        mime_type: Some("text/plain".into()),
                        icons: None,
                    },
                    None,
                ),
                Annotated::new(
                    RawResourceTemplate {
                        uri_template: "tmux://pane/{paneId}/info".into(),
                        name: "Tmux Pane Info".into(),
                        title: None,
                        description: Some("Detailed metadata for a pane (cwd, command, size). Use to decide where to run commands or how to resize/layout.".into()),
                        mime_type: Some("application/json".into()),
                        icons: None,
                    },
                    None,
                ),
                Annotated::new(
                    RawResourceTemplate {
                        uri_template: "tmux://pane/{paneId}/tail/{lines}".into(),
                        name: "Tmux Pane Tail".into(),
                        title: None,
                        description: Some("Tail N lines from a pane for lightweight log polling without full scrollback.".into()),
                        mime_type: Some("text/plain".into()),
                        icons: None,
                    },
                    None,
                ),
                Annotated::new(
                    RawResourceTemplate {
                        uri_template: "tmux://pane/{paneId}/tail/{lines}/ansi".into(),
                        name: "Tmux Pane Tail (ANSI)".into(),
                        title: None,
                        description: Some("Tail N lines with ANSI colors when formatting or highlighting matters.".into()),
                        mime_type: Some("text/plain".into()),
                        icons: None,
                    },
                    None,
                ),
                Annotated::new(
                    RawResourceTemplate {
                        uri_template: "tmux://window/{windowId}/info".into(),
                        name: "Tmux Window Info".into(),
                        title: None,
                        description: Some("Window metadata (layout, active pane, size). Use to normalize layouts or decide where to focus.".into()),
                        mime_type: Some("application/json".into()),
                        icons: None,
                    },
                    None,
                ),
                Annotated::new(
                    RawResourceTemplate {
                        uri_template: "tmux://session/{sessionId}/tree".into(),
                        name: "Tmux Session Tree".into(),
                        title: None,
                        description: Some("Snapshot of session, windows, and panes for planning multi-pane workflows.".into()),
                        mime_type: Some("application/json".into()),
                        icons: None,
                    },
                    None,
                ),
                Annotated::new(
                    RawResourceTemplate {
                        uri_template: "tmux://clients".into(),
                        name: "Tmux Clients".into(),
                        title: None,
                        description: Some("List of tmux clients to detect observers before detaching or resizing.".into()),
                        mime_type: Some("application/json".into()),
                        icons: None,
                    },
                    None,
                ),
                Annotated::new(
                    RawResourceTemplate {
                        uri_template: "tmux://command/{commandId}/result".into(),
                        name: "Command Execution Result".into(),
                        title: None,
                        description: Some("Get the result of an executed command; use for polling without re-running.".into()),
                        mime_type: Some("text/plain".into()),
                        icons: None,
                    },
                    None,
                ),
            ],
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ReadResourceResult, McpError> {
        let uri = request.uri.as_str();

        if uri == "tmux://server/info" {
            let info = serde_json::json!({
                "default_socket": tmux::resolve_socket(None),
                "ssh": std::env::var("TMUX_MCP_SSH").ok().filter(|value| !value.is_empty()),
            });
            Ok(rmcp::model::ReadResourceResult {
                contents: vec![ResourceContents::text(
                    serde_json::to_string_pretty(&info).unwrap_or_default(),
                    uri,
                )],
            })
        } else if let Some(rest) = uri.strip_prefix("tmux://pane/") {
            let socket = tmux::resolve_socket(None);
            if let Err(e) = self.policy.check_socket(socket.as_deref()) {
                return Ok(rmcp::model::ReadResourceResult {
                    contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                });
            }
            let parts: Vec<&str> = rest.split('/').collect();
            let pane_id = parts.first().copied().unwrap_or_default();
            if pane_id.is_empty() {
                return Ok(rmcp::model::ReadResourceResult {
                    contents: vec![ResourceContents::text("Invalid pane resource URI", uri)],
                });
            }
            if let Err(e) = self.policy.check_tool("capture-pane") {
                return Ok(rmcp::model::ReadResourceResult {
                    contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                });
            }
            if let Err(e) = self.policy.check_pane(pane_id) {
                return Ok(rmcp::model::ReadResourceResult {
                    contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                });
            }
            match parts.as_slice() {
                [pane_id] => match tmux::capture_pane(
                    pane_id,
                    Some(200),
                    false,
                    None,
                    None,
                    false,
                    socket.as_deref(),
                )
                .await
                {
                    Ok(content) => Ok(rmcp::model::ReadResourceResult {
                        contents: vec![ResourceContents::text(content, uri)],
                    }),
                    Err(e) => Ok(rmcp::model::ReadResourceResult {
                        contents: vec![ResourceContents::text(format!("Error: {e}"), uri)],
                    }),
                },
                [pane_id, "info"] => match tmux::pane_info(pane_id, socket.as_deref()).await {
                    Ok(info) => Ok(rmcp::model::ReadResourceResult {
                        contents: vec![ResourceContents::text(
                            serde_json::to_string_pretty(&info).unwrap_or_default(),
                            uri,
                        )],
                    }),
                    Err(e) => Ok(rmcp::model::ReadResourceResult {
                        contents: vec![ResourceContents::text(format!("Error: {e}"), uri)],
                    }),
                },
                [pane_id, "tail", lines] => {
                    let parsed = lines.parse::<u32>();
                    if let Ok(lines_val) = parsed {
                        match tmux::capture_pane(
                            pane_id,
                            Some(lines_val),
                            false,
                            None,
                            None,
                            false,
                            socket.as_deref(),
                        )
                        .await
                        {
                            Ok(content) => Ok(rmcp::model::ReadResourceResult {
                                contents: vec![ResourceContents::text(content, uri)],
                            }),
                            Err(e) => Ok(rmcp::model::ReadResourceResult {
                                contents: vec![ResourceContents::text(format!("Error: {e}"), uri)],
                            }),
                        }
                    } else {
                        Ok(rmcp::model::ReadResourceResult {
                            contents: vec![ResourceContents::text(
                                "Invalid pane tail resource URI",
                                uri,
                            )],
                        })
                    }
                }
                [pane_id, "tail", lines, "ansi"] => {
                    let parsed = lines.parse::<u32>();
                    if let Ok(lines_val) = parsed {
                        match tmux::capture_pane(
                            pane_id,
                            Some(lines_val),
                            true,
                            None,
                            None,
                            false,
                            socket.as_deref(),
                        )
                        .await
                        {
                            Ok(content) => Ok(rmcp::model::ReadResourceResult {
                                contents: vec![ResourceContents::text(content, uri)],
                            }),
                            Err(e) => Ok(rmcp::model::ReadResourceResult {
                                contents: vec![ResourceContents::text(format!("Error: {e}"), uri)],
                            }),
                        }
                    } else {
                        Ok(rmcp::model::ReadResourceResult {
                            contents: vec![ResourceContents::text(
                                "Invalid pane tail resource URI",
                                uri,
                            )],
                        })
                    }
                }
                _ => Ok(rmcp::model::ReadResourceResult {
                    contents: vec![ResourceContents::text("Invalid pane resource URI", uri)],
                }),
            }
        } else if let Some(rest) = uri.strip_prefix("tmux://window/") {
            if let Some(window_id) = rest.strip_suffix("/info") {
                let socket = tmux::resolve_socket(None);
                if let Err(e) = self.policy.check_socket(socket.as_deref()) {
                    return Ok(rmcp::model::ReadResourceResult {
                        contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                    });
                }
                if let Err(e) = self.policy.check_tool("list-windows") {
                    return Ok(rmcp::model::ReadResourceResult {
                        contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                    });
                }
                match tmux::window_info(window_id, socket.as_deref()).await {
                    Ok(info) => Ok(rmcp::model::ReadResourceResult {
                        contents: vec![ResourceContents::text(
                            serde_json::to_string_pretty(&info).unwrap_or_default(),
                            uri,
                        )],
                    }),
                    Err(e) => Ok(rmcp::model::ReadResourceResult {
                        contents: vec![ResourceContents::text(format!("Error: {e}"), uri)],
                    }),
                }
            } else {
                Ok(rmcp::model::ReadResourceResult {
                    contents: vec![ResourceContents::text("Invalid window resource URI", uri)],
                })
            }
        } else if let Some(rest) = uri.strip_prefix("tmux://session/") {
            if let Some(session_id) = rest.strip_suffix("/tree") {
                let socket = tmux::resolve_socket(None);
                if let Err(e) = self.policy.check_socket(socket.as_deref()) {
                    return Ok(rmcp::model::ReadResourceResult {
                        contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                    });
                }
                if let Err(e) = self.policy.check_tool("list-sessions") {
                    return Ok(rmcp::model::ReadResourceResult {
                        contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                    });
                }
                if let Err(e) = self.policy.check_session(session_id) {
                    return Ok(rmcp::model::ReadResourceResult {
                        contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                    });
                }
                match tmux::list_sessions(socket.as_deref()).await {
                    Ok(sessions) => {
                        let session = sessions.into_iter().find(|s| s.id == session_id);
                        if let Some(session) = session {
                            let mut windows_tree = Vec::new();
                            if let Ok(windows) =
                                tmux::list_windows(&session.id, socket.as_deref()).await
                            {
                                for window in windows {
                                    let panes = tmux::list_panes(&window.id, socket.as_deref())
                                        .await
                                        .unwrap_or_default()
                                        .into_iter()
                                        .filter(|pane| self.policy.check_pane(&pane.id).is_ok())
                                        .collect();
                                    windows_tree.push(crate::types::WindowTree { window, panes });
                                }
                            }
                            let tree = crate::types::SessionTree {
                                session,
                                windows: windows_tree,
                            };
                            Ok(rmcp::model::ReadResourceResult {
                                contents: vec![ResourceContents::text(
                                    serde_json::to_string_pretty(&tree).unwrap_or_default(),
                                    uri,
                                )],
                            })
                        } else {
                            Ok(rmcp::model::ReadResourceResult {
                                contents: vec![ResourceContents::text(
                                    format!("Session not found: {session_id}"),
                                    uri,
                                )],
                            })
                        }
                    }
                    Err(e) => Ok(rmcp::model::ReadResourceResult {
                        contents: vec![ResourceContents::text(format!("Error: {e}"), uri)],
                    }),
                }
            } else {
                Ok(rmcp::model::ReadResourceResult {
                    contents: vec![ResourceContents::text("Invalid session resource URI", uri)],
                })
            }
        } else if uri == "tmux://clients" {
            let socket = tmux::resolve_socket(None);
            if let Err(e) = self.policy.check_socket(socket.as_deref()) {
                return Ok(rmcp::model::ReadResourceResult {
                    contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                });
            }
            if let Err(e) = self.policy.check_tool("list-clients") {
                return Ok(rmcp::model::ReadResourceResult {
                    contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                });
            }
            match tmux::list_clients(socket.as_deref()).await {
                Ok(clients) => Ok(rmcp::model::ReadResourceResult {
                    contents: vec![ResourceContents::text(
                        serde_json::to_string_pretty(&clients).unwrap_or_default(),
                        uri,
                    )],
                }),
                Err(e) => Ok(rmcp::model::ReadResourceResult {
                    contents: vec![ResourceContents::text(format!("Error: {e}"), uri)],
                }),
            }
        } else if let Some(rest) = uri.strip_prefix("tmux://command/") {
            if let Some(command_id) = rest.strip_suffix("/result") {
                if let Err(e) = self.policy.check_tool("get-command-result") {
                    return Ok(rmcp::model::ReadResourceResult {
                        contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                    });
                }
                if let Some(cmd) = self.tracker.get_command(command_id).await {
                    if let Err(e) = self.policy.check_pane(&cmd.pane_id) {
                        return Ok(rmcp::model::ReadResourceResult {
                            contents: vec![ResourceContents::text(
                                format!("Access denied: {e}"),
                                uri,
                            )],
                        });
                    }
                } else {
                    return Ok(rmcp::model::ReadResourceResult {
                        contents: vec![ResourceContents::text(
                            format!("Command not found: {command_id}"),
                            uri,
                        )],
                    });
                }
                match self.tracker.check_status(command_id, None).await {
                    Ok(Some(cmd)) => {
                        let result = GetCommandResultOutput {
                            status: format!("{:?}", cmd.status).to_lowercase(),
                            exit_code: cmd.exit_code,
                            command: cmd.command.clone(),
                            output: if matches!(
                                cmd.status,
                                CommandStatus::Completed | CommandStatus::Error
                            ) {
                                cmd.output.clone()
                            } else {
                                None
                            },
                        };
                        Ok(rmcp::model::ReadResourceResult {
                            contents: vec![ResourceContents::text(
                                serde_json::to_string_pretty(&result).unwrap_or_default(),
                                uri,
                            )],
                        })
                    }
                    Ok(None) => Ok(rmcp::model::ReadResourceResult {
                        contents: vec![ResourceContents::text(
                            format!("Command not found: {command_id}"),
                            uri,
                        )],
                    }),
                    Err(e) => Ok(rmcp::model::ReadResourceResult {
                        contents: vec![ResourceContents::text(format!("Error: {e}"), uri)],
                    }),
                }
            } else {
                Ok(rmcp::model::ReadResourceResult {
                    contents: vec![ResourceContents::text("Invalid command resource URI", uri)],
                })
            }
        } else {
            Ok(rmcp::model::ReadResourceResult {
                contents: vec![ResourceContents::text("Unknown resource", uri)],
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TmuxStub;
    use crate::types::ShellType;
    use crate::types::{Pane, Session, Window};
    use rmcp::model::{NumberOrString, ReadResourceRequestParams, ResourceContents};
    use rmcp::service::{self, RequestContext, RoleServer};
    use rmcp::ServerHandler;
    use serde_json::Value;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tokio::io::duplex;

    fn policy_from_toml(contents: &str) -> SecurityPolicy {
        let mut file = NamedTempFile::new().expect("create temp config");
        file.write_all(contents.as_bytes()).expect("write config");
        SecurityPolicy::load(file.path()).expect("load policy")
    }

    fn server_with_policy(contents: &str) -> TmuxMcpServer {
        let policy = policy_from_toml(contents);
        let tracker = CommandTracker::new(ShellType::Bash);
        TmuxMcpServer::new(tracker, policy)
    }

    fn server_default() -> TmuxMcpServer {
        TmuxMcpServer::new(
            CommandTracker::new(ShellType::Bash),
            SecurityPolicy::default(),
        )
    }

    fn first_text(result: &CallToolResult) -> String {
        result
            .content
            .first()
            .and_then(|content| content.raw.as_text())
            .map(|text| text.text.clone())
            .unwrap_or_default()
    }

    fn first_text_resource(contents: &[ResourceContents]) -> &str {
        for content in contents {
            if let ResourceContents::TextResourceContents { text, .. } = content {
                return text;
            }
        }
        ""
    }

    fn context_for_server(
        server: &TmuxMcpServer,
    ) -> (
        RequestContext<RoleServer>,
        tokio::io::DuplexStream,
        service::RunningService<RoleServer, TmuxMcpServer>,
    ) {
        let (server_transport, client_transport) = duplex(1024);
        let running = service::serve_directly(server.clone(), server_transport, None);
        let context = RequestContext {
            peer: running.peer().clone(),
            ct: Default::default(),
            id: NumberOrString::Number(1),
            meta: Default::default(),
            extensions: Default::default(),
        };
        (context, client_transport, running)
    }

    #[tokio::test]
    async fn list_sessions_denied_by_policy() {
        let server = server_with_policy("[security]\nallow_list = false\n");

        let result = server
            .list_sessions(Parameters(SocketInput { socket: None }))
            .await
            .expect("list sessions");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("list-sessions"));
    }

    #[tokio::test]
    async fn list_clients_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();

        let result = server
            .list_clients(Parameters(SocketInput { socket: None }))
            .await
            .expect("list clients");

        assert_eq!(result.is_error, Some(false));
        let payload: ListClientsOutput = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(payload.clients.len(), 1);
        assert_eq!(payload.clients[0].tty, "/dev/ttys000");
        assert_eq!(payload.clients[0].name, "client0");
        assert_eq!(payload.clients[0].session_name, "alpha");
        assert_eq!(payload.clients[0].pid, Some(123));
        assert!(payload.clients[0].attached);
    }

    #[tokio::test]
    async fn list_buffers_and_show_buffer_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();

        let result = server
            .list_buffers(Parameters(SocketInput { socket: None }))
            .await
            .expect("list buffers");

        assert_eq!(result.is_error, Some(false));
        let payload: ListBuffersOutput = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(payload.buffers.len(), 1);
        assert_eq!(payload.buffers[0].name, "buffer0");
        assert_eq!(payload.buffers[0].size, 10);
        assert_eq!(payload.buffers[0].created, Some(1700000000));

        let result = server
            .show_buffer(Parameters(ShowBufferInput {
                name: None,
                offset_bytes: None,
                max_bytes: None,
                socket: None,
            }))
            .await
            .expect("show buffer");

        assert_eq!(result.is_error, Some(false));
        assert_eq!(first_text(&result), "stub-buffer");
    }

    #[tokio::test]
    async fn save_delete_and_detach_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();

        let result = server
            .load_buffer(Parameters(LoadBufferInput {
                name: "buffer0".into(),
                path: "tests/fixtures/old-man-and-the-sea.txt".into(),
                socket: None,
            }))
            .await
            .expect("load buffer");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("loaded"));

        let result = server
            .save_buffer(Parameters(SaveBufferInput {
                name: "buffer0".into(),
                path: "/tmp/buffer.txt".into(),
                socket: None,
            }))
            .await
            .expect("save buffer");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("saved"));

        let result = server
            .delete_buffer(Parameters(DeleteBufferInput {
                name: "buffer0".into(),
                socket: None,
            }))
            .await
            .expect("delete buffer");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("deleted"));

        let result = server
            .detach_client(Parameters(DetachClientInput {
                client_tty: "/dev/ttys000".into(),
                socket: None,
            }))
            .await
            .expect("detach client");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("detached"));
    }

    #[test]
    fn subsearch_input_accepts_snake_case_and_anchor_buffer() {
        let json = r#"{
            "anchor": {"buffer": "buf0", "offset_bytes": 12, "match_len": 8},
            "context_bytes": 200,
            "query": "baseball",
            "mode": "literal"
        }"#;
        let input: SubsearchBufferInput = serde_json::from_str(json).expect("parse input");
        assert_eq!(input.buffer, None);
        assert_eq!(input.anchor.buffer.as_deref(), Some("buf0"));
        assert_eq!(input.anchor.offset_bytes, 12);
        assert_eq!(input.anchor.match_len, 8);
        assert_eq!(input.context_bytes, 200);
    }

    #[test]
    fn search_input_accepts_single_buffer_alias() {
        let json = r#"{
            "buffer": "oldman",
            "query": "the boy",
            "mode": "literal"
        }"#;
        let input: SearchBufferInput = serde_json::from_str(json).expect("parse input");
        assert_eq!(input.buffer.as_deref(), Some("oldman"));
        assert!(input.buffers.is_none());
    }

    #[tokio::test]
    async fn resize_pane_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();

        let result = server
            .resize_pane(Parameters(ResizePaneInput {
                pane_id: "%1".into(),
                direction: None,
                amount: None,
                width: Some(120),
                height: Some(40),
                socket: None,
            }))
            .await
            .expect("resize pane");

        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("resized"));
    }

    #[tokio::test]
    async fn zoom_and_layout_and_pane_moves_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();

        let result = server
            .zoom_pane(Parameters(PaneIdInput {
                pane_id: "%1".into(),
                socket: None,
            }))
            .await
            .expect("zoom pane");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("zoom toggled"));

        let result = server
            .select_layout(Parameters(SelectLayoutInput {
                window_id: "@1".into(),
                layout: "tiled".into(),
                socket: None,
            }))
            .await
            .expect("select layout");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("layout set"));

        let result = server
            .join_pane(Parameters(JoinPaneInput {
                source_pane_id: "%1".into(),
                target_pane_id: "%2".into(),
                socket: None,
            }))
            .await
            .expect("join pane");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("joined"));

        let result = server
            .swap_pane(Parameters(SwapPaneInput {
                source_pane_id: "%1".into(),
                target_pane_id: "%2".into(),
                socket: None,
            }))
            .await
            .expect("swap pane");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("swapped"));
    }

    #[tokio::test]
    async fn select_layout_tmux_error() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_ERROR_CMD", "select-layout");
        stub.set_var("TMUX_STUB_ERROR_MSG", "layout-fail");
        let server = server_default();

        let result = server
            .select_layout(Parameters(SelectLayoutInput {
                window_id: "@1".into(),
                layout: "tiled".into(),
                socket: None,
            }))
            .await
            .expect("select layout");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("layout-fail"));
    }

    #[tokio::test]
    async fn resize_pane_invalid_direction() {
        let _stub = TmuxStub::new();
        let server = server_default();

        let result = server
            .resize_pane(Parameters(ResizePaneInput {
                pane_id: "%1".into(),
                direction: Some("diagonal".into()),
                amount: Some(5),
                width: None,
                height: None,
                socket: None,
            }))
            .await
            .expect("resize pane");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("unknown resize direction"));
    }

    #[tokio::test]
    async fn break_pane_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();

        let result = server
            .break_pane(Parameters(BreakPaneInput {
                pane_id: "%1".into(),
                name: Some("breakout".into()),
                socket: None,
            }))
            .await
            .expect("break pane");

        assert_eq!(result.is_error, Some(false));
        let window: Window = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(window.id, "@9");
        assert_eq!(window.name, "broken");
        assert_eq!(window.session_id, "%1");
    }

    #[tokio::test]
    async fn capture_pane_denied_by_policy() {
        let server = server_with_policy("[security]\nallowed_panes = []\n");
        let input = Parameters(CapturePaneInput {
            pane_id: "%1".into(),
            lines: None,
            colors: None,
            start: None,
            end: None,
            join: None,
            socket: None,
        });

        let result = server.capture_pane(input).await.expect("capture pane");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("allowed panes"));
    }

    #[tokio::test]
    async fn execute_command_raw_mode_denied() {
        let server = server_with_policy("[security]\nallow_raw_mode = false\n");
        let input = Parameters(ExecuteCommandInput {
            pane_id: "%1".into(),
            command: "echo hi".into(),
            raw_mode: Some(true),
            no_enter: None,
            delay_ms: None,
            socket: None,
        });

        let result = server
            .execute_command(input)
            .await
            .expect("execute command");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("raw mode"));
    }

    #[tokio::test]
    async fn send_keys_denied_by_policy() {
        let server = server_with_policy("[security]\nallow_send_keys = false\n");
        let input = Parameters(SendKeysInput {
            pane_id: "%1".into(),
            keys: "hello".into(),
            literal: None,
            repeat: None,
            delay_ms: None,
            socket: None,
        });

        let result = server.send_keys(input).await.expect("send keys");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("send-keys"));
    }

    #[tokio::test]
    async fn send_cancel_denied_by_policy() {
        let server = server_with_policy("[security]\nallow_send_keys = false\n");
        let input = Parameters(PaneIdInput {
            pane_id: "%1".into(),
            socket: None,
        });

        let result = server.send_cancel(input).await.expect("send cancel");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("send-cancel"));
    }

    #[tokio::test]
    async fn get_command_result_missing() {
        let server = server_default();
        let input = Parameters(GetCommandResultInput {
            command_id: "missing-command".into(),
            socket: None,
        });

        let result = server
            .get_command_result(input)
            .await
            .expect("get command result");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Command not found"));
    }

    #[tokio::test]
    async fn get_info_exposes_tools_and_resources() {
        let server = server_default();
        let info = server.get_info();

        assert!(info.capabilities.tools.is_some());
        assert!(info.capabilities.resources.is_some());
    }

    #[tokio::test]
    async fn socket_for_path_normalizes_and_hashes() {
        let server = server_default();
        let result = server
            .socket_for_path(Parameters(SocketForPathInput {
                path: "/Users/example/project/".into(),
            }))
            .await
            .expect("socket-for-path");
        assert_eq!(result.is_error, Some(false));
        let first = first_text(&result).to_string();
        assert!(first.starts_with("/tmp/"));
        assert!(first.ends_with(".sock"));

        let result = server
            .socket_for_path(Parameters(SocketForPathInput {
                path: "/Users/example/project".into(),
            }))
            .await
            .expect("socket-for-path");
        let second = first_text(&result).to_string();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn socket_for_path_requires_path() {
        let server = server_default();
        let result = server
            .socket_for_path(Parameters(SocketForPathInput { path: "  ".into() }))
            .await
            .expect("socket-for-path");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("path is required"));
    }

    #[tokio::test]
    async fn list_resource_templates_returns_defaults() {
        let server = server_default();
        let (context, _client_transport, _running) = context_for_server(&server);

        let result = server
            .list_resource_templates(None, context)
            .await
            .expect("list resource templates");

        assert_eq!(result.resource_templates.len(), 9);
    }

    #[test]
    fn first_text_resource_handles_non_text() {
        let contents = vec![ResourceContents::BlobResourceContents {
            uri: "tmux://blob".into(),
            mime_type: None,
            blob: "AA==".into(),
            meta: None,
        }];

        assert_eq!(first_text_resource(&contents), "");
    }

    #[tokio::test]
    async fn list_tools_denied_by_policy() {
        let server = server_with_policy("[security]\nallow_list = false\n");

        let result = server
            .find_session(Parameters(FindSessionInput {
                name: "alpha".into(),
                socket: None,
            }))
            .await
            .expect("find session");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .list_windows(Parameters(SessionIdInput {
                session_id: "%1".into(),
                socket: None,
            }))
            .await
            .expect("list windows");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .list_panes(Parameters(WindowIdInput {
                window_id: "@1".into(),
                socket: None,
            }))
            .await
            .expect("list panes");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .get_current_session(Parameters(SocketInput { socket: None }))
            .await
            .expect("get current session");
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn list_sessions_and_find_session_tmux_error() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_ERROR_CMD", "list-sessions");
        stub.set_var("TMUX_STUB_ERROR_MSG", "boom");
        let server = server_default();

        let result = server
            .list_sessions(Parameters(SocketInput { socket: None }))
            .await
            .expect("list sessions");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Error listing sessions"));

        let result = server
            .find_session(Parameters(FindSessionInput {
                name: "alpha".into(),
                socket: None,
            }))
            .await
            .expect("find session");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Error finding session"));
    }

    #[tokio::test]
    async fn list_windows_and_panes_tmux_errors() {
        let mut stub = TmuxStub::new();
        let server = server_default();

        stub.set_var("TMUX_STUB_ERROR_CMD", "list-windows");
        stub.set_var("TMUX_STUB_ERROR_MSG", "windows-fail");
        let result = server
            .list_windows(Parameters(SessionIdInput {
                session_id: "%1".into(),
                socket: None,
            }))
            .await
            .expect("list windows");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Error listing windows"));

        stub.set_var("TMUX_STUB_ERROR_CMD", "list-panes");
        stub.set_var("TMUX_STUB_ERROR_MSG", "panes-fail");
        let result = server
            .list_panes(Parameters(WindowIdInput {
                window_id: "@1".into(),
                socket: None,
            }))
            .await
            .expect("list panes");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Error listing panes"));
    }

    #[tokio::test]
    async fn session_denied_across_tools() {
        let server = server_with_policy("[security]\nallowed_sessions = []\n");

        let result = server
            .list_windows(Parameters(SessionIdInput {
                session_id: "%1".into(),
                socket: None,
            }))
            .await
            .expect("list windows");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .create_window(Parameters(CreateWindowInput {
                session_id: "%1".into(),
                name: "new-window".into(),
                socket: None,
            }))
            .await
            .expect("create window");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .kill_session(Parameters(SessionIdInput {
                session_id: "%1".into(),
                socket: None,
            }))
            .await
            .expect("kill session");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .move_window(Parameters(MoveWindowInput {
                window_id: "@1".into(),
                target_session_id: "%1".into(),
                target_index: None,
                socket: None,
            }))
            .await
            .expect("move window");
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn capture_pane_tool_denied() {
        let server = server_with_policy("[security]\nallow_capture = false\n");
        let result = server
            .capture_pane(Parameters(CapturePaneInput {
                pane_id: "%1".into(),
                lines: None,
                colors: None,
                start: None,
                end: None,
                join: None,
                socket: None,
            }))
            .await
            .expect("capture pane");
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn capture_pane_empty_output() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_CAPTURE_OUTPUT", "");
        let server = server_default();

        let result = server
            .capture_pane(Parameters(CapturePaneInput {
                pane_id: "%1".into(),
                lines: None,
                colors: None,
                start: None,
                end: None,
                join: None,
                socket: None,
            }))
            .await
            .expect("capture pane");
        assert_eq!(result.is_error, Some(false));
        assert_eq!(first_text(&result), "No content captured");
    }

    #[tokio::test]
    async fn capture_pane_tmux_error() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_ERROR_CMD", "capture-pane");
        stub.set_var("TMUX_STUB_ERROR_MSG", "capture-fail");
        let server = server_default();

        let result = server
            .capture_pane(Parameters(CapturePaneInput {
                pane_id: "%1".into(),
                lines: None,
                colors: None,
                start: None,
                end: None,
                join: None,
                socket: None,
            }))
            .await
            .expect("capture pane");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Error capturing pane"));
    }

    #[tokio::test]
    async fn create_tools_denied_by_policy() {
        let server = server_with_policy("[security]\nallow_create = false\n");

        let result = server
            .create_session(Parameters(CreateSessionInput {
                name: "new-session".into(),
                socket: None,
            }))
            .await
            .expect("create session");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .create_window(Parameters(CreateWindowInput {
                session_id: "%1".into(),
                name: "new-window".into(),
                socket: None,
            }))
            .await
            .expect("create window");
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn create_session_tmux_error() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_ERROR_CMD", "new-session");
        stub.set_var("TMUX_STUB_ERROR_MSG", "create-session-fail");
        let server = server_default();

        let result = server
            .create_session(Parameters(CreateSessionInput {
                name: "new-session".into(),
                socket: None,
            }))
            .await
            .expect("create session");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Error creating session"));
    }

    #[tokio::test]
    async fn create_window_tmux_error() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_ERROR_CMD", "new-window");
        stub.set_var("TMUX_STUB_ERROR_MSG", "create-window-fail");
        let server = server_default();

        let result = server
            .create_window(Parameters(CreateWindowInput {
                session_id: "%1".into(),
                name: "new-window".into(),
                socket: None,
            }))
            .await
            .expect("create window");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Error creating window"));
    }

    #[tokio::test]
    async fn split_pane_denied_by_policy() {
        let server = server_with_policy("[security]\nallow_split = false\n");
        let result = server
            .split_pane(Parameters(SplitPaneInput {
                pane_id: "%1".into(),
                direction: None,
                size: None,
                socket: None,
            }))
            .await
            .expect("split pane");
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn split_pane_tmux_error() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_ERROR_CMD", "split-window");
        stub.set_var("TMUX_STUB_ERROR_MSG", "split-fail");
        let server = server_default();

        let result = server
            .split_pane(Parameters(SplitPaneInput {
                pane_id: "%1".into(),
                direction: None,
                size: None,
                socket: None,
            }))
            .await
            .expect("split pane");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Error splitting pane"));
    }

    #[tokio::test]
    async fn pane_denied_across_tools() {
        let server = server_with_policy("[security]\nallowed_panes = []\n");

        let result = server
            .split_pane(Parameters(SplitPaneInput {
                pane_id: "%1".into(),
                direction: None,
                size: None,
                socket: None,
            }))
            .await
            .expect("split pane");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .kill_pane(Parameters(PaneIdInput {
                pane_id: "%1".into(),
                socket: None,
            }))
            .await
            .expect("kill pane");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .rename_pane(Parameters(RenamePaneInput {
                pane_id: "%1".into(),
                title: "title".into(),
                socket: None,
            }))
            .await
            .expect("rename pane");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .send_keys(Parameters(SendKeysInput {
                pane_id: "%1".into(),
                keys: "echo hi".into(),
                literal: None,
                repeat: None,
                delay_ms: None,
                socket: None,
            }))
            .await
            .expect("send keys");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .send_cancel(Parameters(PaneIdInput {
                pane_id: "%1".into(),
                socket: None,
            }))
            .await
            .expect("send cancel");
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn kill_tools_denied_by_policy() {
        let server = server_with_policy("[security]\nallow_kill = false\n");

        let result = server
            .kill_session(Parameters(SessionIdInput {
                session_id: "%1".into(),
                socket: None,
            }))
            .await
            .expect("kill session");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .kill_window(Parameters(WindowIdInput {
                window_id: "@1".into(),
                socket: None,
            }))
            .await
            .expect("kill window");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .kill_pane(Parameters(PaneIdInput {
                pane_id: "%1".into(),
                socket: None,
            }))
            .await
            .expect("kill pane");
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn kill_tmux_errors() {
        let mut stub = TmuxStub::new();
        let server = server_default();

        stub.set_var("TMUX_STUB_ERROR_CMD", "kill-session");
        stub.set_var("TMUX_STUB_ERROR_MSG", "kill-session-fail");
        let result = server
            .kill_session(Parameters(SessionIdInput {
                session_id: "%1".into(),
                socket: None,
            }))
            .await
            .expect("kill session");
        assert_eq!(result.is_error, Some(true));

        stub.set_var("TMUX_STUB_ERROR_CMD", "kill-window");
        stub.set_var("TMUX_STUB_ERROR_MSG", "kill-window-fail");
        let result = server
            .kill_window(Parameters(WindowIdInput {
                window_id: "@1".into(),
                socket: None,
            }))
            .await
            .expect("kill window");
        assert_eq!(result.is_error, Some(true));

        stub.set_var("TMUX_STUB_ERROR_CMD", "kill-pane");
        stub.set_var("TMUX_STUB_ERROR_MSG", "kill-pane-fail");
        let result = server
            .kill_pane(Parameters(PaneIdInput {
                pane_id: "%1".into(),
                socket: None,
            }))
            .await
            .expect("kill pane");
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn execute_command_denied_by_policy() {
        let server = server_with_policy("[security]\nallow_execute_command = false\n");

        let result = server
            .execute_command(Parameters(ExecuteCommandInput {
                pane_id: "%1".into(),
                command: "echo hi".into(),
                raw_mode: None,
                no_enter: None,
                delay_ms: None,
                socket: None,
            }))
            .await
            .expect("execute command");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .get_command_result(Parameters(GetCommandResultInput {
                command_id: "cmd".into(),
                socket: None,
            }))
            .await
            .expect("get command result");
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn execute_command_pane_denied() {
        let server = server_with_policy("[security]\nallowed_panes = []\n");

        let result = server
            .execute_command(Parameters(ExecuteCommandInput {
                pane_id: "%1".into(),
                command: "echo hi".into(),
                raw_mode: None,
                no_enter: None,
                delay_ms: None,
                socket: None,
            }))
            .await
            .expect("execute command");
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn execute_command_command_denied() {
        let server = server_with_policy(
            "[security]\ncommand_filter = { mode = \"denylist\", patterns = [\"echo\"] }\n",
        );

        let result = server
            .execute_command(Parameters(ExecuteCommandInput {
                pane_id: "%1".into(),
                command: "echo hi".into(),
                raw_mode: None,
                no_enter: None,
                delay_ms: None,
                socket: None,
            }))
            .await
            .expect("execute command");
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn execute_command_tmux_error() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_ERROR_CMD", "send-keys");
        stub.set_var("TMUX_STUB_ERROR_MSG", "send-keys-fail");
        let server = server_default();

        let result = server
            .execute_command(Parameters(ExecuteCommandInput {
                pane_id: "%1".into(),
                command: "echo hi".into(),
                raw_mode: None,
                no_enter: None,
                delay_ms: None,
                socket: None,
            }))
            .await
            .expect("execute command");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Error executing command"));
    }

    #[tokio::test]
    async fn get_command_result_tmux_error() {
        let mut stub = TmuxStub::new();
        let server = server_default();

        let result = server
            .execute_command(Parameters(ExecuteCommandInput {
                pane_id: "%1".into(),
                command: "echo hi".into(),
                raw_mode: None,
                no_enter: None,
                delay_ms: None,
                socket: None,
            }))
            .await
            .expect("execute command");
        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        let command_id = payload["commandId"].as_str().unwrap();

        stub.set_var("TMUX_STUB_ERROR_CMD", "capture-pane");
        stub.set_var("TMUX_STUB_ERROR_MSG", "capture-fail");
        let result = server
            .get_command_result(Parameters(GetCommandResultInput {
                command_id: command_id.to_string(),
                socket: None,
            }))
            .await
            .expect("get command result");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Error getting command result"));
    }

    #[tokio::test]
    async fn get_current_session_success_and_error() {
        let mut stub = TmuxStub::new();
        let server = server_default();

        let result = server
            .get_current_session(Parameters(SocketInput { socket: None }))
            .await
            .expect("get current session");
        assert_eq!(result.is_error, Some(false));
        let session: Session = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(session.name, "alpha");

        stub.set_var("TMUX_STUB_ERROR_CMD", "display-message");
        stub.set_var("TMUX_STUB_ERROR_MSG", "display-fail");
        let result = server
            .get_current_session(Parameters(SocketInput { socket: None }))
            .await
            .expect("get current session");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Error getting current session"));
    }

    #[tokio::test]
    async fn rename_tools_denied_by_policy() {
        let server = server_with_policy("[security]\nallow_rename = false\n");

        let result = server
            .rename_window(Parameters(RenameWindowInput {
                window_id: "@1".into(),
                name: "name".into(),
                socket: None,
            }))
            .await
            .expect("rename window");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .rename_pane(Parameters(RenamePaneInput {
                pane_id: "%1".into(),
                title: "title".into(),
                socket: None,
            }))
            .await
            .expect("rename pane");
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn rename_tmux_errors() {
        let mut stub = TmuxStub::new();
        let server = server_default();

        stub.set_var("TMUX_STUB_ERROR_CMD", "rename-window");
        stub.set_var("TMUX_STUB_ERROR_MSG", "rename-window-fail");
        let result = server
            .rename_window(Parameters(RenameWindowInput {
                window_id: "@1".into(),
                name: "name".into(),
                socket: None,
            }))
            .await
            .expect("rename window");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Error renaming window"));

        stub.set_var("TMUX_STUB_ERROR_CMD", "select-pane");
        stub.set_var("TMUX_STUB_ERROR_MSG", "rename-pane-fail");
        let result = server
            .rename_pane(Parameters(RenamePaneInput {
                pane_id: "%1".into(),
                title: "title".into(),
                socket: None,
            }))
            .await
            .expect("rename pane");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Error renaming pane"));
    }

    #[tokio::test]
    async fn move_window_denied_and_error() {
        let server = server_with_policy("[security]\nallow_move = false\n");
        let result = server
            .move_window(Parameters(MoveWindowInput {
                window_id: "@1".into(),
                target_session_id: "%1".into(),
                target_index: None,
                socket: None,
            }))
            .await
            .expect("move window");
        assert_eq!(result.is_error, Some(true));

        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_ERROR_CMD", "move-window");
        stub.set_var("TMUX_STUB_ERROR_MSG", "move-fail");
        let server = server_default();
        let result = server
            .move_window(Parameters(MoveWindowInput {
                window_id: "@1".into(),
                target_session_id: "%1".into(),
                target_index: None,
                socket: None,
            }))
            .await
            .expect("move window");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Error moving window"));
    }

    #[tokio::test]
    async fn send_keys_non_literal_command_denied() {
        let server = server_with_policy(
            "[security]\ncommand_filter = { mode = \"denylist\", patterns = [\"hi\"] }\n",
        );

        let result = server
            .send_keys(Parameters(SendKeysInput {
                pane_id: "%1".into(),
                keys: "hi".into(),
                literal: Some(false),
                repeat: None,
                delay_ms: None,
                socket: None,
            }))
            .await
            .expect("send keys");
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn send_keys_tmux_errors() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_ERROR_CMD", "send-keys");
        stub.set_var("TMUX_STUB_ERROR_MSG", "send-keys-fail");
        let server = server_default();

        let result = server
            .send_keys(Parameters(SendKeysInput {
                pane_id: "%1".into(),
                keys: "hi".into(),
                literal: Some(true),
                repeat: None,
                delay_ms: Some(1),
                socket: None,
            }))
            .await
            .expect("send keys");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .send_keys(Parameters(SendKeysInput {
                pane_id: "%1".into(),
                keys: "C-c".into(),
                literal: Some(false),
                repeat: None,
                delay_ms: Some(1),
                socket: None,
            }))
            .await
            .expect("send keys");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .send_keys(Parameters(SendKeysInput {
                pane_id: "%1".into(),
                keys: "ls".into(),
                literal: Some(false),
                repeat: None,
                delay_ms: None,
                socket: None,
            }))
            .await
            .expect("send keys");
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn send_special_key_tmux_error() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_ERROR_CMD", "send-keys");
        stub.set_var("TMUX_STUB_ERROR_MSG", "send-keys-fail");
        let server = server_default();

        let result = server
            .send_cancel(Parameters(PaneIdInput {
                pane_id: "%1".into(),
                socket: None,
            }))
            .await
            .expect("send cancel");
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn list_resources_policy_skips() {
        let _stub = TmuxStub::new();

        let server = server_with_policy("[security]\nallow_list = false\n");
        let (context, _client_transport, _running) = context_for_server(&server);
        let result = server
            .list_resources(None, context)
            .await
            .expect("list resources");
        assert_eq!(result.resources.len(), 1);
        assert_eq!(result.resources[0].uri, "tmux://server/info");

        let server = server_with_policy("[security]\nallowed_sessions = []\n");
        let (context, _client_transport, _running) = context_for_server(&server);
        let result = server
            .list_resources(None, context)
            .await
            .expect("list resources");
        assert_eq!(result.resources.len(), 1);
        assert_eq!(result.resources[0].uri, "tmux://server/info");

        let server = server_with_policy("[security]\nallowed_panes = []\n");
        let (context, _client_transport, _running) = context_for_server(&server);
        let result = server
            .list_resources(None, context)
            .await
            .expect("list resources");
        assert_eq!(result.resources.len(), 1);
        assert_eq!(result.resources[0].uri, "tmux://server/info");
    }

    #[tokio::test]
    async fn list_resources_denied_by_socket_policy() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_MCP_SOCKET", "/tmp/disallowed.sock");

        let server = server_with_policy("[security]\nallowed_sockets = [\"/tmp/allowed.sock\"]\n");
        let (context, _client_transport, _running) = context_for_server(&server);
        let result = server
            .list_resources(None, context)
            .await
            .expect("list resources");
        assert_eq!(result.resources.len(), 1);
        assert_eq!(result.resources[0].uri, "tmux://server/info");
    }

    #[tokio::test]
    async fn list_resources_skips_command_for_denied_pane_and_truncates() {
        let _stub = TmuxStub::new();

        let server = server_with_policy("[security]\nallowed_panes = []\n");
        server
            .tracker
            .execute_command("%1", "echo short", false, false, None, None)
            .await
            .expect("execute command");
        let (context, _client_transport, _running) = context_for_server(&server);
        let result = server
            .list_resources(None, context)
            .await
            .expect("list resources");
        assert!(!result
            .resources
            .iter()
            .any(|res| res.uri.starts_with("tmux://command/")));

        let server = server_default();
        let long_command = "echo 123456789012345678901234567890123";
        server
            .tracker
            .execute_command("%1", long_command, false, false, None, None)
            .await
            .expect("execute command");
        let (context, _client_transport, _running) = context_for_server(&server);
        let result = server
            .list_resources(None, context)
            .await
            .expect("list resources");
        let command_name = result
            .resources
            .iter()
            .find(|res| res.uri.starts_with("tmux://command/"))
            .map(|res| res.name.clone())
            .unwrap_or_default();
        assert!(command_name.contains("..."));
    }

    #[tokio::test]
    async fn read_resource_pane_error() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_ERROR_CMD", "capture-pane");
        stub.set_var("TMUX_STUB_ERROR_MSG", "capture-fail");
        let server = server_default();
        let (context, _client_transport, _running) = context_for_server(&server);
        let request = ReadResourceRequestParams {
            uri: "tmux://pane/%1".into(),
            meta: None,
        };

        let result = server
            .read_resource(request, context)
            .await
            .expect("read resource");
        let text = first_text_resource(&result.contents);
        assert!(text.contains("Error:"));
    }

    #[tokio::test]
    async fn read_resource_denied_by_socket_policy() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_MCP_SOCKET", "/tmp/disallowed.sock");
        let server = server_with_policy("[security]\nallowed_sockets = [\"/tmp/allowed.sock\"]\n");
        let (context, _client_transport, _running) = context_for_server(&server);
        let request = ReadResourceRequestParams {
            uri: "tmux://pane/%1".into(),
            meta: None,
        };

        let result = server
            .read_resource(request, context)
            .await
            .expect("read resource");
        let text = first_text_resource(&result.contents);
        assert!(text.contains("Access denied"));
    }

    #[tokio::test]
    async fn read_resource_command_pending_and_error() {
        let mut stub = TmuxStub::new();
        let server = server_default();
        let (context, _client_transport, _running) = context_for_server(&server);
        let context2 = context.clone();
        let context3 = context.clone();

        let execute = Parameters(ExecuteCommandInput {
            pane_id: "%1".into(),
            command: "echo hi".into(),
            raw_mode: Some(true),
            no_enter: None,
            delay_ms: None,
            socket: None,
        });
        let result = server.execute_command(execute).await.unwrap();
        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        let command_id = payload["commandId"].as_str().unwrap();

        let request = ReadResourceRequestParams {
            uri: format!("tmux://command/{command_id}/result"),
            meta: None,
        };
        let result = server
            .read_resource(request, context2)
            .await
            .expect("read resource");
        let payload: Value = serde_json::from_str(first_text_resource(&result.contents)).unwrap();
        assert_eq!(payload["status"], "pending");
        assert!(payload.get("output").is_none());

        let execute = Parameters(ExecuteCommandInput {
            pane_id: "%1".into(),
            command: "echo hi".into(),
            raw_mode: None,
            no_enter: None,
            delay_ms: None,
            socket: None,
        });
        let result = server.execute_command(execute).await.unwrap();
        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        let command_id = payload["commandId"].as_str().unwrap();

        stub.set_var("TMUX_STUB_ERROR_CMD", "capture-pane");
        stub.set_var("TMUX_STUB_ERROR_MSG", "capture-fail");
        let request = ReadResourceRequestParams {
            uri: format!("tmux://command/{command_id}/result"),
            meta: None,
        };
        let result = server
            .read_resource(request, context3)
            .await
            .expect("read resource");
        let text = first_text_resource(&result.contents);
        assert!(text.contains("Error:"));
    }

    #[tokio::test]
    async fn list_sessions_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();

        let result = server
            .list_sessions(Parameters(SocketInput { socket: None }))
            .await
            .expect("list sessions");

        assert_eq!(result.is_error, Some(false));
        let payload: ListSessionsOutput = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(payload.sessions.len(), 2);
        assert_eq!(payload.sessions[0].name, "alpha");
    }

    #[tokio::test]
    async fn find_session_found() {
        let _stub = TmuxStub::new();
        let server = server_default();
        let input = Parameters(FindSessionInput {
            name: "alpha".into(),
            socket: None,
        });

        let result = server.find_session(input).await.expect("find session");

        assert_eq!(result.is_error, Some(false));
        let session: Session = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(session.name, "alpha");
    }

    #[tokio::test]
    async fn find_session_missing() {
        let _stub = TmuxStub::new();
        let server = server_default();
        let input = Parameters(FindSessionInput {
            name: "missing".into(),
            socket: None,
        });

        let result = server.find_session(input).await.expect("find session");

        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("Session not found"));
    }

    #[tokio::test]
    async fn list_windows_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();
        let input = Parameters(SessionIdInput {
            session_id: "%1".into(),
            socket: None,
        });

        let result = server.list_windows(input).await.expect("list windows");

        assert_eq!(result.is_error, Some(false));
        let payload: ListWindowsOutput = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(payload.windows.len(), 2);
        assert_eq!(payload.windows[0].name, "first");
    }

    #[tokio::test]
    async fn list_panes_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();
        let input = Parameters(WindowIdInput {
            window_id: "@1".into(),
            socket: None,
        });

        let result = server.list_panes(input).await.expect("list panes");

        assert_eq!(result.is_error, Some(false));
        let payload: ListPanesOutput = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(payload.panes.len(), 2);
        assert_eq!(payload.panes[0].title, "pane-one");
    }

    #[tokio::test]
    async fn capture_pane_happy_path_with_colors() {
        let _stub = TmuxStub::new();
        let server = server_default();
        let input = Parameters(CapturePaneInput {
            pane_id: "%1".into(),
            lines: Some(50),
            colors: Some(true),
            start: None,
            end: None,
            join: None,
            socket: None,
        });

        let result = server.capture_pane(input).await.expect("capture pane");

        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("stub-output"));
    }

    #[tokio::test]
    async fn create_session_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();
        let input = Parameters(CreateSessionInput {
            name: "new-session".into(),
            socket: None,
        });

        let result = server.create_session(input).await.expect("create session");

        assert_eq!(result.is_error, Some(false));
        let session: Session = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(session.name, "new-session");
    }

    #[tokio::test]
    async fn create_window_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();
        let input = Parameters(CreateWindowInput {
            session_id: "%1".into(),
            name: "new-window".into(),
            socket: None,
        });

        let result = server.create_window(input).await.expect("create window");

        assert_eq!(result.is_error, Some(false));
        let window: Window = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(window.name, "new-window");
    }

    #[tokio::test]
    async fn split_pane_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();
        let input = Parameters(SplitPaneInput {
            pane_id: "%1".into(),
            direction: Some("horizontal".into()),
            size: Some(50),
            socket: None,
        });

        let result = server.split_pane(input).await.expect("split pane");

        assert_eq!(result.is_error, Some(false));
        let pane: Pane = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(pane.id, "%3");
    }

    #[tokio::test]
    async fn kill_operations_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();

        let session = Parameters(SessionIdInput {
            session_id: "%1".into(),
            socket: None,
        });
        let window = Parameters(WindowIdInput {
            window_id: "@1".into(),
            socket: None,
        });
        let pane = Parameters(PaneIdInput {
            pane_id: "%1".into(),
            socket: None,
        });

        let result = server.kill_session(session).await.expect("kill session");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("has been killed"));

        let result = server.kill_window(window).await.expect("kill window");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("has been killed"));

        let result = server.kill_pane(pane).await.expect("kill pane");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("has been killed"));
    }

    #[tokio::test]
    async fn rename_and_move_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();

        let rename_window = Parameters(RenameWindowInput {
            window_id: "@1".into(),
            name: "renamed".into(),
            socket: None,
        });
        let result = server
            .rename_window(rename_window)
            .await
            .expect("rename window");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("renamed"));

        let rename_pane = Parameters(RenamePaneInput {
            pane_id: "%1".into(),
            title: "new-title".into(),
            socket: None,
        });
        let result = server.rename_pane(rename_pane).await.expect("rename pane");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("title set"));

        let move_window = Parameters(MoveWindowInput {
            window_id: "@1".into(),
            target_session_id: "%1".into(),
            target_index: Some(1),
            socket: None,
        });
        let result = server.move_window(move_window).await.expect("move window");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("moved"));
    }

    #[tokio::test]
    async fn send_keys_variants_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();

        let literal = Parameters(SendKeysInput {
            pane_id: "%1".into(),
            keys: "hi".into(),
            literal: Some(true),
            repeat: Some(2),
            delay_ms: Some(0),
            socket: None,
        });
        let result = server.send_keys(literal).await.expect("send keys");
        assert_eq!(result.is_error, Some(false));

        let delayed = Parameters(SendKeysInput {
            pane_id: "%1".into(),
            keys: "C-c".into(),
            literal: Some(false),
            repeat: Some(1),
            delay_ms: Some(0),
            socket: None,
        });
        let result = server.send_keys(delayed).await.expect("send keys");
        assert_eq!(result.is_error, Some(false));

        let immediate = Parameters(SendKeysInput {
            pane_id: "%1".into(),
            keys: "ls".into(),
            literal: Some(false),
            repeat: None,
            delay_ms: None,
            socket: None,
        });
        let result = server.send_keys(immediate).await.expect("send keys");
        assert_eq!(result.is_error, Some(false));
    }

    #[tokio::test]
    async fn send_special_keys_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();
        let pane_id = "%1".to_string();
        let pane = || {
            Parameters(PaneIdInput {
                pane_id: pane_id.clone(),
                socket: None,
            })
        };

        assert_eq!(
            server.send_cancel(pane()).await.unwrap().is_error,
            Some(false)
        );
        assert_eq!(server.send_eof(pane()).await.unwrap().is_error, Some(false));
        assert_eq!(
            server.send_escape(pane()).await.unwrap().is_error,
            Some(false)
        );
        assert_eq!(
            server.send_enter(pane()).await.unwrap().is_error,
            Some(false)
        );
        assert_eq!(server.send_tab(pane()).await.unwrap().is_error, Some(false));
        assert_eq!(
            server.send_backspace(pane()).await.unwrap().is_error,
            Some(false)
        );
        assert_eq!(server.send_up(pane()).await.unwrap().is_error, Some(false));
        assert_eq!(
            server.send_down(pane()).await.unwrap().is_error,
            Some(false)
        );
        assert_eq!(
            server.send_left(pane()).await.unwrap().is_error,
            Some(false)
        );
        assert_eq!(
            server.send_right(pane()).await.unwrap().is_error,
            Some(false)
        );
        assert_eq!(
            server.send_page_up(pane()).await.unwrap().is_error,
            Some(false)
        );
        assert_eq!(
            server.send_page_down(pane()).await.unwrap().is_error,
            Some(false)
        );
        assert_eq!(
            server.send_home(pane()).await.unwrap().is_error,
            Some(false)
        );
        assert_eq!(server.send_end(pane()).await.unwrap().is_error, Some(false));
    }

    #[tokio::test]
    async fn execute_and_get_command_result_completed() {
        let _stub = TmuxStub::new();
        let server = server_default();
        let input = Parameters(ExecuteCommandInput {
            pane_id: "%1".into(),
            command: "echo hi".into(),
            raw_mode: None,
            no_enter: None,
            delay_ms: None,
            socket: None,
        });

        let result = server
            .execute_command(input)
            .await
            .expect("execute command");
        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        let command_id = payload["commandId"].as_str().unwrap();

        let result = server
            .get_command_result(Parameters(GetCommandResultInput {
                command_id: command_id.to_string(),
                socket: None,
            }))
            .await
            .expect("get command result");

        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(payload["status"], "completed");
        assert_eq!(payload["exitCode"], 0);
        assert_eq!(payload["output"], "stub-output");
    }

    #[tokio::test]
    async fn execute_command_raw_mode_pending() {
        let _stub = TmuxStub::new();
        let server = server_default();
        let input = Parameters(ExecuteCommandInput {
            pane_id: "%1".into(),
            command: "echo hi".into(),
            raw_mode: Some(true),
            no_enter: None,
            delay_ms: None,
            socket: None,
        });

        let result = server
            .execute_command(input)
            .await
            .expect("execute command");
        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        let command_id = payload["commandId"].as_str().unwrap();

        let result = server
            .get_command_result(Parameters(GetCommandResultInput {
                command_id: command_id.to_string(),
                socket: None,
            }))
            .await
            .expect("get command result");

        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(payload["status"], "pending");
        assert!(payload.get("output").is_none());
    }

    #[tokio::test]
    async fn list_resources_includes_panes_and_commands() {
        let _stub = TmuxStub::new();
        let server = server_default();
        let (context, _client_transport, _running) = context_for_server(&server);

        let execute = Parameters(ExecuteCommandInput {
            pane_id: "%1".into(),
            command: "echo hi".into(),
            raw_mode: None,
            no_enter: None,
            delay_ms: None,
            socket: None,
        });
        let result = server.execute_command(execute).await.unwrap();
        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        let command_id = payload["commandId"].as_str().unwrap();

        let resources = server
            .list_resources(None, context)
            .await
            .expect("list resources");
        let uris: Vec<String> = resources
            .resources
            .iter()
            .map(|res| res.uri.clone())
            .collect();

        assert!(uris.iter().any(|uri| uri == "tmux://pane/%1"));
        assert!(uris
            .iter()
            .any(|uri| uri == &format!("tmux://command/{command_id}/result")));
    }

    #[tokio::test]
    async fn read_resource_pane_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();
        let (context, _client_transport, _running) = context_for_server(&server);
        let request = ReadResourceRequestParams {
            uri: "tmux://pane/%1".into(),
            meta: None,
        };

        let result = server
            .read_resource(request, context)
            .await
            .expect("read resource");
        let text = first_text_resource(&result.contents);
        assert!(text.contains("stub-output"));
    }

    #[tokio::test]
    async fn read_resource_command_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();
        let (context, _client_transport, _running) = context_for_server(&server);

        let execute = Parameters(ExecuteCommandInput {
            pane_id: "%1".into(),
            command: "echo hi".into(),
            raw_mode: None,
            no_enter: None,
            delay_ms: None,
            socket: None,
        });
        let result = server.execute_command(execute).await.unwrap();
        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        let command_id = payload["commandId"].as_str().unwrap();

        let request = ReadResourceRequestParams {
            uri: format!("tmux://command/{command_id}/result"),
            meta: None,
        };
        let result = server
            .read_resource(request, context)
            .await
            .expect("read resource");
        let text = first_text_resource(&result.contents);
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["status"], "completed");
        assert_eq!(payload["exitCode"], 0);
    }

    #[tokio::test]
    async fn read_resource_unknown_uri() {
        let server = server_default();
        let (context, _client_transport, _running) = context_for_server(&server);
        let request = ReadResourceRequestParams {
            uri: "tmux://unknown".into(),
            meta: None,
        };

        let result = server
            .read_resource(request, context)
            .await
            .expect("read resource");
        let text = first_text_resource(&result.contents);
        assert_eq!(text, "Unknown resource");
    }

    #[tokio::test]
    async fn read_resource_invalid_command_uri() {
        let server = server_default();
        let (context, _client_transport, _running) = context_for_server(&server);
        let request = ReadResourceRequestParams {
            uri: "tmux://command/abc".into(),
            meta: None,
        };

        let result = server
            .read_resource(request, context)
            .await
            .expect("read resource");
        let text = first_text_resource(&result.contents);
        assert_eq!(text, "Invalid command resource URI");
    }

    #[tokio::test]
    async fn read_resource_command_not_found() {
        let server = server_default();
        let (context, _client_transport, _running) = context_for_server(&server);
        let request = ReadResourceRequestParams {
            uri: "tmux://command/abc/result".into(),
            meta: None,
        };

        let result = server
            .read_resource(request, context)
            .await
            .expect("read resource");
        let text = first_text_resource(&result.contents);
        assert_eq!(text, "Command not found: abc");
    }

    #[tokio::test]
    async fn read_resource_pane_denied() {
        let server = server_with_policy("[security]\nallowed_panes = []\n");
        let (context, _client_transport, _running) = context_for_server(&server);
        let request = ReadResourceRequestParams {
            uri: "tmux://pane/%1".into(),
            meta: None,
        };

        let result = server
            .read_resource(request, context)
            .await
            .expect("read resource");
        let text = first_text_resource(&result.contents);
        assert!(text.contains("Access denied"));
    }

    #[tokio::test]
    async fn get_command_result_denied_for_pane() {
        let _stub = TmuxStub::new();
        let server = server_with_policy("[security]\nallowed_panes = []\n");

        let command_id = server
            .tracker
            .execute_command("%1", "echo hi", false, false, None, None)
            .await
            .expect("execute command");

        let result = server
            .get_command_result(Parameters(GetCommandResultInput {
                command_id,
                socket: None,
            }))
            .await
            .expect("get command result");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Access denied"));
    }

    #[tokio::test]
    async fn read_resource_pane_denied_by_capture_policy() {
        let _stub = TmuxStub::new();
        let server = server_with_policy("[security]\nallow_capture = false\n");
        let (context, _client_transport, _running) = context_for_server(&server);
        let request = ReadResourceRequestParams {
            uri: "tmux://pane/%1".into(),
            meta: None,
        };

        let result = server
            .read_resource(request, context)
            .await
            .expect("read resource");
        let text = first_text_resource(&result.contents);
        assert!(text.contains("Access denied"));
    }

    #[tokio::test]
    async fn read_resource_command_denied_by_policy() {
        let _stub = TmuxStub::new();
        let server = server_with_policy("[security]\nallow_execute_command = false\n");
        let (context, _client_transport, _running) = context_for_server(&server);

        let command_id = server
            .tracker
            .execute_command("%1", "echo hi", false, false, None, None)
            .await
            .expect("execute command");

        let request = ReadResourceRequestParams {
            uri: format!("tmux://command/{command_id}/result"),
            meta: None,
        };
        let result = server
            .read_resource(request, context)
            .await
            .expect("read resource");
        let text = first_text_resource(&result.contents);
        assert!(text.contains("Access denied"));
    }
}
