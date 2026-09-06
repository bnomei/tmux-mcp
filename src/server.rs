//! stdio MCP server: tool router, input/output schemas, and dynamic resources.
//!
//! `TmuxMcpServer` wires `CommandTracker`, `SecurityPolicy`, and the tmux adapter
//! into rmcp tools. Policy removes disallowed routes at construction and is
//! re-checked per call for sockets, sessions, panes, commands, and buffer paths.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, ContentBlock as Content, Resource, ResourceContents, ResourceTemplate,
    ResourceUpdatedNotificationParam, ServerCapabilities, ServerInfo,
};
use rmcp::schemars::JsonSchema;
use rmcp::serde::{Deserialize, Serialize};
use rmcp::serde_json;
use rmcp::service::{Peer, RequestContext, RoleServer};
use rmcp::tool;
use rmcp::tool_router;
use rmcp::ErrorData as McpError;
use tokio::sync::RwLock;

struct Annotated;

struct RawResource {
    uri: String,
    name: String,
    title: Option<String>,
    description: Option<String>,
    mime_type: Option<String>,
    size: Option<u64>,
    icons: Option<Vec<rmcp::model::Icon>>,
    meta: Option<rmcp::model::Meta>,
}

struct RawResourceTemplate {
    uri_template: String,
    name: String,
    title: Option<String>,
    description: Option<String>,
    mime_type: Option<String>,
    icons: Option<Vec<rmcp::model::Icon>>,
}

trait IntoAnnotated {
    type Output;

    fn into_annotated(self) -> Self::Output;
}

impl IntoAnnotated for RawResource {
    type Output = Resource;

    fn into_annotated(self) -> Self::Output {
        let mut resource = Resource::new(self.uri, self.name);
        if let Some(title) = self.title {
            resource = resource.with_title(title);
        }
        if let Some(description) = self.description {
            resource = resource.with_description(description);
        }
        if let Some(mime_type) = self.mime_type {
            resource = resource.with_mime_type(mime_type);
        }
        if let Some(size) = self.size {
            resource = resource.with_size(size);
        }
        if let Some(icons) = self.icons {
            resource = resource.with_icons(icons);
        }
        if let Some(meta) = self.meta {
            resource = resource.with_meta(meta);
        }
        resource
    }
}

impl IntoAnnotated for RawResourceTemplate {
    type Output = ResourceTemplate;

    fn into_annotated(self) -> Self::Output {
        let mut template = ResourceTemplate::new(self.uri_template, self.name);
        if let Some(title) = self.title {
            template = template.with_title(title);
        }
        if let Some(description) = self.description {
            template = template.with_description(description);
        }
        if let Some(mime_type) = self.mime_type {
            template = template.with_mime_type(mime_type);
        }
        if let Some(icons) = self.icons {
            template = template.with_icons(icons);
        }
        template
    }
}

impl Annotated {
    // This mirrors rmcp's compatibility constructor and intentionally returns
    // the concrete annotated resource/template type instead of `Annotated`.
    #[allow(clippy::new_ret_no_self)]
    fn new<T: IntoAnnotated>(value: T, _annotations: Option<()>) -> T::Output {
        value.into_annotated()
    }
}

use crate::commands::{CommandEventKind, CommandTracker};
use crate::security::{SearchConfig, SecurityPolicy};
use crate::tmux;
use crate::types::{
    command_resource_uri, BufferInfo, BufferSearchOutput, ClientInfo, CommandSnapshot,
    CommandStatus, Pane, SearchMode, Session, Window,
};
use crate::watch::{self, AnchorRegistry, WatchConfig};

/// stdio MCP server: policy-gated tool router, command tracker, and dynamic resources.
///
/// Constructed once at process start. Policy removes denied tool routes at build
/// time and re-checks sockets/sessions/panes/commands/paths on each call. Command
/// lifecycle events fan out to subscribed `tmux://command/{id}/result` resources.
#[derive(Clone)]
pub struct TmuxMcpServer {
    tracker: Arc<CommandTracker>,
    policy: Arc<SecurityPolicy>,
    search: SearchConfig,
    /// Poll/timeout/debounce budgets for `wait-for-pane-change`.
    watch: WatchConfig,
    /// Last-seen pane text per `(socket, pane_id)` — the anchor baseline pool.
    anchors: Arc<tokio::sync::Mutex<AnchorRegistry>>,
    router: ToolRouter<Self>,
    /// Connected MCP peer used for resource list/updated notifications.
    peer: Arc<RwLock<Option<Peer<RoleServer>>>>,
    /// Resource URIs currently subscribed by the client.
    subscriptions: Arc<RwLock<HashSet<String>>>,
}

/// Tool capabilities required to expose each MCP resource family.
///
/// Keep this matrix as the single authorization source for resource templates,
/// concrete resource listings, and direct resource reads. Concrete catalog
/// discovery may require additional list capabilities to enumerate target IDs,
/// but it must never weaken these per-resource requirements.
#[derive(Clone, Copy, Debug)]
enum ResourceCapability {
    Pane,
    Window,
    SessionTree,
    Clients,
    CommandResult,
}

impl ResourceCapability {
    const fn required_tools(self) -> &'static [&'static str] {
        match self {
            Self::Pane => &["capture-pane"],
            Self::Window => &["list-windows"],
            Self::SessionTree => &["list-sessions", "list-windows", "list-panes"],
            Self::Clients => &["list-clients"],
            Self::CommandResult => &["get-command-result"],
        }
    }

    fn check(self, policy: &SecurityPolicy) -> Result<(), crate::errors::Error> {
        for tool_name in self.required_tools() {
            policy.check_tool(tool_name)?;
        }
        Ok(())
    }
}

/// Serialize a successful tool payload as MCP structured content.
fn structured_output<T: Serialize>(value: &T) -> CallToolResult {
    match serde_json::to_value(value) {
        Ok(json) => CallToolResult::structured(json),
        Err(e) => CallToolResult::error(vec![Content::text(format!(
            "Error serializing output: {e}"
        ))]),
    }
}

/// Serialize a structured error payload (for example failed command snapshots).
fn structured_error_output<T: Serialize>(value: &T) -> CallToolResult {
    match serde_json::to_value(value) {
        Ok(json) => CallToolResult::structured_error(json),
        Err(e) => CallToolResult::error(vec![Content::text(format!(
            "Error serializing output: {e}"
        ))]),
    }
}

fn truncate_command_label(command: &str) -> String {
    let mut chars = command.chars();
    let label: String = chars.by_ref().take(30).collect();
    if chars.next().is_some() {
        format!("{label}...")
    } else {
        command.to_string()
    }
}

macro_rules! read_resource_result {
    (contents: $contents:expr $(,)?) => {
        rmcp::model::ReadResourceResult::new($contents)
    };
}

#[cfg(test)]
macro_rules! read_resource_request {
    (uri: $uri:expr, meta: $meta:expr $(,)?) => {{
        let uri: String = $uri;
        let mut request = ReadResourceRequestParams::new(uri);
        request.meta = $meta;
        request
    }};
}

// ============================================================================
// Tool Output Schemas
// ============================================================================

/// Accept response for `execute-command` (before optional wait completion).
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteCommandOutput {
    /// Opaque id for `get-command-result` / command resources.
    pub command_id: String,
    /// `tmux://command/{id}/result` URI for resources/subscribe.
    pub resource_uri: String,
    /// Initial lifecycle status wire string (`queued` or `running`).
    pub status: String,
    /// Human-readable accept note (not the command's shell output).
    pub message: String,
}

/// `list-sessions` structured payload.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListSessionsOutput {
    pub sessions: Vec<Session>,
}

/// `list-windows` structured payload.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListWindowsOutput {
    pub windows: Vec<Window>,
}

/// `list-panes` structured payload.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListPanesOutput {
    pub panes: Vec<Pane>,
}

/// `list-clients` structured payload.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListClientsOutput {
    pub clients: Vec<ClientInfo>,
}

/// `list-buffers` structured payload.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListBuffersOutput {
    pub buffers: Vec<BufferInfo>,
}

/// `get-command-result` payload (same schema as command resources).
pub type GetCommandResultOutput = CommandSnapshot;

// ============================================================================
// Tool Input Schemas
// ============================================================================

/// Shared optional socket override for inventory tools that need no other target.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SocketInput {
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `socket-for-path`: derive a deterministic isolated socket from a project path.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SocketForPathInput {
    /// Project/worktree path hashed into `/tmp/{fnv}.sock` (or platform temp).
    pub path: String,
}

/// `find-session`: exact session-name lookup.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindSessionInput {
    /// Session display name (exact match, not id).
    pub name: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// Session-targeted tools (`list-windows`, `kill-session`, …).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SessionIdInput {
    /// Session target id (typically `$N`).
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// Window-targeted tools (`list-panes`, `kill-window`, `select-window`, …).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct WindowIdInput {
    /// Window target id (typically `@N`).
    #[serde(rename = "windowId")]
    pub window_id: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// Pane-targeted tools (`kill-pane`, `select-pane`, `zoom-pane`, …).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PaneIdInput {
    /// Pane target id (typically `%N`); unique only within one tmux server/socket.
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `capture-pane`: read scrollback/screen text (not a substitute for tracked command output).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CapturePaneInput {
    /// Pane target id (`%N`).
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// History line budget when start/end are omitted.
    pub lines: Option<u32>,
    /// Keep SGR/escape sequences when true.
    pub colors: Option<bool>,
    /// Start line offset (negative counts from the bottom).
    pub start: Option<i32>,
    /// End line offset (negative counts from the bottom).
    pub end: Option<i32>,
    /// Join soft-wrapped lines when true.
    pub join: Option<bool>,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `wait-for-pane-change`: block until the pane's displayed text differs.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct WaitForPaneChangeInput {
    /// Pane target id (`%N`), mirroring `capture-pane` targeting.
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// Blocking budget in milliseconds; timeout is a successful `timedOut` result.
    /// Clamped to the `[watch]` `timeout_max_ms` ceiling.
    #[serde(rename = "timeoutMs")]
    pub timeout_ms: Option<u64>,
    /// Debounce window in milliseconds: keep resetting while the screen keeps
    /// changing, wake once it has been stable this long. `0` wakes at the first
    /// change. Defaults to `[watch]` `stable_ms` (250).
    #[serde(rename = "stableMs")]
    pub stable_ms: Option<u64>,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `wait-for-pane-change` result: signal only, no pane content.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WaitForPaneChangeOutput {
    /// Watched pane target id.
    pub pane_id: String,
    /// True when the displayed text differed from the baseline.
    pub changed: bool,
    /// True when the blocking budget elapsed without a settled change.
    /// A timeout is not an error: the pane simply stayed quiet.
    pub timed_out: bool,
    /// Milliseconds spent blocking before the wake or timeout.
    pub waited_ms: u64,
    /// Milliseconds the screen was stable when the engine woke.
    pub quiet_ms: u64,
}

/// `create-session`: detached session bootstrap.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateSessionInput {
    /// Display name for the new session.
    pub name: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `create-window`: named window inside an existing session.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateWindowInput {
    /// Session target id (`$N`).
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// Display name for the new window.
    pub name: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `split-pane`: horizontal/vertical split with optional percent size.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SplitPaneInput {
    /// Pane to split (`%N`).
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// `"horizontal"` or `"vertical"` (default vertical).
    pub direction: Option<String>,
    /// New-pane size percent for tmux 3.x `-l N%`.
    pub size: Option<u32>,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `execute-command`: tracked shell work or raw key injection into a pane.
///
/// Tracked mode (default) queues per pane, wraps with a private exit-code side
/// channel, and rejects unquoted `#`, `&`, and embedded newlines. Prefer
/// resources/subscribe on the returned URI over tight poll loops.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecuteCommandInput {
    /// Pane target id (`%N`).
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// Shell text to inject. Tracked mode forbids unquoted `#`, `&`, and newlines.
    pub command: String,
    /// Skip side-channel tracking wrappers (raw send; no authoritative exit code).
    #[serde(rename = "rawMode")]
    pub raw_mode: Option<bool>,
    /// Omit the trailing Enter; also disables tracking.
    #[serde(rename = "noEnter")]
    pub no_enter: Option<bool>,
    /// Per-character send delay in milliseconds (slow typing).
    #[serde(rename = "delayMs")]
    pub delay_ms: Option<u64>,
    /// Optional block until terminal or timeout after accept. Prefer resource subscribe.
    #[serde(rename = "waitMs")]
    pub wait_ms: Option<u64>,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `get-command-result`: poll or wait for a tracked command snapshot.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetCommandResultInput {
    /// Command id returned by `execute-command`.
    #[serde(rename = "commandId")]
    pub command_id: String,
    /// Block until terminal or timeout; timeout does not change command status.
    #[serde(rename = "waitMs")]
    pub wait_ms: Option<u64>,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `rename-window` args.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameWindowInput {
    /// Window target id (`@N`).
    #[serde(rename = "windowId")]
    pub window_id: String,
    /// New window display name.
    pub name: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `rename-pane` args (sets `#{pane_title}`).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenamePaneInput {
    /// Pane target id (`%N`).
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// New pane title string.
    pub title: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `move-window`: relocate a window into another session.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct MoveWindowInput {
    /// Window to move (`@N`).
    #[serde(rename = "windowId")]
    pub window_id: String,
    /// Destination session id (`$N`).
    #[serde(rename = "targetSessionId")]
    pub target_session_id: String,
    /// Optional index in the destination session.
    #[serde(rename = "targetIndex")]
    pub target_index: Option<u32>,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `rename-session` args.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameSessionInput {
    /// Session target id (`$N`).
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// New session display name.
    pub name: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `resize-pane`: relative direction/amount or absolute width/height.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResizePaneInput {
    /// Pane target id (`%N`).
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// Relative resize direction: `left`, `right`, `up`, or `down`.
    pub direction: Option<String>,
    /// Cells to grow/shrink when `direction` is set.
    pub amount: Option<u32>,
    /// Absolute width in cells (overrides relative resize when set with height).
    pub width: Option<u32>,
    /// Absolute height in cells.
    pub height: Option<u32>,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `select-layout`: apply a named tmux layout algorithm to a window.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SelectLayoutInput {
    /// Window target id (`@N`).
    #[serde(rename = "windowId")]
    pub window_id: String,
    /// Layout name (for example `even-horizontal`, `tiled`, `main-vertical`).
    pub layout: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `join-pane`: move source pane into the window that owns the target pane.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct JoinPaneInput {
    /// Pane to relocate (`%N`).
    #[serde(rename = "sourcePaneId")]
    pub source_pane_id: String,
    /// Destination pane whose window receives the join (`%N`).
    #[serde(rename = "targetPaneId")]
    pub target_pane_id: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `swap-pane`: exchange two pane positions.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SwapPaneInput {
    /// First pane (`%N`).
    #[serde(rename = "sourcePaneId")]
    pub source_pane_id: String,
    /// Second pane (`%N`).
    #[serde(rename = "targetPaneId")]
    pub target_pane_id: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `break-pane`: promote a pane into its own window.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct BreakPaneInput {
    /// Pane to break out (`%N`).
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// Optional name for the new window.
    pub name: Option<String>,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `set-synchronize-panes`: fan-out typing to every pane in a window.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetSynchronizePanesInput {
    /// Window target id (`@N`).
    #[serde(rename = "windowId")]
    pub window_id: String,
    /// Enable (`true`) or disable (`false`) synchronize-panes.
    pub enabled: bool,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `detach-client`: disconnect an observer by TTY (not session kill).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DetachClientInput {
    /// Client TTY path from `list-clients`.
    #[serde(rename = "clientTty")]
    pub client_tty: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `show-buffer`: read a paste buffer with optional byte window.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ShowBufferInput {
    /// Buffer name; omit to show the most recent buffer.
    pub name: Option<String>,
    /// Absolute UTF-8 byte offset into the buffer.
    #[serde(rename = "offsetBytes")]
    pub offset_bytes: Option<u64>,
    /// Maximum UTF-8 bytes to return from the offset.
    #[serde(rename = "maxBytes")]
    pub max_bytes: Option<u64>,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `save-buffer`: write a paste buffer to a policy-resolved filesystem path.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SaveBufferInput {
    /// Paste-buffer name to export.
    pub name: String,
    /// Destination path (sandbox-relative when no buffer path allowlist is set).
    pub path: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `load-buffer`: replace a paste buffer from a policy-resolved filesystem path.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct LoadBufferInput {
    /// Paste-buffer name to create or replace.
    pub name: String,
    /// Source path (must pass buffer path policy).
    pub path: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `delete-buffer` args.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteBufferInput {
    /// Paste-buffer name to remove.
    pub name: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `set-buffer`: create or replace a paste buffer from UTF-8 text.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetBufferInput {
    /// Paste-buffer name to create or replace.
    pub name: String,
    /// Full buffer body (UTF-8).
    pub content: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `append-buffer`: append UTF-8 text (creates the buffer when missing).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AppendBufferInput {
    /// Paste-buffer name to append to.
    pub name: String,
    /// Text to append (UTF-8).
    pub content: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `rename-buffer`: copy+delete rename (tmux has no atomic buffer rename).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameBufferInput {
    /// Existing paste-buffer name.
    pub from: String,
    /// New paste-buffer name.
    pub to: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// Prior match position used as the `subsearch-buffer` scan anchor.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchAnchorInput {
    /// Absolute UTF-8 byte offset of the prior match start.
    #[serde(rename = "offsetBytes", alias = "offset_bytes")]
    pub offset_bytes: u64,
    /// Prior match length in UTF-8 bytes.
    #[serde(rename = "matchLen", alias = "match_len")]
    pub match_len: u32,
    /// Buffer name when the top-level `buffer` field is omitted.
    pub buffer: Option<String>,
}

/// `search-buffer`: multi-buffer literal/regex search with optional fuzzy scoring.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchBufferInput {
    /// Single buffer name (alias for a one-element `buffers` list).
    #[serde(rename = "buffer")]
    pub buffer: Option<String>,
    /// Buffer names to scan; omit to search every paste buffer.
    pub buffers: Option<Vec<String>>,
    /// Search query (literal text or regex depending on `mode`).
    pub query: String,
    /// Match strategy: `literal` or `regex`.
    pub mode: SearchMode,
    /// Snippet context radius in bytes around each hit.
    #[serde(rename = "contextBytes")]
    pub context_bytes: Option<u32>,
    /// Hard cap on matches returned for the whole request.
    #[serde(rename = "maxMatches")]
    pub max_matches: Option<u32>,
    /// Per-buffer scan budget for literal starts; regex/fuzzy need full-buffer coverage.
    #[serde(rename = "maxScanBytes")]
    pub max_scan_bytes: Option<u64>,
    /// Attach similarity scores when the fuzzy feature stack is enabled.
    #[serde(rename = "includeSimilarity")]
    pub include_similarity: Option<bool>,
    /// Prefer fuzzy line scoring over exact mode when supported.
    #[serde(rename = "fuzzyMatch")]
    pub fuzzy_match: Option<bool>,
    /// Drop fuzzy hits below this score in `[0.0, 1.0]`.
    #[serde(rename = "similarityThreshold")]
    pub similarity_threshold: Option<f32>,
    /// Per-buffer absolute byte cursors from a prior truncated result.
    #[serde(rename = "resumeFromOffset")]
    pub resume_from_offset: Option<BTreeMap<String, u64>>,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `subsearch-buffer`: follow-up search inside a window around a prior match.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SubsearchBufferInput {
    /// Paste-buffer name (may also come from `anchor.buffer`).
    pub buffer: Option<String>,
    /// Prior match offset/length defining the subsearch window center.
    pub anchor: SearchAnchorInput,
    /// Half-window of context around the anchor used as the scan range.
    #[serde(rename = "contextBytes", alias = "context_bytes")]
    pub context_bytes: u32,
    /// Resume cursor within the anchor window for paged subsearch.
    #[serde(rename = "resumeFromOffset")]
    pub resume_from_offset: Option<u64>,
    /// Search query (literal text or regex depending on `mode`).
    pub query: String,
    /// Match strategy: `literal` or `regex`.
    pub mode: SearchMode,
    /// Hard cap on matches returned.
    #[serde(rename = "maxMatches")]
    pub max_matches: Option<u32>,
    /// Attach similarity scores when the fuzzy feature stack is enabled.
    #[serde(rename = "includeSimilarity")]
    pub include_similarity: Option<bool>,
    /// Prefer fuzzy line scoring over exact mode when supported.
    #[serde(rename = "fuzzyMatch")]
    pub fuzzy_match: Option<bool>,
    /// Drop fuzzy hits below this score in `[0.0, 1.0]`.
    #[serde(rename = "similarityThreshold")]
    pub similarity_threshold: Option<f32>,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `send-keys` (feature `interactive`): raw key injection without command tracking.
#[cfg(feature = "interactive")]
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SendKeysInput {
    /// Pane target id (`%N`).
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// Key sequence or literal text to inject.
    pub keys: String,
    /// When true, send each character with `-l` so shell metacharacters stay raw.
    pub literal: Option<bool>,
    /// Press Enter after each repeat.
    pub enter: Option<bool>,
    /// How many times to emit `keys` (default 1).
    pub repeat: Option<u32>,
    /// Delay between key transmissions in milliseconds.
    #[serde(rename = "delayMs")]
    pub delay_ms: Option<u64>,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `send-hex` (feature `interactive`): inject raw bytes via `send-keys -H`.
#[cfg(feature = "interactive")]
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SendHexInput {
    /// Pane target id (`%N`).
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// Whitespace-separated hex byte tokens (`00`-`ff`), e.g. CSI-u sequences.
    pub hex: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

/// `paste-text` (feature `interactive`): paste UTF-8 via a disposable paste buffer.
#[cfg(feature = "interactive")]
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PasteTextInput {
    /// Pane target id (`%N`).
    #[serde(rename = "paneId")]
    pub pane_id: String,
    /// UTF-8 text staged through a temporary paste buffer then pasted.
    pub content: String,
    /// Per-call tmux socket path. Prefer a unique per-agent socket for isolation.
    pub socket: Option<String>,
}

// ============================================================================
// Tool Router Implementation
// ============================================================================

/// Collapse trailing slashes so project paths hash to a stable socket id.
fn normalize_path_for_socket(path: &str) -> String {
    let mut normalized = path.trim().to_string();
    while normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    normalized
}

/// FNV-1a hex digest used by `socket-for-path` to derive isolated agent sockets.
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
    /// Build a server with default search and watch budgets.
    ///
    /// Convenience wrapper for tests and simple embedders; the binary and
    /// config-aware callers use [`Self::new_with_search_and_watch`].
    #[allow(dead_code)]
    pub fn new(tracker: CommandTracker, policy: SecurityPolicy) -> Self {
        Self::new_with_search_and_watch(
            tracker,
            policy,
            SearchConfig::default(),
            WatchConfig::default(),
        )
    }

    /// Build a server with explicit search and watch budgets.
    ///
    /// The single real constructor: merges feature-gated tool routers,
    /// drops routes denied by policy, and spawns the command-event fan-out.
    /// The `[search]`/`[watch]` sections of config.toml map to their
    /// respective parameters.
    pub fn new_with_search_and_watch(
        tracker: CommandTracker,
        policy: SecurityPolicy,
        search: SearchConfig,
        watch: WatchConfig,
    ) -> Self {
        #[allow(unused_mut)]
        let mut router = Self::tool_router();
        #[cfg(feature = "interactive")]
        router.merge(Self::interactive_tool_router());
        #[cfg(feature = "special-keys")]
        router.merge(Self::special_keys_tool_router());
        Self::apply_tool_policy(&mut router, &policy);
        let command_resources_enabled = ResourceCapability::CommandResult.check(&policy).is_ok();
        let tracker = Arc::new(tracker);
        let peer: Arc<RwLock<Option<Peer<RoleServer>>>> = Arc::new(RwLock::new(None));
        let subscriptions: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));

        {
            let mut events = tracker.subscribe_events();
            let peer = Arc::clone(&peer);
            let subscriptions = Arc::clone(&subscriptions);
            tokio::spawn(async move {
                loop {
                    match events.recv().await {
                        Ok(event) => {
                            let peer_guard = peer.read().await;
                            let Some(peer) = peer_guard.as_ref() else {
                                continue;
                            };
                            match event.kind {
                                CommandEventKind::Created | CommandEventKind::Evicted => {
                                    if command_resources_enabled {
                                        let _ = peer.notify_resource_list_changed().await;
                                    }
                                    if event.kind == CommandEventKind::Evicted {
                                        let mut subs = subscriptions.write().await;
                                        subs.remove(&event.resource_uri);
                                    }
                                }
                                CommandEventKind::Updated | CommandEventKind::Terminal => {
                                    let subscribed = {
                                        let subs = subscriptions.read().await;
                                        subs.contains(&event.resource_uri)
                                    };
                                    if subscribed {
                                        let _ = peer
                                            .notify_resource_updated(
                                                ResourceUpdatedNotificationParam::new(
                                                    event.resource_uri.clone(),
                                                ),
                                            )
                                            .await;
                                    }
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
        }

        Self {
            tracker,
            policy: Arc::new(policy),
            search,
            watch,
            anchors: Arc::new(tokio::sync::Mutex::new(AnchorRegistry::new())),
            router,
            peer,
            subscriptions,
        }
    }

    async fn capture_peer(&self, context: &RequestContext<RoleServer>) {
        let mut slot = self.peer.write().await;
        *slot = Some(context.peer.clone());
    }

    /// Capture the pane's current visible text as its interaction anchor.
    ///
    /// Called by every content-touching tool: input tools before delivering
    /// (so the anchor is pre-output), reads after. Failures are logged and
    /// ignored — a failed anchor capture must never break the tool call
    /// itself; the wait falls back to the current-screen baseline.
    async fn capture_anchor(&self, pane_id: &str, socket: Option<&str>) {
        match tmux::capture_pane(pane_id, None, false, None, None, true, socket).await {
            Ok(text) => {
                self.anchors.lock().await.set(pane_id, socket, text);
            }
            Err(e) => {
                tracing::debug!("anchor capture failed for {pane_id}: {e}");
            }
        }
    }

    /// Drop routes that fail capability flags or the tool filter so clients never
    /// discover denied tools in `tools/list`.
    fn apply_tool_policy(router: &mut ToolRouter<Self>, policy: &SecurityPolicy) {
        for tool_name in router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect::<Vec<_>>()
        {
            if policy.check_tool(&tool_name).is_err() {
                router.remove_route(&tool_name);
            }
        }
    }

    fn resource_template(
        uri_template: &str,
        name: &str,
        description: &str,
        mime_type: &str,
    ) -> ResourceTemplate {
        Annotated::new(
            RawResourceTemplate {
                uri_template: uri_template.into(),
                name: name.into(),
                title: None,
                description: Some(description.into()),
                mime_type: Some(mime_type.into()),
                icons: None,
            },
            None,
        )
    }

    fn check_resource_capability(
        &self,
        capability: ResourceCapability,
    ) -> Result<(), crate::errors::Error> {
        capability.check(&self.policy)
    }

    fn policy_filtered_resource_templates(&self) -> Vec<ResourceTemplate> {
        let socket = tmux::resolve_socket(None);
        if self.policy.check_socket(socket.as_deref()).is_err() {
            return Vec::new();
        }

        let mut templates = Vec::new();
        templates.push(Self::resource_template(
            "tmux://server/info",
            "Tmux Server Info",
            "Default socket and SSH context for selecting the right tmux target.",
            "application/json",
        ));

        if self
            .check_resource_capability(ResourceCapability::Pane)
            .is_ok()
        {
            templates.push(Self::resource_template(
                "tmux://pane/{paneId}",
                "Tmux Pane Content",
                "Capture pane content for state checks or log monitoring; use when polling output without sending input.",
                "text/plain",
            ));
            templates.push(Self::resource_template(
                "tmux://pane/{paneId}/info",
                "Tmux Pane Info",
                "Detailed metadata for a pane (cwd, command, size). Use to decide where to run commands or how to resize/layout.",
                "application/json",
            ));
            templates.push(Self::resource_template(
                "tmux://pane/{paneId}/tail/{lines}",
                "Tmux Pane Tail",
                "Tail N lines from a pane for lightweight log polling without full scrollback.",
                "text/plain",
            ));
            templates.push(Self::resource_template(
                "tmux://pane/{paneId}/tail/{lines}/ansi",
                "Tmux Pane Tail (ANSI)",
                "Tail N lines with ANSI colors when formatting or highlighting matters.",
                "text/plain",
            ));
        }

        if self
            .check_resource_capability(ResourceCapability::Window)
            .is_ok()
        {
            templates.push(Self::resource_template(
                "tmux://window/{windowId}/info",
                "Tmux Window Info",
                "Window metadata (layout, active pane, size). Use to normalize layouts or decide where to focus.",
                "application/json",
            ));
        }

        if self
            .check_resource_capability(ResourceCapability::SessionTree)
            .is_ok()
        {
            templates.push(Self::resource_template(
                "tmux://session/{sessionId}/tree",
                "Tmux Session Tree",
                "Snapshot of session, windows, and panes for planning multi-pane workflows.",
                "application/json",
            ));
        }

        if self
            .check_resource_capability(ResourceCapability::Clients)
            .is_ok()
        {
            templates.push(Self::resource_template(
                "tmux://clients",
                "Tmux Clients",
                "List of tmux clients to detect observers before detaching or resizing.",
                "application/json",
            ));
        }

        if self
            .check_resource_capability(ResourceCapability::CommandResult)
            .is_ok()
        {
            templates.push(Self::resource_template(
                "tmux://command/{commandId}/result",
                "Command Execution Result",
                "Tracked command snapshot; prefer subscribe for updates then read.",
                "application/json",
            ));
        }

        templates
    }

    async fn enforce_session_for_pane(
        &self,
        pane_id: &str,
        socket: Option<&str>,
    ) -> Result<(), crate::errors::Error> {
        if !self.policy.has_session_allowlist() {
            return Ok(());
        }
        let info = tmux::pane_info(pane_id, socket).await.map_err(|_| {
            crate::errors::Error::PolicyDenied {
                message: format!("unable to resolve session for pane '{pane_id}'"),
            }
        })?;
        self.enforce_session_target(&info.session_id, socket).await
    }

    async fn enforce_session_for_window(
        &self,
        window_id: &str,
        socket: Option<&str>,
    ) -> Result<(), crate::errors::Error> {
        if !self.policy.has_session_allowlist() {
            return Ok(());
        }
        let info = tmux::window_info(window_id, socket).await.map_err(|_| {
            crate::errors::Error::PolicyDenied {
                message: format!("unable to resolve session for window '{window_id}'"),
            }
        })?;
        self.enforce_session_target(&info.session_id, socket).await
    }

    async fn enforce_session_target(
        &self,
        target: &str,
        socket: Option<&str>,
    ) -> Result<(), crate::errors::Error> {
        if !self.policy.has_session_allowlist() || self.policy.check_session(target).is_ok() {
            return Ok(());
        }

        let sessions =
            tmux::list_sessions(socket)
                .await
                .map_err(|_| crate::errors::Error::PolicyDenied {
                    message: format!("unable to resolve session '{target}'"),
                })?;
        if let Some(session) = sessions
            .iter()
            .find(|session| session.id == target || session.name == target)
        {
            return self
                .policy
                .check_session_identity(&session.id, Some(&session.name));
        }

        self.policy.check_session(target)
    }

    async fn enforce_allowed_panes_for_window(
        &self,
        window_id: &str,
        socket: Option<&str>,
    ) -> Result<(), crate::errors::Error> {
        if !self.policy.has_pane_allowlist() {
            return Ok(());
        }

        let panes = tmux::list_panes(window_id, socket).await.map_err(|_| {
            crate::errors::Error::PolicyDenied {
                message: format!("unable to resolve panes for window '{window_id}'"),
            }
        })?;

        for pane in panes {
            if self.policy.check_pane(&pane.id).is_err() {
                return Err(crate::errors::Error::PolicyDenied {
                    message: format!(
                        "window '{window_id}' contains panes outside allowed panes list"
                    ),
                });
            }
        }
        Ok(())
    }

    async fn filter_allowed_clients(
        &self,
        clients: Vec<ClientInfo>,
        socket: Option<&str>,
    ) -> Vec<ClientInfo> {
        if !self.policy.has_session_allowlist() {
            return clients;
        }

        let mut allowed = Vec::new();
        for client in clients {
            if self
                .enforce_session_target(&client.session_name, socket)
                .await
                .is_ok()
            {
                allowed.push(client);
            }
        }
        allowed
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
            Ok(sessions) => {
                let sessions = sessions
                    .into_iter()
                    .filter(|session| {
                        self.policy
                            .check_session_identity(&session.id, Some(&session.name))
                            .is_ok()
                    })
                    .collect();
                Ok(structured_output(&ListSessionsOutput { sessions }))
            }
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
            Ok(Some(session)) => {
                if let Err(e) = self
                    .policy
                    .check_session_identity(&session.id, Some(&session.name))
                {
                    return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
                }
                Ok(structured_output(&session))
            }
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
        if let Err(e) = self
            .enforce_session_target(&input.0.session_id, socket.as_deref())
            .await
        {
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
        if let Err(e) = self
            .enforce_session_for_window(&input.0.window_id, socket.as_deref())
            .await
        {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::list_panes(&input.0.window_id, socket.as_deref()).await {
            Ok(panes) => {
                let panes = panes
                    .into_iter()
                    .filter(|pane| self.policy.check_pane(&pane.id).is_ok())
                    .collect();
                Ok(structured_output(&ListPanesOutput { panes }))
            }
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
            Ok(clients) => {
                let clients = self
                    .filter_allowed_clients(clients, socket.as_deref())
                    .await;
                Ok(structured_output(&ListClientsOutput { clients }))
            }
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
        if let Err(e) = self
            .enforce_session_for_pane(&input.0.pane_id, socket.as_deref())
            .await
        {
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
            Ok(content) => {
                // Read anchor: the agent has now seen this text — a following
                // wait arms from here (no double-report of old changes).
                self.capture_anchor(&input.0.pane_id, socket.as_deref())
                    .await;
                Ok(CallToolResult::success(vec![Content::text(
                    if content.is_empty() {
                        "No content captured".into()
                    } else {
                        content
                    },
                )]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error capturing pane: {e}"
            ))])),
        }
    }

    #[tool(
        name = "wait-for-pane-change",
        description = "Block until the pane's displayed text changes since your last interaction with it (input like send-keys, or any read of the pane), then return so the caller can capture-pane on its own decision. The wake predicate is byte-exact visible-screen comparison; commands that finish before you call this tool still wake it immediately. One tool call replaces poll loops when driving ssh sessions, containers, or REPLs. Timeout is a success with `timedOut: true`, not an error. Returns no pane content. Targeting mirrors capture-pane (paneId). Any tmux error aborts the wait: a pane that disappeared errors with that message. `timeoutMs` values above the `[watch]` `timeout_max_ms` ceiling are rejected with an error.",
        annotations(read_only_hint = true),
        output_schema = rmcp::handler::server::common::schema_for_type::<WaitForPaneChangeOutput>()
    )]
    async fn wait_for_pane_change(
        &self,
        input: Parameters<WaitForPaneChangeInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("wait-for-pane-change") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(&input.0.pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self
            .enforce_session_for_pane(&input.0.pane_id, socket.as_deref())
            .await
        {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Access denied: {e}"
            ))]));
        }

        let params =
            match watch::WaitParams::resolve(input.0.timeout_ms, input.0.stable_ms, &self.watch) {
                Ok(params) => params,
                Err(e) => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Invalid wait parameters: {e}"
                    ))]))
                }
            };
        // Arm against the interaction anchor (pre-input baseline), falling
        // back to the current screen when no anchor exists. This closes the
        // fast-command race: output that landed between the agent's last
        // input/read and this call still wakes the wait.
        let anchor = self
            .anchors
            .lock()
            .await
            .get(&input.0.pane_id, socket.as_deref())
            .map(|snap| snap.text);
        let mut source = watch::TmuxPollSource::new(input.0.pane_id.clone(), socket.clone());
        match watch::wait_for_change(&mut source, &params, anchor).await {
            Ok(result) => {
                // Re-anchor at the current screen on every wake (changed or
                // timed out): repeated waits arm from what the caller just
                // observed, never re-reporting an already-reported change.
                // `current.text` is not exposed by `WaitResult`, so recapture
                // — the wait just proved the pane readable.
                self.capture_anchor(&input.0.pane_id, socket.as_deref())
                    .await;
                let output = WaitForPaneChangeOutput {
                    pane_id: input.0.pane_id.clone(),
                    changed: result.outcome == watch::WaitOutcome::Changed,
                    timed_out: result.outcome == watch::WaitOutcome::TimedOut,
                    waited_ms: result.waited.as_millis() as u64,
                    quiet_ms: result.quiet.as_millis() as u64,
                };
                Ok(structured_output(&output))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error waiting for pane change: {e}"
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
        let save_path = match tmux::ssh_enabled() {
            Ok(true) => {
                let remote_candidate = match self.policy.remote_buffer_path_candidate(&input.0.path)
                {
                    Ok(path) => path,
                    Err(e) => {
                        return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]))
                    }
                };
                if self.policy.uses_default_buffer_dir() {
                    let dir = crate::security::default_remote_buffer_dir();
                    if let Err(e) = tmux::create_remote_dir(&dir).await {
                        return Ok(CallToolResult::error(vec![Content::text(format!(
                            "remote default buffer path '{dir}' is not accessible: {e}"
                        ))]));
                    }
                }
                let mut canonical_allowed_dirs = Vec::new();
                for dir in self.policy.remote_buffer_allowlist_candidates() {
                    match tmux::canonicalize_remote_path(&dir).await {
                        Ok(path) => canonical_allowed_dirs.push(path),
                        Err(e) => {
                            return Ok(CallToolResult::error(vec![Content::text(format!(
                                "remote allowed buffer path '{dir}' is not accessible: {e}"
                            ))]));
                        }
                    }
                }
                match tmux::canonicalize_remote_path(&remote_candidate).await {
                    Ok(canonical_path) => {
                        match self.policy.resolve_remote_buffer_path(
                            &input.0.path,
                            &canonical_path,
                            &canonical_allowed_dirs,
                        ) {
                            Ok(path) => path,
                            Err(e) => {
                                return Ok(CallToolResult::error(vec![Content::text(format!(
                                    "{e}"
                                ))]));
                            }
                        }
                    }
                    Err(_) => {
                        match tmux::remote_path_is_symlink(&remote_candidate).await {
                            Ok(true) => {
                                return Ok(CallToolResult::error(vec![Content::text(format!(
                                    "remote buffer path '{remote_candidate}' is not accessible"
                                ))]));
                            }
                            Ok(false) => {}
                            Err(e) => {
                                return Ok(CallToolResult::error(vec![Content::text(format!(
                                    "remote buffer path '{remote_candidate}' could not be validated: {e}"
                                ))]));
                            }
                        }
                        let (parent, filename) = match self
                            .policy
                            .remote_buffer_destination_path_candidate(&input.0.path)
                        {
                            Ok(parts) => parts,
                            Err(e) => {
                                return Ok(CallToolResult::error(vec![Content::text(format!(
                                    "{e}"
                                ))]));
                            }
                        };
                        let canonical_parent = match tmux::canonicalize_remote_path(&parent).await {
                            Ok(path) => path,
                            Err(e) => {
                                return Ok(CallToolResult::error(vec![Content::text(format!(
                                    "remote buffer path parent '{parent}' is not accessible: {e}"
                                ))]));
                            }
                        };
                        match self.policy.resolve_remote_buffer_destination_path(
                            &input.0.path,
                            &canonical_parent,
                            &filename,
                            &canonical_allowed_dirs,
                        ) {
                            Ok(path) => path,
                            Err(e) => {
                                return Ok(CallToolResult::error(vec![Content::text(format!(
                                    "{e}"
                                ))]));
                            }
                        }
                    }
                }
            }
            Ok(false) => match self
                .policy
                .resolve_local_buffer_destination_path(&input.0.path)
            {
                Ok(path) => path,
                Err(e) => return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))])),
            },
            Err(e) => return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))])),
        };
        match tmux::save_buffer(&input.0.name, &save_path, socket.as_deref()).await {
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
        let load_path = match tmux::ssh_enabled() {
            Ok(true) => {
                let remote_candidate = match self.policy.remote_buffer_path_candidate(&input.0.path)
                {
                    Ok(path) => path,
                    Err(e) => {
                        return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]))
                    }
                };
                let canonical_path = match tmux::canonicalize_remote_path(&remote_candidate).await {
                    Ok(path) => path,
                    Err(e) => {
                        return Ok(CallToolResult::error(vec![Content::text(format!(
                            "remote buffer path '{remote_candidate}' is not accessible: {e}"
                        ))]));
                    }
                };
                let mut canonical_allowed_dirs = Vec::new();
                for dir in self.policy.remote_buffer_allowlist_candidates() {
                    match tmux::canonicalize_remote_path(&dir).await {
                        Ok(path) => canonical_allowed_dirs.push(path),
                        Err(e) => {
                            return Ok(CallToolResult::error(vec![Content::text(format!(
                                "remote allowed buffer path '{dir}' is not accessible: {e}"
                            ))]));
                        }
                    }
                }
                match self.policy.resolve_remote_buffer_path(
                    &input.0.path,
                    &canonical_path,
                    &canonical_allowed_dirs,
                ) {
                    Ok(path) => path,
                    Err(e) => {
                        return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]))
                    }
                }
            }
            Ok(false) => match self.policy.resolve_local_buffer_path(&input.0.path) {
                Ok(path) => path,
                Err(e) => return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))])),
            },
            Err(e) => return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))])),
        };
        match tmux::load_buffer(&input.0.name, &load_path, socket.as_deref()).await {
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
        if let Err(e) = self.policy.check_command(&input.0.content) {
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
        if let Err(e) = self.policy.check_command(&input.0.content) {
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
            self.search.streaming_threshold_bytes,
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
            self.search.streaming_threshold_bytes,
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
        if let Err(e) = self
            .enforce_session_target(&input.0.name, socket.as_deref())
            .await
        {
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
        if let Err(e) = self
            .enforce_session_target(&input.0.session_id, socket.as_deref())
            .await
        {
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
        if let Err(e) = self
            .enforce_session_for_pane(&input.0.pane_id, socket.as_deref())
            .await
        {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if self.policy.has_pane_allowlist() {
            return Ok(CallToolResult::error(vec![Content::text(
                "split-pane cannot create a pane when allowed_panes is configured".to_string(),
            )]));
        }
        match tmux::split_pane(
            &input.0.pane_id,
            input.0.direction.as_deref(),
            input.0.size,
            socket.as_deref(),
        )
        .await
        {
            Ok(pane) => {
                // Anchor the newborn pane at its birth screen so a following
                // wait-for-pane-change (e.g. "wait for the first prompt")
                // wakes when the shell draws — the pane-birth flavor of the
                // fast-command race.
                self.capture_anchor(&pane.id, socket.as_deref()).await;
                Ok(structured_output(&pane))
            }
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
        if let Err(e) = self
            .enforce_session_target(&input.0.session_id, socket.as_deref())
            .await
        {
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
        if let Err(e) = self
            .enforce_session_for_window(&input.0.window_id, socket.as_deref())
            .await
        {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self
            .enforce_allowed_panes_for_window(&input.0.window_id, socket.as_deref())
            .await
        {
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
        if let Err(e) = self
            .enforce_session_for_pane(&input.0.pane_id, socket.as_deref())
            .await
        {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        match tmux::kill_pane(&input.0.pane_id, socket.as_deref()).await {
            Ok(()) => {
                self.tracker
                    .purge_pane(&input.0.pane_id, socket.as_deref())
                    .await;
                self.anchors
                    .lock()
                    .await
                    .purge_pane(&input.0.pane_id, socket.as_deref());
                Ok(CallToolResult::success(vec![Content::text(format!(
                    "Pane {} has been killed",
                    input.0.pane_id
                ))]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error killing pane: {e}"
            ))])),
        }
    }

    #[tool(
        name = "execute-command",
        description = "Run a shell command in a pane with side-channel exit-code tracking. Returns JSON: {commandId, resourceUri, status, message}. Prefer resources/subscribe on resourceUri then resources/read on notifications/resources/updated; fallback: get-command-result with waitMs. Tracked commands queue per pane. For interactive programs (vim/htop), use send-keys instead.",
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
        if let Err(e) = self
            .enforce_session_for_pane(&input.0.pane_id, socket.as_deref())
            .await
        {
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
        // Input anchor: tracked wrapper is input — arm before it lands so a
        // follow-up wait-for-pane-change catches fast completed commands.
        self.capture_anchor(&input.0.pane_id, socket.as_deref())
            .await;
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
                if let Some(wait_ms) = input.0.wait_ms.filter(|ms| *ms > 0) {
                    let _ = self.tracker.wait_for(&command_id, wait_ms).await;
                }
                let status = self
                    .tracker
                    .get_command(&command_id)
                    .await
                    .map(|c| c.status.as_str().to_string())
                    .unwrap_or_else(|| "running".into());
                let response = ExecuteCommandOutput {
                    command_id: command_id.clone(),
                    resource_uri: command_resource_uri(&command_id),
                    status,
                    message: "Command accepted; prefer resources/subscribe on resourceUri or get-command-result with waitMs"
                        .into(),
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
        description = "Get status/output of a tracked command by ID (CommandSnapshot JSON). Prefer resources/subscribe + read for async completion; use waitMs to block until terminal or timeout without inventing poll loops. Timeout leaves the command running.",
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
        let requested_override = input.0.socket.as_deref().filter(|s| !s.is_empty());
        let socket = tmux::resolve_socket(requested_override);
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Some(cmd) = self.tracker.get_command(&input.0.command_id).await {
            let recorded = cmd.socket.as_deref();
            match (requested_override, recorded) {
                (Some(requested), Some(recorded)) if requested != recorded => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Socket override does not match recorded socket for command {}",
                        input.0.command_id
                    ))]));
                }
                (Some(_), None) => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Socket override is not allowed for command {}",
                        input.0.command_id
                    ))]));
                }
                (None, Some(recorded)) if socket.as_deref() != Some(recorded) => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Socket does not match recorded socket for command {}",
                        input.0.command_id
                    ))]));
                }
                _ => {}
            }
            if let Err(e) = self.policy.check_pane(&cmd.pane_id) {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Access denied: {e}"
                ))]));
            }
            if let Err(e) = self
                .enforce_session_for_pane(&cmd.pane_id, socket.as_deref())
                .await
            {
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

        let wait_ms = input.0.wait_ms.unwrap_or(0);
        let (cmd, wait_timed_out) = if wait_ms > 0 {
            match self.tracker.wait_for(&input.0.command_id, wait_ms).await {
                Ok(Some((cmd, timed_out))) => (cmd, timed_out.then_some(true)),
                Ok(None) => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Command not found: {}",
                        input.0.command_id
                    ))]));
                }
                Err(e) => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Error getting command result: {e}"
                    ))]));
                }
            }
        } else {
            match self
                .tracker
                .check_status(&input.0.command_id, socket.as_deref())
                .await
            {
                Ok(Some(cmd)) => (cmd, None),
                Ok(None) => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Command not found: {}",
                        input.0.command_id
                    ))]));
                }
                Err(e) => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Error getting command result: {e}"
                    ))]));
                }
            }
        };

        let result = CommandSnapshot::from_execution(&cmd, wait_timed_out);
        if matches!(
            cmd.status,
            CommandStatus::Failed | CommandStatus::TrackingError
        ) {
            Ok(structured_error_output(&result))
        } else {
            Ok(structured_output(&result))
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
            Ok(session) => {
                if let Err(e) = self
                    .policy
                    .check_session_identity(&session.id, Some(&session.name))
                {
                    return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
                }
                Ok(structured_output(&session))
            }
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
        if let Err(e) = self
            .enforce_session_target(&input.0.session_id, socket.as_deref())
            .await
        {
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
        if let Err(e) = self
            .enforce_session_for_window(&input.0.window_id, socket.as_deref())
            .await
        {
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
        if let Err(e) = self
            .enforce_session_for_pane(&input.0.pane_id, socket.as_deref())
            .await
        {
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
        if let Err(e) = self
            .enforce_session_for_window(&input.0.window_id, socket.as_deref())
            .await
        {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self
            .enforce_session_target(&input.0.target_session_id, socket.as_deref())
            .await
        {
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
        if let Err(e) = self
            .enforce_session_for_window(&input.0.window_id, socket.as_deref())
            .await
        {
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
        if let Err(e) = self
            .enforce_session_for_pane(&input.0.pane_id, socket.as_deref())
            .await
        {
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
        if let Err(e) = self
            .enforce_session_for_pane(&input.0.pane_id, socket.as_deref())
            .await
        {
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
        if let Err(e) = self
            .enforce_session_for_pane(&input.0.pane_id, socket.as_deref())
            .await
        {
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
        if let Err(e) = self
            .enforce_session_for_window(&input.0.window_id, socket.as_deref())
            .await
        {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self
            .enforce_allowed_panes_for_window(&input.0.window_id, socket.as_deref())
            .await
        {
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
        if let Err(e) = self
            .enforce_session_for_pane(&input.0.source_pane_id, socket.as_deref())
            .await
        {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self
            .enforce_session_for_pane(&input.0.target_pane_id, socket.as_deref())
            .await
        {
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
        if let Err(e) = self
            .enforce_session_for_pane(&input.0.pane_id, socket.as_deref())
            .await
        {
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
        if let Err(e) = self
            .enforce_session_for_pane(&input.0.source_pane_id, socket.as_deref())
            .await
        {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self
            .enforce_session_for_pane(&input.0.target_pane_id, socket.as_deref())
            .await
        {
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
        if let Err(e) = self
            .enforce_session_for_window(&input.0.window_id, socket.as_deref())
            .await
        {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if input.0.enabled {
            if let Err(e) = self
                .enforce_allowed_panes_for_window(&input.0.window_id, socket.as_deref())
                .await
            {
                return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
            }
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
        if self.policy.has_session_allowlist() {
            let clients = match tmux::list_clients(socket.as_deref()).await {
                Ok(clients) => clients,
                Err(e) => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Error resolving client session: {e}"
                    ))]));
                }
            };
            let Some(client) = clients
                .iter()
                .find(|client| client.tty == input.0.client_tty)
            else {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Client not found: {}",
                    input.0.client_tty
                ))]));
            };
            if let Err(e) = self
                .enforce_session_target(&client.session_name, socket.as_deref())
                .await
            {
                return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
            }
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
}

#[cfg(feature = "interactive")]
#[tool_router(router = interactive_tool_router)]
impl TmuxMcpServer {
    // Dedicated terminal interaction tools
    #[tool(
        name = "send-keys",
        description = "Send keystrokes to a pane. Use for interactive programs; prefer execute-command for shell commands.",
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
        if let Err(e) = self
            .enforce_session_for_pane(&input.0.pane_id, socket.as_deref())
            .await
        {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let literal = input.0.literal.unwrap_or(false);
        if let Err(e) = self.policy.check_command(&input.0.keys) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        // Input anchor: capture the pre-input screen once per call (the
        // repeat loop below is one key sequence) so a following
        // wait-for-pane-change arms against what the agent last saw.
        self.capture_anchor(&input.0.pane_id, socket.as_deref())
            .await;
        let repeat_count = input.0.repeat.unwrap_or(1).max(1);
        for _ in 0..repeat_count {
            if let Some(delay) = input.0.delay_ms {
                if literal {
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
            if input.0.enter.unwrap_or(false) {
                if let Err(e) =
                    tmux::send_keys(&input.0.pane_id, "Enter", false, socket.as_deref()).await
                {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Error sending Enter: {e}"
                    ))]));
                }
            }
        }
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Keys sent to pane {}",
            input.0.pane_id
        ))]))
    }

    #[tool(
        name = "send-hex",
        description = "Send raw bytes to a pane as whitespace-separated hex tokens via tmux send-keys -H. Rejects line-editing controls (BS/NAK/ETB/DEL) that can rewrite prior filtered input; use send-backspace for intentional edits.",
        annotations(open_world_hint = true)
    )]
    async fn send_hex(&self, input: Parameters<SendHexInput>) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("send-hex") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(&input.0.pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self
            .enforce_session_for_pane(&input.0.pane_id, socket.as_deref())
            .await
        {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let tokens = match tmux::parse_hex_tokens(&input.0.hex) {
            Ok(t) => t,
            Err(e) => return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))])),
        };
        let decoded: Vec<u8> = tokens
            .iter()
            .map(|t| u8::from_str_radix(t, 16).expect("normalized hex"))
            .collect();
        if let Some(&b) = decoded
            .iter()
            .find(|&&b| matches!(b, 0x08 | 0x15 | 0x17 | 0x7f))
        {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "send-hex rejects line-editing control byte {b:#04x}; use send-backspace instead"
            ))]));
        }
        if let Err(e) = self
            .policy
            .check_command(&String::from_utf8_lossy(&decoded))
        {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        // Input anchor: arm before the bytes land (see `send-keys`).
        self.capture_anchor(&input.0.pane_id, socket.as_deref())
            .await;
        match tmux::send_keys_hex(&input.0.pane_id, &input.0.hex, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Hex bytes sent to pane {}",
                input.0.pane_id
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error sending hex: {e}"
            ))])),
        }
    }

    #[tool(
        name = "paste-text",
        description = "Paste UTF-8 text into a pane via tmux bracketed paste.",
        annotations(open_world_hint = true)
    )]
    async fn paste_text(
        &self,
        input: Parameters<PasteTextInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.policy.check_tool("paste-text") {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        let socket = tmux::resolve_socket(input.0.socket.as_deref());
        if let Err(e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_pane(&input.0.pane_id) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self
            .enforce_session_for_pane(&input.0.pane_id, socket.as_deref())
            .await
        {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        if let Err(e) = self.policy.check_command(&input.0.content) {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        // Input anchor: arm before the paste lands (see `send-keys`).
        self.capture_anchor(&input.0.pane_id, socket.as_deref())
            .await;
        match tmux::paste_text(&input.0.pane_id, &input.0.content, socket.as_deref()).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Pasted text into pane {}",
                input.0.pane_id
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error pasting text: {e}"
            ))])),
        }
    }
}

#[cfg(feature = "special-keys")]
#[tool_router(router = special_keys_tool_router)]
impl TmuxMcpServer {
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

#[cfg(feature = "special-keys")]
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
        if let Err(e) = self
            .enforce_session_for_pane(pane_id, socket.as_deref())
            .await
        {
            return Ok(CallToolResult::error(vec![Content::text(format!("{e}"))]));
        }
        // Input anchor for every special-key tool: arm before the key lands.
        self.capture_anchor(pane_id, socket.as_deref()).await;
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

#[rmcp::tool_handler(router = self.router)]
impl rmcp::ServerHandler for TmuxMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_resources_subscribe()
                .enable_resources_list_changed()
                .build(),
        )
        .with_instructions(
            "Tmux MCP server for sessions, windows, panes, and tracked commands. Prefer per-agent isolated sockets (TMUX_MCP_SOCKET/--socket). execute-command returns commandId + resourceUri (tmux://command/{id}/result). Preferred completion path: resources/subscribe on resourceUri, wait for notifications/resources/updated, then resources/read. Fallback: get-command-result with waitMs. Tracked commands queue one-at-a-time per pane; interactive send-keys during a tracked run is unsafe. Completion is side-channel based—do not trust DONE lines in pane text.",
        )
    }

    async fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ListResourcesResult, McpError> {
        self.capture_peer(&context).await;
        let mut resources: Vec<Resource> = Vec::new();

        let socket = tmux::resolve_socket(None);
        if self.policy.check_socket(socket.as_deref()).is_ok() {
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
        }

        if let Err(_e) = self.policy.check_socket(socket.as_deref()) {
            return Ok(rmcp::model::ListResourcesResult {
                resources,
                next_cursor: None,
                meta: None,
            });
        }

        let can_discover_sessions = self.policy.check_tool("list-sessions").is_ok();
        let can_discover_windows =
            can_discover_sessions && self.policy.check_tool("list-windows").is_ok();
        let can_discover_panes =
            can_discover_windows && self.policy.check_tool("list-panes").is_ok();
        let can_publish_panes = can_discover_panes
            && self
                .check_resource_capability(ResourceCapability::Pane)
                .is_ok();
        let can_publish_windows = can_discover_windows
            && self
                .check_resource_capability(ResourceCapability::Window)
                .is_ok();
        let can_publish_session_trees = can_discover_panes
            && self
                .check_resource_capability(ResourceCapability::SessionTree)
                .is_ok();

        if can_publish_panes || can_publish_windows || can_publish_session_trees {
            let sessions = tmux::list_sessions(socket.as_deref()).await.map_err(|e| {
                McpError::internal_error(format!("Error listing tmux sessions: {e}"), None)
            })?;
            for session in sessions {
                if self
                    .policy
                    .check_session_identity(&session.id, Some(&session.name))
                    .is_err()
                {
                    continue;
                }
                let mut session_has_visible_window = false;
                let windows = tmux::list_windows(&session.id, socket.as_deref())
                    .await
                    .map_err(|e| {
                        McpError::internal_error(
                            format!("Error listing tmux windows for session {}: {e}", session.id),
                            None,
                        )
                    })?;
                for window in windows {
                    let inspect_panes = can_discover_panes || self.policy.has_pane_allowlist();
                    let (window_has_allowed_panes, all_window_panes_allowed) = if inspect_panes {
                        let panes = tmux::list_panes(&window.id, socket.as_deref())
                            .await
                            .map_err(|e| {
                                McpError::internal_error(
                                    format!(
                                        "Error listing tmux panes for window {}: {e}",
                                        window.id
                                    ),
                                    None,
                                )
                            })?;
                        let all_allowed = panes
                            .iter()
                            .all(|pane| self.policy.check_pane(&pane.id).is_ok());
                        let mut any_allowed = false;
                        for pane in panes {
                            if self.policy.check_pane(&pane.id).is_err() {
                                continue;
                            }
                            any_allowed = true;
                            if can_publish_panes {
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
                        (any_allowed, all_allowed)
                    } else {
                        // A tmux window always owns at least one pane. Without a pane
                        // allowlist, no pane IDs need to be discovered to publish its
                        // independently authorized window-info resource.
                        (true, true)
                    };

                    if window_has_allowed_panes && all_window_panes_allowed {
                        session_has_visible_window = true;
                    }

                    if can_publish_windows && window_has_allowed_panes && all_window_panes_allowed {
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
                if can_publish_session_trees && session_has_visible_window {
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

        if self
            .check_resource_capability(ResourceCapability::Clients)
            .is_ok()
        {
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

        if self
            .check_resource_capability(ResourceCapability::CommandResult)
            .is_ok()
        {
            for id in self.tracker.get_active_ids().await {
                let Some(cmd) = self.tracker.get_command(&id).await else {
                    continue;
                };
                if self.policy.check_socket(cmd.socket.as_deref()).is_err() {
                    continue;
                }
                if self.policy.check_pane(&cmd.pane_id).is_err() {
                    continue;
                }
                if self
                    .enforce_session_for_pane(&cmd.pane_id, cmd.socket.as_deref())
                    .await
                    .is_err()
                {
                    continue;
                }
                let truncated_cmd = truncate_command_label(&cmd.command);
                resources.push(Annotated::new(
                    RawResource {
                        uri: command_resource_uri(&id),
                        name: format!("Command: {truncated_cmd}"),
                        title: None,
                        description: Some(format!(
                            "Tracked command status: {}. Subscribe for updates; read for snapshot.",
                            cmd.status.as_str()
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

        Ok(rmcp::model::ListResourcesResult {
            resources,
            next_cursor: None,
            meta: None,
        })
    }

    async fn list_resource_templates(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ListResourceTemplatesResult, McpError> {
        self.capture_peer(&context).await;
        Ok(rmcp::model::ListResourceTemplatesResult {
            resource_templates: self.policy_filtered_resource_templates(),
            next_cursor: None,
            meta: None,
        })
    }

    async fn subscribe(
        &self,
        request: rmcp::model::SubscribeRequestParams,
        context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<(), McpError> {
        self.capture_peer(&context).await;
        let uri = request.uri;
        if let Err(e) = self.check_resource_capability(ResourceCapability::CommandResult) {
            return Err(McpError::invalid_params(
                format!("Access denied: {e}"),
                None,
            ));
        }
        let Some(command_id) = uri
            .strip_prefix("tmux://command/")
            .and_then(|rest| rest.strip_suffix("/result"))
        else {
            return Err(McpError::invalid_params(
                format!("unsupported resource URI for subscribe: {uri}"),
                None,
            ));
        };
        if !self.tracker.has_command(command_id).await {
            return Err(McpError::invalid_params(
                format!("unknown command resource: {uri}"),
                None,
            ));
        }
        let Some(cmd) = self.tracker.get_command(command_id).await else {
            return Err(McpError::invalid_params(
                format!("unknown command resource: {uri}"),
                None,
            ));
        };
        if let Err(e) = self.policy.check_socket(cmd.socket.as_deref()) {
            return Err(McpError::invalid_params(
                format!("Access denied: {e}"),
                None,
            ));
        }
        if let Err(e) = self.policy.check_pane(&cmd.pane_id) {
            return Err(McpError::invalid_params(
                format!("Access denied: {e}"),
                None,
            ));
        }
        if let Err(e) = self
            .enforce_session_for_pane(&cmd.pane_id, cmd.socket.as_deref())
            .await
        {
            return Err(McpError::invalid_params(
                format!("Access denied: {e}"),
                None,
            ));
        }
        {
            let mut subs = self.subscriptions.write().await;
            subs.insert(uri.clone());
        }
        // Already-terminal commands never emit Updated/Terminal after subscribe; chime once.
        if cmd.status.is_terminal() {
            let peer = self.peer.read().await;
            if let Some(peer) = peer.as_ref() {
                let _ = peer
                    .notify_resource_updated(ResourceUpdatedNotificationParam::new(uri))
                    .await;
            }
        }
        Ok(())
    }

    async fn unsubscribe(
        &self,
        request: rmcp::model::UnsubscribeRequestParams,
        context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<(), McpError> {
        self.capture_peer(&context).await;
        let mut subs = self.subscriptions.write().await;
        subs.remove(&request.uri);
        Ok(())
    }

    async fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParams,
        context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ReadResourceResult, McpError> {
        self.capture_peer(&context).await;
        let uri = request.uri.as_str();

        if uri == "tmux://server/info" {
            let socket = tmux::resolve_socket(None);
            if let Err(e) = self.policy.check_socket(socket.as_deref()) {
                return Ok(read_resource_result! {
                    contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                });
            }
            let info = serde_json::json!({
                "default_socket": socket,
                "ssh": std::env::var("TMUX_MCP_SSH").ok().filter(|value| !value.is_empty()),
            });
            Ok(read_resource_result! {
                contents: vec![ResourceContents::text(
                    serde_json::to_string_pretty(&info).unwrap_or_default(),
                    uri,
                )],
            })
        } else if let Some(rest) = uri.strip_prefix("tmux://pane/") {
            let socket = tmux::resolve_socket(None);
            if let Err(e) = self.policy.check_socket(socket.as_deref()) {
                return Ok(read_resource_result! {
                    contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                });
            }
            let parts: Vec<&str> = rest.split('/').collect();
            let pane_id = parts.first().copied().unwrap_or_default();
            if pane_id.is_empty() {
                return Ok(read_resource_result! {
                    contents: vec![ResourceContents::text("Invalid pane resource URI", uri)],
                });
            }
            if let Err(e) = self.check_resource_capability(ResourceCapability::Pane) {
                return Ok(read_resource_result! {
                    contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                });
            }
            if let Err(e) = self.policy.check_pane(pane_id) {
                return Ok(read_resource_result! {
                    contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                });
            }
            if let Err(e) = self
                .enforce_session_for_pane(pane_id, socket.as_deref())
                .await
            {
                return Ok(read_resource_result! {
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
                    Ok(content) => {
                        // Read anchor: the caller has seen this text.
                        self.capture_anchor(pane_id, socket.as_deref()).await;
                        Ok(read_resource_result! {
                            contents: vec![ResourceContents::text(content, uri)],
                        })
                    }
                    Err(e) => Ok(read_resource_result! {
                        contents: vec![ResourceContents::text(format!("Error: {e}"), uri)],
                    }),
                },
                [pane_id, "info"] => match tmux::pane_info(pane_id, socket.as_deref()).await {
                    Ok(info) => Ok(read_resource_result! {
                        contents: vec![ResourceContents::text(
                            serde_json::to_string_pretty(&info).unwrap_or_default(),
                            uri,
                        )],
                    }),
                    Err(e) => Ok(read_resource_result! {
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
                            Ok(content) => {
                                // Read anchor: the caller has seen this text.
                                self.capture_anchor(pane_id, socket.as_deref()).await;
                                Ok(read_resource_result! {
                                    contents: vec![ResourceContents::text(content, uri)],
                                })
                            }
                            Err(e) => Ok(read_resource_result! {
                                contents: vec![ResourceContents::text(format!("Error: {e}"), uri)],
                            }),
                        }
                    } else {
                        Ok(read_resource_result! {
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
                            Ok(content) => {
                                // Read anchor: the caller has seen this text
                                // (ANSI variant included).
                                self.capture_anchor(pane_id, socket.as_deref()).await;
                                Ok(read_resource_result! {
                                    contents: vec![ResourceContents::text(content, uri)],
                                })
                            }
                            Err(e) => Ok(read_resource_result! {
                                contents: vec![ResourceContents::text(format!("Error: {e}"), uri)],
                            }),
                        }
                    } else {
                        Ok(read_resource_result! {
                            contents: vec![ResourceContents::text(
                                "Invalid pane tail resource URI",
                                uri,
                            )],
                        })
                    }
                }
                _ => Ok(read_resource_result! {
                    contents: vec![ResourceContents::text("Invalid pane resource URI", uri)],
                }),
            }
        } else if let Some(rest) = uri.strip_prefix("tmux://window/") {
            if let Some(window_id) = rest.strip_suffix("/info") {
                let socket = tmux::resolve_socket(None);
                if let Err(e) = self.policy.check_socket(socket.as_deref()) {
                    return Ok(read_resource_result! {
                        contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                    });
                }
                if let Err(e) = self.check_resource_capability(ResourceCapability::Window) {
                    return Ok(read_resource_result! {
                        contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                    });
                }
                if let Err(e) = self
                    .enforce_session_for_window(window_id, socket.as_deref())
                    .await
                {
                    return Ok(read_resource_result! {
                        contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                    });
                }
                if let Err(e) = self
                    .enforce_allowed_panes_for_window(window_id, socket.as_deref())
                    .await
                {
                    return Ok(read_resource_result! {
                        contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                    });
                }
                match tmux::window_info(window_id, socket.as_deref()).await {
                    Ok(info) => Ok(read_resource_result! {
                        contents: vec![ResourceContents::text(
                            serde_json::to_string_pretty(&info).unwrap_or_default(),
                            uri,
                        )],
                    }),
                    Err(e) => Ok(read_resource_result! {
                        contents: vec![ResourceContents::text(format!("Error: {e}"), uri)],
                    }),
                }
            } else {
                Ok(read_resource_result! {
                    contents: vec![ResourceContents::text("Invalid window resource URI", uri)],
                })
            }
        } else if let Some(rest) = uri.strip_prefix("tmux://session/") {
            if let Some(session_id) = rest.strip_suffix("/tree") {
                let socket = tmux::resolve_socket(None);
                if let Err(e) = self.policy.check_socket(socket.as_deref()) {
                    return Ok(read_resource_result! {
                        contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                    });
                }
                if let Err(e) = self.check_resource_capability(ResourceCapability::SessionTree) {
                    return Ok(read_resource_result! {
                        contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                    });
                }
                if let Err(e) = self
                    .enforce_session_target(session_id, socket.as_deref())
                    .await
                {
                    return Ok(read_resource_result! {
                        contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                    });
                }
                match tmux::list_sessions(socket.as_deref()).await {
                    Ok(sessions) => {
                        let session = sessions
                            .into_iter()
                            .find(|s| s.id == session_id || s.name == session_id);
                        if let Some(session) = session {
                            let mut windows_tree = Vec::new();
                            let windows =
                                match tmux::list_windows(&session.id, socket.as_deref()).await {
                                    Ok(windows) => windows,
                                    Err(e) => {
                                        return Ok(read_resource_result! {
                                            contents: vec![ResourceContents::text(
                                                format!("Error: {e}"),
                                                uri,
                                            )],
                                        });
                                    }
                                };
                            for window in windows {
                                let panes =
                                    match tmux::list_panes(&window.id, socket.as_deref()).await {
                                        Ok(panes) => panes,
                                        Err(e) => {
                                            return Ok(read_resource_result! {
                                                contents: vec![ResourceContents::text(
                                                    format!("Error: {e}"),
                                                    uri,
                                                )],
                                            });
                                        }
                                    };
                                if panes.is_empty()
                                    || panes
                                        .iter()
                                        .any(|pane| self.policy.check_pane(&pane.id).is_err())
                                {
                                    continue;
                                }
                                windows_tree.push(crate::types::WindowTree { window, panes });
                            }
                            let tree = crate::types::SessionTree {
                                session,
                                windows: windows_tree,
                            };
                            Ok(read_resource_result! {
                                contents: vec![ResourceContents::text(
                                    serde_json::to_string_pretty(&tree).unwrap_or_default(),
                                    uri,
                                )],
                            })
                        } else {
                            Ok(read_resource_result! {
                                contents: vec![ResourceContents::text(
                                    format!("Session not found: {session_id}"),
                                    uri,
                                )],
                            })
                        }
                    }
                    Err(e) => Ok(read_resource_result! {
                        contents: vec![ResourceContents::text(format!("Error: {e}"), uri)],
                    }),
                }
            } else {
                Ok(read_resource_result! {
                    contents: vec![ResourceContents::text("Invalid session resource URI", uri)],
                })
            }
        } else if uri == "tmux://clients" {
            let socket = tmux::resolve_socket(None);
            if let Err(e) = self.policy.check_socket(socket.as_deref()) {
                return Ok(read_resource_result! {
                    contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                });
            }
            if let Err(e) = self.check_resource_capability(ResourceCapability::Clients) {
                return Ok(read_resource_result! {
                    contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                });
            }
            match tmux::list_clients(socket.as_deref()).await {
                Ok(clients) => {
                    let clients = self
                        .filter_allowed_clients(clients, socket.as_deref())
                        .await;
                    Ok(read_resource_result! {
                        contents: vec![ResourceContents::text(
                            serde_json::to_string_pretty(&clients).unwrap_or_default(),
                            uri,
                        )],
                    })
                }
                Err(e) => Ok(read_resource_result! {
                    contents: vec![ResourceContents::text(format!("Error: {e}"), uri)],
                }),
            }
        } else if let Some(rest) = uri.strip_prefix("tmux://command/") {
            if let Some(command_id) = rest.strip_suffix("/result") {
                if let Err(e) = self.check_resource_capability(ResourceCapability::CommandResult) {
                    return Ok(read_resource_result! {
                        contents: vec![ResourceContents::text(format!("Access denied: {e}"), uri)],
                    });
                }
                if let Some(cmd) = self.tracker.get_command(command_id).await {
                    if let Err(e) = self.policy.check_socket(cmd.socket.as_deref()) {
                        return Ok(read_resource_result! {
                            contents: vec![ResourceContents::text(
                                format!("Access denied: {e}"),
                                uri,
                            )],
                        });
                    }
                    if let Err(e) = self.policy.check_pane(&cmd.pane_id) {
                        return Ok(read_resource_result! {
                            contents: vec![ResourceContents::text(
                                format!("Access denied: {e}"),
                                uri,
                            )],
                        });
                    }
                    if let Err(e) = self
                        .enforce_session_for_pane(&cmd.pane_id, cmd.socket.as_deref())
                        .await
                    {
                        return Ok(read_resource_result! {
                            contents: vec![ResourceContents::text(
                                format!("Access denied: {e}"),
                                uri,
                            )],
                        });
                    }
                } else {
                    return Ok(read_resource_result! {
                        contents: vec![ResourceContents::text(
                            format!("Command not found: {command_id}"),
                            uri,
                        )],
                    });
                }
                match self.tracker.check_status(command_id, None).await {
                    Ok(Some(cmd)) => {
                        let result = CommandSnapshot::from_execution(&cmd, None);
                        Ok(read_resource_result! {
                            contents: vec![ResourceContents::text(
                                serde_json::to_string_pretty(&result).unwrap_or_default(),
                                uri,
                            )],
                        })
                    }
                    Ok(None) => Ok(read_resource_result! {
                        contents: vec![ResourceContents::text(
                            format!("Command not found: {command_id}"),
                            uri,
                        )],
                    }),
                    Err(e) => Ok(read_resource_result! {
                        contents: vec![ResourceContents::text(format!("Error: {e}"), uri)],
                    }),
                }
            } else {
                Ok(read_resource_result! {
                    contents: vec![ResourceContents::text("Invalid command resource URI", uri)],
                })
            }
        } else {
            Ok(read_resource_result! {
                contents: vec![ResourceContents::text("Unknown resource", uri)],
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TmuxStub;

    // Keep buffer policy tests self-contained; the optional copyrighted search
    // corpus is intentionally not required for CI compilation or execution.
    const BUFFER_FILE_TEST_CONTENT: &str = "tmux-mcp buffer policy test payload\n";
    use crate::types::ShellType;
    use crate::types::{Pane, Session, Window};
    use rmcp::model::{NumberOrString, ReadResourceRequestParams, ResourceContents};
    use rmcp::service::{self, RequestContext, RoleServer};
    use rmcp::ServerHandler;
    use serde_json::Value;
    use std::collections::BTreeSet;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tokio::io::duplex;

    fn stage_default_buffer_file(name: &str, contents: &str) {
        let dir = crate::security::default_buffer_dir();
        std::fs::create_dir_all(&dir).expect("create default buffer dir");
        std::fs::write(dir.join(name), contents).expect("write buffer file");
    }

    fn remove_default_buffer_file(name: &str) {
        let path = crate::security::default_buffer_dir().join(name);
        let _ = std::fs::remove_file(path);
    }

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
            .and_then(Content::as_text)
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

    fn resource_template_uris(server: &TmuxMcpServer) -> BTreeSet<String> {
        server
            .policy_filtered_resource_templates()
            .into_iter()
            .map(|template| template.uri_template)
            .collect()
    }

    fn resource_uris(resources: &[Resource]) -> BTreeSet<String> {
        resources
            .iter()
            .map(|resource| resource.uri.clone())
            .collect()
    }

    async fn read_resource_text(server: &TmuxMcpServer, uri: &str) -> String {
        let (context, _client_transport, _running) = context_for_server(server);
        let result = server
            .read_resource(
                read_resource_request!(uri: uri.to_string(), meta: None),
                context,
            )
            .await
            .expect("read resource");
        first_text_resource(&result.contents).to_string()
    }

    fn tool_names(server: &TmuxMcpServer) -> BTreeSet<String> {
        server
            .router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect()
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
        let context = RequestContext::new(NumberOrString::Number(1), running.peer().clone());
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
    async fn session_discovery_respects_allowed_sessions() {
        let _stub = TmuxStub::new();
        let server = server_with_policy("[security]\nallowed_sessions = [\"%1\"]\n");

        let result = server
            .list_sessions(Parameters(SocketInput { socket: None }))
            .await
            .expect("list sessions");
        assert_eq!(result.is_error, Some(false));

        let payload: ListSessionsOutput = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(payload.sessions.len(), 1);
        assert_eq!(payload.sessions[0].id, "%1");
        assert_eq!(payload.sessions[0].name, "alpha");
        assert!(!payload.sessions.iter().any(|session| session.id == "%2"));
        assert!(!payload
            .sessions
            .iter()
            .any(|session| session.name == "beta"));

        let result = server
            .find_session(Parameters(FindSessionInput {
                name: "beta".into(),
                socket: None,
            }))
            .await
            .expect("find session");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("session '%2' is not in allowed sessions list"));
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
    async fn buffer_file_operations_allowed_by_capture_policy() {
        let _stub = TmuxStub::new();
        let server = server_with_policy("[security]\nallow_capture = true\n");
        stage_default_buffer_file("buffer-input.txt", BUFFER_FILE_TEST_CONTENT);
        remove_default_buffer_file("buffer.txt");

        let result = server
            .load_buffer(Parameters(LoadBufferInput {
                name: "buffer0".into(),
                path: "buffer-input.txt".into(),
                socket: None,
            }))
            .await
            .expect("load buffer");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("loaded"));

        let result = server
            .save_buffer(Parameters(SaveBufferInput {
                name: "buffer0".into(),
                path: "buffer.txt".into(),
                socket: None,
            }))
            .await
            .expect("save buffer");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("saved"));
    }

    #[tokio::test]
    async fn load_buffer_rejects_absolute_path_by_default_policy() {
        let server =
            server_with_policy("[security]\nallow_capture = true\nallowed_sessions = [\"%1\"]\n");

        let result = server
            .load_buffer(Parameters(LoadBufferInput {
                name: "exfil".into(),
                path: "/etc/passwd".into(),
                socket: None,
            }))
            .await
            .expect("load buffer");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("policy denied"));
        assert!(first_text(&result).contains("must be relative"));
    }

    #[tokio::test]
    async fn buffer_file_operations_denied_by_capture_policy() {
        let server = server_with_policy("[security]\nallow_capture = false\n");

        let result = server
            .load_buffer(Parameters(LoadBufferInput {
                name: "buffer0".into(),
                path: "buffer-input.txt".into(),
                socket: None,
            }))
            .await
            .expect("load buffer");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("not allowed by security policy"));

        let result = server
            .save_buffer(Parameters(SaveBufferInput {
                name: "buffer0".into(),
                path: "buffer.txt".into(),
                socket: None,
            }))
            .await
            .expect("save buffer");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("not allowed by security policy"));
    }

    #[tokio::test]
    async fn save_buffer_rejects_absolute_path_by_default_policy() {
        let server =
            server_with_policy("[security]\nallow_capture = true\nallowed_sessions = [\"%1\"]\n");

        let result = server
            .save_buffer(Parameters(SaveBufferInput {
                name: "exfil".into(),
                path: "/tmp/evil.sh".into(),
                socket: None,
            }))
            .await
            .expect("save buffer");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("policy denied"));
        assert!(first_text(&result).contains("must be relative"));
    }

    #[tokio::test]
    async fn save_delete_and_detach_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();
        stage_default_buffer_file("buffer-input.txt", BUFFER_FILE_TEST_CONTENT);
        remove_default_buffer_file("buffer.txt");

        let result = server
            .load_buffer(Parameters(LoadBufferInput {
                name: "buffer0".into(),
                path: "buffer-input.txt".into(),
                socket: None,
            }))
            .await
            .expect("load buffer");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("loaded"));

        let result = server
            .save_buffer(Parameters(SaveBufferInput {
                name: "buffer0".into(),
                path: "buffer.txt".into(),
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
            wait_ms: None,
        });

        let result = server
            .execute_command(input)
            .await
            .expect("execute command");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("raw mode"));
    }

    #[cfg(feature = "interactive")]
    #[tokio::test]
    async fn send_keys_denied_by_policy() {
        let server = server_with_policy("[security]\nallow_send_keys = false\n");
        let input = Parameters(SendKeysInput {
            pane_id: "%1".into(),
            keys: "hello".into(),
            literal: None,
            enter: None,
            repeat: None,
            delay_ms: None,
            socket: None,
        });

        let result = server.send_keys(input).await.expect("send keys");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("send-keys"));
    }

    #[cfg(feature = "interactive")]
    #[tokio::test]
    async fn send_hex_denied_by_policy() {
        let server = server_with_policy("[security]\nallow_send_keys = false\n");
        let input = Parameters(SendHexInput {
            pane_id: "%1".into(),
            hex: "1b 5b 31 33 3b 32 75".into(),
            socket: None,
        });

        let result = server.send_hex(input).await.expect("send hex");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("send-hex"));
    }

    #[cfg(feature = "interactive")]
    #[tokio::test]
    async fn send_hex_rejects_invalid_token() {
        let server = server_with_policy("[security]\nenabled = false\n");
        let input = Parameters(SendHexInput {
            pane_id: "%1".into(),
            hex: "1b zz".into(),
            socket: None,
        });

        let result = server.send_hex(input).await.expect("send hex");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("invalid hex"));
    }

    #[cfg(feature = "interactive")]
    #[tokio::test]
    async fn send_hex_rejects_line_editing_controls() {
        let server = server_with_policy("[security]\nenabled = false\n");
        let input = Parameters(SendHexInput {
            pane_id: "%1".into(),
            // rx\b m -rf / would become rm -rf / after backspace
            hex: "72 78 08 6d 20 2d 72 66 20 2f 0d".into(),
            socket: None,
        });

        let result = server.send_hex(input).await.expect("send hex");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("line-editing control byte"));
    }

    #[cfg(feature = "special-keys")]
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
            wait_ms: None,
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
    async fn list_resource_templates_respect_policy() {
        let server = server_default();
        let (context, _client_transport, _running) = context_for_server(&server);

        let result = server
            .list_resource_templates(None, context)
            .await
            .expect("list resource templates");

        assert_eq!(result.resource_templates.len(), 9);

        let server = server_with_policy("[security]\nallow_capture = false\nallow_list = false\n");
        let (context, _client_transport, _running) = context_for_server(&server);
        let result = server
            .list_resource_templates(None, context)
            .await
            .expect("list resource templates");
        let templates = result
            .resource_templates
            .iter()
            .map(|template| template.uri_template.as_str())
            .collect::<BTreeSet<_>>();

        assert!(templates.contains("tmux://server/info"));
        assert!(templates.contains("tmux://command/{commandId}/result"));
        assert!(!templates.contains("tmux://pane/{paneId}"));
        assert!(!templates.contains("tmux://pane/{paneId}/info"));
        assert!(!templates.contains("tmux://pane/{paneId}/tail/{lines}"));
        assert!(!templates.contains("tmux://pane/{paneId}/tail/{lines}/ansi"));
        assert!(!templates.contains("tmux://window/{windowId}/info"));
        assert!(!templates.contains("tmux://session/{sessionId}/tree"));
        assert!(!templates.contains("tmux://clients"));

        let server =
            server_with_policy("[security]\nallowed_sockets = [\"/tmp/not-default.sock\"]\n");
        let (context, _client_transport, _running) = context_for_server(&server);
        let result = server
            .list_resource_templates(None, context)
            .await
            .expect("list resource templates");

        assert!(result.resource_templates.is_empty());
    }

    #[tokio::test]
    async fn resource_template_capability_matrix_handles_composite_tool_filters() {
        let deny_windows =
            server_with_policy("[security.tools]\nmode = \"deny\"\nitems = [\"list-windows\"]\n");
        let templates = resource_template_uris(&deny_windows);
        assert!(!templates.contains("tmux://window/{windowId}/info"));
        assert!(!templates.contains("tmux://session/{sessionId}/tree"));
        assert!(templates.contains("tmux://pane/{paneId}"));
        assert!(templates.contains("tmux://clients"));
        assert!(templates.contains("tmux://command/{commandId}/result"));

        let deny_panes =
            server_with_policy("[security.tools]\nmode = \"deny\"\nitems = [\"list-panes\"]\n");
        let templates = resource_template_uris(&deny_panes);
        assert!(templates.contains("tmux://window/{windowId}/info"));
        assert!(!templates.contains("tmux://session/{sessionId}/tree"));
        assert!(templates.contains("tmux://pane/{paneId}"));

        let deny_capture =
            server_with_policy("[security.tools]\nmode = \"deny\"\nitems = [\"capture-pane\"]\n");
        let templates = resource_template_uris(&deny_capture);
        assert!(!templates.iter().any(|uri| uri.starts_with("tmux://pane/")));
        assert!(templates.contains("tmux://window/{windowId}/info"));
        assert!(templates.contains("tmux://session/{sessionId}/tree"));

        let deny_clients_and_commands = server_with_policy(
            "[security.tools]\nmode = \"deny\"\nitems = [\"list-clients\", \"get-command-result\"]\n",
        );
        let templates = resource_template_uris(&deny_clients_and_commands);
        assert!(!templates.contains("tmux://clients"));
        assert!(!templates.contains("tmux://command/{commandId}/result"));

        let topology_only = server_with_policy(
            "[security.tools]\nmode = \"allow\"\nitems = [\"list-sessions\", \"list-windows\", \"list-panes\"]\n",
        );
        let templates = resource_template_uris(&topology_only);
        assert_eq!(
            templates,
            BTreeSet::from([
                "tmux://server/info".to_string(),
                "tmux://session/{sessionId}/tree".to_string(),
                "tmux://window/{windowId}/info".to_string(),
            ])
        );
    }

    #[tokio::test]
    async fn read_window_info_respects_allowed_panes() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_LIST_PANES", "%99\tdisallowed\t1");
        stub.set_var(
            "TMUX_STUB_WINDOW_INFO_OUTPUT",
            "@2\tsecond\t%1\t0\tlayout\t1\t80\t24\t0\t%99",
        );
        let server = server_with_policy("[security]\nallowed_panes = [\"%1\"]\n");
        let (context, _client_transport, _running) = context_for_server(&server);

        let result = server
            .read_resource(
                read_resource_request!(uri: "tmux://window/@2/info".to_string(), meta: None),
                context,
            )
            .await
            .expect("read window info resource");

        let text = first_text_resource(&result.contents);
        assert!(text.contains("Access denied"));
        assert!(text.contains("allowed panes"));
        assert!(!text.contains("%99"));
        assert!(!text.contains("active_pane_id"));
    }

    #[tokio::test]
    async fn resource_reads_enforce_composite_capability_matrix() {
        let _stub = TmuxStub::new();

        let deny_windows =
            server_with_policy("[security.tools]\nmode = \"deny\"\nitems = [\"list-windows\"]\n");
        let text = read_resource_text(&deny_windows, "tmux://window/@1/info").await;
        assert!(text.contains("Access denied"));
        assert!(text.contains("list-windows"));
        let text = read_resource_text(&deny_windows, "tmux://session/%1/tree").await;
        assert!(text.contains("Access denied"));
        assert!(text.contains("list-windows"));

        let deny_panes =
            server_with_policy("[security.tools]\nmode = \"deny\"\nitems = [\"list-panes\"]\n");
        let text = read_resource_text(&deny_panes, "tmux://session/%1/tree").await;
        assert!(text.contains("Access denied"));
        assert!(text.contains("list-panes"));
        let text = read_resource_text(&deny_panes, "tmux://window/@1/info").await;
        assert!(!text.contains("Access denied"));

        let deny_capture =
            server_with_policy("[security.tools]\nmode = \"deny\"\nitems = [\"capture-pane\"]\n");
        let text = read_resource_text(&deny_capture, "tmux://pane/%1/info").await;
        assert!(text.contains("Access denied"));
        assert!(text.contains("capture-pane"));
        let text = read_resource_text(&deny_capture, "tmux://pane/%1/tail/10").await;
        assert!(text.contains("Access denied"));

        let deny_clients =
            server_with_policy("[security.tools]\nmode = \"deny\"\nitems = [\"list-clients\"]\n");
        let text = read_resource_text(&deny_clients, "tmux://clients").await;
        assert!(text.contains("Access denied"));
        assert!(text.contains("list-clients"));

        let topology_only = server_with_policy(
            "[security.tools]\nmode = \"allow\"\nitems = [\"list-sessions\", \"list-windows\", \"list-panes\"]\n",
        );
        let text = read_resource_text(&topology_only, "tmux://session/%1/tree").await;
        assert!(!text.contains("Access denied"));
        let payload: Value = serde_json::from_str(&text).expect("session tree JSON");
        assert!(payload.get("session").is_some());
        let text = read_resource_text(&topology_only, "tmux://pane/%1").await;
        assert!(text.contains("Access denied"));
        assert!(text.contains("capture-pane"));
    }

    #[tokio::test]
    async fn session_tree_fails_closed_for_disallowed_panes() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_LIST_PANES", "%1\tallowed\t1\n%99\tdisallowed\t0");
        let server = server_with_policy("[security]\nallowed_panes = [\"%1\"]\n");

        let text = read_resource_text(&server, "tmux://session/%1/tree").await;
        let payload: Value = serde_json::from_str(&text).expect("session tree JSON");
        assert!(payload["windows"]
            .as_array()
            .expect("windows array")
            .is_empty());
        assert!(!text.contains("%99"));
        assert!(!text.contains("disallowed"));

        let (context, _client_transport, _running) = context_for_server(&server);
        let resources = server
            .list_resources(None, context)
            .await
            .expect("list resources");
        let uris = resource_uris(&resources.resources);
        assert!(!uris.iter().any(|uri| uri.starts_with("tmux://window/")));
        assert!(!uris.iter().any(|uri| uri.starts_with("tmux://session/")));
        assert!(uris.contains("tmux://pane/%1"));
        assert!(!uris.contains("tmux://pane/%99"));

        let no_allowed_sessions = server_with_policy("[security]\nallowed_sessions = []\n");
        let clients = read_resource_text(&no_allowed_sessions, "tmux://clients").await;
        let payload: Value = serde_json::from_str(&clients).expect("clients JSON");
        assert_eq!(payload, Value::Array(Vec::new()));
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

        let result = server
            .socket_for_path(Parameters(SocketForPathInput {
                path: "/workspace".into(),
            }))
            .await
            .expect("socket-for-path");
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn tool_filter_prunes_denied_tools_from_router() {
        let server = server_with_policy(
            "[security.tools]\nmode = \"deny\"\nitems = [\"kill-session\", \"@special-keys\"]\n",
        );
        let names = tool_names(&server);

        assert!(!names.contains("kill-session"));
        #[cfg(feature = "special-keys")]
        assert!(!names.contains("send-enter"));
        assert!(names.contains("execute-command"));
    }

    #[tokio::test]
    async fn tool_filter_allowlist_prunes_router_to_allowed_tools() {
        let server =
            server_with_policy("[security.tools]\nmode = \"allow\"\nitems = [\"list-sessions\"]\n");
        let names = tool_names(&server);

        assert!(names.contains("list-sessions"));
        assert!(!names.contains("execute-command"));
        assert_eq!(names.len(), 1);
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
        let _stub = TmuxStub::new();
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
            .create_session(Parameters(CreateSessionInput {
                name: "agent-sandbox".into(),
                socket: None,
            }))
            .await
            .expect("create session");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("allowed sessions"));

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
    async fn pane_tools_respect_allowed_sessions() {
        let mut stub = TmuxStub::new();
        stub.set_var(
            "TMUX_STUB_CURRENT_SESSION_OUTPUT",
            "%1\t@1\t%1\t1\tpane-one\t/Users\tbash\t80\t24\t1234\t0",
        );
        let server = server_with_policy("[security]\nallowed_sessions = [\"%1\"]\n");

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
    }

    #[tokio::test]
    async fn pane_tools_deny_unlisted_sessions() {
        let mut stub = TmuxStub::new();
        stub.set_var(
            "TMUX_STUB_CURRENT_SESSION_OUTPUT",
            "%1\t@1\t%1\t1\tpane-one\t/Users\tbash\t80\t24\t1234\t0",
        );
        let server = server_with_policy("[security]\nallowed_sessions = [\"%2\"]\n");

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
        assert!(first_text(&result).contains("session '%1' is not in allowed sessions list"));
    }

    #[tokio::test]
    async fn enforce_session_for_pane_re_resolves_after_ssh_target_changes() {
        let mut stub = TmuxStub::new();
        stub.set_var(
            "TMUX_STUB_PANE_INFO_OUTPUT",
            "%1\t@1\t%1\t1\tpane-one\t/tmp\tbash\t80\t24\t1234\t0",
        );
        let server = server_with_policy("[security]\nallowed_sessions = [\"%1\"]\n");

        server
            .enforce_session_for_pane("%1", None)
            .await
            .expect("initial pane session allowed");

        stub.set_var("TMUX_MCP_SSH", "user@example.test");
        stub.set_var(
            "TMUX_STUB_PANE_INFO_OUTPUT",
            "%1\t@9\t%2\t1\tremote-pane\t/tmp\tbash\t80\t24\t1234\t0",
        );

        let err = server
            .enforce_session_for_pane("%1", None)
            .await
            .expect_err("changed ssh target re-resolves pane session");
        assert!(err
            .to_string()
            .contains("session '%2' is not in allowed sessions list"));
    }

    #[tokio::test]
    async fn window_tools_deny_unlisted_sessions() {
        let mut stub = TmuxStub::new();
        stub.set_var(
            "TMUX_STUB_CURRENT_SESSION_OUTPUT",
            "@1\tfirst\t%1\t1\teven-horizontal\t2\t80\t24\t0\t%1",
        );
        let server = server_with_policy("[security]\nallowed_sessions = [\"%2\"]\n");

        let result = server
            .list_panes(Parameters(WindowIdInput {
                window_id: "@1".into(),
                socket: None,
            }))
            .await
            .expect("list panes");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("session '%1' is not in allowed sessions list"));
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
    async fn wait_for_pane_change_tool_denied_by_policy() {
        let server = server_with_policy("[security]\nallow_capture = false\n");

        let result = server
            .wait_for_pane_change(Parameters(WaitForPaneChangeInput {
                pane_id: "%1".into(),
                timeout_ms: Some(50),
                stable_ms: Some(0),
                socket: None,
            }))
            .await
            .expect("wait for pane change");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("wait-for-pane-change"));
    }

    #[tokio::test]
    async fn wait_for_pane_change_pane_gone_errors() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_ERROR_CMD", "capture-pane");
        stub.set_var("TMUX_STUB_ERROR_MSG", "can't find pane: %1");
        let server = server_with_policy("[security]\nallowed_sessions = [\"%1\"]\n");

        let result = server
            .wait_for_pane_change(Parameters(WaitForPaneChangeInput {
                pane_id: "%1".into(),
                timeout_ms: Some(2_000),
                stable_ms: Some(0),
                socket: None,
            }))
            .await
            .expect("wait for pane change");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("can't find pane"));
    }

    #[tokio::test]
    async fn wait_for_pane_change_timeout_is_success() {
        // Static stub screen: the wait times out successfully with no wake.
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_CAPTURE_OUTPUT", "static screen");
        let server = server_with_policy("[security]\nallowed_sessions = [\"%1\"]\n");

        let result = server
            .wait_for_pane_change(Parameters(WaitForPaneChangeInput {
                pane_id: "%1".into(),
                timeout_ms: Some(80),
                stable_ms: Some(0),
                socket: None,
            }))
            .await
            .expect("wait for pane change");
        assert_eq!(result.is_error, Some(false));
        let payload: WaitForPaneChangeOutput = serde_json::from_str(&first_text(&result)).unwrap();
        assert!(!payload.changed);
        assert!(payload.timed_out);
        assert!(payload.waited_ms >= 70);
    }

    #[tokio::test]
    async fn wait_for_pane_change_wakes_on_screen_change() {
        // The stub flips its capture output after the first poll.
        let mut stub = TmuxStub::new();
        let count_dir = tempfile::TempDir::new().expect("count dir");
        let count_file = count_dir
            .path()
            .join("wait-count")
            .to_string_lossy()
            .to_string();
        stub.set_var("TMUX_STUB_CAPTURE_COUNT_FILE", &count_file);
        stub.set_var("TMUX_STUB_CAPTURE_BEFORE", "before");
        stub.set_var("TMUX_STUB_CAPTURE_AFTER", "2");
        stub.set_var("TMUX_STUB_CAPTURE_AFTER_OUTPUT", "after");
        let server = server_with_policy("[security]\nallowed_sessions = [\"%1\"]\n");

        let result = server
            .wait_for_pane_change(Parameters(WaitForPaneChangeInput {
                pane_id: "%1".into(),
                timeout_ms: Some(5_000),
                stable_ms: Some(0),
                socket: None,
            }))
            .await
            .expect("wait for pane change");
        assert_eq!(result.is_error, Some(false));
        let payload: WaitForPaneChangeOutput = serde_json::from_str(&first_text(&result)).unwrap();
        assert!(payload.changed);
        assert!(!payload.timed_out);
    }

    #[tokio::test]
    async fn wait_for_pane_change_rejects_over_ceiling_timeout() {
        let _stub = TmuxStub::new();
        let server = server_with_policy("[security]\nallowed_sessions = [\"%1\"]\n");

        let result = server
            .wait_for_pane_change(Parameters(WaitForPaneChangeInput {
                pane_id: "%1".into(),
                timeout_ms: Some(10_000_000),
                stable_ms: Some(0),
                socket: None,
            }))
            .await
            .expect("wait for pane change");
        assert_eq!(result.is_error, Some(true));
        let text = first_text(&result);
        assert!(
            text.contains("exceeds the configured maximum"),
            "got: {text}"
        );
        assert!(text.contains("600000 ms"));
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

    #[cfg(all(feature = "interactive", feature = "special-keys"))]
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
                enter: None,
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
    async fn kill_pane_success_purges_tracked_commands_for_pane() {
        let _stub = TmuxStub::new();
        let server = server_default();
        let socket_a = "/tmp/tmux-mcp-a.sock";
        let socket_b = "/tmp/tmux-mcp-b.sock";

        let killed_id = server
            .tracker
            .execute_command(
                "%1",
                "echo killed",
                false,
                false,
                None,
                Some(socket_a.into()),
            )
            .await
            .expect("track command for killed pane");
        let kept_id = server
            .tracker
            .execute_command("%1", "echo kept", false, false, None, Some(socket_b.into()))
            .await
            .expect("track command for same pane id on other socket");

        let result = server
            .kill_pane(Parameters(PaneIdInput {
                pane_id: "%1".into(),
                socket: Some(socket_a.into()),
            }))
            .await
            .expect("kill pane");

        assert_eq!(result.is_error, Some(false));
        assert!(server.tracker.get_command(&killed_id).await.is_none());
        assert!(server.tracker.get_command(&kept_id).await.is_some());
    }

    #[tokio::test]
    async fn kill_pane_tmux_failure_does_not_purge_tracked_commands() {
        let mut stub = TmuxStub::new();
        let server = server_default();
        let id = server
            .tracker
            .execute_command("%1", "echo still tracked", false, false, None, None)
            .await
            .expect("track command");

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
        assert!(server.tracker.get_command(&id).await.is_some());
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
                wait_ms: None,
            }))
            .await
            .expect("execute command");
        assert_eq!(result.is_error, Some(true));

        let result = server
            .get_command_result(Parameters(GetCommandResultInput {
                command_id: "cmd".into(),
                socket: None,
                wait_ms: None,
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
                wait_ms: None,
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
                wait_ms: None,
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
                wait_ms: None,
            }))
            .await
            .expect("execute command");
        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Error executing command"));
    }

    #[tokio::test]
    async fn get_command_result_tmux_error() {
        let _stub = TmuxStub::new();
        let server = server_default();

        let result = server
            .execute_command(Parameters(ExecuteCommandInput {
                pane_id: "%1".into(),
                command: "echo hi".into(),
                raw_mode: None,
                no_enter: None,
                delay_ms: None,
                socket: None,
                wait_ms: None,
            }))
            .await
            .expect("execute command");
        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        let command_id = payload["commandId"].as_str().unwrap();

        let result = server
            .get_command_result(Parameters(GetCommandResultInput {
                command_id: command_id.to_string(),
                socket: None,
                wait_ms: Some(5_000),
            }))
            .await
            .expect("get command result");
        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(payload["status"], "completed");
    }

    #[tokio::test]
    async fn get_command_result_rejects_mismatched_socket_override_when_default_recorded() {
        let mut stub = TmuxStub::new();
        stub.remove_var("TMUX_MCP_SOCKET");
        let server = server_default();

        let result = server
            .execute_command(Parameters(ExecuteCommandInput {
                pane_id: "%1".into(),
                command: "echo hi".into(),
                raw_mode: None,
                no_enter: None,
                delay_ms: None,
                socket: None,
                wait_ms: None,
            }))
            .await
            .expect("execute command");
        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        let command_id = payload["commandId"].as_str().unwrap();

        let result = server
            .get_command_result(Parameters(GetCommandResultInput {
                command_id: command_id.to_string(),
                socket: Some("/tmp/override.sock".into()),
                wait_ms: None,
            }))
            .await
            .expect("get command result");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Socket override does not match"));
    }

    #[tokio::test]
    async fn get_command_result_rejects_mismatched_socket_override() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_MCP_SOCKET", "/tmp/recorded.sock");
        let server = server_default();

        let result = server
            .execute_command(Parameters(ExecuteCommandInput {
                pane_id: "%1".into(),
                command: "echo hi".into(),
                raw_mode: None,
                no_enter: None,
                delay_ms: None,
                socket: None,
                wait_ms: None,
            }))
            .await
            .expect("execute command");
        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        let command_id = payload["commandId"].as_str().unwrap();

        let result = server
            .get_command_result(Parameters(GetCommandResultInput {
                command_id: command_id.to_string(),
                socket: Some("/tmp/other.sock".into()),
                wait_ms: None,
            }))
            .await
            .expect("get command result");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Socket override does not match"));
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
    async fn get_current_session_respects_allowed_sessions() {
        let _stub = TmuxStub::new();
        let server = server_with_policy("[security]\nallowed_sessions = [\"%2\"]\n");

        let result = server
            .get_current_session(Parameters(SocketInput { socket: None }))
            .await
            .expect("get current session");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("session '%1' is not in allowed sessions list"));
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

    #[cfg(feature = "interactive")]
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
                enter: None,
                repeat: None,
                delay_ms: None,
                socket: None,
            }))
            .await
            .expect("send keys");
        assert_eq!(result.is_error, Some(true));
    }

    #[cfg(feature = "interactive")]
    #[tokio::test]
    async fn send_keys_literal_command_denied() {
        let server = server_with_policy(
            "[security]\ncommand_filter = { mode = \"denylist\", patterns = [\"rm -rf\"] }\n",
        );

        let result = server
            .send_keys(Parameters(SendKeysInput {
                pane_id: "%1".into(),
                keys: "rm -rf /important".into(),
                literal: Some(true),
                enter: Some(true),
                repeat: None,
                delay_ms: None,
                socket: None,
            }))
            .await
            .expect("send keys");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("in the denylist"));
    }

    #[cfg(feature = "interactive")]
    #[tokio::test]
    async fn send_keys_literal_command_allowed_when_filter_passes() {
        let _stub = TmuxStub::new();
        let server = server_with_policy(
            "[security]\ncommand_filter = { mode = \"denylist\", patterns = [\"rm -rf\"] }\n",
        );

        let result = server
            .send_keys(Parameters(SendKeysInput {
                pane_id: "%1".into(),
                keys: "printf ok".into(),
                literal: Some(true),
                enter: Some(true),
                repeat: None,
                delay_ms: None,
                socket: None,
            }))
            .await
            .expect("send keys");

        assert_eq!(result.is_error, Some(false));
    }

    #[cfg(feature = "interactive")]
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
                enter: None,
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
                enter: None,
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
                enter: None,
                repeat: None,
                delay_ms: None,
                socket: None,
            }))
            .await
            .expect("send keys");
        assert_eq!(result.is_error, Some(true));
    }

    #[cfg(feature = "special-keys")]
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
        assert_eq!(
            resource_uris(&result.resources),
            BTreeSet::from([
                "tmux://clients".to_string(),
                "tmux://server/info".to_string(),
            ])
        );

        let server = server_with_policy("[security]\nallowed_panes = []\n");
        let (context, _client_transport, _running) = context_for_server(&server);
        let result = server
            .list_resources(None, context)
            .await
            .expect("list resources");
        assert_eq!(
            resource_uris(&result.resources),
            BTreeSet::from([
                "tmux://clients".to_string(),
                "tmux://server/info".to_string(),
            ])
        );
    }

    #[tokio::test]
    async fn list_resources_enforces_composite_capability_matrix() {
        let _stub = TmuxStub::new();

        let deny_windows =
            server_with_policy("[security.tools]\nmode = \"deny\"\nitems = [\"list-windows\"]\n");
        let (context, _client_transport, _running) = context_for_server(&deny_windows);
        let resources = deny_windows
            .list_resources(None, context)
            .await
            .expect("list resources");
        let uris = resource_uris(&resources.resources);
        assert_eq!(
            uris,
            BTreeSet::from([
                "tmux://clients".to_string(),
                "tmux://server/info".to_string(),
            ])
        );

        let deny_panes =
            server_with_policy("[security.tools]\nmode = \"deny\"\nitems = [\"list-panes\"]\n");
        let (context, _client_transport, _running) = context_for_server(&deny_panes);
        let resources = deny_panes
            .list_resources(None, context)
            .await
            .expect("list resources");
        let uris = resource_uris(&resources.resources);
        assert!(uris.iter().any(|uri| uri.starts_with("tmux://window/")));
        assert!(!uris.iter().any(|uri| uri.starts_with("tmux://pane/")));
        assert!(!uris.iter().any(|uri| uri.starts_with("tmux://session/")));

        let deny_capture =
            server_with_policy("[security.tools]\nmode = \"deny\"\nitems = [\"capture-pane\"]\n");
        let (context, _client_transport, _running) = context_for_server(&deny_capture);
        let resources = deny_capture
            .list_resources(None, context)
            .await
            .expect("list resources");
        let uris = resource_uris(&resources.resources);
        assert!(uris.iter().any(|uri| uri.starts_with("tmux://window/")));
        assert!(uris.iter().any(|uri| uri.starts_with("tmux://session/")));
        assert!(!uris.iter().any(|uri| uri.starts_with("tmux://pane/")));

        let topology_only = server_with_policy(
            "[security.tools]\nmode = \"allow\"\nitems = [\"list-sessions\", \"list-windows\", \"list-panes\"]\n",
        );
        let (context, _client_transport, _running) = context_for_server(&topology_only);
        let resources = topology_only
            .list_resources(None, context)
            .await
            .expect("list resources");
        let uris = resource_uris(&resources.resources);
        assert!(uris.iter().any(|uri| uri.starts_with("tmux://window/")));
        assert!(uris.iter().any(|uri| uri.starts_with("tmux://session/")));
        assert!(!uris.contains("tmux://clients"));
        assert!(!uris.iter().any(|uri| uri.starts_with("tmux://pane/")));
        assert!(!uris.iter().any(|uri| uri.starts_with("tmux://command/")));
    }

    #[tokio::test]
    async fn list_resources_keeps_clients_and_commands_independent_from_topology() {
        let _stub = TmuxStub::new();
        let server =
            server_with_policy("[security.tools]\nmode = \"deny\"\nitems = [\"list-sessions\"]\n");
        let result = server
            .execute_command(Parameters(ExecuteCommandInput {
                pane_id: "%1".into(),
                command: "echo hi".into(),
                raw_mode: None,
                no_enter: None,
                delay_ms: None,
                wait_ms: None,
                socket: None,
            }))
            .await
            .expect("execute command");
        let payload: Value = serde_json::from_str(&first_text(&result)).expect("command payload");
        let command_uri = payload["resourceUri"]
            .as_str()
            .expect("command resource URI");

        let (context, _client_transport, _running) = context_for_server(&server);
        let resources = server
            .list_resources(None, context)
            .await
            .expect("list resources");
        let uris = resource_uris(&resources.resources);
        assert!(uris.contains("tmux://server/info"));
        assert!(uris.contains("tmux://clients"));
        assert!(uris.contains(command_uri));
        assert!(!uris.iter().any(|uri| uri.starts_with("tmux://pane/")));
        assert!(!uris.iter().any(|uri| uri.starts_with("tmux://window/")));
        assert!(!uris.iter().any(|uri| uri.starts_with("tmux://session/")));

        let deny_command = server_with_policy(
            "[security.tools]\nmode = \"deny\"\nitems = [\"get-command-result\"]\n",
        );
        deny_command
            .tracker
            .execute_command("%1", "echo hi", false, false, None, None)
            .await
            .expect("track command");
        let (context, _client_transport, _running) = context_for_server(&deny_command);
        let resources = deny_command
            .list_resources(None, context)
            .await
            .expect("list resources");
        assert!(!resource_uris(&resources.resources)
            .iter()
            .any(|uri| uri.starts_with("tmux://command/")));
    }

    #[tokio::test]
    async fn list_resources_returns_error_when_sessions_fail() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_ERROR_CMD", "list-sessions");
        stub.set_var("TMUX_STUB_ERROR_MSG", "sessions-fail");
        let server = server_default();
        let (context, _client_transport, _running) = context_for_server(&server);

        let error = server
            .list_resources(None, context)
            .await
            .expect_err("list resources should fail");

        assert!(error.message.contains("Error listing tmux sessions"));
        assert!(error.message.contains("sessions-fail"));
    }

    #[tokio::test]
    async fn list_resources_returns_error_when_nested_windows_or_panes_fail() {
        let mut stub = TmuxStub::new();
        let server = server_default();

        stub.set_var("TMUX_STUB_ERROR_CMD", "list-windows");
        stub.set_var("TMUX_STUB_ERROR_MSG", "windows-fail");
        let (context, _client_transport, _running) = context_for_server(&server);
        let error = server
            .list_resources(None, context)
            .await
            .expect_err("list resources should fail");
        assert!(error.message.contains("Error listing tmux windows"));
        assert!(error.message.contains("windows-fail"));

        stub.set_var("TMUX_STUB_ERROR_CMD", "list-panes");
        stub.set_var("TMUX_STUB_ERROR_MSG", "panes-fail");
        let (context, _client_transport, _running) = context_for_server(&server);
        let error = server
            .list_resources(None, context)
            .await
            .expect_err("list resources should fail");
        assert!(error.message.contains("Error listing tmux panes"));
        assert!(error.message.contains("panes-fail"));
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
        assert!(result.resources.is_empty());
    }

    #[tokio::test]
    async fn list_resources_hides_pane_uris_when_capture_denied() {
        let _stub = TmuxStub::new();

        let server =
            server_with_policy("[security]\nallow_capture = false\nallowed_panes = [\"%1\"]\n");
        let (context, _client_transport, _running) = context_for_server(&server);
        let result = server
            .list_resources(None, context)
            .await
            .expect("list resources");

        assert!(!result
            .resources
            .iter()
            .any(|res| res.uri.starts_with("tmux://pane/")));
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
    async fn list_resources_lists_command_catalog_from_memory() {
        let _stub = TmuxStub::new();
        let server = server_default();
        let command_id = server
            .tracker
            .execute_command("%1", "echo hi", false, false, None, None)
            .await
            .expect("execute command");
        let _ = server.tracker.wait_for(&command_id, 5_000).await;
        let (context, _client_transport, _running) = context_for_server(&server);

        let result = server
            .list_resources(None, context)
            .await
            .expect("list resources");

        let resource = result
            .resources
            .iter()
            .find(|res| res.uri == format!("tmux://command/{command_id}/result"))
            .expect("command resource");
        assert_eq!(
            resource.description.as_deref(),
            Some("Tracked command status: completed. Subscribe for updates; read for snapshot.")
        );
        assert_eq!(resource.mime_type.as_deref(), Some("application/json"));
        let command = server
            .tracker
            .get_command(&command_id)
            .await
            .expect("stored command");
        assert!(matches!(command.status, CommandStatus::Completed));
    }

    #[tokio::test]
    async fn read_resource_pane_error() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_ERROR_CMD", "capture-pane");
        stub.set_var("TMUX_STUB_ERROR_MSG", "capture-fail");
        let server = server_default();
        let (context, _client_transport, _running) = context_for_server(&server);
        let request = read_resource_request! {
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
        let request = read_resource_request! {
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
    async fn read_server_info_denied_by_socket_policy() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_MCP_SOCKET", "/tmp/disallowed.sock");
        let server = server_with_policy("[security]\nallowed_sockets = [\"/tmp/allowed.sock\"]\n");
        let (context, _client_transport, _running) = context_for_server(&server);
        let request = read_resource_request! {
            uri: "tmux://server/info".into(),
            meta: None,
        };

        let result = server
            .read_resource(request, context)
            .await
            .expect("read resource");
        let text = first_text_resource(&result.contents);
        assert!(text.contains("Access denied"));
        assert!(!text.contains("\"default_socket\""));
        assert!(!text.contains("\"ssh\""));
    }

    #[tokio::test]
    async fn read_resource_command_pending_and_error() {
        let _stub = TmuxStub::new();
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
            wait_ms: None,
        });
        let result = server.execute_command(execute).await.unwrap();
        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        let command_id = payload["commandId"].as_str().unwrap();

        let request = read_resource_request! {
            uri: format!("tmux://command/{command_id}/result"),
            meta: None,
        };
        let result = server
            .read_resource(request, context2)
            .await
            .expect("read resource");
        let payload: Value = serde_json::from_str(first_text_resource(&result.contents)).unwrap();
        assert_eq!(payload["status"], "running");

        let execute = Parameters(ExecuteCommandInput {
            pane_id: "%1".into(),
            command: "echo hi".into(),
            raw_mode: None,
            no_enter: None,
            delay_ms: None,
            socket: None,
            wait_ms: Some(5_000),
        });
        let result = server.execute_command(execute).await.unwrap();
        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        let command_id = payload["commandId"].as_str().unwrap();

        let request = read_resource_request! {
            uri: format!("tmux://command/{command_id}/result"),
            meta: None,
        };
        let result = server
            .read_resource(request, context3)
            .await
            .expect("read resource");
        let payload: Value = serde_json::from_str(first_text_resource(&result.contents)).unwrap();
        assert_eq!(payload["status"], "completed");
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
    async fn list_panes_respects_allowed_panes() {
        let mut stub = TmuxStub::new();
        stub.set_var(
            "TMUX_STUB_LIST_PANES",
            "%1\tpane-one\t1\n%2\tpane-two\t0\n%3\tpane-three\t0",
        );
        let server = server_with_policy("[security]\nallowed_panes = [\"%1\"]\n");
        let input = Parameters(WindowIdInput {
            window_id: "@1".into(),
            socket: None,
        });

        let result = server.list_panes(input).await.expect("list panes");

        assert_eq!(result.is_error, Some(false));
        let payload: ListPanesOutput = serde_json::from_str(&first_text(&result)).unwrap();
        let pane_ids: Vec<&str> = payload.panes.iter().map(|pane| pane.id.as_str()).collect();
        assert_eq!(pane_ids, vec!["%1"]);
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

    #[cfg(feature = "interactive")]
    #[tokio::test]
    async fn send_keys_variants_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();

        let literal = Parameters(SendKeysInput {
            pane_id: "%1".into(),
            keys: "hi".into(),
            literal: Some(true),
            enter: None,
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
            enter: None,
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
            enter: None,
            repeat: None,
            delay_ms: None,
            socket: None,
        });
        let result = server.send_keys(immediate).await.expect("send keys");
        assert_eq!(result.is_error, Some(false));
    }

    #[cfg(feature = "interactive")]
    #[tokio::test]
    async fn send_keys_enter_flag_sends_enter() {
        let mut stub = TmuxStub::new();
        let log = NamedTempFile::new().expect("create log file");
        stub.set_var("TMUX_STUB_SEND_KEYS_LOG", log.path());
        let server = server_default();

        let result = server
            .send_keys(Parameters(SendKeysInput {
                pane_id: "%1".into(),
                keys: "ls".into(),
                literal: Some(false),
                enter: Some(true),
                repeat: None,
                delay_ms: None,
                socket: None,
            }))
            .await
            .expect("send keys");
        assert_eq!(result.is_error, Some(false));

        let logged = std::fs::read_to_string(log.path()).expect("read send-keys log");
        assert!(
            logged.contains("ls"),
            "expected payload send, got: {logged}"
        );
        assert!(
            logged.contains("Enter"),
            "expected Enter send, got: {logged}"
        );
    }

    #[cfg(feature = "interactive")]
    #[tokio::test]
    async fn paste_text_denied_by_policy() {
        let server = server_with_policy("[security]\nallow_send_keys = false\n");
        let result = server
            .paste_text(Parameters(PasteTextInput {
                pane_id: "%1".into(),
                content: "hello".into(),
                socket: None,
            }))
            .await
            .expect("paste text");
        assert_eq!(result.is_error, Some(true));
    }

    #[cfg(feature = "interactive")]
    #[tokio::test]
    async fn paste_text_command_denied_by_policy() {
        let server = server_with_policy(
            "[security]\ncommand_filter = { mode = \"denylist\", patterns = [\"blocked\"] }\n",
        );
        let result = server
            .paste_text(Parameters(PasteTextInput {
                pane_id: "%1".into(),
                content: "blocked".into(),
                socket: None,
            }))
            .await
            .expect("paste text");
        assert_eq!(result.is_error, Some(true));
    }

    #[cfg(feature = "interactive")]
    #[tokio::test]
    async fn paste_text_multiline_command_denied_by_policy() {
        let server = server_with_policy(
            "[security]\ncommand_filter = { mode = \"denylist\", patterns = [\"^rm \"] }\n",
        );
        let result = server
            .paste_text(Parameters(PasteTextInput {
                pane_id: "%1".into(),
                content: "echo ok\nrm -rf /".into(),
                socket: None,
            }))
            .await
            .expect("paste text");
        assert_eq!(result.is_error, Some(true));
    }

    #[cfg(feature = "interactive")]
    #[tokio::test]
    async fn paste_text_happy_path() {
        let _stub = TmuxStub::new();
        let server = server_default();
        let result = server
            .paste_text(Parameters(PasteTextInput {
                pane_id: "%1".into(),
                content: "line1\nline2\n".into(),
                socket: None,
            }))
            .await
            .expect("paste text");
        assert_eq!(result.is_error, Some(false));
        assert!(first_text(&result).contains("Pasted text"));
    }

    #[cfg(feature = "interactive")]
    #[tokio::test]
    async fn paste_text_uses_bracketed_paste_flags() {
        let mut stub = TmuxStub::new();
        let log = NamedTempFile::new().expect("create paste-buffer log");
        stub.set_var("TMUX_STUB_PASTE_BUFFER_LOG", log.path());
        let server = server_default();

        let result = server
            .paste_text(Parameters(PasteTextInput {
                pane_id: "%1".into(),
                content: "line1\nline2\n".into(),
                socket: None,
            }))
            .await
            .expect("paste text");
        assert_eq!(result.is_error, Some(false));

        let logged = std::fs::read_to_string(log.path()).expect("read paste-buffer log");
        assert!(
            logged.contains("paste-buffer"),
            "expected paste-buffer call, got: {logged}"
        );
        assert!(
            logged.contains("-p"),
            "expected bracketed flag -p, got: {logged}"
        );
        assert!(
            logged.contains("-d"),
            "expected delete flag -d, got: {logged}"
        );
        assert!(logged.contains("%1"), "expected target pane, got: {logged}");
    }

    #[cfg(all(feature = "interactive", feature = "special-keys"))]
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
            wait_ms: None,
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
                wait_ms: Some(5_000),
            }))
            .await
            .expect("get command result");

        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(payload["status"], "completed");
        assert_eq!(payload["exitCode"], 0);
        assert!(payload.get("resourceUri").is_some());
    }

    #[tokio::test]
    async fn execute_and_get_command_result_error_status_is_mcp_error() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_EXIT_CODE", "7");
        let server = server_default();
        let input = Parameters(ExecuteCommandInput {
            pane_id: "%1".into(),
            command: "false".into(),
            raw_mode: None,
            no_enter: None,
            delay_ms: None,
            socket: None,
            wait_ms: None,
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
                wait_ms: Some(5_000),
            }))
            .await
            .expect("get command result");

        assert_eq!(result.is_error, Some(true));
        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(payload["status"], "failed");
        assert_eq!(payload["exitCode"], 7);
        assert_eq!(payload["command"], "false");
        assert_eq!(result.structured_content, Some(payload));
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
            wait_ms: None,
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
                wait_ms: None,
            }))
            .await
            .expect("get command result");

        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        assert_eq!(payload["status"], "running");
        assert!(payload.get("output").is_some());
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
            wait_ms: None,
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
        let request = read_resource_request! {
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
            wait_ms: Some(5_000),
        });
        let result = server.execute_command(execute).await.unwrap();
        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        let command_id = payload["commandId"].as_str().unwrap();

        let request = read_resource_request! {
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
        let request = read_resource_request! {
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
        let request = read_resource_request! {
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
        let request = read_resource_request! {
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
        let request = read_resource_request! {
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
                wait_ms: None,
            }))
            .await
            .expect("get command result");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("Access denied"));
    }

    #[tokio::test]
    async fn get_command_result_denied_for_unlisted_session() {
        let mut stub = TmuxStub::new();
        stub.set_var(
            "TMUX_STUB_PANE_INFO_OUTPUT",
            "%1\t@1\t%1\t1\tpane-one\t/tmp\tbash\t80\t24\t1234\t0",
        );
        let server = server_with_policy("[security]\nallowed_sessions = [\"%2\"]\n");

        let command_id = server
            .tracker
            .execute_command("%1", "echo hi", false, false, None, None)
            .await
            .expect("execute command");

        let result = server
            .get_command_result(Parameters(GetCommandResultInput {
                command_id,
                socket: None,
                wait_ms: None,
            }))
            .await
            .expect("get command result");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("session '%1' is not in allowed sessions list"));
    }

    #[tokio::test]
    async fn get_command_result_denies_session_changed_after_execute() {
        let mut stub = TmuxStub::new();
        stub.set_var(
            "TMUX_STUB_PANE_INFO_OUTPUT",
            "%1\t@1\t%1\t1\tpane-one\t/tmp\tbash\t80\t24\t1234\t0",
        );
        let server = server_with_policy("[security]\nallowed_sessions = [\"%1\"]\n");

        let result = server
            .execute_command(Parameters(ExecuteCommandInput {
                pane_id: "%1".into(),
                command: "echo hi".into(),
                raw_mode: None,
                no_enter: None,
                delay_ms: None,
                socket: None,
                wait_ms: None,
            }))
            .await
            .expect("execute command");
        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        let command_id = payload["commandId"].as_str().unwrap();

        stub.set_var(
            "TMUX_STUB_PANE_INFO_OUTPUT",
            "%1\t@1\t%2\t1\tpane-one\t/tmp\tbash\t80\t24\t1234\t0",
        );

        let result = server
            .get_command_result(Parameters(GetCommandResultInput {
                command_id: command_id.to_string(),
                socket: None,
                wait_ms: None,
            }))
            .await
            .expect("get command result");

        assert_eq!(result.is_error, Some(true));
        assert!(first_text(&result).contains("session '%2' is not in allowed sessions list"));
    }

    #[tokio::test]
    async fn read_resource_pane_denied_by_capture_policy() {
        let _stub = TmuxStub::new();
        let server = server_with_policy("[security]\nallow_capture = false\n");
        let (context, _client_transport, _running) = context_for_server(&server);
        let request = read_resource_request! {
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
        let server = server_with_policy(
            "[security.tools]\nmode = \"deny\"\nitems = [\"get-command-result\"]\n",
        );
        let (context, _client_transport, _running) = context_for_server(&server);

        let command_id = server
            .tracker
            .execute_command("%1", "echo hi", false, false, None, None)
            .await
            .expect("execute command");

        let request = read_resource_request! {
            uri: format!("tmux://command/{command_id}/result"),
            meta: None,
        };
        let result = server
            .read_resource(request, context)
            .await
            .expect("read resource");
        let text = first_text_resource(&result.contents);
        assert!(text.contains("Access denied"));
        assert!(text.contains("get-command-result"));
    }

    #[tokio::test]
    async fn read_resource_command_denied_for_unlisted_session() {
        let mut stub = TmuxStub::new();
        stub.set_var(
            "TMUX_STUB_PANE_INFO_OUTPUT",
            "%1\t@1\t%1\t1\tpane-one\t/tmp\tbash\t80\t24\t1234\t0",
        );
        let server = server_with_policy("[security]\nallowed_sessions = [\"%2\"]\n");
        let (context, _client_transport, _running) = context_for_server(&server);

        let command_id = server
            .tracker
            .execute_command("%1", "echo hi", false, false, None, None)
            .await
            .expect("execute command");

        let request = read_resource_request! {
            uri: format!("tmux://command/{command_id}/result"),
            meta: None,
        };
        let result = server
            .read_resource(request, context)
            .await
            .expect("read resource");
        let text = first_text_resource(&result.contents);
        assert!(text.contains("Access denied"));
        assert!(text.contains("session '%1' is not in allowed sessions list"));
    }

    #[tokio::test]
    async fn read_resource_command_denies_session_changed_after_execute() {
        let mut stub = TmuxStub::new();
        stub.set_var(
            "TMUX_STUB_PANE_INFO_OUTPUT",
            "%1\t@1\t%1\t1\tpane-one\t/tmp\tbash\t80\t24\t1234\t0",
        );
        let server = server_with_policy("[security]\nallowed_sessions = [\"%1\"]\n");
        let (context, _client_transport, _running) = context_for_server(&server);

        let result = server
            .execute_command(Parameters(ExecuteCommandInput {
                pane_id: "%1".into(),
                command: "echo hi".into(),
                raw_mode: None,
                no_enter: None,
                delay_ms: None,
                socket: None,
                wait_ms: None,
            }))
            .await
            .expect("execute command");
        let payload: Value = serde_json::from_str(&first_text(&result)).unwrap();
        let command_id = payload["commandId"].as_str().unwrap();

        stub.set_var(
            "TMUX_STUB_PANE_INFO_OUTPUT",
            "%1\t@1\t%2\t1\tpane-one\t/tmp\tbash\t80\t24\t1234\t0",
        );

        let request = read_resource_request! {
            uri: format!("tmux://command/{command_id}/result"),
            meta: None,
        };
        let result = server
            .read_resource(request, context)
            .await
            .expect("read resource");
        let text = first_text_resource(&result.contents);
        assert!(text.contains("Access denied"));
        assert!(text.contains("session '%2' is not in allowed sessions list"));
    }

    #[tokio::test]
    async fn read_resource_command_denied_by_socket_policy() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_MCP_SOCKET", "/tmp/recorded.sock");
        let server = server_with_policy("[security]\nallowed_sockets = [\"/tmp/allowed.sock\"]\n");
        let (context, _client_transport, _running) = context_for_server(&server);

        let command_id = server
            .tracker
            .execute_command("%1", "echo hi", false, false, None, None)
            .await
            .expect("execute command");

        let request = read_resource_request! {
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
