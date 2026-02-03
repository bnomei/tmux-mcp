#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::Stdio;

use once_cell::sync::Lazy;
use regex::Regex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Semaphore;

use crate::errors::{Error, Result};
use crate::types::{
    BufferInfo, BufferSearchMatch, BufferSearchOutput, ClientInfo, Pane, PaneInfo, SearchMode,
    Session, Window, WindowInfo,
};

const TMUX_MAX_CONCURRENCY: usize = 8;
const DEFAULT_SHOW_MAX_BYTES: u64 = 65_536;
const DEFAULT_SEARCH_CONTEXT_BYTES: u32 = 40;
const DEFAULT_SEARCH_MAX_MATCHES: u32 = 50;
const DEFAULT_SEARCH_MAX_SCAN_BYTES: u64 = 65_536;
const APPEND_INLINE_MAX_BYTES: u64 = 262_144;
const PARALLEL_BUFFER_THRESHOLD: usize = 10;
const FUZZY_MAX_LINE_BYTES: usize = 4_096;

static TMUX_SEMAPHORE: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(TMUX_MAX_CONCURRENCY));

#[derive(Clone)]
struct BufferText {
    name: String,
    text: String,
    base_offset: usize,
    full_len: usize,
}

/// Options for buffer search operations.
#[derive(Clone, Debug, Default)]
pub struct SearchOptions {
    pub context_bytes: Option<u32>,
    pub max_matches: Option<u32>,
    pub max_scan_bytes: Option<u64>,
    pub include_similarity: bool,
    pub fuzzy_match: bool,
    pub similarity_threshold: Option<f32>,
    pub resume_from_offset: Option<BTreeMap<String, u64>>,
}

/// Options for anchor-scoped subsearch.
#[derive(Clone, Debug)]
pub struct SubsearchOptions {
    pub context_bytes: u32,
    pub max_matches: Option<u32>,
    pub include_similarity: bool,
    pub fuzzy_match: bool,
    pub similarity_threshold: Option<f32>,
    pub resume_from_offset: Option<u64>,
}

struct BufferScanResult {
    name: String,
    matches: Vec<BufferSearchMatch>,
    scan_end: usize,
    truncated_by_scan: bool,
    fuzzy_skipped_lines: u32,
    fuzzy_skipped_bytes: u64,
}

/// Resolve the tmux socket path from an override or environment variable.
pub fn resolve_socket(socket: Option<&str>) -> Option<String> {
    if let Some(socket) = socket {
        if socket.is_empty() {
            return None;
        }
        return Some(socket.to_string());
    }
    match std::env::var("TMUX_MCP_SOCKET") {
        Ok(socket) if !socket.is_empty() => Some(socket),
        _ => None,
    }
}

/// Get socket arguments for tmux commands.
fn get_socket_args(socket: Option<&str>) -> Vec<String> {
    match resolve_socket(socket) {
        Some(socket) => vec!["-S".to_string(), socket],
        None => vec![],
    }
}

/// Get SSH arguments for tmux commands.
/// If TMUX_MCP_SSH is set, returns parsed args (e.g. ["-i", "key", "user@host"]).
fn get_ssh_args() -> Result<Option<Vec<String>>> {
    match std::env::var("TMUX_MCP_SSH") {
        Ok(value) if !value.trim().is_empty() => {
            let parts = shell_words::split(&value).map_err(|e| Error::InvalidArgument {
                message: format!("invalid TMUX_MCP_SSH: {e}"),
            })?;
            if parts.is_empty() {
                Ok(None)
            } else {
                Ok(Some(parts))
            }
        }
        _ => Ok(None),
    }
}

fn ssh_enabled() -> Result<bool> {
    Ok(get_ssh_args()?.is_some())
}

async fn run_tmux_with_socket(
    args: &[&str],
    socket: Option<&str>,
    stdin: Option<&[u8]>,
) -> Result<std::process::Output> {
    let _permit = TMUX_SEMAPHORE.acquire().await.map_err(|e| Error::Tmux {
        message: format!("tmux semaphore closed: {e}"),
    })?;

    let socket_args = get_socket_args(socket);
    let ssh_args = get_ssh_args()?;

    let mut command = if let Some(mut ssh_args) = ssh_args {
        ssh_args.push("tmux".to_string());
        ssh_args.extend(socket_args);
        ssh_args.extend(args.iter().map(|arg| (*arg).to_string()));
        let mut cmd = Command::new("ssh");
        cmd.args(&ssh_args);
        cmd
    } else {
        let mut tmux_args = socket_args;
        tmux_args.extend(args.iter().map(|arg| (*arg).to_string()));
        let mut cmd = Command::new("tmux");
        cmd.args(&tmux_args);
        cmd
    };

    let output = if let Some(input) = stdin {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::Tmux {
                message: format!("failed to spawn tmux: {e}"),
            })?;
        if let Some(mut child_stdin) = child.stdin.take() {
            child_stdin
                .write_all(input)
                .await
                .map_err(|e| Error::Tmux {
                    message: format!("failed to write tmux stdin: {e}"),
                })?;
        }
        child.wait_with_output().await.map_err(|e| Error::Tmux {
            message: format!("failed to wait for tmux: {e}"),
        })?
    } else {
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| Error::Tmux {
                message: format!("failed to spawn tmux: {e}"),
            })?
    };

    Ok(output)
}

async fn execute_tmux_with_socket_bytes(
    args: &[&str],
    socket: Option<&str>,
    stdin: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let output = run_tmux_with_socket(args, socket, stdin).await?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(Error::Tmux { message: stderr })
    }
}

async fn execute_tmux_with_socket_to_file(
    args: &[&str],
    socket: Option<&str>,
    path: &Path,
) -> Result<()> {
    let _permit = TMUX_SEMAPHORE.acquire().await.map_err(|e| Error::Tmux {
        message: format!("tmux semaphore closed: {e}"),
    })?;

    let socket_args = get_socket_args(socket);
    let ssh_args = get_ssh_args()?;
    let mut command = if let Some(mut ssh_args) = ssh_args {
        ssh_args.push("tmux".to_string());
        ssh_args.extend(socket_args);
        ssh_args.extend(args.iter().map(|arg| (*arg).to_string()));
        let mut cmd = Command::new("ssh");
        cmd.args(&ssh_args);
        cmd
    } else {
        let mut tmux_args = socket_args;
        tmux_args.extend(args.iter().map(|arg| (*arg).to_string()));
        let mut cmd = Command::new("tmux");
        cmd.args(&tmux_args);
        cmd
    };

    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Tmux {
            message: format!("failed to spawn tmux: {e}"),
        })?;

    let stdout = child.stdout.take().ok_or_else(|| Error::Tmux {
        message: "failed to capture tmux stdout".to_string(),
    })?;
    let stderr = child.stderr.take().ok_or_else(|| Error::Tmux {
        message: "failed to capture tmux stderr".to_string(),
    })?;

    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(|e| Error::Tmux {
            message: format!("failed to create temp buffer file: {e}"),
        })?;

    let stdout_task = tokio::spawn(async move {
        tokio::io::copy(&mut tokio::io::BufReader::new(stdout), &mut file).await
    });
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let mut reader = tokio::io::BufReader::new(stderr);
        reader.read_to_end(&mut buf).await?;
        Ok::<Vec<u8>, std::io::Error>(buf)
    });

    let status = child.wait().await.map_err(|e| Error::Tmux {
        message: format!("failed to wait for tmux: {e}"),
    })?;

    let stdout_result = stdout_task.await.map_err(|e| Error::Tmux {
        message: format!("failed to drain tmux stdout: {e}"),
    })?;
    stdout_result.map_err(|e| Error::Tmux {
        message: format!("failed to write temp buffer file: {e}"),
    })?;

    let stderr_bytes = stderr_task
        .await
        .map_err(|e| Error::Tmux {
            message: format!("failed to drain tmux stderr: {e}"),
        })?
        .map_err(|e| Error::Tmux {
            message: format!("failed to read tmux stderr: {e}"),
        })?;

    if status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&stderr_bytes).trim().to_string();
        Err(Error::Tmux { message: stderr })
    }
}

/// Execute a tmux command with the given arguments and return stdout.
pub async fn execute_tmux_with_socket(args: &[&str], socket: Option<&str>) -> Result<String> {
    let stdout = execute_tmux_with_socket_bytes(args, socket, None).await?;
    Ok(String::from_utf8_lossy(&stdout).trim().to_string())
}

/// Execute a tmux command using the default socket (if configured).
pub async fn execute_tmux(args: &[&str]) -> Result<String> {
    execute_tmux_with_socket(args, None).await
}

/// Check if the tmux server is running.
pub async fn is_tmux_running() -> Result<bool> {
    match execute_tmux(&["list-sessions", "-F", "#{session_name}"]).await {
        Ok(_) => Ok(true),
        Err(Error::Tmux { ref message }) if message.contains("no server running") => Ok(false),
        Err(Error::Tmux { ref message }) if message.contains("no sessions") => Ok(true),
        Err(e) => Err(e),
    }
}

/// Parse `list-sessions -F '#{session_id}\t#{session_name}\t#{?session_attached,1,0}\t#{session_windows}'`
pub fn parse_sessions(output: &str) -> Vec<Session> {
    if output.is_empty() {
        return Vec::new();
    }

    output
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 4 {
                Some(Session {
                    id: parts[0].to_string(),
                    name: parts[1].to_string(),
                    attached: parts[2] == "1",
                    windows: parts[3].parse().unwrap_or(0),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Parse `list-windows -F '#{window_id}\t#{window_name}\t#{?window_active,1,0}'`
pub fn parse_windows(output: &str, session_id: &str) -> Vec<Window> {
    if output.is_empty() {
        return Vec::new();
    }

    output
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                Some(Window {
                    id: parts[0].to_string(),
                    name: parts[1].to_string(),
                    active: parts[2] == "1",
                    session_id: session_id.to_string(),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Parse `list-panes -F '#{pane_id}\t#{pane_title}\t#{?pane_active,1,0}'`
pub fn parse_panes(output: &str, window_id: &str) -> Vec<Pane> {
    if output.is_empty() {
        return Vec::new();
    }

    output
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                Some(Pane {
                    id: parts[0].to_string(),
                    title: parts[1].to_string(),
                    active: parts[2] == "1",
                    window_id: window_id.to_string(),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Parse `list-clients -F '#{client_tty}\t#{client_name}\t#{client_session}\t#{client_pid}\t#{?client_attached,1,0}'`
pub fn parse_clients(output: &str) -> Vec<ClientInfo> {
    if output.is_empty() {
        return Vec::new();
    }

    output
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 5 {
                Some(ClientInfo {
                    tty: parts[0].to_string(),
                    name: parts[1].to_string(),
                    session_name: parts[2].to_string(),
                    pid: parts[3].parse().ok(),
                    attached: parts[4] == "1",
                })
            } else {
                None
            }
        })
        .collect()
}

/// Parse `list-buffers -F '#{buffer_name}\t#{buffer_size}\t#{buffer_created}'`
pub fn parse_buffers(output: &str) -> Vec<BufferInfo> {
    if output.is_empty() {
        return Vec::new();
    }

    output
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                let size_u64: u64 = parts[1].parse().unwrap_or(0);
                let size = std::cmp::min(size_u64, u32::MAX as u64) as u32;
                Some(BufferInfo {
                    name: parts[0].to_string(),
                    size,
                    size_bytes: size_u64,
                    order_index: idx as u32,
                    created: parts[2].parse().ok(),
                })
            } else {
                None
            }
        })
        .collect()
}

/// List all tmux sessions.
pub async fn list_sessions(socket: Option<&str>) -> Result<Vec<Session>> {
    let format = "#{session_id}\t#{session_name}\t#{?session_attached,1,0}\t#{session_windows}";
    let output = execute_tmux_with_socket(&["list-sessions", "-F", format], socket).await?;
    Ok(parse_sessions(&output))
}

/// Find a session by name.
pub async fn find_session_by_name(name: &str, socket: Option<&str>) -> Result<Option<Session>> {
    let sessions = list_sessions(socket).await?;
    Ok(sessions.into_iter().find(|s| s.name == name))
}

/// List windows in a session.
pub async fn list_windows(session_id: &str, socket: Option<&str>) -> Result<Vec<Window>> {
    let format = "#{window_id}\t#{window_name}\t#{?window_active,1,0}";
    let output =
        execute_tmux_with_socket(&["list-windows", "-t", session_id, "-F", format], socket).await?;
    Ok(parse_windows(&output, session_id))
}

/// List panes in a window.
pub async fn list_panes(window_id: &str, socket: Option<&str>) -> Result<Vec<Pane>> {
    let format = "#{pane_id}\t#{pane_title}\t#{?pane_active,1,0}";
    let output =
        execute_tmux_with_socket(&["list-panes", "-t", window_id, "-F", format], socket).await?;
    Ok(parse_panes(&output, window_id))
}

/// Capture content from a pane.
pub async fn capture_pane(
    pane_id: &str,
    lines: Option<u32>,
    colors: bool,
    start: Option<i32>,
    end: Option<i32>,
    join: bool,
    socket: Option<&str>,
) -> Result<String> {
    let mut args: Vec<String> = vec![
        "capture-pane".into(),
        "-p".into(),
        "-t".into(),
        pane_id.into(),
    ];

    if colors {
        args.push("-e".into());
    }
    if join {
        args.push("-J".into());
    }

    if start.is_some() || end.is_some() {
        let start_val = start.unwrap_or(0);
        args.push("-S".into());
        args.push(start_val.to_string());
        args.push("-E".into());
        if let Some(end_val) = end {
            args.push(end_val.to_string());
        } else {
            args.push("-".into());
        }
    } else {
        let lines_val = lines.unwrap_or(200);
        args.push("-S".into());
        args.push(format!("-{}", lines_val));
        args.push("-E".into());
        args.push("-".into());
    }

    let arg_refs: Vec<&str> = args.iter().map(|arg| arg.as_str()).collect();
    execute_tmux_with_socket(&arg_refs, socket).await
}

/// List connected tmux clients.
pub async fn list_clients(socket: Option<&str>) -> Result<Vec<ClientInfo>> {
    let format =
        "#{client_tty}\t#{client_name}\t#{client_session}\t#{client_pid}\t#{?client_attached,1,0}";
    match execute_tmux_with_socket(&["list-clients", "-F", format], socket).await {
        Ok(output) => Ok(parse_clients(&output)),
        Err(Error::Tmux { ref message }) if message.contains("no clients") => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Detach a tmux client.
pub async fn detach_client(client_tty: &str, socket: Option<&str>) -> Result<()> {
    execute_tmux_with_socket(&["detach-client", "-t", client_tty], socket).await?;
    Ok(())
}

/// List tmux paste buffers.
pub async fn list_buffers(socket: Option<&str>) -> Result<Vec<BufferInfo>> {
    let format = "#{buffer_name}\t#{buffer_size}\t#{buffer_created}";
    match execute_tmux_with_socket(&["list-buffers", "-F", format], socket).await {
        Ok(output) => Ok(parse_buffers(&output)),
        Err(Error::Tmux { ref message }) if message.contains("no buffers") => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Show a tmux buffer.
pub async fn show_buffer(name: Option<&str>, socket: Option<&str>) -> Result<String> {
    let mut args = vec!["show-buffer"];
    if let Some(name) = name {
        args.push("-b");
        args.push(name);
    }
    let stdout = execute_tmux_with_socket_bytes(&args, socket, None).await?;
    Ok(String::from_utf8_lossy(&stdout).to_string())
}

/// Show a tmux buffer and return raw bytes.
pub async fn show_buffer_bytes(name: Option<&str>, socket: Option<&str>) -> Result<Vec<u8>> {
    let mut args = vec!["show-buffer"];
    if let Some(name) = name {
        args.push("-b");
        args.push(name);
    }
    execute_tmux_with_socket_bytes(&args, socket, None).await
}

/// Stream a tmux buffer to a file path.
pub async fn show_buffer_to_file(
    name: Option<&str>,
    path: &Path,
    socket: Option<&str>,
) -> Result<()> {
    let mut args = vec!["show-buffer"];
    if let Some(name) = name {
        args.push("-b");
        args.push(name);
    }
    execute_tmux_with_socket_to_file(&args, socket, path).await
}

/// Show a tmux buffer slice bounded by offset/max bytes (lossy UTF-8).
pub async fn show_buffer_slice(
    name: Option<&str>,
    offset_bytes: Option<u64>,
    max_bytes: Option<u64>,
    socket: Option<&str>,
) -> Result<String> {
    let bytes = show_buffer_bytes(name, socket).await?;
    let offset = offset_bytes.unwrap_or(0) as usize;
    let max = max_bytes.unwrap_or(DEFAULT_SHOW_MAX_BYTES) as usize;
    if max == 0 || offset >= bytes.len() {
        return Ok(String::new());
    }
    let end = std::cmp::min(bytes.len(), offset.saturating_add(max));
    let slice = &bytes[offset..end];
    Ok(String::from_utf8_lossy(slice).to_string())
}

fn read_window_from_file(path: &Path, start: u64, len: u64) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut file = std::fs::File::open(path).map_err(|e| Error::Tmux {
        message: format!("failed to open temp buffer file: {e}"),
    })?;
    file.seek(SeekFrom::Start(start)).map_err(|e| Error::Tmux {
        message: format!("failed to seek temp buffer file: {e}"),
    })?;
    let mut buf = vec![0u8; len as usize];
    let mut read_total = 0usize;
    while read_total < buf.len() {
        let n = file.read(&mut buf[read_total..]).map_err(|e| Error::Tmux {
            message: format!("failed to read temp buffer file: {e}"),
        })?;
        if n == 0 {
            break;
        }
        read_total = read_total.saturating_add(n);
    }
    buf.truncate(read_total);
    Ok(buf)
}

/// Save a tmux buffer to a file path.
pub async fn save_buffer(name: &str, path: &str, socket: Option<&str>) -> Result<()> {
    execute_tmux_with_socket(&["save-buffer", "-b", name, path], socket).await?;
    Ok(())
}

/// Load a tmux buffer from a file path.
pub async fn load_buffer(name: &str, path: &str, socket: Option<&str>) -> Result<()> {
    execute_tmux_with_socket(&["load-buffer", "-b", name, path], socket).await?;
    Ok(())
}

/// Delete a tmux buffer.
pub async fn delete_buffer(name: &str, socket: Option<&str>) -> Result<()> {
    execute_tmux_with_socket(&["delete-buffer", "-b", name], socket).await?;
    Ok(())
}

/// Set a tmux buffer from raw bytes, preferring stdin load-buffer.
pub async fn set_buffer_bytes(name: &str, content: &[u8], socket: Option<&str>) -> Result<()> {
    let load_args = ["load-buffer", "-b", name, "-"];
    match execute_tmux_with_socket_bytes(&load_args, socket, Some(content)).await {
        Ok(_) => Ok(()),
        Err(_) => {
            let content_str = String::from_utf8_lossy(content);
            execute_tmux_with_socket(&["set-buffer", "-b", name, "--", &content_str], socket)
                .await?;
            Ok(())
        }
    }
}

/// Set a tmux buffer from UTF-8 content.
pub async fn set_buffer(name: &str, content: &str, socket: Option<&str>) -> Result<()> {
    set_buffer_bytes(name, content.as_bytes(), socket).await
}

/// Append content to a tmux buffer.
pub async fn append_buffer(name: &str, content: &str, socket: Option<&str>) -> Result<()> {
    let buffers = list_buffers(socket).await?;
    let existing = buffers.iter().find(|b| b.name == name);
    if existing.is_none() {
        return set_buffer(name, content, socket).await;
    }

    let size_bytes = existing.map(|b| b.size_bytes).unwrap_or(0);
    let use_tempfile = size_bytes > APPEND_INLINE_MAX_BYTES && !ssh_enabled()?;

    if use_tempfile {
        let temp = tempfile::NamedTempFile::new().map_err(|e| Error::Tmux {
            message: format!("failed to create temp file: {e}"),
        })?;
        let path = temp.path().to_string_lossy().to_string();
        save_buffer(name, &path, socket).await?;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .and_then(|mut file| std::io::Write::write_all(&mut file, content.as_bytes()))
            .map_err(|e| Error::Tmux {
                message: format!("failed to append temp buffer: {e}"),
            })?;
        execute_tmux_with_socket(&["load-buffer", "-b", name, &path], socket).await?;
        Ok(())
    } else {
        let mut existing_bytes = show_buffer_bytes(Some(name), socket).await?;
        existing_bytes.extend_from_slice(content.as_bytes());
        set_buffer_bytes(name, &existing_bytes, socket).await
    }
}

/// Rename a tmux buffer by copying and deleting the original.
pub async fn rename_buffer(from: &str, to: &str, socket: Option<&str>) -> Result<()> {
    let bytes = show_buffer_bytes(Some(from), socket).await?;
    set_buffer_bytes(to, &bytes, socket).await?;
    delete_buffer(from, socket).await?;
    Ok(())
}

fn clamp_char_boundary(text: &str, idx: usize, forward: bool) -> usize {
    if idx >= text.len() {
        return text.len();
    }
    if text.is_char_boundary(idx) {
        return idx;
    }
    let mut i = idx;
    if forward {
        while i < text.len() && !text.is_char_boundary(i) {
            i += 1;
        }
    } else {
        while i > 0 && !text.is_char_boundary(i) {
            i -= 1;
        }
    }
    i
}

fn is_utf8_continuation(byte: u8) -> bool {
    (byte & 0b1100_0000) == 0b1000_0000
}

fn decode_window(buffer: &str, bytes: &[u8], base_offset: usize) -> Result<(String, usize)> {
    if bytes.is_empty() {
        return Ok((String::new(), base_offset));
    }

    let mut start = 0usize;
    while start < bytes.len() && is_utf8_continuation(bytes[start]) {
        start += 1;
    }

    let mut end = bytes.len();
    while end > start && is_utf8_continuation(bytes[end.saturating_sub(1)]) {
        end = end.saturating_sub(1);
    }

    loop {
        if start >= end {
            return Ok((String::new(), base_offset.saturating_add(start)));
        }

        let slice = &bytes[start..end];
        match std::str::from_utf8(slice) {
            Ok(text) => return Ok((text.to_string(), base_offset.saturating_add(start))),
            Err(err) => {
                if err.error_len().is_none() {
                    // Truncated UTF-8 sequence at the end of the window; trim to valid prefix.
                    let valid = err.valid_up_to();
                    end = start.saturating_add(valid);
                    continue;
                }
                return Err(Error::InvalidArgument {
                    message: format!(
                        "buffer '{buffer}' contains non-UTF-8 bytes; search requires UTF-8"
                    ),
                });
            }
        }
    }
}

// rapidfuzz (feature-gated) provides fuzzy similarity scoring when requested.
#[cfg(feature = "rapidfuzz")]
fn similarity_score(query: &str, matched: &str) -> f32 {
    rapidfuzz::fuzz::ratio(query.chars(), matched.chars()).clamp(0.0, 1.0) as f32
}

#[cfg(not(feature = "rapidfuzz"))]
fn similarity_score(_query: &str, _matched: &str) -> f32 {
    0.0
}

fn best_fuzzy_window(query: &str, line: &str) -> (f32, usize, usize) {
    if line.is_empty() {
        return (0.0, 0, 0);
    }
    let query_chars = query.chars().count();
    if query_chars == 0 {
        return (0.0, 0, 0);
    }

    let line_chars: Vec<usize> = line.char_indices().map(|(i, _)| i).collect();
    if query_chars >= line_chars.len() {
        return (similarity_score(query, line), 0, line.len());
    }

    let mut best_score = 0.0;
    let mut best_start = 0;
    let mut best_len = line.len();
    for i in 0..=line_chars.len().saturating_sub(query_chars) {
        let start = line_chars[i];
        let end = if i + query_chars < line_chars.len() {
            line_chars[i + query_chars]
        } else {
            line.len()
        };
        let window = &line[start..end];
        let score = similarity_score(query, window);
        if score > best_score {
            best_score = score;
            best_start = start;
            best_len = end.saturating_sub(start);
        }
    }

    (best_score, best_start, best_len)
}

struct MatchContext<'a> {
    buffer: &'a str,
    text: &'a str,
    query: &'a str,
    context_bytes: usize,
    include_similarity: bool,
    base_offset: usize,
}

struct MatchCollection {
    matches: Vec<BufferSearchMatch>,
    fuzzy_skipped_lines: u32,
    fuzzy_skipped_bytes: u64,
}

fn build_match(
    ctx: &MatchContext<'_>,
    offset: usize,
    match_len: usize,
    scan_start: usize,
    scan_end: usize,
) -> BufferSearchMatch {
    let context_start =
        clamp_char_boundary(ctx.text, offset.saturating_sub(ctx.context_bytes), false);
    let context_end = clamp_char_boundary(
        ctx.text,
        offset
            .saturating_add(match_len)
            .saturating_add(ctx.context_bytes),
        true,
    );
    let bounded_start = context_start.max(scan_start);
    let bounded_end = context_end.min(scan_end);
    let snippet = if bounded_start < bounded_end {
        ctx.text[bounded_start..bounded_end].to_string()
    } else {
        String::new()
    };
    let matched_text = &ctx.text[offset..offset.saturating_add(match_len)];
    let similarity = if ctx.include_similarity {
        Some(similarity_score(ctx.query, matched_text))
    } else {
        None
    };
    let absolute_offset = ctx.base_offset.saturating_add(offset);
    let absolute_context_start = ctx.base_offset.saturating_add(bounded_start);
    let absolute_context_end = ctx.base_offset.saturating_add(bounded_end);
    BufferSearchMatch {
        match_id: format!("{}:{absolute_offset}", ctx.buffer),
        buffer: ctx.buffer.to_string(),
        offset_bytes: absolute_offset as u64,
        match_len: match_len as u32,
        context_start: absolute_context_start as u64,
        context_end: absolute_context_end as u64,
        snippet,
        similarity,
    }
}

fn collect_matches(
    ctx: &MatchContext<'_>,
    scan_start: usize,
    scan_end: usize,
    mode: SearchMode,
    regex: Option<&Regex>,
    fuzzy_enabled: bool,
    similarity_threshold: f32,
) -> MatchCollection {
    let scan_text = &ctx.text[scan_start..scan_end];
    let mut matches: Vec<BufferSearchMatch> = Vec::new();
    let mut seen_offsets: BTreeSet<u64> = BTreeSet::new();
    let mut fuzzy_skipped_lines: u32 = 0;
    let mut fuzzy_skipped_bytes: u64 = 0;

    if mode == SearchMode::Literal {
        for (offset, _) in scan_text.match_indices(ctx.query) {
            let absolute = scan_start.saturating_add(offset);
            matches.push(build_match(
                ctx,
                absolute,
                ctx.query.len(),
                scan_start,
                scan_end,
            ));
            seen_offsets.insert(absolute as u64);
        }
    } else if let Some(regex) = regex {
        for m in regex.find_iter(scan_text) {
            let match_len = m.end().saturating_sub(m.start());
            let absolute = scan_start.saturating_add(m.start());
            matches.push(build_match(ctx, absolute, match_len, scan_start, scan_end));
            seen_offsets.insert(absolute as u64);
        }
    }

    // Optional fuzzy match path (feature-gated) for typo-tolerant searching.
    if fuzzy_enabled {
        let mut offset = 0usize;
        for line in scan_text.split('\n') {
            let line_len = line.len();
            if line_len > 0 {
                if line_len > FUZZY_MAX_LINE_BYTES {
                    fuzzy_skipped_lines = fuzzy_skipped_lines.saturating_add(1);
                    fuzzy_skipped_bytes = fuzzy_skipped_bytes.saturating_add(line_len as u64);
                } else {
                    let (score, best_start, best_len) = best_fuzzy_window(ctx.query, line);
                    if score >= similarity_threshold && best_len > 0 {
                        let absolute = scan_start.saturating_add(offset).saturating_add(best_start);
                        let absolute_u64 = absolute as u64;
                        if !seen_offsets.contains(&absolute_u64) {
                            let mut entry =
                                build_match(ctx, absolute, best_len, scan_start, scan_end);
                            entry.similarity = Some(score);
                            matches.push(entry);
                            seen_offsets.insert(absolute_u64);
                        }
                    }
                }
            }
            offset = offset.saturating_add(line_len + 1);
            if offset >= scan_text.len() {
                break;
            }
        }
    }

    matches.sort_by_key(|m| m.offset_bytes);
    MatchCollection {
        matches,
        fuzzy_skipped_lines,
        fuzzy_skipped_bytes,
    }
}

fn resolve_similarity_flags(
    include_similarity: bool,
    fuzzy_match: bool,
    similarity_threshold: Option<f32>,
) -> Result<(bool, bool, f32)> {
    let fuzzy_enabled = fuzzy_match || similarity_threshold.is_some();
    let include_similarity = include_similarity || fuzzy_enabled;

    if include_similarity && !cfg!(feature = "rapidfuzz") {
        return Err(Error::InvalidArgument {
            message: "similarity/fuzzy matching requires the rapidfuzz feature".into(),
        });
    }

    let threshold = similarity_threshold.unwrap_or(0.8).clamp(0.0, 1.0);
    Ok((include_similarity, fuzzy_enabled, threshold))
}

fn search_texts(
    buffers: Vec<BufferText>,
    query: &str,
    mode: SearchMode,
    options: SearchOptions,
) -> Result<BufferSearchOutput> {
    if query.is_empty() {
        return Err(Error::InvalidArgument {
            message: "query must not be empty".into(),
        });
    }

    let SearchOptions {
        context_bytes,
        max_matches,
        max_scan_bytes,
        include_similarity,
        fuzzy_match,
        similarity_threshold,
        resume_from_offset,
    } = options;

    let context_bytes = context_bytes.unwrap_or(DEFAULT_SEARCH_CONTEXT_BYTES) as usize;
    let max_matches = max_matches.unwrap_or(DEFAULT_SEARCH_MAX_MATCHES);
    let max_scan_bytes = max_scan_bytes.unwrap_or(DEFAULT_SEARCH_MAX_SCAN_BYTES) as usize;
    let (include_similarity, fuzzy_enabled, similarity_threshold) =
        resolve_similarity_flags(include_similarity, fuzzy_match, similarity_threshold)?;

    let regex = if mode == SearchMode::Regex {
        Some(Regex::new(query).map_err(|e| Error::InvalidArgument {
            message: format!("invalid regex: {e}"),
        })?)
    } else {
        None
    };

    let mut buffer_texts: Vec<(BufferText, usize, usize, usize, bool)> = Vec::new();
    let mut bytes_scanned_total: u64 = 0;

    if let Some(ref resume) = resume_from_offset {
        let buffer_names: BTreeSet<&str> = buffers.iter().map(|b| b.name.as_str()).collect();
        for name in resume.keys() {
            if !buffer_names.contains(name.as_str()) {
                return Err(Error::InvalidArgument {
                    message: format!("resumeFromOffset references unknown buffer '{name}'"),
                });
            }
        }
    }

    for buffer in buffers.iter() {
        let window_len = buffer.text.len();
        let buffer_len = buffer.full_len;
        let window_start = buffer.base_offset;
        let scan_start = if let Some(ref resume) = resume_from_offset {
            if let Some(offset) = resume.get(&buffer.name) {
                let offset = *offset as usize;
                if offset > buffer_len {
                    return Err(Error::InvalidArgument {
                        message: format!(
                            "resumeFromOffset {} exceeds buffer '{}' length {}",
                            offset, buffer.name, buffer_len
                        ),
                    });
                }
                let relative = offset.saturating_sub(window_start);
                if relative > window_len {
                    return Err(Error::InvalidArgument {
                        message: format!(
                            "resumeFromOffset {} is outside the scan window for buffer '{}'",
                            offset, buffer.name
                        ),
                    });
                }
                clamp_char_boundary(&buffer.text, relative, false)
            } else {
                0
            }
        } else {
            0
        };
        let scan_limit_end = clamp_char_boundary(
            &buffer.text,
            scan_start.saturating_add(max_scan_bytes).min(window_len),
            false,
        );
        let scan_end = window_len;
        bytes_scanned_total += (scan_limit_end - scan_start) as u64;
        buffer_texts.push((
            buffer.clone(),
            scan_start,
            scan_limit_end,
            scan_end,
            window_start.saturating_add(scan_limit_end) < buffer_len,
        ));
    }

    let use_parallel = cfg!(feature = "rayon") && buffer_texts.len() >= PARALLEL_BUFFER_THRESHOLD;

    let scan_results: Vec<BufferScanResult> = if use_parallel {
        #[cfg(feature = "rayon")]
        {
            use rayon::prelude::*;
            buffer_texts
                .par_iter()
                .map(
                    |(buffer, scan_start, scan_limit_end, scan_end, truncated_by_scan)| {
                        let ctx = MatchContext {
                            buffer: &buffer.name,
                            text: &buffer.text,
                            query,
                            context_bytes,
                            include_similarity,
                            base_offset: buffer.base_offset,
                        };
                        let collection = collect_matches(
                            &ctx,
                            *scan_start,
                            *scan_end,
                            mode,
                            regex.as_ref(),
                            fuzzy_enabled,
                            similarity_threshold,
                        );
                        let max_offset = buffer.base_offset.saturating_add(*scan_limit_end) as u64;
                        let matches = collection
                            .matches
                            .into_iter()
                            .filter(|m| m.offset_bytes < max_offset)
                            .collect();
                        BufferScanResult {
                            name: buffer.name.clone(),
                            matches,
                            scan_end: max_offset as usize,
                            truncated_by_scan: *truncated_by_scan,
                            fuzzy_skipped_lines: collection.fuzzy_skipped_lines,
                            fuzzy_skipped_bytes: collection.fuzzy_skipped_bytes,
                        }
                    },
                )
                .collect()
        }
        #[cfg(not(feature = "rayon"))]
        {
            Vec::new()
        }
    } else {
        buffer_texts
            .iter()
            .map(
                |(buffer, scan_start, scan_limit_end, scan_end, truncated_by_scan)| {
                    let ctx = MatchContext {
                        buffer: &buffer.name,
                        text: &buffer.text,
                        query,
                        context_bytes,
                        include_similarity,
                        base_offset: buffer.base_offset,
                    };
                    let collection = collect_matches(
                        &ctx,
                        *scan_start,
                        *scan_end,
                        mode,
                        regex.as_ref(),
                        fuzzy_enabled,
                        similarity_threshold,
                    );
                    let max_offset = buffer.base_offset.saturating_add(*scan_limit_end) as u64;
                    let matches = collection
                        .matches
                        .into_iter()
                        .filter(|m| m.offset_bytes < max_offset)
                        .collect();
                    BufferScanResult {
                        name: buffer.name.clone(),
                        matches,
                        scan_end: max_offset as usize,
                        truncated_by_scan: *truncated_by_scan,
                        fuzzy_skipped_lines: collection.fuzzy_skipped_lines,
                        fuzzy_skipped_bytes: collection.fuzzy_skipped_bytes,
                    }
                },
            )
            .collect()
    };

    let mut output_matches: Vec<BufferSearchMatch> = Vec::new();
    let mut truncated_buffers: Vec<String> = Vec::new();
    let mut resume_from_offset: BTreeMap<String, u64> = BTreeMap::new();
    let mut remaining = max_matches as i64;
    let mut similarity_sum: f32 = 0.0;
    let mut similarity_max: f32 = 0.0;
    let mut similarity_count: u32 = 0;
    let mut fuzzy_skipped_lines: u32 = 0;
    let mut fuzzy_skipped_bytes: u64 = 0;

    for result in scan_results {
        fuzzy_skipped_lines = fuzzy_skipped_lines.saturating_add(result.fuzzy_skipped_lines);
        fuzzy_skipped_bytes = fuzzy_skipped_bytes.saturating_add(result.fuzzy_skipped_bytes);
        let mut added_in_buffer: usize = 0;
        if remaining > 0 {
            for m in &result.matches {
                if remaining == 0 {
                    break;
                }
                output_matches.push(m.clone());
                added_in_buffer += 1;
                remaining -= 1;
                if include_similarity {
                    if let Some(score) = m.similarity {
                        similarity_sum += score;
                        similarity_max = similarity_max.max(score);
                        similarity_count += 1;
                    }
                }
            }
            if remaining == 0 && result.matches.len() > added_in_buffer {
                let next_match = &result.matches[added_in_buffer];
                resume_from_offset
                    .entry(result.name.clone())
                    .or_insert(next_match.offset_bytes);
                if !truncated_buffers.contains(&result.name) {
                    truncated_buffers.push(result.name.clone());
                }
            }
        } else if let Some(first) = result.matches.first() {
            resume_from_offset
                .entry(result.name.clone())
                .or_insert(first.offset_bytes);
            if !truncated_buffers.contains(&result.name) {
                truncated_buffers.push(result.name.clone());
            }
        }

        if result.truncated_by_scan {
            resume_from_offset
                .entry(result.name.clone())
                .or_insert(result.scan_end as u64);
            if !truncated_buffers.contains(&result.name) {
                truncated_buffers.push(result.name.clone());
            }
        }
    }

    let total_matches = output_matches.len() as u32;
    let avg_similarity = if include_similarity && similarity_count > 0 {
        Some(similarity_sum / similarity_count as f32)
    } else {
        None
    };
    let max_similarity = if include_similarity && similarity_count > 0 {
        Some(similarity_max)
    } else {
        None
    };

    Ok(BufferSearchOutput {
        query: query.to_string(),
        mode,
        context_bytes: context_bytes as u32,
        max_matches,
        include_similarity,
        fuzzy_match: fuzzy_enabled,
        similarity_threshold: if fuzzy_enabled {
            Some(similarity_threshold)
        } else {
            None
        },
        buffers: buffers.iter().map(|b| b.name.clone()).collect(),
        total_matches,
        buffers_scanned: buffers.len() as u32,
        bytes_scanned_total,
        truncated_buffers,
        resume_from_offset,
        matches: output_matches,
        max_similarity,
        avg_similarity,
        fuzzy_skipped_lines,
        fuzzy_skipped_bytes,
    })
}

/// Pure search over a single UTF-8 buffer (no tmux interaction).
pub fn search_text(
    buffer_name: &str,
    text: &str,
    query: &str,
    mode: SearchMode,
    options: SearchOptions,
) -> Result<BufferSearchOutput> {
    search_texts(
        vec![BufferText {
            name: buffer_name.to_string(),
            text: text.to_string(),
            base_offset: 0,
            full_len: text.len(),
        }],
        query,
        mode,
        options,
    )
}

fn subsearch_text_view(
    buffer: &BufferText,
    anchor_offset: u64,
    anchor_len: u32,
    query: &str,
    mode: SearchMode,
    options: SubsearchOptions,
) -> Result<BufferSearchOutput> {
    if query.is_empty() {
        return Err(Error::InvalidArgument {
            message: "query must not be empty".into(),
        });
    }

    let (include_similarity, fuzzy_enabled, similarity_threshold) = resolve_similarity_flags(
        options.include_similarity,
        options.fuzzy_match,
        options.similarity_threshold,
    )?;

    let anchor_offset = anchor_offset as usize;
    if anchor_offset > buffer.full_len {
        return Err(Error::InvalidArgument {
            message: format!(
                "anchor offset {anchor_offset} exceeds buffer length {}",
                buffer.full_len
            ),
        });
    }

    let context = options.context_bytes as usize;
    let anchor_len = anchor_len as usize;
    let start = anchor_offset.saturating_sub(context);
    let end = anchor_offset
        .saturating_add(anchor_len)
        .saturating_add(context)
        .min(buffer.full_len);

    if start < buffer.base_offset || end > buffer.base_offset.saturating_add(buffer.text.len()) {
        return Err(Error::InvalidArgument {
            message: format!(
                "anchor window for buffer '{}' is outside the scan window",
                buffer.name
            ),
        });
    }

    let mut scan_start = clamp_char_boundary(
        &buffer.text,
        start.saturating_sub(buffer.base_offset),
        false,
    );
    let scan_end = clamp_char_boundary(&buffer.text, end.saturating_sub(buffer.base_offset), true);
    let max_matches = options.max_matches.unwrap_or(DEFAULT_SEARCH_MAX_MATCHES);
    if let Some(resume_offset) = options.resume_from_offset {
        let resume_offset = resume_offset as usize;
        if resume_offset > buffer.full_len {
            return Err(Error::InvalidArgument {
                message: format!(
                    "resumeFromOffset {} exceeds buffer length {}",
                    resume_offset, buffer.full_len
                ),
            });
        }
        if resume_offset < start || resume_offset > end {
            return Err(Error::InvalidArgument {
                message: format!(
                    "resumeFromOffset {} is outside the anchor window",
                    resume_offset
                ),
            });
        }
        scan_start = clamp_char_boundary(
            &buffer.text,
            resume_offset.saturating_sub(buffer.base_offset),
            false,
        );
    }

    let regex = if mode == SearchMode::Regex {
        Some(Regex::new(query).map_err(|e| Error::InvalidArgument {
            message: format!("invalid regex: {e}"),
        })?)
    } else {
        None
    };

    let ctx = MatchContext {
        buffer: &buffer.name,
        text: &buffer.text,
        query,
        context_bytes: context,
        include_similarity,
        base_offset: buffer.base_offset,
    };
    let collection = collect_matches(
        &ctx,
        scan_start,
        scan_end,
        mode,
        regex.as_ref(),
        fuzzy_enabled,
        similarity_threshold,
    );
    let all_matches = collection.matches;

    let mut output_matches: Vec<BufferSearchMatch> = Vec::new();
    let mut truncated_buffers: Vec<String> = Vec::new();
    let mut resume_from_offset: BTreeMap<String, u64> = BTreeMap::new();
    let mut remaining = max_matches as i64;
    let mut similarity_sum: f32 = 0.0;
    let mut similarity_max: f32 = 0.0;
    let mut similarity_count: u32 = 0;
    let fuzzy_skipped_lines = collection.fuzzy_skipped_lines;
    let fuzzy_skipped_bytes = collection.fuzzy_skipped_bytes;

    let mut added = 0usize;
    for m in &all_matches {
        if remaining == 0 {
            break;
        }
        output_matches.push(m.clone());
        added += 1;
        remaining -= 1;
        if include_similarity {
            if let Some(score) = m.similarity {
                similarity_sum += score;
                similarity_max = similarity_max.max(score);
                similarity_count += 1;
            }
        }
    }

    if remaining == 0 && all_matches.len() > added {
        let next_match = &all_matches[added];
        resume_from_offset.insert(buffer.name.clone(), next_match.offset_bytes);
        truncated_buffers.push(buffer.name.clone());
    }

    if end < buffer.full_len {
        resume_from_offset
            .entry(buffer.name.clone())
            .or_insert(end as u64);
        if !truncated_buffers.contains(&buffer.name) {
            truncated_buffers.push(buffer.name.clone());
        }
    }

    let total_matches = output_matches.len() as u32;
    let avg_similarity = if include_similarity && similarity_count > 0 {
        Some(similarity_sum / similarity_count as f32)
    } else {
        None
    };
    let max_similarity = if include_similarity && similarity_count > 0 {
        Some(similarity_max)
    } else {
        None
    };

    Ok(BufferSearchOutput {
        query: query.to_string(),
        mode,
        context_bytes: options.context_bytes,
        max_matches,
        include_similarity,
        fuzzy_match: fuzzy_enabled,
        similarity_threshold: if fuzzy_enabled {
            Some(similarity_threshold)
        } else {
            None
        },
        buffers: vec![buffer.name.clone()],
        total_matches,
        buffers_scanned: 1,
        bytes_scanned_total: (scan_end.saturating_sub(scan_start)) as u64,
        truncated_buffers,
        resume_from_offset,
        matches: output_matches,
        max_similarity,
        avg_similarity,
        fuzzy_skipped_lines,
        fuzzy_skipped_bytes,
    })
}

/// Pure anchor-scoped subsearch over a single UTF-8 buffer (no tmux interaction).
pub fn subsearch_text(
    buffer: &str,
    text: &str,
    anchor_offset: u64,
    anchor_len: u32,
    query: &str,
    mode: SearchMode,
    options: SubsearchOptions,
) -> Result<BufferSearchOutput> {
    let view = BufferText {
        name: buffer.to_string(),
        text: text.to_string(),
        base_offset: 0,
        full_len: text.len(),
    };
    subsearch_text_view(&view, anchor_offset, anchor_len, query, mode, options)
}

async fn load_buffer_window(
    buffer: &str,
    window_start: u64,
    window_len: u64,
    streaming_threshold_bytes: u64,
    size_hint: Option<u64>,
    socket: Option<&str>,
) -> Result<BufferText> {
    let use_streaming = size_hint.unwrap_or(0) > streaming_threshold_bytes;
    if use_streaming {
        let temp = tempfile::NamedTempFile::new().map_err(|e| Error::Tmux {
            message: format!("failed to create temp file: {e}"),
        })?;
        show_buffer_to_file(Some(buffer), temp.path(), socket).await?;
        let metadata_len = std::fs::metadata(temp.path())
            .map_err(|e| Error::Tmux {
                message: format!("failed to stat temp buffer file: {e}"),
            })?
            .len();
        let full_len = size_hint.unwrap_or(metadata_len).max(metadata_len) as usize;
        if window_start as usize > full_len {
            return Err(Error::InvalidArgument {
                message: format!(
                    "resumeFromOffset {} exceeds buffer '{}' length {}",
                    window_start, buffer, full_len
                ),
            });
        }
        let window_end = std::cmp::min(full_len as u64, window_start.saturating_add(window_len));
        let bytes = read_window_from_file(temp.path(), window_start, window_end - window_start)?;
        let (text, base_offset) = decode_window(buffer, &bytes, window_start as usize)?;
        Ok(BufferText {
            name: buffer.to_string(),
            text,
            base_offset,
            full_len,
        })
    } else {
        let bytes = show_buffer_bytes(Some(buffer), socket).await?;
        let full_len = bytes.len();
        if window_start as usize > full_len {
            return Err(Error::InvalidArgument {
                message: format!(
                    "resumeFromOffset {} exceeds buffer '{}' length {}",
                    window_start, buffer, full_len
                ),
            });
        }
        let window_end = std::cmp::min(full_len as u64, window_start.saturating_add(window_len));
        let start = window_start as usize;
        let end = window_end as usize;
        let window_bytes = &bytes[start..end];
        let (text, base_offset) = decode_window(buffer, window_bytes, start)?;
        Ok(BufferText {
            name: buffer.to_string(),
            text,
            base_offset,
            full_len,
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn search_buffers(
    names: Option<Vec<String>>,
    query: &str,
    mode: SearchMode,
    context_bytes: Option<u32>,
    max_matches: Option<u32>,
    max_scan_bytes: Option<u64>,
    include_similarity: bool,
    fuzzy_match: bool,
    similarity_threshold: Option<f32>,
    resume_from_offset: Option<BTreeMap<String, u64>>,
    streaming_threshold_bytes: u64,
    socket: Option<&str>,
) -> Result<BufferSearchOutput> {
    let buffer_infos = list_buffers(socket).await?;
    let mut size_by_name: BTreeMap<String, u64> = BTreeMap::new();
    for info in buffer_infos {
        size_by_name.insert(info.name.clone(), info.size_bytes);
    }

    let buffers = if let Some(names) = names {
        if names.is_empty() {
            Vec::new()
        } else {
            names
        }
    } else {
        size_by_name.keys().cloned().collect()
    };

    let context_for_window = context_bytes.unwrap_or(DEFAULT_SEARCH_CONTEXT_BYTES) as u64;
    let max_scan_for_window = max_scan_bytes.unwrap_or(DEFAULT_SEARCH_MAX_SCAN_BYTES);
    let overlap = context_for_window.saturating_add(query.len() as u64);
    let window_len = max_scan_for_window.saturating_add(overlap);

    let mut buffer_texts: Vec<BufferText> = Vec::new();
    for buffer in &buffers {
        let resume_offset = resume_from_offset
            .as_ref()
            .and_then(|offsets| offsets.get(buffer))
            .copied()
            .unwrap_or(0);
        let size_hint = size_by_name.get(buffer).copied();
        let window = load_buffer_window(
            buffer,
            resume_offset,
            window_len,
            streaming_threshold_bytes,
            size_hint,
            socket,
        )
        .await?;
        buffer_texts.push(window);
    }

    let options = SearchOptions {
        context_bytes,
        max_matches,
        max_scan_bytes,
        include_similarity,
        fuzzy_match,
        similarity_threshold,
        resume_from_offset,
    };

    search_texts(buffer_texts, query, mode, options)
}

#[allow(clippy::too_many_arguments)]
pub async fn subsearch_buffer(
    buffer: &str,
    anchor_offset: u64,
    anchor_len: u32,
    context_bytes: u32,
    resume_from_offset: Option<u64>,
    query: &str,
    mode: SearchMode,
    max_matches: Option<u32>,
    include_similarity: bool,
    fuzzy_match: bool,
    similarity_threshold: Option<f32>,
    streaming_threshold_bytes: u64,
    socket: Option<&str>,
) -> Result<BufferSearchOutput> {
    let buffer_infos = list_buffers(socket).await?;
    let size_hint = buffer_infos
        .iter()
        .find(|info| info.name == buffer)
        .map(|info| info.size_bytes);

    let buffer_len = size_hint.unwrap_or(0) as usize;
    if anchor_offset as usize > buffer_len && size_hint.is_some() {
        return Err(Error::InvalidArgument {
            message: format!(
                "anchor offset {} exceeds buffer length {}",
                anchor_offset, buffer_len
            ),
        });
    }

    let context = context_bytes as u64;
    let anchor_len_u64 = anchor_len as u64;
    let start = anchor_offset.saturating_sub(context);
    let end = anchor_offset
        .saturating_add(anchor_len_u64)
        .saturating_add(context);
    let window_len = end.saturating_sub(start);

    let window = load_buffer_window(
        buffer,
        start,
        window_len,
        streaming_threshold_bytes,
        size_hint,
        socket,
    )
    .await?;

    let options = SubsearchOptions {
        context_bytes,
        max_matches,
        include_similarity,
        fuzzy_match,
        similarity_threshold,
        resume_from_offset,
    };

    subsearch_text_view(&window, anchor_offset, anchor_len, query, mode, options)
}

/// Get detailed info about a pane.
pub async fn pane_info(pane_id: &str, socket: Option<&str>) -> Result<PaneInfo> {
    let format = "#{pane_id}\t#{window_id}\t#{session_id}\t#{?pane_active,1,0}\t#{pane_title}\t#{pane_current_path}\t#{pane_current_command}\t#{pane_width}\t#{pane_height}\t#{pane_pid}\t#{?pane_in_mode,1,0}";
    let output =
        execute_tmux_with_socket(&["display-message", "-p", "-t", pane_id, format], socket).await?;
    let parts: Vec<&str> = output.split('\t').collect();
    if parts.len() >= 11 {
        Ok(PaneInfo {
            id: parts[0].to_string(),
            window_id: parts[1].to_string(),
            session_id: parts[2].to_string(),
            active: parts[3] == "1",
            title: parts[4].to_string(),
            current_path: parts[5].to_string(),
            current_command: parts[6].to_string(),
            width: parts[7].parse().unwrap_or(0),
            height: parts[8].parse().unwrap_or(0),
            pid: parts[9].parse().ok(),
            in_mode: parts[10] == "1",
        })
    } else {
        Err(Error::Parse {
            message: format!("failed to parse pane info: {output}"),
        })
    }
}

/// Get detailed info about a window.
pub async fn window_info(window_id: &str, socket: Option<&str>) -> Result<WindowInfo> {
    let format = "#{window_id}\t#{window_name}\t#{session_id}\t#{?window_active,1,0}\t#{window_layout}\t#{window_panes}\t#{window_width}\t#{window_height}\t#{window_zoomed_flag}\t#{pane_id}";
    let output =
        execute_tmux_with_socket(&["display-message", "-p", "-t", window_id, format], socket)
            .await?;
    let parts: Vec<&str> = output.split('\t').collect();
    if parts.len() >= 10 {
        Ok(WindowInfo {
            id: parts[0].to_string(),
            name: parts[1].to_string(),
            session_id: parts[2].to_string(),
            active: parts[3] == "1",
            layout: parts[4].to_string(),
            panes: parts[5].parse().unwrap_or(0),
            width: parts[6].parse().unwrap_or(0),
            height: parts[7].parse().unwrap_or(0),
            zoomed: parts[8] == "1",
            active_pane_id: parts[9].to_string(),
        })
    } else {
        Err(Error::Parse {
            message: format!("failed to parse window info: {output}"),
        })
    }
}

/// Create a new tmux session.
pub async fn create_session(name: &str, socket: Option<&str>) -> Result<Session> {
    let format = "#{session_id}\t#{session_name}\t#{?session_attached,1,0}\t#{session_windows}";
    let output = execute_tmux_with_socket(
        &["new-session", "-d", "-P", "-F", format, "-s", name],
        socket,
    )
    .await?;

    let parts: Vec<&str> = output.split('\t').collect();
    if parts.len() >= 4 {
        Ok(Session {
            id: parts[0].to_string(),
            name: parts[1].to_string(),
            attached: parts[2] == "1",
            windows: parts[3].parse().unwrap_or(1),
        })
    } else {
        Err(Error::Tmux {
            message: format!("failed to parse new session output: {output}"),
        })
    }
}

/// Create a new window in a session.
pub async fn create_window(session_id: &str, name: &str, socket: Option<&str>) -> Result<Window> {
    let format = "#{window_id}\t#{window_name}\t#{?window_active,1,0}";
    let output = execute_tmux_with_socket(
        &[
            "new-window",
            "-P",
            "-F",
            format,
            "-t",
            session_id,
            "-n",
            name,
        ],
        socket,
    )
    .await?;

    let parts: Vec<&str> = output.split('\t').collect();
    if parts.len() >= 3 {
        Ok(Window {
            id: parts[0].to_string(),
            name: parts[1].to_string(),
            active: parts[2] == "1",
            session_id: session_id.to_string(),
        })
    } else {
        Err(Error::Tmux {
            message: format!("failed to parse new window output: {output}"),
        })
    }
}

/// Split a pane.
pub async fn split_pane(
    pane_id: &str,
    direction: Option<&str>,
    size: Option<u32>,
    socket: Option<&str>,
) -> Result<Pane> {
    let dir_flag = match direction {
        Some("horizontal") | Some("h") => "-h",
        _ => "-v",
    };

    let format = "#{pane_id}\t#{pane_title}\t#{?pane_active,1,0}\t#{window_id}";
    let mut args = vec!["split-window", "-P", "-F", format, dir_flag, "-t", pane_id];

    let size_str;
    if let Some(s) = size {
        if s > 0 && s < 100 {
            size_str = s.to_string();
            args.push("-p");
            args.push(&size_str);
        }
    }

    let output = execute_tmux_with_socket(&args, socket).await?;

    let parts: Vec<&str> = output.split('\t').collect();
    if parts.len() >= 4 {
        Ok(Pane {
            id: parts[0].to_string(),
            title: parts[1].to_string(),
            active: parts[2] == "1",
            window_id: parts[3].to_string(),
        })
    } else {
        Err(Error::Tmux {
            message: format!("failed to parse new pane output: {output}"),
        })
    }
}

/// Kill a session.
pub async fn kill_session(session_id: &str, socket: Option<&str>) -> Result<()> {
    execute_tmux_with_socket(&["kill-session", "-t", session_id], socket).await?;
    Ok(())
}

/// Kill a window.
pub async fn kill_window(window_id: &str, socket: Option<&str>) -> Result<()> {
    execute_tmux_with_socket(&["kill-window", "-t", window_id], socket).await?;
    Ok(())
}

/// Kill a pane.
pub async fn kill_pane(pane_id: &str, socket: Option<&str>) -> Result<()> {
    execute_tmux_with_socket(&["kill-pane", "-t", pane_id], socket).await?;
    Ok(())
}

/// Send keys to a pane.
pub async fn send_keys(
    pane_id: &str,
    keys: &str,
    literal: bool,
    socket: Option<&str>,
) -> Result<()> {
    if literal {
        for ch in keys.chars() {
            let ch_str = ch.to_string();
            execute_tmux_with_socket(&["send-keys", "-t", pane_id, "-l", &ch_str], socket).await?;
        }
    } else {
        execute_tmux_with_socket(&["send-keys", "-t", pane_id, keys], socket).await?;
    }
    Ok(())
}

/// Get the current session (the one the client is attached to).
pub async fn get_current_session(socket: Option<&str>) -> Result<Session> {
    let format = "#{session_id}\t#{session_name}\t#{?session_attached,1,0}\t#{session_windows}";
    let output = execute_tmux_with_socket(&["display-message", "-p", format], socket).await?;

    let sessions = parse_sessions(&output);
    sessions.into_iter().next().ok_or_else(|| Error::Tmux {
        message: "current session not found".to_string(),
    })
}

/// Rename a session.
pub async fn rename_session(session_id: &str, name: &str, socket: Option<&str>) -> Result<()> {
    execute_tmux_with_socket(&["rename-session", "-t", session_id, name], socket).await?;
    Ok(())
}

/// Select (focus) a window.
pub async fn select_window(window_id: &str, socket: Option<&str>) -> Result<()> {
    execute_tmux_with_socket(&["select-window", "-t", window_id], socket).await?;
    Ok(())
}

/// Select (focus) a pane.
pub async fn select_pane(pane_id: &str, socket: Option<&str>) -> Result<()> {
    execute_tmux_with_socket(&["select-pane", "-t", pane_id], socket).await?;
    Ok(())
}

/// Resize a pane.
pub async fn resize_pane(
    pane_id: &str,
    direction: Option<&str>,
    amount: Option<u32>,
    width: Option<u32>,
    height: Option<u32>,
    socket: Option<&str>,
) -> Result<()> {
    let mut args: Vec<String> = vec!["resize-pane".into(), "-t".into(), pane_id.into()];

    if width.is_some() || height.is_some() {
        if let Some(w) = width {
            args.push("-x".into());
            args.push(w.to_string());
        }
        if let Some(h) = height {
            args.push("-y".into());
            args.push(h.to_string());
        }
    } else if let Some(dir) = direction {
        let flag = match dir {
            "left" | "l" => "-L",
            "right" | "r" => "-R",
            "up" | "u" => "-U",
            "down" | "d" => "-D",
            _ => {
                return Err(Error::InvalidArgument {
                    message: format!("unknown resize direction: {dir}"),
                })
            }
        };
        args.push(flag.into());
        if let Some(val) = amount {
            args.push(val.to_string());
        }
    } else {
        return Err(Error::InvalidArgument {
            message: "resize-pane requires direction/amount or width/height".to_string(),
        });
    }

    let arg_refs: Vec<&str> = args.iter().map(|arg| arg.as_str()).collect();
    execute_tmux_with_socket(&arg_refs, socket).await?;
    Ok(())
}

/// Toggle zoom for a pane.
pub async fn zoom_pane(pane_id: &str, socket: Option<&str>) -> Result<()> {
    execute_tmux_with_socket(&["resize-pane", "-Z", "-t", pane_id], socket).await?;
    Ok(())
}

/// Select a window layout.
pub async fn select_layout(window_id: &str, layout: &str, socket: Option<&str>) -> Result<()> {
    execute_tmux_with_socket(&["select-layout", "-t", window_id, layout], socket).await?;
    Ok(())
}

/// Join a source pane into a target pane's window.
pub async fn join_pane(
    source_pane_id: &str,
    target_pane_id: &str,
    socket: Option<&str>,
) -> Result<()> {
    execute_tmux_with_socket(
        &["join-pane", "-s", source_pane_id, "-t", target_pane_id],
        socket,
    )
    .await?;
    Ok(())
}

/// Break a pane out into its own window.
pub async fn break_pane(pane_id: &str, name: Option<&str>, socket: Option<&str>) -> Result<Window> {
    let format = "#{window_id}\t#{window_name}\t#{?window_active,1,0}\t#{session_id}";
    let mut args = vec!["break-pane", "-P", "-F", format, "-s", pane_id];
    if let Some(name) = name {
        args.push("-n");
        args.push(name);
    }
    let output = execute_tmux_with_socket(&args, socket).await?;
    let parts: Vec<&str> = output.split('\t').collect();
    if parts.len() >= 4 {
        Ok(Window {
            id: parts[0].to_string(),
            name: parts[1].to_string(),
            active: parts[2] == "1",
            session_id: parts[3].to_string(),
        })
    } else {
        Err(Error::Tmux {
            message: format!("failed to parse break-pane output: {output}"),
        })
    }
}

/// Swap two panes.
pub async fn swap_pane(
    source_pane_id: &str,
    target_pane_id: &str,
    socket: Option<&str>,
) -> Result<()> {
    execute_tmux_with_socket(
        &["swap-pane", "-s", source_pane_id, "-t", target_pane_id],
        socket,
    )
    .await?;
    Ok(())
}

/// Enable or disable synchronize-panes for a window.
pub async fn set_synchronize_panes(
    window_id: &str,
    enabled: bool,
    socket: Option<&str>,
) -> Result<()> {
    let value = if enabled { "on" } else { "off" };
    execute_tmux_with_socket(
        &["set-option", "-t", window_id, "synchronize-panes", value],
        socket,
    )
    .await?;
    Ok(())
}

/// Rename a window.
pub async fn rename_window(window_id: &str, name: &str, socket: Option<&str>) -> Result<()> {
    execute_tmux_with_socket(&["rename-window", "-t", window_id, name], socket).await?;
    Ok(())
}

/// Rename (set title of) a pane.
pub async fn rename_pane(pane_id: &str, title: &str, socket: Option<&str>) -> Result<()> {
    execute_tmux_with_socket(&["select-pane", "-t", pane_id, "-T", title], socket).await?;
    Ok(())
}

/// Move a window to another session.
pub async fn move_window(
    window_id: &str,
    target_session_id: &str,
    target_index: Option<u32>,
    socket: Option<&str>,
) -> Result<()> {
    let target = match target_index {
        Some(idx) => format!("{}:{}", target_session_id, idx),
        None => target_session_id.to_string(),
    };

    execute_tmux_with_socket(&["move-window", "-s", window_id, "-t", &target], socket).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TmuxStub;
    use rstest::rstest;

    #[rstest]
    #[case(
        "$0\tmain\t1\t3\n$1\tdev\t0\t2",
        vec![
            Session { id: "$0".into(), name: "main".into(), attached: true, windows: 3 },
            Session { id: "$1".into(), name: "dev".into(), attached: false, windows: 2 },
        ]
    )]
    #[case(
        "$5\twork\t1\t1",
        vec![
            Session { id: "$5".into(), name: "work".into(), attached: true, windows: 1 },
        ]
    )]
    #[case("", vec![])]
    fn test_parse_sessions(#[case] input: &str, #[case] expected: Vec<Session>) {
        let result = parse_sessions(input);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_sessions_skips_malformed_lines() {
        let input = "$0\tmain\t1\t2\ninvalid-line\n$1\tdev\t0\t1";
        let result = parse_sessions(input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "main");
        assert_eq!(result[1].name, "dev");
    }

    #[rstest]
    #[case(
        "@0\tzsh\t1\n@1\tvim\t0",
        "$0",
        vec![
            Window { id: "@0".into(), name: "zsh".into(), active: true, session_id: "$0".into() },
            Window { id: "@1".into(), name: "vim".into(), active: false, session_id: "$0".into() },
        ]
    )]
    #[case(
        "@5\teditor\t0",
        "$2",
        vec![
            Window { id: "@5".into(), name: "editor".into(), active: false, session_id: "$2".into() },
        ]
    )]
    #[case("", "$0", vec![])]
    fn test_parse_windows(
        #[case] input: &str,
        #[case] session_id: &str,
        #[case] expected: Vec<Window>,
    ) {
        let result = parse_windows(input, session_id);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_windows_skips_malformed_lines() {
        let input = "@0\tzsh\t1\nbad-line\n@1\tvim\t0";
        let result = parse_windows(input, "$0");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "zsh");
        assert_eq!(result[1].name, "vim");
    }

    #[rstest]
    #[case(
        "%0\tbash\t1\n%1\thtop\t0",
        "@0",
        vec![
            Pane { id: "%0".into(), title: "bash".into(), active: true, window_id: "@0".into() },
            Pane { id: "%1".into(), title: "htop".into(), active: false, window_id: "@0".into() },
        ]
    )]
    #[case(
        "%10\tvim\t1",
        "@5",
        vec![
            Pane { id: "%10".into(), title: "vim".into(), active: true, window_id: "@5".into() },
        ]
    )]
    #[case("", "@0", vec![])]
    fn test_parse_panes(#[case] input: &str, #[case] window_id: &str, #[case] expected: Vec<Pane>) {
        let result = parse_panes(input, window_id);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_panes_skips_malformed_lines() {
        let input = "%0\tbash\t1\nbad-line\n%1\thtop\t0";
        let result = parse_panes(input, "@0");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].title, "bash");
        assert_eq!(result[1].title, "htop");
    }

    #[rstest]
    #[case(
        "buffer0\t10\t1700000000\nbuffer1\t5\t1700000100",
        vec![
            BufferInfo { name: "buffer0".into(), size: 10, size_bytes: 10, order_index: 0, created: Some(1700000000) },
            BufferInfo { name: "buffer1".into(), size: 5, size_bytes: 5, order_index: 1, created: Some(1700000100) },
        ]
    )]
    #[case("", vec![])]
    fn test_parse_buffers(#[case] input: &str, #[case] expected: Vec<BufferInfo>) {
        let result = parse_buffers(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case("$0\tmy:session:with:colons\t1\t2", vec![
        Session { id: "$0".into(), name: "my:session:with:colons".into(), attached: true, windows: 2 },
    ])]
    fn test_parse_sessions_with_colons_in_name(
        #[case] input: &str,
        #[case] expected: Vec<Session>,
    ) {
        let result = parse_sessions(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case("@0\twindow:with:colons\t1", "$0", vec![
        Window { id: "@0".into(), name: "window:with:colons".into(), active: true, session_id: "$0".into() },
    ])]
    fn test_parse_windows_with_colons(
        #[case] input: &str,
        #[case] session_id: &str,
        #[case] expected: Vec<Window>,
    ) {
        let result = parse_windows(input, session_id);
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn execute_tmux_success() {
        let _stub = TmuxStub::new();
        let output = execute_tmux(&["list-sessions", "-F", "ignored"])
            .await
            .expect("execute tmux");
        assert!(output.contains("alpha"));
    }

    #[tokio::test]
    async fn execute_tmux_spawn_error() {
        let mut stub = TmuxStub::new();
        stub.set_var("PATH", "/nonexistent");

        let err = execute_tmux(&["list-sessions"]).await.unwrap_err();
        match err {
            Error::Tmux { message } => assert!(message.contains("failed to spawn tmux")),
            _ => panic!("expected tmux error"),
        }
    }

    #[tokio::test]
    async fn execute_tmux_error_message() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_FORCE_ERROR", "1");
        stub.set_var("TMUX_STUB_ERROR_MSG", "boom");

        let err = execute_tmux(&["list-sessions"]).await.unwrap_err();
        match err {
            Error::Tmux { message } => assert!(message.contains("boom")),
            _ => panic!("expected tmux error"),
        }
    }

    #[tokio::test]
    async fn is_tmux_running_reports_states() {
        let mut stub = TmuxStub::new();

        stub.remove_var("TMUX_STUB_FORCE_ERROR");
        stub.remove_var("TMUX_STUB_ERROR_MSG");
        assert!(is_tmux_running().await.unwrap());

        stub.set_var("TMUX_STUB_FORCE_ERROR", "1");
        stub.set_var("TMUX_STUB_ERROR_MSG", "no server running");
        assert!(!is_tmux_running().await.unwrap());

        stub.set_var("TMUX_STUB_ERROR_MSG", "no sessions");
        assert!(is_tmux_running().await.unwrap());

        stub.set_var("TMUX_STUB_ERROR_MSG", "unexpected failure");
        assert!(is_tmux_running().await.is_err());
    }

    #[tokio::test]
    async fn execute_tmux_uses_socket_args() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_MCP_SOCKET", "/tmp/tmux-test.sock");

        let output = execute_tmux(&["socket-test"]).await.expect("socket test");
        assert_eq!(output, "/tmp/tmux-test.sock");
    }

    #[tokio::test]
    async fn execute_tmux_uses_ssh_when_configured() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_MCP_SSH", "user@host");

        let output = execute_tmux(&["ssh-test"]).await.expect("ssh test");
        assert_eq!(output, "via-ssh");
    }

    #[tokio::test]
    async fn create_session_parses_output() {
        let _stub = TmuxStub::new();
        let session = create_session("new-session", None)
            .await
            .expect("create session");
        assert_eq!(session.name, "new-session");
    }

    #[tokio::test]
    async fn create_session_handles_bad_output() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_NEW_SESSION_OUTPUT", "bad-output");

        let err = create_session("bad", None).await.unwrap_err();
        match err {
            Error::Tmux { message } => assert!(message.contains("failed to parse new session")),
            _ => panic!("expected tmux error"),
        }
    }

    #[tokio::test]
    async fn create_window_parses_output() {
        let _stub = TmuxStub::new();
        let window = create_window("%1", "new-window", None)
            .await
            .expect("create window");
        assert_eq!(window.name, "new-window");
    }

    #[tokio::test]
    async fn create_window_handles_bad_output() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_NEW_WINDOW_OUTPUT", "bad-output");

        let err = create_window("%1", "bad", None).await.unwrap_err();
        match err {
            Error::Tmux { message } => assert!(message.contains("failed to parse new window")),
            _ => panic!("expected tmux error"),
        }
    }

    #[tokio::test]
    async fn split_pane_parses_output() {
        let _stub = TmuxStub::new();
        let pane = split_pane("%1", Some("horizontal"), Some(50), None)
            .await
            .expect("split pane");
        assert_eq!(pane.id, "%3");
    }

    #[tokio::test]
    async fn split_pane_handles_bad_output() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_SPLIT_WINDOW_OUTPUT", "bad-output");

        let err = split_pane("%1", Some("vertical"), Some(50), None)
            .await
            .unwrap_err();
        match err {
            Error::Tmux { message } => assert!(message.contains("failed to parse new pane")),
            _ => panic!("expected tmux error"),
        }
    }

    #[tokio::test]
    async fn break_pane_parses_output() {
        let _stub = TmuxStub::new();
        let window = break_pane("%1", Some("breakout"), None)
            .await
            .expect("break pane");
        assert_eq!(window.id, "@9");
        assert_eq!(window.name, "broken");
        assert_eq!(window.session_id, "%1");
    }

    #[tokio::test]
    async fn break_pane_handles_bad_output() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_BREAK_PANE_OUTPUT", "bad-output");

        let err = break_pane("%1", None, None).await.unwrap_err();
        match err {
            Error::Tmux { message } => assert!(message.contains("failed to parse break-pane")),
            _ => panic!("expected tmux error"),
        }
    }

    #[tokio::test]
    async fn capture_pane_returns_content() {
        let _stub = TmuxStub::new();
        let content = capture_pane("%1", Some(10), true, None, None, false, None)
            .await
            .expect("capture pane");
        assert!(content.contains("stub-output"));
    }

    #[tokio::test]
    async fn list_windows_and_panes() {
        let _stub = TmuxStub::new();
        let windows = list_windows("%1", None).await.expect("list windows");
        assert_eq!(windows.len(), 2);

        let panes = list_panes("@1", None).await.expect("list panes");
        assert_eq!(panes.len(), 2);
    }

    #[tokio::test]
    async fn get_current_session_handles_missing() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_CURRENT_SESSION_OUTPUT", " ");

        let err = get_current_session(None).await.unwrap_err();
        match err {
            Error::Tmux { message } => assert!(message.contains("current session not found")),
            _ => panic!("expected tmux error"),
        }
    }

    #[tokio::test]
    async fn select_layout_happy_path() {
        let _stub = TmuxStub::new();
        select_layout("@1", "tiled", None)
            .await
            .expect("select layout");
    }

    #[tokio::test]
    async fn select_layout_tmux_error() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_ERROR_CMD", "select-layout");
        stub.set_var("TMUX_STUB_ERROR_MSG", "layout-fail");

        let err = select_layout("@1", "tiled", None).await.unwrap_err();
        match err {
            Error::Tmux { message } => assert!(message.contains("layout-fail")),
            _ => panic!("expected tmux error"),
        }
    }

    #[tokio::test]
    async fn join_and_swap_panes_happy_path() {
        let _stub = TmuxStub::new();
        join_pane("%1", "%2", None).await.expect("join pane");
        swap_pane("%1", "%2", None).await.expect("swap pane");
    }

    #[tokio::test]
    async fn zoom_pane_happy_path() {
        let _stub = TmuxStub::new();
        zoom_pane("%1", None).await.expect("zoom pane");
    }

    #[tokio::test]
    async fn resize_pane_invalid_direction_returns_error() {
        let _stub = TmuxStub::new();
        let err = resize_pane("%1", Some("diagonal"), Some(5), None, None, None)
            .await
            .unwrap_err();
        match err {
            Error::InvalidArgument { message } => {
                assert!(message.contains("unknown resize direction"))
            }
            _ => panic!("expected invalid argument error"),
        }
    }

    #[tokio::test]
    async fn resize_pane_requires_dimensions_or_direction() {
        let _stub = TmuxStub::new();
        let err = resize_pane("%1", None, None, None, None, None)
            .await
            .unwrap_err();
        match err {
            Error::InvalidArgument { message } => {
                assert!(message.contains("resize-pane requires direction/amount or width/height"))
            }
            _ => panic!("expected invalid argument error"),
        }
    }

    #[tokio::test]
    async fn search_buffers_returns_offsets_and_snippets() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_SHOW_BUFFER", "alpha beta gamma beta");

        let result = search_buffers(
            Some(vec!["buffer0".to_string()]),
            "beta",
            SearchMode::Literal,
            Some(2),
            Some(10),
            Some(1024),
            false,
            false,
            None,
            None,
            262_144,
            None,
        )
        .await
        .expect("search buffers");

        assert_eq!(result.total_matches, 2);
        assert_eq!(result.matches.len(), 2);
        assert_eq!(result.matches[0].offset_bytes, 6);
        assert!(result.matches[0].snippet.contains("beta"));
    }

    #[tokio::test]
    async fn search_buffers_streaming_uses_scan_window() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_LIST_BUFFERS", "buffer0\t15\t0");
        stub.set_var("TMUX_STUB_SHOW_BUFFER", "aaaaabbbbbccccc");

        let result = search_buffers(
            Some(vec!["buffer0".to_string()]),
            "b",
            SearchMode::Literal,
            Some(0),
            Some(10),
            Some(5),
            false,
            false,
            None,
            None,
            1,
            None,
        )
        .await
        .expect("search buffers");

        assert_eq!(result.total_matches, 0);
        assert!(result.truncated_buffers.contains(&"buffer0".to_string()));
        assert_eq!(result.resume_from_offset.get("buffer0"), Some(&5));
    }

    #[test]
    fn decode_window_rejects_invalid_utf8() {
        let bytes = [0xff, 0xff];
        let err = decode_window("buffer0", &bytes, 0).unwrap_err();
        match err {
            Error::InvalidArgument { message } => {
                assert!(message.contains("non-UTF-8"));
            }
            _ => panic!("expected invalid argument error"),
        }
    }

    #[test]
    fn resolve_socket_prefers_override_and_env() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_MCP_SOCKET", "/tmp/env.sock");

        assert_eq!(resolve_socket(None), Some("/tmp/env.sock".to_string()));
        assert_eq!(
            resolve_socket(Some("/tmp/override.sock")),
            Some("/tmp/override.sock".to_string())
        );
        assert_eq!(resolve_socket(Some("")), None);

        stub.set_var("TMUX_MCP_SOCKET", "");
        assert_eq!(resolve_socket(None), None);
    }

    #[tokio::test]
    async fn execute_tmux_invalid_ssh_returns_error() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_MCP_SSH", "user@host \"unterminated");

        let err = execute_tmux(&["list-sessions"]).await.unwrap_err();
        match err {
            Error::InvalidArgument { message } => {
                assert!(message.contains("invalid TMUX_MCP_SSH"))
            }
            _ => panic!("expected invalid argument error"),
        }
    }
}
