#![allow(dead_code)]

use tokio::process::Command;

use crate::errors::{Error, Result};
use crate::types::{BufferInfo, ClientInfo, Pane, PaneInfo, Session, Window, WindowInfo};

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

/// Execute a tmux command with the given arguments and return stdout.
pub async fn execute_tmux_with_socket(args: &[&str], socket: Option<&str>) -> Result<String> {
    let socket_args = get_socket_args(socket);
    let ssh_args = get_ssh_args()?;

    let output = if let Some(mut ssh_args) = ssh_args {
        ssh_args.push("tmux".to_string());
        ssh_args.extend(socket_args);
        ssh_args.extend(args.iter().map(|arg| (*arg).to_string()));
        Command::new("ssh")
            .args(&ssh_args)
            .output()
            .await
            .map_err(|e| Error::Tmux {
                message: format!("failed to spawn ssh: {e}"),
            })?
    } else {
        let mut tmux_args = socket_args;
        tmux_args.extend(args.iter().map(|arg| (*arg).to_string()));
        Command::new("tmux")
            .args(&tmux_args)
            .output()
            .await
            .map_err(|e| Error::Tmux {
                message: format!("failed to spawn tmux: {e}"),
            })?
    };

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(Error::Tmux { message: stderr })
    }
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
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                Some(BufferInfo {
                    name: parts[0].to_string(),
                    size: parts[1].parse().unwrap_or(0),
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
    execute_tmux_with_socket(&args, socket).await
}

/// Save a tmux buffer to a file path.
pub async fn save_buffer(name: &str, path: &str, socket: Option<&str>) -> Result<()> {
    execute_tmux_with_socket(&["save-buffer", "-b", name, path], socket).await?;
    Ok(())
}

/// Delete a tmux buffer.
pub async fn delete_buffer(name: &str, socket: Option<&str>) -> Result<()> {
    execute_tmux_with_socket(&["delete-buffer", "-b", name], socket).await?;
    Ok(())
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
