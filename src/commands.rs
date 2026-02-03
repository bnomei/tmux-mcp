//! Command execution tracking with markers for tmux-mcp.
//!
//! This module provides the `CommandTracker` struct that manages command execution
//! in tmux panes, using special markers to track command start/completion and exit codes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use regex::Regex;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::errors::Result;
use crate::tmux;
use crate::types::{CommandExecution, CommandStatus, ShellType};

/// Marker echoed before command execution begins.
pub const START_MARKER: &str = "TMUX_MCP_START";

/// Prefix for the end marker, followed by exit code.
pub const END_MARKER_PREFIX: &str = "TMUX_MCP_DONE_";

/// Compiled regex for matching end markers with exit codes.
static END_MARKER_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&format!(r"{}(\d+)", regex::escape(END_MARKER_PREFIX)))
        .expect("END_MARKER_REGEX should be valid")
});

/// Tracks active and recently completed commands across tmux panes.
#[derive(Debug)]
pub struct CommandTracker {
    active_commands: Arc<RwLock<HashMap<String, CommandExecution>>>,
    shell_type: ShellType,
}

impl CommandTracker {
    /// Create a new CommandTracker for the given shell type.
    pub fn new(shell_type: ShellType) -> Self {
        Self {
            active_commands: Arc::new(RwLock::new(HashMap::new())),
            shell_type,
        }
    }

    /// Execute a command in a tmux pane with optional tracking markers.
    ///
    /// Returns the command ID that can be used to check status.
    pub async fn execute_command(
        &self,
        pane_id: &str,
        command: &str,
        raw_mode: bool,
        no_enter: bool,
        delay_ms: Option<u64>,
        socket: Option<String>,
    ) -> Result<String> {
        let command_id = Uuid::new_v4().to_string();
        let resolved_socket = tmux::resolve_socket(socket.as_deref());

        let (wrapped_command, tracking_disabled) = if raw_mode || no_enter {
            (command.to_string(), true)
        } else {
            let end_marker = get_end_marker(&self.shell_type);
            let wrapped = format!(
                "echo \"{}\"; {}; echo \"{}\"",
                START_MARKER, command, end_marker
            );
            (wrapped, false)
        };

        let execution = CommandExecution {
            id: command_id.clone(),
            pane_id: pane_id.to_string(),
            socket: resolved_socket.clone(),
            command: command.to_string(),
            status: CommandStatus::Pending,
            exit_code: None,
            output: if tracking_disabled {
                Some("Tracking disabled for raw_mode or no_enter commands".to_string())
            } else {
                None
            },
            started_at: Instant::now(),
            completed_at: None,
            raw_mode,
        };

        {
            let mut commands = self.active_commands.write().await;
            commands.insert(command_id.clone(), execution);
        }

        if let Some(delay) = delay_ms {
            for ch in wrapped_command.chars() {
                tmux::send_keys(pane_id, &ch.to_string(), true, resolved_socket.as_deref()).await?;
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            if !no_enter {
                tmux::send_keys(pane_id, "Enter", false, resolved_socket.as_deref()).await?;
            }
        } else {
            // Send command as a whole (not literal/per-character)
            tmux::send_keys(pane_id, &wrapped_command, false, resolved_socket.as_deref()).await?;
            // Send Enter if needed
            if !no_enter {
                tmux::send_keys(pane_id, "Enter", false, resolved_socket.as_deref()).await?;
            }
        }

        Ok(command_id)
    }

    /// Check the status of a command by its ID.
    ///
    /// Returns `None` if the command ID is not found.
    /// Updates the command status based on captured pane output.
    pub async fn check_status(
        &self,
        command_id: &str,
        socket_override: Option<&str>,
    ) -> Result<Option<CommandExecution>> {
        let execution = {
            let commands = self.active_commands.read().await;
            commands.get(command_id).cloned()
        };

        let mut execution = match execution {
            Some(e) => e,
            None => return Ok(None),
        };

        match execution.status {
            CommandStatus::Completed | CommandStatus::Error => {
                return Ok(Some(execution));
            }
            CommandStatus::Pending if execution.raw_mode => {
                return Ok(Some(execution));
            }
            _ => {}
        }

        let captured_output = tmux::capture_pane(
            &execution.pane_id,
            Some(1000),
            false,
            None,
            None,
            false,
            execution.socket.as_deref().or(socket_override),
        )
        .await?;

        if let Some((output, exit_code)) = parse_command_output(&captured_output) {
            execution.exit_code = Some(exit_code);
            execution.output = Some(output);
            execution.completed_at = Some(Instant::now());
            execution.status = if exit_code == 0 {
                CommandStatus::Completed
            } else {
                CommandStatus::Error
            };

            let mut commands = self.active_commands.write().await;
            commands.insert(command_id.to_string(), execution.clone());
        }

        Ok(Some(execution))
    }

    /// Get a command by ID without updating its status.
    pub async fn get_command(&self, id: &str) -> Option<CommandExecution> {
        let commands = self.active_commands.read().await;
        commands.get(id).cloned()
    }

    /// Get all active command IDs.
    pub async fn get_active_ids(&self) -> Vec<String> {
        let commands = self.active_commands.read().await;
        commands.keys().cloned().collect()
    }

    /// Remove completed commands older than the specified threshold.
    #[allow(dead_code)]
    pub async fn cleanup_old(&self, max_age_minutes: u64) {
        let threshold = Duration::from_secs(max_age_minutes * 60);
        let now = Instant::now();

        let mut commands = self.active_commands.write().await;
        commands.retain(|_, exec| {
            if let Some(completed_at) = exec.completed_at {
                now.duration_since(completed_at) < threshold
            } else {
                true
            }
        });
    }
}

/// Get the end marker command for the given shell type.
///
/// Fish shell uses `$status` for exit codes, while bash/zsh use `$?`.
pub fn get_end_marker(shell: &ShellType) -> String {
    match shell {
        ShellType::Fish => format!("{}$status", END_MARKER_PREFIX),
        ShellType::Bash | ShellType::Zsh | ShellType::Unknown => {
            format!("{}$?", END_MARKER_PREFIX)
        }
    }
}

/// Parse captured output to extract command output and exit code.
///
/// Looks for the last START_MARKER and END_MARKER_PREFIX pair.
/// Returns `None` if markers are not found or incomplete.
fn parse_command_output(captured: &str) -> Option<(String, i32)> {
    let start_idx = captured.rfind(START_MARKER)?;
    let after_start = &captured[start_idx + START_MARKER.len()..];

    // Find the LAST match of the end marker (not the first)
    // This is important because the pane output may contain the typed command line
    // (e.g., `echo TMUX_MCP_DONE_$?`) before the actual echoed output
    let last_match = END_MARKER_REGEX.captures_iter(after_start).last()?;

    let exit_code: i32 = last_match.get(1)?.as_str().parse().ok()?;

    let end_match = last_match.get(0)?;
    let output_end = end_match.start();

    let output = after_start[..output_end].trim().to_string();

    Some((output, exit_code))
}

/// Extract exit code from an end marker line.
#[allow(dead_code)]
fn extract_exit_code(line: &str) -> Option<i32> {
    if line.contains(END_MARKER_PREFIX) {
        let caps = END_MARKER_REGEX.captures(line)?;
        caps.get(1)?.as_str().parse().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::Error;
    use crate::test_support::TmuxStub;
    use crate::types::{CommandExecution, CommandStatus};
    use rstest::rstest;
    use std::time::Duration;

    #[rstest]
    #[case(ShellType::Bash, "TMUX_MCP_DONE_$?")]
    #[case(ShellType::Zsh, "TMUX_MCP_DONE_$?")]
    #[case(ShellType::Fish, "TMUX_MCP_DONE_$status")]
    #[case(ShellType::Unknown, "TMUX_MCP_DONE_$?")]
    fn test_get_end_marker(#[case] shell: ShellType, #[case] expected: &str) {
        assert_eq!(get_end_marker(&shell), expected);
    }

    #[rstest]
    #[case("TMUX_MCP_DONE_0", Some(0))]
    #[case("TMUX_MCP_DONE_1", Some(1))]
    #[case("TMUX_MCP_DONE_127", Some(127))]
    #[case("TMUX_MCP_DONE_255", Some(255))]
    #[case("some output TMUX_MCP_DONE_42 more text", Some(42))]
    #[case("no marker here", None)]
    #[case("TMUX_MCP_DONE_", None)]
    #[case("TMUX_MCP_DONE_abc", None)]
    fn test_extract_exit_code(#[case] input: &str, #[case] expected: Option<i32>) {
        assert_eq!(extract_exit_code(input), expected);
    }

    #[rstest]
    #[case(
        "prompt$ TMUX_MCP_START\nhello world\nTMUX_MCP_DONE_0\nprompt$",
        Some(("hello world".to_string(), 0))
    )]
    #[case(
        "TMUX_MCP_START\nerror occurred\nTMUX_MCP_DONE_1",
        Some(("error occurred".to_string(), 1))
    )]
    #[case(
        "old TMUX_MCP_START\nold output\nTMUX_MCP_DONE_0\nnew TMUX_MCP_START\nnew output\nTMUX_MCP_DONE_2",
        Some(("new output".to_string(), 2))
    )]
    #[case(
        "TMUX_MCP_START\nline1\nline2\nline3\nTMUX_MCP_DONE_0",
        Some(("line1\nline2\nline3".to_string(), 0))
    )]
    #[case("no markers at all", None)]
    #[case("TMUX_MCP_START\nno end marker", None)]
    #[case("TMUX_MCP_DONE_0\nno start marker", None)]
    fn test_parse_command_output(#[case] input: &str, #[case] expected: Option<(String, i32)>) {
        assert_eq!(parse_command_output(input), expected);
    }

    #[rstest]
    #[case(
        "$ echo TMUX_MCP_START\nTMUX_MCP_START\n$ ls -la\ntotal 0\ndrwxr-xr-x  2 user user  40 Jan  1 00:00 .\ndrwxr-xr-x 10 user user 200 Jan  1 00:00 ..\n$ echo TMUX_MCP_DONE_0\nTMUX_MCP_DONE_0\n$",
        Some(0)
    )]
    #[case(
        "TMUX_MCP_START\ncommand not found: foobar\nTMUX_MCP_DONE_127",
        Some(127)
    )]
    fn test_parse_realistic_output(#[case] input: &str, #[case] expected_exit: Option<i32>) {
        let result = parse_command_output(input);
        match (result, expected_exit) {
            (Some((_, code)), Some(expected)) => assert_eq!(code, expected),
            (None, None) => {}
            (result, expected) => panic!("Expected {:?}, got {:?}", expected, result),
        }
    }

    #[test]
    fn test_markers_are_correct() {
        assert_eq!(START_MARKER, "TMUX_MCP_START");
        assert_eq!(END_MARKER_PREFIX, "TMUX_MCP_DONE_");
    }

    #[rstest]
    fn test_command_tracker_new() {
        let tracker = CommandTracker::new(ShellType::Bash);
        assert!(matches!(tracker.shell_type, ShellType::Bash));
    }

    #[tokio::test]
    async fn execute_command_with_delay_sends_enter() {
        let _stub = TmuxStub::new();
        let tracker = CommandTracker::new(ShellType::Bash);

        let id = tracker
            .execute_command("%1", "echo hi", false, false, Some(0), None)
            .await
            .expect("execute command");

        assert!(!id.is_empty());
    }

    #[tokio::test]
    async fn execute_command_without_delay_sends_enter() {
        let _stub = TmuxStub::new();
        let tracker = CommandTracker::new(ShellType::Bash);

        let id = tracker
            .execute_command("%1", "echo hi", false, false, None, None)
            .await
            .expect("execute command");

        assert!(!id.is_empty());
    }

    #[tokio::test]
    async fn execute_command_returns_error_when_send_keys_fails() {
        let mut stub = TmuxStub::new();
        stub.set_var("TMUX_STUB_ERROR_CMD", "send-keys");
        let tracker = CommandTracker::new(ShellType::Bash);

        let err = tracker
            .execute_command("%1", "echo hi", false, false, None, None)
            .await
            .unwrap_err();

        match err {
            Error::Tmux { message } => assert!(message.contains("stub error")),
            _ => panic!("expected tmux error"),
        }
    }

    #[tokio::test]
    async fn check_status_returns_early_for_completed() {
        let tracker = CommandTracker::new(ShellType::Bash);
        let id = "completed-cmd".to_string();
        let execution = CommandExecution {
            id: id.clone(),
            pane_id: "%1".into(),
            socket: None,
            command: "echo done".into(),
            status: CommandStatus::Completed,
            exit_code: Some(0),
            output: Some("done".into()),
            started_at: Instant::now(),
            completed_at: Some(Instant::now()),
            raw_mode: false,
        };

        {
            let mut commands = tracker.active_commands.write().await;
            commands.insert(id.clone(), execution);
        }

        let result = tracker.check_status(&id, None).await.expect("check status");
        assert!(matches!(
            result.map(|cmd| cmd.status),
            Some(CommandStatus::Completed)
        ));
    }

    #[tokio::test]
    async fn check_status_returns_none_for_unknown_id() {
        let tracker = CommandTracker::new(ShellType::Bash);
        let result = tracker
            .check_status("missing-command", None)
            .await
            .expect("check status");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn check_status_sets_error_on_nonzero_exit() {
        let mut stub = TmuxStub::new();
        stub.set_var(
            "TMUX_STUB_CAPTURE_OUTPUT",
            "TMUX_MCP_START\nbad\nTMUX_MCP_DONE_1\n",
        );
        let tracker = CommandTracker::new(ShellType::Bash);
        let id = "error-cmd".to_string();
        let execution = CommandExecution {
            id: id.clone(),
            pane_id: "%1".into(),
            socket: None,
            command: "false".into(),
            status: CommandStatus::Pending,
            exit_code: None,
            output: None,
            started_at: Instant::now(),
            completed_at: None,
            raw_mode: false,
        };

        {
            let mut commands = tracker.active_commands.write().await;
            commands.insert(id.clone(), execution);
        }

        let result = tracker.check_status(&id, None).await.expect("check status");
        let status = result.map(|cmd| cmd.status).unwrap();
        assert_eq!(status, CommandStatus::Error);
    }

    #[tokio::test]
    async fn cleanup_old_removes_stale() {
        let tracker = CommandTracker::new(ShellType::Bash);
        let old_id = "old".to_string();
        let new_id = "new".to_string();
        let pending_id = "pending".to_string();

        let old_exec = CommandExecution {
            id: old_id.clone(),
            pane_id: "%1".into(),
            socket: None,
            command: "old".into(),
            status: CommandStatus::Completed,
            exit_code: Some(0),
            output: Some("old".into()),
            started_at: Instant::now(),
            completed_at: Some(Instant::now() - Duration::from_secs(120)),
            raw_mode: false,
        };
        let new_exec = CommandExecution {
            id: new_id.clone(),
            pane_id: "%1".into(),
            socket: None,
            command: "new".into(),
            status: CommandStatus::Completed,
            exit_code: Some(0),
            output: Some("new".into()),
            started_at: Instant::now(),
            completed_at: Some(Instant::now()),
            raw_mode: false,
        };
        let pending_exec = CommandExecution {
            id: pending_id.clone(),
            pane_id: "%1".into(),
            socket: None,
            command: "pending".into(),
            status: CommandStatus::Pending,
            exit_code: None,
            output: None,
            started_at: Instant::now(),
            completed_at: None,
            raw_mode: false,
        };

        {
            let mut commands = tracker.active_commands.write().await;
            commands.insert(old_id.clone(), old_exec);
            commands.insert(new_id.clone(), new_exec);
            commands.insert(pending_id.clone(), pending_exec);
        }

        tracker.cleanup_old(1).await;

        let commands = tracker.active_commands.read().await;
        assert!(!commands.contains_key(&old_id));
        assert!(commands.contains_key(&new_id));
        assert!(commands.contains_key(&pending_id));
    }
}
