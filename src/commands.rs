//! Command execution tracking with markers for tmux-mcp.
//!
//! This module provides the `CommandTracker` struct that manages command execution
//! in tmux panes, using special markers to track command start/completion and exit codes.

use std::collections::HashMap;
#[cfg(test)]
use std::ffi::OsString;
use std::sync::Arc;
use std::time::{Duration, Instant};

use regex::Regex;
use serde::Deserialize;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::errors::Result;
use crate::tmux;
use crate::types::{CommandExecution, CommandStatus, ShellType};

/// Prefix for the start marker, followed by command id.
pub const START_MARKER_PREFIX: &str = "TMUX_MCP_START_";

/// Prefix for the end marker, followed by command id and exit code.
pub const END_MARKER_PREFIX: &str = "TMUX_MCP_DONE_";

#[cfg(test)]
struct EnvVarGuard {
    key: &'static str,
    prev: Option<OsString>,
}

#[cfg(test)]
impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, prev }
    }
}

#[cfg(test)]
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(prev) = self.prev.take() {
            std::env::set_var(self.key, prev);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

/// Tracking configuration for command capture retries.
#[derive(Debug, Clone, Deserialize)]
pub struct TrackingConfig {
    #[serde(default = "default_capture_initial_lines")]
    pub capture_initial_lines: u32,
    #[serde(default = "default_capture_max_lines")]
    pub capture_max_lines: u32,
    #[serde(default = "default_capture_backoff_factor")]
    pub capture_backoff_factor: u32,
}

fn default_capture_initial_lines() -> u32 {
    1000
}

fn default_capture_max_lines() -> u32 {
    16_000
}

fn default_capture_backoff_factor() -> u32 {
    2
}

impl Default for TrackingConfig {
    fn default() -> Self {
        Self {
            capture_initial_lines: default_capture_initial_lines(),
            capture_max_lines: default_capture_max_lines(),
            capture_backoff_factor: default_capture_backoff_factor(),
        }
    }
}

/// Tracks active and recently completed commands across tmux panes.
#[derive(Debug)]
pub struct CommandTracker {
    active_commands: Arc<RwLock<HashMap<String, CommandExecution>>>,
    shell_type: ShellType,
    tracking: TrackingConfig,
}

impl CommandTracker {
    /// Create a new CommandTracker for the given shell type.
    pub fn new(shell_type: ShellType) -> Self {
        Self::with_tracking(shell_type, TrackingConfig::default())
    }

    /// Create a new CommandTracker with custom tracking configuration.
    pub fn with_tracking(shell_type: ShellType, tracking: TrackingConfig) -> Self {
        Self {
            active_commands: Arc::new(RwLock::new(HashMap::new())),
            shell_type,
            tracking,
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
            let end_marker = get_end_marker(&self.shell_type, &command_id);
            let start_marker = get_start_marker(&command_id);
            let wrapped = format!(
                "echo \"{}\"; {}; echo \"{}\"",
                start_marker, command, end_marker
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
            tracking_disabled,
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
            CommandStatus::Pending if execution.raw_mode || execution.tracking_disabled => {
                return Ok(Some(execution));
            }
            _ => {}
        }

        #[cfg(test)]
        let _env_guard = EnvVarGuard::set("TMUX_MCP_TEST_COMMAND_ID", &execution.id);

        let mut capture_lines = self.tracking.capture_initial_lines.max(1);
        let max_lines = self.tracking.capture_max_lines.max(capture_lines);
        let backoff = self.tracking.capture_backoff_factor.max(1);

        loop {
            let captured_output = tmux::capture_pane(
                &execution.pane_id,
                Some(capture_lines),
                false,
                None,
                None,
                false,
                execution.socket.as_deref().or(socket_override),
            )
            .await?;

            if let Some((output, exit_code)) = parse_command_output(&captured_output, &execution.id)
            {
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
                break;
            }

            if capture_lines >= max_lines {
                execution.status = CommandStatus::Error;
                execution.output =
                    Some("tracking expired; markers not found in pane history".to_string());
                execution.completed_at = Some(Instant::now());

                let mut commands = self.active_commands.write().await;
                commands.insert(command_id.to_string(), execution.clone());
                break;
            }

            capture_lines = (capture_lines.saturating_mul(backoff)).min(max_lines);
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
pub fn get_start_marker(command_id: &str) -> String {
    format!("{START_MARKER_PREFIX}{command_id}")
}

fn end_marker_prefix(command_id: &str) -> String {
    format!("{END_MARKER_PREFIX}{command_id}_")
}

pub fn get_end_marker(shell: &ShellType, command_id: &str) -> String {
    let prefix = end_marker_prefix(command_id);
    match shell {
        ShellType::Fish => format!("{prefix}$status"),
        ShellType::Bash | ShellType::Zsh | ShellType::Unknown => format!("{prefix}$?"),
    }
}

/// Parse captured output to extract command output and exit code.
///
/// Looks for the last command-specific marker pair.
/// Returns `None` if markers are not found or incomplete.
fn parse_command_output(captured: &str, command_id: &str) -> Option<(String, i32)> {
    let start_marker = get_start_marker(command_id);
    let start_idx = captured.rfind(&start_marker)?;
    let after_start = &captured[start_idx + start_marker.len()..];

    // Find the LAST match of the end marker (not the first)
    // This is important because the pane output may contain the typed command line
    // (e.g., `echo TMUX_MCP_DONE_<id>_$?`) before the actual echoed output
    let end_prefix = end_marker_prefix(command_id);
    let end_regex = Regex::new(&format!(r"{}(\d+)", regex::escape(&end_prefix))).ok()?;
    let last_match = end_regex.captures_iter(after_start).last()?;

    let exit_code: i32 = last_match.get(1)?.as_str().parse().ok()?;

    let end_match = last_match.get(0)?;
    let output_end = end_match.start();

    let output = after_start[..output_end].trim().to_string();

    Some((output, exit_code))
}

/// Extract exit code from an end marker line.
#[allow(dead_code)]
fn extract_exit_code(line: &str, command_id: &str) -> Option<i32> {
    let end_prefix = end_marker_prefix(command_id);
    if line.contains(&end_prefix) {
        let end_regex = Regex::new(&format!(r"{}(\d+)", regex::escape(&end_prefix))).ok()?;
        let caps = end_regex.captures(line)?;
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
    use tempfile::tempdir;

    #[rstest]
    #[case(ShellType::Bash, "TMUX_MCP_DONE_cmd-1_$?")]
    #[case(ShellType::Zsh, "TMUX_MCP_DONE_cmd-1_$?")]
    #[case(ShellType::Fish, "TMUX_MCP_DONE_cmd-1_$status")]
    #[case(ShellType::Unknown, "TMUX_MCP_DONE_cmd-1_$?")]
    fn test_get_end_marker(#[case] shell: ShellType, #[case] expected: &str) {
        assert_eq!(get_end_marker(&shell, "cmd-1"), expected);
    }

    #[rstest]
    #[case("TMUX_MCP_DONE_cmd-1_0", Some(0))]
    #[case("TMUX_MCP_DONE_cmd-1_1", Some(1))]
    #[case("TMUX_MCP_DONE_cmd-1_127", Some(127))]
    #[case("TMUX_MCP_DONE_cmd-1_255", Some(255))]
    #[case("some output TMUX_MCP_DONE_cmd-1_42 more text", Some(42))]
    #[case("no marker here", None)]
    #[case("TMUX_MCP_DONE_cmd-1_", None)]
    #[case("TMUX_MCP_DONE_cmd-1_abc", None)]
    fn test_extract_exit_code(#[case] input: &str, #[case] expected: Option<i32>) {
        assert_eq!(extract_exit_code(input, "cmd-1"), expected);
    }

    #[rstest]
    #[case(
        "prompt$ TMUX_MCP_START_cmd-1\nhello world\nTMUX_MCP_DONE_cmd-1_0\nprompt$",
        Some(("hello world".to_string(), 0))
    )]
    #[case(
        "TMUX_MCP_START_cmd-1\nerror occurred\nTMUX_MCP_DONE_cmd-1_1",
        Some(("error occurred".to_string(), 1))
    )]
    #[case(
        "old TMUX_MCP_START_cmd-1\nold output\nTMUX_MCP_DONE_cmd-1_0\nnew TMUX_MCP_START_cmd-1\nnew output\nTMUX_MCP_DONE_cmd-1_2",
        Some(("new output".to_string(), 2))
    )]
    #[case(
        "TMUX_MCP_START_cmd-1\nline1\nline2\nline3\nTMUX_MCP_DONE_cmd-1_0",
        Some(("line1\nline2\nline3".to_string(), 0))
    )]
    #[case("no markers at all", None)]
    #[case("TMUX_MCP_START_cmd-1\nno end marker", None)]
    #[case("TMUX_MCP_DONE_cmd-1_0\nno start marker", None)]
    fn test_parse_command_output(#[case] input: &str, #[case] expected: Option<(String, i32)>) {
        assert_eq!(parse_command_output(input, "cmd-1"), expected);
    }

    #[rstest]
    #[case(
        "$ echo TMUX_MCP_START_cmd-1\nTMUX_MCP_START_cmd-1\n$ ls -la\ntotal 0\ndrwxr-xr-x  2 user user  40 Jan  1 00:00 .\ndrwxr-xr-x 10 user user 200 Jan  1 00:00 ..\n$ echo TMUX_MCP_DONE_cmd-1_$?\nTMUX_MCP_DONE_cmd-1_0\n$",
        Some(0)
    )]
    #[case(
        "TMUX_MCP_START_cmd-1\ncommand not found: foobar\nTMUX_MCP_DONE_cmd-1_127",
        Some(127)
    )]
    fn test_parse_realistic_output(#[case] input: &str, #[case] expected_exit: Option<i32>) {
        let result = parse_command_output(input, "cmd-1");
        match (result, expected_exit) {
            (Some((_, code)), Some(expected)) => assert_eq!(code, expected),
            (None, None) => {}
            (result, expected) => panic!("Expected {:?}, got {:?}", expected, result),
        }
    }

    #[test]
    fn test_markers_are_correct() {
        assert_eq!(START_MARKER_PREFIX, "TMUX_MCP_START_");
        assert_eq!(END_MARKER_PREFIX, "TMUX_MCP_DONE_");
        assert_eq!(get_start_marker("cmd-1"), "TMUX_MCP_START_cmd-1");
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
            tracking_disabled: false,
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
        let id = "error-cmd".to_string();
        stub.set_var(
            "TMUX_STUB_CAPTURE_OUTPUT",
            format!("TMUX_MCP_START_{id}\nbad\nTMUX_MCP_DONE_{id}_1\n", id = id),
        );
        let tracker = CommandTracker::new(ShellType::Bash);
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
            tracking_disabled: false,
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
    async fn check_status_retries_capture_until_markers_found() {
        let mut stub = TmuxStub::new();
        let temp_dir = tempdir().expect("tempdir");
        let count_path = temp_dir.path().join("capture-count");
        let id = "retry-cmd".to_string();

        stub.set_var(
            "TMUX_STUB_CAPTURE_COUNT_FILE",
            count_path.to_str().expect("count path"),
        );
        stub.set_var("TMUX_STUB_CAPTURE_AFTER", "2");
        stub.set_var("TMUX_STUB_CAPTURE_BEFORE", "prompt\nno markers yet\n");
        stub.set_var(
            "TMUX_STUB_CAPTURE_AFTER_OUTPUT",
            format!(
                "TMUX_MCP_START_{id}\nretry ok\nTMUX_MCP_DONE_{id}_0\n",
                id = id
            ),
        );

        let tracking = TrackingConfig {
            capture_initial_lines: 2,
            capture_max_lines: 4,
            capture_backoff_factor: 2,
        };
        let tracker = CommandTracker::with_tracking(ShellType::Bash, tracking);
        let execution = CommandExecution {
            id: id.clone(),
            pane_id: "%1".into(),
            socket: None,
            command: "echo retry".into(),
            status: CommandStatus::Pending,
            exit_code: None,
            output: None,
            started_at: Instant::now(),
            completed_at: None,
            raw_mode: false,
            tracking_disabled: false,
        };

        {
            let mut commands = tracker.active_commands.write().await;
            commands.insert(id.clone(), execution);
        }

        let result = tracker.check_status(&id, None).await.expect("check status");
        let command = result.expect("command");
        assert_eq!(command.status, CommandStatus::Completed);
        assert_eq!(command.exit_code, Some(0));
        assert_eq!(command.output.as_deref(), Some("retry ok"));

        let count = std::fs::read_to_string(&count_path)
            .expect("read count")
            .trim()
            .parse::<u32>()
            .expect("parse count");
        assert!(count >= 2);
    }

    #[tokio::test]
    async fn check_status_sets_error_when_markers_never_found() {
        let mut stub = TmuxStub::new();
        let id = "expired-cmd".to_string();
        stub.set_var("TMUX_STUB_CAPTURE_OUTPUT", "no markers here");

        let tracking = TrackingConfig {
            capture_initial_lines: 1,
            capture_max_lines: 2,
            capture_backoff_factor: 2,
        };
        let tracker = CommandTracker::with_tracking(ShellType::Bash, tracking);
        let execution = CommandExecution {
            id: id.clone(),
            pane_id: "%1".into(),
            socket: None,
            command: "echo missing".into(),
            status: CommandStatus::Pending,
            exit_code: None,
            output: None,
            started_at: Instant::now(),
            completed_at: None,
            raw_mode: false,
            tracking_disabled: false,
        };

        {
            let mut commands = tracker.active_commands.write().await;
            commands.insert(id.clone(), execution);
        }

        let result = tracker.check_status(&id, None).await.expect("check status");
        let command = result.expect("command");
        assert_eq!(command.status, CommandStatus::Error);
        assert_eq!(
            command.output.as_deref(),
            Some("tracking expired; markers not found in pane history")
        );
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
            tracking_disabled: false,
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
            tracking_disabled: false,
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
            tracking_disabled: false,
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
