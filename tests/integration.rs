//! Integration tests for tmux-mcp-rs.
//!
//! These tests require tmux installed; they create an isolated server via a temp socket.
//! Run with: TMUX_MCP_INTEGRATION=1 cargo test --test integration

use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// Unique counter for test session names to avoid collisions.
static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Check if integration tests should run.
fn should_run_integration_tests() -> bool {
    std::env::var("TMUX_MCP_INTEGRATION").is_ok()
}

/// Generate a unique test session name.
fn unique_session_name(prefix: &str) -> String {
    let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("{}-{}-{}", prefix, std::process::id(), count)
}

/// Fixture that cleans up test sessions on drop.
struct TmuxFixture {
    _socket_dir: TempDir,
    socket_path: String,
    sessions_to_cleanup: Vec<String>,
}

impl TmuxFixture {
    fn new() -> Self {
        let socket_dir = TempDir::new().expect("create tmux socket dir");
        let socket_path = socket_dir.path().join("tmux.sock");
        let socket_path = socket_path.to_string_lossy().to_string();
        Self {
            _socket_dir: socket_dir,
            socket_path,
            sessions_to_cleanup: Vec::new(),
        }
    }

    fn track_session(&mut self, name: &str) {
        self.sessions_to_cleanup.push(name.to_string());
    }

    fn socket(&self) -> &str {
        &self.socket_path
    }
}

impl Drop for TmuxFixture {
    fn drop(&mut self) {
        for session in &self.sessions_to_cleanup {
            let _ = Command::new("tmux")
                .args(["-S", &self.socket_path, "kill-session", "-t", session])
                .output();
        }
        let _ = Command::new("tmux")
            .args(["-S", &self.socket_path, "kill-server"])
            .output();
    }
}

async fn wait_for_pane_output(
    pane_id: &str,
    needle: &str,
    timeout: Duration,
    socket: &str,
) -> String {
    let start = Instant::now();
    loop {
        let content = tmux_mcp_rs::tmux::capture_pane(
            pane_id,
            Some(200),
            false,
            None,
            None,
            false,
            Some(socket),
        )
        .await
        .unwrap_or_default();

        if content.contains(needle) {
            return content;
        }

        if start.elapsed() > timeout {
            panic!(
                "Timed out waiting for pane output to contain '{needle}'. Last content:\n{content}"
            );
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn test_smoke_tmux_available() {
    if !should_run_integration_tests() {
        return;
    }

    let output = Command::new("tmux")
        .args(["-V"])
        .output()
        .expect("tmux should be available");

    assert!(output.status.success());
    let version = String::from_utf8_lossy(&output.stdout);
    assert!(version.starts_with("tmux"));
}

#[tokio::test]
async fn test_full_lifecycle() {
    if !should_run_integration_tests() {
        return;
    }

    let mut fixture = TmuxFixture::new();
    let session_name = unique_session_name("lifecycle-test");
    fixture.track_session(&session_name);

    use tmux_mcp_rs::tmux;

    let socket = fixture.socket();
    let socket_opt = Some(socket);

    // Create session
    let session = tmux::create_session(&session_name, socket_opt)
        .await
        .expect("create session");
    assert_eq!(session.name, session_name);

    // List sessions
    let sessions = tmux::list_sessions(socket_opt)
        .await
        .expect("list sessions");
    assert!(sessions.iter().any(|s| s.name == session_name));

    // List windows (session starts with one window)
    let windows = tmux::list_windows(&session.id, socket_opt)
        .await
        .expect("list windows");
    assert!(!windows.is_empty());
    let window = &windows[0];

    // List panes (window starts with one pane)
    let panes = tmux::list_panes(&window.id, socket_opt)
        .await
        .expect("list panes");
    assert_eq!(panes.len(), 1);
    let pane_id = &panes[0].id;

    // Split pane
    let new_pane = tmux::split_pane(pane_id, Some("horizontal"), Some(50), socket_opt)
        .await
        .expect("split pane");

    // Verify we now have 2 panes
    let panes = tmux::list_panes(&window.id, socket_opt)
        .await
        .expect("list panes after split");
    assert_eq!(panes.len(), 2);

    // Create another window
    let new_window = tmux::create_window(&session.id, "second-window", socket_opt)
        .await
        .expect("create window");
    assert_eq!(new_window.name, "second-window");

    // Rename window
    tmux::rename_window(&new_window.id, "renamed-window", socket_opt)
        .await
        .expect("rename window");

    // Kill pane
    tmux::kill_pane(&new_pane.id, socket_opt)
        .await
        .expect("kill pane");
    let panes = tmux::list_panes(&window.id, socket_opt)
        .await
        .expect("list panes after kill");
    assert_eq!(panes.len(), 1);

    // Kill session (cleanup)
    tmux::kill_session(&session.id, socket_opt)
        .await
        .expect("kill session");

    let sessions = tmux::list_sessions(socket_opt).await.unwrap_or_default();
    assert!(!sessions.iter().any(|s| s.name == session_name));
}

#[tokio::test]
async fn test_execute_command_tracking() {
    if !should_run_integration_tests() {
        return;
    }

    let mut fixture = TmuxFixture::new();
    let session_name = unique_session_name("cmd-test");
    fixture.track_session(&session_name);

    use std::time::Duration;
    use tmux_mcp_rs::{commands::CommandTracker, tmux, types::ShellType};

    let socket = fixture.socket();
    let socket_opt = Some(socket);
    let socket_owned = Some(socket.to_string());

    // Create a session and get the pane
    let session = tmux::create_session(&session_name, socket_opt)
        .await
        .expect("create session");
    let windows = tmux::list_windows(&session.id, socket_opt)
        .await
        .expect("list windows");
    let panes = tmux::list_panes(&windows[0].id, socket_opt)
        .await
        .expect("list panes");
    let pane_id = &panes[0].id;

    // Create tracker
    let tracker = CommandTracker::new(ShellType::Bash);

    // Execute a simple command
    let cmd_id = tracker
        .execute_command(
            pane_id,
            "echo 'hello-integration-test'",
            false,                // not raw mode
            false,                // not no_enter
            None,                 // no delay
            socket_owned.clone(), // socket
        )
        .await
        .expect("execute command");

    // Wait for completion (poll with timeout)
    let timeout = Duration::from_secs(5);
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            panic!("Command did not complete within timeout");
        }

        if let Ok(Some(cmd)) = tracker.check_status(&cmd_id, socket_opt).await {
            if cmd.status == tmux_mcp_rs::types::CommandStatus::Completed {
                assert_eq!(cmd.exit_code, Some(0));
                assert!(cmd
                    .output
                    .as_ref()
                    .unwrap()
                    .contains("hello-integration-test"));
                break;
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Cleanup
    tmux::kill_session(&session.id, socket_opt)
        .await
        .expect("kill session");
}

#[tokio::test]
async fn test_workflow_synchronized_panes_broadcast() {
    if !should_run_integration_tests() {
        return;
    }

    let mut fixture = TmuxFixture::new();
    let session_name = unique_session_name("workflow-sync");
    fixture.track_session(&session_name);

    use tmux_mcp_rs::tmux;

    let socket = fixture.socket();
    let socket_opt = Some(socket);

    let session = tmux::create_session(&session_name, socket_opt)
        .await
        .expect("create session");
    let windows = tmux::list_windows(&session.id, socket_opt)
        .await
        .expect("list windows");
    let window_id = &windows[0].id;

    let panes = tmux::list_panes(window_id, socket_opt)
        .await
        .expect("list panes");
    let first_pane = &panes[0].id;
    let _second_pane = tmux::split_pane(first_pane, Some("horizontal"), Some(50), socket_opt)
        .await
        .expect("split pane");

    tmux::set_synchronize_panes(window_id, true, socket_opt)
        .await
        .expect("enable synchronize-panes");

    let token = format!("sync-{}", session_name);
    tmux::send_keys(first_pane, &format!("echo {token}"), false, socket_opt)
        .await
        .expect("send sync command");
    tmux::send_keys(first_pane, "Enter", false, socket_opt)
        .await
        .expect("enter sync command");

    let panes = tmux::list_panes(window_id, socket_opt)
        .await
        .expect("list panes after sync");
    for pane in panes {
        let output = wait_for_pane_output(&pane.id, &token, Duration::from_secs(2), socket).await;
        assert!(output.contains(&token));
    }

    tmux::set_synchronize_panes(window_id, false, socket_opt)
        .await
        .expect("disable synchronize-panes");

    tmux::kill_session(&session.id, socket_opt)
        .await
        .expect("kill session");
}

#[tokio::test]
async fn test_workflow_pane_rearrangements() {
    if !should_run_integration_tests() {
        return;
    }

    let mut fixture = TmuxFixture::new();
    let session_name = unique_session_name("workflow-rearrange");
    fixture.track_session(&session_name);

    use tmux_mcp_rs::tmux;

    let socket = fixture.socket();
    let socket_opt = Some(socket);

    let session = tmux::create_session(&session_name, socket_opt)
        .await
        .expect("create session");
    let windows = tmux::list_windows(&session.id, socket_opt)
        .await
        .expect("list windows");
    let window_id = &windows[0].id;

    let panes = tmux::list_panes(window_id, socket_opt)
        .await
        .expect("list panes");
    let base_pane_id = panes[0].id.clone();
    let second_pane = tmux::split_pane(&base_pane_id, Some("vertical"), Some(50), socket_opt)
        .await
        .expect("split pane");

    tmux::select_layout(window_id, "even-horizontal", socket_opt)
        .await
        .expect("select layout");

    tmux::swap_pane(&base_pane_id, &second_pane.id, socket_opt)
        .await
        .expect("swap panes");

    let panes_after_swap = tmux::list_panes(window_id, socket_opt)
        .await
        .expect("list panes after swap");
    assert!(panes_after_swap.iter().any(|p| p.id == base_pane_id));
    assert!(panes_after_swap.iter().any(|p| p.id == second_pane.id));

    let breakout_window = tmux::break_pane(&second_pane.id, Some("breakout"), socket_opt)
        .await
        .expect("break pane");

    let panes_in_original = tmux::list_panes(window_id, socket_opt)
        .await
        .expect("list panes after break");
    assert_eq!(panes_in_original.len(), 1);

    let panes_in_breakout = tmux::list_panes(&breakout_window.id, socket_opt)
        .await
        .expect("list panes in breakout");
    assert_eq!(panes_in_breakout.len(), 1);
    let breakout_pane_id = panes_in_breakout[0].id.clone();

    tmux::join_pane(&breakout_pane_id, &base_pane_id, socket_opt)
        .await
        .expect("join pane");

    let panes_after_join = tmux::list_panes(window_id, socket_opt)
        .await
        .expect("list panes after join");
    assert_eq!(panes_after_join.len(), 2);

    let windows_after_join = tmux::list_windows(&session.id, socket_opt)
        .await
        .expect("list windows after join");
    assert!(!windows_after_join
        .iter()
        .any(|window| window.id == breakout_window.id));

    tmux::kill_session(&session.id, socket_opt)
        .await
        .expect("kill session");
}

#[tokio::test]
async fn test_workflow_metadata_and_zoom() {
    if !should_run_integration_tests() {
        return;
    }

    let mut fixture = TmuxFixture::new();
    let session_name = unique_session_name("workflow-meta");
    fixture.track_session(&session_name);

    use tmux_mcp_rs::tmux;

    let socket = fixture.socket();
    let socket_opt = Some(socket);

    let session = tmux::create_session(&session_name, socket_opt)
        .await
        .expect("create session");
    let windows = tmux::list_windows(&session.id, socket_opt)
        .await
        .expect("list windows");
    let window_id = &windows[0].id;

    let new_session_name = format!("renamed-{}", session_name);
    tmux::rename_session(&session.id, &new_session_name, socket_opt)
        .await
        .expect("rename session");

    let sessions = tmux::list_sessions(socket_opt)
        .await
        .expect("list sessions");
    assert!(sessions.iter().any(|s| s.name == new_session_name));

    tmux::rename_window(window_id, "meta-window", socket_opt)
        .await
        .expect("rename window");
    let window_info = tmux::window_info(window_id, socket_opt)
        .await
        .expect("window info");
    assert_eq!(window_info.name, "meta-window");

    let panes = tmux::list_panes(window_id, socket_opt)
        .await
        .expect("list panes");
    let pane_id = &panes[0].id;

    tmux::rename_pane(pane_id, "meta-pane", socket_opt)
        .await
        .expect("rename pane");
    let pane_info = tmux::pane_info(pane_id, socket_opt)
        .await
        .expect("pane info");
    assert_eq!(pane_info.title, "meta-pane");

    tmux::zoom_pane(pane_id, socket_opt)
        .await
        .expect("zoom pane");
    let window_info = tmux::window_info(window_id, socket_opt)
        .await
        .expect("window info after zoom");
    assert!(window_info.zoomed);

    tmux::zoom_pane(pane_id, socket_opt)
        .await
        .expect("unzoom pane");
    let window_info = tmux::window_info(window_id, socket_opt)
        .await
        .expect("window info after unzoom");
    assert!(!window_info.zoomed);

    tmux::resize_pane(pane_id, Some("right"), Some(1), None, None, socket_opt)
        .await
        .expect("resize pane");
    let pane_info = tmux::pane_info(pane_id, socket_opt)
        .await
        .expect("pane info after resize");
    assert!(pane_info.width > 0);
    assert!(pane_info.height > 0);

    tmux::kill_session(&session.id, socket_opt)
        .await
        .expect("kill session");
}

#[tokio::test]
async fn test_workflow_buffer_roundtrip() {
    if !should_run_integration_tests() {
        return;
    }

    let mut fixture = TmuxFixture::new();
    let session_name = unique_session_name("workflow-buffer");
    fixture.track_session(&session_name);

    use tempfile::NamedTempFile;
    use tmux_mcp_rs::tmux;

    let socket = fixture.socket();
    let socket_opt = Some(socket);

    let session = tmux::create_session(&session_name, socket_opt)
        .await
        .expect("create session");

    let buffer_name = format!("buffer-{}", session_name);
    let buffer_value = format!("buffer-value-{}", session_name);

    tmux::execute_tmux_with_socket(
        &["set-buffer", "-b", &buffer_name, &buffer_value],
        socket_opt,
    )
    .await
    .expect("set buffer");

    let buffers = tmux::list_buffers(socket_opt).await.expect("list buffers");
    assert!(buffers.iter().any(|b| b.name == buffer_name));

    let content = tmux::show_buffer(Some(&buffer_name), socket_opt)
        .await
        .expect("show buffer");
    assert!(content.contains(&buffer_value));

    let temp_file = NamedTempFile::new().expect("create temp file");
    let path = temp_file.path().to_string_lossy().to_string();
    tmux::save_buffer(&buffer_name, &path, socket_opt)
        .await
        .expect("save buffer");
    let saved = std::fs::read_to_string(&path).expect("read saved buffer");
    assert!(saved.contains(&buffer_value));

    tmux::delete_buffer(&buffer_name, socket_opt)
        .await
        .expect("delete buffer");
    let buffers = tmux::list_buffers(socket_opt)
        .await
        .expect("list buffers after delete");
    assert!(!buffers.iter().any(|b| b.name == buffer_name));

    tmux::kill_session(&session.id, socket_opt)
        .await
        .expect("kill session");
}

#[tokio::test]
async fn test_workflow_agent_orchestration() {
    if !should_run_integration_tests() {
        return;
    }

    let mut fixture = TmuxFixture::new();
    let session_name = unique_session_name("workflow-agent");
    fixture.track_session(&session_name);

    use tmux_mcp_rs::{commands::CommandTracker, tmux, types::ShellType};

    let socket = fixture.socket();
    let socket_opt = Some(socket);
    let socket_owned = Some(socket.to_string());

    let session = tmux::create_session(&session_name, socket_opt)
        .await
        .expect("create session");

    let server_window = tmux::create_window(&session.id, "server", socket_opt)
        .await
        .expect("create server window");
    let tests_window = tmux::create_window(&session.id, "tests", socket_opt)
        .await
        .expect("create tests window");
    let logs_window = tmux::create_window(&session.id, "logs", socket_opt)
        .await
        .expect("create logs window");

    let tracker = CommandTracker::new(ShellType::Bash);

    let server_pane = tmux::list_panes(&server_window.id, socket_opt)
        .await
        .expect("list server panes")[0]
        .id
        .clone();
    let tests_panes = tmux::list_panes(&tests_window.id, socket_opt)
        .await
        .expect("list test panes");
    let runner_pane = tests_panes[0].id.clone();
    let watcher_pane = tmux::split_pane(&runner_pane, Some("horizontal"), Some(50), socket_opt)
        .await
        .expect("split test pane");
    let logs_pane = tmux::list_panes(&logs_window.id, socket_opt)
        .await
        .expect("list logs panes")[0]
        .id
        .clone();

    tmux::rename_pane(&runner_pane, "runner", socket_opt)
        .await
        .expect("rename runner pane");
    tmux::rename_pane(&watcher_pane.id, "watcher", socket_opt)
        .await
        .expect("rename watcher pane");

    let server_token = format!("srv-ready-{}", session_name);
    let tests_token = format!("tests-done-{}", session_name);
    let logs_token = format!("log-2-{}", session_name);

    let server_cmd = format!(
        "sh -c 'printf \"srv-start\\n\"; sleep 0.2; printf \"{}\\n\"'",
        server_token
    );
    let tests_cmd = format!(
        "sh -c 'printf \"test-start\\n\"; sleep 0.1; printf \"{}\\n\"'",
        tests_token
    );

    let server_cmd_id = tracker
        .execute_command(
            &server_pane,
            &server_cmd,
            false,
            false,
            None,
            socket_owned.clone(),
        )
        .await
        .expect("execute server command");
    let tests_cmd_id = tracker
        .execute_command(
            &runner_pane,
            &tests_cmd,
            false,
            false,
            None,
            socket_owned.clone(),
        )
        .await
        .expect("execute tests command");

    let logs_cmd = format!(
        "sh -c 'printf \"log-1\\n\"; sleep 0.1; printf \"{}\\n\"'",
        logs_token
    );
    tmux::send_keys(&logs_pane, &logs_cmd, false, socket_opt)
        .await
        .expect("send logs command");
    tmux::send_keys(&logs_pane, "Enter", false, socket_opt)
        .await
        .expect("enter logs command");

    let _ = wait_for_pane_output(&server_pane, &server_token, Duration::from_secs(3), socket).await;
    let _ = wait_for_pane_output(&runner_pane, &tests_token, Duration::from_secs(3), socket).await;
    let _ = wait_for_pane_output(&logs_pane, &logs_token, Duration::from_secs(3), socket).await;

    let timeout = Duration::from_secs(5);
    let start = Instant::now();
    loop {
        if start.elapsed() > timeout {
            panic!("Command did not complete within timeout");
        }
        if let Ok(Some(cmd)) = tracker.check_status(&server_cmd_id, socket_opt).await {
            if cmd.status == tmux_mcp_rs::types::CommandStatus::Completed {
                assert_eq!(cmd.exit_code, Some(0));
                assert!(cmd.output.unwrap_or_default().contains(&server_token));
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let start = Instant::now();
    loop {
        if start.elapsed() > timeout {
            panic!("Command did not complete within timeout");
        }
        if let Ok(Some(cmd)) = tracker.check_status(&tests_cmd_id, socket_opt).await {
            if cmd.status == tmux_mcp_rs::types::CommandStatus::Completed {
                assert_eq!(cmd.exit_code, Some(0));
                assert!(cmd.output.unwrap_or_default().contains(&tests_token));
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    tmux::kill_session(&session.id, socket_opt)
        .await
        .expect("kill session");
}

#[tokio::test]
async fn test_workflow_interactive_interrupts() {
    if !should_run_integration_tests() {
        return;
    }

    let mut fixture = TmuxFixture::new();
    let session_name = unique_session_name("workflow-interrupt");
    fixture.track_session(&session_name);

    use tmux_mcp_rs::tmux;

    let socket = fixture.socket();
    let socket_opt = Some(socket);

    let session = tmux::create_session(&session_name, socket_opt)
        .await
        .expect("create session");
    let windows = tmux::list_windows(&session.id, socket_opt)
        .await
        .expect("list windows");
    let panes = tmux::list_panes(&windows[0].id, socket_opt)
        .await
        .expect("list panes");
    let pane_id = &panes[0].id;

    tmux::send_keys(pane_id, "sleep 5", false, socket_opt)
        .await
        .expect("send sleep");
    tmux::send_keys(pane_id, "Enter", false, socket_opt)
        .await
        .expect("enter sleep");

    tokio::time::sleep(Duration::from_millis(200)).await;
    tmux::send_keys(pane_id, "C-c", false, socket_opt)
        .await
        .expect("send cancel");
    tmux::send_keys(pane_id, "echo canceled", false, socket_opt)
        .await
        .expect("send canceled");
    tmux::send_keys(pane_id, "Enter", false, socket_opt)
        .await
        .expect("enter canceled");

    let output = wait_for_pane_output(pane_id, "canceled", Duration::from_secs(2), socket).await;
    assert!(output.contains("canceled"));

    let eof_token = format!("eof-{}", session_name);
    tmux::send_keys(pane_id, "cat", false, socket_opt)
        .await
        .expect("send cat");
    tmux::send_keys(pane_id, "Enter", false, socket_opt)
        .await
        .expect("enter cat");
    tmux::send_keys(pane_id, &eof_token, false, socket_opt)
        .await
        .expect("send eof token");
    tmux::send_keys(pane_id, "Enter", false, socket_opt)
        .await
        .expect("enter eof token");

    let _ = wait_for_pane_output(pane_id, &eof_token, Duration::from_secs(2), socket).await;

    tmux::send_keys(pane_id, "C-d", false, socket_opt)
        .await
        .expect("send eof");
    tmux::send_keys(pane_id, "echo after-eof", false, socket_opt)
        .await
        .expect("send after-eof");
    tmux::send_keys(pane_id, "Enter", false, socket_opt)
        .await
        .expect("enter after-eof");

    let output = wait_for_pane_output(pane_id, "after-eof", Duration::from_secs(2), socket).await;
    assert!(output.contains("after-eof"));

    tmux::kill_session(&session.id, socket_opt)
        .await
        .expect("kill session");
}

#[tokio::test]
async fn test_send_keys_and_capture() {
    if !should_run_integration_tests() {
        return;
    }

    let mut fixture = TmuxFixture::new();
    let session_name = unique_session_name("sendkeys-test");
    fixture.track_session(&session_name);

    use std::time::Duration;
    use tmux_mcp_rs::tmux;

    let socket = fixture.socket();
    let socket_opt = Some(socket);

    // Create session
    let session = tmux::create_session(&session_name, socket_opt)
        .await
        .expect("create session");
    let windows = tmux::list_windows(&session.id, socket_opt)
        .await
        .expect("list windows");
    let panes = tmux::list_panes(&windows[0].id, socket_opt)
        .await
        .expect("list panes");
    let pane_id = &panes[0].id;

    // Send keys to type a command
    tmux::send_keys(pane_id, "echo 'sent-via-keys'", false, socket_opt)
        .await
        .expect("send keys");
    tmux::send_keys(pane_id, "Enter", false, socket_opt)
        .await
        .expect("send enter");

    // Wait a bit for output
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Capture and verify
    let content = tmux::capture_pane(pane_id, Some(50), false, None, None, false, socket_opt)
        .await
        .expect("capture pane");
    assert!(
        content.contains("sent-via-keys"),
        "Output should contain sent text: {}",
        content
    );

    // Cleanup
    tmux::kill_session(&session.id, socket_opt)
        .await
        .expect("kill session");
}

#[tokio::test]
async fn test_workflow_task_per_session_layout() {
    if !should_run_integration_tests() {
        return;
    }

    let mut fixture = TmuxFixture::new();
    let session_name = unique_session_name("workflow-layout");
    fixture.track_session(&session_name);

    use tmux_mcp_rs::tmux;

    let socket = fixture.socket();
    let socket_opt = Some(socket);

    let session = tmux::create_session(&session_name, socket_opt)
        .await
        .expect("create session");

    let build_window = tmux::create_window(&session.id, "build", socket_opt)
        .await
        .expect("create build window");
    let test_window = tmux::create_window(&session.id, "test", socket_opt)
        .await
        .expect("create test window");
    let docs_window = tmux::create_window(&session.id, "docs", socket_opt)
        .await
        .expect("create docs window");

    let test_panes = tmux::list_panes(&test_window.id, socket_opt)
        .await
        .expect("list test panes");
    let runner_pane = &test_panes[0];
    let logs_pane = tmux::split_pane(&runner_pane.id, Some("horizontal"), Some(50), socket_opt)
        .await
        .expect("split test window");

    tmux::rename_pane(&runner_pane.id, "runner", socket_opt)
        .await
        .expect("rename runner pane");
    tmux::rename_pane(&logs_pane.id, "logs", socket_opt)
        .await
        .expect("rename logs pane");

    let windows = tmux::list_windows(&session.id, socket_opt)
        .await
        .expect("list windows");
    let window_names: Vec<&str> = windows.iter().map(|w| w.name.as_str()).collect();
    assert!(window_names.contains(&build_window.name.as_str()));
    assert!(window_names.contains(&test_window.name.as_str()));
    assert!(window_names.contains(&docs_window.name.as_str()));

    let panes = tmux::list_panes(&test_window.id, socket_opt)
        .await
        .expect("list panes after split");
    assert_eq!(panes.len(), 2);
    assert!(panes.iter().any(|p| p.title == "runner"));
    assert!(panes.iter().any(|p| p.title == "logs"));

    tmux::kill_session(&session.id, socket_opt)
        .await
        .expect("kill session");
}

#[tokio::test]
async fn test_workflow_stateful_shell_context() {
    if !should_run_integration_tests() {
        return;
    }

    let mut fixture = TmuxFixture::new();
    let session_name = unique_session_name("workflow-state");
    fixture.track_session(&session_name);

    use tmux_mcp_rs::tmux;

    let socket = fixture.socket();
    let socket_opt = Some(socket);

    let session = tmux::create_session(&session_name, socket_opt)
        .await
        .expect("create session");
    let windows = tmux::list_windows(&session.id, socket_opt)
        .await
        .expect("list windows");
    let panes = tmux::list_panes(&windows[0].id, socket_opt)
        .await
        .expect("list panes");
    let pane_id = &panes[0].id;

    let token = format!("wf-state-{}", session_name);

    tmux::send_keys(
        pane_id,
        &format!("export WF_STATE={token}"),
        false,
        socket_opt,
    )
    .await
    .expect("export state");
    tmux::send_keys(pane_id, "Enter", false, socket_opt)
        .await
        .expect("enter export");

    tmux::send_keys(pane_id, "echo $WF_STATE", false, socket_opt)
        .await
        .expect("echo state");
    tmux::send_keys(pane_id, "Enter", false, socket_opt)
        .await
        .expect("enter echo");

    let output = wait_for_pane_output(pane_id, &token, Duration::from_secs(2), socket).await;
    assert!(output.contains(&token));

    tmux::kill_session(&session.id, socket_opt)
        .await
        .expect("kill session");
}

#[tokio::test]
async fn test_workflow_interactive_prompt() {
    if !should_run_integration_tests() {
        return;
    }

    let mut fixture = TmuxFixture::new();
    let session_name = unique_session_name("workflow-prompt");
    fixture.track_session(&session_name);

    use tmux_mcp_rs::tmux;

    let socket = fixture.socket();
    let socket_opt = Some(socket);

    let session = tmux::create_session(&session_name, socket_opt)
        .await
        .expect("create session");
    let windows = tmux::list_windows(&session.id, socket_opt)
        .await
        .expect("list windows");
    let panes = tmux::list_panes(&windows[0].id, socket_opt)
        .await
        .expect("list panes");
    let pane_id = &panes[0].id;

    let token = format!("prompt-{}", session_name);
    let command = "sh -c 'printf \"input? \"; read ANSWER; echo \"prompt:$ANSWER\"'";

    tmux::send_keys(pane_id, command, false, socket_opt)
        .await
        .expect("send prompt command");
    tmux::send_keys(pane_id, "Enter", false, socket_opt)
        .await
        .expect("enter prompt command");

    let _ = wait_for_pane_output(pane_id, "input?", Duration::from_secs(2), socket).await;

    tmux::send_keys(pane_id, &token, false, socket_opt)
        .await
        .expect("send prompt response");
    tmux::send_keys(pane_id, "Enter", false, socket_opt)
        .await
        .expect("enter prompt response");

    let output = wait_for_pane_output(
        pane_id,
        &format!("prompt:{token}"),
        Duration::from_secs(2),
        socket,
    )
    .await;
    assert!(output.contains(&format!("prompt:{token}")));

    tmux::kill_session(&session.id, socket_opt)
        .await
        .expect("kill session");
}

#[tokio::test]
async fn test_workflow_continuous_output_capture() {
    if !should_run_integration_tests() {
        return;
    }

    let mut fixture = TmuxFixture::new();
    let session_name = unique_session_name("workflow-stream");
    fixture.track_session(&session_name);

    use tmux_mcp_rs::tmux;

    let socket = fixture.socket();
    let socket_opt = Some(socket);

    let session = tmux::create_session(&session_name, socket_opt)
        .await
        .expect("create session");
    let windows = tmux::list_windows(&session.id, socket_opt)
        .await
        .expect("list windows");
    let panes = tmux::list_panes(&windows[0].id, socket_opt)
        .await
        .expect("list panes");
    let pane_id = &panes[0].id;

    let tick_one = format!("tick-1-{session_name}");
    let tick_two = format!("tick-2-{session_name}");
    let command = format!(
        "sh -c 'printf \"{}\\n\"; sleep 0.2; printf \"{}\\n\"'",
        tick_one, tick_two
    );

    tmux::send_keys(pane_id, &command, false, socket_opt)
        .await
        .expect("send command");
    tmux::send_keys(pane_id, "Enter", false, socket_opt)
        .await
        .expect("enter command");

    let output = wait_for_pane_output(pane_id, &tick_two, Duration::from_secs(3), socket).await;
    assert!(output.contains(&tick_one));
    assert!(output.contains(&tick_two));

    tmux::kill_session(&session.id, socket_opt)
        .await
        .expect("kill session");
}

#[tokio::test]
async fn test_workflow_audit_context_bundle() {
    if !should_run_integration_tests() {
        return;
    }

    let mut fixture = TmuxFixture::new();
    let session_name = unique_session_name("workflow-audit");
    fixture.track_session(&session_name);

    use tmux_mcp_rs::{commands::CommandTracker, tmux, types::ShellType};

    let socket = fixture.socket();
    let socket_opt = Some(socket);
    let socket_owned = Some(socket.to_string());

    let session = tmux::create_session(&session_name, socket_opt)
        .await
        .expect("create session");
    let windows = tmux::list_windows(&session.id, socket_opt)
        .await
        .expect("list windows");
    let panes = tmux::list_panes(&windows[0].id, socket_opt)
        .await
        .expect("list panes");
    let pane_id = &panes[0].id;

    let token = format!("audit-{}", session_name);
    let tracker = CommandTracker::new(ShellType::Bash);
    let cmd_id = tracker
        .execute_command(
            pane_id,
            &format!("echo {token}"),
            false,
            false,
            None,
            socket_owned.clone(),
        )
        .await
        .expect("execute command");

    let timeout = Duration::from_secs(5);
    let start = Instant::now();
    loop {
        if start.elapsed() > timeout {
            panic!("Command did not complete within timeout");
        }

        if let Ok(Some(cmd)) = tracker.check_status(&cmd_id, socket_opt).await {
            if cmd.status == tmux_mcp_rs::types::CommandStatus::Completed {
                let output = cmd.output.unwrap_or_default();
                assert!(output.contains(&token));
                break;
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let output = wait_for_pane_output(pane_id, &token, Duration::from_secs(2), socket).await;
    assert!(output.contains(&token));

    tmux::kill_session(&session.id, socket_opt)
        .await
        .expect("kill session");
}

#[tokio::test]
async fn test_workflow_id_first_targeting() {
    if !should_run_integration_tests() {
        return;
    }

    let mut fixture = TmuxFixture::new();
    let session_name = unique_session_name("workflow-ids");
    fixture.track_session(&session_name);

    use tmux_mcp_rs::tmux;

    let socket = fixture.socket();
    let socket_opt = Some(socket);

    let session = tmux::create_session(&session_name, socket_opt)
        .await
        .expect("create session");

    let window_name = "dup-window";
    let first_window = tmux::create_window(&session.id, window_name, socket_opt)
        .await
        .expect("create first window");
    let _second_window = tmux::create_window(&session.id, window_name, socket_opt)
        .await
        .expect("create second window");

    let windows = tmux::list_windows(&session.id, socket_opt)
        .await
        .expect("list windows");
    let dup_windows: Vec<_> = windows
        .iter()
        .filter(|window| window.name == window_name)
        .collect();
    assert!(
        dup_windows.len() >= 2,
        "Expected duplicate window names for id-based targeting"
    );

    tmux::rename_window(&first_window.id, "dup-window-renamed", socket_opt)
        .await
        .expect("rename window by id");

    let windows = tmux::list_windows(&session.id, socket_opt)
        .await
        .expect("list windows after rename");
    let renamed_count = windows
        .iter()
        .filter(|window| window.name == "dup-window-renamed")
        .count();
    let remaining_dup = windows
        .iter()
        .filter(|window| window.name == window_name)
        .count();

    assert_eq!(renamed_count, 1);
    assert!(remaining_dup >= 1);

    tmux::kill_session(&session.id, socket_opt)
        .await
        .expect("kill session");
}
