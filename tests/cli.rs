use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use tempfile::NamedTempFile;

fn bin_path() -> PathBuf {
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_tmux-mcp-rs") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_tmux_mcp_rs") {
        return PathBuf::from(path);
    }
    let exe = std::env::current_exe().expect("current exe");
    let target_dir = exe.parent().and_then(|p| p.parent()).expect("target dir");
    let mut bin = target_dir.join("tmux-mcp-rs");
    if cfg!(windows) {
        bin.set_extension("exe");
    }
    bin
}

fn command() -> Command {
    let mut command = Command::new(bin_path());
    command.env_remove("TMUX_MCP_SSH");
    command.env_remove("TMUX_MCP_TOOLS");
    command
}

fn run_with_stdin_closed(args: &[&str]) -> std::process::Output {
    let mut child = command()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn binary");
    drop(child.stdin.take());
    child.wait_with_output().expect("wait for output")
}

#[test]
fn cli_rejects_missing_config() {
    let output = command()
        .args(["--config", "does-not-exist.toml"])
        .output()
        .expect("run binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error reading config file"));
}

#[test]
fn cli_rejects_invalid_config() {
    let mut file = NamedTempFile::new().expect("temp config");
    writeln!(file, "not = = valid").expect("write config");

    let output = command()
        .args(["--config", file.path().to_str().unwrap()])
        .output()
        .expect("run binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error parsing config file"));
}

#[test]
fn cli_rejects_invalid_policy_regex() {
    let mut file = NamedTempFile::new().expect("temp config");
    writeln!(
        file,
        "[security]\ncommand_filter = {{ mode = \"allowlist\", patterns = [\"*[\" ] }}\n"
    )
    .expect("write config");

    let output = command()
        .args(["--config", file.path().to_str().unwrap()])
        .output()
        .expect("run binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error loading security policy"));
}

#[test]
fn cli_rejects_invalid_ssh_quoting() {
    let output = command()
        .args(["--ssh", "user@host 'unterminated"])
        .output()
        .expect("run binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error parsing SSH connection string"));
    assert!(stderr.contains("invalid TMUX_MCP_SSH"));
}

#[test]
fn cli_rejects_invalid_env_ssh_quoting() {
    let output = command()
        .env("TMUX_MCP_SSH", "user@host 'unterminated")
        .output()
        .expect("run binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error parsing SSH connection string"));
    assert!(stderr.contains("invalid TMUX_MCP_SSH"));
}

#[test]
fn cli_rejects_invalid_tools_env() {
    let output = command()
        .env("TMUX_MCP_TOOLS", "maybe:send-keys")
        .output()
        .expect("run binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error loading security policy"));
    assert!(stderr.contains("invalid TMUX_MCP_TOOLS mode"));
}

#[test]
fn cli_accepts_valid_shell_type_and_exits_when_stdio_closed() {
    let output =
        run_with_stdin_closed(&["--shell-type", "fish", "--socket", "/tmp/tmux-test.sock"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed to start server"));
    assert!(!stderr.contains("Error parsing shell type"));
}

#[test]
fn cli_rejects_invalid_shell_type() {
    let output = command()
        .args(["--shell-type", "powershell"])
        .output()
        .expect("run binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error parsing shell type"));
    assert!(stderr.contains("unknown shell type \"powershell\""));
    assert!(stderr.contains("expected one of: bash, zsh, fish"));
}

#[test]
fn cli_rejects_invalid_config_shell_type() {
    let mut file = NamedTempFile::new().expect("temp config");
    writeln!(file, "[shell]\ntype = \"powershell\"").expect("write config");

    let output = command()
        .args(["--config", file.path().to_str().unwrap()])
        .output()
        .expect("run binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error parsing shell type"));
    assert!(stderr.contains("unknown shell type \"powershell\""));
    assert!(stderr.contains("expected one of: bash, zsh, fish"));
}

#[test]
fn cli_exits_when_stdio_closed() {
    let output = run_with_stdin_closed(&["--socket", "/tmp/tmux-test.sock"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed to start server"));
}

#[test]
fn cli_reads_valid_config_and_exits_when_stdio_closed() {
    let mut file = NamedTempFile::new().expect("temp config");
    writeln!(file, "[shell]\ntype = \"zsh\"").expect("write config");

    let output = run_with_stdin_closed(&[
        "--config",
        file.path().to_str().unwrap(),
        "--socket",
        "/tmp/tmux-test.sock",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed to start server"));
}
