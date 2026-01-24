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

fn run_with_stdin_closed(args: &[&str]) -> std::process::Output {
    let mut child = Command::new(bin_path())
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
    let output = Command::new(bin_path())
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

    let output = Command::new(bin_path())
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

    let output = Command::new(bin_path())
        .args(["--config", file.path().to_str().unwrap()])
        .output()
        .expect("run binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error loading security policy"));
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
