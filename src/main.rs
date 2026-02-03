mod commands;
mod errors;
mod security;
mod server;
#[cfg(test)]
mod test_support;
mod tmux;
mod types;

use std::path::PathBuf;

use clap::Parser;
use rmcp::ServiceExt;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::commands::{CommandTracker, TrackingConfig};
use crate::security::{ConfigFile, SecurityPolicy};
use crate::server::TmuxMcpServer;
use crate::types::ShellType;

#[derive(Parser, Debug)]
#[command(name = "tmux-mcp-rs")]
#[command(about = "Tmux MCP server in Rust")]
#[command(version)]
struct Cli {
    /// Shell type (bash, zsh, fish)
    #[arg(short = 't', long = "shell-type", default_value = "bash")]
    shell_type: String,

    /// Path to TOML configuration file
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Path to tmux socket (for isolation or connecting to specific server)
    #[arg(short = 's', long = "socket")]
    socket: Option<PathBuf>,

    /// SSH connection string for remote tmux (e.g. "user@host" or "-i key user@host")
    #[arg(short = 'r', long = "ssh")]
    ssh: Option<String>,
}

fn parse_shell_type(s: &str) -> ShellType {
    match s.to_lowercase().as_str() {
        "bash" => ShellType::Bash,
        "zsh" => ShellType::Zsh,
        "fish" => ShellType::Fish,
        _ => ShellType::Bash,
    }
}

fn init_tracing() {
    if let Ok(filter) = EnvFilter::try_from_default_env() {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .init();
    }
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(_) => {
                let _ = ctrl_c.await;
                return;
            }
        };

        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Some(socket) = &cli.socket {
        std::env::set_var("TMUX_MCP_SOCKET", socket);
    }

    init_tracing();

    let (security_policy, config_shell_type, config_ssh, tracking_config) = match &cli.config {
        Some(path) => {
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error reading config file: {e}");
                    std::process::exit(1);
                }
            };

            let config_file: ConfigFile = match toml::from_str(&content) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error parsing config file: {e}");
                    std::process::exit(1);
                }
            };

            let policy = match SecurityPolicy::load(path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error loading security policy: {e}");
                    std::process::exit(1);
                }
            };

            (
                policy,
                config_file.shell.shell_type,
                config_file.ssh.remote,
                config_file.tracking,
            )
        }
        None => (
            SecurityPolicy::default(),
            None,
            None,
            TrackingConfig::default(),
        ),
    };

    let shell_type = config_shell_type
        .map(|s| parse_shell_type(&s))
        .unwrap_or_else(|| parse_shell_type(&cli.shell_type));

    let ssh_connection = cli.ssh.or(config_ssh);
    if let Some(ssh) = ssh_connection {
        std::env::set_var("TMUX_MCP_SSH", ssh);
    }

    let tracker = if cli.config.is_some() {
        CommandTracker::with_tracking(shell_type, tracking_config)
    } else {
        CommandTracker::new(shell_type)
    };
    let server = TmuxMcpServer::new(tracker, security_policy);

    tracing::info!("Starting tmux-mcp-rs server with stdio transport");

    let transport = rmcp::transport::io::stdio();

    match server.serve(transport).await {
        Ok(service) => {
            let cancel_token = service.cancellation_token();
            let mut wait = Box::pin(service.waiting());

            tokio::select! {
                result = &mut wait => {
                    if let Err(e) = result {
                        eprintln!("Server error: {e}");
                        std::process::exit(1);
                    }
                }
                _ = shutdown_signal() => {
                    cancel_token.cancel();
                    if let Err(e) = wait.await {
                        eprintln!("Server error: {e}");
                        std::process::exit(1);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to start server: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_shell_type;
    use crate::types::ShellType;

    #[test]
    fn parse_shell_type_recognizes_known_shells() {
        assert_eq!(parse_shell_type("bash"), ShellType::Bash);
        assert_eq!(parse_shell_type("zsh"), ShellType::Zsh);
        assert_eq!(parse_shell_type("fish"), ShellType::Fish);
    }

    #[test]
    fn parse_shell_type_is_case_insensitive_and_defaults() {
        assert_eq!(parse_shell_type("ZSH"), ShellType::Zsh);
        assert_eq!(parse_shell_type("unknown"), ShellType::Bash);
    }
}
