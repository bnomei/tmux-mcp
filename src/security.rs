use regex::Regex;
use serde::Deserialize;
use std::path::Path;

use crate::errors::{Error, Result};

/// Mode for applying regex-based command filters.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CommandFilterMode {
    /// Do not apply any command filtering.
    #[default]
    Off,
    /// Allow only commands that match at least one pattern.
    Allowlist,
    /// Deny commands that match any pattern.
    Denylist,
}

/// Shell configuration loaded from config.toml.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ShellConfig {
    #[serde(rename = "type")]
    pub shell_type: Option<String>,
}

/// SSH configuration loaded from config.toml.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SshConfig {
    #[serde(default)]
    pub remote: Option<String>,
}

/// Regex-based command filtering configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CommandFilter {
    #[serde(default)]
    pub mode: CommandFilterMode,
    #[serde(default)]
    pub patterns: Vec<String>,
}

/// Security policy configuration loaded from config.toml.
#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub allow_execute_command: bool,
    #[serde(default = "default_true")]
    pub allow_raw_mode: bool,
    #[serde(default = "default_true")]
    pub allow_send_keys: bool,
    #[serde(default = "default_true")]
    pub allow_kill: bool,
    #[serde(default = "default_true")]
    pub allow_create: bool,
    #[serde(default = "default_true")]
    pub allow_split: bool,
    #[serde(default = "default_true")]
    pub allow_rename: bool,
    #[serde(default = "default_true")]
    pub allow_move: bool,
    #[serde(default = "default_true")]
    pub allow_capture: bool,
    #[serde(default = "default_true")]
    pub allow_list: bool,
    #[serde(default)]
    pub allowed_sockets: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_sessions: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_panes: Option<Vec<String>>,
    #[serde(default)]
    pub command_filter: CommandFilter,
}

fn default_true() -> bool {
    true
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_execute_command: true,
            allow_raw_mode: true,
            allow_send_keys: true,
            allow_kill: true,
            allow_create: true,
            allow_split: true,
            allow_rename: true,
            allow_move: true,
            allow_capture: true,
            allow_list: true,
            allowed_sockets: None,
            allowed_sessions: None,
            allowed_panes: None,
            command_filter: CommandFilter::default(),
        }
    }
}

/// Root configuration file schema for config.toml.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConfigFile {
    #[serde(default)]
    pub shell: ShellConfig,
    #[serde(default)]
    pub ssh: SshConfig,
    #[serde(default)]
    pub security: SecurityConfig,
}

/// Enforces security rules derived from configuration.
#[derive(Debug, Clone, Default)]
pub struct SecurityPolicy {
    config: SecurityConfig,
    compiled_patterns: Vec<Regex>,
}

impl SecurityPolicy {
    /// Load and compile policy configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| Error::Config {
            message: format!("failed to read config file: {e}"),
        })?;

        let config_file: ConfigFile = toml::from_str(&content).map_err(|e| Error::Config {
            message: format!("failed to parse config file: {e}"),
        })?;

        let compiled_patterns = config_file
            .security
            .command_filter
            .patterns
            .iter()
            .map(|p| Regex::new(p))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Config {
                message: format!("invalid regex pattern: {e}"),
            })?;

        Ok(Self {
            config: config_file.security,
            compiled_patterns,
        })
    }

    /// Validate whether a tool is allowed under the current policy.
    pub fn check_tool(&self, tool_name: &str) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let allowed = match tool_name {
            "execute-command" | "get-command-result" => self.config.allow_execute_command,
            "send-keys" | "send-cancel" | "send-eof" | "send-escape" | "send-enter"
            | "send-tab" | "send-backspace" | "send-up" | "send-down" | "send-left"
            | "send-right" | "send-page-up" | "send-page-down" | "send-home" | "send-end" => {
                self.config.allow_send_keys
            }
            "kill-session" | "kill-window" | "kill-pane" | "detach-client" => {
                self.config.allow_kill
            }
            "create-session" | "create-window" => self.config.allow_create,
            "split-pane" => self.config.allow_split,
            "rename-session" | "rename-window" | "rename-pane" => self.config.allow_rename,
            "move-window"
            | "select-window"
            | "select-pane"
            | "resize-pane"
            | "zoom-pane"
            | "select-layout"
            | "join-pane"
            | "break-pane"
            | "swap-pane"
            | "set-synchronize-panes" => self.config.allow_move,
            "capture-pane" | "show-buffer" | "save-buffer" | "delete-buffer" => {
                self.config.allow_capture
            }
            "list-sessions"
            | "list-windows"
            | "list-panes"
            | "find-session"
            | "get-current-session"
            | "list-clients"
            | "list-buffers" => self.config.allow_list,
            _ => true,
        };

        if allowed {
            Ok(())
        } else {
            Err(Error::PolicyDenied {
                message: format!("tool '{tool_name}' is not allowed by security policy"),
            })
        }
    }

    /// Validate a command string against allow/deny patterns.
    pub fn check_command(&self, command: &str) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        match self.config.command_filter.mode {
            CommandFilterMode::Off => Ok(()),
            CommandFilterMode::Allowlist => {
                let matches = self.compiled_patterns.iter().any(|re| re.is_match(command));
                if matches {
                    Ok(())
                } else {
                    Err(Error::PolicyDenied {
                        message: format!("command '{command}' is not in the allowlist"),
                    })
                }
            }
            CommandFilterMode::Denylist => {
                let matches = self.compiled_patterns.iter().any(|re| re.is_match(command));
                if matches {
                    Err(Error::PolicyDenied {
                        message: format!("command '{command}' is in the denylist"),
                    })
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Validate a socket path against the allowed sockets list.
    pub fn check_socket(&self, socket: Option<&str>) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        match &self.config.allowed_sockets {
            None => Ok(()),
            Some(allowed) => match socket {
                None => Ok(()),
                Some(socket) => {
                    if allowed.iter().any(|s| s == socket) {
                        Ok(())
                    } else {
                        Err(Error::PolicyDenied {
                            message: format!("socket '{socket}' is not in allowed sockets list"),
                        })
                    }
                }
            },
        }
    }

    /// Validate a session id against the allowed sessions list.
    pub fn check_session(&self, session: &str) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        match &self.config.allowed_sessions {
            None => Ok(()),
            Some(allowed) => {
                if allowed.iter().any(|s| s == session) {
                    Ok(())
                } else {
                    Err(Error::PolicyDenied {
                        message: format!("session '{session}' is not in allowed sessions list"),
                    })
                }
            }
        }
    }

    /// Validate a pane id against the allowed panes list.
    pub fn check_pane(&self, pane_id: &str) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        match &self.config.allowed_panes {
            None => Ok(()),
            Some(allowed) => {
                if allowed.iter().any(|p| p == pane_id) {
                    Ok(())
                } else {
                    Err(Error::PolicyDenied {
                        message: format!("pane '{pane_id}' is not in allowed panes list"),
                    })
                }
            }
        }
    }

    /// Validate that raw mode is permitted by policy.
    pub fn check_raw_mode(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        if self.config.allow_raw_mode {
            Ok(())
        } else {
            Err(Error::PolicyDenied {
                message: "raw mode is not allowed by security policy".to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_policy_allows_all() {
        let policy = SecurityPolicy::default();
        assert!(policy.check_tool("execute-command").is_ok());
        assert!(policy.check_tool("send-keys").is_ok());
        assert!(policy.check_tool("kill-session").is_ok());
        assert!(policy.check_command("rm -rf /").is_ok());
        assert!(policy.check_session("any-session").is_ok());
        assert!(policy.check_pane("%99").is_ok());
    }

    #[test]
    fn test_tool_denial() {
        let config = SecurityConfig {
            enabled: true,
            allow_kill: false,
            ..Default::default()
        };
        let policy = SecurityPolicy {
            config,
            compiled_patterns: Vec::new(),
        };

        assert!(policy.check_tool("kill-session").is_err());
        assert!(policy.check_tool("kill-window").is_err());
        assert!(policy.check_tool("kill-pane").is_err());
        assert!(policy.check_tool("execute-command").is_ok());
    }

    #[test]
    fn test_command_allowlist() {
        let config = SecurityConfig {
            enabled: true,
            command_filter: CommandFilter {
                mode: CommandFilterMode::Allowlist,
                patterns: vec!["^git ".to_string(), "^ls".to_string()],
            },
            ..Default::default()
        };
        let compiled = config
            .command_filter
            .patterns
            .iter()
            .map(|p| Regex::new(p).unwrap())
            .collect();
        let policy = SecurityPolicy {
            config,
            compiled_patterns: compiled,
        };

        assert!(policy.check_command("git status").is_ok());
        assert!(policy.check_command("ls -la").is_ok());
        assert!(policy.check_command("rm -rf /").is_err());
    }

    #[test]
    fn test_command_denylist() {
        let config = SecurityConfig {
            enabled: true,
            command_filter: CommandFilter {
                mode: CommandFilterMode::Denylist,
                patterns: vec!["^rm ".to_string(), "^sudo".to_string()],
            },
            ..Default::default()
        };
        let compiled = config
            .command_filter
            .patterns
            .iter()
            .map(|p| Regex::new(p).unwrap())
            .collect();
        let policy = SecurityPolicy {
            config,
            compiled_patterns: compiled,
        };

        assert!(policy.check_command("git status").is_ok());
        assert!(policy.check_command("rm -rf /").is_err());
        assert!(policy.check_command("sudo apt install").is_err());
    }

    #[test]
    fn test_session_restriction() {
        let config = SecurityConfig {
            enabled: true,
            allowed_sessions: Some(vec!["work".to_string(), "dev".to_string()]),
            ..Default::default()
        };
        let policy = SecurityPolicy {
            config,
            compiled_patterns: Vec::new(),
        };

        assert!(policy.check_session("work").is_ok());
        assert!(policy.check_session("dev").is_ok());
        assert!(policy.check_session("personal").is_err());
    }

    #[test]
    fn test_pane_restriction() {
        let config = SecurityConfig {
            enabled: true,
            allowed_panes: Some(vec!["%1".to_string(), "%2".to_string()]),
            ..Default::default()
        };
        let policy = SecurityPolicy {
            config,
            compiled_patterns: Vec::new(),
        };

        assert!(policy.check_pane("%1").is_ok());
        assert!(policy.check_pane("%2").is_ok());
        assert!(policy.check_pane("%99").is_err());
    }

    #[test]
    fn test_socket_restriction() {
        let config = SecurityConfig {
            enabled: true,
            allowed_sockets: Some(vec!["/tmp/allowed.sock".to_string()]),
            ..Default::default()
        };
        let policy = SecurityPolicy {
            config,
            compiled_patterns: Vec::new(),
        };

        assert!(policy.check_socket(Some("/tmp/allowed.sock")).is_ok());
        assert!(policy.check_socket(Some("/tmp/other.sock")).is_err());
        assert!(policy.check_socket(None).is_ok());
    }

    #[test]
    fn test_disabled_security_allows_all() {
        let config = SecurityConfig {
            enabled: false,
            allow_kill: false,
            allowed_sessions: Some(vec!["only-this".to_string()]),
            command_filter: CommandFilter {
                mode: CommandFilterMode::Denylist,
                patterns: vec![".*".to_string()],
            },
            ..Default::default()
        };
        let compiled = config
            .command_filter
            .patterns
            .iter()
            .map(|p| Regex::new(p).unwrap())
            .collect();
        let policy = SecurityPolicy {
            config,
            compiled_patterns: compiled,
        };

        assert!(policy.check_tool("kill-session").is_ok());
        assert!(policy.check_command("anything").is_ok());
        assert!(policy.check_session("other-session").is_ok());
        assert!(policy.check_pane("%9").is_ok());
        assert!(policy.check_socket(Some("/tmp/ignored.sock")).is_ok());
        assert!(policy.check_raw_mode().is_ok());
    }

    #[test]
    fn test_check_tool_allows_unknown() {
        let policy = SecurityPolicy::default();
        assert!(policy.check_tool("unknown-tool").is_ok());
    }

    #[test]
    fn test_load_missing_file_returns_error() {
        let dir = TempDir::new().expect("temp dir");
        let missing = dir.path().join("missing.toml");

        let err = SecurityPolicy::load(&missing).unwrap_err();
        assert!(matches!(
            err,
            Error::Config { message } if message.contains("failed to read config file")
        ));
    }

    #[test]
    fn test_load_invalid_toml_returns_error() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "not = [valid").expect("write invalid toml");

        let err = SecurityPolicy::load(&path).unwrap_err();
        assert!(matches!(
            err,
            Error::Config { message } if message.contains("failed to parse config file")
        ));
    }
}
