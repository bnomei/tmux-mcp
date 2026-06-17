use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

use crate::commands::TrackingConfig;
use crate::errors::{Error, Result};

const TOOLS_ENV_VAR: &str = "TMUX_MCP_TOOLS";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ToolFilterMode {
    /// Disable the listed tools/groups; every other compiled tool remains available.
    #[default]
    Deny,
    /// Enable only the listed tools/groups.
    Allow,
}

/// Runtime tool-surface filtering configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ToolFilter {
    #[serde(default)]
    pub mode: ToolFilterMode,
    #[serde(default)]
    pub items: Vec<String>,
}

#[derive(Debug, Clone)]
struct CompiledToolFilter {
    mode: ToolFilterMode,
    tools: BTreeSet<String>,
}

impl Default for CompiledToolFilter {
    fn default() -> Self {
        Self {
            mode: ToolFilterMode::Deny,
            tools: BTreeSet::new(),
        }
    }
}

struct ToolManifestEntry {
    name: &'static str,
    groups: &'static [&'static str],
}

const TOOL_MANIFEST: &[ToolManifestEntry] = &[
    ToolManifestEntry {
        name: "socket-for-path",
        groups: &["socket", "read"],
    },
    ToolManifestEntry {
        name: "list-sessions",
        groups: &["list", "read"],
    },
    ToolManifestEntry {
        name: "find-session",
        groups: &["list", "read"],
    },
    ToolManifestEntry {
        name: "list-windows",
        groups: &["list", "read"],
    },
    ToolManifestEntry {
        name: "list-panes",
        groups: &["list", "read"],
    },
    ToolManifestEntry {
        name: "list-clients",
        groups: &["list", "read"],
    },
    ToolManifestEntry {
        name: "list-buffers",
        groups: &["list", "buffer-read", "read"],
    },
    ToolManifestEntry {
        name: "capture-pane",
        groups: &["capture", "read"],
    },
    ToolManifestEntry {
        name: "show-buffer",
        groups: &["buffer-read", "read"],
    },
    ToolManifestEntry {
        name: "search-buffer",
        groups: &["buffer-read", "read"],
    },
    ToolManifestEntry {
        name: "subsearch-buffer",
        groups: &["buffer-read", "read"],
    },
    ToolManifestEntry {
        name: "save-buffer",
        groups: &["buffer-write"],
    },
    ToolManifestEntry {
        name: "load-buffer",
        groups: &["buffer-write"],
    },
    ToolManifestEntry {
        name: "delete-buffer",
        groups: &["buffer-write"],
    },
    ToolManifestEntry {
        name: "set-buffer",
        groups: &["buffer-write"],
    },
    ToolManifestEntry {
        name: "append-buffer",
        groups: &["buffer-write"],
    },
    ToolManifestEntry {
        name: "rename-buffer",
        groups: &["buffer-write"],
    },
    ToolManifestEntry {
        name: "create-session",
        groups: &["create"],
    },
    ToolManifestEntry {
        name: "create-window",
        groups: &["create"],
    },
    ToolManifestEntry {
        name: "split-pane",
        groups: &["split"],
    },
    ToolManifestEntry {
        name: "kill-session",
        groups: &["kill"],
    },
    ToolManifestEntry {
        name: "kill-window",
        groups: &["kill"],
    },
    ToolManifestEntry {
        name: "kill-pane",
        groups: &["kill"],
    },
    ToolManifestEntry {
        name: "detach-client",
        groups: &["kill"],
    },
    ToolManifestEntry {
        name: "execute-command",
        groups: &["execute"],
    },
    ToolManifestEntry {
        name: "get-command-result",
        groups: &["execute", "read"],
    },
    ToolManifestEntry {
        name: "get-current-session",
        groups: &["list", "read"],
    },
    ToolManifestEntry {
        name: "rename-session",
        groups: &["rename"],
    },
    ToolManifestEntry {
        name: "rename-window",
        groups: &["rename"],
    },
    ToolManifestEntry {
        name: "rename-pane",
        groups: &["rename"],
    },
    ToolManifestEntry {
        name: "move-window",
        groups: &["move"],
    },
    ToolManifestEntry {
        name: "select-window",
        groups: &["move"],
    },
    ToolManifestEntry {
        name: "select-pane",
        groups: &["move"],
    },
    ToolManifestEntry {
        name: "resize-pane",
        groups: &["move"],
    },
    ToolManifestEntry {
        name: "zoom-pane",
        groups: &["move"],
    },
    ToolManifestEntry {
        name: "select-layout",
        groups: &["move"],
    },
    ToolManifestEntry {
        name: "join-pane",
        groups: &["move"],
    },
    ToolManifestEntry {
        name: "break-pane",
        groups: &["move"],
    },
    ToolManifestEntry {
        name: "swap-pane",
        groups: &["move"],
    },
    ToolManifestEntry {
        name: "set-synchronize-panes",
        groups: &["move"],
    },
    ToolManifestEntry {
        name: "send-keys",
        groups: &["interactive", "raw-input"],
    },
    ToolManifestEntry {
        name: "send-hex",
        groups: &["interactive", "raw-input"],
    },
    ToolManifestEntry {
        name: "paste-text",
        groups: &["interactive", "raw-input"],
    },
    ToolManifestEntry {
        name: "send-cancel",
        groups: &["special-keys", "raw-input"],
    },
    ToolManifestEntry {
        name: "send-eof",
        groups: &["special-keys", "raw-input"],
    },
    ToolManifestEntry {
        name: "send-escape",
        groups: &["special-keys", "raw-input"],
    },
    ToolManifestEntry {
        name: "send-enter",
        groups: &["special-keys", "raw-input"],
    },
    ToolManifestEntry {
        name: "send-tab",
        groups: &["special-keys", "raw-input"],
    },
    ToolManifestEntry {
        name: "send-backspace",
        groups: &["special-keys", "raw-input"],
    },
    ToolManifestEntry {
        name: "send-up",
        groups: &["special-keys", "raw-input"],
    },
    ToolManifestEntry {
        name: "send-down",
        groups: &["special-keys", "raw-input"],
    },
    ToolManifestEntry {
        name: "send-left",
        groups: &["special-keys", "raw-input"],
    },
    ToolManifestEntry {
        name: "send-right",
        groups: &["special-keys", "raw-input"],
    },
    ToolManifestEntry {
        name: "send-page-up",
        groups: &["special-keys", "raw-input"],
    },
    ToolManifestEntry {
        name: "send-page-down",
        groups: &["special-keys", "raw-input"],
    },
    ToolManifestEntry {
        name: "send-home",
        groups: &["special-keys", "raw-input"],
    },
    ToolManifestEntry {
        name: "send-end",
        groups: &["special-keys", "raw-input"],
    },
];

fn is_known_tool(name: &str) -> bool {
    TOOL_MANIFEST.iter().any(|tool| tool.name == name)
}

fn is_known_group(name: &str) -> bool {
    name == "all" || TOOL_MANIFEST.iter().any(|tool| tool.groups.contains(&name))
}

fn expand_tool_filter_item(item: &str, tools: &mut BTreeSet<String>) -> Result<()> {
    let normalized = item.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(());
    }

    if let Some(group) = normalized.strip_prefix('@') {
        if !is_known_group(group) {
            return Err(Error::Config {
                message: format!("unknown tool group '@{group}' in tool filter"),
            });
        }
        for tool in TOOL_MANIFEST {
            if group == "all" || tool.groups.contains(&group) {
                tools.insert(tool.name.to_string());
            }
        }
        return Ok(());
    }

    if !is_known_tool(&normalized) {
        return Err(Error::Config {
            message: format!("unknown tool '{normalized}' in tool filter"),
        });
    }
    tools.insert(normalized);
    Ok(())
}

fn compile_tool_filter(filter: &ToolFilter) -> Result<CompiledToolFilter> {
    let mut tools = BTreeSet::new();
    for item in &filter.items {
        expand_tool_filter_item(item, &mut tools)?;
    }
    Ok(CompiledToolFilter {
        mode: filter.mode,
        tools,
    })
}

fn parse_tool_filter_items(items: &str) -> Vec<String> {
    items
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn tool_filter_from_env() -> Result<Option<ToolFilter>> {
    let value = match std::env::var(TOOLS_ENV_VAR) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(Error::Config {
                message: format!("{TOOLS_ENV_VAR} must be valid UTF-8"),
            });
        }
    };

    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let (mode, items) = match trimmed.split_once(':') {
        Some((mode, items)) if mode.eq_ignore_ascii_case("allow") => (ToolFilterMode::Allow, items),
        Some((mode, items)) if mode.eq_ignore_ascii_case("deny") => (ToolFilterMode::Deny, items),
        Some((mode, _)) => {
            return Err(Error::Config {
                message: format!(
                    "invalid {TOOLS_ENV_VAR} mode '{mode}', expected 'allow:' or 'deny:'"
                ),
            });
        }
        None => (ToolFilterMode::Deny, trimmed),
    };

    Ok(Some(ToolFilter {
        mode,
        items: parse_tool_filter_items(items),
    }))
}

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

/// Search configuration loaded from config.toml.
#[derive(Debug, Clone, Deserialize)]
pub struct SearchConfig {
    #[serde(default = "default_streaming_threshold_bytes")]
    pub streaming_threshold_bytes: u64,
}

fn default_streaming_threshold_bytes() -> u64 {
    262_144
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            streaming_threshold_bytes: default_streaming_threshold_bytes(),
        }
    }
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
    #[serde(default)]
    pub tools: ToolFilter,
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
            tools: ToolFilter::default(),
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
    #[serde(default)]
    pub tracking: TrackingConfig,
    #[serde(default)]
    pub search: SearchConfig,
}

/// Enforces security rules derived from configuration.
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    config: SecurityConfig,
    compiled_patterns: Vec<Regex>,
    tool_filter: CompiledToolFilter,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::from_config(SecurityConfig::default()).expect("default security policy")
    }
}

impl SecurityPolicy {
    pub fn from_config(config: SecurityConfig) -> Result<Self> {
        Self::compile(config)
    }

    pub fn from_config_with_env(mut config: SecurityConfig) -> Result<Self> {
        if let Some(filter) = tool_filter_from_env()? {
            config.tools = filter;
        }
        Self::compile(config)
    }

    pub fn default_with_env() -> Result<Self> {
        Self::from_config_with_env(SecurityConfig::default())
    }

    /// Load and compile policy configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| Error::Config {
            message: format!("failed to read config file: {e}"),
        })?;

        let config_file: ConfigFile = toml::from_str(&content).map_err(|e| Error::Config {
            message: format!("failed to parse config file: {e}"),
        })?;

        Self::from_config_with_env(config_file.security)
    }

    fn compile(config: SecurityConfig) -> Result<Self> {
        let compiled_patterns = config
            .command_filter
            .patterns
            .iter()
            .map(|p| Regex::new(p))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Config {
                message: format!("invalid regex pattern: {e}"),
            })?;
        let tool_filter = compile_tool_filter(&config.tools)?;

        Ok(Self {
            config,
            compiled_patterns,
            tool_filter,
        })
    }

    /// Validate whether a tool is allowed under the current policy.
    pub fn check_tool(&self, tool_name: &str) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let allowed = match tool_name {
            "execute-command" | "get-command-result" => self.config.allow_execute_command,
            "send-keys" | "send-hex" | "paste-text" | "send-cancel" | "send-eof"
            | "send-escape" | "send-enter" | "send-tab" | "send-backspace" | "send-up"
            | "send-down" | "send-left" | "send-right" | "send-page-up" | "send-page-down"
            | "send-home" | "send-end" => self.config.allow_send_keys,
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
            "capture-pane" | "show-buffer" | "save-buffer" | "load-buffer" | "delete-buffer"
            | "set-buffer" | "append-buffer" | "rename-buffer" | "search-buffer"
            | "subsearch-buffer" => self.config.allow_capture,
            "list-sessions"
            | "list-windows"
            | "list-panes"
            | "find-session"
            | "get-current-session"
            | "list-clients"
            | "list-buffers" => self.config.allow_list,
            _ => true,
        };

        if !allowed {
            return Err(Error::PolicyDenied {
                message: format!("tool '{tool_name}' is not allowed by security policy"),
            });
        }

        if !self.check_tool_filter(tool_name) {
            return Err(Error::PolicyDenied {
                message: format!("tool '{tool_name}' is not allowed by configured tool filter"),
            });
        }

        Ok(())
    }

    fn check_tool_filter(&self, tool_name: &str) -> bool {
        match self.tool_filter.mode {
            ToolFilterMode::Deny => !self.tool_filter.tools.contains(tool_name),
            ToolFilterMode::Allow => self.tool_filter.tools.contains(tool_name),
        }
    }

    fn check_command_line(&self, command: &str) -> Result<()> {
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

    /// Validate command text against allow/deny patterns, line by line.
    pub fn check_command(&self, command: &str) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut checked_any = false;
        for line in command
            .split(['\n', '\r'])
            .filter(|line| !line.trim().is_empty())
        {
            checked_any = true;
            self.check_command_line(line)?;
        }

        if checked_any {
            Ok(())
        } else {
            self.check_command_line(command)
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
                None => Err(Error::PolicyDenied {
                    message: "effective socket is not in allowed sockets list".to_string(),
                }),
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

    /// Returns true if session allowlist enforcement is configured.
    pub fn has_session_allowlist(&self) -> bool {
        self.config.allowed_sessions.is_some()
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
        let policy = SecurityPolicy::from_config(config).expect("compile policy");

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
        let policy = SecurityPolicy::from_config(config).expect("compile policy");

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
        let policy = SecurityPolicy::from_config(config).expect("compile policy");

        assert!(policy.check_command("git status").is_ok());
        assert!(policy.check_command("rm -rf /").is_err());
        assert!(policy.check_command("sudo apt install").is_err());
    }

    #[test]
    fn test_command_filter_checks_each_non_empty_line() {
        let config = SecurityConfig {
            enabled: true,
            command_filter: CommandFilter {
                mode: CommandFilterMode::Denylist,
                patterns: vec!["^rm ".to_string()],
            },
            ..Default::default()
        };
        let policy = SecurityPolicy::from_config(config).expect("compile policy");

        assert!(policy.check_command("echo ok\nrm -rf /").is_err());
        assert!(policy.check_command("echo ok\r\nrm -rf /").is_err());
        assert!(policy.check_command("echo ok\n\nprintf done").is_ok());
    }

    #[test]
    fn test_command_allowlist_checks_each_non_empty_line() {
        let config = SecurityConfig {
            enabled: true,
            command_filter: CommandFilter {
                mode: CommandFilterMode::Allowlist,
                patterns: vec!["^echo ".to_string(), "^printf ".to_string()],
            },
            ..Default::default()
        };
        let policy = SecurityPolicy::from_config(config).expect("compile policy");

        assert!(policy.check_command("echo ok\nprintf done").is_ok());
        assert!(policy.check_command("echo ok\nrm -rf /").is_err());
    }

    #[test]
    fn test_session_restriction() {
        let config = SecurityConfig {
            enabled: true,
            allowed_sessions: Some(vec!["work".to_string(), "dev".to_string()]),
            ..Default::default()
        };
        let policy = SecurityPolicy::from_config(config).expect("compile policy");

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
        let policy = SecurityPolicy::from_config(config).expect("compile policy");

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
        let policy = SecurityPolicy::from_config(config).expect("compile policy");

        assert!(policy.check_socket(Some("/tmp/allowed.sock")).is_ok());
        assert!(policy.check_socket(Some("/tmp/other.sock")).is_err());
        assert!(policy.check_socket(None).is_err());
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
        let policy = SecurityPolicy::from_config(config).expect("compile policy");

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
    fn test_tool_filter_denies_exact_tools() {
        let config = SecurityConfig {
            tools: ToolFilter {
                mode: ToolFilterMode::Deny,
                items: vec!["kill-session".to_string(), "paste-text".to_string()],
            },
            ..Default::default()
        };
        let policy = SecurityPolicy::from_config(config).expect("compile policy");

        assert!(policy.check_tool("kill-session").is_err());
        assert!(policy.check_tool("paste-text").is_err());
        assert!(policy.check_tool("execute-command").is_ok());
    }

    #[test]
    fn test_tool_filter_allows_only_list_group() {
        let config = SecurityConfig {
            tools: ToolFilter {
                mode: ToolFilterMode::Allow,
                items: vec!["@list".to_string()],
            },
            ..Default::default()
        };
        let policy = SecurityPolicy::from_config(config).expect("compile policy");

        assert!(policy.check_tool("list-sessions").is_ok());
        assert!(policy.check_tool("find-session").is_ok());
        assert!(policy.check_tool("capture-pane").is_err());
        assert!(policy.check_tool("execute-command").is_err());
    }

    #[test]
    fn test_tool_filter_group_denies_raw_input() {
        let config = SecurityConfig {
            tools: ToolFilter {
                mode: ToolFilterMode::Deny,
                items: vec!["@raw-input".to_string()],
            },
            ..Default::default()
        };
        let policy = SecurityPolicy::from_config(config).expect("compile policy");

        assert!(policy.check_tool("send-keys").is_err());
        assert!(policy.check_tool("send-enter").is_err());
        assert!(policy.check_tool("execute-command").is_ok());
    }

    #[test]
    fn test_tool_filter_rejects_unknown_items() {
        let config = SecurityConfig {
            tools: ToolFilter {
                mode: ToolFilterMode::Deny,
                items: vec!["missing-tool".to_string()],
            },
            ..Default::default()
        };

        let err = SecurityPolicy::from_config(config).unwrap_err();
        assert!(matches!(
            err,
            Error::Config { message } if message.contains("unknown tool 'missing-tool'")
        ));
    }

    #[test]
    fn test_tool_filter_rejects_unknown_groups() {
        let config = SecurityConfig {
            tools: ToolFilter {
                mode: ToolFilterMode::Deny,
                items: vec!["@missing".to_string()],
            },
            ..Default::default()
        };

        let err = SecurityPolicy::from_config(config).unwrap_err();
        assert!(matches!(
            err,
            Error::Config { message } if message.contains("unknown tool group '@missing'")
        ));
    }

    #[test]
    fn test_disabled_security_ignores_tool_filter() {
        let config = SecurityConfig {
            enabled: false,
            tools: ToolFilter {
                mode: ToolFilterMode::Allow,
                items: Vec::new(),
            },
            ..Default::default()
        };
        let policy = SecurityPolicy::from_config(config).expect("compile policy");

        assert!(policy.check_tool("execute-command").is_ok());
        assert!(policy.check_tool("send-keys").is_ok());
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
