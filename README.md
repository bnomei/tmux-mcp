# tmux-mcp-rs

[![Crates.io Version](https://img.shields.io/crates/v/tmux-mcp-rs)](https://crates.io/crates/tmux-mcp-rs)
[![CI](https://img.shields.io/github/actions/workflow/status/bnomei/tmux-mcp/ci.yml?branch=main)](https://github.com/bnomei/tmux-mcp/actions/workflows/ci.yml)
[![Crates.io Downloads](https://img.shields.io/crates/d/tmux-mcp-rs)](https://crates.io/crates/tmux-mcp-rs)
[![License](https://img.shields.io/crates/l/tmux-mcp-rs)](https://crates.io/crates/tmux-mcp-rs)
[![Discord](https://flat.badgen.net/badge/discord/bnomei?color=7289da&icon=discord&label)](https://discordapp.com/users/bnomei)
[![Buymecoffee](https://flat.badgen.net/badge/icon/donate?icon=buymeacoffee&color=FF813F&label)](https://www.buymeacoffee.com/bnomei)

A Model Context Protocol (MCP) server for tmux, written in Rust. It lets AI assistants create sessions, split panes, run commands, and capture output.

**For**:
- Rust users who want `cargo install` and a native CLI.
- npm users who want `npm install -g` and automatic binary downloads.
- tmux users who want to watch an agent work in real time.

Requires tmux installed and available on `PATH`.

> [!WARNING]
> Using this MCP allow the agent to escape the sandbox and its security limitations. Here be dragons!

## Highlights

- **Remote SSH control (brand new for agents)**: Agents can connect to tmux over SSH, enabling remote, live tmux control on dev boxes, build hosts, or long-running machines.
- **Socket isolation**: Target a specific tmux server socket so agents can work in their own clean workspace without touching your default tmux.
- **Better together**: Combine `--ssh` + `--socket` to run an isolated tmux server on a remote host.

```bash
# Remote + isolated (SSH + socket)
tmux-mcp-rs --ssh "user@host" --socket /tmp/ai-agent.sock
```

## Installation

### Cargo (crates.io)
```bash
cargo install tmux-mcp-rs
```

### Homebrew
```bash
brew install bnomei/tmux-mcp/tmux-mcp-rs
```

### npm
```bash
npm install -g @bnomei/tmux-mcp-rs
```

### npx (no install)
```bash
npx -y @bnomei/tmux-mcp-rs@latest -- --shell-type zsh
```

## Quick Start

1) Start a tmux session (local, isolated socket, or remote over SSH).
2) Add this MCP configuration:

```json
{
  "mcpServers": {
    "tmux": {
      "command": "tmux-mcp-rs",
      "args": ["--shell-type", "zsh"]
    }
  }
}
```

3) Attach to watch the agent work:
```bash
tmux attach -t <session>
```

## Usage

### MCP Configuration

Add the Quick Start snippet to your MCP client config. Or use a config file:

```json
{
  "mcpServers": {
    "tmux": {
      "command": "tmux-mcp-rs",
      "args": ["--config", "/path/to/config.toml"]
    }
  }
}
```

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--shell-type <SHELL>` | Shell to use (bash, zsh, fish) | `bash` |
| `--socket <PATH>` | Path to tmux server socket (recommend per-agent isolated socket id) | Default server (if unset) |
| `--ssh <CONNECTION>` | Run tmux over SSH (options + destination, destination last) | None |
| `--config <PATH>` | Path to TOML configuration file | None |

Environment variables: `TMUX_MCP_SOCKET` can also set the socket path (recommend per-agent isolated socket id). `TMUX_MCP_SSH` can set the SSH connection string.

### Sample Configuration (config.toml)

```toml
[shell]
type = "zsh"

[ssh]
remote = "user@host"

[security]
enabled = true
allow_execute_command = true

[security.command_filter]
mode = "off" # off | allowlist | denylist
patterns = []
```

### Security defaults (why nothing is denied)

By default, the security policy is permissive to avoid breaking agent workflows:

- `security.enabled = true`, but all `allow_*` flags are `true`
- `command_filter.mode = "off"` (no allow/deny patterns)
- `allowed_sockets/sessions/panes` are unset (no scoping)

**Denylist behavior:** when `command_filter.mode = "denylist"`, any regex in
`security.command_filter.patterns` that matches a command string will block that
command. This applies to `execute-command` and non-literal `send-keys` only.

To harden a deployment, flip specific `allow_*` flags, add deny/allow patterns,
or restrict sockets/sessions/panes explicitly.

## Remote SSH (why it matters)

If your tmux server runs on another machine, you can tunnel tmux commands over SSH. This unlocks a brand‑new agent pattern: live tmux control over SSH on remote hosts. It’s ideal when the agent should work near the code or hardware:

- Use a remote dev box, CI runner, or lab machine without changing your local tmux setup.
- Keep long-running sessions off your laptop while still attaching to observe.
- Centralize a shared tmux server for multiple agents.

Make sure SSH authentication is non-interactive (e.g. agent or keys).

```bash
tmux-mcp-rs --ssh "user@host"
```

For extra SSH options, put them before the host (e.g. `--ssh "-i ~/.ssh/key user@host"`) or use `~/.ssh/config`. The destination should be the last token in the `--ssh` string.

> [!TIP]
> Consider running another agent on the remote host within that TMUX session.

### Remote + isolated (SSH + socket)

Create a dedicated tmux server on the remote host, then point the MCP server at that socket:

```bash
# On the remote host (once):
ssh user@host 'tmux -S /tmp/ai-agent.sock -f /dev/null new-session -d -s workspace'

# Locally:
tmux-mcp-rs --ssh "user@host" --socket /tmp/ai-agent.sock
```

## Socket Isolation (why it matters)

By default, each LLM instance should run against its own isolated tmux server. Set a unique socket id per agent (recommendation: use the same ID as the harness session) using the `--socket` flag or `TMUX_MCP_SOCKET` environment variable:

```bash
# Connect to a specific socket id
tmux-mcp-rs --socket /tmp/tmux-mcp-<agent-id>.sock

# Or via environment variable
TMUX_MCP_SOCKET=/tmp/tmux-mcp-<agent-id>.sock tmux-mcp-rs
```

### AI Agent Orchestration

This feature enables AI agents to create and manage their own isolated tmux environments without affecting user sessions:

```bash
# Create an isolated tmux server for the AI
tmux -S /tmp/ai-agent.sock -f /dev/null new-session -d -s workspace

# Start MCP server pointing to that socket
TMUX_MCP_SOCKET=/tmp/ai-agent.sock tmux-mcp-rs
```

The AI can then:
- Create sessions, windows, and panes freely
- Run commands without interfering with user work
- Clean up completely by killing the isolated server

You can still watch the agent work in real time by attaching to the same tmux server:
- Shared server: `tmux attach -t <session>`
- Isolated server: `tmux -S /tmp/ai-agent.sock attach -t <session>`

### Workflow Patterns (CLI Agents)

These patterns mirror how CLI agents like Codex can structure tmux work. Each is backed by an integration test in `tests/integration.rs` (run with `TMUX_MCP_INTEGRATION=1`).

- **ID-first targeting**: Use window/pane IDs for operations when names collide. Tools: list-windows/list-panes, rename-window. Test: `test_workflow_id_first_targeting`.
- **Task-per-session layout**: Create a session per task, add windows for build/test/docs, and split panes for runners/logs. Tools: create-session, create-window, split-pane, rename-pane, list-windows, list-panes. Test: `test_workflow_task_per_session_layout`.
- **Stateful shell context**: Set environment/state in a pane and reuse it across commands. Tools: send-keys, capture-pane. Test: `test_workflow_stateful_shell_context`.
- **Continuous output pane**: Run a long command and poll `capture-pane` to summarize progress without losing terminal state. Tools: send-keys, capture-pane. Test: `test_workflow_continuous_output_capture`.
- **Interactive prompt automation**: Drive a blocking prompt (or simple TUI) by sending responses via keys, then capture the result. Tools: send-keys, capture-pane. Test: `test_workflow_interactive_prompt`.
- **Interactive interrupts**: Cancel long-running commands and end stdin streams with EOF. Tools: send-cancel, send-eof, capture-pane. Test: `test_workflow_interactive_interrupts`.
- **Synchronized panes broadcast**: Fan out a command to multiple panes at once using synchronize-panes. Tools: set-synchronize-panes, send-keys, capture-pane. Test: `test_workflow_synchronized_panes_broadcast`.
- **Buffer handoff**: Stash output in buffers, save to disk, and delete when done. Tools: list-buffers, show-buffer, save-buffer, delete-buffer. Test: `test_workflow_buffer_roundtrip`.
- **Pane rearrangements**: Swap/break/join panes and apply layouts while preserving pane identities. Tools: split-pane, select-layout, swap-pane, break-pane, join-pane, list-panes, list-windows. Test: `test_workflow_pane_rearrangements`.
- **Metadata + zoom**: Rename session/window/pane and inspect pane/window metadata; toggle zoom and resize. Tools: rename-session, rename-window, rename-pane, zoom-pane, resize-pane. Resources: `tmux://pane/{paneId}/info`, `tmux://window/{windowId}/info`. Test: `test_workflow_metadata_and_zoom`.
- **Audit-ready context bundle**: Pair tracked command output with raw pane capture for traceability. Tools: execute-command, get-command-result, capture-pane. Test: `test_workflow_audit_context_bundle`.
- **Agent orchestration**: Run parallel commands across windows/panes with log monitoring. Tools: create-window, split-pane, execute-command, send-keys, capture-pane. Test: `test_workflow_agent_orchestration`.

## Tools

### Core Utilities
- **socket-for-path** - Derive a deterministic tmux socket path for a project directory

### Session Management
- **list-sessions** - List all tmux sessions
- **find-session** - Find a session by name pattern
- **create-session** - Create a new session
- **kill-session** - Kill a session
- **get-current-session** - Get the current/attached session
- **rename-session** - Rename a session

### Window Management
- **list-windows** - List windows in a session
- **create-window** - Create a new window
- **kill-window** - Kill a window
- **rename-window** - Rename a window
- **move-window** - Move a window to another position/session
- **select-window** - Select/focus a window
- **select-layout** - Apply a window layout (tiled/even/main-*)
- **set-synchronize-panes** - Toggle synchronize-panes for a window

### Pane Management
- **list-panes** - List panes in a window
- **split-pane** - Split a pane horizontally or vertically
- **kill-pane** - Kill a pane (closing the last pane also closes its window)
- **rename-pane** - Set pane title
- **capture-pane** - Capture pane content
- **select-pane** - Select/focus a pane
- **resize-pane** - Resize a pane by direction or size
- **zoom-pane** - Toggle pane zoom
- **join-pane** - Join a source pane into a target pane's window
- **break-pane** - Break a pane into a new window
- **swap-pane** - Swap two panes

### Command Execution
- **execute-command** - Execute a command in a pane
- **get-command-result** - Get the result of an executed command

### Client Management
- **list-clients** - List tmux clients
- **detach-client** - Detach a tmux client

### Buffer Management
- **list-buffers** - List tmux paste buffers
- **show-buffer** - Show buffer contents
- **save-buffer** - Save buffer contents to a file
- **delete-buffer** - Delete a buffer

### Key Sending
- **send-keys** - Send arbitrary keys to a pane
- **send-cancel** - Send Ctrl+C
- **send-eof** - Send Ctrl+D (EOF)
- **send-escape** - Send Escape key
- **send-enter** - Send Enter key
- **send-tab** - Send Tab key
- **send-backspace** - Send Backspace key

### Navigation Keys
- **send-up** - Send Up arrow
- **send-down** - Send Down arrow
- **send-left** - Send Left arrow
- **send-right** - Send Right arrow
- **send-page-up** - Send Page Up
- **send-page-down** - Send Page Down
- **send-home** - Send Home key
- **send-end** - Send End key

## Resources

The server exposes the following MCP resources:

| URI | Description |
|-----|-------------|
| `tmux://server/info` | Default socket and SSH context for routing tool calls |
| `tmux://pane/{paneId}` | Content of a specific pane (last 200 lines) |
| `tmux://pane/{paneId}/info` | Metadata for a specific pane |
| `tmux://pane/{paneId}/tail/{lines}` | Tail N lines from a pane |
| `tmux://pane/{paneId}/tail/{lines}/ansi` | Tail N lines with ANSI colors |
| `tmux://window/{windowId}/info` | Metadata for a window |
| `tmux://session/{sessionId}/tree` | Session + windows + panes snapshot |
| `tmux://clients` | List tmux clients |
| `tmux://command/{commandId}/result` | Status and output of a tracked command |

Resources are dynamically enumerated - the server lists available panes, windows, sessions, clients, and active commands.

## Development

### Running Tests

Unit tests (no tmux required):
```bash
cargo test --lib
```

Integration tests (requires tmux installed):
```bash
# Install tmux if needed
# macOS: brew install tmux
# Ubuntu: sudo apt-get install tmux

# Run integration tests (uses isolated tmux server)
TMUX_MCP_INTEGRATION=1 cargo test --test integration
```

Integration tests create an isolated tmux server using a temp socket, so they won't affect your running tmux sessions.

## License

MIT License - see [LICENSE](LICENSE) for details.
