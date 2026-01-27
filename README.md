# tmux-mcp-rs

[![Crates.io Version](https://img.shields.io/crates/v/tmux-mcp-rs)](https://crates.io/crates/tmux-mcp-rs)
[![CI](https://img.shields.io/github/actions/workflow/status/bnomei/tmux-mcp/ci.yml?branch=main)](https://github.com/bnomei/tmux-mcp/actions/workflows/ci.yml)
[![Crates.io Downloads](https://img.shields.io/crates/d/tmux-mcp-rs)](https://crates.io/crates/tmux-mcp-rs)
[![License](https://img.shields.io/crates/l/tmux-mcp-rs)](https://crates.io/crates/tmux-mcp-rs)
[![Discord](https://flat.badgen.net/badge/discord/bnomei?color=7289da&icon=discord&label)](https://discordapp.com/users/bnomei)
[![Buymecoffee](https://flat.badgen.net/badge/icon/donate?icon=buymeacoffee&color=FF813F&label)](https://www.buymeacoffee.com/bnomei)

A Model Context Protocol (MCP) server for tmux, written in Rust. It lets AI assistants create sessions, split panes, run commands, and capture output.

- The agent runs this MCP server to create and manage its own tmux session (often on an isolated socket).
- The user/developer can attach to the same session to watch or participate in real time.
- Bonus: it also works with human-created sessions, including remote setups over SSH.

Requires tmux installed and available on `PATH`.

> [!WARNING]
> Using this MCP allows the agent to escape the sandbox and its security limitations. Here be dragons!

## Why MCP (Not Just A Skill)

You can automate tmux with a plain-text skill, but the MCP tools are more reliable and cheaper to run:

- Structured inputs and structured outputs reduce ambiguity, which improves agent quality.
- Tool responses return stable IDs (session/window/pane/command), which avoids fragile name matching.
- `execute-command` + `get-command-result` yields attributable output and exit codes without screen scraping.
- Structured results are compact, so the agent spends fewer tokens than repeatedly capturing and parsing panes.
- The MCP server can enforce policy (tool gating, allow/deny patterns, scoped sockets/sessions/panes).

## Installation

### Cargo (crates.io)
```bash
cargo install tmux-mcp-rs
```

### Homebrew
```bash
brew install bnomei/tmux-mcp/tmux-mcp-rs
```

### GitHub Releases
Download a prebuilt archive from the GitHub Releases page, extract it, and place `tmux-mcp-rs` on your `PATH`.

### From source
```bash
git clone https://github.com/bnomei/tmux-mcp.git
cd tmux-mcp
cargo build --release
```

## Quick Start

1) Add this MCP configuration. Examples for common MCP clients (pick one):
    
```bash
# Claude Code
claude mcp add --transport stdio tmux -- tmux-mcp-rs

# Codex CLI
codex mcp add tmux -- tmux-mcp-rs

# OpenCode (interactive)
opencode mcp add

# Amp (non-workspace)
amp mcp add tmux -- tmux-mcp-rs
```

```json
{
  "mcpServers": {
    "tmux": {
      "command": "tmux-mcp-rs"
    }
  }
}
```

2) Let the agent create its own tmux session (it will return the session id by default), or start one yourself if you want a pre-existing session (local, isolated socket, or remote over SSH).
3) Optional: attach to watch the agent work:
```bash
tmux attach -t <session>
```

## Usage

### MCP Configuration

Add the Quick Start snippet to your MCP client config. Example below includes all supported args (remove the ones you don't need):

```json
{
  "mcpServers": {
    "tmux": {
      "command": "tmux-mcp-rs",
      "args": [
        "--shell-type",
        "zsh",
        "--socket",
        "/path/to/tmux.sock",
        "--ssh",
        "user@host",
        "--config",
        "/path/to/config.toml"
      ]
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
- **capture-pane** - Capture pane content (state/logs; not for routine command output)
- **select-pane** - Select/focus a pane
- **resize-pane** - Resize a pane by direction or size
- **zoom-pane** - Toggle pane zoom
- **join-pane** - Join a source pane into a target pane's window
- **break-pane** - Break a pane into a new window
- **swap-pane** - Swap two panes

### Command Execution
- **execute-command** - Execute a command in a pane (preferred for non-interactive)
- **get-command-result** - Get the result of an executed command (preferred output path)

### Client Management
- **list-clients** - List tmux clients
- **detach-client** - Detach a tmux client

### Buffer Management
- **list-buffers** - List tmux paste buffers
- **show-buffer** - Show buffer contents (supports offset/max bytes; defaults to 64KB)
- **save-buffer** - Save buffer contents to a file
- **delete-buffer** - Delete a buffer

### Additional Buffer Tools
- **set-buffer** - Create or replace a buffer with UTF-8 content
- **load-buffer** - Load buffer contents from a file
- **append-buffer** - Append UTF-8 content to an existing buffer
- **rename-buffer** - Emulate rename by copying then deleting
- **search-buffer** - Structured search over one or more buffers (literal/regex + metadata)
- **subsearch-buffer** - Anchor-scoped follow-up search with structured metadata

### Key Sending
- **send-keys** - Send arbitrary keys to a pane (interactive only)
- **send-cancel** - Send Ctrl+C
- **send-eof** - Send Ctrl+D (EOF)
- **send-escape** - Send Escape key
- **send-enter** - Send Enter key (interactive prompts)
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

## Skills

- [tmux-via-mcp](skills/tmux-via-mcp/SKILL.md) - Use the tmux MCP tools to create sessions, shape layouts, run tracked commands, and automate interactive terminals when a real TTY or parallel panes are required.
- [tmux-buffer-explorer](skills/tmux-buffer-explorer/SKILL.md) - Explore large tmux buffers via search and bounded slices. Use when buffer data is too large to load at once or needs incremental inspection.

### Probing and Refining with tmux-buffer-explorer

The additonal buffer tools extend tmux’s native buffers for the probe‑and‑refine workflow described in the paper from Alex L. Zhang, Tim Kraska and Omar Khattab [Recursive Language Models](https://arxiv.org/pdf/2512.24601), while keeping all state inside tmux buffers and thus in RAM. They’re general-purpose building blocks used by the coordinating Skill at [skills/tmux-buffer-explorer/SKILL.md](https://github.com/bnomei/tmux-mcp/blob/main/skills/tmux-buffer-explorer/SKILL.md).

The tmux buffer search is **not intended to replace ripgrep** or similar search approaches. `rg` is a high-performance, one-shot search tool optimized for humans who already know what they are looking for. This skill targets a different problem: enabling **LLM agents to explore large contexts incrementally**.

Search here is a **navigation primitive**, not an end result. It provides:
- structured results with stable offsets and match IDs
- bounded, zoom-able reads for follow-up inspection
- deterministic behavior across multiple reasoning steps

This aligns with the *Recursive Language Models* approach: treat context as an **external environment to explore**, not a blob to ingest. Performance is more than enough for buffer-scale text, and the dominant cost is agent reasoning, not scanning.

### Examples: Old Man and the Sea (113 KB = too big for LLM context)
- **Q:** Use the _tmux buffer_ to search the tests/fixtures/old-man-and-the-sea.txt for
baseball near dimago.
- **Q:** Where does the old man talk about why he admires DiMaggio, and what reason does he
give?
- **Q:** Where does the old man reflect on his loneliness at sea, and how does that reflection change later in the story?
- **Q:** Find the passage where the lions are mentioned most vividly and summarize what they symbolize.

> **Q:** Locate the moment where the old man’s confidence shifts into doubt during the fight with the fish.
> 
> **A:** In tmux buffer oldman around byte offset ~56320 (mid‑fight, when his left hand
  cramps), he asserts he can handle the line with his right arm alone, then
  immediately says he doesn’t know what the fish will do and starts questioning the
  fish’s plan and his own. That’s the confidence‑to‑doubt shift.


## Remote SSH (optional)

Use `--ssh` to control a tmux server on another machine. Make sure SSH authentication is non-interactive (e.g. agent or keys).

```bash
tmux-mcp-rs --ssh "user@host"
```

For extra SSH options, put them before the host (e.g. `--ssh "-i ~/.ssh/key user@host"`) or use `~/.ssh/config`. The destination should be the last token in the `--ssh` string.

### Remote + isolated (SSH + socket)

Create a dedicated tmux server on the remote host, then point the MCP server at that socket:

```bash
# On the remote host (once):
ssh user@host 'tmux -S /tmp/ai-agent.sock -f /dev/null new-session -d -s workspace'

# Locally:
tmux-mcp-rs --ssh "user@host" --socket /tmp/ai-agent.sock
```

## Socket isolation (optional)

Use `--socket` or `TMUX_MCP_SOCKET` to point the MCP server at a specific tmux server socket.

```bash
# Connect to a specific socket id
tmux-mcp-rs --socket /tmp/tmux-mcp-<agent-id>.sock

# Or via environment variable
TMUX_MCP_SOCKET=/tmp/tmux-mcp-<agent-id>.sock tmux-mcp-rs
```

If you want to pre-create an isolated tmux server for the agent:

```bash
tmux -S /tmp/ai-agent.sock -f /dev/null new-session -d -s workspace
TMUX_MCP_SOCKET=/tmp/ai-agent.sock tmux-mcp-rs
```

## Workflow Patterns (CLI Agents)

These patterns mirror how CLI agents like Codex can structure tmux work. Each is backed by an integration test in `tests/integration.rs` (run with `TMUX_MCP_INTEGRATION=1`).

- **ID-first targeting**: Use window/pane IDs for operations when names collide. Tools: list-windows/list-panes, rename-window. Test: `test_workflow_id_first_targeting`.
- **Task-per-session layout**: Create a session per task, add windows for build/test/docs, and split panes for runners/logs. Tools: create-session, create-window, split-pane, rename-pane, list-windows, list-panes. Test: `test_workflow_task_per_session_layout`.
- **Stateful shell context**: Set environment/state in a pane and reuse it across commands. Tools: send-keys, capture-pane. Test: `test_workflow_stateful_shell_context`.
- **Continuous output pane**: Run a long command and poll `capture-pane` to summarize progress without losing terminal state. Tools: send-keys, capture-pane. Test: `test_workflow_continuous_output_capture`.
- **Interactive prompt automation**: Drive a blocking prompt (or simple TUI) by sending responses via keys, then capture the result. Tools: send-keys, capture-pane. Test: `test_workflow_interactive_prompt`.
- **Interactive interrupts**: Cancel long-running commands and end stdin streams with EOF. Tools: send-cancel, send-eof, capture-pane. Test: `test_workflow_interactive_interrupts`.
- **Synchronized panes broadcast**: Fan out a command to multiple panes at once using synchronize-panes. Tools: set-synchronize-panes, send-keys, capture-pane. Test: `test_workflow_synchronized_panes_broadcast`.
- **Buffer handoff + probe**: Stash output in buffers, optionally search/subsearch for targeted slices, save to disk, and delete when done. Tools: list-buffers, show-buffer, save-buffer, delete-buffer, search-buffer, subsearch-buffer. Test: `test_workflow_buffer_roundtrip` (core flow).
- **Pane rearrangements**: Swap/break/join panes and apply layouts while preserving pane identities. Tools: split-pane, select-layout, swap-pane, break-pane, join-pane, list-panes, list-windows. Test: `test_workflow_pane_rearrangements`.
- **Metadata + zoom**: Rename session/window/pane and inspect pane/window metadata; toggle zoom and resize. Tools: rename-session, rename-window, rename-pane, zoom-pane, resize-pane. Resources: `tmux://pane/{paneId}/info`, `tmux://window/{windowId}/info`. Test: `test_workflow_metadata_and_zoom`.
- **Audit-ready context bundle**: Pair tracked command output with raw pane capture for traceability. Tools: execute-command, get-command-result, capture-pane. Test: `test_workflow_audit_context_bundle`.
- **Agent orchestration**: Run parallel commands across windows/panes with log monitoring. Tools: create-window, split-pane, execute-command, send-keys, capture-pane. Test: `test_workflow_agent_orchestration`.

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


## License

MIT License - see [LICENSE](LICENSE) for details.
