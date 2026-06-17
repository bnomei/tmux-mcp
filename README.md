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

Requires **tmux 3.x** installed and available on `PATH`. The server checks the
version on startup and refuses to run against tmux 2.x, whose output formats and
split flags differ. CI runs integration tests against the tmux version provided
by `ubuntu-latest`; development is on 3.6.

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

### Hardened build (compile-time tool removal)
The raw input tools are gated behind Cargo features that are **enabled by
default**:

- `interactive` — the `send-keys`, `send-hex`, and `paste-text` tools.
- `special-keys` — the `send-enter`, `send-tab`, `send-escape`, arrow, page,
  home/end, `send-backspace`, `send-cancel`, and `send-eof` tools.

Because these tools can inject bytes straight into the PTY, the
`command_filter` is not a complete boundary for the feature set (for example, a
denied command can be typed character-by-character and then submitted with
Enter). Disabling a feature removes those tools from the binary entirely — they
are never registered, so an agent cannot call them and `list-tools` will not
advertise them.

```bash
# Filtered-only build: execute-command is the sole shell-input path.
cargo build --release --no-default-features --features rayon,rapidfuzz

# Keep raw keystrokes but drop the special-key helpers (or vice versa).
cargo build --release --no-default-features --features rayon,rapidfuzz,interactive
```

`execute-command` is always present and remains subject to the `command_filter`
allow/deny patterns, so a hardened build forces all shell input through the
validated path.

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

Environment variables: `TMUX_MCP_SOCKET` can also set the socket path (recommend per-agent isolated socket id). `TMUX_MCP_SSH` can set the SSH connection string and is parsed with the same startup validation as `--ssh`. `TMUX_MCP_TOOLS` can override the configured tool surface for one process.

### Sample Configuration (config.toml)

```toml
[shell]
type = "zsh"

[ssh]
remote = "user@host"

[security]
enabled = true
allow_execute_command = true
allowed_sockets = ["/tmp/ai-agent.sock"]
allowed_sessions = ["workspace"]
allowed_panes = ["%1"]

[security.command_filter]
mode = "off" # off | allowlist | denylist
patterns = []

[security.tools]
mode = "deny" # deny | allow
items = []    # tool names or groups such as "@raw-input"

[tracking]
capture_initial_lines = 1000
capture_max_lines = 16000
capture_backoff_factor = 2
completed_retention_minutes = 240
completed_max_entries = 1000
tracking_deadline_seconds = 600

[search]
streaming_threshold_bytes = 262144
```

### Security defaults and controls

By default, `tmux-mcp-rs` is intentionally permissive. If you do not provide a
`config.toml`, security policy enforcement is enabled but every operation group
is allowed, command filtering is off, and sockets, sessions, and panes are not
restricted. This means an MCP client can create and kill tmux objects, send raw
PTY input, run shell commands, capture pane and buffer contents, and target any
tmux socket reachable by the process. Use an isolated socket per agent whenever
possible.

The settings below are the runtime controls that affect command, capture, and
socket behavior:

| Setting | Default | Effect |
|---------|---------|--------|
| `security.enabled` | `true` | Turns policy checks on. Set to `false` only to bypass all security policy checks. |
| `security.allow_execute_command` | `true` | Allows `execute-command` and `get-command-result`. `execute-command` is the only shell-input path checked by `security.command_filter`. |
| `security.command_filter` | `mode = "off"` | Applies regex allowlist or denylist checks to each non-empty line passed to `execute-command`. It does not cover raw input tools such as `send-keys` or `paste-text`. |
| `security.allow_send_keys` | `true` | Allows raw PTY input tools (`send-keys`, `send-hex`, `paste-text`, and special-key helpers). Disable this or deny `@raw-input` to prevent typing directly into panes. |
| `security.allow_capture` | `true` | Allows `capture-pane` and buffer read/write/search tools, so clients can read pane output and tmux buffers. Set to `false` to block capture and buffer tools. |
| `security.allow_list` | `true` | Allows session/window/pane/client/buffer listing and discovery tools. |
| `security.allowed_sockets` | unset | When unset, the default tmux server and any provided socket override are accepted. When set, socket overrides must exactly match one of the listed socket paths; calls without a socket still use the default socket. |
| `security.allowed_sessions` | unset | When set, operations scoped to a session/window/pane are limited to the listed tmux session IDs. |
| `security.allowed_panes` | unset | When set, direct pane operations are limited to the listed pane IDs. |
| `security.tools` | deny mode with no items | Filters the advertised and callable tool surface. Deny mode removes listed tools/groups; allow mode exposes only listed tools/groups. |
| `shell.type` / `--shell-type` | `bash` | Selects the shell used for shell-aware command wrapping (`bash`, `zsh`, or `fish`). It is not a security boundary. |
| `--socket` / `TMUX_MCP_SOCKET` | unset | Sets this server process's default tmux socket. Combine with `allowed_sockets` to keep the process on an isolated socket. |

Examples for tightening a local setup without introducing a profile system:

```toml
# Keep one agent on one isolated tmux socket.
[security]
allowed_sockets = ["/tmp/tmux-mcp-agent.sock"]
```

```toml
# Force shell input through execute-command and regex filtering.
[security]
allow_send_keys = false
command_filter = { mode = "allowlist", patterns = ["^cargo ", "^git ", "^npm (test|run )"] }

[security.tools]
mode = "deny"
items = ["@raw-input"]
```

```toml
# Read/list plus tracked command execution only; no create, split, kill, move, or raw input tools.
[security.tools]
mode = "allow"
items = ["@read", "execute-command"]
```

```toml
# Prevent clients from reading pane contents or tmux buffers.
[security]
allow_capture = false
```

### Tracking configuration (optional)
- `capture_initial_lines`: initial number of lines to capture for command output.
- `capture_max_lines`: maximum lines to capture before giving up.
- `capture_backoff_factor`: multiplier for each capture retry window.
- `completed_retention_minutes`: age threshold for evicting completed command history.
- `completed_max_entries`: max number of completed commands retained.
- `tracking_deadline_seconds`: how long a command whose START marker has scrolled out of reach (very large output) stays Pending before being declared expired. The DONE marker still completes it at any time; this only bounds genuinely-lost tracking. Raise it for high-output commands that also run long.

### Search configuration (optional)
- `streaming_threshold_bytes`: when a buffer exceeds this size, search streams a window via a temp file instead of loading the full buffer in memory.

### Tool surface configuration (optional)

Use `[security.tools]` to remove tools from `list-tools` and deny direct calls.
Entries can be exact tool names or groups prefixed with `@`.

```toml
# Disable raw PTY input while keeping execute-command available.
[security.tools]
mode = "deny"
items = ["@raw-input"]
```

```toml
# Expose only read-only context tools plus tracked command execution.
[security.tools]
mode = "allow"
items = ["@read", "execute-command"]
```

`TMUX_MCP_TOOLS` overrides `[security.tools]` for a single process. Without a
prefix it is a denylist; use `allow:` for an explicit allowlist.

```bash
TMUX_MCP_TOOLS=send-keys,paste-text tmux-mcp-rs
TMUX_MCP_TOOLS=deny:@raw-input tmux-mcp-rs
TMUX_MCP_TOOLS=allow:@read,execute-command tmux-mcp-rs
```

Known groups:

| Group | Tools |
|-------|-------|
| `@all` | Every known tool compiled into the binary |
| `@read` | Read-only/introspection tools, including list/find, capture, buffer reads, and command result reads |
| `@list` | `list-*`, `find-session`, and `get-current-session` |
| `@execute` | `execute-command`, `get-command-result` |
| `@raw-input` | All raw PTY input tools from `@interactive` and `@special-keys` |
| `@interactive` | `send-keys`, `send-hex`, `paste-text` |
| `@special-keys` | `send-enter`, arrows, page/home/end, tab, escape, backspace, cancel, EOF |
| `@capture` | `capture-pane` |
| `@buffer-read` | `list-buffers`, `show-buffer`, `search-buffer`, `subsearch-buffer` |
| `@buffer-write` | `save-buffer`, `load-buffer`, `delete-buffer`, `set-buffer`, `append-buffer`, `rename-buffer` |
| `@create` | `create-session`, `create-window` |
| `@split` | `split-pane` |
| `@rename` | `rename-session`, `rename-window`, `rename-pane` |
| `@move` | focus, resize, zoom, layout, join, break, swap, move, synchronize-panes |
| `@kill` | `kill-session`, `kill-window`, `kill-pane`, `detach-client` |
| `@socket` | `socket-for-path` |

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
- **send-keys** - Send keys to a pane (interactive only). Use `literal=true` for exact text and `enter=true` to submit in one call
- **paste-text** - Paste multi-line UTF-8 text via bracketed paste (`paste-buffer -p`); embedded newlines stay literal (no per-line submit) when the receiving program supports bracketed paste
- **send-hex** - Send raw bytes as whitespace-separated hex tokens (e.g. CSI-u `1b 5b 31 33 3b 32 75` = Shift+Enter) for escape sequences key names cannot express
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

The connection string is split with shell-word rules (quotes honored); an unbalanced quote is rejected at startup. On the remote, the server runs `ssh <args> <quoted tmux command>`, and the tmux version check applies to the remote tmux when it can be reached. SSH parsing and remote command quoting are unit-tested; end-to-end remote behavior is verified manually, not in CI (no remote host in the test environment).

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

These patterns mirror how CLI agents like Codex can structure tmux work. Each core flow is backed by an integration test in `tests/integration.rs` (run with `TMUX_MCP_INTEGRATION=1`).

- **ID-first targeting**: Use window/pane IDs for operations when names collide. Tools: list-windows/list-panes, rename-window. Test: `test_workflow_id_first_targeting`.
- **Task-per-session layout**: Create a session per task, add windows for build/test/docs, and split panes for runners/logs. Tools: create-session, create-window, split-pane, rename-pane, list-windows, list-panes. Test: `test_workflow_task_per_session_layout`.
- **Stateful shell context**: Set environment/state in a pane and reuse it across commands. Tools: send-keys, capture-pane. Test: `test_workflow_stateful_shell_context`.
- **Continuous output pane**: Run a long command and poll `capture-pane` to summarize progress without losing terminal state. Tools: send-keys, capture-pane. Test: `test_workflow_continuous_output_capture`.
- **Interactive prompt automation**: Drive a blocking prompt (or simple TUI) by sending responses via keys, then capture the result. Tools: send-keys, capture-pane. Test: `test_workflow_interactive_prompt`.
- **Interactive interrupts**: Cancel long-running commands and end stdin streams with EOF. Tools: send-cancel, send-eof, capture-pane. Test: `test_workflow_interactive_interrupts`.
- **Synchronized panes broadcast**: Fan out a command to multiple panes at once using synchronize-panes. Tools: set-synchronize-panes, send-keys, capture-pane. Test: `test_workflow_synchronized_panes_broadcast`.
- **Buffer handoff + probe**: Stash output in buffers, inspect it, save to disk, and delete when done. Tools: list-buffers, show-buffer, save-buffer, delete-buffer. Test: `test_workflow_buffer_roundtrip` (core flow).
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
- `security.tools.mode = "deny"` with no items (no tool filtering)
- `command_filter.mode = "off"` (no allow/deny patterns)
- `allowed_sockets/sessions/panes` are unset (no scoping)

**Denylist behavior:** when `command_filter.mode = "denylist"`, any regex in
`security.command_filter.patterns` that matches a command string will block that
command. This applies to `execute-command`, non-literal `send-keys`, and
`paste-text`; multi-line inputs are checked one non-empty line at a time so
anchored patterns such as `^rm ` still apply after embedded newlines. For
`send-hex`, decoded bytes are screened by the same command filter on a
best-effort basis: erase/kill line-editing control bytes are rejected outright,
but raw bytes can still encode actions a string-matching regex cannot fully
anticipate, so do not rely on the denylist as a hard boundary for raw input.
Literal `send-keys` is gated by `allow_send_keys` only; its content is not
screened. Scope raw input tools with `allowed_panes`/`allowed_sessions`, or
disable `allow_send_keys`.

Command results are socket-bound: when a command is executed, the resolved socket is recorded
and `get-command-result` must use the same socket (explicitly or via defaults), or it will be denied.

To harden a deployment, configure `[security.tools]`, add command deny/allow
patterns, or restrict sockets/sessions/panes explicitly. The older `allow_*`
flags still work as coarse group gates, but `[security.tools]` is the preferred
surface because it removes disabled tools from `list-tools`. For the strongest
guarantee that shell input cannot bypass the `command_filter`, compile without
the raw input tools (see [Hardened build](#hardened-build-compile-time-tool-removal)).

## Notes and limitations

- **Memory use is intentionally bounded only in some paths.** Paste buffers and
  command output live in
  RAM (the buffer-explorer workflow deliberately keeps large data resident for
  fast search/slicing). `paste-text`, `set-buffer`/`append-buffer`, and a single
  command's retained output can consume host memory accordingly. Tracked output
  is line-capped by `capture_max_lines`, but retained strings and individual line
  length are not byte-capped. Search streams large buffers via a temp file once
  they exceed `search.streaming_threshold_bytes`, but the buffers themselves are
  not evicted by size. Keep this in mind when pasting or capturing huge payloads.
- **tmux output is parsed as tab-delimited fields.** Sessions, windows, panes,
  clients, and buffers are read from `\t`-separated `-F` format strings. A field
  value containing a literal tab (rare, but possible in a pane title or path) can
  shift the remaining fields and produce a malformed or skipped row. This is a
  known limitation; titles/paths with embedded tabs are not supported.
- **`paste-text` newline-holding depends on the receiving program.** Content is
  wrapped in bracketed-paste markers (`ESC[200~`/`ESC[201~`), but holding embedded
  newlines (instead of submitting line by line) only works when the program at the
  pane understands those markers — zsh, bash ≥ 5.1, and most modern REPLs/editors.
  Programs without bracketed-paste support — notably **bash 3.2, the default
  `/bin/bash` on macOS** — ignore the markers, so each embedded newline acts as
  Enter and a multi-line paste executes one line at a time. Use zsh (the macOS
  login-shell default since Catalina) or a newer bash for the target pane when
  multi-line input must stay un-submitted.

## License

MIT License - see [LICENSE](LICENSE) for details.
