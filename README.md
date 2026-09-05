# tmux-mcp-rs

[![Crates.io Version](https://img.shields.io/crates/v/tmux-mcp-rs)](https://crates.io/crates/tmux-mcp-rs)
[![CI](https://img.shields.io/github/actions/workflow/status/bnomei/tmux-mcp/ci.yml?branch=main)](https://github.com/bnomei/tmux-mcp/actions/workflows/ci.yml)
[![Crates.io Downloads](https://img.shields.io/crates/d/tmux-mcp-rs)](https://crates.io/crates/tmux-mcp-rs)
[![License](https://img.shields.io/crates/l/tmux-mcp-rs)](https://crates.io/crates/tmux-mcp-rs)
[![Discord](https://flat.badgen.net/badge/discord/bnomei?color=7289da&icon=discord&label)](https://discordapp.com/users/bnomei)
[![Buymecoffee](https://flat.badgen.net/badge/icon/donate?icon=buymeacoffee&color=FF813F&label)](https://www.buymeacoffee.com/bnomei)

`tmux-mcp-rs` is a Model Context Protocol (MCP) server for tmux. It lets MCP clients create sessions, shape windows and panes, run tracked commands, inspect output, manage tmux buffers, and drive interactive terminal programs through structured tools instead of brittle screen scraping.

Use it when an agent needs a real TTY, long-running commands, parallel panes, resumable terminal state, or a tmux session that a human can attach to during the same task.

> [!WARNING]
> This server can let an MCP client run shell commands, type into panes, read terminal output, modify tmux sessions, and read or write tmux buffers. The default runtime policy is permissive. Use isolated tmux sockets and a `config.toml` policy before exposing it to a client you do not fully trust.

## Contents

- [What the server provides](#what-the-server-provides)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Client configuration](#client-configuration)
- [Configuration reference](#configuration-reference)
- [Security hardening](#security-hardening)
- [MCP tool reference](#mcp-tool-reference)
- [MCP resource reference](#mcp-resource-reference)
- [Remote and socket workflows](#remote-and-socket-workflows)
- [Agent workflow patterns](#agent-workflow-patterns)
- [Development](#development)
- [Notes and limitations](#notes-and-limitations)
- [Source anchors](#source-anchors)

## What the server provides

- Session, window, pane, client, and buffer tools with structured inputs and outputs.
- `execute-command` and `get-command-result` for shell commands with command IDs, resource URIs, status, output, and side-channel exit-code tracking (optional `waitMs`; prefer resource subscribe for completion).
- `wait-for-pane-change` for blocking on any visible pane change—inside ssh sessions, containers, REPLs, and TUIs where the side-channel tracker cannot see completion.
- Pane, window, session, client, server, and tracked-command resources for lightweight state checks without re-running tools.
- Optional raw input tools for interactive programs, prompts, REPLs, and TUIs.
- Runtime policy controls for tool filtering, command filtering, socket/session/pane scoping, and coarse operation groups.
- Compile-time feature flags that remove raw input tools from the binary for hardened builds.
- Optional SSH routing so the local MCP server can control a remote tmux server.

The MCP path is usually more reliable than a plain tmux skill because every operation has a named tool, typed parameters, stable IDs, and structured responses. Clients do not need to infer pane IDs from captured text or parse command output to determine whether a command has finished.

## Requirements

- tmux 3.0 or newer on `PATH`.
- Rust 1.70 or newer when building from source.
- A shell supported by the command tracker: `bash`, `zsh`, or `fish`.

On startup the server runs `tmux -V`. It exits when it detects tmux 2.x because tmux 2.x uses different output formats and split flags. If the version cannot be detected, startup continues and tmux errors are reported by the affected tool calls.

## Installation

### Cargo

```bash
cargo install tmux-mcp-rs
```

### Homebrew

```bash
brew install bnomei/tmux-mcp/tmux-mcp-rs
```

### npm

```bash
npx @bnomei/tmux-mcp-rs --version
# or: npm install -g @bnomei/tmux-mcp-rs
```

The npm package is a thin wrapper: on first run it downloads the matching GitHub Release binary, verifies the `.sha256`, caches it, and forwards argv.

### Docker

```bash
docker run --rm ghcr.io/bnomei/tmux-mcp:0.6.0 --version
```

The image is **self-contained**: it includes Alpine `tmux` 3.x and the prebuilt musl Linux binary. Sessions run **inside the container**, not on your desktop tmux server.

- **Default (recommended for Docker):** isolated agent sandbox. Human attach uses `docker exec` (see below).
- **Optional (Linux only):** mount a host tmux socket so the container drives a host-side server you can `tmux attach` to natively. Docker Desktop on macOS/Windows generally cannot reach host Unix sockets this way.
- For easy human/agent co-attach on a laptop, prefer Homebrew, cargo, or npm on the host instead of Docker.

stdio MCP client (keep stdin attached):

```bash
docker run --rm -i \
  --name tmux-mcp \
  -v "$PWD:/workspace" \
  ghcr.io/bnomei/tmux-mcp:0.6.0
```

Watch a session created inside the container:

```bash
docker exec -it tmux-mcp tmux attach -t workspace
```

Linux host-socket wiring (advanced):

```bash
# host: start an isolated tmux server
tmux -S /tmp/tmux-mcp-agent.sock -f /dev/null new-session -d -s workspace

# container: talk to that socket (image still needs its own tmux client)
docker run --rm -i \
  -v /tmp/tmux-mcp-agent.sock:/tmp/tmux-mcp-agent.sock \
  --user "$(id -u):$(id -g)" \
  ghcr.io/bnomei/tmux-mcp:0.6.0 \
  --socket /tmp/tmux-mcp-agent.sock

# host: attach as usual
tmux -S /tmp/tmux-mcp-agent.sock attach -t workspace
```

Match container UID/GID to the socket owner when permissions fail. More detail: [packaging/README.md](packaging/README.md#docker-image).

### GitHub Releases

Download a prebuilt archive from [GitHub Releases](https://github.com/bnomei/tmux-mcp/releases), extract it, and place `tmux-mcp-rs` on your `PATH`.

### From source

```bash
git clone https://github.com/bnomei/tmux-mcp.git
cd tmux-mcp
cargo build --release
```

The binary is written to `target/release/tmux-mcp-rs`.

### Verify the install

```bash
tmux -V
tmux-mcp-rs --version
```

Expected output:

```txt
tmux 3.x
tmux-mcp-rs <version>
```
## Quick start

1. Add the server to your MCP client.

   Codex CLI:

   ```bash
   codex mcp add tmux -- tmux-mcp-rs
   ```

   Claude Code:

   ```bash
   claude mcp add --transport stdio tmux -- tmux-mcp-rs
   ```

   Generic MCP client configuration:

   ```json
   {
     "mcpServers": {
       "tmux": {
         "command": "tmux-mcp-rs"
       }
     }
   }
   ```

2. In your MCP client, ask the agent to create or list tmux sessions.

   A typical first task is:

   ```txt
   Create a tmux session named workspace, list its windows and panes, then run pwd in the first pane.
   ```

   The tool responses should include a session ID, window ID, pane ID, and a `commandId` for the tracked command.

3. Attach to the same tmux session if you want to watch or participate.

   ```bash
   tmux attach -t workspace
   ```

For safer multi-agent work, start with an isolated socket instead of the default tmux server:

```bash
tmux -S /tmp/tmux-mcp-agent.sock -f /dev/null new-session -d -s workspace
tmux -S /tmp/tmux-mcp-agent.sock attach -t workspace
```

Then configure the MCP server with `--socket /tmp/tmux-mcp-agent.sock`, `TMUX_MCP_SOCKET=/tmp/tmux-mcp-agent.sock`, or a per-tool `socket` override.

## Client configuration

Use `args` when your MCP client accepts JSON configuration:

```json
{
  "mcpServers": {
    "tmux": {
      "command": "tmux-mcp-rs",
      "args": [
        "--shell-type",
        "zsh",
        "--socket",
        "/tmp/tmux-mcp-agent.sock",
        "--config",
        "/path/to/config.toml"
      ]
    }
  }
}
```

For a remote tmux server, add `--ssh`:

```json
{
  "mcpServers": {
    "tmux": {
      "command": "tmux-mcp-rs",
      "args": [
        "--ssh",
        "user@host",
        "--socket",
        "/tmp/tmux-mcp-agent.sock"
      ]
    }
  }
}
```

Every MCP tool except `socket-for-path` accepts an optional `socket` parameter. If a tool omits it, the server uses the process default socket.

## Configuration reference

`tmux-mcp-rs` does not auto-load a config file. Pass one with `--config /path/to/config.toml`.

### CLI options

| Option | Default | Description |
| --- | --- | --- |
| `--shell-type <SHELL>` | `bash` | Shell used for shell-aware command tracking. Supported values: `bash`, `zsh`, `fish`. If `[shell].type` exists in the config file, the config value wins. |
| `--config <PATH>` | unset | TOML configuration file to read. Invalid TOML, invalid regexes, and unknown tools or groups fail startup. |
| `--socket <PATH>` | tmux default socket | Sets `TMUX_MCP_SOCKET` for this server process. A per-tool `socket` parameter still wins for that call. |
| `--ssh <CONNECTION>` | unset | Routes tmux commands through SSH. This value wins over `[ssh].remote` and `TMUX_MCP_SSH`. |
| `--help` | n/a | Prints CLI help. |
| `--version` | n/a | Prints the binary version. |

### Environment variables

| Variable | Description |
| --- | --- |
| `TMUX_MCP_SOCKET` | Default tmux socket path when no per-tool `socket` override is provided. If unset, the server uses tmux's default socket path: `$TMUX_TMPDIR/tmux-$UID/default`, or `/tmp/tmux-$UID/default` when `TMUX_TMPDIR` is unset. |
| `TMUX_MCP_SSH` | SSH connection string used when `--ssh` and `[ssh].remote` are unset. The string is parsed with shell-word rules. Unbalanced quotes fail startup. |
| `TMUX_MCP_TOOLS` | Per-process override for `[security.tools]`. Use `allow:<items>` or `deny:<items>`. Without a prefix, the value is treated as a denylist. |
| `RUST_LOG` | Enables tracing output through `tracing-subscriber` when set. Logs are written to stderr. |

Precedence rules:

| Setting | Precedence |
| --- | --- |
| Socket | Per-tool `socket` parameter, then `--socket` or `TMUX_MCP_SOCKET`, then tmux default socket path. |
| SSH | `--ssh`, then `[ssh].remote`, then `TMUX_MCP_SSH`, then no SSH. |
| Shell type | `[shell].type`, then `--shell-type`, then `bash`. |
| Tool filter | `TMUX_MCP_TOOLS`, then `[security.tools]`, then deny mode with no denied items. |

### Example config

```toml
[shell]
type = "zsh"

[ssh]
remote = "user@host"

[security]
enabled = true
allow_execute_command = true
allow_raw_mode = true
allow_send_keys = false
allow_kill = true
allow_create = true
allow_split = true
allow_rename = true
allow_move = true
allow_capture = true
allow_list = true
allowed_sockets = ["/tmp/tmux-mcp-agent.sock"]
allowed_sessions = ["workspace"]
allowed_panes = ["%1"]
allowed_buffer_paths = ["/srv/tmux-mcp-buffers"]

[security.command_filter]
mode = "allowlist"
patterns = ["^cargo ", "^git ", "^rg ", "^sed "]

[security.tools]
mode = "deny"
items = ["@raw-input"]

[tracking]
capture_initial_lines = 1000
capture_max_lines = 16000
completed_retention_minutes = 240
completed_max_entries = 1000
tracking_deadline_seconds = 600

[search]
streaming_threshold_bytes = 262144

[watch]
poll_interval_ms = 300
stable_ms = 250
timeout_default_ms = 30000
timeout_max_ms = 600000
```

### Security options

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `security.enabled` | boolean | `true` | Enables policy checks. Set to `false` only when you want to bypass every policy check. |
| `security.allow_execute_command` | boolean | `true` | Allows `execute-command` and `get-command-result`. |
| `security.allow_raw_mode` | boolean | `true` | Allows `execute-command` with `rawMode=true`, which sends the command without tracking markers. |
| `security.allow_send_keys` | boolean | `true` | Allows raw input tools: `send-keys`, `send-hex`, `paste-text`, and special-key helpers. |
| `security.allow_kill` | boolean | `true` | Allows `kill-session`, `kill-window`, `kill-pane`, and `detach-client`. |
| `security.allow_create` | boolean | `true` | Allows `create-session` and `create-window`. |
| `security.allow_split` | boolean | `true` | Allows `split-pane`. |
| `security.allow_rename` | boolean | `true` | Allows session, window, and pane rename tools. |
| `security.allow_move` | boolean | `true` | Allows focus, resize, zoom, layout, join, break, swap, move, and synchronize-panes tools. |
| `security.allow_capture` | boolean | `true` | Allows `capture-pane`, `wait-for-pane-change`, and tmux buffer read, write, and search tools. Buffer file operations are part of this capture surface. |
| `security.allow_list` | boolean | `true` | Allows session, window, pane, client, buffer, and current-session listing tools. |
| `security.allowed_sockets` | string array or unset | unset | When set, the effective socket for every tool and resource request must exactly match one of these paths. |
| `security.allowed_sessions` | string array or unset | unset | When set, session-scoped operations are limited to exact tmux session IDs or names in the list. |
| `security.allowed_panes` | string array or unset | unset | When set, direct pane operations are limited to the listed pane IDs. |
| `security.allowed_buffer_paths` | string array or unset | unset | Canonical directories allowed for `save-buffer` and `load-buffer`. When unset, paths must be relative and stay under the local temp directory's `tmux-mcp-buffers/` directory, or `/tmp/tmux-mcp-buffers/` over SSH. An empty list denies all buffer file paths. |
| `security.command_filter.mode` | `off`, `allowlist`, `denylist` | `off` | Regex command filter mode. |
| `security.command_filter.patterns` | string array | `[]` | Regex patterns used by the command filter. |
| `security.tools.mode` | `deny`, `allow` | `deny` | Runtime tool-surface filter mode. |
| `security.tools.items` | string array | `[]` | Exact tool names or groups such as `@raw-input`. |

`security.command_filter` checks each non-empty shell statement for `execute-command`, `send-keys` (literal and non-literal), `paste-text`, `set-buffer`, `append-buffer`, and the decoded bytes passed to `send-hex`. It splits unquoted `;`, `|`, `&`, and newlines, then recursively checks command substitutions, process substitutions, subshells, and brace groups. It rejects shell forms it cannot safely analyze, including ANSI-C `$'...'` quoting and shell `-c` wrappers. It does not screen special-key helpers. For a hard boundary, disable raw input tools at runtime or compile them out.

### Tracking options

| Key | Default | Description |
| --- | --- | --- |
| `tracking.capture_initial_lines` | `1000` | Pane lines captured when refreshing partial output for a running command. |
| `tracking.capture_max_lines` | `16000` | Maximum pane lines captured when extracting final output between the human-visible START/DONE markers. |
| `tracking.capture_backoff_factor` | `2` | Accepted for configuration compatibility. Side-channel completion no longer uses capture backoff. |
| `tracking.completed_retention_minutes` | `240` | Age limit for completed command history retained in memory. |
| `tracking.completed_max_entries` | `1000` | Maximum completed command entries retained in memory. Set to `0` to disable entry-count pruning and rely on retention time only. |
| `tracking.tracking_deadline_seconds` | `600` | How long the side-channel watcher waits for `tmux wait-for` before marking `tracking_error`. |

### Search options

| Key | Default | Description |
| --- | --- | --- |
| `search.streaming_threshold_bytes` | `262144` | Buffer size threshold where search streams through a temp file instead of loading the full buffer text into one string for the search pass. |

### Watch options

Options for `wait-for-pane-change`, the blocking pane watcher.

| Key | Default | Description |
| --- | --- | --- |
| `watch.poll_interval_ms` | `300` over a local socket, `800` when `TMUX_MCP_SSH` is set | Milliseconds between polls of the pane's visible screen. Over SSH each poll is a full ssh exec, hence the longer interval. |
| `watch.stable_ms` | `250` | Default `stableMs` debounce window: the wake fires once the screen has been stable this long. `0` in a tool call wakes at the first change. |
| `watch.timeout_default_ms` | `30000` | Default `timeoutMs` when the caller omits it. |
| `watch.timeout_max_ms` | `600000` | Ceiling for caller-supplied `timeoutMs`. Larger requests are rejected with an error naming the ceiling, not silently clamped. |

## Security hardening

By default, policy enforcement is enabled but permissive:

- All coarse `allow_*` gates are `true`.
- `command_filter.mode` is `off`.
- `allowed_sockets`, `allowed_sessions`, `allowed_panes`, and `allowed_buffer_paths` are unset. Buffer file operations remain restricted to the default temp-directory sandbox.
- `[security.tools]` is deny mode with no denied items.

That default is convenient for local experimentation, but it is not a sandbox.

### Use an isolated tmux socket

```bash
tmux -S /tmp/tmux-mcp-agent.sock -f /dev/null new-session -d -s workspace
tmux-mcp-rs --socket /tmp/tmux-mcp-agent.sock --config config.toml
```

```toml
[security]
allowed_sockets = ["/tmp/tmux-mcp-agent.sock"]
```

When `allowed_sockets` is set, calls without an explicit socket still resolve to the process default socket and must match the allowlist.

### Remove raw input at runtime

```toml
[security]
allow_send_keys = false

[security.tools]
mode = "deny"
items = ["@raw-input"]
```

Use this when shell input should go through `execute-command` so command filtering and command-result tracking remain central.

### Expose only read tools and tracked command execution

```toml
[security.tools]
mode = "allow"
items = ["@read", "execute-command"]
```

`@read` includes `get-command-result`, listing tools, capture tools, buffer read/search tools, and `socket-for-path`.

### Override the tool surface for one process

```bash
TMUX_MCP_TOOLS=send-keys,paste-text tmux-mcp-rs
TMUX_MCP_TOOLS=deny:@raw-input tmux-mcp-rs
TMUX_MCP_TOOLS=allow:@read,execute-command tmux-mcp-rs
```

### Compile out raw input tools

The default Cargo feature set includes `interactive` and `special-keys`.

- `interactive` registers `send-keys`, `send-hex`, and `paste-text`.
- `special-keys` registers `send-cancel`, `send-eof`, `send-escape`, `send-enter`, `send-tab`, `send-backspace`, `send-up`, `send-down`, `send-left`, `send-right`, `send-page-up`, `send-page-down`, `send-home`, and `send-end`.

Disable those features to remove the tools from the binary:

```bash
# Filtered-only build: execute-command is the only shell-input path.
cargo build --release --no-default-features --features rayon,rapidfuzz

# Keep raw keystrokes but remove special-key helpers.
cargo build --release --no-default-features --features rayon,rapidfuzz,interactive
```

`execute-command` is always registered and remains subject to `security.command_filter`.

## MCP tool reference

Tool availability depends on Cargo features and runtime policy. Runtime-denied tools are removed from the advertised MCP tool list and denied when called.

### Tool groups

| Group | Tools |
| --- | --- |
| `@all` | Every known tool compiled into the binary. |
| `@read` | `socket-for-path`, list/find tools, `capture-pane`, `wait-for-pane-change`, buffer read/search tools, and `get-command-result`. |
| `@socket` | `socket-for-path`. |
| `@list` | `list-sessions`, `find-session`, `list-windows`, `list-panes`, `list-clients`, `list-buffers`, `get-current-session`. |
| `@execute` | `execute-command`, `get-command-result`. |
| `@capture` | `capture-pane`, `wait-for-pane-change`. |
| `@buffer-read` | `list-buffers`, `show-buffer`, `search-buffer`, `subsearch-buffer`. |
| `@buffer-write` | `save-buffer`, `load-buffer`, `delete-buffer`, `set-buffer`, `append-buffer`, `rename-buffer`. |
| `@create` | `create-session`, `create-window`. |
| `@split` | `split-pane`. |
| `@rename` | `rename-session`, `rename-window`, `rename-pane`. |
| `@move` | `move-window`, `select-window`, `select-pane`, `resize-pane`, `zoom-pane`, `select-layout`, `join-pane`, `break-pane`, `swap-pane`, `set-synchronize-panes`. |
| `@kill` | `kill-session`, `kill-window`, `kill-pane`, `detach-client`. |
| `@interactive` | `send-keys`, `send-hex`, `paste-text`. |
| `@special-keys` | `send-cancel`, `send-eof`, `send-escape`, `send-enter`, `send-tab`, `send-backspace`, `send-up`, `send-down`, `send-left`, `send-right`, `send-page-up`, `send-page-down`, `send-home`, `send-end`. |
| `@raw-input` | All `@interactive` and `@special-keys` tools. |

### Tools by task

| Task | Tools |
| --- | --- |
| Socket utility | `socket-for-path` derives a deterministic `/tmp/<hash>.sock` path from a project path. |
| Session management | `list-sessions`, `find-session`, `create-session`, `kill-session`, `get-current-session`, `rename-session`. |
| Window management | `list-windows`, `create-window`, `kill-window`, `rename-window`, `move-window`, `select-window`, `select-layout`, `set-synchronize-panes`. |
| Pane management | `list-panes`, `split-pane`, `kill-pane`, `rename-pane`, `capture-pane`, `wait-for-pane-change`, `select-pane`, `resize-pane`, `zoom-pane`, `join-pane`, `break-pane`, `swap-pane`. |
| Command execution | `execute-command` returns `commandId` + `resourceUri`; prefer `resources/subscribe` then read on `resources/updated`, or `get-command-result` with `waitMs`. |
| Client management | `list-clients`, `detach-client`. |
| Buffer inspection | `list-buffers`, `show-buffer`, `search-buffer`, `subsearch-buffer`. |
| Buffer mutation | `save-buffer`, `load-buffer`, `delete-buffer`, `set-buffer`, `append-buffer`, `rename-buffer`. |
| Raw input | `send-keys`, `paste-text`, `send-hex`, `send-cancel`, `send-eof`, `send-escape`, `send-enter`, `send-tab`, `send-backspace`, `send-up`, `send-down`, `send-left`, `send-right`, `send-page-up`, `send-page-down`, `send-home`, `send-end`. |

Prefer `execute-command` with resource subscribe/read (or `get-command-result` + `waitMs`) for non-interactive commands. Tracked commands queue per pane. Use `capture-pane` for live progress only; do not treat pane DONE markers as authoritative. Use raw input tools only for prompts, REPLs, editors, pagers, and TUIs—and not while a tracked command is running on that pane.

### Waiting for nested or interactive output

`wait-for-pane-change` blocks server-side until the pane's displayed text changes, then returns so the caller can `capture-pane` on its own decision. Use it instead of poll loops when the interesting process is *nested*—ssh sessions, containers, REPLs, editors, test watchers—because the side-channel tracker that powers `execute-command` only sees the pane's shell, not the program inside it.

- The wake predicate is byte-exact visible-screen comparison, mirroring `capture-pane` targeting (`paneId`, same scope). No content is returned; capture afterwards to see what changed.
- Timeout is a **success** result with `timedOut: true`—a quiet pane is not an error.
- Any tmux error aborts the wait: a pane that disappeared returns an error stating the pane is gone.
- `timeoutMs` values above `[watch]` `timeout_max_ms` (default 600 s) are rejected with an error naming the ceiling.
- `stableMs` (default 250 ms) debounces bursts: the wake fires once output settles. Pass `stableMs: 0` to wake at the first change—for example, when waiting for a prompt to reappear.
- Changes in other panes, cursor-only motion, copy-mode scrolling, and title changes do not wake the watcher: only the watched pane's displayed text matters.

Typical flow when driving an ssh session:

1. `send-keys` the remote command into the pane.
2. `wait-for-pane-change` on that pane with a `timeoutMs` that covers the expected runtime.
3. On wake (or timeout), `capture-pane` to read the result.

One tool call replaces every iteration of "capture, inspect, decide, sleep" in that loop.

Tracked command snapshots use `schemaVersion: 1` and currently move through `queued`, `running`, then `completed`, `failed`, or `tracking_error`. The schema also reserves `cancelled`, but the current tracker does not emit it. Normal tracked commands reject embedded newlines, unquoted shell comment markers (`#`), and unquoted background operators (`&`) because those forms can bypass the tracking epilogue. Set `rawMode=true` or `noEnter=true` only when you intentionally want to disable side-channel completion tracking; those records remain `running`.

`show-buffer` reads at most 65,536 bytes by default. `search-buffer` defaults to 40 context bytes, 50 matches, and 65,536 scanned bytes per buffer; it returns byte offsets and resume cursors when results are truncated. Literal and regex search are always available. Fuzzy matching and similarity scores require the `rapidfuzz` Cargo feature, which is enabled by default.

## MCP resource reference

Server, pane, window, session, and client resources reflect the server's default socket. Tracked-command resources retain the effective socket recorded by their originating `execute-command`, including per-tool socket overrides. Resources are dynamically enumerated and filtered by the current security policy.

Only tracked-command result resources support `resources/subscribe`; read the resource after a `notifications/resources/updated` event. Other resource URIs provide on-demand snapshots.

| URI | Description |
| --- | --- |
| `tmux://server/info` | JSON with default socket and SSH context. |
| `tmux://pane/{paneId}` | Last 200 lines from a pane as plain text. |
| `tmux://pane/{paneId}/info` | Pane metadata as JSON. |
| `tmux://pane/{paneId}/tail/{lines}` | Tail N lines from a pane as plain text. |
| `tmux://pane/{paneId}/tail/{lines}/ansi` | Tail N lines from a pane with ANSI colors. |
| `tmux://window/{windowId}/info` | Window metadata as JSON. |
| `tmux://session/{sessionId}/tree` | Session, window, and pane snapshot as JSON. |
| `tmux://clients` | tmux clients as JSON. |
| `tmux://command/{commandId}/result` | Tracked command status and output. |

## Remote and socket workflows

### Remote SSH

Use `--ssh` to run tmux commands on another machine. SSH authentication must be non-interactive, such as an agent or key-based login.

```bash
tmux-mcp-rs --ssh "user@host"
```

Pass SSH options before the destination:

```bash
tmux-mcp-rs --ssh "-i ~/.ssh/key user@host"
```

The connection string is split with shell-word rules. The destination should be the last token. The server quotes the remote tmux command before sending it to SSH, and the tmux version check applies to the remote tmux when it can be reached.

### Remote plus isolated socket

Create a dedicated tmux server on the remote host:

```bash
ssh user@host 'tmux -S /tmp/tmux-mcp-agent.sock -f /dev/null new-session -d -s workspace'
```

Start the local MCP server against that remote socket:

```bash
tmux-mcp-rs --ssh "user@host" --socket /tmp/tmux-mcp-agent.sock
```

Attach directly from a shell when needed:

```bash
ssh -t user@host 'tmux -S /tmp/tmux-mcp-agent.sock attach -t workspace'
```

### Socket isolation

Use `--socket` or `TMUX_MCP_SOCKET` to keep one agent on one tmux server:

```bash
tmux-mcp-rs --socket /tmp/tmux-mcp-agent.sock
```

```bash
TMUX_MCP_SOCKET=/tmp/tmux-mcp-agent.sock tmux-mcp-rs
```

Pre-create the session when you want a human-visible workspace before the MCP client starts:

```bash
tmux -S /tmp/tmux-mcp-agent.sock -f /dev/null new-session -d -s workspace
TMUX_MCP_SOCKET=/tmp/tmux-mcp-agent.sock tmux-mcp-rs
```

### Docker and sockets

The GHCR image includes tmux 3.x and defaults to **self-contained** sessions inside the container (`docker exec … tmux attach`). On Linux only, you can instead mount a host socket so the container MCP server drives a host tmux server—see [Installation → Docker](#docker) and [packaging/README.md](packaging/README.md#docker-image). Docker Desktop on macOS/Windows is not a reliable host-socket path; use a native install when you need easy local co-attach.

## Agent workflow patterns

The integration tests cover these tmux workflows:

| Pattern | Tool surface |
| --- | --- |
| ID-first targeting | `list-windows`, `list-panes`, `rename-window`. |
| Task-per-session layout | `create-session`, `create-window`, `split-pane`, `rename-pane`, list tools. |
| Stateful shell context | `send-keys`, `capture-pane`. |
| Continuous output pane | `send-keys`, `capture-pane`, `wait-for-pane-change`. |
| Interactive prompt automation | `send-keys`, `wait-for-pane-change`, `capture-pane`. |
| Interactive interrupts | `send-cancel`, `send-eof`, `capture-pane`. |
| Synchronized panes broadcast | `set-synchronize-panes`, `send-keys`, `capture-pane`. |
| Buffer handoff and search | `list-buffers`, `show-buffer`, `save-buffer`, `delete-buffer`, `search-buffer`, `subsearch-buffer`. |
| Pane rearrangements | `split-pane`, `select-layout`, `swap-pane`, `break-pane`, `join-pane`. |
| Metadata and zoom | Rename tools, `zoom-pane`, `resize-pane`, pane/window resources. |
| Audit-ready context bundle | `execute-command`, `get-command-result`, `capture-pane`. |
| Nested ssh/container/REPL output | `send-keys`, `wait-for-pane-change`, `capture-pane`. |
| Agent orchestration | `create-window`, `split-pane`, `execute-command`, `send-keys`, `wait-for-pane-change`, `capture-pane`. |

For agent-facing tmux workflows, see:

- [tmux-via-mcp](skills/tmux-via-mcp/SKILL.md)
- [tmux-buffer-explorer](skills/tmux-buffer-explorer/SKILL.md)

`tmux-buffer-explorer` uses tmux buffers as an external search space for large text. It is useful when an agent needs bounded search and follow-up slices instead of loading a whole buffer into context.

## Development

Build the binary:

```bash
cargo build --release
```

Run unit tests that do not require tmux:

```bash
cargo test --lib
cargo test --test cli
cargo test --test search
```

Run tmux-backed integration tests:

```bash
TMUX_MCP_INTEGRATION=1 cargo test --test integration
```

Integration tests create isolated tmux servers using temporary sockets and clean them up afterward.

Run the same Rust checks as CI:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

Release notes and release packaging details live in [CHANGELOG.md](CHANGELOG.md) and [docs/RELEASE.md](docs/RELEASE.md).

## Notes and limitations

- tmux owns paste buffers, while this server retains tracked command snapshots in memory. `paste-text`, `set-buffer`, `append-buffer`, and large retained command outputs can still consume host memory. Tracked output is line-capped by `capture_max_lines`, but retained strings and individual line length are not byte-capped.
- Buffer search streams large buffers through a temp file after `search.streaming_threshold_bytes`, but tmux buffers themselves are not evicted by size.
- tmux rows are parsed from tab-delimited `-F` output. A literal tab inside a pane title, path, or similar field can shift later fields and produce malformed or skipped rows.
- `paste-text` uses bracketed paste markers. Shells and programs that do not support bracketed paste may treat embedded newlines as Enter. On macOS, the default `/bin/bash` 3.2 does not support modern bracketed paste behavior; zsh or a newer bash is safer for multi-line input that should not submit line by line.
- `save-buffer` writes to the tmux server filesystem, and `load-buffer` reads from it. Both are governed by `allow_capture`, `[security.tools]`, and `security.allowed_buffer_paths`. With the default enabled policy, callers use relative paths inside the local temp directory's `tmux-mcp-buffers/` sandbox or `/tmp/tmux-mcp-buffers/` over SSH; parent traversal and canonical or symlink escapes are rejected.
- Command results are socket-bound. `get-command-result` must use the same effective socket as the original `execute-command` call.
- Tracked command completion uses a private tmux exit buffer + `wait-for` signal, not forgeable pane scrollback. Optional START/DONE lines are for humans/debug only.
- Interactive `send-keys`/`paste-text` during a tracked run on the same pane is undefined; wait for the command to finish or use another pane.
- `wait-for-pane-change` polls the visible screen at `[watch]` `poll_interval_ms`, so wake latency is bounded by that interval (300 ms local, 800 ms over SSH by default). It watches the pane's displayed text only: cursor motion, title changes, copy-mode scrolling, and changes in other panes do not wake it. An identical frame from a TUI (for example an idle status screen) is indistinguishable from a quiet pane.
- End-to-end SSH behavior is manually verified because CI does not provide a remote host.

## Source anchors

- CLI parsing and startup behavior: [src/main.rs](src/main.rs)
- MCP tools, resources, and server instructions: [src/server.rs](src/server.rs)
- Security policy and tool groups: [src/security.rs](src/security.rs)
- Command tracking: [src/commands.rs](src/commands.rs)
- tmux socket, SSH, and process wrapper behavior: [src/tmux.rs](src/tmux.rs)
- Blocking pane watcher: [src/watch.rs](src/watch.rs)
- Public data types: [src/types.rs](src/types.rs)
- CLI tests: [tests/cli.rs](tests/cli.rs)
- Integration workflows: [tests/integration.rs](tests/integration.rs)
- Buffer search tests: [tests/search.rs](tests/search.rs)

## License

MIT License. See [LICENSE](LICENSE).
