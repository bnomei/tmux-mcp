---
name: tmux-via-mcp
description: Use the tmux MCP tools to create sessions, shape layouts, run tracked commands, and automate interactive terminals when a real TTY or parallel panes are required.
---

# tmux via MCP

Use this skill when a task needs a real TTY, persistent shell state, or multiple panes running in parallel. For simple, one-shot commands, prefer the normal shell tool.

## Core operating rules

- Start with discovery. Call `list-sessions`, then `list-windows(sessionId)`, then `list-panes(windowId)` to get stable IDs before you act.
- Prefer IDs over names. Names are for humans; IDs are for tooling. If you need clarity, use `rename-session`, `rename-window`, or `rename-pane`.
- Isolate by socket when possible. Use `socket-for-path(path=<project-root>)` and pass the returned `socket` on every call that supports it.
- For non-interactive commands, use tracked execution. Call `execute-command(paneId, command, socket?)`, then poll `get-command-result(commandId, socket?)`.
- Avoid the fragile loop of send-keys -> send-enter -> capture-pane for routine command output. Use `execute-command` + `get-command-result` instead.
- Use `send-keys` only for interactive programs (REPLs, prompts, TUIs, ssh). Pair it with `capture-pane` in a read-act loop.
- Treat `capture-pane` as a state probe. Use it to check progress, verify prompts, or read live output when tracking is unavailable.
- Broadcast carefully. If you enable `set-synchronize-panes(windowId, enabled=true)`, disable it as soon as the fan-out step is done.
- For large outputs, move data into buffers and explore incrementally. Use `set-buffer`/`load-buffer` with `search-buffer` and `subsearch-buffer`, or trigger the `tmux-buffer-explorer` skill.
- Be conservative with destructive actions. Use `list-clients` before `detach-client`, and confirm targets before `kill-pane`, `kill-window`, or `kill-session`.

## Playbooks

### 1) Create an isolated workspace layout

Use this when you are about to run multiple related commands or agents.

1. Derive a deterministic socket for the project:

   `socket-for-path(path="/abs/path/to/project")`

2. Create a task-scoped session:

   `create-session(name="task-<short>", socket="<socket>")`

3. Add windows and shape panes:

   - `create-window(sessionId="<sessionId>", name="build", socket="<socket>")`
   - `split-pane(paneId="<paneId>", direction="vertical", socket="<socket>")`
   - `select-layout(windowId="<windowId>", layout="tiled", socket="<socket>")`
   - `rename-pane(paneId="<paneId>", title="logs", socket="<socket>")`

4. Re-list panes and capture IDs you will use:

   `list-panes(windowId="<windowId>", socket="<socket>")`

### 2) Run a command with reliable output capture

Use this for builds, tests, and scripts that do not require interactivity.

1. Start the command:

   `execute-command(paneId="<paneId>", command="sh -lc '<cmd>'", socket="<socket>")`

2. Poll for completion and collect the result:

   `get-command-result(commandId="<commandId>", socket="<socket>")`

3. If you need live progress while the command is still pending, probe the pane:

   `capture-pane(paneId="<paneId>", lines=200, join=true, socket="<socket>")`

Notes:
- Prefer the default tracking mode. `rawMode=true` or `noEnter=true` disables marker-based tracking.
- For pipes, quoting, or shell features, wrapping with `sh -lc '...'` is usually the least error-prone.

### 3) Drive an interactive terminal safely

Use this for prompts, REPLs, ssh, or text UIs.

1. Inspect state before sending input:

   `capture-pane(paneId="<paneId>", lines=120, join=true, socket="<socket>")`

2. Send text precisely:

   `send-keys(paneId="<paneId>", keys="your input", literal=true, socket="<socket>")`

3. Confirm the action:

   - `send-enter(paneId="<paneId>", socket="<socket>")`
   - `capture-pane(paneId="<paneId>", lines=120, join=true, socket="<socket>")`

4. Interrupt or end input streams when needed:

   - `send-cancel(paneId="<paneId>", socket="<socket>")`
   - `send-eof(paneId="<paneId>", socket="<socket>")`

### 4) Coordinate parallel panes or agents

Use this when you need multiple concurrent runners with periodic summaries.

1. Create a window, split panes, and label them:

   - `create-window(sessionId="<sessionId>", name="orchestrate", socket="<socket>")`
   - `split-pane(paneId="<paneId>", direction="horizontal", socket="<socket>")`
   - `rename-pane(paneId="<paneId>", title="agent-1", socket="<socket>")`
   - `rename-pane(paneId="<paneId>", title="agent-2", socket="<socket>")`

2. Launch work in each pane:

   - `execute-command(paneId="<paneA>", command="sh -lc '<cmdA>'", socket="<socket>")`
   - `execute-command(paneId="<paneB>", command="sh -lc '<cmdB>'", socket="<socket>")`

3. Poll tracked commands first, then probe panes for live context:

   - `get-command-result(commandId="<idA>", socket="<socket>")`
   - `capture-pane(paneId="<paneA>", lines=120, join=true, socket="<socket>")`

4. Broadcast a one-off command to every pane in a window:

   - `set-synchronize-panes(windowId="<windowId>", enabled=true, socket="<socket>")`
   - `send-keys(paneId="<any-pane-in-window>", keys="<cmd>", literal=false, socket="<socket>")`
   - `send-enter(paneId="<any-pane-in-window>", socket="<socket>")`
   - `set-synchronize-panes(windowId="<windowId>", enabled=false, socket="<socket>")`

## Selection heuristics

- Reach for tmux MCP when you need interactivity, persistent shell state, or pane-level parallelism.
- Reach for `execute-command` when you want clean, attributable output and exit codes.
- Reach for `send-keys` only when the target program expects keystrokes.
- If a tool call is denied, check the server security configuration and allowed scopes (socket/session/pane restrictions).
