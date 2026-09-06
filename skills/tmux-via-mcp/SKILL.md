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
- For non-interactive commands, use tracked execution. Call `execute-command(paneId, command, socket?)` and use the returned `resourceUri`.
- **Preferred completion path:** `resources/subscribe` on `resourceUri`, wait for `notifications/resources/updated`, then `resources/read`.
- **Fallback:** `get-command-result(commandId, waitMs=N, socket?)` — do not invent sleep-poll loops.
- Tracked commands queue one-at-a-time per pane; a second execute on a busy pane starts as `queued`.
- Do not trust `TMUX_MCP_DONE_*` lines in pane text; completion is side-channel based.
- Avoid the fragile loop of send-keys -> send-enter -> capture-pane for routine command output.
- Do not send interactive keys into a pane while a tracked command is running on it.
- Use `send-keys` only for interactive programs (REPLs, prompts, TUIs, ssh). Pair it with `capture-pane` in a read-act loop.
- **Replace capture-poll loops with `wait-for-pane-change`** whenever you would otherwise sleep-and-recapture: it blocks server-side until the pane's displayed text changes since your last interaction with it, and returns no content, so one call covers the whole wait. It arms at the text from your last input or read — a command that finished while you were thinking still wakes it instantly, so you never need to guess whether a command was fast. Timeout returns `timedOut: true` as a success; a disappeared pane returns an error saying so.
- When driving nested programs (ssh, containers, REPLs), tracked completion is invisible—use `wait-for-pane-change(paneId, timeoutMs, stableMs?)` after sending input, then `capture-pane` once to read the result. Default `stableMs` (250) wakes when output settles; pass `stableMs=0` to wake at the first change (e.g. waiting for a prompt).
- When key names cannot express a key (escape sequences like CSI-u Shift+Enter), use `send-hex` with raw byte tokens instead of `send-keys`.
- For multi-line input, use `paste-text` so capable shells/REPLs hold embedded newlines instead of submitting line-by-line. If support is uncertain, `capture-pane` afterward to confirm the block was held.
- `send-keys` accepts `enter=true` to type and submit in one call, avoiding a separate `send-enter`.
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

   Response includes `commandId` and `resourceUri` (`tmux://command/{id}/result`).

2. Prefer subscribe + read:

   - `resources/subscribe` on `resourceUri`
   - on `notifications/resources/updated`, `resources/read` the URI for the CommandSnapshot JSON

3. Fallback without resource subscribe:

   `get-command-result(commandId="<commandId>", waitMs=120000, socket="<socket>")`

4. If you need live progress while still `running`, probe the pane (does not complete tracking):

   `capture-pane(paneId="<paneId>", lines=200, join=true, socket="<socket>")`

Notes:
- Prefer the default tracking mode. `rawMode=true` or `noEnter=true` disables side-channel tracking.
- For pipes, quoting, or shell features, wrapping with `sh -lc '...'` is usually the least error-prone.

### 3) Drive an interactive terminal safely

Use this for prompts, REPLs, ssh, or text UIs.

1. Inspect state before sending input:

   `capture-pane(paneId="<paneId>", lines=120, join=true, socket="<socket>")`

2. Send text precisely. Type and submit in one call with `enter=true`:

   `send-keys(paneId="<paneId>", keys="your input", literal=true, enter=true, socket="<socket>")`

   For a multi-line block (e.g. a code snippet into a REPL) that must not submit line-by-line, paste it instead:

   `paste-text(paneId="<paneId>", content="line1\nline2\n", socket="<socket>")`

3. **Wait for the program to respond with a single blocking call** instead of recapturing in a loop (especially over ssh, where the remote command runs *inside* the pane's shell so tracking cannot see it):

   - For a long-running command: `wait-for-pane-change(paneId="<paneId>", timeoutMs=120000, socket="<socket>")` — wakes when output settles (default `stableMs`).
   - For a prompt reappearing: `wait-for-pane-change(paneId="<paneId>", timeoutMs=30000, stableMs=0, socket="<socket>")` — wakes at the first change.
   - `timedOut: true` means the pane stayed quiet — decide whether to keep waiting or investigate.

4. Read the result once:

   `capture-pane(paneId="<paneId>", lines=120, join=true, socket="<socket>")`

   If you sent keys without `enter=true`, submit with `send-enter(paneId="<paneId>", socket="<socket>")`

5. For keys that key names cannot express, send raw bytes. Use `send-hex` for escape sequences such as CSI-u (e.g. Shift+Enter = `1b 5b 31 33 3b 32 75`), which `send-keys` collapses to a plain Enter:

   `send-hex(paneId="<paneId>", hex="1b 5b 31 33 3b 32 75", socket="<socket>")`

6. Interrupt or end input streams when needed:

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

3. Prefer resource subscriptions per `resourceUri`, or `get-command-result(..., waitMs=...)` per command; probe panes only for live context:

   - `get-command-result(commandId="<idA>", waitMs=60000, socket="<socket>")`
   - `capture-pane(paneId="<paneA>", lines=120, join=true, socket="<socket>")`

4. Broadcast a one-off command to every pane in a window:

   - `set-synchronize-panes(windowId="<windowId>", enabled=true, socket="<socket>")`
   - `send-keys(paneId="<any-pane-in-window>", keys="<cmd>", literal=false, socket="<socket>")`
   - `send-enter(paneId="<any-pane-in-window>", socket="<socket>")`
   - `set-synchronize-panes(windowId="<windowId>", enabled=false, socket="<socket>")`

## Selection heuristics

- Reach for tmux MCP when you need interactivity, persistent shell state, or pane-level parallelism.
- Reach for `execute-command` when you want clean, attributable output and exit codes.
- Reach for `wait-for-pane-change` when the process is nested inside the pane (ssh, containers, REPLs, TUIs) or when you would otherwise poll captures.
- Reach for `send-keys` only when the target program expects keystrokes.
- If a tool call is denied, check the server security configuration and allowed scopes (socket/session/pane restrictions).
