# Design

## Overview
Add tmux-native buffer primitives using the existing tool naming convention (kebab-case). Keep all content in tmux buffers, cap outputs by default, and avoid any orchestration logic inside the server.

## Modules and ownership
- `src/tmux.rs`: extend with async tmux command execution (stdout/stderr capture) and a semaphore for bounded concurrency.
- `src/server.rs`: tool schemas + handlers for new buffer tools, delegating to tmux helpers.
- `src/security.rs`: allowlist updates for new tool names.

## Tool mapping and compatibility
- Preserve existing tools (`list-buffers`, `show-buffer`, `save-buffer`, `delete-buffer`) for compatibility.
- Add new tools following the current naming convention: `set-buffer`, `append-buffer`, `rename-buffer`, `search-buffer`, `subsearch-buffer`.
- Prefer small adapters rather than duplicating logic (e.g., `list-buffers` and `show-buffer` reuse shared parsing/slicing helpers).

## Buffer parsing and encoding
- Use `tmux list-buffers -F` with a stable format and derive `order_index` from row order.
- Use `tmux show-buffer -b <name>` and apply slicing in Rust (`offset_bytes`, `max_bytes`).
- Show-buffer returns plain text (lossy if needed). Search/subsearch validate UTF-8 and error if invalid.

## Search/subsearch response shape
- Return structured JSON with echoed inputs (`query`, `mode`, `context_bytes`, `max_matches`, resolved `buffers`), aggregate metadata (`total_matches`, `buffers_scanned`, `bytes_scanned_total`), and `matches` entries with offsets and snippets.
- Include pagination metadata (`truncated_buffers`, `resume_from_offset`) when scanning or match limits are hit.
- If `include_similarity=true`, add a `similarity` score per match and aggregate `max_similarity`/`avg_similarity`.

## Subsearch scope
- Subsearch uses an explicit anchor supplied by the caller: `buffer`, `offset_bytes`, `match_len`, plus `context_bytes` to derive the scan window; the server remains stateless.

## Append strategy
- Default: read (bounded) + concat + set.
- If the existing buffer is large or concatenation exceeds a threshold, fall back to `load-buffer` from a temp file (written via `tempfile`).

## Concurrency and limits
- tmux semaphore (default 8) wraps all tmux calls.
- Defaults are constants; optionally allow env override in the future.

## Error mapping
- Map tmux failures to MCP tool errors with concise messages.

## Sequence sketches
Buffer show:
1) Handler -> tmux::show_buffer (or helper)
2) tmux::show_buffer -> tmux command execution
3) Slice + encode -> response

Subsearch:
1) Handler -> show buffer content
2) Apply search mode and scope constraints
3) Return bounded snippets + offsets
