# Tmux Buffer Foundation Requirements

System: tmux-mcp server

## Buffer tools (existing naming convention)
- WHEN list-buffers is called THE SYSTEM SHALL invoke `tmux list-buffers` and return an array of objects with `name`, `size_bytes`, and `order_index`.
- WHEN show-buffer is called THE SYSTEM SHALL return a slice of the buffer content bounded by `offset_bytes` and `max_bytes` (default 65536).
- WHEN show-buffer is called THE SYSTEM SHALL enforce bounds on raw bytes before decoding to text.
- WHEN show-buffer is called THE SYSTEM SHALL return plain text; invalid UTF-8 bytes may be replaced.
- WHEN set-buffer is called THE SYSTEM SHALL create or replace the tmux buffer with the provided content.
- WHEN append-buffer is called THE SYSTEM SHALL append the provided content to the existing buffer content and persist the result back to tmux.
- WHEN delete-buffer is called THE SYSTEM SHALL delete the named buffer via `tmux delete-buffer`.
- WHEN rename-buffer is called THE SYSTEM SHALL emulate rename by reading the source buffer, writing the destination buffer, and deleting the source buffer.
- WHEN search-buffer is called THE SYSTEM SHALL require UTF-8 buffer content, then search the selected buffers using literal or regex mode and return structured JSON with echoed inputs, match offsets, bounded context snippets, and aggregate metadata.
- WHEN search-buffer returns results THE SYSTEM SHALL include pagination metadata (`truncated_buffers`, `resume_from_offset`) when limits are reached.
- WHEN search-buffer is called with `include_similarity=true` THE SYSTEM SHALL compute a normalized similarity score for each match.
- WHEN subsearch-buffer is called THE SYSTEM SHALL require UTF-8 buffer content, then perform a follow-up search scoped to an anchor (`buffer`, `offset_bytes`, `match_len`, `context_bytes`) and return the same structured JSON schema as search-buffer.
- WHEN buffer tools return content THE SYSTEM SHALL cap output by default to avoid unbounded payloads.
- WHILE handling buffer tools THE SYSTEM SHALL remain anchored to tmux buffers and SHALL NOT persist buffer data in a separate storage layer.

## Concurrency and limits
- THE SYSTEM SHALL bound concurrent tmux command executions with a semaphore (default max 8).

## Compatibility
- WHEN introducing new buffer tools THE SYSTEM SHALL keep existing buffer tools functional and follow the current naming convention.
