# Tasks

1) Inventory existing buffer tools and tmux helpers; decide exact names for new tools (`set-buffer`, `append-buffer`, `rename-buffer`, `search-buffer`, `subsearch-buffer`).
2) Extend `src/tmux.rs` with async command execution, SSH/socket support, and a tmux semaphore (default 8).
3) Implement list/show/set/append/delete/rename/search/subsearch helpers with UTF-8 validation for search/subsearch (show-buffer can be lossy), anchor-based subsearch scoping, truncation, pagination metadata, and match snippet formatting.
4) Extend types for buffer list output (`size_bytes`, `order_index`) and search results; wire tool schemas and handlers in `src/server.rs`.
5) Update `src/security.rs` to allow new tool names (and note any policy grouping changes).
6) Add unit tests: list-buffers parsing variants; search snippet formatting.
7) Update README with new tools + examples.

## Open questions / decisions
- Confirm the exact tool names for `search` and `subsearch` (e.g., `search-buffer`, `subsearch-buffer`) to match the current naming convention.
