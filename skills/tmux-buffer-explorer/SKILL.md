---
name: tmux-buffer-explorer
description: Explore large tmux buffers via search and bounded slices. Use when
  buffer data is too large to load at once or needs incremental inspection.
---

# Tmux Buffer Explorer

## When to use
- Buffer-backed data is large and cannot be loaded in one response.
- The task needs incremental search, slicing, and synthesis.
- Deterministic offsets and pagination are important.

## Tools
- list-buffers
- show-buffer
- search-buffer
- subsearch-buffer
- set-buffer
- load-buffer
- append-buffer
- rename-buffer (optional)
- delete-buffer (optional)

## Workflow
1) List and prioritize
- Call list-buffers and prefer likely sources by size_bytes/order_index.
2) Import local files when needed
- If the source is a local file, use load-buffer(name, path) instead of
  pasting content into set-buffer.
3) Search first
- Use search-buffer with a focused query and mode (literal/regex).
- search-buffer requires UTF-8 buffers and returns byte-based offsets.
- Optional: includeSimilarity=true and/or similarityThreshold for fuzzy scoring.
- If truncated_buffers or resume_from_offset is returned, re-invoke
  search-buffer with resumeFromOffset (per-buffer byte offsets).
- Prefer buffers=[...] but buffer="name" is accepted as a shorthand.
4) Inspect bounded slices
- Use show-buffer with offset_bytes/max_bytes around matches.
- show-buffer returns plain text and may replace invalid UTF-8 bytes.
- Use subsearch-buffer anchored to a match for localized refinement (requires
  UTF-8 content and may error if invalid). subsearch-buffer also accepts
  resumeFromOffset within the anchor window.
- subsearch-buffer expects buffer (top-level) and anchor={offsetBytes, matchLen}.
  It will also accept anchor.buffer if top-level buffer is omitted. matchId is
  not a valid anchor.
5) Summarize and persist
- Store notes in set-buffer or append-buffer.
- If a non-UTF8 error appears during search/subsearch, pick a different buffer
  or narrow scope.
6) Iterate
- Refine queries based on prior results.
- Avoid full-buffer reads unless the buffer is known small.

## Decision rules
- If the user asks "near/around/within N of X", first search-buffer for X, then
  subsearch-buffer for the target term anchored on the chosen match.
- Avoid regex proximity across large buffers; prefer subsearch for deterministic,
  bounded windows.
- When multiple matches are returned, ask the user to pick a match unless the
  first match is obviously sufficient.
- Default window sizes: context_bytes=200; bump to 400–800 if no hits.

## Examples

Example: Find facts relevant to "error propagation"
1. Search all buffers:

search-buffer(
  query="error propagation",
  mode="literal",
  context_bytes=200,
  max_matches=20,
  include_similarity=false
)

If the content lives in a local file:

load-buffer(name="bigdoc", path="/path/to/file.txt")

Example: "near" query
1. Find the anchor:

search-buffer(
  query="DiMaggio",
  mode="literal",
  context_bytes=200,
  max_matches=20
)

2. Refine near that match:

subsearch-buffer(
  query="baseball",
  mode="literal",
  anchor={
    buffer: "bigdoc",
    offset_bytes: 12340,
    match_len: 42,
    context_bytes: 200
  },
  max_matches=10
)

If the response includes resume_from_offset, continue with:

search-buffer(
  query="error propagation",
  mode="literal",
  context_bytes=200,
  max_matches=20,
  resumeFromOffset={ "bigdoc": 25000 }
)

2. Inspect a bounded slice:

show-buffer(name="bigdoc", offset_bytes=12340, max_bytes=400)

3. Persist summary:

append-buffer(name="evidence", content="<summary>")

Example: Refine within a match window
1. Subsearch around a match:

subsearch-buffer(
  query="root cause",
  mode="regex",
  buffer="bigdoc",
  anchor={
    offsetBytes: 12340,
    matchLen: 42
  },
  contextBytes=512,
  max_matches=10,
  resumeFromOffset=12380
)

## Notes
- This Skill defines orchestration guidance, not tool implementation.
- Prefer search before show to minimize payloads.
- Use show-buffer when you need a lossy but readable slice.
- Fuzzy search: set fuzzyMatch=true or similarityThreshold. Output includes
  fuzzySkippedLines/fuzzySkippedBytes when long lines are skipped.
- Offsets/lengths are byte-based (UTF-8).
- Common errors: invalid UTF-8 (choose a different buffer or narrow scope),
  fuzzy skipped long lines (switch to literal/regex or narrow the window).
