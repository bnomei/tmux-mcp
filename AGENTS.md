# Repository Guidelines

## Project Structure & Module Organization
- `src/` holds the Rust crate. Key files: `main.rs` (CLI entry), `lib.rs` (library exports), `server.rs` (MCP server), `tmux.rs` (tmux process wrapper), `security.rs` (policy checks/config schema), `commands.rs`, `types.rs`, `errors.rs`, and `test_support.rs` (tmux/ssh stubs for tests).
- `tests/` contains Rust tests: `cli.rs` for CLI behavior and `integration.rs` for tmux-backed workflows.
- `scripts/` and `npm/` support the npm distribution (workspace base + platform packages) plus release packaging helpers.
- `npm/base/`: npm wrapper package (launcher + optionalDependencies).
- `npm/platform/<os-arch>/`: platform packages containing the binary.
- `docs/RELEASE.md` is the release guide; `DIST.md` is the distribution checklist.
- Build outputs live in `target/`; npm installs create `node_modules/` (both are generated).

## Build, Test, and Development Commands
- `cargo build --release` builds the `tmux-mcp-rs` binary in `target/release/`.
- `cargo test --lib` runs unit tests without tmux.
- `cargo test --test cli` runs CLI tests without tmux.
- `TMUX_MCP_INTEGRATION=1 cargo test --test integration` runs tmux integration tests (requires tmux on PATH).
- `npm install`: install workspace packages.
- `npm run check-version-sync`: verify Rust/npm version alignment (Cargo.toml vs `npm/base/package.json`).

## Coding Style & Naming Conventions
- Rust 2021 edition; prefer rustfmt defaults (`cargo fmt`) when formatting.
- Use standard Rust naming: `snake_case` for functions/modules, `CamelCase` for types.
- CLI flags use `kebab-case` (for example, `--shell-type`, `--socket`).
- Tests should use clear `test_*` names and mirror the feature being exercised.

## Testing Guidelines
- Frameworks: Rust test harness plus `rstest` for fixtures; integration tests live in `tests/integration.rs`.
- Integration tests create isolated tmux servers; keep them deterministic and ensure cleanup.
- Prefer adding tests alongside new tool behavior or security checks.

## Commit & Pull Request Guidelines
- Git history only shows "Initial commit", so no formal convention exists. Use concise, imperative subjects (example: "Add socket allowlist").
- PRs should include: a short summary, testing performed, and any new env vars or config.
- Link related issues and include screenshots only for user-facing CLI output changes.

## Security & Configuration Tips
- Security policy schema lives in `src/security.rs`; users supply a `config.toml` (see README sample). Keep defaults safe and explicit.
- Use isolated tmux sockets for agents via `--socket` or `TMUX_MCP_SOCKET`; use `--ssh` or `TMUX_MCP_SSH` for remote control.
