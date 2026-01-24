after making a change and pushing it...

# Release Guide

This repo publishes the CLI in four places:
- GitHub Releases (prebuilt binaries + checksums)
- crates.io (Cargo install)
- npm (global install + postinstall download)
- Homebrew (tap formula)

The GitHub Release assets are the source of truth for npm and Homebrew installs, so publish releases first.

## Before You Tag

1) Update versions (must match):
- `Cargo.toml` `[package].version`
- `package.json` `version`

2) Run the version sync check:
```bash
node scripts/check-version-sync.js
```

3) Optional but recommended:
- Update README or release notes.
- Run tests locally if needed.

## Release (Every Time)

1) Commit your changes and push:
```bash
git add -A
git commit -m "Release vX.Y.Z"
git push
```

2) Create and push a tag (this triggers GitHub Actions release builds):
```bash
git tag vX.Y.Z
git push --tags
```

3) Wait for the GitHub Actions workflow `Release` to finish.
- It builds for:
  - `x86_64-unknown-linux-musl`
  - `aarch64-unknown-linux-musl`
  - `x86_64-apple-darwin`
  - `aarch64-apple-darwin`
  - `x86_64-pc-windows-msvc`
- It uploads assets named like:
  - `tmux-mcp-rs-vX.Y.Z-<target>.tar.gz` (macOS/Linux)
  - `tmux-mcp-rs-vX.Y.Z-<target>.zip` (Windows)
  - matching `.sha256` files

4) Verify the GitHub Release has all assets.

## Publish to crates.io

1) Log in (first time):
```bash
cargo login <CRATES_IO_TOKEN>
```

2) Publish:
```bash
cargo publish
```

## Publish to npm

1) Log in (first time):
```bash
npm login
```

2) Publish the scoped package:
```bash
npm publish --access public
```

## Publish to Homebrew (tap)

1) Ensure the tap repo exists (separate repo: `bnomei/homebrew-tmux-mcp`).
   - The formula lives in the tap repo at `Formula/tmux-mcp-rs.rb`.

2) Update the formula for this release:
   - Set `version` to `X.Y.Z`.
   - Update each `sha256` to match the GitHub Release assets for macOS + Linux.
     - You can use the `.sha256` files in the GitHub Release assets, or compute locally:
       ```bash
       shasum -a 256 tmux-mcp-rs-vX.Y.Z-<target>.tar.gz
       ```

3) Commit and push changes in the tap repo.

4) Optional local verification:
```bash
brew install bnomei/tmux-mcp/tmux-mcp-rs
brew test bnomei/tmux-mcp/tmux-mcp-rs
```

## First Release Checklist

If this is the very first release:
- Confirm GitHub Releases are created in the correct repo (`bnomei/tmux-mcp`).
- Ensure the package name exists on npm: `@bnomei/tmux-mcp-rs`.
- Ensure crates.io package name `tmux-mcp-rs` is available.
- Create the Homebrew tap repo (`bnomei/homebrew-tmux-mcp`) and add `Formula/tmux-mcp-rs.rb`.

## Notes

- npm installs download binaries from GitHub Releases based on `package.json` version.
- Homebrew installs use the GitHub Release tarballs + checksums from the tap formula.
- If you need to test the npm installer without a release, you can set:
  - `TMUX_MCP_RS_LOCAL_BIN=/path/to/tmux-mcp-rs`
  - `TMUX_MCP_RS_SKIP_DOWNLOAD=1`
- The release workflow uses tags like `vX.Y.Z`; the tag version must match Cargo/npm versions.
