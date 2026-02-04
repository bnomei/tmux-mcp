# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Enforced session allowlist checks across pane/window tools and resources.
- Added configurable command tracking settings (capture limits and backoff).
- Added retention controls for completed command history.
- Added search streaming threshold for large buffer searches.

### Changed
- Bound command results to the resolved tmux socket and enforced socket policy on command reads.
- Improved literal send-keys performance with chunked fast paths for large payloads.

## [0.1.2] - 2026-01-26
### Changed
- Upgraded the optional rapidfuzz dependency to 0.5.0 for fuzzy similarity scoring.
- Improved the README

## [0.1.1] - 2026-01-26
### Added
- Added probe-and-refine workflow and tmux-buffer-explorer buffer tooling.

## [0.1.0] - 2026-01-24
- Initial Release
