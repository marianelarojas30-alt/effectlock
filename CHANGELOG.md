# Changelog

## 0.2.1 - 2026-09-29

- fix: multi-argument commands are re-quoted with `shlex.join`, so the inspected and recorded command matches what would run
- fix: receipt test no longer fails on macOS (`/var` -> `/private/var`)
- add `docs/SRS.md` with requirement-to-test traceability
- add CI quality gate: ruff, strict mypy, branch coverage >= 85%

## 0.2.0 - 2026-09-27

- add deterministic effect graph with command -> metadata -> effect chains
- add explicit JSON policy files with deny lists and `deny_unknowns`
- keep repository policy opt-in rather than auto-loading it
- add policy fingerprint and full report SHA-256 while preserving the v0.1 prediction hash
- harden policy loading with bounded POSIX dir-fd traversal, `O_NOFOLLOW`, and hardlink rejection
- expand regression suite from 40 to 52 tests

## 0.1.1 - 2026-09-27

- add source-backed npm lifecycle expansion
- redact package script bodies from evidence
- escape terminal control and bidi characters
- replace absolute cwd in receipts with a workspace fingerprint
- confine receipt writes with dir-fd traversal, `O_NOFOLLOW`, private permissions, and atomic rename
- add offline installer and security regression tests

## 0.1.0

- initial deterministic effect prediction for npm, Git, pip/uv, Cargo, Docker/Podman, MCP, and generic shell commands
