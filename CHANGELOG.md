# Changelog

## Unreleased

- relicense from MIT to PolyForm Noncommercial 1.0.0: free for noncommercial use, commercial use requires a separate license from the author
- show copyright and license notice in `--version` and `--help`
- add origin fingerprint `EL-MB-C8FBF0BBFB03BD6A` to every source file header and a hash-covered `generator` block to JSON reports and receipts, enforced by `tests/test_provenance.py`
- refactor: the no-follow receipt writer and policy reader now share one module, `effectlock/safefs.py`, instead of two near-identical copies of the security-critical descriptor walk; behavior and error messages are unchanged, with 9 new tests in `tests/test_safefs.py` (design note: `docs/design/safefs.md`)

## 0.3.0 - 2026-09-30

- add tools inspection: running an AI coding-agent CLI (`claude`, `codex`, `gemini`, ...) or an MCP command maps every server in `.mcp.json`, `mcp.json`, `.cursor/mcp.json` and `.vscode/mcp.json` to its own effects (process, network, container, environment, file); secret values and URLs are never copied into output
- fix: compound commands (`&&`, `||`, `;`, `|`) are inspected segment by segment; `cd app && npm install` now reads `app/package.json`
- fix: `sudo`, `env`, `nohup`, `time`, `exec` and `sh/bash -c '...'` are unwrapped before classification; `sudo` is reported as privileged
- fix: ephemeral runners (`npx`, `pnpm dlx`, `yarn dlx`, `bunx`, `uvx`, `pipx run`, `npm exec`) now predict network and file effects
- cleanup: remove duplicated Cargo condition; generic process evidence only when no expander already reported one
- expand regression suite from 54 to 73 tests

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
