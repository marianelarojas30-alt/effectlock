# Changelog

## 0.1.1 - 2026-09-27

- add source-backed npm lifecycle expansion
- redact package script bodies from evidence
- escape terminal control and bidi characters
- replace absolute cwd in receipts with a workspace fingerprint
- confine receipt writes with dir-fd traversal, `O_NOFOLLOW`, private permissions, and atomic rename
- add offline installer and security regression tests

## 0.1.0

- initial deterministic effect prediction for npm, Git, pip/uv, Cargo, Docker/Podman, MCP, and generic shell commands
