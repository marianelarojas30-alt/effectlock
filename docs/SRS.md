# EffectLock — Software Requirements Specification

Lightweight SRS in the style of ISO/IEC/IEEE 29148. Scope, invariants and non-goals are in [ARCHITECTURE.md](../ARCHITECTURE.md); threats in [THREAT_MODEL.md](../THREAT_MODEL.md).

## 1. Purpose

Give a developer or coding-agent approver a deterministic, offline preview of the effects a command could have, before they approve running it.

## 2. Functional requirements

| ID | Requirement | Verified by |
|----|-------------|-------------|
| FR-1 | Classify predicted effects into exactly: process, file, environment, network, container, mcp. | `test_effectlock` family tests |
| FR-2 | Every predicted effect carries confidence, reason and source. | `test_graph_has_transitive_source_chain` |
| FR-3 | Expand npm/pnpm/yarn/bun, git, pip/uv, cargo, docker/podman and MCP commands using bounded local metadata. | `test_effectlock` expander tests |
| FR-4 | Report unresolved transitive behavior as `unknowns`, never as safe. | `test_unknown_npm_script_is_explicit` |
| FR-5 | Emit an effect graph (command -> source -> effect) without script bodies. | `test_graph_does_not_include_script_body` |
| FR-6 | Block via `--deny` and explicit `--policy` JSON; exit 3 when blocked, 2 on invalid input. | `test_cli_policy_exit_code_3`, `test_policy_*` |
| FR-7 | Optionally write a JSON receipt under the project directory. | `test_receipt_*` |
| FR-8 | The recorded command equals the command that would run (argv re-quoted). | `test_cli_preserves_argv_quoting` |
| FR-9 | Analyze every segment of a compound command (`&&`, `\|\|`, `;`, `\|`); a leading `cd DIR` inside the project redirects metadata reads for later segments; a `cd` outside the project is reported as unknown. | `test_compound_*`, `test_cd_*` |
| FR-10 | Unwrap `sudo`, `env`, `nohup`, `time`, `command`, `exec` and `sh/bash/zsh -c '...'` before classification; `sudo` is reported as privileged process execution. | `test_wrapper_*` |
| FR-11 | Ephemeral package runners (`npx`, `pnpm dlx`, `yarn dlx`, `bunx`, `uvx`, `pipx run`) predict network, file and process effects (download and execute remote code). | `test_ephemeral_runner_*` |
| FR-12 | Tools: when a command runs an MCP server or a known AI coding-agent CLI, every server in the project's MCP configuration (`.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`) becomes its own source: local command → process, ephemeral runner → network, remote URL → network, container runtime → container, env names → environment, absolute/home path args → file. Env values and URLs are never copied into output. | `test_tools_*` |

## 3. Non-functional requirements

| ID | Requirement | Verified by |
|----|-------------|-------------|
| NFR-1 | Never execute the inspected command; no network or LLM calls. | code review; no subprocess/socket imports |
| NFR-2 | Deterministic output; prediction hash independent of policy. | `test_report_hash_is_stable` |
| NFR-3 | Project reads are size-bounded and never follow symlinks outside the project. | `test_symlinked_package_json_not_read`, `test_policy_rejects_*` |
| NFR-4 | Receipt writes are atomic, mode 0600, and never follow symlinks or mutate hardlink peers. | `test_receipt_write_*` |
| NFR-5 | Untrusted text is terminal-escaped. | `test_terminal_*` |
| NFR-6 | Zero runtime dependencies; Python >= 3.10; POSIX for receipt/policy I/O. | CI matrix 3.10–3.13 |
| NFR-7 | Quality gate: ruff clean, `mypy --strict` clean, branch coverage >= 85%. | CI `quality` job |

## 4. Constraints and assumptions

- Static prediction cannot prove runtime behavior; runtime containment is out of scope.
- Repository policy is never auto-loaded.
- Agent CLIs are recognized by executable name (`claude`, `codex`, `gemini`, `cursor-agent`, `aider`, `goose`, `opencode`, `amp`, `copilot`); an agent with no project MCP configuration reports an unknown, because user-level tool configuration is outside the project and is not read.
