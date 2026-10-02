# EffectLock

**See the hidden effect boundary before you approve a developer command.**

EffectLock is a local, deterministic preflight for developer commands and AI coding-agent approvals. It does **not execute the inspected command** and it does not call an LLM.

It predicts six effect classes:

`process · file · environment · network · container · mcp`

```bash
effectlock -- npm install
```

## v0.3: tools

Before you let a coding agent run, see which tools it can reach:

```bash
effectlock --graph -- claude
```

Every server in the project's MCP configuration (`.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`) becomes its own source:

```text
command -> .mcp.json:mcpServers.filesystem -> process [high]
command -> .mcp.json:mcpServers.filesystem -> network [high]   (npx downloads the server)
command -> .mcp.json:mcpServers.github -> network [high]
command -> .mcp.json:mcpServers.github -> environment [medium] (GITHUB_TOKEN)
```

Environment values and server URLs are never copied into the output. Block agents that can reach tools with `--deny mcp`.

Real agent commands are inspected as written: `cd app && npm install` reads `app/package.json`, `sudo` and `bash -c '...'` are unwrapped, and `npx`/`uvx`/`pnpm dlx` are reported as downloading code.

## v0.2: effect graph

Show where predicted effects come from:

```bash
effectlock --graph -- npm install
```

Example chain:

```text
effect graph:
  command -> package.json:scripts.postinstall -> network [medium]
```

The graph is also included in JSON output and receipts. Script bodies are never copied into the graph.

## v0.2: policy engine

Inline policy still works:

```bash
effectlock --deny network --deny container -- npm install
```

Or use an explicit JSON policy under the project directory:

```json
{
  "version": 1,
  "deny": ["network", "container"],
  "deny_unknowns": true
}
```

```bash
effectlock --policy effectlock-policy.json -- npm install
```

EffectLock never auto-loads repository policy. The policy file must be explicitly selected, is size-bounded, and is read without following symlinks or hardlinks.

Exit codes: `0` accepted, `2` invalid input/configuration, `3` blocked by policy.

## Install

Offline, no package download required:

```bash
./install.sh
```

Python 3.10+ is required. Secure policy/receipt handling targets macOS and Linux.

## Machine-readable receipt

```bash
effectlock --json --receipt .effectlock/last.json -- npm install
```

Receipts contain:

- predicted effects and source-backed evidence
- explicit unknowns
- effect graph
- effective policy and decision
- stable prediction SHA-256
- full report SHA-256

The hashes are tamper-evident metadata, **not cryptographic signatures**.

## Shell operators

Quote compound shell strings so your shell does not run them first:

```bash
effectlock -- "npm install && curl https://example.com"
```

## Current expanders

- npm / pnpm / yarn / bun install and package scripts
- Git network/worktree commands and executable commit hooks
- pip / uv install and Python build metadata
- Cargo build scripts
- Docker / Podman builds
- MCP-related commands and local MCP config
- generic shell heuristics

## Security boundary

EffectLock is a preflight analyzer, not a sandbox. Static prediction is intentionally conservative and incomplete. `unknowns` are part of the product contract and must not be interpreted as approval.

See [SECURITY.md](SECURITY.md), [ARCHITECTURE.md](ARCHITECTURE.md), and [THREAT_MODEL.md](THREAT_MODEL.md).

## License

Copyright (c) 2026 Marianela Bourgault.

EffectLock is **free for noncommercial use** under the [PolyForm Noncommercial License 1.0.0](LICENSE). You may not sell it, charge for it, or use it for commercial purposes without a separate written license from the author. Copies and modified versions must keep the copyright notice.

Versions up to and including 0.2.0 were published under the MIT License; copies obtained under those terms keep them.
