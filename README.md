# EffectLock

**See the hidden effect boundary before you approve a developer command.**

Coding-agent approval UIs usually show the entry invocation. Developer commands can activate more authority than that one line reveals: package lifecycle scripts, Git hooks, build scripts, container work, network access, and MCP transports.

EffectLock is a small, local, deterministic preflight. It does **not execute the inspected command** and it does not call an LLM. It predicts six effect classes from the command plus inspectable project metadata:

`process · file · environment · network · container · mcp`

```bash
effectlock -- npm install
```

Example:

```text
command: npm install
effects: process, file, network
  [high] process: npm executes package-manager code (command semantics)
  [high] file: dependency installation writes package/cache/workspace files (command semantics)
  [high] network: dependency installation may contact registries or git remotes (command semantics)
  [high] process: referenced script can start child processes (package.json:scripts.postinstall)
unknowns:
  - dependency lifecycle scripts can add effects not visible from the root package.json
```

## Why

Recent 2026 research formalized **approval laundering**: an approval record can truthfully name a command while omitting effects activated by the workflow behind it. EffectLock is an independent experimental implementation inspired by that problem statement, not an implementation from the authors' code.

Paper: *Agent Approval Laundering: Transitive Effects Beyond the Approved Invocation*, arXiv:2609.28586 (2026).

## Install

Offline, no package download required:

```bash
./install.sh
```

The secure receipt writer targets macOS and Linux. Python 3.10+ is required.

For packaging/development environments that already have a compatible build backend, `python3 -m pip install .` is also supported.

## Policy mode

Fail closed when a predicted effect is outside your policy:

```bash
effectlock --deny network --deny container -- npm install
```

Exit codes: `0` prediction accepted, `2` invalid input, `3` policy denied.

## Machine-readable receipt

```bash
effectlock --json --receipt .effectlock/last.json -- npm install
```

Receipts are confined to the project directory and refuse symlinked paths. The receipt stores a workspace fingerprint rather than your absolute filesystem path.

The receipt includes the command, source-backed evidence, explicit unknowns, and a deterministic SHA-256 digest. The digest is tamper-evident metadata, **not a cryptographic signature**.

## Shell operators

If you want to inspect a compound shell string, quote it so your shell does not execute it first:

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
- generic shell heuristics for file, network, environment and container effects

## Security boundary

EffectLock is a preflight analyzer, not a sandbox. It never runs the proposed command and does not invoke Git, package managers, shells, network clients, or an LLM during prediction. It reads bounded project metadata only. Predictions are conservative but incomplete; `unknowns` are part of the product contract and must not be interpreted as approval.

See [SECURITY.md](SECURITY.md), [ARCHITECTURE.md](ARCHITECTURE.md), and [THREAT_MODEL.md](THREAT_MODEL.md).
