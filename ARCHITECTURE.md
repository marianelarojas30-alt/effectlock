# Architecture

## Invariants

1. The inspected command is never executed.
2. No model or network service is used by EffectLock.
3. Every predicted effect has a reason and source.
4. Unknown transitive behavior is surfaced, never silently converted to "safe".
5. Policy decisions operate on structured effect classes, not prose.
6. Receipt hashes are reproducible for the same command, workspace fingerprint and evidence.

## Flow

`command -> shell parse -> family expander -> metadata expansion -> generic evidence -> normalized effect set -> policy -> receipt`

Expanders are deterministic functions. They may inspect bounded local metadata such as `package.json`, `pyproject.toml`, `build.rs`, `Dockerfile`, Git hook paths and MCP JSON configuration.

## Non-goals

- proving that a command is safe
- executing or sandboxing commands
- recursively evaluating arbitrary scripts
- replacing OS-level containment
- claiming complete transitive closure
