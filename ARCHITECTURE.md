# Architecture

## Invariants

1. The inspected command is never executed.
2. No model or network service is used by EffectLock.
3. Every predicted effect has a reason and source.
4. Unknown transitive behavior is surfaced, never silently converted to "safe".
5. Policy decisions operate on structured effect classes, not prose.
6. Repository policy is never auto-loaded.
7. Graph nodes never contain package-script bodies.
8. Prediction hashes remain stable independently of policy; report hashes cover graph + policy decision.

## Flow

`command -> shell parse -> segments (&&, ||, ;, |) -> unwrap (sudo, env, sh -c) -> family expander -> metadata expansion -> evidence -> effect graph -> policy -> receipt`

Expanders are deterministic functions. They may inspect bounded local metadata such as `package.json`, `pyproject.toml`, `build.rs`, `Dockerfile`, Git hook paths and MCP JSON configuration. A `cd` into a project subdirectory redirects metadata reads for later segments; a `cd` that leaves the project is reported as unknown.

### Effect graph

The graph has three node kinds:

- `command`: the requested invocation
- `source`: inspectable metadata that can activate additional behavior
- `effect`: one of the six EffectLock effect classes

This makes transitive chains machine-readable without copying script bodies into receipts.

### Policy

Policies are explicit JSON files selected with `--policy`. Supported controls are:

- `deny`: effect classes that must block
- `deny_unknowns`: fail closed when static analysis reports unresolved behavior

The CLI `--deny` flags are unioned with file policy.

## Non-goals

- proving that a command is safe
- executing or sandboxing commands
- recursively evaluating arbitrary scripts
- replacing OS-level containment
- claiming complete transitive closure
