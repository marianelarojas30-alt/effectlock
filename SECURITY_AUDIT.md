# Security audit

## v0.2.0 release gate

- 52/52 unit and security regression tests passing locally
- 5,000 fuzz inputs completed without an unexpected exception after malformed commands were treated as expected parse failures
- Python bytecode compilation passing
- offline installer smoke test passing
- inspected command remains non-executing
- graph output does not include package-script bodies
- policy file path traversal blocked
- symlinked policy blocked
- hardlinked policy blocked
- oversized policy blocked
- policy unknown fields rejected
- receipt atomic/symlink/hardlink tests retained from v0.1.1
- CI remains pinned to commit SHAs for checkout/setup-python

Residual risk: static effect prediction cannot prove runtime behavior. TOCTOU remains possible for project metadata read by the v0.1 metadata readers; v0.2 specifically hardens policy loading and receipt writing. Runtime containment remains out of scope.
