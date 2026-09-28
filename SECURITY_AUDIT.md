# Security audit 0.1.1

Date: 2026-09-27

## Security properties tested

- inspected commands are never executed
- no network client or subprocess primitive exists in the runtime package
- project metadata symlinks are not followed
- Git hooks are inspected but not executed
- package script bodies are not echoed into terminal output or receipts
- terminal control, newline, tab, and bidi characters are escaped in human output
- receipt paths cannot escape the project or traverse symlinked parents
- receipt writes use a POSIX dir-fd walk, `O_NOFOLLOW`, private mode `0600`, and atomic rename
- existing symlink receipt targets are rejected
- receipt metadata does not expose the absolute workspace path
- malformed and oversized command input fails closed
- oversized project metadata is ignored rather than parsed
- policy denial returns a distinct nonzero exit code
- offline installer refuses symlink launcher replacement

## Verification performed

- 40 deterministic unit/security tests passed
- 5,000 deterministic fuzz inputs completed without an unexpected exception
- adversarial `package.json` test did not execute its payload, leak its secret token, or emit terminal escape bytes
- static scan found no `subprocess`, socket/HTTP client, `os.system`, `os.popen`, `exec`, or `eval` primitive in the runtime package
- policy-denial smoke test returned exit code 3
- offline install and installed CLI smoke test passed

This audit does not claim complete prediction of arbitrary program behavior. Static transitive-effect prediction is inherently incomplete; unknowns are surfaced explicitly. EffectLock is not an OS sandbox.
