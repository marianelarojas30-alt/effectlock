<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0 · Copyright (c) 2026 Marianela Bourgault · EffectLock-Origin: EL-MB-C8FBF0BBFB03BD6A -->
# Design note: one module for no-follow file access

## Problem
`cli.write_receipt` and `policy._read_policy_bytes` each carried their own copy of the same
security-critical logic: open the project root, walk each directory with `O_NOFOLLOW`, close every
descriptor, check the final file. Two copies of security code drift apart: a fix applied to one is
easily forgotten in the other (repetition and information leakage: one design decision living in
two modules).

## Options considered
- **A. A deep module (`safefs`)** with two calls, `read_bytes_under(root, rel, max_bytes, what=...)` and
  `write_bytes_atomic_under(root, rel, payload, what=...)`. The descriptor walk, symlink refusal,
  hard-link and size checks, atomic rename and cleanup stay hidden behind them.
- **B. A shared private helper** that only yields the directory descriptor, leaving file checks and
  the atomic write in each caller.

**Chosen: A.** B removes less duplication and still leaves callers responsible for the subtle parts
(O_EXCL temp file, fsync, unlink on failure). A gives a small interface over a lot of hidden behavior.

## Non-goals
- No change to which paths are accepted: path validation (`.json` suffix, no `..`, relative only)
  stays with each caller, because the rules differ per file type.
- No change to user-facing messages: `what` keeps each caller's wording ("policy", "receipt").
- Project metadata reads in `core.py` (`_safe_project_file`) are not migrated in this change.

## Follow-up candidate
`core._safe_project_file` checks the path and then opens it later (check-then-use). Moving project
reads onto `safefs` would close that window, but it changes behavior (POSIX-only, hard-linked
files refused), so it needs its own decision and tests.
