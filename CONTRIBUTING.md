# Contributing to EffectLock

Thanks for your interest in improving EffectLock.

## Before you start

- Read the [Code of Conduct](CODE_OF_CONDUCT.md).
- Security issues: do not open a public issue. Follow [SECURITY.md](SECURITY.md).
- For anything larger than a small fix, open an issue first so the approach can be agreed before you write code.

## Development

EffectLock has no runtime dependencies and uses only the Python standard library.

```bash
python -m unittest discover -s tests -v
python -m compileall -q effectlock
```

Every pull request must:

- keep the suite green and add regression tests for new behavior or fixed bugs;
- keep prediction deterministic and offline: no network calls, no LLM calls, never execute the inspected command;
- keep untrusted text (script bodies, paths, policy files) redacted or terminal-escaped as the existing code does;
- update `CHANGELOG.md` under `Unreleased`.

## License of contributions

EffectLock is distributed under the [PolyForm Noncommercial License 1.0.0](LICENSE), and the project owner, Marianela Bourgault, also offers it under separate commercial licenses.

By submitting a contribution, you confirm that you wrote it or have the right to submit it, and you grant Marianela Bourgault a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to use, modify, sublicense, and distribute your contribution under any license terms, including commercial ones. You keep the copyright in your contribution.

If you cannot agree to this, please do not submit a pull request.
