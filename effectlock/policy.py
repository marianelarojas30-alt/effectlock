# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Marianela Bourgault
# Part of EffectLock, original source: https://github.com/marianelarojas30-alt/effectlock
# EffectLock-Origin: EL-MB-C8FBF0BBFB03BD6A
# This notice must be kept in all copies and modified versions (see LICENSE).

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import os
import stat

from .core import EFFECTS, Prediction

_MAX_POLICY_BYTES = 64 * 1024
_ALLOWED_KEYS = {"version", "deny", "deny_unknowns"}


@dataclass(frozen=True)
class PolicyConfig:
    deny: tuple[str, ...] = ()
    deny_unknowns: bool = False

    def canonical(self) -> dict:
        return {
            "schema": "effectlock.policy.v1",
            "deny": list(self.deny),
            "deny_unknowns": self.deny_unknowns,
        }

    def sha256(self) -> str:
        payload = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    denied_effects: tuple[str, ...]
    denied_unknowns: bool
    effective: PolicyConfig

    def to_dict(self) -> dict:
        return {
            "schema": "effectlock.policy-decision.v1",
            "allowed": self.allowed,
            "denied_effects": list(self.denied_effects),
            "denied_unknowns": self.denied_unknowns,
            "effective_policy": self.effective.canonical(),
            "policy_sha256": self.effective.sha256(),
        }


def _policy_relative_path(requested: str) -> Path:
    rel = Path(requested)
    if not requested or rel.is_absolute() or ".." in rel.parts:
        raise ValueError("policy path must be relative to the project directory")
    if rel.suffix.lower() != ".json":
        raise ValueError("policy path must end in .json")
    if any(part in {"", ".", ".."} for part in rel.parts):
        raise ValueError("invalid policy path component")
    return rel


def _read_policy_bytes(cwd: Path, requested: str) -> bytes:
    """Read a bounded policy file beneath cwd without following symlinks."""
    root = cwd.resolve()
    rel = _policy_relative_path(requested)
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ValueError("secure policy loading requires a POSIX platform with O_NOFOLLOW")

    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_fd = os.open(root, dir_flags)
    opened: list[int] = [root_fd]
    dir_fd = root_fd
    try:
        for part in rel.parts[:-1]:
            try:
                child_fd = os.open(part, dir_flags, dir_fd=dir_fd)
            except OSError as exc:
                raise ValueError("policy path contains an unsafe directory") from exc
            opened.append(child_fd)
            dir_fd = child_fd

        file_flags = os.O_RDONLY | os.O_NOFOLLOW
        try:
            fd = os.open(rel.parts[-1], file_flags, dir_fd=dir_fd)
        except OSError as exc:
            raise ValueError("policy file is not safely readable") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_POLICY_BYTES or st.st_nlink != 1:
                raise ValueError("policy file is not safely readable")
            chunks: list[bytes] = []
            remaining = _MAX_POLICY_BYTES + 1
            while remaining > 0:
                chunk = os.read(fd, min(remaining, 16384))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > _MAX_POLICY_BYTES:
                raise ValueError("policy file is not safely readable")
            return raw
        finally:
            os.close(fd)
    finally:
        for fd in reversed(opened):
            try:
                os.close(fd)
            except OSError:
                pass


def load_policy(cwd: Path, requested: str) -> PolicyConfig:
    try:
        raw = _read_policy_bytes(cwd, requested)
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid policy JSON") from exc
    if not isinstance(obj, dict):
        raise ValueError("policy must be a JSON object")
    unknown_keys = set(obj) - _ALLOWED_KEYS
    if unknown_keys:
        raise ValueError("policy contains unknown fields")
    if obj.get("version", 1) != 1:
        raise ValueError("unsupported policy version")

    deny_raw = obj.get("deny", [])
    if not isinstance(deny_raw, list) or any(not isinstance(item, str) for item in deny_raw):
        raise ValueError("policy deny must be a list of effect names")
    invalid = [item for item in deny_raw if item not in EFFECTS]
    if invalid:
        raise ValueError("policy contains an unknown effect")

    deny_unknowns = obj.get("deny_unknowns", False)
    if not isinstance(deny_unknowns, bool):
        raise ValueError("policy deny_unknowns must be boolean")

    return PolicyConfig(tuple(sorted(set(deny_raw))), deny_unknowns)


def evaluate_policy(pred: Prediction, cli_deny: list[str] | tuple[str, ...], config: PolicyConfig | None = None) -> PolicyDecision:
    config = config or PolicyConfig()
    effective_deny = tuple(sorted(set(config.deny).union(cli_deny)))
    effective = PolicyConfig(effective_deny, config.deny_unknowns)
    denied_effects = tuple(sorted(set(pred.effects).intersection(effective.deny)))
    denied_unknowns = bool(effective.deny_unknowns and pred.unknowns)
    return PolicyDecision(not denied_effects and not denied_unknowns, denied_effects, denied_unknowns, effective)
