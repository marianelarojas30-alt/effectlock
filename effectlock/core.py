# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Marianela Bourgault
# Part of EffectLock, original source: https://github.com/marianelarojas30-alt/effectlock
# EffectLock-Origin: EL-MB-C8FBF0BBFB03BD6A
# This notice must be kept in all copies and modified versions (see LICENSE).

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import json
import os
import re
import shlex
import unicodedata

EFFECTS = ("process", "file", "environment", "network", "container", "mcp")

@dataclass(frozen=True)
class Evidence:
    effect: str
    confidence: str
    reason: str
    source: str

@dataclass(frozen=True)
class Prediction:
    command: str
    cwd: str
    effects: tuple[str, ...]
    evidence: tuple[Evidence, ...]
    unknowns: tuple[str, ...]

    def to_dict(self) -> dict:
        body = {
            "schema": "effectlock.prediction.v1",
            "command": self.command,
            "workspace_fingerprint": hashlib.sha256(self.cwd.encode("utf-8")).hexdigest()[:16],
            "effects": list(self.effects),
            "evidence": [asdict(x) for x in self.evidence],
            "unknowns": list(self.unknowns),
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        body["sha256"] = hashlib.sha256(canonical).hexdigest()
        return body


def terminal_safe(value: object) -> str:
    """Render untrusted text without terminal control or bidi characters."""
    out: list[str] = []
    for ch in str(value):
        category = unicodedata.category(ch)
        if ch == "\r" or category in {"Cc", "Cf"}:
            code = ord(ch)
            out.append(f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
        else:
            out.append(ch)
    return "".join(out)


def _add(out: list[Evidence], effect: str, confidence: str, reason: str, source: str) -> None:
    if effect not in EFFECTS:
        raise ValueError(f"unknown effect: {effect}")
    item = Evidence(effect, confidence, reason, source)
    if item not in out:
        out.append(item)


def _safe_project_file(cwd: Path, rel: str, max_bytes: int = 1_000_000) -> Path | None:
    relp = Path(rel)
    if relp.is_absolute() or ".." in relp.parts:
        return None
    root = cwd.resolve()
    cur = root
    for part in relp.parts:
        cur = cur / part
        try:
            if cur.is_symlink():
                return None
        except OSError:
            return None
    try:
        resolved = cur.resolve()
        resolved.relative_to(root)
        if not resolved.is_file() or resolved.stat().st_size > max_bytes:
            return None
    except (OSError, ValueError):
        return None
    return resolved


def _read_project_text(cwd: Path, rel: str, max_bytes: int = 1_000_000) -> str | None:
    p = _safe_project_file(cwd, rel, max_bytes=max_bytes)
    if p is None:
        return None
    try:
        raw = p.read_bytes()
        if len(raw) > max_bytes:
            return None
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return None


def _read_project_json(cwd: Path, rel: str) -> dict | None:
    text = _read_project_text(cwd, rel)
    if text is None:
        return None
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def _script_effects(script: str, source: str, out: list[Evidence]) -> None:
    _add(out, "process", "high", "referenced script can start child processes", source)
    if re.search(r"(?:^|[\s;&|])(?:curl|wget|ssh|scp|rsync|nc|ncat|git\s+(?:clone|fetch|pull|push)|npm|pnpm|yarn|pip|pip3|brew|apt|apt-get|dnf|yum)\b", script):
        _add(out, "network", "medium", "script contains a command that commonly uses the network", source)
    if re.search(r"(?:>|>>|\brm\b|\bmv\b|\bcp\b|\bmkdir\b|\btouch\b|\bchmod\b|\bchown\b|\btee\b)", script):
        _add(out, "file", "medium", "script contains filesystem mutation syntax", source)
    if re.search(r"\b(?:export|env)\b|[A-Za-z_][A-Za-z0-9_]*=", script):
        _add(out, "environment", "medium", "script can set or consume environment state", source)
    if re.search(r"\b(?:docker|podman|kubectl)\b", script):
        _add(out, "container", "medium", "script invokes container/orchestration tooling", source)


def _npm(words: list[str], cwd: Path, out: list[Evidence], unknowns: list[str]) -> bool:
    exe = Path(words[0]).name if words else ""
    if exe not in {"npm", "pnpm", "yarn", "bun"}:
        return False
    _add(out, "process", "high", f"{exe} executes package-manager code", "command semantics")
    sub = words[1] if len(words) > 1 else ""
    installish = sub in {"install", "i", "add", "ci", "update", "up"} or (exe == "yarn" and sub == "")
    if installish:
        _add(out, "file", "high", "dependency installation writes package/cache/workspace files", "command semantics")
        _add(out, "network", "high", "dependency installation may contact registries or git remotes", "command semantics")
        pkg = _read_project_json(cwd, "package.json")
        scripts = pkg.get("scripts", {}) if pkg else {}
        if isinstance(scripts, dict):
            for name in ("preinstall", "install", "postinstall", "prepare"):
                val = scripts.get(name)
                if isinstance(val, str) and val.strip():
                    _script_effects(val, f"package.json:scripts.{name}", out)
        unknowns.append("dependency lifecycle scripts can add effects not visible from the root package.json")
        return True
    script_name = None
    if sub in {"run", "run-script"} and len(words) >= 3:
        script_name = words[2]
    elif exe == "npm" and sub in {"test", "start", "stop", "restart"}:
        script_name = sub
    elif exe in {"pnpm", "yarn"} and sub and not sub.startswith("-"):
        script_name = sub
    if script_name:
        pkg = _read_project_json(cwd, "package.json")
        scripts = pkg.get("scripts", {}) if pkg and isinstance(pkg.get("scripts"), dict) else {}
        # npm lifecycle shorthands can trigger preX/X/postX. Include each source-backed script.
        names = [script_name]
        if exe == "npm":
            names = [f"pre{script_name}", script_name, f"post{script_name}"]
        found = False
        for name in names:
            script = scripts.get(name) if isinstance(scripts, dict) else None
            if isinstance(script, str) and script.strip():
                found = True
                _script_effects(script, f"package.json:scripts.{name}", out)
        if not found:
            unknowns.append(f"could not resolve package script {script_name!r} from package.json")
        return True
    return True


def _git(words: list[str], cwd: Path, out: list[Evidence], unknowns: list[str]) -> bool:
    if not words or Path(words[0]).name != "git":
        return False
    _add(out, "process", "high", "git starts a process", "command semantics")
    sub = words[1] if len(words) > 1 else ""
    if sub in {"clone", "fetch", "pull", "push", "submodule", "ls-remote"}:
        _add(out, "network", "high", f"git {sub} can contact a remote", "command semantics")
    if sub in {"checkout", "switch", "merge", "rebase", "reset", "clean", "apply", "commit", "stash"}:
        _add(out, "file", "high", f"git {sub} can mutate the worktree or repository metadata", "command semantics")
    if sub == "commit":
        # Deliberately avoid invoking Git while inspecting an untrusted repository.
        # Only inspect the conventional in-repository .git/hooks directory. Worktree
        # or custom hooks paths are reported as unknown rather than followed outside cwd.
        hooks_dir = cwd / ".git" / "hooks"
        names = ("pre-commit", "prepare-commit-msg", "commit-msg", "post-commit")
        found = False
        for name in names:
            rel = f".git/hooks/{name}"
            p = _safe_project_file(cwd, rel, max_bytes=20000)
            if p is not None and os.access(p, os.X_OK):
                found = True
                _add(out, "process", "high", f"git commit can execute hook {name}", rel)
                text = _read_project_text(cwd, rel, max_bytes=20000)
                if text is not None:
                    _script_effects(text, rel, out)
                else:
                    unknowns.append(f"could not safely inspect executable hook {rel}")
        if not found:
            unknowns.append("git commit may execute hooks from a custom core.hooksPath or worktree metadata not followed by EffectLock")
    return True


def _pip(words: list[str], cwd: Path, out: list[Evidence], unknowns: list[str]) -> bool:
    if not words or Path(words[0]).name not in {"pip", "pip3", "uv"}:
        return False
    _add(out, "process", "high", "Python package tooling executes build/install processes", "command semantics")
    if "install" in words or "sync" in words:
        _add(out, "file", "high", "package installation writes environment/cache files", "command semantics")
        _add(out, "network", "medium", "package installation may contact indexes or VCS remotes", "command semantics")
        text = _read_project_text(cwd, "pyproject.toml", max_bytes=100000)
        if text is not None and "[build-system]" in text:
            _add(out, "process", "high", "pyproject.toml declares a build backend that may execute code", "pyproject.toml:[build-system]")
            if "requires" in text:
                _add(out, "network", "medium", "build-system requirements may need resolution", "pyproject.toml:[build-system]")
        elif (cwd / "pyproject.toml").exists():
            unknowns.append("could not safely inspect pyproject.toml")
        if _safe_project_file(cwd, "setup.py") is not None:
            _add(out, "process", "high", "legacy setup.py can execute Python during build/install", "setup.py")
        unknowns.append("dependency build backends can add effects not visible from project metadata")
    return True


def _cargo(words: list[str], cwd: Path, out: list[Evidence], unknowns: list[str]) -> bool:
    if not words or Path(words[0]).name != "cargo":
        return False
    _add(out, "process", "high", "Cargo executes compiler/build processes", "command semantics")
    sub = words[1] if len(words) > 1 else ""
    if sub in {"build", "test", "run", "install", "update", "fetch"}:
        _add(out, "file", "high", "Cargo can write build artifacts or package metadata", "command semantics")
    if sub in {"build", "test", "run", "install", "update", "fetch"}:
        _add(out, "network", "medium", "Cargo may contact registries or git sources", "command semantics")
    if _safe_project_file(cwd, "build.rs") is not None:
        _add(out, "process", "high", "project contains build.rs which Cargo executes as a build script", "build.rs")
        unknowns.append("dependency build.rs scripts may add effects beyond the root package")
    return True


def _docker(words: list[str], cwd: Path, out: list[Evidence], unknowns: list[str]) -> bool:
    if not words or Path(words[0]).name not in {"docker", "podman"}:
        return False
    _add(out, "process", "high", "container CLI starts local helper/runtime processes", "command semantics")
    _add(out, "container", "high", "command can create or modify container/image state", "command semantics")
    sub = words[1] if len(words) > 1 else ""
    if sub in {"pull", "push", "build", "run", "compose"}:
        _add(out, "network", "medium", f"{words[0]} {sub} may use network access", "command semantics")
    if sub in {"build", "compose", "run", "cp", "volume"}:
        _add(out, "file", "medium", f"{words[0]} {sub} can read/write host or build-context files", "command semantics")
    if sub == "build":
        docker_text = _read_project_text(cwd, "Dockerfile", max_bytes=200000)
        if docker_text is not None:
            for i, line in enumerate(docker_text.splitlines(), 1):
                s = line.strip()
                if s.upper().startswith("RUN "):
                    _script_effects(s[4:], f"Dockerfile:{i}", out)
                if re.match(r"(?i)^ADD\s+https?://", s):
                    _add(out, "network", "high", "Dockerfile ADD fetches a remote URL", f"Dockerfile:{i}")
        elif (cwd / "Dockerfile").exists():
            unknowns.append("could not safely inspect Dockerfile")
    return True


def _mcp(words: list[str], cwd: Path, out: list[Evidence], unknowns: list[str]) -> bool:
    if not words:
        return False
    exe = Path(words[0]).name.lower()
    joined = " ".join(words).lower()
    if "mcp" not in exe and "mcp" not in joined:
        return False
    _add(out, "process", "medium", "command appears to invoke MCP-related tooling", "command semantics")
    _add(out, "mcp", "high", "MCP call can exercise the capability represented by the configured server/tool", "command semantics")
    for name in (".mcp.json", "mcp.json"):
        p = cwd / name
        obj = _read_project_json(cwd, name)
        if not obj:
            continue
        text = json.dumps(obj)
        if re.search(r"https?://|wss?://", text):
            _add(out, "network", "high", "MCP configuration contains a remote transport", name)
        if re.search(r'"command"\s*:', text):
            _add(out, "process", "high", "MCP configuration can spawn a local server process", name)
    unknowns.append("MCP server implementations may exercise effects beyond their advertised tool name")
    return True


def _generic(words: list[str], raw: str, out: list[Evidence]) -> None:
    if not words:
        return
    _add(out, "process", "high", "executing a shell command starts at least one process", "command semantics")
    if re.search(r"(?:>|>>|\brm\b|\bmv\b|\bcp\b|\bmkdir\b|\btouch\b|\bchmod\b|\bchown\b|\btee\b|\bsed\s+-i\b)", raw):
        _add(out, "file", "medium", "command text includes filesystem mutation syntax", "command text")
    if re.search(r"\b(?:curl|wget|ssh|scp|rsync|nc|ncat|ftp|sftp)\b", raw):
        _add(out, "network", "high", "command text includes a network-capable utility", "command text")
    if re.search(r"\b(?:docker|podman|kubectl)\b", raw):
        _add(out, "container", "medium", "command text includes container/orchestration tooling", "command text")
    if re.search(r"\b(?:export|env)\b|(?:^|\s)[A-Za-z_][A-Za-z0-9_]*=", raw):
        _add(out, "environment", "medium", "command text sets or passes environment values", "command text")


def predict(command: str, cwd: Path) -> Prediction:
    cwd = cwd.resolve()
    if not cwd.is_dir():
        raise ValueError("cwd must be an existing directory")
    if "\x00" in command or len(command.encode("utf-8")) > 32768:
        raise ValueError("invalid command")
    try:
        words = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ValueError(f"cannot parse command: {exc}") from exc
    out: list[Evidence] = []
    unknowns: list[str] = []
    handled = False
    for f in (_npm, _git, _pip, _cargo, _docker, _mcp):
        if f(words, cwd, out, unknowns):
            handled = True
            break
    _generic(words, command, out)
    effects = tuple(e for e in EFFECTS if any(x.effect == e for x in out))
    return Prediction(command, str(cwd), effects, tuple(out), tuple(dict.fromkeys(unknowns)))
