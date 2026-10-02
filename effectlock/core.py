# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Marianela Bourgault
# Part of EffectLock, original source: https://github.com/marianelarojas30-alt/effectlock
# EffectLock-Origin: EL-MB-C8FBF0BBFB03BD6A
# This notice must be kept in all copies and modified versions (see LICENSE).

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

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

    def to_dict(self) -> dict[str, Any]:
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


def _read_project_json(cwd: Path, rel: str) -> dict[str, Any] | None:
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


def _ephemeral_runner(words: list[str]) -> bool:
    """True for commands that download a package and execute it in one step."""
    if not words:
        return False
    exe = Path(words[0]).name
    sub = words[1] if len(words) > 1 else ""
    return (
        exe in {"npx", "bunx", "uvx"}
        or (exe in {"pnpm", "yarn"} and sub == "dlx")
        or (exe == "npm" and sub in {"exec", "x"})
        or (exe == "pipx" and sub == "run")
    )


def _runner(words: list[str], cwd: Path, out: list[Evidence], unknowns: list[str]) -> bool:
    if not _ephemeral_runner(words):
        return False
    exe = Path(words[0]).name
    _add(out, "process", "high", f"{exe} executes a package resolved at run time", "command semantics")
    _add(out, "network", "high", f"{exe} may download the package from a registry before running it", "command semantics")
    _add(out, "file", "medium", f"{exe} writes the downloaded package to a local cache", "command semantics")
    unknowns.append("code fetched at run time is not visible to static inspection")
    return True


AGENT_CLIS = frozenset({"claude", "codex", "gemini", "cursor-agent", "aider", "goose", "opencode", "amp", "copilot"})
MCP_CONFIGS = (".mcp.json", "mcp.json", ".cursor/mcp.json", ".vscode/mcp.json")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")


def _tool_server(name: str, spec: dict[str, Any], source: str, out: list[Evidence]) -> None:
    """Map one configured MCP server to the effects its tools can reach."""
    _add(out, "mcp", "high", f"agent can call the tools exposed by MCP server {name!r}", source)
    command = spec.get("command")
    args = [a for a in spec.get("args", []) if isinstance(a, str)] if isinstance(spec.get("args"), list) else []
    if isinstance(command, str) and command.strip():
        argv = [command, *args]
        _add(out, "process", "high", "server starts as a local process", source)
        if _ephemeral_runner(argv):
            _add(out, "network", "high", "server package is downloaded when the server starts", source)
        if Path(command).name in {"docker", "podman"}:
            _add(out, "container", "high", "server runs inside a container runtime", source)
        if any(a.startswith(("/", "~")) for a in args):
            _add(out, "file", "medium", "server is given a filesystem path to operate on", source)
    if any(isinstance(spec.get(key), str) for key in ("url", "serverUrl", "httpUrl")):
        _add(out, "network", "high", "server is reached over the network", source)
    env = spec.get("env")
    if isinstance(env, dict) and env:
        names = sorted(k for k in env if isinstance(k, str) and _ENV_NAME.fullmatch(k))
        shown = ", ".join(names[:5]) + (", ..." if len(names) > 5 else "")
        _add(out, "environment", "medium", f"server receives environment variables: {shown or 'unnamed'}", source)


def _tools(words: list[str], cwd: Path, out: list[Evidence], unknowns: list[str]) -> bool:
    if not words:
        return False
    exe = Path(words[0]).name.lower()
    agent = exe in AGENT_CLIS
    if not agent and "mcp" not in " ".join(words).lower():
        return False
    if agent:
        _add(out, "process", "high", f"{exe} is an AI coding agent that can run commands on its own", "command semantics")
        _add(out, "file", "medium", f"{exe} can edit files in the project", "command semantics")
        _add(out, "network", "high", f"{exe} contacts its model provider", "command semantics")
    else:
        _add(out, "process", "medium", "command appears to invoke MCP-related tooling", "command semantics")
        _add(out, "mcp", "high", "MCP call can exercise the capability represented by the configured server/tool", "command semantics")
    found = False
    for rel in MCP_CONFIGS:
        obj = _read_project_json(cwd, rel)
        if not obj:
            continue
        for key in ("mcpServers", "servers"):
            servers = obj.get(key)
            if not isinstance(servers, dict):
                continue
            for name, spec in sorted(servers.items()):
                if isinstance(name, str) and isinstance(spec, dict):
                    found = True
                    _tool_server(name[:64], spec, f"{rel}:{key}.{name[:64]}", out)
    if agent and not found:
        unknowns.append(f"{exe} may load user-level MCP tools outside the project that EffectLock does not read")
    unknowns.append("MCP server implementations may exercise effects beyond their advertised tool name")
    return True


_SEGMENT_OPS = frozenset({"&&", "||", ";", "|", "&", ";;", "|&"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash"})
_MAX_DEPTH = 4


def _split_segments(command: str) -> list[list[str]]:
    lex = shlex.shlex(command, posix=True, punctuation_chars=";&|")
    lex.whitespace_split = True
    segments: list[list[str]] = [[]]
    for token in lex:
        if token in _SEGMENT_OPS:
            segments.append([])
        else:
            segments[-1].append(token)
    return [s for s in segments if s]


def _unwrap(words: list[str], out: list[Evidence]) -> list[str] | str:
    """Strip wrappers that run another command; return the inner argv, or a nested shell string."""
    while words:
        exe = Path(words[0]).name
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[0]):
            words = words[1:]
        elif exe in {"sudo", "doas"}:
            _add(out, "process", "high", f"{exe} runs the command with elevated privileges", "command semantics")
            i = 1
            while i < len(words) and words[i].startswith("-"):
                i += 2 if words[i] in {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"} else 1
            words = words[i:]
        elif exe in {"env", "nohup", "time", "command", "exec", "nice"}:
            i = 1
            while i < len(words) and (words[i].startswith("-") or "=" in words[i]):
                i += 2 if exe == "nice" and words[i] == "-n" else 1
            words = words[i:]
        elif exe in _SHELLS and "-c" in words[1:] and words.index("-c") + 1 < len(words):
            return words[words.index("-c") + 1]
        else:
            return words
    return words


def _project_subdir(root: Path, cur: Path, target: str) -> Path | None:
    candidate = Path(target)
    if candidate.is_absolute() or target.startswith("~"):
        return None
    probe = cur
    for part in candidate.parts:
        probe = probe / part
        if probe.is_symlink():
            return None
    try:
        resolved = probe.resolve()
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    return resolved if resolved.is_dir() else None


def _inspect(command: str, root: Path, out: list[Evidence], unknowns: list[str], depth: int) -> None:
    try:
        segments = _split_segments(command)
    except ValueError as exc:
        raise ValueError(f"cannot parse command: {exc}") from exc
    cur = root
    for segment in segments:
        words = _unwrap(segment, out)
        if isinstance(words, str):
            if depth >= _MAX_DEPTH:
                unknowns.append("nested shell -c commands exceed the inspection depth")
            else:
                _inspect(words, root, out, unknowns, depth + 1)
            continue
        if not words:
            continue
        if words[0] == "cd":
            nxt = _project_subdir(root, cur, words[1]) if len(words) > 1 else None
            if nxt is None:
                unknowns.append("cd leaves the project directory or cannot be resolved; later metadata is read from the previous directory")
            else:
                cur = nxt
            continue
        start = len(out)
        for expander in (_runner, _npm, _git, _pip, _cargo, _docker, _tools):
            if expander(words, cur, out, unknowns):
                break
        if cur != root:
            # Metadata sources are reported relative to the project root, not the cd target.
            prefix = cur.relative_to(root).as_posix()
            for i in range(start, len(out)):
                ev = out[i]
                if ev.source not in {"command semantics", "command text"}:
                    out[i] = Evidence(ev.effect, ev.confidence, ev.reason, f"{prefix}/{ev.source}")


def _generic(raw: str, out: list[Evidence]) -> None:
    if not raw.strip():
        return
    if not any(x.effect == "process" for x in out):
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
    out: list[Evidence] = []
    unknowns: list[str] = []
    _inspect(command, cwd, out, unknowns, 0)
    _generic(command, out)
    effects = tuple(e for e in EFFECTS if any(x.effect == e for x in out))
    return Prediction(command, str(cwd), effects, tuple(out), tuple(dict.fromkeys(unknowns)))
