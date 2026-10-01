from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import stat
import sys

from . import NOTICE, __version__
from .core import EFFECTS, predict, terminal_safe
from .graph import render_effect_graph
from .policy import PolicyConfig, evaluate_policy, load_policy
from .report import build_report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="effectlock", description="Preview transitive effects before approving a developer command.", epilog=NOTICE)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}\n{NOTICE}")
    p.add_argument("--cwd", default=".", help="project directory (default: current directory)")
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    p.add_argument("--graph", action="store_true", help="show a human-readable effect graph")
    p.add_argument("--receipt", help="write receipt under the project directory")
    p.add_argument("--policy", help="load an explicit JSON policy under the project directory")
    p.add_argument("--deny", action="append", choices=EFFECTS, default=[], help="exit 3 if an effect is predicted; repeatable")
    p.add_argument("command", nargs=argparse.REMAINDER, help="command to inspect; prefix with --")
    return p


def _receipt_relative_path(cwd: Path, requested: str) -> tuple[Path, Path]:
    root = cwd.resolve()
    raw = Path(requested).expanduser()
    if not requested or raw.name in {"", ".", ".."}:
        raise ValueError("invalid receipt path")
    if raw.is_absolute():
        raise ValueError("receipt path must be relative to the project directory")
    if ".." in raw.parts:
        raise ValueError("receipt path must stay inside the project directory")
    if raw.suffix.lower() != ".json":
        raise ValueError("receipt path must end in .json")
    if any(part in {"", ".", ".."} for part in raw.parts):
        raise ValueError("invalid receipt path component")
    return root, raw


def safe_receipt_path(cwd: Path, requested: str) -> Path:
    """Validate and normalize a receipt path without writing it."""
    root, rel = _receipt_relative_path(cwd, requested)
    cur = root
    for part in rel.parts[:-1]:
        cur = cur / part
        if cur.is_symlink():
            raise ValueError("receipt path contains a symlinked directory")
    target = root / rel
    if target.is_symlink():
        raise ValueError("receipt target must not be a symlink")
    return target


def write_receipt(cwd: Path, requested: str, body: dict) -> Path:
    """Write a receipt atomically beneath cwd without following symlinks."""
    root, rel = _receipt_relative_path(cwd, requested)
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ValueError("secure receipt writing requires a POSIX platform with O_NOFOLLOW")

    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_fd = os.open(root, dir_flags)
    opened: list[int] = [root_fd]
    dir_fd = root_fd
    try:
        for part in rel.parts[:-1]:
            if part in {"", ".", ".."}:
                raise ValueError("invalid receipt path component")
            try:
                child_fd = os.open(part, dir_flags, dir_fd=dir_fd)
            except FileNotFoundError:
                os.mkdir(part, mode=0o700, dir_fd=dir_fd)
                child_fd = os.open(part, dir_flags, dir_fd=dir_fd)
            except OSError as exc:
                raise ValueError("receipt path contains an unsafe directory") from exc
            opened.append(child_fd)
            dir_fd = child_fd

        filename = rel.parts[-1]
        try:
            st = os.stat(filename, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            st = None
        if st is not None and stat.S_ISLNK(st.st_mode):
            raise ValueError("receipt target must not be a symlink")
        if st is not None and not stat.S_ISREG(st.st_mode):
            raise ValueError("receipt target must be a regular file")

        payload = (json.dumps(body, indent=2, sort_keys=True) + "\n").encode("utf-8")
        tmp_name = f".{filename}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        fd = os.open(tmp_name, flags, 0o600, dir_fd=dir_fd)
        try:
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            try:
                os.unlink(tmp_name, dir_fd=dir_fd)
            except OSError:
                pass
            raise

        try:
            os.replace(tmp_name, filename, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except Exception:
            try:
                os.unlink(tmp_name, dir_fd=dir_fd)
            except OSError:
                pass
            raise
        os.fsync(dir_fd)
        return root / rel
    finally:
        for fd in reversed(opened):
            try:
                os.close(fd)
            except OSError:
                pass


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cmd = list(args.command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("effectlock: provide a command after --", file=sys.stderr)
        return 2
    command = " ".join(cmd)
    cwd = Path(args.cwd)
    try:
        pred = predict(command, cwd)
        config = load_policy(cwd, args.policy) if args.policy else PolicyConfig()
        decision = evaluate_policy(pred, args.deny, config)
        receipt_path = safe_receipt_path(cwd, args.receipt) if args.receipt else None
    except ValueError as exc:
        print(f"effectlock: {terminal_safe(exc)}", file=sys.stderr)
        return 2

    body = build_report(pred, decision)
    if receipt_path:
        try:
            write_receipt(cwd, args.receipt, body)
        except (OSError, ValueError) as exc:
            print(f"effectlock: {terminal_safe(exc)}", file=sys.stderr)
            return 2

    if args.json:
        print(json.dumps(body, indent=2, sort_keys=True))
    else:
        print(f"command: {terminal_safe(pred.command)}")
        print("effects: " + (", ".join(pred.effects) if pred.effects else "none predicted"))
        for ev in pred.evidence:
            print(f"  [{ev.confidence}] {ev.effect}: {terminal_safe(ev.reason)} ({terminal_safe(ev.source)})")
        if args.graph:
            print("effect graph:")
            for line in render_effect_graph(pred):
                print(f"  {terminal_safe(line)}")
        if pred.unknowns:
            print("unknowns:")
            for item in pred.unknowns:
                print(f"  - {terminal_safe(item)}")
        print(f"prediction-sha256: {body['sha256']}")
        print(f"report-sha256: {body['report_sha256']}")

    if not decision.allowed:
        if not args.json:
            reasons = list(decision.denied_effects)
            if decision.denied_unknowns:
                reasons.append("unknowns")
            print("blocked by policy: " + ", ".join(reasons), file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
