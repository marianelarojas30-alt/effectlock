# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Marianela Bourgault
# Part of EffectLock, original source: https://github.com/marianelarojas30-alt/effectlock
# EffectLock-Origin: EL-MB-C8FBF0BBFB03BD6A
# This notice must be kept in all copies and modified versions (see LICENSE).
"""Read and write files beneath a project root without ever following a symlink.

This module is the only place in EffectLock that touches the filesystem for
trusted outputs (receipts) and trusted inputs (policies). Callers pass a root
directory and an already-validated relative path; the module walks the path one
directory at a time with ``O_NOFOLLOW`` file descriptors, so a symlink swapped in
at any level is refused instead of silently redirecting the read or write
outside the project. Every descriptor it opens is closed before it returns.

``what`` names the file in error messages ("policy", "receipt"), so each caller
keeps its own wording without re-implementing the walk. All failures raise
``ValueError`` with a message safe to show the user.
"""

from __future__ import annotations

import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def _require_posix(what: str, verb: str) -> None:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ValueError(f"secure {what} {verb} requires a POSIX platform with O_NOFOLLOW")


@contextmanager
def _parent_dir_fd(root: Path, rel: Path, what: str, create: bool) -> Iterator[int]:
    """Yield a no-follow descriptor for ``rel``'s parent directory beneath ``root``.

    Missing directories are created with mode 0700 when ``create`` is true.
    """
    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    opened = [os.open(root, dir_flags)]
    try:
        for part in rel.parts[:-1]:
            if part in {"", ".", ".."}:
                raise ValueError(f"invalid {what} path component")
            try:
                child = os.open(part, dir_flags, dir_fd=opened[-1])
            except FileNotFoundError:
                if not create:
                    raise ValueError(f"{what} path contains an unsafe directory") from None
                os.mkdir(part, mode=0o700, dir_fd=opened[-1])
                child = os.open(part, dir_flags, dir_fd=opened[-1])
            except OSError as exc:
                raise ValueError(f"{what} path contains an unsafe directory") from exc
            opened.append(child)
        yield opened[-1]
    finally:
        for fd in reversed(opened):
            try:
                os.close(fd)
            except OSError:
                pass


def read_bytes_under(root: Path, rel: Path, max_bytes: int, *, what: str) -> bytes:
    """Return the contents of ``root/rel``, a single-link regular file of at most ``max_bytes``.

    Refuses symlinks at any level, hard-linked files, special files, and files
    larger than ``max_bytes`` (checked both by size and by the bytes actually read).
    """
    _require_posix(what, "loading")
    unreadable = f"{what} file is not safely readable"
    with _parent_dir_fd(root.resolve(), rel, what, create=False) as dir_fd:
        try:
            fd = os.open(rel.parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
        except OSError as exc:
            raise ValueError(unreadable) from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes or st.st_nlink != 1:
                raise ValueError(unreadable)
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining > 0:
                chunk = os.read(fd, min(remaining, 16384))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > max_bytes:
                raise ValueError(unreadable)
            return raw
        finally:
            os.close(fd)


def write_bytes_atomic_under(root: Path, rel: Path, payload: bytes, *, what: str) -> Path:
    """Atomically replace ``root/rel`` with ``payload`` (mode 0600) and return its path.

    Missing parent directories are created (mode 0700). An existing target must be
    a regular file, never a symlink. The data is written to a temporary sibling,
    fsynced, then renamed over the target, so readers never see a partial file and
    a failure leaves no temporary file behind.
    """
    _require_posix(what, "writing")
    resolved_root = root.resolve()
    with _parent_dir_fd(resolved_root, rel, what, create=True) as dir_fd:
        filename = rel.parts[-1]
        try:
            st = os.stat(filename, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            st = None
        if st is not None and stat.S_ISLNK(st.st_mode):
            raise ValueError(f"{what} target must not be a symlink")
        if st is not None and not stat.S_ISREG(st.st_mode):
            raise ValueError(f"{what} target must be a regular file")

        tmp_name = f".{filename}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        fd = os.open(tmp_name, flags, 0o600, dir_fd=dir_fd)
        try:
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp_name, filename, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except BaseException:
            try:
                os.unlink(tmp_name, dir_fd=dir_fd)
            except OSError:
                pass
            raise
        os.fsync(dir_fd)
    return resolved_root / rel
