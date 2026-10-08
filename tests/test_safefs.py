# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Marianela Bourgault
# Part of EffectLock, original source: https://github.com/marianelarojas30-alt/effectlock
# EffectLock-Origin: EL-MB-C8FBF0BBFB03BD6A
# This notice must be kept in all copies and modified versions (see LICENSE).

import os
import stat
import tempfile
import unittest
from pathlib import Path

from effectlock.safefs import read_bytes_under, write_bytes_atomic_under


@unittest.skipUnless(os.name == "posix", "safefs requires POSIX")
class SafeFsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.outside = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.tmp.cleanup()
        self.outside.cleanup()

    def test_read_returns_contents(self) -> None:
        (self.root / "sub").mkdir()
        (self.root / "sub" / "p.json").write_bytes(b"{}")
        self.assertEqual(read_bytes_under(self.root, Path("sub/p.json"), 100, what="policy"), b"{}")

    def test_read_refuses_symlinked_directory(self) -> None:
        (Path(self.outside.name) / "p.json").write_bytes(b"{}")
        (self.root / "alias").symlink_to(self.outside.name)
        with self.assertRaisesRegex(ValueError, "policy path contains an unsafe directory"):
            read_bytes_under(self.root, Path("alias/p.json"), 100, what="policy")

    def test_read_refuses_symlinked_file(self) -> None:
        target = Path(self.outside.name) / "p.json"
        target.write_bytes(b"{}")
        (self.root / "p.json").symlink_to(target)
        with self.assertRaisesRegex(ValueError, "policy file is not safely readable"):
            read_bytes_under(self.root, Path("p.json"), 100, what="policy")

    def test_read_refuses_hard_link_and_oversize(self) -> None:
        (self.root / "a.json").write_bytes(b"{}")
        os.link(self.root / "a.json", self.root / "b.json")
        with self.assertRaises(ValueError):
            read_bytes_under(self.root, Path("b.json"), 100, what="policy")
        (self.root / "big.json").write_bytes(b"x" * 101)
        with self.assertRaises(ValueError):
            read_bytes_under(self.root, Path("big.json"), 100, what="policy")

    def test_read_missing_directory_is_refused_not_created(self) -> None:
        with self.assertRaises(ValueError):
            read_bytes_under(self.root, Path("nope/p.json"), 100, what="policy")
        self.assertFalse((self.root / "nope").exists())

    def test_write_creates_private_dirs_and_file(self) -> None:
        path = write_bytes_atomic_under(self.root, Path("a/b/r.json"), b"1", what="receipt")
        self.assertEqual(path, self.root.resolve() / "a/b/r.json")
        self.assertEqual(path.read_bytes(), b"1")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.root / "a").stat().st_mode) & 0o077, 0)

    def test_write_replaces_existing_file_without_leftovers(self) -> None:
        write_bytes_atomic_under(self.root, Path("r.json"), b"old", what="receipt")
        write_bytes_atomic_under(self.root, Path("r.json"), b"new", what="receipt")
        self.assertEqual((self.root / "r.json").read_bytes(), b"new")
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["r.json"])

    def test_write_refuses_symlink_target_and_directory_target(self) -> None:
        (self.root / "r.json").symlink_to(Path(self.outside.name) / "x.json")
        with self.assertRaisesRegex(ValueError, "receipt target must not be a symlink"):
            write_bytes_atomic_under(self.root, Path("r.json"), b"1", what="receipt")
        self.assertFalse((Path(self.outside.name) / "x.json").exists())
        (self.root / "d.json").mkdir()
        with self.assertRaisesRegex(ValueError, "receipt target must be a regular file"):
            write_bytes_atomic_under(self.root, Path("d.json"), b"1", what="receipt")

    def test_write_refuses_symlinked_directory(self) -> None:
        (self.root / "alias").symlink_to(self.outside.name)
        with self.assertRaisesRegex(ValueError, "receipt path contains an unsafe directory"):
            write_bytes_atomic_under(self.root, Path("alias/r.json"), b"1", what="receipt")
        self.assertEqual(list(Path(self.outside.name).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
