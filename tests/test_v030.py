# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Marianela Bourgault
# Part of EffectLock, original source: https://github.com/marianelarojas30-alt/effectlock
# EffectLock-Origin: EL-MB-C8FBF0BBFB03BD6A
# This notice must be kept in all copies and modified versions (see LICENSE).

import json
import tempfile
import unittest
from pathlib import Path

from effectlock.core import predict


class CompoundAndToolsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def effects(self, cmd: str) -> set[str]:
        return set(predict(cmd, self.root).effects)

    def sources(self, cmd: str) -> set[str]:
        return {x.source for x in predict(cmd, self.root).evidence}

    def mcp_config(self, servers: dict, rel: str = ".mcp.json", key: str = "mcpServers") -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({key: servers}))

    # FR-9 compound commands and cd
    def test_compound_second_segment_is_expanded(self):
        self.assertTrue({"file", "network"}.issubset(self.effects("echo start && npm install")))

    def test_compound_without_spaces(self):
        self.assertIn("container", self.effects("true&&docker ps"))

    def test_compound_pipe_segment(self):
        self.assertIn("network", self.effects("echo x | git push"))

    def test_cd_into_subdir_reads_its_metadata(self):
        (self.root / "app").mkdir()
        (self.root / "app" / "package.json").write_text(json.dumps({"scripts": {"postinstall": "docker ps"}}))
        self.assertIn("app/package.json:scripts.postinstall", self.sources("cd app && npm install"))
        self.assertIn("container", self.effects("cd app && npm install"))

    def test_cd_outside_project_is_unknown(self):
        p = predict("cd /tmp && npm install", self.root)
        self.assertTrue(any("cd leaves the project" in u for u in p.unknowns))

    def test_cd_symlink_not_followed(self):
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        Path(outside.name, "package.json").write_text(json.dumps({"scripts": {"postinstall": "docker ps"}}))
        (self.root / "link").symlink_to(outside.name)
        p = predict("cd link && npm install", self.root)
        self.assertNotIn("container", p.effects)
        self.assertTrue(any("cd leaves the project" in u for u in p.unknowns))

    # FR-10 wrappers
    def test_wrapper_sudo_is_privileged(self):
        p = predict("sudo -u root rm -rf build", self.root)
        self.assertTrue(any("elevated privileges" in x.reason for x in p.evidence))
        self.assertIn("file", p.effects)

    def test_wrapper_sudo_expands_inner_command(self):
        self.assertIn("network", self.effects("sudo npm install"))

    def test_wrapper_env_assignment(self):
        e = self.effects("env NODE_ENV=production npm install")
        self.assertTrue({"environment", "network"}.issubset(e))

    def test_wrapper_shell_c_is_inspected(self):
        self.assertIn("container", self.effects("bash -c 'cd . && docker build .'"))

    def test_wrapper_nested_shell_depth_is_bounded(self):
        cmd = "echo hi"
        for _ in range(6):
            cmd = f"sh -c {json.dumps(cmd)}"
        p = predict(cmd, self.root)
        self.assertTrue(any("inspection depth" in u for u in p.unknowns))

    # FR-11 ephemeral runners
    def test_ephemeral_runner_npx(self):
        p = predict("npx -y cowsay hi", self.root)
        self.assertTrue({"process", "network", "file"}.issubset(set(p.effects)))
        self.assertTrue(any("not visible to static inspection" in u for u in p.unknowns))

    def test_ephemeral_runner_variants(self):
        for cmd in ("pnpm dlx create-vite", "yarn dlx x", "bunx x", "uvx ruff", "pipx run black", "npm exec x"):
            with self.subTest(cmd=cmd):
                self.assertIn("network", self.effects(cmd))

    # FR-12 tools
    def test_tools_agent_cli_maps_each_server(self):
        self.mcp_config({
            "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me"]},
            "gh": {"url": "https://api.example.test/mcp", "env": {"GITHUB_TOKEN": "secret-value"}},
            "db": {"command": "docker", "args": ["run", "-i", "db-mcp"]},
        })
        p = predict("claude", self.root)
        self.assertEqual(set(p.effects), {"process", "file", "environment", "network", "container", "mcp"})
        by_source = {}
        for ev in p.evidence:
            by_source.setdefault(ev.source, set()).add(ev.effect)
        self.assertEqual(by_source[".mcp.json:mcpServers.fs"], {"mcp", "process", "network", "file"})
        self.assertEqual(by_source[".mcp.json:mcpServers.gh"], {"mcp", "network", "environment"})
        self.assertEqual(by_source[".mcp.json:mcpServers.db"], {"mcp", "process", "container"})

    def test_tools_never_copy_secret_values_or_urls(self):
        self.mcp_config({"gh": {"url": "https://api.example.test/mcp", "env": {"GITHUB_TOKEN": "secret-value"}}})
        body = json.dumps(predict("codex exec fix", self.root).to_dict())
        self.assertNotIn("secret-value", body)
        self.assertNotIn("api.example.test", body)
        self.assertIn("GITHUB_TOKEN", body)

    def test_tools_vscode_servers_key(self):
        self.mcp_config({"x": {"url": "https://x.test"}}, rel=".vscode/mcp.json", key="servers")
        self.assertIn(".vscode/mcp.json:servers.x", self.sources("gemini"))

    def test_tools_agent_without_config_is_unknown(self):
        p = predict("claude -p 'fix tests'", self.root)
        self.assertNotIn("mcp", p.effects)
        self.assertTrue(any("user-level MCP tools" in u for u in p.unknowns))

    def test_tools_symlinked_config_not_read(self):
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        target = Path(outside.name, "mcp.json")
        target.write_text(json.dumps({"mcpServers": {"x": {"url": "https://x.test"}}}))
        (self.root / ".mcp.json").symlink_to(target)
        self.assertNotIn(".mcp.json:mcpServers.x", self.sources("claude"))

    def test_tools_non_agent_command_does_not_read_config(self):
        self.mcp_config({"db": {"command": "docker"}})
        self.assertNotIn("container", self.effects("ls"))


if __name__ == "__main__":
    unittest.main()
