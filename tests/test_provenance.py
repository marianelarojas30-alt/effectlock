# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Marianela Bourgault
# Part of EffectLock, original source: https://github.com/marianelarojas30-alt/effectlock
# EffectLock-Origin: EL-MB-C8FBF0BBFB03BD6A
# This notice must be kept in all copies and modified versions (see LICENSE).

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from effectlock import ORIGIN_ID, PolicyConfig, build_report, evaluate_policy, predict
from effectlock.provenance import GENERATOR

ROOT = Path(__file__).resolve().parents[1]


class ProvenanceTests(unittest.TestCase):
    def test_every_source_file_carries_the_origin_notice(self):
        files = sorted([*ROOT.glob("effectlock/*.py"), *ROOT.glob("tests/*.py"), ROOT / "install.sh"])
        self.assertTrue(files)
        for path in files:
            head = "\n".join(path.read_text(encoding="utf-8").splitlines()[:8])
            with self.subTest(path=path.name):
                self.assertIn("Copyright (c) 2026 Marianela Bourgault", head)
                self.assertIn(f"EffectLock-Origin: {ORIGIN_ID}", head)
                self.assertIn("SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0", head)

    def test_license_keeps_required_notice(self):
        first = (ROOT / "LICENSE").read_text(encoding="utf-8").splitlines()[0]
        self.assertTrue(first.startswith("Required Notice: Copyright (c) 2026 Marianela Bourgault"))

    def test_report_carries_generator_and_hash_covers_it(self):
        pred = predict("echo hi", ROOT)
        body = build_report(pred, evaluate_policy(pred, [], PolicyConfig()))
        self.assertEqual(body["generator"], GENERATOR)
        stripped = {k: v for k, v in body.items() if k != "report_sha256"}
        stripped["generator"] = dict(stripped["generator"], author="someone else")
        tampered = hashlib.sha256(json.dumps(stripped, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertNotEqual(tampered, body["report_sha256"])

    def test_version_output_shows_notice(self):
        out = subprocess.run([sys.executable, "-c", "from effectlock.cli import main; main()", "--version"],
                             capture_output=True, text=True, cwd=ROOT)
        self.assertIn("Marianela Bourgault", out.stdout)


if __name__ == "__main__":
    unittest.main()
