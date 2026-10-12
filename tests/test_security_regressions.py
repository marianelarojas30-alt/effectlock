# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Marianela Bourgault
# Part of EffectLock, original source: https://github.com/marianelarojas30-alt/effectlock
# EffectLock-Origin: EL-MB-C8FBF0BBFB03BD6A
# This notice must be kept in all copies and modified versions (see LICENSE).

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFOs")
class PolicySpecialFileTests(unittest.TestCase):
    def test_fifo_policy_is_rejected_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.mkfifo(root / "policy.json")
            code = """from pathlib import Path
from effectlock.policy import load_policy
import sys
try:
    load_policy(Path(sys.argv[1]), 'policy.json')
except ValueError:
    sys.exit(0)
sys.exit(1)
"""
            try:
                result = subprocess.run([sys.executable, "-c", code, directory], capture_output=True, timeout=2)
            except subprocess.TimeoutExpired:
                self.fail("Untrusted FIFO blocked the policy reader")
            self.assertEqual(result.returncode, 0, result.stderr.decode())
