# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Marianela Bourgault
# Part of EffectLock, original source: https://github.com/marianelarojas30-alt/effectlock
# EffectLock-Origin: EL-MB-C8FBF0BBFB03BD6A
# This notice must be kept in all copies and modified versions (see LICENSE).

from __future__ import annotations

import hashlib
import json
from typing import Any

from .core import Prediction
from .graph import build_effect_graph
from .policy import PolicyDecision
from .provenance import GENERATOR


def build_report(pred: Prediction, decision: PolicyDecision) -> dict[str, Any]:
    """Build the additive v0.2 report while preserving the v0.1 prediction hash."""
    body = pred.to_dict()
    body["graph"] = build_effect_graph(pred)
    body["policy"] = decision.to_dict()
    # Covered by report_sha256: editing the origin mark without rehashing is detectable.
    body["generator"] = dict(GENERATOR)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    body["report_sha256"] = hashlib.sha256(canonical).hexdigest()
    return body
