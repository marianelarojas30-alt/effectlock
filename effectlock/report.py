from __future__ import annotations

import hashlib
import json
from typing import Any

from .core import Prediction
from .graph import build_effect_graph
from .policy import PolicyDecision


def build_report(pred: Prediction, decision: PolicyDecision) -> dict[str, Any]:
    """Build the additive v0.2 report while preserving the v0.1 prediction hash."""
    body = pred.to_dict()
    body["graph"] = build_effect_graph(pred)
    body["policy"] = decision.to_dict()
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    body["report_sha256"] = hashlib.sha256(canonical).hexdigest()
    return body
