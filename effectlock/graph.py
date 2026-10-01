# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Marianela Bourgault
# Part of EffectLock, original source: https://github.com/marianelarojas30-alt/effectlock
# EffectLock-Origin: EL-MB-C8FBF0BBFB03BD6A
# This notice must be kept in all copies and modified versions (see LICENSE).

from __future__ import annotations

import hashlib

from .core import EFFECTS, Prediction

_GENERIC_SOURCES = {"command semantics", "command text"}


def _source_id(source: str) -> str:
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:12]
    return f"source:{digest}"


def build_effect_graph(pred: Prediction) -> dict:
    """Build a deterministic graph without exposing script bodies."""
    nodes: list[dict] = [{"id": "command", "kind": "command", "label": "requested command"}]
    edges: list[dict] = []
    source_nodes: dict[str, str] = {}
    seen_edges: set[tuple[str, str, str, str]] = set()

    for effect in EFFECTS:
        if effect in pred.effects:
            nodes.append({"id": f"effect:{effect}", "kind": "effect", "label": effect})

    for ev in pred.evidence:
        target = f"effect:{ev.effect}"
        if ev.source in _GENERIC_SOURCES:
            key = ("command", target, "predicts", ev.confidence)
            if key not in seen_edges:
                seen_edges.add(key)
                edges.append({"from": "command", "to": target, "kind": "predicts", "confidence": ev.confidence})
            continue

        source_id = source_nodes.get(ev.source)
        if source_id is None:
            source_id = _source_id(ev.source)
            source_nodes[ev.source] = source_id

        activate = ("command", source_id, "activates", "high")
        if activate not in seen_edges:
            seen_edges.add(activate)
            edges.append({"from": "command", "to": source_id, "kind": "activates", "confidence": "high"})

        predicts = (source_id, target, "predicts", ev.confidence)
        if predicts not in seen_edges:
            seen_edges.add(predicts)
            edges.append({"from": source_id, "to": target, "kind": "predicts", "confidence": ev.confidence})

    for source, source_id in sorted(source_nodes.items()):
        nodes.append({"id": source_id, "kind": "source", "label": source})

    nodes.sort(key=lambda item: (0 if item["id"] == "command" else 1, item["kind"], item["id"]))
    edges.sort(key=lambda item: (item["from"], item["to"], item["kind"], item["confidence"]))
    return {"schema": "effectlock.graph.v1", "nodes": nodes, "edges": edges}


def render_effect_graph(pred: Prediction) -> tuple[str, ...]:
    lines: list[str] = []
    for ev in pred.evidence:
        if ev.source in _GENERIC_SOURCES:
            lines.append(f"command -> {ev.effect} [{ev.confidence}]")
        else:
            lines.append(f"command -> {ev.source} -> {ev.effect} [{ev.confidence}]")
    return tuple(dict.fromkeys(lines))
