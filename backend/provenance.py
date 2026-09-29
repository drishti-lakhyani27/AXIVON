"""AXIVON — Provenance helpers.

Field-level provenance records are produced by the parsers and by the
unknown-format onboarding; this module carries shared helpers:
formatting, sorting and merging provenance lists.
"""

from __future__ import annotations

from typing import Any, Dict, List


def merge_provenance(*groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge provenance groups (parser + onboarding) preserving order."""
    out: List[Dict[str, Any]] = []
    for group in groups:
        for rec in group or []:
            out.append(rec)
    return out


def to_table(provenance: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Render provenance as UI-ready rows for the CANONICAL FIELD / SOURCE FIELD
    / VALUE / METHOD / CONFIDENCE table."""
    rows: List[Dict[str, Any]] = []
    for rec in provenance or []:
        rows.append({
            "canonical_field": rec.get("canonical_field"),
            "source_field": rec.get("source_field"),
            "value": rec.get("source_value"),
            "method": rec.get("method"),
            "confidence": rec.get("confidence"),
        })
    return rows


def summarize(provenance: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate provenance stats used by the UI."""
    if not provenance:
        return {"count": 0, "methods": {}, "mean_confidence": None}
    methods: Dict[str, int] = {}
    total_conf = 0.0
    for rec in provenance:
        methods[rec.get("method", "unknown")] = methods.get(rec.get("method", "unknown"), 0) + 1
        total_conf += float(rec.get("confidence") or 0.0)
    return {
        "count": len(provenance),
        "methods": methods,
        "mean_confidence": round(total_conf / len(provenance), 3),
    }
