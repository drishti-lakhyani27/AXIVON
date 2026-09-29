"""AXIVON — Semantic normalization: parsed payloads → canonical event.

Merges parser output + unknown-format onboarding into the canonical AXIVON
event model. Only derivable fields are set; everything else stays None.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import models


def normalize(
    raw: str,
    detection: Dict[str, Any],
    parsed: Optional[Dict[str, Any]],
    onboarding: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build a canonical event dict (pre-hash, pre-validation)."""
    event: Dict[str, Any] = {
        "event_id": models.new_event_id(),
        "timestamp": None,
        "source": {"vendor": None, "product": None, "format": detection["format"]},
        "network": {},
        "network_protocol": None,
        "action": None,
        "policy_id": None,
        "severity": None,
        "signature_id": None,
        "user": None,
        "host": None,
        "message": None,
        "fields": {},
        "raw_sha256": None,
        "provenance": [],
        "confidence": {},
    }

    provenance: List[Dict[str, Any]] = list(parsed["provenance"]) if parsed else []
    fields = parsed["fields"] if parsed else {}
    confidences: Dict[str, float] = {}

    if onboarding:
        for stage in onboarding.get("stages", []):
            pass  # stages kept for the UI flow, not merged into the event
        fields = _merge_fields(fields, onboarding.get("fields", {}))
        provenance.extend(onboarding.get("provenance", []))

    # Route merged fields into canonical slots
    network = {}
    for key, value in fields.items():
        if key == "network":
            network.update(value or {})
        elif key == "source" and isinstance(value, dict):
            # merge into the canonical source block without clobbering format
            for sk, sv in value.items():
                if sk in ("vendor", "product") and sv is not None:
                    event["source"][sk] = event["source"].get(sk) or sv
        elif key == "extra":
            event["fields"]["extra"] = value
        else:
            event[key] = value

    event["network"] = network
    event["provenance"] = provenance
    event["confidence"] = confidences

    # Parser-level outputs
    if parsed:
        event["timestamp"] = parsed.get("timestamp")
        event["source"]["vendor"] = parsed.get("vendor")
        event["source"]["product"] = parsed.get("product")
        event["message"] = parsed.get("message")
        if parsed.get("host"):
            event["host"] = parsed["host"]

    # Per-field confidence from provenance records
    for rec in provenance:
        cf = rec.get("canonical_field")
        if cf and rec.get("confidence") is not None and cf not in confidences:
            confidences[cf] = rec["confidence"]

    event["confidence"] = confidences
    return event


def _merge_fields(base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    """Merge parser fields with onboarding fields (onboarding wins on conflicts)."""
    merged = dict(base)
    for key, value in extra.items():
        if key == "network" and isinstance(value, dict):
            net = dict(merged.get("network") or {})
            net.update(value)
            merged["network"] = net
        elif key == "source" and isinstance(value, dict):
            src = dict(merged.get("source") or {})
            src.update(value)
            merged["source"] = src
        else:
            merged[key] = value
    return merged
