"""AXIVON — Format Intelligence (deterministic format detection).

Detects JSON, CEF, LEEF, Syslog and UNKNOWN using ordered deterministic
signatures. No randomness, no ML — every decision is explainable.

Detection order matters: specific signatures (CEF/LEEF) are checked before
generic ones (syslog/JSON) so a CEF line wrapped in syslog is still detected
as CEF (the CEF payload is the semantically meaningful part).
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Syslog heuristics
# ---------------------------------------------------------------------------

# RFC 5424: "<PRI>1 2024-05-01T12:00:00.000Z host app proc msgid [sd] msg"
RFC5424_RE = re.compile(
    r"^(?:<\d{1,3}>\d\s)?"                      # optional PRI + VERSION
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"      # ISO timestamp
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+"     # fractional + TZ
    r"\S+\s+\S+"                                # HOSTNAME APP-NAME
)

# RFC 3164: "May  1 12:00:00 host proc[pid]: msg" or ISO-variant
RFC3164_RE = re.compile(
    r"^(?:<\d{1,3}>)?"                          # optional PRI
    r"(?:[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}"   # "May  1 12:00:00"
    r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)"  # ISO-ish
    r"\s+\S+\s+"                                # HOSTNAME
    r"[^:\s\[]+(?:\[\d+\])?:"                   # PROCESS[pid]:
)

MONTHS = (
    "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_format(raw: str) -> Dict[str, Any]:
    """Return {"format", "confidence", "reason", "method"}.

    Confidence values are deterministic heuristic scores, not measured
    probabilities — they express signature strength.
    """
    text = raw.strip()
    if not text:
        return _result("UNKNOWN", 0.0, "empty input")

    # 1. JSON — must parse as object or array
    if text[0] in "{[":
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            parsed = None
        if isinstance(parsed, (dict, list)):
            kind = "object" if isinstance(parsed, dict) else "array"
            return _result("JSON", 0.98, f"valid JSON {kind} parsed")

    # 2. CEF — "CEF:Version|Device Vendor|..."
    if re.match(r"^CEF:\d+\|", text):
        return _result("CEF", 0.98, "CEF header detected: 'CEF:<version>|' prefix")

    # 3. LEEF — "LEEF:Version|Vendor|Product|..." (1.x/2.x bar-delimited, 3.x uses spaces)
    if re.match(r"^LEEF:[12]\.\d+\|", text):
        return _result("LEEF", 0.98, "LEEF header detected: 'LEEF:1.x|' or 'LEEF:2.x|' prefix")
    if re.match(r"^LEEF:3\.\d+\s", text):
        return _result("LEEF", 0.98, "LEEF header detected: 'LEEF:3.x ' carriage-return separated header")

    # 4. XML — well-formed document rooted by a tag (practical support)
    if text.startswith("<"):
        if _looks_like_xml(text):
            return _result("XML", 0.95, "well-formed XML document detected")

    # 5. Syslog-wrapped CEF/LEEF payloads: the payload is the semantically
    #    meaningful part, so classify by it (documented heuristic). Checked
    #    before the generic syslog patterns.
    embedded_cef = re.search(r"\bCEF:\d+\|", text)
    if embedded_cef:
        return _result("CEF", 0.85, "CEF payload detected inside syslog-style wrapper")
    embedded_leef = re.search(r"\bLEEF:[123]\.\d+[\| ]", text)
    if embedded_leef:
        return _result("LEEF", 0.85, "LEEF payload detected inside syslog-style wrapper")

    # 6. Syslog — RFC 3164 / RFC 5424 patterns
    if RFC5424_RE.match(text):
        return _result("SYSLOG", 0.92, "RFC 5424 syslog pattern (PRI/version + ISO timestamp + host)")
    if RFC3164_RE.match(text):
        return _result("SYSLOG", 0.90, "RFC 3164 syslog pattern (timestamp + host + process[pid]:)")

    # 6. Weak-signal ordering fallbacks before declaring UNKNOWN
    m = re.match(r"^CEF:[^\d|]", text)
    if m:
        return _result("CEF", 0.4, "'CEF:' prefix present but version malformed — treated as heuristic CEF match")

    # Generic syslog guess: starts with month name + day + time
    if re.match(rf"^(?:<\d{{1,3}}>)?(?:{MONTHS})\s+\d{{1,2}}\s\d{{2}}:\d{{2}}:\d{{2}}\s", text):
        return _result("SYSLOG", 0.55, "month-name + timestamp + host opening — heuristic syslog match")

    return _result("UNKNOWN", 0.0, "no known format signature matched")


def _looks_like_xml(text: str) -> bool:
    """Cheap structural check: paired root tag with matching close."""
    m = re.match(r"^<([A-Za-z_][\w.\-]*)" , text)
    if not m:
        return False
    root = m.group(1)
    close = f"</{root}>"
    # Reject self-closing / declaration-only strings; require the close tag.
    if close not in text:
        return False
    # Basic sanity: more than one tag-like token
    return len(re.findall(r"<[^>]+>", text)) >= 2


def _result(fmt: str, confidence: float, reason: str) -> Dict[str, Any]:
    return {
        "format": fmt,
        "confidence": confidence,
        "reason": reason,
        "method": "deterministic signatures (prototype heuristics, not ML)",
    }
