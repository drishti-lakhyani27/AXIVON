"""AXIVON — Unknown-format onboarding (deterministic heuristics).

Given a raw event with no recognized format signature, discover structure
and propose a semantic mapping. Everything here is deterministic string /
regex logic — clearly labelled "prototype heuristic onboarding", NOT ML.

Example input:  FW-X|BLK|TCP|10.2.1.5|443|10.5.2.8|53|P17

Stages: FINGERPRINT → STRUCTURE DISCOVERY → SEMANTIC MAPPING → VALIDATION
Each stage returns structured, explainable output for the UI flow.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
PROTO_RE = re.compile(r"^(?:TCP|UDP|ICMP|GRE|SCTP|ESP|AH)$", re.IGNORECASE)
PORT_RE = re.compile(r"^\d{1,5}$")
ACTION_RE = re.compile(
    r"^(?:BLK|BLOCK|DENY|DROP|REJ|REJECT|ALLOW|ACCEPT|PERMIT|PASS|"
    r"ALERT|MONITOR|RESET|FORWARD|QUAR|QUARANTINE)$",
    re.IGNORECASE,
)
POLICY_RE = re.compile(r"^(?:P|POL|POLICY)[-_]?\d+$", re.IGNORECASE)
SESSION_RE = re.compile(r"^(?:S|SES|SESSION)[-_]?\d+$", re.IGNORECASE)

# Deterministic heuristic confidences for the FW-X demo. These are fixed
# scores chosen by the engineer (documented heuristics), NOT measured
# probabilities and NOT ML outputs.
CONF_TOKEN_IP = 0.94
CONF_TOKEN_PORT = 0.88
CONF_TOKEN_PROTO = 0.96
CONF_TOKEN_ACTION = 0.92
CONF_TOKEN_POLICY = 0.90

METHOD = "prototype heuristic onboarding (deterministic, not ML)"


def fingerprint(raw: str) -> Dict[str, Any]:
    """Stage 1 — FINGERPRINT: structural signature of the raw line."""
    tokens = [t for t in raw.split("|")]
    nonempty = [t for t in tokens if t.strip()]
    fp = {
        "delimiter": "|" if "|" in raw else ("space" if " " in raw else "none"),
        "token_count": len(nonempty),
        "has_ipv4": bool(IPV4_RE.search(raw)),
        "has_port_range": bool(re.search(r"\b\d{1,5}\b", raw)),
        "ipv4_count": len(IPV4_RE.findall(raw)),
        "alpha_tokens": [t for t in nonempty if t.isalpha()],
        "alphanumeric_tokens": [t for t in nonempty if re.fullmatch(r"[A-Za-z]+\d+", t)],
    }
    return {
        "stage": "FINGERPRINT",
        "detail": (
            f"pipe-delimited structure with {fp['token_count']} tokens; "
            f"{fp['ipv4_count']} IPv4 address(es) present"
        ),
        "fingerprint": fp,
        "method": METHOD,
    }


def discover_structure(raw: str) -> Dict[str, Any]:
    """Stage 2 — STRUCTURE DISCOVERY: delimiter, arity, token typing."""
    tokens = [t.strip() for t in raw.split("|") if t.strip()]
    token_types = []
    for t in tokens:
        if IPV4_RE.fullmatch(t):
            token_types.append({"token": t, "inferred_type": "ipv4"})
        elif PROTO_RE.fullmatch(t):
            token_types.append({"token": t, "inferred_type": "protocol"})
        elif PORT_RE.fullmatch(t) and len(t) <= 5:
            token_types.append({"token": t, "inferred_type": "port"})
        elif ACTION_RE.fullmatch(t):
            token_types.append({"token": t, "inferred_type": "action"})
        elif POLICY_RE.fullmatch(t):
            token_types.append({"token": t, "inferred_type": "policy_id"})
        elif SESSION_RE.fullmatch(t):
            token_types.append({"token": t, "inferred_type": "session_id"})
        else:
            token_types.append({"token": t, "inferred_type": "identifier"})

    return {
        "stage": "STRUCTURE DISCOVERY",
        "detail": f"delimiter='|', {len(tokens)} tokens typed",
        "tokens": token_types,
        "method": METHOD,
    }


def map_semantics(raw: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Stage 3 — SEMANTIC MAPPING: propose canonical fields for tokens.

    Position-based network mapping (documented heuristic):
        token[2] = protocol, token[3] = src_ip, token[4] = src_port,
        token[5] = dst_ip, token[6] = dst_port
    """
    tokens = [t.strip() for t in raw.split("|") if t.strip()]
    fields: Dict[str, Any] = {}
    provenance: List[Dict[str, Any]] = []

    def add(canon: str, source_field: str, value: Any, conf: float) -> None:
        if value is None:
            return
        if canon.startswith("network."):
            fields.setdefault("network", {})[canon.split(".", 1)[1]] = value
        else:
            fields[canon] = value
        provenance.append({
            "canonical_field": canon,
            "source_field": source_field,
            "source_value": value,
            "method": "heuristic",
            "confidence": conf,
        })

    # vendor/product heuristic: leading identifier token (stored nested so the
    # normalizer can merge it into the canonical source block)
    if tokens and re.fullmatch(r"[A-Za-z][\w-]*", tokens[0]):
        fields.setdefault("source", {})
        fields["source"]["vendor"] = tokens[0]
        fields["source"]["product"] = tokens[0]
        provenance.append({
            "canonical_field": "source.vendor",
            "source_field": "token[0]",
            "source_value": tokens[0],
            "method": "heuristic",
            "confidence": CONF_TOKEN_POLICY,
        })
        provenance.append({
            "canonical_field": "source.product",
            "source_field": "token[0]",
            "source_value": tokens[0],
            "method": "heuristic",
            "confidence": CONF_TOKEN_POLICY,
        })

    if len(tokens) > 2 and PROTO_RE.fullmatch(tokens[2]):
        add("network_protocol", "token[2]", tokens[2].upper(), CONF_TOKEN_PROTO)
    if len(tokens) > 3 and IPV4_RE.fullmatch(tokens[3]):
        add("network.source_ip", "token[3]", tokens[3], CONF_TOKEN_IP)
    if len(tokens) > 4 and PORT_RE.fullmatch(tokens[4]) and len(tokens[4]) <= 5:
        port = int(tokens[4])
        if 0 <= port <= 65535:
            add("network.source_port", "token[4]", port, CONF_TOKEN_PORT)
    if len(tokens) > 5 and IPV4_RE.fullmatch(tokens[5]):
        add("network.destination_ip", "token[5]", tokens[5], CONF_TOKEN_IP)
    if len(tokens) > 6 and PORT_RE.fullmatch(tokens[6]) and len(tokens[6]) <= 5:
        port = int(tokens[6])
        if 0 <= port <= 65535:
            add("network.destination_port", "token[6]", port, CONF_TOKEN_PORT)
    if len(tokens) > 1 and ACTION_RE.fullmatch(tokens[1]):
        add("action", "token[1]", tokens[1].upper(), CONF_TOKEN_ACTION)
    if len(tokens) > 7 and POLICY_RE.fullmatch(tokens[7]):
        add("policy_id", "token[7]", tokens[7].upper(), CONF_TOKEN_POLICY)

    return fields, provenance


def onboard(raw: str) -> Dict[str, Any]:
    """Full unknown-format onboarding flow for one raw event."""
    fp = fingerprint(raw)
    structure = discover_structure(raw)
    fields, provenance = map_semantics(raw)
    understood = bool(provenance)
    return {
        "stages": [fp, structure],
        "fields": fields,
        "provenance": provenance,
        "understood": understood,
        "method": METHOD,
        "detail": (
            "Unknown format: deterministic heuristics proposed a semantic mapping. "
            "No ML involved. An operator would review and register this mapping "
            "before production use."
        ),
    }
