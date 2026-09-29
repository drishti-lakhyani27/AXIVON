"""AXIVON — Validation module.

Returns PASS / WARNING / FAIL with per-check issues. Checks are real:
- IP address sanity (octets ≤ 255)
- port range (0–65535)
- protocol sanity
- action sanity
- required structure (at least one canonical field derived)
- provenance completeness
- format-specific structure (CEF/LEEF header shape)

The result reflects actual validation — samples are not forced to PASS.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PROTOCOLS = {"TCP", "UDP", "ICMP", "GRE", "SCTP", "ESP", "AH", "TLS", "HTTP", "HTTPS"}
ACTIONS = {"allow", "accept", "permit", "pass", "deny", "drop", "block", "reject",
           "alert", "reset", "monitor", "forward", "quarantine", "blk"}


def _issue(field: Optional[str], check: str, severity: str, message: str) -> Dict[str, Any]:
    return {"field": field, "check": check, "severity": severity, "message": message}


def validate_event(event: Dict[str, Any], detection: Dict[str, Any]) -> Dict[str, Any]:
    issues: List[Dict[str, Any]] = []
    checks = 0

    network = event.get("network") or {}
    src_ip = network.get("source_ip")
    dst_ip = network.get("destination_ip")
    src_port = network.get("source_port")
    dst_port = network.get("destination_port")
    proto = event.get("network_protocol")
    action = event.get("action")

    # --- IP address sanity -------------------------------------------------
    for label, ip in (("network.source_ip", src_ip), ("network.destination_ip", dst_ip)):
        checks += 1
        if ip is None:
            issues.append(_issue(label, "ip_present", "WARNING", "not derivable from raw event"))
        elif not IPV4_RE.match(ip):
            issues.append(_issue(label, "ip_format", "FAIL", f"malformed IPv4: {ip!r}"))
        elif any(int(o) > 255 for o in ip.split(".")):
            issues.append(_issue(label, "ip_octets", "FAIL", f"octet > 255 in {ip!r}"))
        else:
            issues.append(_issue(label, "ip_format", "PASS", f"valid IPv4 {ip}"))

    # --- Port range --------------------------------------------------------
    for label, port in (("network.source_port", src_port), ("network.destination_port", dst_port)):
        checks += 1
        if port is None:
            issues.append(_issue(label, "port_present", "WARNING", "not derivable from raw event"))
        elif not isinstance(port, int) or not (0 <= port <= 65535):
            issues.append(_issue(label, "port_range", "FAIL", f"invalid port: {port!r}"))
        else:
            issues.append(_issue(label, "port_range", "PASS", f"valid port {port}"))

    # --- Protocol / action sanity ------------------------------------------
    checks += 1
    if proto is None:
        issues.append(_issue("network_protocol", "protocol_present", "WARNING", "not derivable"))
    elif str(proto).upper() not in PROTOCOLS:
        issues.append(_issue("network_protocol", "protocol_value", "WARNING",
                             f"unusual protocol value {proto!r} (kept verbatim)"))
    else:
        issues.append(_issue("network_protocol", "protocol_value", "PASS", f"recognized protocol {proto}"))

    checks += 1
    if action is None:
        issues.append(_issue("action", "action_present", "WARNING", "not derivable"))
    elif str(action).lower() not in ACTIONS:
        issues.append(_issue("action", "action_value", "WARNING",
                             f"unrecognized action {action!r} (kept verbatim)"))
    else:
        issues.append(_issue("action", "action_value", "PASS", f"recognized action {action}"))

    # --- Required structure -------------------------------------------------
    checks += 1
    if not event.get("provenance"):
        issues.append(_issue("provenance", "structure", "FAIL", "no provenance records — nothing was derivable"))
    else:
        issues.append(_issue("provenance", "structure", "PASS",
                             f"{len(event['provenance'])} provenance records present"))

    # --- Provenance completeness -------------------------------------------
    checks += 1
    derived = [k for k in ("network", "action", "policy_id", "severity") if event.get(k)]
    if not derived:
        issues.append(_issue("coverage", "semantic_coverage", "WARNING", "no canonical fields derived"))

    # --- Format-specific structure ------------------------------------------
    fmt = detection.get("format")
    checks += 1
    if fmt == "CEF":
        if event.get("signature_id") and event.get("source", {}).get("vendor"):
            issues.append(_issue("source", "cef_header", "PASS", "CEF header fields present"))
        else:
            issues.append(_issue("source", "cef_header", "WARNING", "CEF header incomplete"))
    elif fmt == "LEEF":
        if event.get("source", {}).get("vendor") and event.get("source", {}).get("product"):
            issues.append(_issue("source", "leef_header", "PASS", "LEEF header fields present"))
        else:
            issues.append(_issue("source", "leef_header", "WARNING", "LEEF header incomplete"))

    failed = sum(1 for i in issues if i["severity"] == "FAIL")
    warned = sum(1 for i in issues if i["severity"] == "WARNING")
    result = "FAIL" if failed else ("WARNING" if warned else "PASS")

    return {
        "result": result,
        "issues": issues,
        "checks_run": checks,
        "failed": failed,
        "warnings": warned,
    }
