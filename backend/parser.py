"""AXIVON — Parsers for JSON, CEF, LEEF, Syslog and XML.

Each parser returns a flat dict of extracted fields plus a provenance list
recording exactly where every value came from in the raw input. Parsers
NEVER fabricate data: when a value cannot be determined it stays absent.

Provenance record shape:
    {"canonical_field": ..., "source_field": ..., "source_value": ...,
     "method": "extracted" | "heuristic" | "derived", "confidence": float}
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from . import detector

# Heuristic confidences for EXTRACTED values (deterministic parser output).
CONF_EXACT = 1.0        # value taken verbatim from a labelled field
CONF_DERIVED = 0.95     # value derived by a documented rule (e.g. token position)


def _prov(canonical_field: str, source_field: str, source_value: Any,
          method: str = "extracted", confidence: float = CONF_EXACT) -> Dict[str, Any]:
    return {
        "canonical_field": canonical_field,
        "source_field": source_field,
        "source_value": source_value,
        "method": method,
        "confidence": confidence,
    }


CEF_KV_RE = re.compile(r"(\w+)=(.*?)(?=\s+\w+=|$)")


def _split_cep(value: str) -> List[str]:
    """Split a CEF extension into key/value strings.

    CEF extensions are space-separated key=value pairs; a value may contain
    an escaped equals (\\=). We split pair boundaries on the lookahead of a
    new key token, and unescape \\= inside values.
    """
    pairs: List[str] = []
    for m in CEF_KV_RE.finditer(value):
        key = m.group(1)
        val = m.group(2).strip().replace("\\=", "=")
        pairs.append(f"{key}={val}")
    return pairs


def _port(value: Any) -> Optional[int]:
    """Strict integer port; returns None for garbage (never guesses)."""
    try:
        p = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return p if 0 <= p <= 65535 else None


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

JSON_SEMANTIC_KEYS: Dict[str, tuple] = {
    # canonical field: (candidate keys, normalizer)
    "network.source_ip": (["src_ip", "source_ip", "src", "sourceAddress", "client_ip", "srcip"], "ip"),
    "network.source_port": (["src_port", "source_port", "sport", "sourcePort", "client_port"], "port"),
    "network.destination_ip": (["dst_ip", "dest_ip", "destination_ip", "dst", "dest", "destinationAddress", "target_ip"], "ip"),
    "network.destination_port": (["dst_port", "dest_port", "destination_port", "dport", "destinationPort"], "port"),
    "network_protocol": (["proto", "protocol", "network_protocol", "transport"], "upper"),
    "action": (["action", "act", "verdict", "decision", "disposition"], "lower"),
    "policy_id": (["policy_id", "policy", "rule_id", "rule", "policyid"], "str"),
    "severity": (["severity", "sev", "level", "priority"], "lower"),
    "signature_id": (["signature_id", "sig_id", "signature", "attack_id"], "str"),
    "user": (["user", "username", "user_name", "usr", "account"], "str"),
    "host": (["host", "hostname", "device", "hostname"], "str"),
    "message": (["message", "msg", "log", "description", "reason"], "str"),
    "timestamp": (["timestamp", "time", "event_time", "@timestamp", "datetime", "date"], "str"),
    "vendor": (["vendor"], "str"),
    "product": (["product", "device_product", "app"], "str"),
}


def _normalize_ip(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return s if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", s) else None


def parse_json(raw: str) -> Dict[str, Any]:
    data = json.loads(raw)
    if not isinstance(data, dict):
        return {"fields": {}, "provenance": [], "vendor": None, "product": None,
                "timestamp": None, "message": None}

    fields: Dict[str, Any] = {}
    provenance: List[Dict[str, Any]] = []
    out: Dict[str, Any] = {
        "fields": fields, "provenance": provenance,
        "vendor": None, "product": None, "timestamp": None, "message": None,
    }

    for canonical, (candidates, norm) in JSON_SEMANTIC_KEYS.items():
        for key in candidates:
            if key in data and data[key] is not None:
                value = data[key]
                if norm == "ip":
                    value = _normalize_ip(value)
                    if value is None:
                        continue  # don't guess: skip non-IP-shaped values
                elif norm == "port":
                    value = _port(value)
                    if value is None:
                        continue
                elif norm == "upper":
                    value = str(value).strip().upper() or None
                elif norm == "lower":
                    value = str(value).strip().lower() or None
                elif norm == "str":
                    value = str(value).strip() or None

                if value is None:
                    continue

                # route into the canonical slots
                if canonical.startswith("network."):
                    fields.setdefault("network", {})[canonical.split(".", 1)[1]] = value
                elif canonical == "timestamp":
                    out["timestamp"] = value
                elif canonical == "message":
                    out["message"] = value
                elif canonical == "vendor":
                    out["vendor"] = value
                elif canonical == "product":
                    out["product"] = value
                else:
                    fields[canonical] = value

                provenance.append(_prov(canonical, key, value))
                break  # first matching key wins

    # everything not mapped semantically is preserved verbatim in fields
    for key, value in data.items():
        if key not in {c for cand in JSON_SEMANTIC_KEYS.values() for c in cand[0]}:
            fields.setdefault("extra", {})[key] = value
    return out


# ---------------------------------------------------------------------------
# CEF
# ---------------------------------------------------------------------------

CEF_HEADER_RE = re.compile(
    r"^(?:<\d+>)?\d?\s*"                      # optional syslog PRI/timestamp prefix
    r"(?:[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}\s+\S+\s+)?"  # optional syslog stamp
    r"CEF:(?P<version>\d+)\|"
    r"(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<device_version>[^|]*)\|"
    r"(?P<signature_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|?(?P<extension>.*)$",
    re.DOTALL,
)

CEF_FIELD_MAP = {
    "src": ("network.source_ip", "ip"),
    "sourceAddress": ("network.source_ip", "ip"),
    "spt": ("network.source_port", "port"),
    "sourcePort": ("network.source_port", "port"),
    "dst": ("network.destination_ip", "ip"),
    "destinationAddress": ("network.destination_ip", "ip"),
    "dpt": ("network.destination_port", "port"),
    "destinationPort": ("network.destination_port", "port"),
    "proto": ("network_protocol", "upper"),
    "act": ("action", "lower"),
    "cs1": ("policy_id", "str"),
    "policyid": ("policy_id", "str"),
    "duser": ("user", "str"),
    "suser": ("user", "str"),
    "dvc": ("host", "str"),
    "shost": ("host", "str"),
}


def parse_cef(raw: str) -> Dict[str, Any]:
    m = CEF_HEADER_RE.search(raw)
    if not m:
        raise ValueError("CEF header not parseable")

    fields: Dict[str, Any] = {}
    provenance: List[Dict[str, Any]] = []
    extension = m.group("extension") or ""

    header_map = [
        ("signature_id", "CEF header:Signature ID", m.group("signature_id").strip(), "str"),
        ("severity", "CEF header:severity", m.group("severity").strip(), "lower"),
    ]
    for canon, src, value, norm in header_map:
        if value:
            if norm == "lower":
                value = value.lower()
            fields[canon] = value
            provenance.append(_prov(canon, src, value))

    # extension key=value pairs (escaped \= respected)
    for pair in _split_cep(extension):
        if "=" not in pair:
            continue
        key, _, raw_value = pair.partition("=")
        key = key.strip()
        value = raw_value.strip()
        if not key or not value:
            continue
        mapped = CEF_FIELD_MAP.get(key)
        if mapped:
            canon, norm = mapped
            if norm == "ip":
                value = _normalize_ip(value)
                if value is None:
                    continue
            elif norm == "port":
                value = _port(value)
                if value is None:
                    continue
            elif norm == "upper":
                value = value.upper()
            elif norm == "lower":
                value = value.lower()
            if canon.startswith("network."):
                fields.setdefault("network", {})[canon.split(".", 1)[1]] = value
            else:
                fields[canon] = value
            provenance.append(_prov(canon, f"CEF extension:{key}", value))
        else:
            fields.setdefault("extra", {})[key] = value

    return {
        "fields": fields,
        "provenance": provenance,
        "vendor": m.group("vendor").strip() or None,
        "product": m.group("product").strip() or None,
        "timestamp": None,   # CEF header carries no timestamp; syslog wrapper might
        "message": m.group("name").strip() or None,
    }


# ---------------------------------------------------------------------------
# LEEF
# ---------------------------------------------------------------------------

LEEF_HEADER_RE = re.compile(
    r"^LEEF:(?P<version>\d+\.\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|",
    re.DOTALL,
)

LEEF_FIELD_MAP = {
    "src": ("network.source_ip", "ip"),
    "srcPort": ("network.source_port", "port"),
    "dst": ("network.destination_ip", "ip"),
    "dstPort": ("network.destination_port", "port"),
    "proto": ("network_protocol", "upper"),
    "cat": ("category", "str"),
    "sev": ("severity", "lower"),
    "usrName": ("user", "str"),
    "username": ("user", "str"),
    "identHostName": ("host", "str"),
    "policy": ("policy_id", "str"),
}


def parse_leef(raw: str) -> Dict[str, Any]:
    m = LEEF_HEADER_RE.match(raw)
    if not m:
        raise ValueError("LEEF header not parseable")

    version = m.group("version")

    # LEEF 1.x/2.x: header fields are pipe-delimited through EventID, then the
    # extension follows. Per IBM spec the extension separator may be announced
    # as a leading char; in practice tabs (or spaces) separate key=value pairs.
    # Deterministic rule: non-alphanumeric leading char → that is the separator;
    # otherwise tab if present, else space. LEEF 3.x: 0x01 header separators,
    # tab extension separator.
    if version.startswith("3."):
        rest = raw[m.end():]
        device_version, _, remainder = rest.partition("|")
        event_id, _, ext_start = remainder.partition("|")
        sep = "\t"
        ext = ext_start
    else:
        parts = raw.split("|", 5)
        if len(parts) < 6:
            raise ValueError("LEEF header incomplete")
        device_version, event_id = parts[3], parts[4]
        ext = parts[5]
        if ext and not ext[0].isalnum() and ext[0] != "=":
            sep = ext[0]
            ext = ext[1:]
        elif "\t" in ext:
            sep = "\t"
        else:
            sep = " "

    rest = ext

    fields: Dict[str, Any] = {}
    provenance: List[Dict[str, Any]] = []

    for pair in rest.split(sep):
        if "=" not in pair:
            continue
        key, _, value = pair.partition("=")
        key = key.strip()
        value = value.strip()
        if not key or not value:
            continue
        mapped = LEEF_FIELD_MAP.get(key)
        if mapped:
            canon, norm = mapped
            if norm == "ip":
                value = _normalize_ip(value)
                if value is None:
                    continue
            elif norm == "port":
                value = _port(value)
                if value is None:
                    continue
            elif norm == "upper":
                value = value.upper()
            elif norm == "lower":
                value = value.lower()
            if canon.startswith("network."):
                fields.setdefault("network", {})[canon.split(".", 1)[1]] = value
            else:
                fields[canon] = value
            provenance.append(_prov(canon, f"LEEF extension:{key}", value))
        else:
            fields.setdefault("extra", {})[key] = value

    event_id = (event_id or "").strip()
    if event_id:
        # LEEF EventID is semantically a signature identifier; the AXIVON
        # event_id is generated by the fabric and must never be clobbered.
        fields["signature_id"] = event_id
        provenance.append(_prov("signature_id", "LEEF header:EventID", event_id))

    return {
        "fields": fields,
        "provenance": provenance,
        "vendor": m.group("vendor").strip() or None,
        "product": m.group("product").strip() or None,
        "timestamp": None,
        "message": event_id or None,
    }


# ---------------------------------------------------------------------------
# Syslog (RFC 3164 primary; RFC 5424 header extracted best-effort)
# ---------------------------------------------------------------------------

SYSLOG_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?P<host>\S+)\s+"
    r"(?P<proc>[^:\s\[]+)(?:\[(?P<pid>\d+)\])?:\s?"
    r"(?P<msg>.*)$",
    re.DOTALL,
)

SYSLOG_KV_RE = re.compile(r"(\w+)=(\S+)")

SYSLOG_KV_MAP = {
    "src": ("network.source_ip", "ip"),
    "srcip": ("network.source_ip", "ip"),
    "spt": ("network.source_port", "port"),
    "dst": ("network.destination_ip", "ip"),
    "dstip": ("network.destination_ip", "ip"),
    "dpt": ("network.destination_port", "port"),
    "proto": ("network_protocol", "upper"),
    "action": ("action", "lower"),
    "policy": ("policy_id", "str"),
    "user": ("user", "str"),
}


def parse_syslog(raw: str) -> Dict[str, Any]:
    m = SYSLOG_RE.match(raw.strip())
    if not m:
        raise ValueError("Syslog pattern not parseable")

    fields: Dict[str, Any] = {}
    provenance: List[Dict[str, Any]] = []
    msg = m.group("msg") or ""

    for key, value in SYSLOG_KV_RE.findall(msg):
        mapped = SYSLOG_KV_MAP.get(key.lower())
        if not mapped:
            continue
        canon, norm = mapped
        if norm == "ip":
            v = _normalize_ip(value.rstrip(",;"))
            if v is None:
                continue
            value = v
        elif norm == "port":
            v = _port(value.rstrip(",;"))
            if v is None:
                continue
            value = v
        elif norm == "upper":
            value = value.upper()
        elif norm == "lower":
            value = value.lower()
        if canon.startswith("network."):
            fields.setdefault("network", {})[canon.split(".", 1)[1]] = value
        else:
            fields[canon] = value
        provenance.append(_prov(canon, f"syslog message:{key}", value))

    host = m.group("host")
    if host:
        provenance.append(_prov("host", "syslog header:hostname", host))
    ts = m.group("ts")
    if ts:
        provenance.append(_prov("timestamp", "syslog header:timestamp", ts, confidence=0.9))

    # RFC 5424 PRI → facility/severity (documented derivation, not a guess)
    pri = m.group("pri")
    severity = None
    if pri is not None:
        sev_code = int(pri) % 8
        names = ["emergency", "alert", "critical", "error", "warning",
                 "notice", "informational", "debug"]
        severity = names[sev_code]
        fields["severity"] = severity
        provenance.append(_prov("severity", f"syslog PRI {pri} (facility*8+severity)",
                                severity, method="derived", confidence=CONF_DERIVED))

    proc = m.group("proc")
    return {
        "fields": fields,
        "provenance": provenance,
        "vendor": None,
        "product": proc,
        "timestamp": ts,
        "message": msg or None,
        "host": host,
    }


# ---------------------------------------------------------------------------
# XML (practical support)
# ---------------------------------------------------------------------------

TAG_RE = re.compile(r"<(?P<tag>[A-Za-z_][\w.\-]*)(?:\s[^>]*)?>(?P<text>[^<]*)</(?P=tag)>")

XML_TAG_MAP = {
    "src": ("network.source_ip", "ip"), "source_ip": ("network.source_ip", "ip"),
    "dst": ("network.destination_ip", "ip"), "dest": ("network.destination_ip", "ip"),
    "destination_ip": ("network.destination_ip", "ip"),
    "src_port": ("network.source_port", "port"), "spt": ("network.source_port", "port"),
    "dst_port": ("network.destination_port", "port"), "dpt": ("network.destination_port", "port"),
    "proto": ("network_protocol", "upper"), "protocol": ("network_protocol", "upper"),
    "action": ("action", "lower"), "verdict": ("action", "lower"),
    "policy": ("policy_id", "str"), "policy_id": ("policy_id", "str"),
    "user": ("user", "str"), "usrName": ("user", "str"),
    "host": ("host", "str"), "hostname": ("host", "str"),
    "message": ("message", "str"), "msg": ("message", "str"),
    "timestamp": ("timestamp", "str"), "time": ("timestamp", "str"),
    "severity": ("severity", "lower"), "vendor": ("vendor", "str"),
    "product": ("product", "str"), "signature": ("signature_id", "str"),
}


def parse_xml(raw: str) -> Dict[str, Any]:
    if not detector._looks_like_xml(raw.strip()):
        raise ValueError("not a well-formed XML document")
    fields: Dict[str, Any] = {}
    provenance: List[Dict[str, Any]] = []
    root = re.match(r"^<([A-Za-z_][\w.\-]*)", raw.strip())
    for m in TAG_RE.finditer(raw):
        tag, text = m.group("tag"), m.group("text").strip()
        if not text:
            continue
        mapped = XML_TAG_MAP.get(tag)
        if mapped:
            canon, norm = mapped
            if norm == "ip":
                value = _normalize_ip(text)
                if value is None:
                    fields.setdefault("extra", {})[tag] = text
                    continue
            elif norm == "port":
                value = _port(text)
                if value is None:
                    fields.setdefault("extra", {})[tag] = text
                    continue
            elif norm == "upper":
                value = text.upper()
            elif norm == "lower":
                value = text.lower()
            else:
                value = text
            if canon.startswith("network."):
                fields.setdefault("network", {})[canon.split(".", 1)[1]] = value
            else:
                fields[canon] = value
            provenance.append(_prov(canon, f"XML:<{tag}>", value, confidence=0.9))
        else:
            fields.setdefault("extra", {})[tag] = text
    return {
        "fields": fields,
        "provenance": provenance,
        "vendor": None,
        "product": root.group(1) if root else None,
        "timestamp": None,
        "message": None,
    }


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def parse_event(raw: str, fmt: str) -> Dict[str, Any]:
    """Dispatch to the parser for a detected format. Raises ValueError on
    malformed input of a known format."""
    if fmt == "JSON":
        return parse_json(raw)
    if fmt == "CEF":
        return parse_cef(raw)
    if fmt == "LEEF":
        return parse_leef(raw)
    if fmt == "SYSLOG":
        return parse_syslog(raw)
    if fmt == "XML":
        return parse_xml(raw)
    raise ValueError(f"no parser for detected format {fmt!r}")
