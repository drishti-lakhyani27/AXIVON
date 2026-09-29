"""AXIVON — FastAPI application.

Wires the full pipeline:
INGEST → PRESERVE → DETECT → PARSE → NORMALIZE → VALIDATE → PROVE → EXPORT

Endpoints:
    GET  /api/health        service + pipeline status
    GET  /api/samples       built-in sample inputs
    POST /api/process       full pipeline on one raw event
    POST /api/batch         multi-event batch + Merkle root
    POST /api/verify-hash   verify a raw SHA-256
    POST /api/verify-merkle verify a Merkle root from leaf hashes

Also serves the static frontend from ../frontend at /.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import detector, integrity, models, normalizer, parser, provenance, unknown, validator

app = FastAPI(
    title="AXIVON",
    description="Universal Lossless Cyber Event Intelligence Fabric — local prototype",
    version="0.1.0",
)

FRONTEND_DIR = pathlib.Path(__file__).resolve().parent.parent / "frontend"
SAMPLES_DIR = pathlib.Path(__file__).resolve().parent.parent / "samples"

# ---------------------------------------------------------------------------
# Built-in samples
# ---------------------------------------------------------------------------

SAMPLES: Dict[str, Dict[str, str]] = {
    "syslog": {
        "label": "Syslog (RFC 3164)",
        "format_hint": "SYSLOG",
        "content": "<134>May  1 10:31:07 fw-edge01 secuwall: action=DROP src=203.0.113.45 spt=51500 dst=198.51.100.10 dpt=22 proto=TCP policy=P-101",
    },
    "cef": {
        "label": "CEF (ArcSight)",
        "format_hint": "CEF",
        "content": (
            "CEF:0|Cyberdyne|FireWall-X|12.1|100|Port scan detected|7|"
            "src=203.0.113.45 spt=51500 dst=198.51.100.10 dpt=22 proto=TCP act=BLOCK cs1=P-101 cs1Label=PolicyID"
        ),
    },
    "leef": {
        "label": "LEEF (IBM QRadar)",
        "format_hint": "LEEF",
        "content": (
            "LEEF:2.0|SemperFire|Perimeter-500|1.0|90011|"
            "src=203.0.113.45\tdst=198.51.100.10\tproto=TCP\tusrName=j.doe\tsev=5"
        ),
    },
    "json": {
        "label": "JSON (custom SIEM export)",
        "format_hint": "JSON",
        "content": json.dumps({
            "timestamp": "2026-05-01T10:31:07Z",
            "vendor": "Aegis",
            "product": "SensorMesh",
            "src_ip": "203.0.113.45",
            "src_port": 51500,
            "dst_ip": "198.51.100.10",
            "dst_port": 22,
            "proto": "TCP",
            "action": "BLOCK",
            "policy_id": "P-101",
            "severity": "high",
            "signature_id": "SCAN-H-77",
            "user": "j.doe",
            "message": "SSH brute force pattern matched",
        }, indent=2),
    },
    "xml": {
        "label": "XML (legacy appliance)",
        "format_hint": "XML",
        "content": (
            "<Event>\n  <timestamp>2026-05-01T10:31:07Z</timestamp>\n"
            "  <src>203.0.113.45</src>\n  <dst>198.51.100.10</dst>\n"
            "  <proto>TCP</proto>\n  <action>deny</action>\n"
            "  <message>Policy P-101 violation</message>\n</Event>"
        ),
    },
    "unknown": {
        "label": "UNKNOWN / custom (FW-X)",
        "format_hint": "UNKNOWN",
        "content": "FW-X|BLK|TCP|10.2.1.5|443|10.5.2.8|53|P17",
    },
    "unknown_warning": {
        "label": "UNKNOWN / custom (odd ports, warning)",
        "format_hint": "UNKNOWN",
        "content": "FW-Z|ALLOW|UDP|10.44.9.2|70000|10.44.9.9|99999|P77",
    },
}


def _load_sample_files() -> None:
    """Override built-in samples with sample/ files when present (same keys)."""
    if not SAMPLES_DIR.exists():
        return
    mapping = {
        "syslog": "syslog.log", "cef": "cef.log", "leef": "leef.log",
        "json": "sample.json", "xml": "sample.xml", "unknown": "unknown.log",
        "unknown_warning": "unknown_warning.log",
    }
    for key, filename in mapping.items():
        path = SAMPLES_DIR / filename
        if path.exists():
            try:
                SAMPLES[key]["content"] = path.read_text(encoding="utf-8").rstrip("\n")
            except OSError:
                pass


_load_sample_files()


# ---------------------------------------------------------------------------
# Pipeline core
# ---------------------------------------------------------------------------

def run_pipeline(raw: str, batch_event_id: Optional[str] = None) -> Dict[str, Any]:
    """Full AXIVON pipeline for one raw event. Returns a dict matching
    ProcessResponse."""
    raw_event = raw.rstrip("\n")   # preserve content; trailing newline is transport
    raw_sha256 = integrity.sha256_hex(raw_event)

    # 1. PRESERVE (raw kept verbatim) → 2. DETECT
    detection = detector.detect_format(raw_event)

    # 3. PARSE
    parse_steps: List[Dict[str, Any]] = []
    parsed: Optional[Dict[str, Any]] = None
    if detection["format"] in ("JSON", "CEF", "LEEF", "SYSLOG", "XML"):
        try:
            parsed = parser.parse_event(raw_event, detection["format"])
            parse_steps.append({"parser": detection["format"], "status": "ok", "detail": None})
        except (ValueError, json.JSONDecodeError) as exc:
            parse_steps.append({"parser": detection["format"], "status": "failed",
                                "detail": str(exc)})
            parsed = None

    # UNKNOWN → onboarding (deterministic heuristics)
    onboarding = None
    understood = parsed is not None
    if detection["format"] == "UNKNOWN":
        onboarding = unknown.onboard(raw_event)
        understood = onboarding["understood"]
        parse_steps.append({"parser": "unknown-onboarding", "status": "ok",
                            "detail": "deterministic heuristic structure/semantic discovery"})

    # 4. NORMALIZE
    canonical = normalizer.normalize(raw_event, detection, parsed, onboarding)
    canonical["raw_sha256"] = raw_sha256
    if batch_event_id:
        canonical["event_id"] = batch_event_id

    # 5. VALIDATE
    validation = validator.validate_event(canonical, detection)

    # 6. PROVE (hashes) — canonical hash computed on the canonical event
    canonical_hash = integrity.canonical_hash(canonical)

    return {
        "event_id": canonical["event_id"],
        "preserved": True,
        "raw_evidence": raw_event,
        "raw_sha256": raw_sha256,
        "format_detection": detection,
        "parse": parse_steps,
        "canonical_event": canonical,
        "provenance": provenance.to_table(canonical["provenance"]),
        "validation": validation,
        "integrity": {
            "raw_sha256": raw_sha256,
            "canonical_sha256": canonical_hash,
            "event_id": canonical["event_id"],
            "algorithm": "sha256",
        },
        "processed_at": models.now_iso_utc(),
        "understood": understood,
        "onboarding": (
            {"stages": onboarding["stages"], "method": onboarding["method"],
             "detail": onboarding["detail"], "understood": onboarding["understood"]}
            if onboarding else None
        ),
    }


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health", response_model=models.HealthResponse)
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "AXIVON",
        "version": "0.1.0",
        "pipeline": ["INGEST", "PRESERVE", "DETECT", "PARSE", "NORMALIZE",
                     "VALIDATE", "PROVE", "EXPORT"],
        "timestamp": models.now_iso_utc(),
    }


@app.get("/api/samples", response_model=models.SamplesResponse)
def samples() -> Dict[str, Any]:
    return {
        "samples": [
            {"key": key, "label": s["label"], "format_hint": s["format_hint"],
             "content": s["content"]}
            for key, s in SAMPLES.items()
        ]
    }


@app.post("/api/process", response_model=models.ProcessResponse)
def process_event(body: Dict[str, Any]) -> Dict[str, Any]:
    raw = body.get("raw_event") if isinstance(body, dict) else None
    if not isinstance(raw, str) or not raw.strip():
        raise HTTPException(status_code=422, detail="raw_event must be a non-empty string")
    try:
        return run_pipeline(raw)
    except Exception as exc:  # defensive: never leak a half-state silently
        raise HTTPException(status_code=500, detail=f"pipeline error: {exc}") from exc


@app.post("/api/batch", response_model=models.BatchResponse)
def process_batch(body: Dict[str, Any]) -> Dict[str, Any]:
    raw_events = body.get("raw_events") if isinstance(body, dict) else None
    if not isinstance(raw_events, list) or not raw_events:
        raise HTTPException(status_code=422, detail="raw_events must be a non-empty list")
    if len(raw_events) > 200:
        raise HTTPException(status_code=422, detail="batch limited to 200 events in prototype")

    events: List[Dict[str, Any]] = []
    leaf_hashes: List[str] = []
    for i, raw in enumerate(raw_events):
        if not isinstance(raw, str) or not raw.strip():
            raise HTTPException(status_code=422, detail=f"raw_events[{i}] must be a non-empty string")
        result = run_pipeline(raw)
        leaf_hashes.append(result["raw_sha256"])
        events.append({
            "raw": result["raw_evidence"],
            "raw_sha256": result["raw_sha256"],
            "event_id": result["event_id"],
            "format": result["format_detection"]["format"],
            "canonical_sha256": result["integrity"]["canonical_sha256"],
            "validation": result["validation"]["result"],
        })

    tree = integrity.verify_leaf_batch(leaf_hashes, integrity.root_from_leaves(leaf_hashes))
    verification = dict(tree["verification"])
    verification["levels"] = tree["levels"]
    return {
        "processed": len(events),
        "events": events,
        "leaf_hashes": leaf_hashes,
        "merkle_root": tree["root"],
        "algorithm": "sha256",
        "verification": verification,
    }


@app.post("/api/verify-hash", response_model=models.HashVerifyResponse)
def verify_hash(body: Dict[str, Any]) -> Dict[str, Any]:
    raw = body.get("raw_event")
    expected = body.get("expected_sha256")
    if not isinstance(raw, str) or not isinstance(expected, str):
        raise HTTPException(status_code=422,
                            detail="raw_event and expected_sha256 must be strings")
    computed = integrity.sha256_hex(raw.rstrip("\n"))
    return {
        "matches": computed == expected.strip().lower(),
        "computed_sha256": computed,
        "expected_sha256": expected.strip().lower(),
        "algorithm": "sha256",
    }


@app.post("/api/verify-merkle", response_model=models.MerkleVerifyResponse)
def verify_merkle(body: Dict[str, Any]) -> Dict[str, Any]:
    leaves = body.get("leaf_hashes")
    root = body.get("root")
    if not isinstance(leaves, list) or not leaves or not isinstance(root, str):
        raise HTTPException(status_code=422,
                            detail="leaf_hashes (non-empty list) and root (string) required")
    for i, leaf in enumerate(leaves):
        if not isinstance(leaf, str) or len(leaf) != 64:
            raise HTTPException(status_code=422, detail=f"leaf_hashes[{i}] must be a 64-char sha256 hex")
    if len(root) != 64:
        raise HTTPException(status_code=422, detail="root must be a 64-char sha256 hex")
    tree = integrity.verify_leaf_batch(leaves, root)
    return {
        "verified": tree["verification"]["verified"],
        "root": root,
        "leaf_count": len(leaves),
        "method": tree["verification"]["method"],
    }


# ---------------------------------------------------------------------------
# Static frontend (mounted last so /api takes precedence)
# ---------------------------------------------------------------------------

@app.get("/")
def index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
