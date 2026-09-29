"""AXIVON — Canonical event model (Pydantic v2).

Defines the canonical AXIVON event plus the envelope returned by /api/process.
Only fields that can actually be derived from the raw input are populated;
everything else stays null or is omitted (never fabricated).
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


def new_event_id() -> str:
    return "evt-" + uuid.uuid4().hex[:16]


def now_iso_utc() -> str:
    # Local wall-clock processing timestamp (when AXIVON handled the event).
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"


# ---------------------------------------------------------------------------
# Canonical event model
# ---------------------------------------------------------------------------

class SourceInfo(BaseModel):
    vendor: Optional[str] = None
    product: Optional[str] = None
    format: Optional[str] = None


class NetworkInfo(BaseModel):
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None


class CanonicalEvent(BaseModel):
    event_id: str = Field(default_factory=new_event_id)
    timestamp: Optional[str] = None          # event time if derivable, else null
    source: SourceInfo = Field(default_factory=SourceInfo)
    network: NetworkInfo = Field(default_factory=NetworkInfo)
    network_protocol: Optional[str] = None
    action: Optional[str] = None
    policy_id: Optional[str] = None
    severity: Optional[str] = None
    signature_id: Optional[str] = None       # e.g. CEF signature id
    user: Optional[str] = None
    host: Optional[str] = None
    message: Optional[str] = None
    fields: Dict[str, Any] = Field(default_factory=dict)   # source-native extras
    raw_sha256: Optional[str] = None
    provenance: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pipeline sub-results
# ---------------------------------------------------------------------------

class FormatDetection(BaseModel):
    format: str                      # "JSON" | "CEF" | "LEEF" | "SYSLOG" | "UNKNOWN"
    confidence: float
    reason: str
    method: str = "deterministic signatures (prototype heuristics, not ML)"


class ParseStep(BaseModel):
    parser: str
    status: str                      # "ok" | "failed" | "skipped"
    detail: Optional[str] = None


class ValidationIssue(BaseModel):
    field: Optional[str] = None
    check: str
    severity: str                    # "PASS" | "WARNING" | "FAIL"
    message: str


class ValidationSummary(BaseModel):
    result: str                      # "PASS" | "WARNING" | "FAIL"
    issues: List[ValidationIssue] = Field(default_factory=list)
    checks_run: int = 0
    failed: int = 0
    warnings: int = 0


class ProvenanceRecord(BaseModel):
    canonical_field: str
    source_field: str
    source_value: Any = None
    value: Any = None
    method: str                      # "extracted" | "heuristic" | "derived"
    confidence: float


class IntegrityBlock(BaseModel):
    raw_sha256: Optional[str] = None
    canonical_sha256: Optional[str] = None
    event_id: Optional[str] = None
    algorithm: str = "sha256"


# ---------------------------------------------------------------------------
# API envelopes
# ---------------------------------------------------------------------------

class ProcessResponse(BaseModel):
    event_id: str
    preserved: bool
    raw_evidence: str
    raw_sha256: str
    format_detection: FormatDetection
    parse: List[ParseStep]
    canonical_event: CanonicalEvent
    provenance: List[ProvenanceRecord]
    validation: ValidationSummary
    integrity: IntegrityBlock
    processed_at: str
    understood: bool                 # True when pipeline produced a canonical event
    onboarding: Optional[Dict[str, Any]] = None   # unknown-format onboarding stages


class HashVerifyRequest(BaseModel):
    raw_event: str
    expected_sha256: str


class HashVerifyResponse(BaseModel):
    matches: bool
    computed_sha256: str
    expected_sha256: str
    algorithm: str = "sha256"


class MerkleVerifyRequest(BaseModel):
    leaf_hashes: List[str]
    root: str


class MerkleVerifyResponse(BaseModel):
    verified: bool
    root: str
    leaf_count: int
    method: str


class BatchEventResult(BaseModel):
    raw: str
    raw_sha256: str
    event_id: str
    format: str
    canonical_sha256: str
    validation: str


class BatchResponse(BaseModel):
    processed: int
    events: List[BatchEventResult]
    leaf_hashes: List[str]
    merkle_root: str
    algorithm: str = "sha256"
    verification: Dict[str, Any] = Field(default_factory=dict)


class SampleInfo(BaseModel):
    key: str
    label: str
    format_hint: str
    content: str


class SamplesResponse(BaseModel):
    samples: List[SampleInfo]


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    pipeline: List[str]
    timestamp: str
