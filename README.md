# AXIVON

**Universal Lossless Cyber Event Intelligence Fabric**

> UNKNOWN → UNDERSTOOD

AXIVON is a preprocessing fabric for heterogeneous cybersecurity telemetry.
It sits **between** raw security event sources (firewalls, routers, IDS/IPS,
WAF, VPN, proxy, SIEM exports, custom appliances) and downstream consumers
(SIEM, data lakes, analytics, AI/ML pipelines).

AXIVON is **not a SIEM**. It does not correlate, alert, or store long-term.
It does one thing with cryptographic discipline: turn arbitrary, unknown
security events into **understood, validated, provably-intact canonical
events** — without ever losing or altering the original evidence.

This repository contains a **local working prototype**. Everything it claims
is implemented and tested; everything else is explicitly labelled
**TARGET / FUTURE ARCHITECTURE** (see §12).

---

## 1. Problem

Security telemetry arrives in dozens of incompatible formats: CEF, LEEF,
syslog dialects, vendor JSON, XML exports, and completely proprietary
one-off formats like:

```
FW-X|BLK|TCP|10.2.1.5|443|10.5.2.8|53|P17
```

Downstream systems (SIEM, data lakes, ML models) need consistent, structured,
trustworthy events. Traditional pipelines silently drop or transform the raw
input — so when a parser misreads a value, **nobody can prove what the source
actually said**, or where each normalized field came from.

## 2. Solution

AXIVON guarantees three things for every event:

| Principle | Meaning | Mechanism in this prototype |
|---|---|---|
| **UNDERSTAND** | Detect, parse, normalize | Deterministic format detection → format parsers → canonical event model |
| **PRESERVE** | Never lose the original | Raw evidence kept verbatim + SHA-256 seal |
| **PROVE** | Make everything checkable | Field-level provenance, canonical hash, Merkle batch root, verification endpoints |

## 3. Pipeline

```
SOURCE → INGEST → PRESERVE RAW EVIDENCE → FORMAT INTELLIGENCE → PARSE
       → SEMANTIC NORMALIZATION → VALIDATION → PROVENANCE → INTEGRITY
       → CANONICAL EVENT → EXPORT
```

The UI visualizes this as INGEST → PRESERVE → DETECT → PARSE → NORMALIZE →
VALIDATE → PROVE, and every stage is executed by the backend — the frontend
renders only backend responses.

## 4. Supported formats (current prototype)

| Format | Detection | Parsing |
|---|---|---|
| JSON | valid JSON object/array (0.98) | semantic key mapping + verbatim extras |
| CEF | `CEF:<ver>|` header (0.98; 0.85 inside syslog wrapper) | header + escaped extension k/v |
| LEEF | `LEEF:1.x/2.x|` / `LEEF:3.x ` headers (0.98) | header + extension k/v |
| Syslog | RFC 5424 / RFC 3164 patterns (0.92/0.90) | PRI→severity derivation, k/v payload |
| XML | well-formed paired root tag (0.95) | tag→semantic mapping |
| UNKNOWN | no signature matched (0.0) | deterministic heuristic onboarding |

Confidence values are **deterministic heuristic scores** chosen per signature
strength — they are not measured probabilities and there is **no ML**.

## 5. Unknown-format onboarding (the FW-X demonstration)

Input with no known signature flows through a visible onboarding pipeline:

```
UNKNOWN → FINGERPRINT → STRUCTURE DISCOVERY → SEMANTIC MAPPING → VALIDATION → UNDERSTOOD
```

For `FW-X|BLK|TCP|10.2.1.5|443|10.5.2.8|53|P17` the deterministic heuristics
infer (and display, with per-field confidence):

| Token | Inference | Canonical field | Confidence |
|---|---|---|---|
| `FW-X` | vendor/source identifier | `source.vendor`, `source.product` | 0.90 |
| `BLK` | action | `action` | 0.92 |
| `TCP` | protocol | `network_protocol` | 0.96 |
| `10.2.1.5` | source IP (IPv4 shape) | `network.source_ip` | 0.94 |
| `443` | source port | `network.source_port` | 0.88 |
| `10.5.2.8` | destination IP | `network.destination_ip` | 0.94 |
| `53` | destination port | `network.destination_port` | 0.88 |
| `P17` | policy ID (`P<n>` shape) | `policy_id` | 0.90 |

This is labelled **"prototype heuristic onboarding"** everywhere it appears.
It is deterministic string/regex logic. In the target architecture, a local
AI/ML component would *propose* such mappings for human review — that is
**not implemented here** and is never claimed.

## 6. Raw evidence preservation

Every response includes `raw_evidence` — the exact input as received (only a
trailing transport newline is stripped) — and `raw_sha256 = SHA-256(raw)`.
The canonical event is a **separate representation**; the raw is never
modified to produce it. SHA-256 is deterministic (verified against NIST test
vectors in the test suite).

## 7. Canonical event model

```json
{
  "event_id": "evt-…",
  "timestamp": null,
  "source":   { "vendor": "FW-X", "product": "FW-X", "format": "UNKNOWN" },
  "network":  { "source_ip": "10.2.1.5", "source_port": 443,
                "destination_ip": "10.5.2.8", "destination_port": 53 },
  "network_protocol": "TCP",
  "action": "BLK",
  "policy_id": "P17",
  "severity": null,
  "signature_id": null,
  "user": null, "host": null, "message": null,
  "fields": {},
  "raw_sha256": "0ae89890…",
  "provenance": [ … ],
  "confidence": { … }
}
```

Only derivable fields are populated; the rest stay `null` — **nothing is
guessed silently** (e.g. port `70000` is dropped, not coerced).

## 8. Field-level provenance

Every normalized field carries its origin:

```json
{ "canonical_field": "network.source_ip", "source_field": "token[3]",
  "value": "10.2.1.5", "method": "heuristic", "confidence": 0.94 }
```

For JSON/CEF/LEEF/XML, `source_field` names the actual source key or CEF/LEEF
extension key. The UI renders the full CANONICAL FIELD / SOURCE FIELD / VALUE
/ METHOD / CONFIDENCE table from the backend response.

## 9. Validation

Real checks with real outcomes: IPv4 shape and octet range, port range
0–65535, protocol and action vocabularies, provenance presence, format-header
completeness. Results are **PASS / WARNING / FAIL** and honestly reflect the
input — the "odd ports" sample yields WARNING because invalid ports are
dropped rather than guessed, and an octet >255 yields FAIL.

## 10. Cryptographic integrity

- `raw_sha256` — SHA-256 of the exact raw evidence
- `canonical_sha256` — SHA-256 of the canonical JSON (sorted keys, compact)
- Batch Merkle tree — SHA-256 over leaf hashes (leaves double-hashed, odd
  nodes duplicated), root plus per-leaf audit proofs
- `POST /api/verify-hash` — recompute and compare a raw hash
- `POST /api/verify-merkle` — rebuild the tree, recheck every leaf proof
  against the root

This is a **Merkle hash tree for tamper-evident batch verification**. It is
not a blockchain and is never described as one.

## 11. Run locally

Requirements: Python 3.11+ (developed on 3.13).

```bash
cd axivon
pip install -r requirements.txt
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000> — the FastAPI app serves the frontend directly.

Alternative: `python -m pip install fastapi uvicorn` and run
`uvicorn backend.main:app --reload` for development.

## 12. API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | service + pipeline status |
| GET | `/api/samples` | built-in sample inputs |
| POST | `/api/process` | full pipeline on one raw event `{ "raw_event": "…" }` |
| POST | `/api/batch` | batch + Merkle root `{ "raw_events": [ … ] }` (≤200) |
| POST | `/api/verify-hash` | `{ "raw_event": "…", "expected_sha256": "…" }` |
| POST | `/api/verify-merkle` | `{ "leaf_hashes": […], "root": "…" }` |

Interactive docs: <http://127.0.0.1:8000/docs> (FastAPI auto-generated).

## 13. Testing

```bash
cd axivon
python -m pytest -q
```

44 automated tests cover: health, JSON/CEF/LEEF/syslog/XML/unknown detection,
wrapped-CEF detection, determinism, all parsers (including no-guess cases),
unknown onboarding (FW-X mapping exact), normalization, provenance table,
SHA-256 NIST vectors, canonical hash stability, Merkle proofs + tamper
rejection, validation PASS/WARNING/FAIL, full `/api/process` for every
format, raw-preservation exactness, batch + Merkle verification (including
tampered-leaf rejection), and input rejection.

## 14. Current prototype limitations (honest)

- Single-process, in-memory; no persistence, no storage vault.
- Detection covers JSON/CEF/LEEF/syslog/XML; other formats fall to the
  heuristic unknown-onboarding path.
- Onboarding mapping is position-based (token[3]=src_ip, …) plus token-shape
  checks; a novel layout with different positions will mis-map.
- Timestamps are surfaced only when the source carries them (no timezone
  inference); CEF/LEEF headers carry none.
- No authentication, TLS, multi-tenancy, queueing, or horizontal scaling.
- Heuristic confidences are fixed engineering choices, not learned metrics.
- XML/CSV support is intentionally basic (CSV left to future work).

## 15. Target / future architecture (NOT implemented)

```
Sources → Ingestion Fabric → Raw Evidence Vault → Format Intelligence
        → Parsing Fabric → Semantic Normalization → Validation
        → Provenance → Integrity Engine → Canonical Event
        → SIEM / Data Lake / AI-ML
```

Candidate future technologies — **none of which are part of this prototype**:
Kafka/Redpanda (transport) · Rust/Python services · MinIO/S3 evidence vault ·
Parquet canonical lake · OpenSearch indexing · Docker/Kubernetes deployment ·
mTLS/RBAC · local AI/ML parser-proposal with human-in-the-loop review ·
persistent parser registry.

## 16. Repository layout

```
axivon/
├── README.md · LICENSE · requirements.txt · pytest.ini
├── backend/   main.py · models.py · detector.py · parser.py
│              normalizer.py · provenance.py · integrity.py · validator.py · unknown.py
├── frontend/  index.html · style.css · app.js
├── samples/   syslog.log · cef.log · leef.log · sample.json · sample.xml
│              unknown.log · unknown_warning.log
├── tests/     test_pipeline.py
└── docs/      architecture.md · pipeline.md
```
