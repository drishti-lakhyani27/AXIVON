# AXIVON — Architecture

**Local prototype** (this repository) vs **TARGET / FUTURE** (documented
directions, explicitly not implemented).

## 1. Current prototype architecture

Single FastAPI process, no external services:

```
Browser (frontend/)                 FastAPI (backend/)
┌────────────────────┐   HTTP      ┌──────────────────────────────┐
│ index.html         │ ──────────► │ main.py        endpoints     │
│ app.js  (fetch)    │ ◄────────── │ detector.py    parse steps   │
│ style.css          │   JSON      │ parser.py      JSON/CEF/LEEF│
└────────────────────┘             │               syslog/XML     │
                                   │ unknown.py     onboarding    │
                                   │ normalizer.py  canonical     │
                                   │ validator.py   PASS/WARN/FAIL│
                                   │ provenance.py  table helpers │
                                   │ integrity.py   sha256/Merkle │
                                   │ models.py      pydantic      │
                                   └──────────────────────────────┘
```

The frontend keeps **no domain logic**: every displayed value — detected
format, confidence, provenance rows, validation issues, hashes, Merkle root —
is a backend response field rendered verbatim. Samples are also served by the
backend (`GET /api/samples`, overridable via files in `samples/`).

## 2. Module responsibilities

| Module | Responsibility |
|---|---|
| `detector.py` | deterministic format signatures (JSON/CEF/LEEF/syslog/XML/UNKNOWN) with fixed heuristic confidences |
| `parser.py` | format parsers; extract real fields only; emit provenance records; never guess |
| `unknown.py` | UNKNOWN onboarding: FINGERPRINT → STRUCTURE DISCOVERY → SEMANTIC MAPPING (deterministic heuristics) |
| `normalizer.py` | merges parser + onboarding output into the canonical event |
| `validator.py` | real checks → PASS/WARNING/FAIL with per-check issues |
| `provenance.py` | merge/summarize/tabulate provenance |
| `integrity.py` | SHA-256, canonical JSON hash, Merkle tree/proofs/verification |
| `models.py` | Pydantic canonical model + API envelopes |
| `main.py` | pipeline orchestration + HTTP endpoints + static frontend |

## 3. Data flow for one event

```
raw text
  → preserve verbatim + sha256            (integrity.sha256_hex)
  → detect_format                         (detector)
  → parse_event | unknown.onboard         (parser | unknown)
  → normalize → canonical event           (normalizer)
  → validate_event                        (validator)
  → canonical_hash                        (integrity.canonical_hash)
  → ProcessResponse JSON
```

Batch mode repeats this per event, then builds the Merkle tree over the
per-event `raw_sha256` leaves and self-verifies every leaf proof before
responding.

## 4. Integrity design

- Raw hash: SHA-256 over exact UTF-8 bytes of the evidence — no normalization.
- Canonical hash: SHA-256 over sorted-key compact JSON, so equal events hash
  equally regardless of key order.
- Merkle tree: leaves are double-hashed (`H(leaf)`), pairs combined as
  `H(left+right)`, odd node duplicated (Bitcoin-style). Audit proofs are
  recomputable client-side and server-side; the verify endpoint rebuilds the
  tree and rechecks every proof.

This is a hash tree for tamper-evident verification — **not a blockchain**.

## 5. Target / future architecture (NOT implemented)

```
Sources → Ingestion Fabric (Kafka/Redpanda) → Raw Evidence Vault (S3/MinIO, WORM)
        → Format Intelligence (rules + local AI/ML proposals, human-reviewed)
        → Parsing Fabric (parser registry, plugin lifecycle)
        → Semantic Normalization (schema registry) → Validation
        → Provenance Ledger → Integrity Engine (anchored batch roots)
        → Canonical Event Store (Parquet lake, OpenSearch)
        → SIEM / Data Lake / AI-ML consumers
```

Operational future: containerized deployment (Docker/Kubernetes), horizontal
scalability, mTLS + RBAC, streaming backpressure, Rust hot paths, persistent
evidence storage with retention policy. **None of these exist in this
repository** — the prototype is a single local FastAPI process.
