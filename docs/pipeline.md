# AXIVON — Pipeline Reference

Stage-by-stage description of `backend/main.py::run_pipeline`, including the
exact guarantees at each step.

```
INGEST → PRESERVE → DETECT → PARSE → NORMALIZE → VALIDATE → PROVE → EXPORT
```

## 1. INGEST

Raw text arrives via `POST /api/process` (`raw_event`) or `POST /api/batch`
(`raw_events[]`). A single trailing transport newline is stripped; nothing
else is touched. Empty/whitespace input is rejected with 422.

## 2. PRESERVE

- `raw_evidence` — exact input as received.
- `raw_sha256` — SHA-256 over those exact UTF-8 bytes (deterministic; the
  same input always yields the same hash; verified against NIST vectors).
- The raw evidence is never modified to build the canonical event — the
  canonical event is a separate representation.

## 3. DETECT (Format Intelligence)

Ordered deterministic signatures in `detector.py`:

1. JSON — parses as object/array → 0.98
2. CEF — `^CEF:<n>|` → 0.98
3. LEEF — `^LEEF:1.x/2.x|` or `LEEF:3.x ` → 0.98
4. XML — well-formed paired root tag → 0.95
5. Embedded CEF/LEEF payload inside a syslog-style wrapper → 0.85
6. Syslog RFC 5424 → 0.92, RFC 3164 → 0.90
7. Weak CEF/`month-name` heuristics → 0.4–0.55
8. Otherwise UNKNOWN → 0.0

Every result includes the `reason` and an explicit method label:
`"deterministic signatures (prototype heuristics, not ML)"`.

## 4. PARSE

Known formats dispatch to `parser.py`. Guarantees:

- Only fields actually present are extracted; provenance names the exact
  source key (e.g. `CEF extension:src`, `LEEF extension:usrName`,
  `syslog message:policy`, `token[3]`).
- Values that fail shape checks (IP regex, port 0–65535) are dropped, never
  coerced — no silent guessing.
- Unmapped keys are preserved under `fields.extra`.
- Syslog PRI → severity is a documented derivation (PRI % 8), labelled
  `method: "derived"` with confidence 0.95.
- UNKNOWN input instead flows through `unknown.onboard` (see below).

## 5. NORMALIZE (Semantic Normalization)

`normalizer.py` merges parser + onboarding output into the canonical model:
`event_id`, `timestamp` (null unless derivable), `source{vendor,product,format}`,
`network{source_ip, source_port, destination_ip, destination_port}`,
`network_protocol`, `action`, `policy_id`, `severity`, `signature_id`,
`user`, `host`, `message`, `fields`, `raw_sha256`, `provenance`, `confidence`.

## 6. VALIDATE

`validator.py` runs real checks — IPv4 shape/octets, port range, protocol and
action vocabularies, provenance presence, semantic coverage, format-header
completeness — and returns PASS / WARNING / FAIL with per-check messages.
Samples are not forced to pass: the invalid-port sample returns WARNING,
an IP with octet > 255 returns FAIL.

## 7. PROVE

- Field provenance table (canonical field, source field, value, method,
  confidence) — methods are `extracted`, `derived` or `heuristic`.
- `canonical_sha256` over the canonical JSON (sorted keys, compact).
- Batch: Merkle tree over per-event raw hashes; the API self-verifies all
  leaf proofs before responding, and `/api/verify-merkle` re-verifies.

## 8. EXPORT

`GET`-less export: the frontend serializes the complete ProcessResponse
(evidence + canonical + provenance + validation + integrity) to a JSON file.
No server state is involved.

## 9. UNKNOWN onboarding stages (deterministic)

```
UNKNOWN → FINGERPRINT → STRUCTURE DISCOVERY → SEMANTIC MAPPING → VALIDATION → UNDERSTOOD
```

- FINGERPRINT: delimiter, token count, IPv4 count, alpha/alnum token census.
- STRUCTURE DISCOVERY: per-token inferred type (ipv4 / port / protocol /
  action / policy_id / session_id / identifier).
- SEMANTIC MAPPING: positional network mapping (token[2]=proto, token[3]=src_ip,
  token[4]=src_port, token[5]=dst_ip, token[6]=dst_port) + shape-based action
  (`BLK|BLOCK|…`) and policy (`P<n>`) recognition, vendor from token[0].
- Each mapped field carries `method: "heuristic"` and a fixed confidence.

This is deterministic prototype logic — clearly labelled, never described as
machine learning. The future architecture would insert local AI/ML parser
proposals with human review at this stage (not implemented).
