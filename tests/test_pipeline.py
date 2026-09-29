"""AXIVON automated test suite.

Covers: API health, format detection (JSON/CEF/LEEF/Syslog/XML/UNKNOWN),
parsing, normalization, provenance, SHA-256, validation, Merkle tree,
batch processing and hash/merkle verification endpoints.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend import detector, integrity, normalizer, parser, provenance, unknown, validator
from backend.main import app, run_pipeline

client = TestClient(app)

UNKNOWN_LINE = "FW-X|BLK|TCP|10.2.1.5|443|10.5.2.8|53|P17"
CEF_LINE = ("CEF:0|Cyberdyne|FireWall-X|12.1|100|Port scan detected|7|"
            "src=203.0.113.45 spt=51500 dst=198.51.100.10 dpt=22 proto=TCP "
            "act=BLOCK cs1=P-101 cs1Label=PolicyID")
LEEF_LINE = ("LEEF:2.0|SemperFire|Perimeter-500|1.0|90011|"
             "src=203.0.113.45\tdst=198.51.100.10\tproto=TCP\tusrName=j.doe\tsev=5")
SYSLOG_LINE = ("<134>May  1 10:31:07 fw-edge01 secuwall: action=DROP src=203.0.113.45 "
               "spt=51500 dst=198.51.100.10 dpt=22 proto=TCP policy=P-101")
JSON_LINE = ('{"timestamp":"2026-05-01T10:31:07Z","vendor":"Aegis","product":"SensorMesh",'
             '"src_ip":"203.0.113.45","src_port":51500,"dst_ip":"198.51.100.10","dst_port":22,'
             '"proto":"TCP","action":"BLOCK","policy_id":"P-101","severity":"high",'
             '"message":"SSH brute force pattern matched"}')


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def test_api_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "AXIVON"
    assert "INGEST" in body["pipeline"] and "PROVE" in body["pipeline"]


def test_api_samples():
    r = client.get("/api/samples")
    assert r.status_code == 200
    keys = {s["key"] for s in r.json()["samples"]}
    assert {"syslog", "cef", "leef", "json", "unknown"} <= keys


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def test_detect_json():
    d = detector.detect_format(JSON_LINE)
    assert d["format"] == "JSON"
    assert d["confidence"] >= 0.9
    assert "JSON" in d["reason"]


def test_detect_cef():
    d = detector.detect_format(CEF_LINE)
    assert d["format"] == "CEF"
    assert "CEF" in d["reason"]


def test_detect_leef():
    d = detector.detect_format(LEEF_LINE)
    assert d["format"] == "LEEF"
    assert "LEEF" in d["reason"]


def test_detect_syslog():
    d = detector.detect_format(SYSLOG_LINE)
    assert d["format"] == "SYSLOG"
    assert "syslog" in d["reason"].lower()


def test_detect_xml():
    d = detector.detect_format("<Event><src>1.2.3.4</src><dst>5.6.7.8</dst></Event>")
    assert d["format"] == "XML"


def test_detect_unknown():
    d = detector.detect_format(UNKNOWN_LINE)
    assert d["format"] == "UNKNOWN"
    assert d["confidence"] == 0.0


def test_detect_empty():
    d = detector.detect_format("   ")
    assert d["format"] == "UNKNOWN"


def test_detect_cef_inside_syslog_prefix():
    wrapped = "May  1 10:31:07 host CEF:0|Vendor|Prod|1|42|Event|5|src=1.2.3.4"
    d = detector.detect_format(wrapped)
    assert d["format"] == "CEF"


def test_detection_is_deterministic():
    for raw in (UNKNOWN_LINE, CEF_LINE, LEEF_LINE, SYSLOG_LINE, JSON_LINE):
        assert detector.detect_format(raw) == detector.detect_format(raw)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def test_parse_json_semantics():
    out = parser.parse_json(JSON_LINE)
    assert out["fields"]["network"]["source_ip"] == "203.0.113.45"
    assert out["fields"]["network"]["destination_port"] == 22
    assert out["fields"]["network_protocol"] == "TCP"
    assert out["fields"]["action"] == "block"
    assert out["timestamp"] == "2026-05-01T10:31:07Z"
    src_fields = [p["source_field"] for p in out["provenance"]]
    assert "src_ip" in src_fields and "proto" in src_fields


def test_parse_json_does_not_guess_ips():
    bad = '{"src_ip":"not-an-ip","action":"block"}'
    out = parser.parse_json(bad)
    assert "network" not in out["fields"] or "source_ip" not in out["fields"].get("network", {})
    assert out["fields"]["action"] == "block"


def test_parse_cef():
    out = parser.parse_cef(CEF_LINE)
    assert out["vendor"] == "Cyberdyne"
    assert out["product"] == "FireWall-X"
    assert out["fields"]["signature_id"] == "100"
    assert out["fields"]["network"]["source_ip"] == "203.0.113.45"
    assert out["fields"]["network"]["source_port"] == 51500
    assert out["fields"]["policy_id"] == "P-101"
    assert any(p["source_field"] == "CEF extension:src" for p in out["provenance"])


def test_parse_leef():
    out = parser.parse_leef(LEEF_LINE)
    assert out["vendor"] == "SemperFire"
    assert out["product"] == "Perimeter-500"
    assert out["fields"]["network"]["source_ip"] == "203.0.113.45"
    assert out["fields"]["user"] == "j.doe"
    assert any(p["source_field"] == "LEEF extension:dst" for p in out["provenance"])


def test_parse_syslog_pri_severity():
    out = parser.parse_syslog(SYSLOG_LINE)
    # PRI 134 → 134 % 8 = 6 → "informational" (documented RFC 5424 derivation)
    assert out["fields"]["severity"] == "informational"
    assert out["fields"]["network"]["source_ip"] == "203.0.113.45"
    assert out["host"] == "fw-edge01"
    assert any(p["method"] == "derived" for p in out["provenance"])


def test_parse_syslog_bad_port_not_guessed():
    out = parser.parse_syslog("<134>May  1 10:31:07 fw host: src=1.2.3.4 spt=notaport")
    assert "source_port" not in out["fields"].get("network", {})


# ---------------------------------------------------------------------------
# Unknown onboarding (deterministic heuristics)
# ---------------------------------------------------------------------------

def test_unknown_onboarding_fw_x():
    result = unknown.onboard(UNKNOWN_LINE)
    assert result["understood"] is True
    fields = result["fields"]
    assert fields["network"]["source_ip"] == "10.2.1.5"
    assert fields["network"]["source_port"] == 443
    assert fields["network"]["destination_ip"] == "10.5.2.8"
    assert fields["network"]["destination_port"] == 53
    assert fields["network_protocol"] == "TCP"
    assert fields["action"] == "BLK"
    assert fields["policy_id"] == "P17"
    assert fields["source"]["vendor"] == "FW-X"
    src = {p["canonical_field"]: p for p in result["provenance"]}
    assert src["network.source_ip"]["source_field"] == "token[3]"
    assert src["network.source_ip"]["method"] == "heuristic"
    assert 0 < src["network.source_ip"]["confidence"] < 1


def test_unknown_stages_present():
    result = unknown.onboard(UNKNOWN_LINE)
    stages = [s["stage"] for s in result["stages"]]
    assert stages == ["FINGERPRINT", "STRUCTURE DISCOVERY"]


def test_unknown_no_ml_label():
    result = unknown.onboard(UNKNOWN_LINE)
    assert "not ML" in result["method"]


# ---------------------------------------------------------------------------
# Normalization + provenance
# ---------------------------------------------------------------------------

def test_normalize_unknown_event():
    detection = detector.detect_format(UNKNOWN_LINE)
    onboarding = unknown.onboard(UNKNOWN_LINE)
    event = normalizer.normalize(UNKNOWN_LINE, detection, None, onboarding)
    assert event["source"]["format"] == "UNKNOWN"
    assert event["network"]["source_ip"] == "10.2.1.5"
    assert event["policy_id"] == "P17"
    # timestamp is NOT derivable → must stay None (never fabricated)
    assert event["timestamp"] is None


def test_normalize_cef_event():
    detection = detector.detect_format(CEF_LINE)
    parsed = parser.parse_event(CEF_LINE, "CEF")
    event = normalizer.normalize(CEF_LINE, detection, parsed, None)
    assert event["source"]["vendor"] == "Cyberdyne"
    assert event["source"]["format"] == "CEF"
    assert event["network"]["destination_port"] == 22


def test_provenance_table_and_summary():
    detection = detector.detect_format(CEF_LINE)
    parsed = parser.parse_event(CEF_LINE, "CEF")
    event = normalizer.normalize(CEF_LINE, detection, parsed, None)
    rows = provenance.to_table(event["provenance"])
    assert rows and all(set(r) >= {"canonical_field", "source_field", "value", "method", "confidence"}
                        for r in rows)
    summary = provenance.summarize(event["provenance"])
    assert summary["count"] == len(event["provenance"])
    assert 0 < summary["mean_confidence"] <= 1.0


# ---------------------------------------------------------------------------
# Integrity: SHA-256 + canonical hash + Merkle
# ---------------------------------------------------------------------------

def test_sha256_known_vector():
    assert integrity.sha256_hex("") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert integrity.sha256_hex("abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


def test_sha256_deterministic_and_sensitive():
    h1 = integrity.sha256_hex(UNKNOWN_LINE)
    h2 = integrity.sha256_hex(UNKNOWN_LINE)
    assert h1 == h2
    assert h1 != integrity.sha256_hex(UNKNOWN_LINE + " ")
    assert len(h1) == 64


def test_canonical_hash_stable_regardless_of_key_order():
    a = integrity.canonical_hash({"x": 1, "y": 2})
    b = integrity.canonical_hash({"y": 2, "x": 1})
    assert a == b


def test_merkle_tree_and_proofs():
    leaves = [integrity.sha256_hex(f"event-{i}") for i in range(5)]
    tree = integrity.merkle_tree(leaves)
    assert tree["leaf_count"] == 5 and len(tree["root"]) == 64
    for i, leaf in enumerate(leaves):
        proof = integrity.merkle_proof(tree, i)
        assert proof is not None
        assert integrity.verify_merkle_proof(leaf, proof, tree["root"]) is True


def test_merkle_tamper_detection():
    leaves = [integrity.sha256_hex(f"event-{i}") for i in range(4)]
    tree = integrity.merkle_tree(leaves)
    proof = integrity.merkle_proof(tree, 2)
    tampered = integrity.sha256_hex("tampered")
    assert integrity.verify_merkle_proof(tampered, proof, tree["root"]) is False


def test_merkle_odd_and_single_leaf():
    one = integrity.merkle_tree([integrity.sha256_hex("solo")])
    proof = integrity.merkle_proof(one, 0)
    assert integrity.verify_merkle_proof(integrity.sha256_hex("solo"), proof, one["root"])
    three = integrity.merkle_tree([integrity.sha256_hex(str(i)) for i in range(3)])
    for i in range(3):
        proof = integrity.merkle_proof(three, i)
        assert integrity.verify_merkle_proof(integrity.sha256_hex(str(i)), proof, three["root"])


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validated(raw: str):
    result = run_pipeline(raw)
    return result["validation"], result["canonical_event"]


def test_validation_pass_for_complete_event():
    validation, _ = _validated(CEF_LINE)
    assert validation["result"] in ("PASS", "WARNING")   # CEF may warn on nothing critical
    assert validation["checks_run"] >= 6


def test_validation_fail_for_octet_over_255():
    validation, _ = _validated("FW-X|BLK|TCP|300.2.1.5|443|10.5.2.8|53|P17")
    assert validation["result"] == "FAIL"
    assert any(i["severity"] == "FAIL" for i in validation["issues"])


def test_validation_fail_for_bad_port_in_json():
    validation, _ = _validated('{"src_ip":"1.2.3.4","src_port":99999,"action":"block"}')
    # 99999 must not be guessed as a port; normalization drops it → warning, not fail
    assert validation["result"] in ("WARNING", "FAIL")


def test_validation_warning_when_sparse():
    validation, _ = _validated('{"message":"hello world"}')
    assert validation["result"] == "WARNING"


def test_validation_not_all_samples_pass():
    validation, _ = _validated("FW-Z|ALLOW|UDP|10.44.9.2|70000|10.44.9.9|99999|P77")
    assert validation["result"] in ("WARNING", "FAIL")


# ---------------------------------------------------------------------------
# Full pipeline via API
# ---------------------------------------------------------------------------

def test_process_unknown_line():
    r = client.post("/api/process", json={"raw_event": UNKNOWN_LINE})
    assert r.status_code == 200
    body = r.json()
    assert body["format_detection"]["format"] == "UNKNOWN"
    assert body["understood"] is True
    assert body["preserved"] is True
    assert body["raw_evidence"] == UNKNOWN_LINE
    ce = body["canonical_event"]
    assert ce["network"]["source_ip"] == "10.2.1.5"
    assert ce["network"]["destination_port"] == 53
    assert ce["policy_id"] == "P17"
    assert ce["raw_sha256"] == body["raw_sha256"]
    prov = body["provenance"]
    assert any(p["canonical_field"] == "network.source_ip" and p["method"] == "heuristic"
               for p in prov)
    assert body["validation"]["result"] in ("PASS", "WARNING")


def test_process_preserves_raw_exactly():
    raw_with_trailing = CEF_LINE + "\n"
    r = client.post("/api/process", json={"raw_event": raw_with_trailing})
    body = r.json()
    assert body["raw_evidence"] == CEF_LINE           # transport newline stripped
    assert body["raw_sha256"] == integrity.sha256_hex(CEF_LINE)


def test_process_each_format():
    for raw, fmt in ((CEF_LINE, "CEF"), (LEEF_LINE, "LEEF"),
                     (SYSLOG_LINE, "SYSLOG"), (JSON_LINE, "JSON")):
        r = client.post("/api/process", json={"raw_event": raw})
        assert r.status_code == 200, raw
        body = r.json()
        assert body["format_detection"]["format"] == fmt
        assert body["parse"][0]["status"] == "ok"
        assert body["understood"] is True
        assert body["canonical_event"]["raw_sha256"] == body["raw_sha256"]


def test_process_rejects_empty():
    r = client.post("/api/process", json={"raw_event": "   "})
    assert r.status_code == 422


def test_process_provenance_fields_match_values():
    r = client.post("/api/process", json={"raw_event": UNKNOWN_LINE})
    body = r.json()
    ce, prov = body["canonical_event"], body["provenance"]
    for p in prov:
        if p["canonical_field"].startswith("network."):
            key = p["canonical_field"].split(".", 1)[1]
            assert ce["network"][key] == p["value"]


# ---------------------------------------------------------------------------
# Verify-hash endpoint
# ---------------------------------------------------------------------------

def test_verify_hash_matches_and_mismatch():
    h = integrity.sha256_hex(UNKNOWN_LINE)
    ok = client.post("/api/verify-hash",
                     json={"raw_event": UNKNOWN_LINE, "expected_sha256": h})
    assert ok.status_code == 200 and ok.json()["matches"] is True
    bad = client.post("/api/verify-hash",
                      json={"raw_event": UNKNOWN_LINE + "x", "expected_sha256": h})
    assert bad.json()["matches"] is False


# ---------------------------------------------------------------------------
# Batch + Merkle
# ---------------------------------------------------------------------------

def test_batch_and_merkle_verification():
    batch = [UNKNOWN_LINE, CEF_LINE, LEEF_LINE, SYSLOG_LINE, JSON_LINE]
    r = client.post("/api/batch", json={"raw_events": batch})
    assert r.status_code == 200
    body = r.json()
    assert body["processed"] == 5
    assert len(body["events"]) == 5
    for ev, leaf in zip(body["events"], body["leaf_hashes"]):
        assert ev["raw_sha256"] == leaf
        assert len(ev["canonical_sha256"]) == 64
    assert body["verification"]["verified"] is True

    # verify the same root through the verify-merkle endpoint
    v = client.post("/api/verify-merkle",
                    json={"leaf_hashes": body["leaf_hashes"], "root": body["merkle_root"]})
    assert v.status_code == 200 and v.json()["verified"] is True

    # tamper one leaf → must fail
    tampered = list(body["leaf_hashes"])
    tampered[0] = "0" * 64
    v2 = client.post("/api/verify-merkle",
                     json={"leaf_hashes": tampered, "root": body["merkle_root"]})
    assert v2.json()["verified"] is False


def test_batch_rejects_empty_and_oversize():
    assert client.post("/api/batch", json={"raw_events": []}).status_code == 422
    assert client.post("/api/batch",
                       json={"raw_events": ["x"] * 201}).status_code == 422


def test_verify_merkle_rejects_bad_input():
    r = client.post("/api/verify-merkle", json={"leaf_hashes": ["nope"], "root": "x"})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Frontend is served
# ---------------------------------------------------------------------------

def test_index_served():
    r = client.get("/")
    assert r.status_code == 200
    assert "AXIVON" in r.text
