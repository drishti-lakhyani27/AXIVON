/* AXIVON frontend controller — all results rendered strictly from backend responses. */
"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  lastResult: null,
  batch: null,
};

/* ================= toast ================= */

let toastTimer = null;
function toast(msg, isError = false) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.toggle("error", isError);
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 4200);
}

/* ================= health ping ================= */

async function pingHealth() {
  const dot = $("api-dot");
  const label = $("api-label");
  try {
    const r = await fetch("/api/health");
    if (!r.ok) throw new Error("bad status " + r.status);
    const body = await r.json();
    if (body.service !== "AXIVON") throw new Error("unexpected service");
    dot.classList.remove("err");
    dot.classList.add("ok");
    label.textContent = "API ONLINE";
  } catch {
    dot.classList.remove("ok");
    dot.classList.add("err");
    label.textContent = "API OFFLINE";
    toast("Backend unreachable — is uvicorn running on :8000?", true);
  }
}

/* ================= samples ================= */

async function loadSamples() {
  const sel = $("sample-select");
  try {
    const r = await fetch("/api/samples");
    if (!r.ok) throw new Error("bad status");
    const body = await r.json();
    for (const s of body.samples) {
      const opt = document.createElement("option");
      opt.value = s.content;
      opt.textContent = `${s.label} · ${s.format_hint}`;
      sel.appendChild(opt);
    }
  } catch {
    // samples are a convenience; not fatal
  }
}

function updateCharCount() {
  $("char-count").textContent = $("raw-input").value.length + " CHARS";
}

/* ================= pipeline rendering ================= */

const PIPELINE_STEPS = ["ingest", "preserve", "detect", "parse", "normalize", "validate", "prove"];

function renderPipeline(result) {
  const items = document.querySelectorAll("#pipeline-flow li");
  items.forEach((li) => li.classList.remove("active", "done", "fail"));
  if (!result) return;

  const parsedOk = result.parse.length > 0 && result.parse[0].status === "ok";
  const onboarding = result.format_detection.format === "UNKNOWN";
  const fail = result.parse.length > 0 && result.parse[0].status === "failed";

  items.forEach((li) => {
    const step = li.dataset.step;
    li.classList.add("done");
    if (step === "parse" && fail) { li.classList.remove("done"); li.classList.add("fail"); }
    if (step === "parse" && (parsedOk || onboarding)) { li.classList.add("active"); }
    if (step === "validate" && result.validation.result === "FAIL") {
      li.classList.remove("done"); li.classList.add("fail");
    }
  });
}

/* ================= format intelligence ================= */

function renderFormat(detection) {
  $("fmt-name").textContent = detection.format;
  $("fmt-conf").textContent = (detection.confidence * 100).toFixed(0) + "% (heuristic)";
  $("fmt-reason").textContent = detection.reason;
  $("fmt-method").textContent = detection.method || "";
}

/* ================= unknown → understood flow ================= */

function renderUnknownFlow(result) {
  const sec = $("sec-flow");
  const onboarding = result.format_detection.format === "UNKNOWN";
  if (!onboarding) { sec.hidden = true; return; }
  sec.hidden = false;

  const nodes = document.querySelectorAll("#sec-flow .flow-node");
  nodes.forEach((n) => n.classList.add("pending"));

  const detail = $("flow-detail");
  detail.innerHTML = "";

  // Fingerprint + structure detail from the backend onboarding stages
  const flowStages = (result.onboarding && result.onboarding.stages) || [];
  const fp = flowStages.find((s) => s.stage === "FINGERPRINT");
  const structure = flowStages.find((s) => s.stage === "STRUCTURE DISCOVERY");

  if (fp) {
    const h = document.createElement("h4");
    h.textContent = "FINGERPRINT · " + (fp.detail || "");
    detail.appendChild(h);
    const f = fp.fingerprint || {};
    const line = document.createElement("div");
    line.className = "map-row";
    line.innerHTML =
      `<span class="tok">delimiter</span><span class="arrow">=</span>` +
      `<span class="field">${escapeHtml(f.delimiter || "—")}</span>` +
      `<span class="conf">· tokens: ${f.token_count ?? "—"} · ipv4: ${f.ipv4_count ?? "—"}</span>`;
    detail.appendChild(line);
  }

  if (structure) {
    const h = document.createElement("h4");
    h.textContent = "STRUCTURE DISCOVERY · token typing";
    detail.appendChild(h);
    for (const t of structure.tokens || []) {
      const row = document.createElement("div");
      row.className = "map-row";
      row.innerHTML =
        `<span class="tok">${escapeHtml(t.token)}</span><span class="arrow">→</span>` +
        `<span class="field">${escapeHtml(t.inferred_type)}</span>`;
      detail.appendChild(row);
    }
  }

  // Semantic mapping rows from provenance (heuristic records)
  const h2 = document.createElement("h4");
  h2.textContent = "SEMANTIC MAPPING · proposed canonical fields";
  detail.appendChild(h2);
  const provRows = result.provenance.filter((p) => p.method === "heuristic");
  if (provRows.length === 0) {
    const none = document.createElement("div");
    none.className = "map-row";
    none.textContent = "no confident mapping proposed";
    detail.appendChild(none);
  }
  for (const p of provRows) {
    const row = document.createElement("div");
    row.className = "map-row";
    row.innerHTML =
      `<span class="tok">${escapeHtml(String(p.source_field))}</span>` +
      `<span class="arrow">→</span><span class="field">${escapeHtml(p.canonical_field)}</span>` +
      `<span class="conf">(${escapeHtml(String(p.value))} · conf ${p.confidence})</span>`;
    detail.appendChild(row);
  }

  // Light up stages sequentially for the visual flow
  let delay = 0;
  const seq = ["unknown", "fingerprint", "structure", "semantic", "validation", "understood"];
  const nodeMap = { unknown: nodes[0], fingerprint: nodes[1], structure: nodes[2],
                    semantic: nodes[3], validation: nodes[4], understood: nodes[5] };
  seq.forEach((key, i) => {
    setTimeout(() => {
      if (nodeMap[key]) {
        nodeMap[key].classList.remove("pending");
        nodeMap[key].classList.add(key === "unknown" ? "active" : "done");
        if (key === "validation") nodeMap.validation.classList.add("active");
      }
      if (i === seq.length - 1) {
        nodeMap.understood.classList.add("done");
        nodeMap.validation.classList.remove("active");
        nodeMap.validation.classList.add("done");
      }
    }, delay);
    delay += 160;
  });

  if (result.understood) {
    nodeMap.understood.classList.add("done");
  }
}

/* ================= canonical event ================= */

function syntaxHighlight(json) {
  const esc = escapeHtml(json);
  return esc.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false)\b|\bnull\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g, (m) => {
    let cls = "jn";                                   // numbers
    if (/^"/.test(m)) cls = /:$/.test(m) ? "jk" : "js"; // keys vs strings
    else if (/true|false/.test(m)) cls = "jnull";
    else if (/null/.test(m)) cls = "jnull";
    return `<span class="${cls}">${m}</span>`;
  });
}

function renderCanonical(result) {
  const pretty = JSON.stringify(result.canonical_event, null, 2);
  $("canonical-json").innerHTML = syntaxHighlight(pretty);
  $("btn-copy-json").disabled = false;
  $("btn-export").disabled = false;
}

/* ================= provenance ================= */

function renderProvenance(result) {
  const rows = result.provenance || [];
  const tbody = $("prov-tbody");
  tbody.innerHTML = "";
  if (rows.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="5">no provenance records — nothing derivable</td></tr>`;
    $("prov-summary").textContent = "";
    return;
  }
  const methods = {};
  let confSum = 0;
  for (const r of rows) {
    methods[r.method] = (methods[r.method] || 0) + 1;
    confSum += Number(r.confidence) || 0;
  }
  const mean = (confSum / rows.length).toFixed(3);
  $("prov-summary").textContent =
    `${rows.length} FIELDS · MEAN CONF ${mean} · ` +
    Object.entries(methods).map(([k, v]) => `${k.toUpperCase()}×${v}`).join(" · ");

  for (const r of rows) {
    const tr = document.createElement("tr");
    const conf = Number(r.confidence) || 0;
    tr.innerHTML =
      `<td class="cf">${escapeHtml(r.canonical_field)}</td>` +
      `<td>${escapeHtml(String(r.source_field))}</td>` +
      `<td class="val">${escapeHtml(formatValue(r.value))}</td>` +
      `<td><span class="badge ${escapeHtml(r.method)}">${escapeHtml(r.method)}</span></td>` +
      `<td>${conf.toFixed(2)}<span class="conf-bar"><i style="width:${Math.round(conf * 100)}%"></i></span></td>`;
    tbody.appendChild(tr);
  }
}

function formatValue(v) {
  if (v === null || v === undefined) return "—";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

/* ================= validation ================= */

function renderValidation(result) {
  const v = result.validation;
  const verdict = $("validation-verdict");
  verdict.textContent = `${v.result} · ${v.checks_run} CHECKS · ${v.failed} FAIL · ${v.warnings} WARN`;
  verdict.className = "validation-verdict " + v.result;

  const tbody = $("val-tbody");
  tbody.innerHTML = "";
  for (const issue of v.issues || []) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>${escapeHtml(issue.field || "—")}</td>` +
      `<td>${escapeHtml(issue.check)}</td>` +
      `<td><span class="sev ${escapeHtml(issue.severity)}">${escapeHtml(issue.severity)}</span></td>` +
      `<td class="val">${escapeHtml(issue.message)}</td>`;
    tbody.appendChild(tr);
  }
}

/* ================= raw evidence ================= */

function renderRaw(result) {
  $("raw-evidence").textContent = result.raw_evidence;
}

/* ================= integrity ================= */

function renderIntegrity(result) {
  $("hash-raw").textContent = result.integrity.raw_sha256 || "—";
  $("hash-canonical").textContent = result.integrity.canonical_sha256 || "—";
  $("btn-verify-hash").disabled = false;
}

function renderBatch(batch) {
  $("merkle-count").textContent = batch.processed;
  $("merkle-root").textContent = batch.merkle_root;
  $("merkle-verify").textContent = batch.verification.verified
    ? "VERIFIED — all leaf proofs rechecked against root"
    : "VERIFICATION FAILED";
  $("merkle-verify").className = batch.verification.verified ? "stat-value verified" : "stat-value failed";
  $("btn-verify-merkle").disabled = false;

  const levels = $("merkle-levels");
  levels.innerHTML = "";
  const treeLevels = batch.verification.levels || [];
  treeLevels.forEach((lvl, idx) => {
    const div = document.createElement("div");
    div.className = "lvl" + (idx === treeLevels.length - 1 ? " root" : "");
    const label = idx === treeLevels.length - 1 ? "ROOT" : "L" + idx;
    const shown = lvl.map((h) => h.slice(0, 8)).join("  ");
    div.innerHTML = `<b>${label}</b><span>${escapeHtml(shown)}</span>`;
    levels.appendChild(div);
  });
}

/* ================= batch ================= */

async function processBatch() {
  const batchText = SAMPLE_BATCH.join("\n");
  const rawEvents = batchText.split("\n").filter((l) => l.trim().length > 0);
  setBusy(true, "BATCH RUNNING…");
  try {
    const r = await fetch("/api/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw_events: rawEvents }),
    });
    const body = await r.json();
    if (!r.ok) throw new Error(body.detail || "batch failed");
    state.batch = body;
    renderBatch(body);
    toast(`Batch processed: ${body.processed} events · root verified: ${body.verification.verified}`);
  } catch (err) {
    toast("Batch error: " + err.message, true);
  } finally {
    setBusy(false);
  }
}

/* ================= verify buttons ================= */

async function verifyRawHash() {
  if (!state.lastResult) return;
  const raw = state.lastResult.raw_evidence;
  const expected = state.lastResult.integrity.raw_sha256;
  try {
    const r = await fetch("/api/verify-hash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw_event: raw, expected_sha256: expected }),
    });
    const body = await r.json();
    if (!r.ok) throw new Error(body.detail || "verify failed");
    $("verify-status").textContent = body.matches
      ? "RAW HASH VERIFIED ✓ (deterministic recomputation matches)"
      : "RAW HASH MISMATCH ✗";
    toast(body.matches ? "Raw hash verified" : "Raw hash MISMATCH", !body.matches);
  } catch (err) {
    toast("Verify error: " + err.message, true);
  }
}

async function verifyMerkleRoot() {
  if (!state.batch) { toast("Process a batch first", true); return; }
  try {
    const r = await fetch("/api/verify-merkle", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ leaf_hashes: state.batch.leaf_hashes, root: state.batch.merkle_root }),
    });
    const body = await r.json();
    if (!r.ok) throw new Error(body.detail || "verify failed");
    $("verify-status").textContent = body.verified
      ? "MERKLE ROOT VERIFIED ✓ (" + body.leaf_count + " leaves)"
      : "MERKLE VERIFICATION FAILED ✗";
    toast(body.verified ? "Merkle root verified" : "Merkle verification failed", !body.verified);
  } catch (err) {
    toast("Verify error: " + err.message, true);
  }
}

/* ================= export ================= */

function downloadFile(name, text, type) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function exportCanonical() {
  if (!state.lastResult) return;
  const payload = {
    event_id: state.lastResult.event_id,
    raw_evidence: state.lastResult.raw_evidence,
    raw_sha256: state.lastResult.raw_sha256,
    format_detection: state.lastResult.format_detection,
    canonical_event: state.lastResult.canonical_event,
    provenance: state.lastResult.provenance,
    validation: state.lastResult.validation,
    integrity: state.lastResult.integrity,
    processed_at: state.lastResult.processed_at,
  };
  downloadFile(`${state.lastResult.event_id}_canonical.json`,
               JSON.stringify(payload, null, 2), "application/json");
  $("export-status").textContent = "EXPORTED " + state.lastResult.event_id;
  toast("Canonical JSON exported");
}

/* ================= helpers ================= */

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

function setBusy(busy, label) {
  $("btn-process").disabled = busy;
  $("btn-batch").disabled = busy;
  $("btn-process").textContent = busy ? (label || "PROCESSING…") : "PROCESS EVENT";
}

/* ================= process event ================= */

async function processEvent() {
  const raw = $("raw-input").value;
  if (!raw.trim()) { toast("Paste a raw event first", true); return; }
  setBusy(true);
  try {
    const r = await fetch("/api/process", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw_event: raw }),
    });
    const body = await r.json();
    if (!r.ok) throw new Error(body.detail || "processing failed");

    state.lastResult = body;

    renderFormat(body.format_detection);
    renderPipeline(body);
    renderUnknownFlow(body);
    renderCanonical(body);
    renderProvenance(body);
    renderValidation(body);
    renderIntegrity(body);
    renderRaw(body);
    toast("Event processed — " + body.format_detection.format);
  } catch (err) {
    toast("Process error: " + err.message, true);
  } finally {
    setBusy(false);
  }
}

/* ================= batch sample set ================= */

const SAMPLE_BATCH = [
  "FW-X|BLK|TCP|10.2.1.5|443|10.5.2.8|53|P17",
  "CEF:0|Cyberdyne|FireWall-X|12.1|100|Port scan detected|7|src=203.0.113.45 spt=51500 dst=198.51.100.10 dpt=22 proto=TCP act=BLOCK cs1=P-101 cs1Label=PolicyID",
  "LEEF:2.0|SemperFire|Perimeter-500|1.0|90011|src=203.0.113.45\tdst=198.51.100.10\tproto=TCP\tusrName=j.doe\tsev=5",
  "<134>May  1 10:31:07 fw-edge01 secuwall: action=DROP src=203.0.113.45 spt=51500 dst=198.51.100.10 dpt=22 proto=TCP policy=P-101",
  '{"timestamp":"2026-05-01T10:31:07Z","vendor":"Aegis","product":"SensorMesh","src_ip":"203.0.113.45","src_port":51500,"dst_ip":"198.51.100.10","dst_port":22,"proto":"TCP","action":"BLOCK","policy_id":"P-101","severity":"high","message":"SSH brute force pattern matched"}',
];

/* ================= upload ================= */

function handleUpload(file) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    $("raw-input").value = String(reader.result || "");
    updateCharCount();
    toast("Loaded " + file.name + " — press PROCESS EVENT");
  };
  reader.onerror = () => toast("Could not read file", true);
  reader.readAsText(file);
}

/* ================= wiring ================= */

function wire() {
  $("btn-process").addEventListener("click", processEvent);
  $("btn-batch").addEventListener("click", processBatch);
  $("btn-copy-json").addEventListener("click", () => {
    if (!state.lastResult) return;
    navigator.clipboard.writeText(JSON.stringify(state.lastResult.canonical_event, null, 2))
      .then(() => toast("Canonical JSON copied"))
      .catch(() => toast("Clipboard unavailable", true));
  });
  $("btn-export").addEventListener("click", exportCanonical);
  $("btn-verify-hash").addEventListener("click", verifyRawHash);
  $("btn-verify-merkle").addEventListener("click", verifyMerkleRoot);

  $("raw-input").addEventListener("input", updateCharCount);

  $("sample-select").addEventListener("change", (e) => {
    if (e.target.value) {
      $("raw-input").value = e.target.value;
      updateCharCount();
    }
  });

  $("file-input").addEventListener("change", (e) => handleUpload(e.target.files[0]));
}

wire();
pingHealth();
loadSamples();
updateCharCount();
