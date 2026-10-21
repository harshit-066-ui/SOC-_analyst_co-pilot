/* ── Evaluation Lab JavaScript ──────────────────────────────────────────── */
/* jshint esversion: 11 */

"use strict";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const EvalState = {
  selectedConfigs: new Set(),
  pendingFiles: [],          // [{file, name}]
  inputMode: "upload",       // "upload" | "session"
  sessionId: null,
  normalizedEventCount: 0,
  groundTruthDatasetId: null,
  currentExperiment: null,   // last completed experiment object
  configurations: [],        // loaded from /api/eval/configurations
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];

function esc(v) {
  if (v == null) return "";
  return String(v)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function fmt(v, decimals = 2) {
  if (v == null || v === "") return '<span class="metric-na">N/A</span>';
  const n = parseFloat(v);
  if (isNaN(n)) return esc(v);
  return n.toFixed(decimals);
}

function fmtPct(v) {
  if (v == null) return '<span class="metric-na">N/A</span>';
  return (parseFloat(v) * 100).toFixed(1) + "%";
}

function fmtMs(v) {
  if (v == null) return '<span class="metric-na">N/A</span>';
  return parseFloat(v).toFixed(1) + " ms";
}

function showLoading(show, msg = "Running evaluation…") {
  const el = $("#loading");
  const msgEl = $("#loading-msg");
  if (msgEl) msgEl.textContent = msg;
  el.hidden = !show;
  el.style.display = show ? "flex" : "none";
}

function showToast(msg, isError = true) {
  const el = $("#toast");
  el.textContent = msg;
  el.hidden = false;
  el.style.background = isError ? "var(--error)" : "var(--success)";
  setTimeout(() => { el.hidden = true; }, 5000);
}

function logProgress(msg, type = "info") {
  const log = $("#progress-log");
  if (!log) return;
  const entry = document.createElement("div");
  entry.className = `progress-entry ${type === "ok" ? "ok" : type === "err" ? "err" : type === "warn" ? "warn" : ""}`;
  const ts = new Date().toLocaleTimeString();
  entry.textContent = `[${ts}] ${msg}`;
  log.appendChild(entry);
  log.scrollTop = log.scrollHeight;
}

function setProgress(pct) {
  const bar = $("#progress-bar");
  if (bar) bar.style.width = `${Math.min(100, Math.max(0, pct))}%`;
}

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

function initTabs() {
  $$(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const paneId = btn.dataset.tab;
      $$(".tab-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      $$(".tab-pane").forEach(p => { p.hidden = p.id !== paneId; });
      EvalState.inputMode = paneId === "upload-tab" ? "upload" : "session";
      updateRunButton();
    });
  });
}

// ---------------------------------------------------------------------------
// File upload
// ---------------------------------------------------------------------------

function initFileUpload() {
  const input = $("#eval-file-input");
  const btn   = $("#eval-choose-btn");
  const zone  = $("#eval-drop-zone");

  btn.addEventListener("click", () => input.click());
  input.addEventListener("change", () => addFiles([...input.files]));

  zone.addEventListener("dragover", e => { e.preventDefault(); zone.classList.add("drag-over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
  zone.addEventListener("drop", e => {
    e.preventDefault();
    zone.classList.remove("drag-over");
    addFiles([...e.dataTransfer.files]);
  });
}

function addFiles(files) {
  const allowed = new Set([".csv", ".json", ".jsonl", ".log", ".txt"]);
  files.forEach(f => {
    const ext = "." + f.name.split(".").pop().toLowerCase();
    if (!allowed.has(ext)) { showToast(`Unsupported file type: ${f.name}`); return; }
    if (f.size > 20 * 1024 * 1024) { showToast(`File too large (max 20 MB): ${f.name}`); return; }
    if (EvalState.pendingFiles.find(p => p.name === f.name)) return; // deduplicate
    EvalState.pendingFiles.push({ file: f, name: f.name });
  });
  renderFileList();
  updateRunButton();
}

function renderFileList() {
  const container = $("#eval-file-list");
  if (!EvalState.pendingFiles.length) { container.hidden = true; return; }
  container.hidden = false;
  container.innerHTML = EvalState.pendingFiles.map((p, i) =>
    `<div class="file-item">
      <span class="file-name">${esc(p.name)}</span>
      <span class="file-size">${(p.file.size / 1024).toFixed(1)} KB</span>
      <button class="btn-xs" onclick="removeFile(${i})">✕</button>
    </div>`
  ).join("");
}

window.removeFile = function(idx) {
  EvalState.pendingFiles.splice(idx, 1);
  renderFileList();
  updateRunButton();
};

// ---------------------------------------------------------------------------
// Configuration cards
// ---------------------------------------------------------------------------

const CONFIG_COLORS = {
  rule_based_only: "a",
  llm_only: "b",
  llm_rag: "c",
  llm_rule_based: "d",
  full_framework: "e",
};

function initConfigCards(configurations) {
  EvalState.configurations = configurations;
  const grid = $("#config-cards-grid");
  grid.innerHTML = configurations.map(cfg => {
    const components = Object.entries(cfg.components || {})
      .map(([k, on]) =>
        `<span class="component-badge ${on ? "on" : "off"}">${esc(k.replace(/_/g," "))}</span>`
      ).join("");
    return `
      <div class="config-card" data-config="${esc(cfg.config_id)}" onclick="toggleConfig('${esc(cfg.config_id)}')">
        <div class="config-card-header">
          <div class="config-card-check">✓</div>
          <div class="config-card-title">${esc(cfg.name)}</div>
        </div>
        <div class="config-card-desc">${esc(cfg.description)}</div>
        <div class="config-components">${components}</div>
      </div>`;
  }).join("");

  // Select all by default
  configurations.forEach(c => EvalState.selectedConfigs.add(c.config_id));
  updateConfigCardUI();
}

window.toggleConfig = function(id) {
  if (EvalState.selectedConfigs.has(id)) {
    EvalState.selectedConfigs.delete(id);
  } else {
    EvalState.selectedConfigs.add(id);
  }
  updateConfigCardUI();
  updateRunButton();
};

function updateConfigCardUI() {
  $$(".config-card").forEach(card => {
    const selected = EvalState.selectedConfigs.has(card.dataset.config);
    card.classList.toggle("selected", selected);
  });
}

// ---------------------------------------------------------------------------
// Ground truth
// ---------------------------------------------------------------------------

async function loadGroundTruthList() {
  try {
    const res = await fetch("/api/eval/ground-truth");
    const datasets = await res.json();
    const sel = $("#gt-select");
    const existing = [...sel.options].map(o => o.value).filter(Boolean);
    datasets.forEach(ds => {
      if (!existing.includes(ds.dataset_id)) {
        const opt = document.createElement("option");
        opt.value = ds.dataset_id;
        opt.textContent = `${ds.name} (${ds.label_count} labels${ds.is_synthetic ? " · synthetic" : ""})`;
        sel.appendChild(opt);
      }
    });
  } catch (e) { /* silently fail — GT is optional */ }
}

function initGroundTruth() {
  const sel = $("#gt-select");
  sel.addEventListener("change", () => {
    EvalState.groundTruthDatasetId = sel.value || null;
    updateGTInfo();
  });

  $("#gt-refresh-btn").addEventListener("click", loadGroundTruthList);

  const gtFileInput = $("#gt-file-input");
  $("#gt-upload-btn").addEventListener("click", () => gtFileInput.click());
  gtFileInput.addEventListener("change", async () => {
    const file = gtFileInput.files[0];
    if (!file) return;
    showLoading(true, "Uploading ground truth…");
    try {
      const fd = new FormData();
      fd.append("file", file);
      const res = await fetch("/api/eval/ground-truth/upload", { method: "POST", body: fd });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Upload failed");
      showToast(`Ground truth loaded: ${data.name} (${data.label_count} labels)`, false);
      await loadGroundTruthList();
      // auto-select the newly uploaded dataset
      $("#gt-select").value = data.dataset_id;
      EvalState.groundTruthDatasetId = data.dataset_id;
      updateGTInfo();
    } catch (e) {
      showToast("Ground truth upload failed: " + e.message);
    } finally {
      showLoading(false);
      gtFileInput.value = "";
    }
  });
}

function updateGTInfo() {
  const infoDiv = $("#gt-info");
  const sel     = $("#gt-select");
  const dsStatus = $("#ds-gt-status");
  if (!EvalState.groundTruthDatasetId) {
    infoDiv.hidden = true;
    if (dsStatus) { dsStatus.textContent = "Not loaded"; dsStatus.className = "badge badge-muted"; }
    return;
  }
  const opt = [...sel.options].find(o => o.value === EvalState.groundTruthDatasetId);
  if (opt) {
    infoDiv.hidden = false;
    $("#gt-name").textContent  = opt.textContent;
    const isSynth = opt.textContent.includes("synthetic");
    $("#gt-synthetic").hidden  = !isSynth;
    if (dsStatus) { dsStatus.textContent = "Loaded"; dsStatus.className = "badge badge-success"; }
  }
}

// ---------------------------------------------------------------------------
// Model info
// ---------------------------------------------------------------------------

async function loadModelInfo() {
  try {
    const res  = await fetch("/api/l3/health");
    const data = await res.json();
    const modelEl = $("#model-id-display");
    const ragEl   = $("#rag-collection-display");
    if (modelEl) modelEl.textContent = data.openrouter?.model || "unknown";
    if (ragEl) {
      const evalRes  = await fetch("/api/eval/health");
      const evalData = await evalRes.json();
      ragEl.textContent = "cybersecurity_knowledge";
    }
    const embEl = $("#embedding-display");
    if (embEl) embEl.textContent = "BAAI/bge-m3";
  } catch (e) {
    const modelEl = $("#model-id-display");
    if (modelEl) modelEl.textContent = "unavailable";
  }
}

// ---------------------------------------------------------------------------
// Run button enable/disable
// ---------------------------------------------------------------------------

function updateRunButton() {
  const btn = $("#run-btn");
  if (!btn) return;
  const hasInput = EvalState.inputMode === "upload"
    ? EvalState.pendingFiles.length > 0
    : ($("#eval-session-id")?.value || "").trim().length > 0;
  const hasConfigs = EvalState.selectedConfigs.size > 0;
  btn.disabled = !(hasInput && hasConfigs);
}

// ---------------------------------------------------------------------------
// Run experiment
// ---------------------------------------------------------------------------

async function runExperiment() {
  const runBtn = $("#run-btn");
  runBtn.disabled = true;

  // Show progress
  $("#progress-section").hidden = false;
  $("#progress-section").scrollIntoView({ behavior: "smooth", block: "start" });
  $("#results-section").hidden = true;
  setProgress(5);
  logProgress("Starting evaluation…");

  const selectedConfigs = [...EvalState.selectedConfigs];
  const maxLLM  = parseInt($("#eval-max-llm").value) || 5;
  const notes   = $("#eval-notes").value || "";
  const gtId    = EvalState.groundTruthDatasetId || "";

  let experimentData = null;

  try {
    if (EvalState.inputMode === "upload") {
      logProgress("Uploading and normalising files (L1)…");
      setProgress(15);

      const fd = new FormData();
      EvalState.pendingFiles.forEach(p => fd.append("files", p.file, p.name));
      fd.append("configurations", selectedConfigs.join(","));
      fd.append("ground_truth_dataset_id", gtId);
      fd.append("max_llm_alerts", maxLLM);
      fd.append("notes", notes);
      const hint = $("#eval-source-hint")?.value || "";
      if (hint) fd.append("source_hint", hint);

      setProgress(20);
      logProgress("Normalisation complete. Running configurations…");
      setProgress(30);

      const res = await fetch("/api/eval/run/upload", { method: "POST", body: fd });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      experimentData = await res.json();

    } else {
      const sessionId = ($("#eval-session-id")?.value || "").trim();
      if (!sessionId) { showToast("Enter a session ID."); runBtn.disabled = false; return; }
      EvalState.sessionId = sessionId;

      logProgress(`Using session ${sessionId}. Running configurations…`);
      setProgress(20);

      const body = {
        session_id: sessionId,
        selected_configurations: selectedConfigs,
        max_llm_alerts: maxLLM,
        ground_truth_dataset_id: gtId,
        notes,
      };
      const res = await fetch(`/api/eval/run/session/${sessionId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      experimentData = await res.json();
    }

    setProgress(90);
    logProgress("Processing results…");

    EvalState.currentExperiment = experimentData;
    const warns = experimentData.warnings || [];
    const errs  = experimentData.errors   || [];
    warns.forEach(w => logProgress(w, "warn"));
    errs.forEach(e  => logProgress(e, "err"));

    const status = experimentData.status || "unknown";
    if (status === "completed") {
      logProgress(`Experiment ${experimentData.experiment_id} completed.`, "ok");
    } else if (status === "partial") {
      logProgress(`Experiment ${experimentData.experiment_id} completed with partial failures.`, "warn");
    } else {
      logProgress(`Experiment ${experimentData.experiment_id} status: ${status}.`, "err");
    }

    setProgress(100);
    renderResults(experimentData);
    updateDatasetStats(experimentData.dataset);
    showToast(`Experiment complete — ${selectedConfigs.length} configuration(s) run.`, false);

  } catch (err) {
    logProgress("Experiment failed: " + err.message, "err");
    showToast("Experiment failed: " + err.message);
    setProgress(0);
  } finally {
    runBtn.disabled = false;
  }
}

// ---------------------------------------------------------------------------
// Dataset stats (shown after run)
// ---------------------------------------------------------------------------

function updateDatasetStats(ds) {
  if (!ds) return;
  const show = el => { if (el) el.hidden = false; };
  show($("#dataset-stats"));
  const raw  = $("#ds-raw");
  const norm = $("#ds-norm");
  const dedup= $("#ds-dedup");
  const errs = $("#ds-err");
  const fp   = $("#ds-fingerprint");
  if (raw)   raw.textContent   = ds.raw_event_count ?? ds.normalized_event_count ?? "—";
  if (norm)  norm.textContent  = ds.normalized_event_count ?? "—";
  if (dedup) dedup.textContent = ds.duplicates_removed ?? 0;
  if (errs)  errs.textContent  = ds.normalization_errors ?? 0;
  if (fp)    fp.textContent    = (ds.fingerprint || "").substring(0, 32) + "…";
  updateGTInfo();
}

// ---------------------------------------------------------------------------
// Render results
// ---------------------------------------------------------------------------

const CONFIG_NAMES = {
  rule_based_only: "Rule-Based Only",
  llm_only:        "LLM Only",
  llm_rag:         "LLM + RAG",
  llm_rule_based:  "LLM + Rule-Based",
  full_framework:  "Full Framework",
};

const METRIC_ROWS = [
  { key: "cases_total",            label: "Cases",               fmt: v => v },
  { key: "cases_completed",        label: "Completed",           fmt: v => v },
  { key: "cases_failed",           label: "Failed",              fmt: v => v === 0 ? v : `<span class="metric-warn">${v}</span>` },
  { key: "tp",                     label: "True Positives",      fmt: v => v },
  { key: "fp",                     label: "False Positives",     fmt: v => v },
  { key: "tn",                     label: "True Negatives",      fmt: v => v },
  { key: "fn",                     label: "False Negatives",     fmt: v => v },
  { key: "precision",              label: "Precision",           fmt: v => v == null ? '<span class="metric-na">N/A</span>' : `<span class="${v >= 0.7 ? "metric-good" : v >= 0.4 ? "metric-warn" : "metric-bad"}">${(v*100).toFixed(1)}%</span>` },
  { key: "recall",                 label: "Recall",              fmt: v => v == null ? '<span class="metric-na">N/A</span>' : `<span class="${v >= 0.7 ? "metric-good" : v >= 0.4 ? "metric-warn" : "metric-bad"}">${(v*100).toFixed(1)}%</span>` },
  { key: "f1_score",               label: "F1 Score",            fmt: v => v == null ? '<span class="metric-na">N/A</span>' : `<span class="${v >= 0.7 ? "metric-good" : v >= 0.4 ? "metric-warn" : "metric-bad"}">${(v*100).toFixed(1)}%</span>` },
  { key: "false_positive_rate",    label: "FPR",                 fmt: v => v == null ? '<span class="metric-na">N/A</span>' : fmtPct(v) },
  { key: "false_negative_rate",    label: "FNR",                 fmt: v => v == null ? '<span class="metric-na">N/A</span>' : fmtPct(v) },
  { key: "latency_mean_ms",        label: "Mean Latency",        fmt: v => v == null ? '<span class="metric-na">N/A</span>' : fmtMs(v) },
  { key: "latency_p95_ms",         label: "p95 Latency",         fmt: v => v == null ? '<span class="metric-na">N/A</span>' : fmtMs(v) },
  { key: "risk_score_mean",        label: "Mean Risk Score",     fmt: v => v == null ? '<span class="metric-na">N/A</span>' : parseFloat(v).toFixed(1) },
  { key: "llm_available_count",    label: "LLM Available",       fmt: v => v },
  { key: "llm_unavailable_count",  label: "LLM Unavailable",     fmt: v => v === 0 ? v : `<span class="metric-warn">${v}</span>` },
  { key: "rag_retrieved_count",    label: "RAG Retrievals",      fmt: v => v },
  { key: "evidence_grounding_rate",label: "Evidence Grounding",  fmt: v => v == null ? '<span class="metric-na">N/A</span>' : fmtPct(v) },
  { key: "judge_passed_count",     label: "Judge Passed",        fmt: v => v == null ? '<span class="metric-na">N/A</span>' : v },
  { key: "judge_failed_count",     label: "Judge Failed",        fmt: v => v == null ? '<span class="metric-na">N/A</span>' : (v > 0 ? `<span class="metric-warn">${v}</span>` : v) },
  { key: "judge_pass_rate",        label: "Judge Pass Rate",     fmt: v => v == null ? '<span class="metric-na">N/A</span>' : fmtPct(v) },
];

function renderResults(exp) {
  const section = $("#results-section");
  section.hidden = false;
  section.scrollIntoView({ behavior: "smooth", block: "start" });

  // Experiment metadata
  const metaEl = $("#experiment-meta");
  metaEl.innerHTML = [
    `<span class="meta-item"><span class="meta-key">ID:</span><span class="meta-val">${esc(exp.experiment_id)}</span></span>`,
    `<span class="meta-item"><span class="meta-key">Created:</span><span class="meta-val">${esc(exp.created_at)}</span></span>`,
    `<span class="meta-item"><span class="meta-key">Status:</span><span class="meta-val badge ${exp.status === 'completed' ? 'badge-success' : exp.status === 'partial' ? 'badge-warning' : 'badge-error'}">${esc(exp.status)}</span></span>`,
    `<span class="meta-item"><span class="meta-key">Events:</span><span class="meta-val">${esc(exp.dataset?.normalized_event_count)}</span></span>`,
    `<span class="meta-item"><span class="meta-key">Configs:</span><span class="meta-val">${Object.keys(exp.metrics || {}).length}</span></span>`,
    exp.dataset?.ground_truth_available
      ? `<span class="meta-item"><span class="meta-key">Ground Truth:</span><span class="meta-val badge badge-success">${exp.dataset.labelled_case_count} labels</span></span>`
      : `<span class="meta-item"><span class="meta-key">Ground Truth:</span><span class="meta-val badge badge-muted">None</span></span>`,
  ].join("");

  // Synthetic notice
  const synthNotice = $("#synthetic-notice");
  const isSynth = Object.values(exp.case_results || {})
    .flat()
    .some(r => r.ground_truth_label && (exp.dataset?.is_synthetic || false));
  synthNotice.hidden = !exp.dataset?.is_synthetic;

  const configIds = Object.keys(exp.metrics || {});

  // Build metrics comparison table
  renderMetricsTable(configIds, exp.metrics);

  // Charts
  renderCharts(configIds, exp.metrics, exp.case_results);

  // Per-case table
  renderCasesTable(configIds, exp.case_results);

  // Populate case filter dropdown
  const caseFilter = $("#case-config-filter");
  caseFilter.innerHTML = '<option value="">All</option>' +
    configIds.map(id => `<option value="${esc(id)}">${esc(CONFIG_NAMES[id] || id)}</option>`).join("");

  // Export buttons
  $("#export-json-btn").onclick = () => exportJson(exp);
  $("#export-csv-btn").onclick  = () => downloadCsv(exp.experiment_id);
}

function renderMetricsTable(configIds, metrics) {
  const thead = $("#metrics-thead");
  const tbody = $("#metrics-tbody");

  thead.innerHTML = `<tr><th>Metric</th>${configIds.map(id =>
    `<th>${esc(CONFIG_NAMES[id] || id)}</th>`).join("")}</tr>`;

  tbody.innerHTML = METRIC_ROWS.map(row => {
    const cells = configIds.map(id => {
      const m = metrics[id] || {};
      const val = m[row.key];
      return `<td>${row.fmt(val)}</td>`;
    }).join("");
    return `<tr><td class="stat-label">${esc(row.label)}</td>${cells}</tr>`;
  }).join("");

  // Notes row
  const notesCells = configIds.map(id => {
    const m = metrics[id] || {};
    const note = m.metrics_note || "";
    return note
      ? `<td><span class="metric-na" title="${esc(note)}">ℹ details</span></td>`
      : `<td></td>`;
  }).join("");
  tbody.innerHTML += `<tr><td class="stat-label">Notes</td>${notesCells}</tr>`;
}

function renderCharts(configIds, metrics, caseResults) {
  const colors = ["", "color-b", "color-c", "color-d", "color-e"];

  // Alert detection rate
  const alertData = configIds.map((id, i) => {
    const cases = (caseResults[id] || []);
    const total  = cases.length || 1;
    const alerts = cases.filter(c => c.alert_fired).length;
    return { label: CONFIG_NAMES[id] || id, val: alerts / total, display: `${alerts}/${total}`, color: colors[i] };
  });
  renderBarChart("#bar-alerts", alertData, 1);

  // Mean latency
  const latData = configIds.map((id, i) => {
    const m = metrics[id] || {};
    return { label: CONFIG_NAMES[id] || id, val: m.latency_mean_ms, display: m.latency_mean_ms != null ? m.latency_mean_ms.toFixed(1) + " ms" : "N/A", color: colors[i] };
  });
  const maxLat = Math.max(...latData.map(d => d.val || 0), 1);
  renderBarChart("#bar-latency", latData, maxLat);

  // Mean risk score
  const riskData = configIds.map((id, i) => {
    const m = metrics[id] || {};
    return { label: CONFIG_NAMES[id] || id, val: m.risk_score_mean, display: m.risk_score_mean != null ? m.risk_score_mean.toFixed(1) : "N/A", color: colors[i] };
  });
  renderBarChart("#bar-risk", riskData, 100);
}

function renderBarChart(selector, data, maxVal) {
  const container = $(selector);
  if (!container) return;
  container.innerHTML = data.map(d => {
    const pct = d.val != null ? Math.round((d.val / maxVal) * 100) : 0;
    return `
      <div class="bar-row">
        <div class="bar-label" title="${esc(d.label)}">${esc(d.label.replace(" Only","").replace("LLM + ","").replace("Proposed ",""))}</div>
        <div class="bar-track">
          <div class="bar-fill ${esc(d.color)}" style="width:${pct}%"></div>
        </div>
        <div class="bar-value">${esc(d.display)}</div>
      </div>`;
  }).join("");
}

// ---------------------------------------------------------------------------
// Cases table
// ---------------------------------------------------------------------------

let _allCaseRows = [];  // flat list of {configId, case}

function renderCasesTable(configIds, caseResults) {
  _allCaseRows = [];
  configIds.forEach(id => {
    (caseResults[id] || []).forEach(c => _allCaseRows.push({ configId: id, c }));
  });
  filterAndRenderCases();
}

function filterAndRenderCases() {
  const configFilter  = $("#case-config-filter")?.value  || "";
  const outcomeFilter = $("#case-outcome-filter")?.value || "";

  const rows = _allCaseRows.filter(({ configId, c }) => {
    if (configFilter  && configId !== configFilter)          return false;
    if (outcomeFilter && (c.outcome || "unknown") !== outcomeFilter) return false;
    return true;
  });

  const tbody = $("#cases-tbody");
  if (!tbody) return;

  tbody.innerHTML = rows.map(({ configId, c }, i) => {
    const outcomeClass = {
      TP: "outcome-tp", FP: "outcome-fp",
      TN: "outcome-tn", FN: "outcome-fn",
    }[c.outcome] || "outcome-unknown";

    const alertCell = c.alert_fired
      ? `<span class="alert-yes">Yes</span>`
      : `<span class="alert-no">No</span>`;

    const riskCell = c.risk_score != null
      ? `${parseFloat(c.risk_score).toFixed(1)}<br><small class="text-muted">${esc(c.risk_score_source || "")}</small>`
      : `<span class="metric-na">—</span>`;

    const llmCell = c.llm_status === "available"
      ? `<span class="badge badge-success">${esc(c.llm_status)}</span>`
      : c.llm_status === "not_run"
        ? `<span class="badge badge-muted">—</span>`
        : `<span class="badge badge-warning">${esc(c.llm_status)}</span>`;

    const judgeCell = c.judge_status
      ? `<span class="badge ${c.judge_status === 'passed' ? 'badge-success' : c.judge_status === 'failed' ? 'badge-error' : 'badge-warning'}">${esc(c.judge_status)}</span>`
      : `<span class="metric-na">—</span>`;

    const ragCount = (c.retrieved_evidence || []).length;
    const gtCell   = c.ground_truth_label ? `<span class="badge ${c.ground_truth_label === 'malicious' ? 'badge-error' : 'badge-muted'}">${esc(c.ground_truth_label)}</span>` : '<span class="metric-na">—</span>';
    const outcomeCell = c.outcome && c.outcome !== "unknown"
      ? `<span class="${outcomeClass}">${esc(c.outcome)}</span>`
      : '<span class="outcome-unknown">—</span>';

    const idx = _allCaseRows.indexOf(_allCaseRows.find((r,ri) => r.configId === configId && ri <= i && r.c === c));

    return `<tr>
      <td><code style="font-size:0.7rem">${esc((c.event_id || "").substring(0,20))}</code></td>
      <td><span class="badge badge-muted">${esc(CONFIG_NAMES[configId] || configId)}</span></td>
      <td>${alertCell}</td>
      <td>${riskCell}</td>
      <td>${llmCell}</td>
      <td>${judgeCell}</td>
      <td>${ragCount > 0 ? `<span class="badge badge-primary">${ragCount}</span>` : '<span class="metric-na">0</span>'}</td>
      <td>${gtCell}</td>
      <td>${outcomeCell}</td>
      <td>${c.latency_ms != null ? parseFloat(c.latency_ms).toFixed(0) + " ms" : '<span class="metric-na">—</span>'}</td>
      <td><button class="btn-xs" onclick="showCaseDetail('${esc(configId)}','${esc(c.event_id)}')">Details</button></td>
    </tr>`;
  }).join("");

  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="11" style="text-align:center;color:var(--text-muted);padding:1.5rem">No cases match the current filter.</td></tr>';
  }
}

window.showCaseDetail = function(configId, eventId) {
  const row = _allCaseRows.find(r => r.configId === configId && r.c.event_id === eventId);
  if (!row) return;
  const c = row.c;

  const modal  = $("#case-modal");
  const title  = $("#modal-title");
  const body   = $("#modal-body");
  title.textContent = `Case: ${c.event_id} — ${CONFIG_NAMES[configId] || configId}`;

  let html = `
    <div class="detail-section">
      <h4>Classification</h4>
      <div class="detail-row"><span class="detail-key">Alert fired</span><span class="detail-val">${c.alert_fired ? "Yes" : "No"}</span></div>
      <div class="detail-row"><span class="detail-key">Risk score</span><span class="detail-val">${c.risk_score != null ? parseFloat(c.risk_score).toFixed(2) : "N/A"}</span></div>
      <div class="detail-row"><span class="detail-key">Risk level</span><span class="detail-val">${esc(c.risk_level || "N/A")}</span></div>
      <div class="detail-row"><span class="detail-key">Risk source</span><span class="detail-val">${esc(c.risk_score_source || "none")}</span></div>
      <div class="detail-row"><span class="detail-key">Ground truth</span><span class="detail-val">${esc(c.ground_truth_label || "N/A")}</span></div>
      <div class="detail-row"><span class="detail-key">Outcome</span><span class="detail-val">${esc(c.outcome || "unknown")}</span></div>
      <div class="detail-row"><span class="detail-key">Latency</span><span class="detail-val">${c.latency_ms != null ? parseFloat(c.latency_ms).toFixed(1) + " ms" : "N/A"}</span></div>
    </div>`;

  if ((c.rule_ids_fired || []).length > 0) {
    html += `
      <div class="detail-section">
        <h4>Rule Engine</h4>
        <div class="detail-row"><span class="detail-key">Rules fired</span><span class="detail-val">${esc((c.rule_ids_fired || []).join(", "))}</span></div>
        <div class="detail-row"><span class="detail-key">Rule names</span><span class="detail-val">${esc((c.rule_names_fired || []).join(", "))}</span></div>
        <div class="detail-row"><span class="detail-key">MITRE technique</span><span class="detail-val">${esc(c.mitre_technique_id || "N/A")}</span></div>
      </div>`;
  }

  if ((c.retrieved_evidence || []).length > 0) {
    const evRows = (c.retrieved_evidence || []).map(ev =>
      `<li><strong>${esc(ev.title || ev.doc_id)}</strong> (score: ${(ev.score || 0).toFixed(3)}) — ${esc((ev.snippet || "").substring(0, 150))}</li>`
    ).join("");
    html += `<div class="detail-section"><h4>RAG Evidence (${c.retrieved_evidence.length} hits)</h4><ul class="detail-list">${evRows}</ul></div>`;
  }

  if (c.llm_status && c.llm_status !== "not_run") {
    html += `
      <div class="detail-section">
        <h4>LLM Analysis (${esc(c.llm_model || "unknown model")})</h4>
        <div class="detail-row"><span class="detail-key">Status</span><span class="detail-val">${esc(c.llm_status)}</span></div>`;
    if (c.llm_summary) html += `<div class="detail-row"><span class="detail-key">Summary</span><span class="detail-val">${esc(c.llm_summary)}</span></div>`;
    if (c.llm_reasoning) html += `<div><span class="detail-key">Reasoning</span><div class="detail-pre">${esc(c.llm_reasoning)}</div></div>`;
    if ((c.llm_recommendation || []).length > 0) {
      html += `<div class="detail-row"><span class="detail-key">Recommendations</span><ul class="detail-list">${
        (c.llm_recommendation || []).map(r => `<li>${esc(r)}</li>`).join("")
      }</ul></div>`;
    }
    html += `</div>`;
  }

  if (c.judge_status) {
    html += `
      <div class="detail-section">
        <h4>Judge Validation</h4>
        <div class="detail-row"><span class="detail-key">Status</span><span class="detail-val">${esc(c.judge_status)}</span></div>
        <div class="detail-row"><span class="detail-key">Checks passed</span><span class="detail-val">${c.judge_checks_passed ?? "N/A"} / ${c.judge_checks_total ?? "N/A"}</span></div>
        <div class="detail-row"><span class="detail-key">Evidence coverage</span><span class="detail-val">${c.evidence_coverage != null ? (c.evidence_coverage * 100).toFixed(1) + "%" : "N/A"}</span></div>`;
    if ((c.judge_issues || []).length > 0) {
      html += `<div class="detail-row"><span class="detail-key">Issues</span><ul class="detail-list">${
        c.judge_issues.map(i => `<li class="metric-warn">${esc(i)}</li>`).join("")
      }</ul></div>`;
    }
    html += `</div>`;
  }

  if (c.xai_why_alerted) {
    html += `
      <div class="detail-section">
        <h4>Deterministic XAI Explanation</h4>
        <div class="detail-row"><span class="detail-key">Why alerted</span><span class="detail-val">${esc(c.xai_why_alerted)}</span></div>
        <div class="detail-row"><span class="detail-key">Why risk</span><span class="detail-val">${esc(c.xai_why_risk || "")}</span></div>
        <div class="detail-row"><span class="detail-key">Uncertainty</span><span class="detail-val">${esc(c.xai_uncertainty || "")}</span></div>
      </div>`;
  }

  if (c.error) {
    html += `<div class="detail-section"><h4>Error</h4><div class="detail-pre metric-bad">${esc(c.error)}</div></div>`;
  }

  body.innerHTML = html;
  modal.hidden = false;
};

// ---------------------------------------------------------------------------
// Export helpers
// ---------------------------------------------------------------------------

function exportJson(exp) {
  const blob = new Blob([JSON.stringify(exp, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `experiment_${exp.experiment_id}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

async function downloadCsv(experimentId) {
  try {
    const res = await fetch(`/api/eval/experiments/${experimentId}/export/csv`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `experiment_${experimentId}_cases.csv`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) {
    showToast("CSV export failed: " + e.message);
  }
}

// ---------------------------------------------------------------------------
// Experiment history
// ---------------------------------------------------------------------------

async function loadHistory() {
  const section = $("#history-section");
  section.hidden = false;
  const list = $("#history-list");
  list.innerHTML = '<p class="muted-text">Loading…</p>';
  try {
    const res = await fetch("/api/eval/experiments");
    const experiments = await res.json();
    if (!experiments.length) {
      list.innerHTML = '<p class="muted-text">No previous experiments found.</p>';
      return;
    }
    list.innerHTML = experiments.map(e => `
      <div class="history-item">
        <div>
          <div class="history-meta">
            <strong>${esc(e.experiment_id)}</strong> —
            ${esc(e.created_at?.substring(0, 19).replace("T", " ") || "")} —
            <span class="badge ${e.status === 'completed' ? 'badge-success' : e.status === 'partial' ? 'badge-warning' : 'badge-error'}">${esc(e.status)}</span>
          </div>
          <div class="history-meta" style="margin-top:0.25rem">
            Dataset: ${esc(e.dataset_name || "unknown")} ·
            Configs: ${(e.selected_configurations || []).map(c => esc(CONFIG_NAMES[c] || c)).join(", ")}
            ${e.errors_count > 0 ? `· <span class="metric-warn">${e.errors_count} error(s)</span>` : ""}
          </div>
        </div>
        <div class="history-actions">
          <button class="btn btn-secondary" onclick="loadExperiment('${esc(e.experiment_id)}')">Load</button>
          <button class="btn-xs" onclick="deleteExperiment('${esc(e.experiment_id)}')">Delete</button>
        </div>
      </div>`).join("");
  } catch (err) {
    list.innerHTML = `<p class="muted-text">Failed to load history: ${esc(err.message)}</p>`;
  }
}

window.loadExperiment = async function(id) {
  showLoading(true, "Loading experiment…");
  try {
    const res = await fetch(`/api/eval/experiments/${id}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const exp = await res.json();
    EvalState.currentExperiment = exp;
    renderResults(exp);
    updateDatasetStats(exp.dataset);
    $("#history-section").hidden = true;
    showToast("Experiment loaded.", false);
  } catch (e) {
    showToast("Failed to load experiment: " + e.message);
  } finally {
    showLoading(false);
  }
};

window.deleteExperiment = async function(id) {
  if (!confirm(`Delete experiment ${id}? This cannot be undone.`)) return;
  try {
    const res = await fetch(`/api/eval/experiments/${id}`, { method: "DELETE" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    showToast("Experiment deleted.", false);
    loadHistory();
  } catch (e) {
    showToast("Delete failed: " + e.message);
  }
};

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

async function init() {
  initTabs();
  initFileUpload();
  initGroundTruth();

  // Load configurations
  try {
    const res = await fetch("/api/eval/configurations");
    const configs = await res.json();
    initConfigCards(configs);
  } catch (e) {
    showToast("Failed to load configurations: " + e.message);
  }

  await Promise.allSettled([loadGroundTruthList(), loadModelInfo()]);

  // Session ID field
  const sessionInput = $("#eval-session-id");
  if (sessionInput) {
    sessionInput.addEventListener("input", updateRunButton);
  }

  // Select all / none
  $("#select-all-btn").addEventListener("click", () => {
    EvalState.configurations.forEach(c => EvalState.selectedConfigs.add(c.config_id));
    updateConfigCardUI();
    updateRunButton();
  });
  $("#select-none-btn").addEventListener("click", () => {
    EvalState.selectedConfigs.clear();
    updateConfigCardUI();
    updateRunButton();
  });

  // Run button
  $("#run-btn").addEventListener("click", runExperiment);

  // History
  $("#view-history-btn").addEventListener("click", loadHistory);
  $("#close-history-btn").addEventListener("click", () => {
    $("#history-section").hidden = true;
  });

  // Clear results
  $("#clear-results-btn").addEventListener("click", () => {
    $("#results-section").hidden = true;
    EvalState.currentExperiment = null;
  });

  // Case filters
  const caseConfigFilter  = $("#case-config-filter");
  const caseOutcomeFilter = $("#case-outcome-filter");
  if (caseConfigFilter)  caseConfigFilter.addEventListener("change", filterAndRenderCases);
  if (caseOutcomeFilter) caseOutcomeFilter.addEventListener("change", filterAndRenderCases);

  // Modal close
  $("#modal-close").addEventListener("click", () => { $("#case-modal").hidden = true; });
  $("#modal-backdrop").addEventListener("click", () => { $("#case-modal").hidden = true; });
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") $("#case-modal").hidden = true;
  });
}

document.addEventListener("DOMContentLoaded", init);
