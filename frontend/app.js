const API = "/api/l1";

let currentSessionId = null;
let pendingFiles = [];
let selectedSource = null;

const $ = (sel) => document.querySelector(sel);

function showLoading(show) {
  const el = $("#loading");
  el.hidden = !show;
  el.style.display = show ? "flex" : "none";
}

function showToast(msg) {
  const toast = $("#toast");
  toast.textContent = msg;
  toast.hidden = false;
  setTimeout(() => { toast.hidden = true; }, 4000);
}

function formatNumber(n) {
  return n?.toLocaleString?.() ?? n;
}

function capitalize(s) {
  if (!s) return "—";
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function renderSourcesList(sources) {
  const container = $("#sources-summary-list");
  container.innerHTML = "<h3>Sources</h3><ul>" + 
    Object.keys(sources).map(src => `<li>✓ ${capitalize(src)}</li>`).join("") + 
    "</ul>";
}

function renderFilesList(files) {
  const container = $("#files-breakdown-list");
  container.innerHTML = files.map(f => `
    <div class="file-summary" style="margin-bottom: 10px; padding: 10px; border: 1px solid #ddd; border-radius: 4px;">
      <h4>${f.filename}</h4>
      <p><strong>Source:</strong> ${capitalize(f.source_detected)} | <strong>Format:</strong> ${f.format} | <strong>Status:</strong> ${f.status}</p>
      <p><strong>Events:</strong> ${f.total_events} | <strong>Normalized:</strong> ${f.normalized_events} | <strong>Failed:</strong> ${f.failed_events}</p>
    </div>
  `).join("");
}

function showResults(data) {
  currentSessionId = data.session_id;
  $("#results-section").hidden = false;
  
  if (data.report && data.report.overall) {
    const overall = data.report.overall;
    $("#result-total").textContent = formatNumber(overall.total_events);
    $("#result-success").textContent = formatNumber(overall.normalized_events);
    $("#result-failed").textContent = formatNumber(overall.failed_events);
    $("#result-duplicates").textContent = formatNumber(overall.duplicates_removed);
    
    renderSourcesList(data.report.sources || {});
    renderFilesList(data.report.files || []);
    
    const banner = $("#status-banner");
    if (overall.failed_events > 0) {
      banner.classList.add("has-errors");
      $("#status-text").textContent = "Normalization completed with errors";
      banner.querySelector(".status-icon").textContent = "!";
    } else {
      banner.classList.remove("has-errors");
      $("#status-text").textContent = "Normalization completed";
      banner.querySelector(".status-icon").textContent = "✓";
    }
  } else {
    // fallback for paste
    $("#result-total").textContent = formatNumber(data.total_events);
    $("#result-success").textContent = formatNumber(data.successfully_normalized);
    $("#result-failed").textContent = formatNumber(data.failed_events);
    $("#result-duplicates").textContent = formatNumber(data.duplicate_events);
    
    $("#sources-summary-list").innerHTML = `<h3>Source</h3><p>✓ ${capitalize(data.source_detected)}</p>`;
    $("#files-breakdown-list").innerHTML = `<p>Pasted Event</p>`;
  }
}

const UPLOAD_TIMEOUT_MS = 60000;

async function processFiles() {
  if (pendingFiles.length === 0) {
    showToast("No files selected");
    return;
  }
  showLoading(true);
  const form = new FormData();
  for (const file of pendingFiles) {
    form.append("files", file);
  }
  if (selectedSource) form.append("source_hint", selectedSource);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), UPLOAD_TIMEOUT_MS);

  try {
    const res = await fetch(`${API}/upload`, {
      method: "POST",
      body: form,
      signal: controller.signal,
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Upload failed");

    if (data.needs_source_selection && !selectedSource) {
      $("#source-select").hidden = false;
      showToast("Source uncertain — please select a platform");
      showLoading(false);
      return;
    }

    $("#source-select").hidden = true;
    $("#selected-files-container").hidden = true;
    showResults(data);
  } catch (err) {
    if (err.name === "AbortError") {
      showToast("Upload timed out — server did not respond within 60 seconds");
    } else {
      showToast(err.message || "Upload failed");
    }
  } finally {
    clearTimeout(timeoutId);
    showLoading(false);
  }
}

async function pasteEvent(sourceHint) {
  const text = $("#paste-input").value.trim();
  if (!text) {
    showToast("Please paste an event");
    return;
  }

  showLoading(true);
  const form = new FormData();
  form.append("event_text", text);
  if (sourceHint) form.append("source_hint", sourceHint);

  try {
    const res = await fetch(`${API}/paste`, { method: "POST", body: form });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Paste failed");
    showResults(data);
  } catch (err) {
    showToast(err.message);
  } finally {
    showLoading(false);
  }
}

function updateSelectedFilesList() {
  const container = $("#selected-files-container");
  const list = $("#selected-files-list");
  if (pendingFiles.length > 0) {
    container.hidden = false;
    list.innerHTML = pendingFiles.map(f => `<li>${f.name} (${formatNumber(f.size)} bytes)</li>`).join("");
  } else {
    container.hidden = true;
  }
}

// Event listeners
$("#choose-file-btn").addEventListener("click", () => $("#file-input").click());

$("#file-input").addEventListener("change", (e) => {
  if (e.target.files.length > 0) {
    pendingFiles = Array.from(e.target.files);
    updateSelectedFilesList();
  }
});

const dropZone = $("#drop-zone");
dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("drag-over");
});
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("drag-over");
  if (e.dataTransfer.files.length > 0) {
    pendingFiles = Array.from(e.dataTransfer.files);
    updateSelectedFilesList();
  }
});

$("#process-files-btn").addEventListener("click", () => processFiles());

document.querySelectorAll(".btn-source").forEach((btn) => {
  btn.addEventListener("click", () => {
    selectedSource = btn.dataset.source;
    document.querySelectorAll(".btn-source").forEach((b) => b.classList.remove("selected"));
    btn.classList.add("selected");
    showToast(`Source hint set to: ${capitalize(selectedSource)}`);
  });
});

$("#paste-btn").addEventListener("click", () => pasteEvent(selectedSource));

$("#view-events-btn").addEventListener("click", async () => {
  if (!currentSessionId) return;
  showLoading(true);
  try {
    const res = await fetch(`${API}/events/${currentSessionId}?limit=50`);
    const data = await res.json();
    $("#events-count").textContent = `(${formatNumber(data.total)} total)`;
    $("#events-preview").textContent = JSON.stringify(data.events, null, 2);
    $("#events-view").hidden = false;
  } catch (err) {
    showToast(err.message);
  } finally {
    showLoading(false);
  }
});

$("#close-events-btn").addEventListener("click", () => {
  $("#events-view").hidden = true;
});

$("#download-json-btn").addEventListener("click", () => {
  if (currentSessionId) {
    window.open(`${API}/download/${currentSessionId}/normalized_json`, "_blank");
  }
});

$("#download-report-btn").addEventListener("click", () => {
  if (currentSessionId) {
    window.open(`${API}/download/${currentSessionId}/report`, "_blank");
  }
});

let currentAssessmentResult = null;

async function generateSecurityAssessment() {
  if (currentAssessmentResult) {
    return currentAssessmentResult;
  }
  
  if (!currentSessionId) {
    throw new Error("No active session to assess.");
  }
  
  showLoading(true);
  $("#loading").querySelector("p").textContent = "Generating security assessment...";
  
  try {
    // 1. Get raw normalized events
    const evRes = await fetch(`${API}/events/${currentSessionId}?limit=10000`);
    const evData = await evRes.json();
    if (!evRes.ok) throw new Error(evData.detail || "Failed to fetch L1 events");
    
    // 2. Enrich events via L2
    const l2Res = await fetch("/api/l2/enrich/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(evData.events)
    });
    const enrichedEvents = await l2Res.json();
    if (!l2Res.ok) throw new Error("Security Assessment could not be generated because Context Enrichment failed.");
    
    // 3. Evaluate via Part 2
    const p2Res = await fetch("/api/part2/evaluate/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(enrichedEvents)
    });
    const assessments = await p2Res.json();
    if (!p2Res.ok) throw new Error("Security Assessment could not be generated because Rule/Risk Evaluation failed.");
    
    currentAssessmentResult = assessments;
    return assessments;
    
  } finally {
    $("#loading").querySelector("p").textContent = "Processing events locally...";
    showLoading(false);
  }
}

$("#view-assessment-btn").addEventListener("click", async () => {
  try {
    const assessments = await generateSecurityAssessment();
    
    if (Array.isArray(assessments) && assessments.length === 0) {
      $("#assessment-preview").textContent = 
`Security Assessment completed — no security alerts were generated for this dataset.

L1 Normalization: Complete
L2 Context Enrichment: Complete
Rule Evaluation: Complete
Security Assessment: No matching alerts`;
    } else {
      $("#assessment-preview").textContent = JSON.stringify(assessments, null, 2);
    }
    
    $("#assessment-view").hidden = false;
  } catch (err) {
    showToast(err.message);
  }
});

$("#close-assessment-btn").addEventListener("click", () => {
  $("#assessment-view").hidden = true;
});

$("#download-assessment-btn").addEventListener("click", async () => {
  try {
    const assessments = await generateSecurityAssessment();
    
    const blob = new Blob([JSON.stringify(assessments, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement("a");
    a.href = url;
    a.download = currentSessionId ? `security_assessment_${currentSessionId}.json` : "security_assessment.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (err) {
    showToast(err.message);
  }
});

// ---------------------------------------------------------------------------
// Full pipeline: L1 session -> L2 -> Part 2 -> L3 (LLM + Judge + XAI)
// ---------------------------------------------------------------------------

const PIPELINE_TIMEOUT_MS = 300000;

let currentPipelineResult = null;

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderList(items) {
  if (!items || items.length === 0) return "<p>—</p>";
  return "<ul>" + items.map((i) => `<li>${escapeHtml(i)}</li>`).join("") + "</ul>";
}

function renderStages(stages) {
  const cells = [
    ["L1 Normalized", stages.l1?.normalized_events],
    ["L2 Enriched", stages.l2?.enriched_events],
    ["Part 2 Alerts", stages.part2?.alerts],
    ["L3 Analyzed", stages.l3?.analyzed],
  ];
  $("#pipeline-stages").innerHTML = cells
    .map(
      ([label, value]) => `
    <div class="stat">
      <span class="stat-label">${label}</span>
      <span class="stat-value">${formatNumber(value ?? 0)}</span>
    </div>`
    )
    .join("");
}

function renderFinalAssessment(item) {
  const assessment = item.security_assessment || {};
  const risk = assessment.risk || {};
  const alert = assessment.alert || {};
  const xai = item.explanation || {};
  const llm = item.llm_analysis;
  const validation = item.validation || {};
  const mitre = assessment.mitre || {};

  return `
  <div class="analysis-card">
    <h3>${escapeHtml(alert.rule_name || assessment.alert_id)}</h3>
    <p class="analysis-meta">
      <strong>Alert:</strong> ${escapeHtml(assessment.alert_id)} |
      <strong>Severity:</strong> ${escapeHtml(alert.severity)} |
      <strong>Risk:</strong> ${escapeHtml(risk.score)}/100 (${escapeHtml(risk.level)}) |
      <strong>LLM:</strong> ${escapeHtml(item.llm_status)} |
      <strong>Judge:</strong> ${escapeHtml(validation.status)} |
      <strong>Status:</strong> ${escapeHtml(item.final_status)}
    </p>

    <h4>Why was this alert generated?</h4>
    <p>${escapeHtml(xai.why_alerted)}</p>

    <h4>Why this risk score?</h4>
    <p>${escapeHtml(xai.why_risk)}</p>

    <h4>Supporting factors</h4>
    ${renderList(xai.supporting_factors)}

    <h4>Context influences</h4>
    ${renderList(xai.context_influences)}

    <h4>MITRE ATT&amp;CK</h4>
    <p>${escapeHtml(mitre.technique_id || "—")} ${escapeHtml(mitre.technique_name || "")}</p>
    <p>${escapeHtml(xai.mitre_context)}</p>

    <h4>Evidence</h4>
    <p>${escapeHtml(xai.evidence_summary)}</p>

    <h4>Uncertainty</h4>
    <p>${escapeHtml(xai.uncertainty)}</p>

    <h4>LLM reasoning</h4>
    ${
      llm
        ? `<p><strong>Summary:</strong> ${escapeHtml(llm.summary)}</p>
           <p>${escapeHtml(llm.reasoning)}</p>
           <h4>Analyst recommendations</h4>
           ${renderList(llm.analyst_recommendation)}
           <h4>Possible interpretations</h4>
           ${renderList(llm.possible_interpretations)}`
        : "<p>LLM reasoning unavailable — deterministic results above remain valid.</p>"
    }

    <h4>Validation</h4>
    <p><strong>Evidence coverage:</strong> ${escapeHtml(validation.evidence_coverage)} |
       <strong>Checks passed:</strong> ${escapeHtml(validation.checks_passed)}/${escapeHtml(validation.checks_total)}</p>
    ${renderList(validation.issues)}
  </div>`;
}

function renderPipelineResult(result) {
  renderStages(result.stages || {});

  const finals = result.final_assessments || [];
  const container = $("#analysis-cards");

  if (finals.length === 0) {
    const alerts = result.stages?.part2?.alerts ?? 0;
    container.innerHTML = `<p>${
      alerts === 0
        ? "Pipeline completed — no security alerts were generated for this dataset."
        : "Alerts were generated but no L3 analysis was produced."
    }</p>`;
  } else {
    container.innerHTML = finals.map(renderFinalAssessment).join("");
  }

  $("#analysis-json").textContent = JSON.stringify(result, null, 2);
  $("#analysis-json").hidden = true;
  $("#toggle-analysis-json-btn").textContent = "Show Raw JSON";
  $("#analysis-view").hidden = false;
}

async function runFullPipeline() {
  if (!currentSessionId) throw new Error("No active session to analyze.");
  if (currentPipelineResult) return currentPipelineResult;

  showLoading(true);
  $("#loading").querySelector("p").textContent =
    "Running L2 enrichment, rules, risk, LLM reasoning, judge and XAI...";

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), PIPELINE_TIMEOUT_MS);

  try {
    const res = await fetch(`/api/pipeline/analyze/${currentSessionId}`, {
      method: "POST",
      signal: controller.signal,
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Full analysis failed");
    currentPipelineResult = data;
    return data;
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error("Full analysis timed out — the LLM did not respond in time");
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
    $("#loading").querySelector("p").textContent = "Processing events locally...";
    showLoading(false);
  }
}

$("#run-pipeline-btn").addEventListener("click", async () => {
  try {
    renderPipelineResult(await runFullPipeline());
  } catch (err) {
    showToast(err.message);
  }
});

$("#toggle-analysis-json-btn").addEventListener("click", () => {
  const pre = $("#analysis-json");
  pre.hidden = !pre.hidden;
  $("#toggle-analysis-json-btn").textContent = pre.hidden ? "Show Raw JSON" : "Hide Raw JSON";
});

$("#close-analysis-btn").addEventListener("click", () => {
  $("#analysis-view").hidden = true;
});

$("#download-analysis-btn").addEventListener("click", async () => {
  try {
    await runFullPipeline();
    window.open(`/api/pipeline/download/${currentSessionId}`, "_blank");
  } catch (err) {
    showToast(err.message);
  }
});

$("#new-upload-btn").addEventListener("click", () => {
  currentSessionId = null;
  currentAssessmentResult = null;
  currentPipelineResult = null;
  $("#analysis-view").hidden = true;
  pendingFiles = [];
  selectedSource = null;
  $("#file-input").value = "";
  $("#paste-input").value = "";
  $("#results-section").hidden = true;
  $("#events-view").hidden = true;
  $("#assessment-view").hidden = true;
  $("#source-select").hidden = true;
  $("#selected-files-container").hidden = true;
  document.querySelectorAll(".btn-source").forEach((b) => b.classList.remove("selected"));
});
