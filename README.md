# SOC Analyst Co-Pilot

A local, explainable Cyber Defence Harness that transforms multi-source security telemetry into structured, risk-scored, and evidence-grounded security assessments — with an Evaluation Lab for controlled comparison of analysis architectures.

The system combines deterministic log normalisation, contextual asset and user enrichment, deterministic threshold and correlation rule evaluation, formulaic weighted risk scoring, Explainable AI (XAI) rationale generation, and optional evidence-grounded LLM advisory reasoning governed by a deterministic validation layer (the Judge). A separate Evaluation Lab enables side-by-side comparison of five distinct analysis configurations against the same normalised events.

---

## High-Level Purpose

Security Operations Centre (SOC) analysts face alert fatigue, siloed telemetry formats, and opaque black-box alerting. The SOC Analyst Co-Pilot addresses this by:

1. **Ingesting heterogeneous telemetry** — normalising disparate logs (Wazuh SIEM alerts, Suricata network intrusion events, and perimeter firewall logs) into a unified JSON event schema.
2. **Deterministic context enrichment** — correlating entities (IPs, hostnames, usernames) with asset criticality, user privileges, and initial threat intelligence from in-memory mock databases.
3. **Transparent rule detection and risk scoring** — applying explicit correlation rules and a six-factor weighted scoring formula (0–100) where the score is authoritative and cannot be altered by downstream AI models.
4. **Independent explainability (XAI)** — generating deterministic human-readable explanations answering *why* an alert fired, *why* a risk score was assigned, and what data is missing or uncertain.
5. **Governed LLM reasoning** — providing optional LLM-generated incident summaries, attack chain analyses, and recommendations, strictly constrained to supplied facts and audited by a rule-based Judge to prevent hallucinations.
6. **Controlled evaluation** — running the five configurations against identical inputs, recording reproducible experiment records, and computing measured metrics.

---

## System Architecture

```
[ Security Log Files / Text ]
  (Wazuh JSON, Suricata EVE, Firewall CSV/LOG, Generic)
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 1: L1 Ingestion & Normalisation                   │
│ - Parser (JSON / JSONL / CSV / Syslog text)             │
│ - Source platform auto-detection (Wazuh/Suricata/FW)    │
│ - Schema mapping → Unified NormalizedEvent              │
│ - SHA-256 event fingerprint deduplication               │
└──────────────────────────┬──────────────────────────────┘
                           │ NormalizedEvent[]
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 2: L2 Context Enrichment                          │
│ - Entity extraction (IPs, domains, hashes, users, hosts)│
│ - Context resolution (Mock Asset DB, Mock User DB)      │
│ - Keyword-based MITRE ATT&CK technique mapping          │
│ - Keyword CTI lookup (4-entry curated knowledge base)   │
└──────────────────────────┬──────────────────────────────┘
                           │ ContextEnrichedEvent[]
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 3: Part 2 Detection & Deterministic Risk Engine   │
│ - Custom JSON rule engine (single-event + threshold)    │
│ - Six-factor weighted risk formula (0–100)              │
│ - Risk level assignment (Low / Medium / High / Critical)│
└──────────────────────────┬──────────────────────────────┘
                           │ SecurityAssessment[]
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Integration Adapter (part2_to_l3.py)                    │
│ - Maps Part 2 schema to L3 input contract               │
│ - Queries Qdrant (BGE-M3 dense embeddings) for CTI      │
│ - Falls back to L2 keyword CTI if Qdrant unavailable    │
└──────────────────────────┬──────────────────────────────┘
                           │ L3 SecurityAssessment
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 4: L3 Reasoning, Validation & XAI                 │
│ ┌─────────────────────┐  ┌───────────────────────────┐  │
│ │ Deterministic XAI   │  │ LLM Reasoning (Optional)  │  │
│ │ (Explainer — always)│  │ OpenRouter primary +       │  │
│ │                     │  │ fallback model             │  │
│ └──────────┬──────────┘  └─────────────┬─────────────┘  │
│            │                           │                 │
│            │              ┌────────────▼─────────────┐  │
│            │              │ Deterministic Judge       │  │
│            │              │ (8-check hallucination    │  │
│            │              │  and consistency audit)   │  │
│            │              └────────────┬─────────────┘  │
│            ▼                           ▼                 │
│        FinalSecurityAssessment (Analyst Cards & JSON)    │
└─────────────────────────────────────────────────────────┘
```

---

## Status of Components

| Component | Status | Notes |
|---|---|---|
| **L1 Normalisation** | Implemented | JSON, JSONL, CSV, syslog. Wazuh, Suricata, Firewall, Generic adapters. SHA-256 deduplication. |
| **L2 Entity Extraction** | Implemented | Deterministic regex extraction of IPs, domains, URLs, hashes, ports, users, hosts. |
| **L2 Context Resolution** | Mock / In-Memory | Static dicts: `MOCK_ASSETS` (3 entries), `MOCK_USERS` (3 entries), `MOCK_THREATS` (2 entries). Not connected to live CMDB or directory. |
| **L2 CTI Lookup** | Implemented (4-entry fallback) | Keyword/tag search over a 4-item curated knowledge base. Reliable baseline used when vector retrieval is unavailable. |
| **L2 MITRE Mapping** | Implemented (keyword-based) | 4 keyword-to-technique mappings (T1110, T1548, T1059, T1204). Best-match on event text fields. |
| **Part 2 Custom Rule Engine** | Implemented | Proprietary JSON schema (`rules.json`). Supports `equals`, `contains`, `greater_than`, `less_than`, `in` operators and sliding-window threshold rules with `group_by`. Three active rules shipped. |
| **Sigma Rules** | Not Implemented | No Sigma parser, compiler, or `.yml` rule files. Rules use a custom JSON format only. |
| **Part 2 Risk Scoring** | Implemented | Six-factor deterministic weighted formula. Weights loaded from `risk_weights.json` and re-normalised to sum to 1.0 at runtime. |
| **L3 XAI (Explainer)** | Implemented | Fully deterministic. Runs unconditionally without LLM dependency. |
| **L3 LLM Engine** | Implemented | OpenRouter client. Primary model `deepseek/deepseek-v4-pro`, automatic fallback to `qwen/qwen-2.5-72b-instruct`. Degrades gracefully when unconfigured. |
| **L3 Judge** | Implemented | Eight deterministic checks. Detects hallucinated CVEs, APT groups, altered risk scores, and MITRE inconsistencies. |
| **BGE-M3 Embeddings** | Implemented | `sentence-transformers` wrapping `BAAI/bge-m3` (1024-dim). Lazy-loaded with threading lock. |
| **Vector Store / Qdrant** | Implemented | Qdrant client. In-memory mode (`:memory:`) when no server is configured; auto-seeds from `seed_knowledge.json` on first search. |
| **End-to-End RAG** | Implemented / Integrated | `part2_to_l3.py` queries Qdrant using BGE-M3, injects retrieved chunks into the L3 LLM prompt, and falls back to L2 CTI on Qdrant failure. |
| **Evaluation Lab** | Implemented (tests unverified) | Five configurations, metrics engine, persistence, FastAPI routes, and frontend UI. Regression test suite written but not yet executed. |
| **Knowledge Graph / GraphRAG** | Not Implemented | No graph database or graph traversal logic. |
| **Autonomous Multi-Agent** | Not Implemented | No multi-agent framework (LangGraph, CrewAI, etc.). Sequential deterministic pipeline only. |

---

## Detailed Component Breakdown

### 1. Ingestion & Normalisation (L1)

**Adapters** (`backend/l1/adapters/`):
- `wazuh_adapter.py` — Wazuh rule level, agent info, `full_log`, source IP/port.
- `suricata_adapter.py` — Suricata EVE alerts, flow metadata, signatures, category.
- `firewall_adapter.py` — Source/dest IPs, ports, action (`allow`/`block`).
- `generic_adapter.py` — Fallback for unstructured syslog and CSV entries.

**Normalised event required fields** (validated by `schema_validator.py`):
`event_id`, `timestamp`, `source_platform`, `source_type`, `event_type`.

**Deduplication**: SHA-256 fingerprint over `timestamp`, `source_platform`, `event_type`, `source.ip`, `destination.ip`, `action`, `message`. Duplicates removed before output is written.

**Output per session** (`backend/output/<session_id>/`):

| File | Contents |
|---|---|
| `normalized_events.json` | All unique normalised events (JSON array) |
| `normalized_events.jsonl` | Same events, one JSON object per line |
| `normalization_report.json` | Statistics: total, normalised, failed, duplicates |
| `errors.json` | Per-event normalisation error details |

**Limits** (from `l1/config.py`):

| Limit | Value |
|---|---|
| Max file size | 20 MB |
| Max events parsed | 10,000 |
| Max events retained after dedup | 10,000 |
| Max LLM batch size (default) | 20 |

### 2. Context Enrichment (L2)

- **Entity extraction** — Deterministic regex scan of structured keys and raw log messages. Extracts IPv4 addresses, domains, URLs, MD5/SHA-256 hashes, ports, usernames, and hostnames.
- **Asset context** — Resolves destination then source IP against `MOCK_ASSETS` (3 static entries for `10.0.0.5`, `10.0.0.50`, `192.168.1.100`). Returns an empty `AssetContext` for unknown IPs.
- **User context** — Resolves username against `MOCK_USERS` (3 static entries). Returns a partial `UserContext` with just the username for unknowns.
- **Threat context** — Resolves extracted IPs and domains against `MOCK_THREATS` (2 static entries). Returns empty `ThreatContext` for unknowns.
- **MITRE mapping** — Keyword match over `event_type`, `action`, `process.name`, and `message`. Best-match across 4 curated mappings (T1110, T1548, T1059, T1204).
- **CTI retrieval (L2)** — Keyword/tag search against the 4-entry `KNOWLEDGE_BASE` in `cti_knowledge_base.py`. This is a prototype fallback; the production path uses Qdrant (see RAG section).

> **Note**: All context resolvers in L2 use static in-memory mock data. They are not connected to live CMDBs, LDAP, Active Directory, or dynamic threat feeds.

### 3. Detection & Risk Engine (Part 2)

**Rule engine** (`part2/rules/rule_engine.py`):

Rules are defined in `part2/rules_config/rules.json` using a proprietary JSON schema — not Sigma. Three rules are active:

| Rule ID | Name | Type | Trigger |
|---|---|---|---|
| `AUTH-001` | Multiple Failed Authentication Attempts | Threshold | ≥5 `authentication_failure` events from the same source IP within 5 minutes |
| `ASSET-001` | High Criticality Asset Activity | Single-event | `asset_context.criticality == "critical"` |
| `PRIV-001` | Privileged User Suspicious Activity | Single-event | `user_context.privilege_level` in `[privileged, root, domain_admin, system, admin, administrator]` |

Supported condition operators: `equals`, `contains`, `greater_than`, `less_than`, `in`.

**Risk scoring formula** (`part2/risk/scoring.py`):

$$\text{Score} = \sum_{i} \text{NormalisedFactor}_i \times \text{NormalisedWeight}_i$$

Six factors with default weights from `risk_weights.json`:

| Factor | Default Weight |
|---|:---:|
| `severity` | 0.35 |
| `confidence` | 0.20 |
| `asset_criticality` | 0.20 |
| `user_privilege` | 0.10 |
| `threat_context` | 0.10 |
| `mitre_context` | 0.05 |

Weights are re-normalised at runtime to sum to 1.0. Score range: 0–100.

Risk level brackets:

| Score | Level |
|:---:|---|
| 0 ≤ score < 25 | Low |
| 25 ≤ score < 50 | Medium |
| 50 ≤ score < 75 | High |
| 75 ≤ score ≤ 100 | Critical |

**Invariant**: Once computed by Part 2, the risk score is immutable. Downstream LLM and Judge components read the score but must not alter it.

### 4. Dense-Vector RAG and Evidence Retrieval

**Embeddings** (`backend/embeddings/`):

- Model: `BAAI/bge-m3` via `sentence-transformers`. 1024-dimensional dense vectors.
- Lazy-loaded on first call (threading lock prevents duplicate loads).
- Device: `auto` — uses CUDA if available, falls back to CPU.
- Batch size: 8 (configurable via `EMBEDDING_BATCH_SIZE`).

**Vector store** (`backend/vectorstore/`):

- Client: `qdrant-client`. Supports in-memory mode (`:memory:`), local Docker, and remote networked Qdrant.
- Collection: `cybersecurity_knowledge` (configurable).
- Auto-seeds from `vectorstore/knowledge_config/seed_knowledge.json` when the collection is empty.
- Also ingests the L2 4-entry CTI knowledge base via `documents.cti_documents()`.
- Similarity: cosine distance. Default score threshold: 0.5. Default top-k: 3.

**Integration** (`backend/integration/part2_to_l3.py`):

The integration adapter calls `retrieve_for_assessment()` to query Qdrant using BGE-M3 embeddings of the Part 2 assessment text (built by `assessment_to_text()` in `embeddings/text_builder.py`). Retrieved chunks are injected into the L3 LLM prompt as `[RETRIEVED CTI]`. If Qdrant is offline or returns an error, the adapter falls back silently to the L2 keyword CTI items already attached to the enriched events.

### 5. L3 Analysis, Explainability, LLM, and Judge

**Explainer** (`l3/xai/explainer.py`) — Always runs, fully deterministic:
- *Why alerted*: Rule name, condition, threshold, and description.
- *Why risk*: Score, level, and contributing factor list.
- *Supporting factors*: Source/dest IPs, ports, username, process, action, protocol, severity, risk factors, evidence count.
- *Context influences*: Source platform, hostname, message preview, CTI count.
- *Uncertainty*: HIGH if no evidence and missing fields; MEDIUM if fewer than 3 evidence items; LOW otherwise.
- *MITRE context*: technique ID, name, tactic, sub-technique.
- *Evidence summary*: Count of structured evidence items and CTI snippets.

**LLM engine** (`l3/reasoning/llm_engine.py`):

- Calls OpenRouter via `openrouter_client.py`. Temperature: 0.1. Max tokens: 2048.
- Primary model: `deepseek/deepseek-v4-pro`. Fallback: `qwen/qwen-2.5-72b-instruct`.
- Fallback triggers on HTTP 429, 500–504, 404, recoverable 400 errors, and network timeouts.
- Strips `<think>…</think>` reasoning tags before JSON parsing.
- Filters MITRE interpretations to only the technique IDs supplied in the assessment.
- Returns `(None, LLMStatus.UNAVAILABLE, error_msg)` when unconfigured or offline — the pipeline never crashes.

**Prompt builder** (`l3/reasoning/prompt_builder.py`):

Constructs a structured user prompt with eight labelled sections: `[EVENT]`, `[CONTEXT]`, `[MITRE MAPPING]`, `[RULE RESULT]`, `[RISK FACTORS]`, `[RETRIEVED CTI]`, `[AVAILABLE EVIDENCE]`, `[INSTRUCTIONS]`. Each section is labelled so LLM claims can be traced to a source.

**The Judge** (`l3/validation/judge.py`) — Eight deterministic checks:

| Check | Type | Failure → |
|---|---|---|
| `SCHEMA_COMPLETENESS` | Critical | `FAILED` |
| `SCHEMA_VERSION` | Critical | `FAILED` |
| `RISK_SCORE_UNCHANGED` | Critical | `FAILED` |
| `MITRE_CONSISTENCY` | Non-critical | `REVIEW` |
| `EVIDENCE_COVERAGE` | Non-critical | `REVIEW` |
| `UNCERTAINTY_WARRANTED` | Non-critical | `REVIEW` |
| `RECOMMENDATION_PRESENT` | Non-critical | `REVIEW` |
| `NO_UNSUPPORTED_CLAIMS` | Critical if matches found | `FAILED` |

Unsupported claim patterns: `CVE-NNNN-NNNN`, `APT\d+`, Lazarus/Cozy Bear/Fancy Bear, shodan, "malicious IP".

Validation statuses: `passed`, `review`, `failed`, `skipped` (when LLM was unavailable).

---

## Evaluation Lab

The Evaluation Lab is an additional feature that runs five controlled analysis configurations against the same normalised events and records reproducible experiment results. It does not alter the existing production pipeline.

### Architecture

```
Upload / Session ID
        │
        ▼ (L1 normalisation — once, shared)
┌───────────────────────────────────────────────────┐
│  Same normalised events → all selected configs    │
└──┬──────────┬─────────┬──────────┬───────────────┘
   ▼          ▼         ▼          ▼          ▼
Config A  Config B  Config C  Config D  Config E
   │
   ▼  per-config: CaseConfigResult[]  →  ConfigMetrics
        │
        ▼  Experiment record persisted to
           output/eval_experiments/<id>.json
```

### Five Evaluation Configurations

Each configuration genuinely enables or disables the specified components. A component failure is recorded as an error — it is never silently substituted.

| ID | Name | L1 | L2 | Rules | Risk | RAG | LLM | Judge | XAI |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `rule_based_only` | Rule-Based Only | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| `llm_only` | LLM Only | ✓ | ✓ | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ |
| `llm_rag` | LLM + RAG | ✓ | ✓ | ✗ | ✗ | ✓ | ✓ | ✗ | ✗ |
| `llm_rule_based` | LLM + Rule-Based | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ | ✗ |
| `full_framework` | Proposed Complete Framework | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

**Key constraints**:

- `llm_only` and `llm_rag`: any risk figure is labelled `risk_score_source: "llm_estimate"` — it is not the authoritative deterministic score.
- `llm_rule_based`: RAG is suppressed by temporarily patching `integration.part2_to_l3._retrieve_vector_cti` to return an empty list for the duration of that run only.
- `full_framework`: calls the existing `run_pipeline` / `analyze_assessments` production path without modification.
- The deterministic risk score from Part 2 is never modified in any configuration that uses it.

### Evaluation Metrics

Metrics requiring ground truth are set to `null` (not zero) when labels are absent. An explanatory note is attached to each `null` metric.

| Metric | Ground Truth Required |
|---|:---:|
| True / False Positives and Negatives | Yes |
| Precision, Recall, F1 | Yes |
| False Positive Rate, False Negative Rate | Yes |
| Mean / p95 / min / max latency (ms) | No |
| Mean risk score, standard deviation | No |
| LLM available / unavailable count | No |
| RAG retrieval count | No |
| Evidence grounding rate (mean coverage) | No |
| Judge passed / failed / review counts | No |
| Judge pass rate | No |

### Ground Truth Format

```json
{
  "dataset_id": "my-dataset",
  "name": "My Labelled Dataset",
  "description": "Optional description",
  "is_synthetic": false,
  "labels": [
    {
      "event_id": "EVT-001",
      "label": "malicious",
      "expected_rule_ids": ["AUTH-001"],
      "expected_risk_level": "high",
      "notes": "Optional annotation",
      "is_synthetic": false
    },
    {
      "event_id": "EVT-002",
      "label": "benign"
    }
  ]
}
```

`label` must be `"malicious"` or `"benign"`. `expected_rule_ids` and `expected_risk_level` are informational only — the evaluation engine does not enforce them. Synthetic data must be marked `"is_synthetic": true`; the UI displays a warning banner when synthetic labels appear in results.

A synthetic smoke-test dataset is included at `test_data/eval_ground_truth/synthetic_smoke_test.json` (6 events: 4 malicious, 2 benign) with matching pre-normalised events at `test_data/eval_ground_truth/synthetic_events.json`. These exist for pipeline smoke testing only and do not represent real-world detection performance.

---

## Installation

### Requirements

- Python 3.11 or later
- pip

Dependencies (from `backend/requirements.txt`):

```
fastapi>=0.115.0
uvicorn[standard]>=0.34.0
python-multipart>=0.0.20
pydantic>=2.11.0
pytest>=8.3.0
httpx>=0.28.0
sentence-transformers>=3.0.0
qdrant-client>=1.9.0
python-dotenv
```

### Setup

```bash
# 1. Clone the repository
git clone <repository-url>
cd SOC-_analyst_co-pilot

# 2. Create and activate a virtual environment
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

# 3. Install dependencies
pip install -r backend/requirements.txt

# 4. Configure environment variables
cp backend/.env.example backend/.env
# Edit backend/.env and set OPENROUTER_API_KEY (required for LLM features)
```

### Start the Server

```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The application starts on `http://localhost:8000`.

- Main analysis UI: `http://localhost:8000/`
- Evaluation Lab UI: `http://localhost:8000/eval-lab`
- Interactive API docs: `http://localhost:8000/docs`

---

## Configuration & Environment Variables

Create or update `backend/.env`:

```env
# ==============================================================================
# SOC Analyst Co-Pilot — Environment Configuration
# ==============================================================================

# OpenRouter API Key — leave blank to run in deterministic degraded mode
OPENROUTER_API_KEY=your-openrouter-api-key-here

# LLM Model Configuration
OPENROUTER_PRIMARY_MODEL=deepseek/deepseek-v4-pro
OPENROUTER_FALLBACK_MODEL=qwen/qwen-2.5-72b-instruct
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_TIMEOUT=60

# Logging
LOG_LEVEL=INFO

# Dense Embedding Settings
EMBEDDING_MODEL=BAAI/bge-m3
EMBEDDING_DEVICE=auto
EMBEDDING_BATCH_SIZE=8
EMBEDDING_MAX_LENGTH=1024
EMBEDDING_NORMALIZE=true

# Vector Store (Qdrant)
# Leave QDRANT_HOST and QDRANT_URL blank to use in-memory mode
QDRANT_HOST=
QDRANT_PORT=6333
QDRANT_URL=
QDRANT_COLLECTION=cybersecurity_knowledge
QDRANT_SCORE_THRESHOLD=0.5
QDRANT_TOP_K=3
```

### Degraded (No-LLM) Mode

If `OPENROUTER_API_KEY` is not set:
- L1, L2, Part 2 rules/risk scoring, and XAI remain fully operational.
- LLM analysis is skipped; `llm_status: "unavailable"` is recorded.
- The Judge is skipped; `validation.status: "skipped"` is recorded.
- Alert cards display: `LLM: unavailable | Judge: skipped | Status: llm_unavailable`.

---

## API Endpoints

### L1 — Ingestion

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/l1/upload` | Upload log files (multipart). Returns `session_id` and normalisation report. |
| `POST` | `/api/l1/paste` | Paste a single raw event or JSON blob. |
| `GET` | `/api/l1/events/{session_id}` | Retrieve normalised events (paginated: `offset`, `limit`). |
| `GET` | `/api/l1/download/{session_id}/{type}` | Download: `normalized_json` \| `normalized_jsonl` \| `report` \| `errors`. |
| `GET` | `/api/l1/report/{session_id}` | Normalisation report JSON. |
| `GET` | `/api/l1/sources` | List supported source platforms. |

### L2 — Context Enrichment

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/l2/enrich` | Enrich a single normalised event. |
| `POST` | `/api/l2/enrich/batch` | Enrich a list of normalised events. |

### Part 2 — Assessment

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/part2/evaluate` | Evaluate rules and risk for a single `ContextEnrichedEvent`. |
| `POST` | `/api/part2/evaluate/batch` | Evaluate rules and risk for a batch. |

### L3 — LLM Analysis

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/l3/analyze` | Run XAI, LLM, and Judge on a `SecurityAssessment`. |
| `POST` | `/api/l3/analyze/batch` | Batch analysis (max 20). |
| `GET` | `/api/l3/health` | L3 health and model configuration (key never returned). |
| `GET` | `/api/l3/schema` | JSON Schema for `SecurityAssessment` input. |
| `GET` | `/api/l3/schema/output` | JSON Schema for `FinalSecurityAssessment` output. |

### End-to-End Pipeline

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/pipeline/analyze/{session_id}` | Run L2 → Part 2 → L3 over an L1 session. Query params: `run_llm` (bool), `max_alerts` (int). |
| `GET` | `/api/pipeline/result/{session_id}` | Retrieve cached pipeline result. |
| `GET` | `/api/pipeline/download/{session_id}` | Download complete analysis report as JSON. |

### Evaluation Lab

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/eval/run/upload` | Upload files, normalise once, run selected configurations. |
| `POST` | `/api/eval/run/session/{session_id}` | Run evaluation against an existing L1 session. |
| `GET` | `/api/eval/experiments` | List all stored experiment summaries. |
| `GET` | `/api/eval/experiments/{id}` | Get full experiment record. |
| `DELETE` | `/api/eval/experiments/{id}` | Delete a stored experiment. |
| `GET` | `/api/eval/experiments/{id}/export/json` | Download experiment as JSON. |
| `GET` | `/api/eval/experiments/{id}/export/csv` | Download case-level results as CSV. |
| `GET` | `/api/eval/configurations` | List the five configuration descriptors. |
| `POST` | `/api/eval/ground-truth` | Upload ground truth labels (inline JSON body). |
| `POST` | `/api/eval/ground-truth/upload` | Upload ground truth as a `.json` file. |
| `GET` | `/api/eval/ground-truth` | List available ground truth datasets. |
| `GET` | `/api/eval/ground-truth/{dataset_id}` | Get a ground truth dataset. |
| `GET` | `/api/eval/health` | Evaluation Lab health check. |

### Application Health

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Application-level health check. Returns module list. |

---

## Web Interface

### Main Analysis (/)

1. **Upload / Ingestion** — Drag-and-drop or file selector. Supported: `.json`, `.jsonl`, `.csv`, `.log`, `.txt`. Max 20 MB per file.
2. **Ingestion Summary** — Total events, normalised count, failure count, duplicates removed, per-file breakdown.
3. **Run Full Analysis (L1 → L3)** — Triggers `POST /api/pipeline/analyze/{session_id}`.
4. **Analysis Cards** — One card per triggered alert:
   - Alert severity and immutable risk score.
   - Deterministic XAI explanation panels.
   - MITRE technique alignment.
   - LLM narrative and recommendations (or degraded-mode notice).
   - Judge validation status, check results, evidence coverage.
5. **Exports** — Normalised events JSON, normalisation report, Part 2 assessment JSON, final analysis JSON.

### Evaluation Lab (/eval-lab)

Accessible via the `🧪 Evaluation Lab →` link in the main application header.

**Step 1 — Dataset**: Upload files or enter an existing session ID. After normalisation, displays event count, deduplication statistics, and a SHA-256 dataset fingerprint.

**Step 2 — Ground Truth** *(optional)*: Select or upload a labelled JSON dataset. Without ground truth, classification metrics are skipped and a note is displayed.

**Step 3 — Configuration Selection**: Five selectable cards showing active components for each configuration. Any subset can be selected.

**Step 4 — Settings**: Max LLM alerts (1–20), experiment notes, and a read-only display of the active model identifier, RAG collection, and embedding model.

**Results Dashboard**: Comparative metrics table, three bar charts (alert detection rate, mean latency, mean risk score), and a filterable per-case table. Each row opens a case detail modal showing rule findings, retrieved evidence, LLM output, Judge decisions, XAI explanations, and errors — with rule-derived, retrieval-derived, and LLM-derived information clearly separated.

**Exports**: Full experiment JSON and case-level CSV for every completed experiment.

**History**: Lists all stored experiments with load and delete actions.

---

## Directory Structure

```
SOC-_analyst_co-pilot/
├── frontend/
│   ├── index.html              # Main analysis UI
│   ├── eval_lab.html           # Evaluation Lab UI
│   ├── app.js                  # Main UI JavaScript
│   ├── eval_lab.js             # Evaluation Lab JavaScript
│   ├── style.css               # Shared dark-theme styles
│   └── eval_lab.css            # Evaluation Lab supplemental styles
│
├── backend/
│   ├── main.py                 # FastAPI app, router registration, static files
│   ├── requirements.txt
│   ├── .env.example
│   │
│   ├── l1/                     # Stage 1: Ingestion & Normalisation
│   │   ├── adapters/           # wazuh, suricata, firewall, generic, base
│   │   ├── api/                # ingestion_routes.py (/api/l1/*)
│   │   ├── deduplication/      # fingerprint.py
│   │   ├── normalization/      # field_mapper, normalizer, schema_validator
│   │   ├── parsers/            # get_parser() dispatcher (stub module)
│   │   ├── reports/            # normalization_report.py
│   │   ├── config.py           # Limits and output directory
│   │   └── pipeline.py         # L1Pipeline class (main entry point)
│   │
│   ├── l2/                     # Stage 2: Context Enrichment
│   │   ├── api/                # enrichment_routes.py (/api/l2/*)
│   │   ├── context/            # resolvers.py (MOCK_ASSETS, MOCK_USERS, MOCK_THREATS)
│   │   ├── extractors/         # entity_extractor.py
│   │   ├── kb/                 # cti_knowledge_base.py (4-entry fallback)
│   │   ├── mapper/             # mitre_mapper.py (keyword-based, 4 rules)
│   │   ├── enricher.py         # enrich_event() orchestrator
│   │   └── models.py           # ContextEnrichedEvent and sub-models
│   │
│   ├── part2/                  # Stage 3: Detection & Risk
│   │   ├── api/                # assessment_routes.py (/api/part2/*)
│   │   ├── models/             # security_alert.py, security_assessment.py
│   │   ├── risk/               # risk_engine.py, scoring.py, weights.py
│   │   ├── rules/              # rule_engine.py, conditions.py, rule_schema.py
│   │   └── rules_config/       # rules.json (3 active rules), risk_weights.json
│   │
│   ├── integration/
│   │   └── part2_to_l3.py      # Adapter: Part2 → L3 schema + RAG retrieval
│   │
│   ├── l3/                     # Stage 4: LLM, Judge, XAI
│   │   ├── api/                # analysis_routes.py (/api/l3/*)
│   │   ├── models/             # schemas.py (all Pydantic contracts)
│   │   ├── reasoning/          # llm_engine.py, openrouter_client.py, prompt_builder.py
│   │   ├── validation/         # judge.py
│   │   ├── xai/                # explainer.py
│   │   ├── config.py           # OpenRouter and feature-flag settings
│   │   └── orchestrator.py     # Part3Orchestrator.analyze()
│   │
│   ├── pipeline/
│   │   ├── orchestrator.py     # run_pipeline(): L2 → Part2 → L3
│   │   └── routes.py           # /api/pipeline/* endpoints
│   │
│   ├── embeddings/
│   │   ├── config.py           # BGE-M3 settings
│   │   ├── service.py          # EmbeddingService (lazy-loaded)
│   │   ├── text_builder.py     # alert_to_text(), assessment_to_text()
│   │   └── validate.py         # Standalone embedding validation script
│   │
│   ├── vectorstore/
│   │   ├── config.py           # Qdrant connection settings
│   │   ├── store.py            # KnowledgeStore (Qdrant client wrapper)
│   │   ├── retriever.py        # retrieve_for_text/alert/assessment()
│   │   ├── documents.py        # seed_documents(), cti_documents()
│   │   ├── validate.py         # Standalone vector store validation script
│   │   └── knowledge_config/
│   │       └── seed_knowledge.json
│   │
│   ├── evaluation/             # Evaluation Lab
│   │   ├── models.py           # Pydantic schemas for experiments and metrics
│   │   ├── metrics.py          # compute_metrics(), classify_case()
│   │   ├── orchestrator.py     # run_experiment() entry point
│   │   ├── persistence.py      # JSON file storage (no new database)
│   │   ├── routes.py           # /api/eval/* FastAPI router
│   │   └── configs/
│   │       ├── rule_based_only.py
│   │       ├── llm_only.py
│   │       ├── llm_rag.py
│   │       ├── llm_rule_based.py
│   │       └── full_framework.py
│   │
│   ├── output/                 # Runtime-generated (gitignored)
│   │   ├── <session_id>/       # L1 session outputs
│   │   ├── eval_experiments/   # Evaluation Lab experiment records
│   │   └── eval_ground_truth/  # Uploaded ground truth datasets
│   │
│   └── tests/
│       ├── test_l1.py          # L1 normalisation tests
│       ├── test_pipeline.py    # Integration and pipeline regression tests
│       └── test_evaluation.py  # Evaluation Lab regression tests
│
└── test_data/
    ├── current_demo/
    │   ├── wazuh_alert.json
    │   ├── wazuh_incident.json
    │   ├── suricata_incident.json
    │   └── firewall_incident.json
    └── eval_ground_truth/
        ├── synthetic_smoke_test.json   # 6 labelled synthetic cases
        └── synthetic_events.json       # 6 matching pre-normalised events
```

---

## Testing

### Test Suites

Three test files are present in `backend/tests/`:

#### `test_l1.py`

Tests the L1 ingestion and normalisation pipeline.

| Test Class | What It Covers |
|---|---|
| `TestAdapters` | Wazuh/Suricata/Firewall source detection; Wazuh normalisation produces valid schema output |
| `TestDeduplication` | Duplicate events with identical fingerprints are removed |
| `TestPipeline` | Wazuh/Suricata/Firewall file processing; paste JSON; output file creation; no invented field values |

#### `test_pipeline.py`

Integration and regression tests for the full pipeline.

| Test Class | What It Covers |
|---|---|
| `TestIntegrationAdapter` | Part 2 → L3 schema conversion; risk score preserved through `to_l3_assessment()`; XAI runs without LLM |
| `TestJudgeValidation` | Judge detects hallucinated CVE and APT group names; returns `ValidationStatus.FAILED` |
| `TestEndToEndPipeline` | `run_pipeline(events, run_llm=False)` produces correct stage counts; `final_assessments` is empty when LLM is disabled |

#### `test_evaluation.py`

Regression tests for the Evaluation Lab.

| Test Class | What It Covers |
|---|---|
| `TestModels` | All 5 configs registered; component flags match spec; `CaseConfigResult` serialises; `Experiment` round-trips |
| `TestClassifyCase` | All four TP/FP/TN/FN cases; no-label returns UNKNOWN |
| `TestComputeMetrics` | Correct P/R/F1 with GT; null metrics without GT; latency stats; zero-case edge case; all-FP case; risk score stats; judge and LLM counts |
| `TestApplyGroundTruth` | Labels applied and outcomes set; no GT leaves UNKNOWN; partial labels handled |
| `TestResultsToCsvRows` | Flat dicts produced; empty input returns empty list |
| `TestPersistence` | Save/load/list/delete experiments; save/load ground truth |
| `TestRuleBasedOnly` | One result per event; no LLM fields; deterministic risk source; no RAG fields; empty input |
| `TestLLMOnly` | LLM unavailable → graceful result; no rule IDs; `risk_score_source == "llm_estimate"`; empty input |
| `TestLLMRAG` | RAG unavailable → graceful; RAG hits recorded when available; no rule IDs |
| `TestLLMRuleBased` | RAG suppressed (no `retrieved_evidence`); rule IDs present when alert fires |
| `TestFullFramework` | One result per event; deterministic risk source; score in 0–100; XAI present on alerted events |
| `TestOrchestrator` | Same event count across all configs; experiment persisted; metrics computed; GT applied; empty dataset; partial failure isolation; duplicate events |
| `TestRiskScoreInvariant` | `rule_based_only` and `full_framework` produce identical risk scores for the same events |
| `TestExistingPipelineRegression` | `run_pipeline(run_llm=False)` unchanged; eval import does not break production pipeline |
| `TestRouteHelpers` | `_parse_config_list` defaults; single; multiple; invalid → HTTP 400 |
| `TestGroundTruthEdgeCases` | Dataset fingerprint is deterministic; changes with different events |

### Test Status

**The test suite has not been executed.** All tests were written but no `pytest` run has been completed. Test results, pass/fail counts, and any defects are currently unknown.

### Running Tests Manually

```bash
# From the repository root, activate your virtual environment first

cd backend

# Run all three test files
python -m pytest tests/ -v

# Run only L1 tests
python -m pytest tests/test_l1.py -v

# Run only pipeline integration tests
python -m pytest tests/test_pipeline.py -v

# Run only Evaluation Lab tests
python -m pytest tests/test_evaluation.py -v

# Run a specific test class
python -m pytest tests/test_evaluation.py::TestRiskScoreInvariant -v

# Run with short traceback on first failure
python -m pytest tests/ -x --tb=short
```

### Pass Criteria

A test run is considered successful when all of the following hold:

1. `pytest` exits with code `0` (zero failures, zero errors).
2. All existing `test_l1.py` and `test_pipeline.py` tests pass — this confirms the production pipeline was not broken by the Evaluation Lab additions.
3. All `test_evaluation.py` tests pass, specifically:
   - `TestRiskScoreInvariant` passes — the deterministic risk score is identical between `rule_based_only` and `full_framework` for the same input events.
   - `TestOrchestrator::test_same_events_passed_to_all_configs` passes — all configurations receive the same event count.
   - `TestOrchestrator::test_partial_failure_does_not_stop_other_configs` passes — one failing config does not abort the others.
   - `TestLLMOnly`, `TestLLMRAG`, `TestLLMRuleBased` pass with mocked LLM clients — no paid API calls are made during unit tests.
   - `TestPersistence` passes — experiments and ground truth can be saved and retrieved correctly.
4. No test modifies production behaviour (no test alters `rules.json`, `risk_weights.json`, or any module-level singleton state permanently).

### Known Test Limitations

- LLM-dependent configurations (B, C, D, E) are tested with `unittest.mock.MagicMock`. Real end-to-end LLM execution is not covered by the automated suite and requires a valid `OPENROUTER_API_KEY` and live API access.
- Qdrant integration tests are not present; the test suite relies on Qdrant's in-memory mode or mocked retrieval.
- No FastAPI `TestClient` integration tests for the `/api/eval/*` routes exist yet.

---

## Output Files, Experiment History, and Exports

### L1 Session Outputs

Each L1 upload creates a session directory `backend/output/<session_id>/` containing:

| File | Format |
|---|---|
| `normalized_events.json` | JSON array of normalised events |
| `normalized_events.jsonl` | One event per line (JSONL) |
| `normalization_report.json` | Statistics and per-file breakdown |
| `errors.json` | Per-event error details |

### Pipeline Results

`POST /api/pipeline/analyze/{session_id}` writes `backend/output/<session_id>/final_analysis.json` containing all stages, enriched events, Part 2 assessments, and `FinalSecurityAssessment` objects.

### Evaluation Lab Persistence

| Path | Contents |
|---|---|
| `backend/output/eval_experiments/<id>.json` | Full experiment record |
| `backend/output/eval_ground_truth/<id>.json` | Ground truth dataset |

Each experiment record captures:
- Experiment ID, timestamps, status.
- Dataset fingerprint (SHA-256 of normalised events JSON).
- Selected configurations, model identifier, rule-set fingerprint (SHA-256 of `rules.json`), RAG collection name, embedding model.
- Per-case `CaseConfigResult` objects for every configuration run.
- Aggregate `ConfigMetrics` per configuration.
- Warnings and errors.
- `schema_version: "1.0"`, `software_version: "1.0.0"`.

### Export Formats

| Format | How to Obtain |
|---|---|
| Full experiment JSON | `GET /api/eval/experiments/{id}/export/json` or the Export JSON button in the UI |
| Case-level CSV | `GET /api/eval/experiments/{id}/export/csv` or the Export CSV button in the UI |
| Normalised events JSON | `GET /api/l1/download/{session_id}/normalized_json` |
| Normalisation report JSON | `GET /api/l1/download/{session_id}/report` |
| Final analysis JSON | `GET /api/pipeline/download/{session_id}` |

---

## Security Considerations

- **API keys**: `OPENROUTER_API_KEY` is read from the environment or `.env` file and is never written to logs, responses, or exported files. The `/api/l3/health` endpoint returns model names but not the key.
- **File uploads**: Validated by extension (`.json`, `.jsonl`, `.csv`, `.log`, `.txt`) and size (20 MB cap). File content is treated as untrusted data — uploaded events are not executed or evaluated as code.
- **Session IDs**: Validated against `^[A-Za-z0-9_-]{1,64}$` before use in filesystem paths to prevent path traversal.
- **Ground truth uploads**: Size-capped at 5 MB. Label values validated to `"malicious"` or `"benign"` only.
- **Log content sanitisation**: All user-supplied content is HTML-escaped before rendering in the frontend (`escapeHtml()`).
- **LLM output**: Treated as untrusted. The Judge layer applies deterministic checks before any LLM output is presented as authoritative. The deterministic risk score and MITRE mapping from Part 2 are never overwritten by LLM responses.
- **CORS**: Currently set to `allow_origins=["*"]` for development. Restrict before production deployment.
- **No authentication**: The application does not implement authentication or authorisation. Do not expose it on a public network without an appropriate access control layer.

---

## Current Limitations & Known Gaps

1. **Mock resolution data**: Asset inventories, user identities, and threat indicators in L2 use static in-memory dictionaries (`MOCK_ASSETS` — 3 entries; `MOCK_USERS` — 3 entries; `MOCK_THREATS` — 2 entries). They are not connected to live CMDBs, LDAP, Active Directory, or dynamic threat feeds.
2. **Custom rule format**: Rules use a proprietary JSON schema (`rules.json`). Industry-standard Sigma rules are not supported — there is no Sigma parser or compiler.
3. **Batch size limit**: L3 LLM analysis is capped at 20 alerts per batch (`DEFAULT_MAX_LLM_ALERTS`) to avoid upstream API timeouts.
4. **Local CPU embedding latency**: Running `BAAI/bge-m3` on CPU is slower than GPU acceleration. First-call latency includes model loading time.
5. **Evaluation Lab tests unverified**: The regression test suite in `test_evaluation.py` was written but not executed. Results are unknown.
6. **No authentication or authorisation**: The API has no access controls. Suitable for local/development use only.
7. **Evaluation Lab: sequential execution**: Configurations run sequentially in a single request. Large datasets with multiple LLM-enabled configurations will have long wall-clock times.
8. **Evaluation Lab: no concurrency protection**: Multiple simultaneous experiment runs share the same singleton rule engine and risk engine instances.

---

## Future Roadmap

- **Enterprise asset and identity connectors**: Replace in-memory mock dictionaries with live connectors for CMDBs (ServiceNow), Active Directory / Okta, and external CTI feeds (MISP, AlienVault OTX).
- **Sigma rule engine**: Integrate a native Sigma compiler to translate open-source Sigma detection rules into the engine's condition tree.
- **Interactive analyst feedback loop**: Allow analysts to confirm or dismiss alerts, capturing feedback to refine risk factor weights over time.
- **Incremental knowledge base updates**: Automated pipelines to index new incident post-mortems and threat intelligence reports into the Qdrant collection.
- **Evaluation Lab regression test execution**: Run `pytest tests/test_evaluation.py`, fix any defects found, and establish a CI baseline.
- **Evaluation Lab FastAPI integration tests**: Add `TestClient`-based tests for `/api/eval/*` routes.
- **Evaluation concurrency**: Run selected configurations in parallel using `asyncio` or a worker pool to reduce wall-clock time for multi-config experiments.
