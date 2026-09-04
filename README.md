# SOC Analyst Co-Pilot

A local, explainable Cyber Defense Harness that transforms multi-source security telemetry into structured, risk-scored, and evidence-grounded security assessments.

The system combines deterministic log normalization, contextual asset/user enrichment, deterministic threshold and correlation rule evaluation, formulaic weighted risk scoring, Explainable AI (XAI) rationale generation, and optional evidence-grounded Large Language Model (LLM) advisory reasoning governed by a deterministic validation layer ("The Judge").

---

## High-Level Purpose

Security Operations Center (SOC) analysts face alert fatigue, siloed telemetry formats, and opaque "black-box" alerting. The SOC Analyst Co-Pilot addresses this by:

1. **Ingesting Heterogeneous Telemetry**: Normalizing disparate logs (Wazuh SIEM alerts, Suricata network intrusion events, and perimeter firewall logs) into a unified JSON event schema.
2. **Deterministic Context Enrichment**: Correlating entities (IPs, hostnames, usernames) with asset criticality, user privileges, and initial threat intelligence.
3. **Transparent Rule Detection & Risk Scoring**: Applying explicit correlation rules and a multi-factor weighted scoring formula (0–100) where the score is **authoritative** and cannot be altered by downstream AI models.
4. **Independent Explainability (XAI)**: Generating deterministic human-readable explanations answering *why* an alert fired, *why* a risk score was assigned, and what data is missing or uncertain.
5. **Governed LLM Reasoning**: Providing optional LLM-generated incident summaries, attack chain analyses, and recommendations, strictly constrained to supplied facts and audited by a rule-based Judge to prevent hallucinations.

---

## System Architecture

```
[ Security Log Files / Text ]
  (Wazuh JSON, Suricata EVE, Firewall CSV/LOG, Generic)
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 1: L1 Ingestion & Normalization                   │
│ - Parser (JSON / JSONL / CSV / Syslog text)             │
│ - Source platform auto-detection (Wazuh/Suricata/FW)    │
│ - Schema mapping -> Unified NormalizedEvent             │
│ - SHA-256 event fingerprint deduplication               │
└──────────────────────────┬──────────────────────────────┘
                           │ NormalizedEvent[]
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 2: L2 Context Enrichment                          │
│ - Entity extraction (IPs, domains, hashes, users, hosts)│
│ - Context resolution (Mock Asset DB, Mock User DB)      │
│ - Keyword-based MITRE ATT&CK technique mapping          │
│ - Curated CTI lookup (Keyword text matching)            │
└──────────────────────────┬──────────────────────────────┘
                           │ ContextEnrichedEvent[]
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 3: Part 2 Detection & Deterministic Risk Engine   │
│ - Rule Engine (Single-event, threshold, time-window)    │
│ - Risk Engine (6-factor weighted calculation [0-100])   │
│ - Risk level assignment (Low / Medium / High / Critical)│
└──────────────────────────┬──────────────────────────────┘
                           │ Part 2 SecurityAssessment[]
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Integration Adapter (part2_to_l3.py)                    │
│ - Maps Part 2 alert schema to L3 input contract         │
│ - Packages event context, evidence, and CTI snippets    │
└──────────────────────────┬──────────────────────────────┘
                           │ L3 SecurityAssessment
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 4: L3 Reasoning, Validation & XAI                 │
│ ┌──────────────────────┐   ┌──────────────────────────┐ │
│ │ Deterministic XAI    │   │ LLM Reasoning (Optional) │ │
│ │ (Explainer - Always) │   │ (DeepSeek / Qwen Fallback│ │
│ └──────────┬───────────┘   └─────────────┬────────────┘ │
│            │                             │              │
│            │               ┌─────────────▼────────────┐ │
│            │               │ Deterministic Judge      │ │
│            │               │ (Hallucination & Rule    │ │
│            │               │  Consistency Audit)      │ │
│            │               └─────────────┬────────────┘ │
│            ▼                             ▼              │
│        FinalSecurityAssessment (Analyst Cards & JSON)   │
└─────────────────────────────────────────────────────────┘
```

---

## Status of Components

To maintain technical accuracy, the table below delineates what is genuinely implemented in the codebase versus what is partial, mocked, or planned for future development:

| Component | Status | Implementation Details |
|---|---|---|
| **L1 Normalization** | **Implemented** | Stream parsing for JSON, JSONL, CSV, and line-delimited logs. Platform adapters for Wazuh, Suricata, Firewall, and Generic. SHA-256 fingerprint deduplication. |
| **L2 Entity Extraction** | **Implemented** | Deterministic extraction of IPv4, domains, URLs, MD5/SHA256 hashes, ports, users, and hosts. |
| **L2 Context Resolution** | **Mock / In-Memory** | Static in-memory dictionaries for asset inventory (`MOCK_ASSETS`), user directory (`MOCK_USERS`), and threat reputation (`MOCK_THREATS`). |
| **L2 CTI Lookup** | **Implemented / Fallback** | 4-item hardcoded threat behavior dictionary matched via case-insensitive keyword/tag search, serving as reliable baseline/fallback. |
| **Part 2 Rule Engine** | **Implemented** | Custom Python JSON-based rule engine supporting field comparisons, threshold rules over time windows (`window_minutes`), and `group_by` correlation. |
| **Sigma Rules** | **Future / Not Implemented** | No Sigma rule parser, compiler, or `.yml` Sigma rule files exist in the codebase. Rules use a custom proprietary JSON schema (`rules.json`). |
| **Part 2 Risk Scoring** | **Implemented** | Formulaic, deterministic weighted scoring across 6 normalized factors (severity, confidence, asset criticality, user privilege, threat context, MITRE mapping). |
| **L3 Explainable AI (XAI)** | **Implemented** | Fully deterministic rationale builder (`Explainer`). Runs unconditionally without LLM dependencies. Explains triggering rule, risk breakdown, context influences, and data gaps. |
| **L3 LLM Engine** | **Implemented** | OpenRouter client with primary model (`deepseek/deepseek-v4-pro`) and automatic fallback (`qwen/qwen-2.5-72b-instruct`). Degrades gracefully when unconfigured or offline. |
| **L3 Judge / Validation** | **Implemented** | Deterministic 8-check audit of LLM output: checks schema completeness, invariant risk score preservation, MITRE consistency, evidence coverage, uncertainty justification, and sentinel hallucination patterns (e.g. invented CVEs or APT groups). |
| **Dense Embeddings** | **Implemented / Integrated** | Embedding service (`backend/embeddings`) wrapping HuggingFace `BAAI/bge-m3` (1024-dim dense vectors) via `sentence-transformers`. Generates semantic vectors for alerts and assessments. |
| **Vector Store / Qdrant** | **Implemented / Integrated** | Qdrant client (`backend/vectorstore`) supporting embedded in-memory (`:memory:`) or networked server mode. Auto-seeds curated security playbooks and CTI documents on first search. |
| **End-to-End Semantic RAG** | **Implemented / Integrated** | Canonical pipeline queries Qdrant using BGE-M3 dense embeddings (`backend/integration/part2_to_l3.py`), injects retrieved playbooks into the LLM prompt, validates grounded claims in the Judge, and falls back to Stage 2 CTI if vectorstore is offline. |
| **Knowledge Graph / GraphRAG** | **Future / Not Implemented** | No graph database, RDF/triplestore, or graph-traversal logic is present. |
| **Autonomous Multi-Agent** | **Future / Not Implemented** | No autonomous multi-agent execution frameworks (e.g., LangGraph, CrewAI). The system is a sequential deterministic pipeline with advisory LLM analysis. |

---

## Detailed Component Breakdown

### 1. Ingestion & Normalization (L1)
- **Adapters**:
  - `wazuh_adapter.py`: Parses Wazuh alerts (rule level, agent info, full_log, source IP/port).
  - `suricata_adapter.py`: Parses Suricata EVE alerts, flow metadata, signatures, and category.
  - `firewall_adapter.py`: Parses perimeter firewall logs (source/dest IPs, ports, action [allow/block]).
  - `generic_adapter.py`: Fallback for unstructured syslog and CSV entries.
- **Deduplication**: Calculates a canonical SHA-256 fingerprint from core attributes (`timestamp`, `source_platform`, `event_type`, `source.ip`, `destination.ip`, `action`, `message`).
- **Storage**: Outputs normalized records to `backend/output/<session_id>/normalized_events.json` and `.jsonl`.

### 2. Context Enrichment (L2)
- **Entity Extraction**: Scans both structured keys and freeform event log messages with regexes to identify indicators of compromise (IOCs), usernames, and hostnames.
- **Asset & User Enrichment**: Decorates events with environment criticality (`Critical`, `High`, `Low`) and user privilege tiers (`Root`, `System`, `Standard`) from local context resolvers.
- **MITRE Mapping**: Curated keyword-to-technique mapper associating events with techniques such as `T1110` (Brute Force), `T1548` (Abuse Elevation Control Mechanism), and `T1059` (Command Interpreters).

### 3. Detection & Risk Engine (Part 2)
- **Rule Engine**: Evaluates events against criteria defined in `rules_config/rules.json`. Supports operators (`equals`, `contains`, `greater_than`, `less_than`, `in`) and sliding-window event aggregation (e.g., 5 failed logins within 5 minutes grouped by source IP).
- **Risk Calculation**: Computes a weighted score between 0 and 100 based on weights in `rules_config/risk_weights.json`:
  $$\text{Score} = \sum_{i} \text{Factor}_i \times \text{NormalizedWeight}_i$$
  Categorizes scores into strict brackets:
  - `0 <= score < 25`: Low
  - `25 <= score < 50`: Medium
  - `50 <= score < 75`: High
  - `75 <= score <= 100`: Critical
- **Authority Invariant**: Once computed by Part 2, this score is immutable. Downstream components (LLM, XAI) treat it as ground truth.

### 4. LLM Reasoning, Validation & XAI (L3)
- **Explainer (XAI)**: Generates human-readable answers independently of whether an LLM is configured:
  - *Why alerted*: Exact rule name, condition, and matched threshold.
  - *Why risk*: Breakdown of contributing numerical factors and weights.
  - *Context influences*: Environmental factors (e.g., critical asset tag) that elevated severity.
  - *Uncertainty*: Identifies missing fields (e.g., missing destination IP or username).
- **LLM Reasoning**: Formulates an evidence-bound prompt containing only validated fields, CTI snippets, and rule results. Calls OpenRouter with temperature `0.1`.
- **The Judge**: Audits the LLM output:
  - Confirms the model did not invent external CVEs or threat actors.
  - Enforces that `risk.score` was not mutated or overridden.
  - Verifies that referenced MITRE techniques match the detection mapping.
  - Calculates evidence coverage ratio.

### 5. Embeddings & Vector Knowledge Store (Standalone)
- **Embeddings**: Utilizes `BAAI/bge-m3` (1024-dimensional dense vectors) via `sentence-transformers`.
- **Vector Store**: Qdrant client (`vectorstore/store.py`) configured for in-memory or networked vector search with payload filtering by platform, technique ID, and severity.
- **Text Builder**: Translates structured `SecurityAlert` or `SecurityAssessment` objects into formatted text blocks for semantic embedding.
- *Current Integration*: Validated via standalone scripts (`embeddings/validate.py`, `vectorstore/validate.py`), ready to replace the Stage 2 mock keyword store in a future update.

---

## End-to-End Pipeline & API Reference

### Core API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/l1/upload` | Upload log files (`.json`, `.jsonl`, `.csv`, `.log`, `.txt`). Returns session ID and normalization report. |
| `POST` | `/api/l1/paste` | Paste a single raw event or JSON blob for immediate normalization. |
| `GET` | `/api/l1/events/{session_id}` | Retrieve normalized events for a session. |
| `GET` | `/api/l1/download/{session_id}/{type}` | Download normalized JSON, JSONL, error log, or summary report. |
| `POST` | `/api/l2/enrich` | Enrich a single normalized event. |
| `POST` | `/api/l2/enrich/batch` | Enrich a list of normalized events. |
| `POST` | `/api/part2/evaluate` | Evaluate detection rules and compute risk score for a single enriched event. |
| `POST` | `/api/part2/evaluate/batch` | Evaluate rules and compute risk for a batch of enriched events. |
| `POST` | `/api/l3/analyze` | Run XAI, LLM reasoning, and validation on an L3-formatted security assessment. |
| `POST` | `/api/l3/analyze/batch` | Run L3 analysis on a batch of assessments (max 20). |
| `GET` | `/api/l3/health` | Check L3 health and OpenRouter model configuration. |
| `POST` | `/api/pipeline/analyze/{session_id}` | **Canonical End-to-End Execution**: Runs L2 enrichment, Part 2 rules/risk, schema adaptation, and L3 reasoning/XAI on an L1 session. |
| `GET` | `/api/pipeline/result/{session_id}` | Retrieve cached full pipeline results for a session. |
| `GET` | `/api/pipeline/download/{session_id}` | Download the complete final analysis report as JSON. |
| `GET` | `/health` | Application-level health probe verifying all module routers. |

### Web Interface Flow
1. **Upload / Ingestion**: Upload one or multiple log files via drag-and-drop or file selector.
2. **Ingestion Summary**: Inspect total events, normalization count, failure count, and duplicate removal statistics.
3. **Run Full Analysis (L1 → L3)**: Triggers `/api/pipeline/analyze/{session_id}`.
4. **Analysis Cards**: Displays interactive cards for each alert featuring:
   - Alert severity and immutable risk score.
   - Deterministic XAI explanation panels.
   - Grounded MITRE technique alignment.
   - LLM narrative summary and recommendations (or notice of degraded mode).
   - Judge validation status, check results, and evidence coverage percentage.
5. **Exports**: Download raw normalized events, validation logs, Part 2 assessment JSON, or complete end-to-end analysis reports.

---

## Configuration & Environment Variables

Create or update a `.env` file in the `backend/` directory:

```env
# ==============================================================================
# SOC Analyst Co-Pilot Configuration
# ==============================================================================

# OpenRouter API Key (leave blank to run in deterministic degraded mode)
OPENROUTER_API_KEY=your-openrouter-api-key-here

# LLM Model Configuration
OPENROUTER_PRIMARY_MODEL=deepseek/deepseek-v4-pro
OPENROUTER_FALLBACK_MODEL=qwen/qwen-2.5-72b-instruct
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_TIMEOUT=180

# Logging Configuration
LOG_LEVEL=INFO

# Optional: Dense Embedding Settings (backend/embeddings)
EMBEDDING_MODEL=BAAI/bge-m3
EMBEDDING_DEVICE=auto
EMBEDDING_BATCH_SIZE=8
EMBEDDING_MAX_LENGTH=1024
EMBEDDING_NORMALIZE=true

# Optional: Vector Store Settings (backend/vectorstore)
QDRANT_HOST=
QDRANT_PORT=6333
QDRANT_URL=
QDRANT_COLLECTION=cybersecurity_knowledge
QDRANT_SCORE_THRESHOLD=0.5
QDRANT_TOP_K=3
```

### Degraded (No-LLM) Mode
If `OPENROUTER_API_KEY` is not provided or is invalid:
- The system continues operating without throwing unhandled exceptions.
- Normalization (L1), enrichment (L2), detection & risk scoring (Part 2), and Explainable AI (L3 XAI) remain **100% operational**.
- Alert cards display `LLM: unavailable | Judge: skipped | Status: llm_unavailable`.
- The explanation explicitly notes: *"LLM reasoning unavailable — deterministic results above remain valid."*

---

## Current Limitations & Known Gaps

1. **Mock Resolution Data**: Asset inventories, user identities, and threat indicators in Stage 2 currently rely on static in-memory dictionaries (`MOCK_ASSETS`, `MOCK_USERS`, `MOCK_THREATS`) rather than live CMDB, LDAP/Active Directory, or dynamic threat feed connectors.
2. **Custom Rules Format**: Rules are evaluated via a custom JSON engine (`part2/rules/rule_engine.py`); industry-standard Sigma rules are not supported.
3. **Batch Size Limits**: L3 LLM analysis is capped at 20 alerts per batch to prevent upstream API timeouts.
4. **Local Hardware Requirements for Dense Embeddings**: Running `BAAI/bge-m3` locally on CPU introduces modest latency during vector retrieval compared to GPU acceleration.

---

## Future Roadmap

- **Enterprise Asset & Identity Connectors**: Replace in-memory dictionaries with live connectors for CMDBs (ServiceNow), Active Directory / Okta, and external CTI feeds (MISP, AlienVault OTX).
- **Sigma Rule Engine**: Integrate a native Sigma compiler to translate open-source Sigma detection rules directly into the engine's condition tree.
- **Interactive Analyst Feedback Loop**: Allow analysts to confirm or dismiss alerts, capturing feedback to refine risk factor weights over time.
- **Incremental Knowledge Base Updates**: Provide automated pipelines to index new incident post-mortems and threat intelligence feeds into the Qdrant collection.
