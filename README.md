# Cyber Defense Decision-Support Harness — Minor Prototype

## End-to-End Flow

```
Upload (Wazuh / Suricata / Firewall)
  ↓ L1        normalization           → NormalizedEvent[]
  ↓ L2        enrichment + CTI + MITRE → ContextEnrichedEvent[]
  ↓ Part 2    rule engine + risk engine → SecurityAssessment[]
  ↓ L3        LLM + Judge + XAI        → FinalSecurityAssessment[]
  ↓ Frontend
```

The UI uploads files to `/api/l1/upload` and then calls
`POST /api/pipeline/analyze/{session_id}`, which runs L2 → Part 2 → L3 over the
normalized events of that session and returns the per-stage counts, the Part 2
assessments and the final L3 results.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/pipeline/analyze/{session_id}` | Run L2 → Part 2 → L3 for an L1 session |
| GET | `/api/pipeline/result/{session_id}` | Last stored pipeline result |
| GET | `/api/pipeline/download/{session_id}` | Download the pipeline result JSON |

Query parameters on `analyze`: `run_llm` (default `true`) and `max_alerts`
(default `20`).

L3 reasoning requires `OPENROUTER_API_KEY` in the environment. Without it the
pipeline still completes: `llm_status` is `unavailable` and the deterministic
Part 2 risk plus the XAI explanation are returned unchanged.

## Module L1: Event Collection & Normalization

L1 ingests security logs from Wazuh, Suricata, and firewall sources, normalizes them into a unified event schema, validates, deduplicates, and produces L2-ready output.

### Architecture

```
INPUT (CSV/JSON/JSONL/LOG/TXT or paste)
  ↓
File detection → Parser → Source identification
  ↓
Field extraction → Field mapping → Normalization
  ↓
Schema validation → Deduplication → Quality report
  ↓
Unified Event JSON (L2-ready)
```

**Adapter hierarchy:**
```
BaseLogAdapter
 ├── WazuhAdapter
 ├── SuricataAdapter
 ├── FirewallAdapter
 └── GenericAdapter
```

### Quick Start

```bash
# Install dependencies
cd backend
pip install -r requirements.txt

# Run the server
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Open browser
# http://localhost:8000
```

### Run Tests

```bash
cd backend
pytest tests/ -v
```

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/l1/upload` | Upload log file (multipart form) |
| POST | `/api/l1/paste` | Paste single event |
| GET | `/api/l1/events/{session_id}` | Paginated normalized events |
| GET | `/api/l1/report/{session_id}` | Normalization report |
| GET | `/api/l1/download/{session_id}/{type}` | Download outputs |
| GET | `/api/l1/sources` | List supported sources |

### Output Files

Each processing session generates:

- `normalized_events.json` — Array of unified events
- `normalized_events.jsonl` — Line-delimited events
- `normalization_report.json` — Processing statistics
- `errors.json` — Failed/invalid events with reasons

### Test Data

Sample files in `test_data/`:

- `sample_wazuh.json`
- `sample_suricata.json`
- `sample_firewall.json`
- `sample_mixed.csv`
- `sample_logs.log`

### Limits

- Max file size: 20 MB
- Max events parsed/retained: 10,000
- Default AI batch size: 10 (for downstream L2)

### L2 Consumption

L2 reads `normalized_events.json` — a stable schema regardless of original source. Each event contains `source_platform` for audit only; L2 logic should not branch on it.
