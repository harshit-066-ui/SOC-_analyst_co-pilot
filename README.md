# Cyber Defense Decision-Support Harness — Minor Prototype

## Embeddings (BGE-M3)

`backend/embeddings/` turns security text into dense vectors. BGE-M3 is used
because it runs locally (reproducible, no data leaves the host), is
multilingual and long-context, and supports the dense + sparse retrieval the
planned Qdrant stage needs. Nothing in the deterministic rule/risk/XAI pipeline
imports it; it is additive.

```python
from embeddings import assessment_to_text, embed_text, embed_texts

embed_text("Unauthorized privileged access was detected.")   # -> list[float], len 1024
embed_texts([...])                                            # batched
embed_text(assessment_to_text(part2_assessment))              # rule finding -> vector
```

The model is loaded lazily on first use by the process-wide
`get_embedding_service()` and reused afterwards (~12 s first load on CPU,
sub-second per batch after). Configuration is environment driven — see
`backend/embeddings/config.py`: `EMBEDDING_MODEL` (default `BAAI/bge-m3`),
`EMBEDDING_DEVICE` (`auto` → CUDA when available, else CPU; force with `cpu` /
`cuda`), `EMBEDDING_BATCH_SIZE`, `EMBEDDING_MAX_LENGTH`, `EMBEDDING_NORMALIZE`.

Validate the component with `cd backend && python -m embeddings.validate`.

## Vector store (Qdrant)

`backend/vectorstore/` stores the curated CTI knowledge base as BGE-M3 vectors
and returns the context documents closest to a rule finding. It is still
additive: the deterministic L1 → L2 → Part 2 → L3 pipeline does not call it,
and no prompt/LLM wiring exists yet.

```python
from vectorstore import cti_documents, get_context_store, retrieve_for_assessment

get_context_store().index_documents(cti_documents())   # one-time / on refresh
retrieve_for_assessment(part2_assessment)              # -> [{id, content, category, tags, score}]
```

The documents come from `l2/kb/cti_knowledge_base.KNOWLEDGE_BASE`, so keyword
retrieval (L2) and semantic retrieval share one source. Point IDs are
`uuid5(doc_id)`, so re-indexing updates rather than duplicates. The collection
is created on first use with BGE-M3's 1024 dimensions and cosine distance.

Config (`backend/vectorstore/config.py`): `QDRANT_URL` (default `:memory:`, an
embedded instance — set `http://localhost:6333` for a server),
`QDRANT_API_KEY`, `QDRANT_COLLECTION`, `QDRANT_TOP_K`,
`QDRANT_SCORE_THRESHOLD`, `QDRANT_TIMEOUT`. Run a server with
`docker run -p 6333:6333 qdrant/qdrant`, then check the layer with
`cd backend && python -m vectorstore.validate`.

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
