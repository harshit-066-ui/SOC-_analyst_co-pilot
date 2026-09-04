---
name: testing-soc-pipeline
description: How to run and test the SOC Analyst Co-Pilot (L1 → L2 → Part 2 → L3) locally, including degraded no-LLM-key mode.
---

# Testing the SOC Analyst Co-Pilot end-to-end pipeline

## Run the app
```bash
cd backend && uvicorn main:app --port 8000
```
Deps: fastapi, uvicorn, pydantic, httpx, python-multipart (`pip install -r backend/requirements.txt`).
UI is served at http://localhost:8000/ (frontend/ is mounted at /static).

## Degraded (no LLM) mode
Leave `OPENROUTER_API_KEY` unset. Expected — NOT bugs:
- Server log lines: `LLM unavailable: OPENROUTER_API_KEY is not set.`
- Per-alert card shows `LLM: unavailable | Judge: skipped | Status: llm_unavailable`
  and "LLM reasoning unavailable — deterministic results above remain valid."
- Deterministic Part 2 risk score/level and the XAI sections must still render.
With a key set, LLM reasoning/judge sections should populate instead.

## UI flow
1. "Choose Files" → in the GTK file dialog press `ctrl+l`, type the *directory* path, Enter,
   then ctrl+click the files (typing a single file path only selects one file).
   Demo data: `test_data/current_demo/{wazuh,suricata,firewall}_incident.json`.
2. "Process Incident" → expect 19 total / 18 normalized / 0 failed / 1 duplicate removed.
3. "Run Full Analysis (L1 → L3)" → POST `/api/pipeline/analyze/{session_id}`; the
   "Final Security Analysis" section shows stage counts (18 / 18 / 8 alerts / 8 analyzed)
   and 8 alert cards. Results are cached client-side (`currentPipelineResult`), so a second
   click does not re-run the pipeline — click "Upload Another" to reset.
4. "Download Final Analysis" → `/api/pipeline/download/{session_id}` →
   `~/Downloads/final_analysis_<session>.json`.
5. Regression: "View Security Assessment" is the Part 2-only path
   (`/api/l1/events` → `/api/l2/enrich/batch` → `/api/part2/evaluate/batch`).

## Fast pre-check without the browser
```bash
curl -s -X POST localhost:8000/api/l1/upload -F "files=@test_data/current_demo/wazuh_incident.json" ...
curl -s -X POST localhost:8000/api/pipeline/analyze/<session_id>
```
Watch the uvicorn log for tracebacks — `backend/integration/part2_to_l3.py` is the schema
adapter between Part 2 and L3 and is the most likely place for shape mismatches.

## Devin Secrets Needed
- `OPENROUTER_API_KEY` — only if you want to test the non-degraded LLM/Judge path.
