"""FastAPI routes for the end-to-end pipeline (L1 session -> L2 -> Part 2 -> L3).

The upload/normalization step keeps living in ``/api/l1/upload``; these routes
continue from the L1 session it created, so nothing is normalized twice.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from l1.api.ingestion_routes import pipeline as l1_pipeline
from pipeline.orchestrator import DEFAULT_MAX_LLM_ALERTS, run_pipeline

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/pipeline", tags=["End-to-End Pipeline"])

RESULT_FILENAME = "final_analysis.json"

SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _load_normalized_events(session_id: str) -> list[dict]:
    if not SESSION_ID_PATTERN.match(session_id):
        raise HTTPException(status_code=400, detail="Invalid session id")

    path = l1_pipeline.get_session_output(session_id, "normalized_json")
    if not path:
        raise HTTPException(
            status_code=404,
            detail=f"No normalized events found for session {session_id}",
        )

    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _result_path(session_id: str) -> Path:
    if not SESSION_ID_PATTERN.match(session_id):
        raise HTTPException(status_code=400, detail="Invalid session id")
    return l1_pipeline.output_dir / session_id / RESULT_FILENAME


@router.post("/analyze/{session_id}")
async def analyze_session(
    session_id: str,
    run_llm: bool = True,
    max_alerts: int = DEFAULT_MAX_LLM_ALERTS,
) -> JSONResponse:
    """Run L2 enrichment, Part 2 detection/risk and L3 reasoning for a session."""

    events = _load_normalized_events(session_id)

    try:
        result = run_pipeline(events, run_llm=run_llm, max_alerts=max_alerts)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Pipeline failed for session %s: %s", session_id, exc)
        raise HTTPException(
            status_code=500,
            detail=f"Pipeline failed: {exc}",
        ) from exc

    result["session_id"] = session_id

    result_path = _result_path(session_id)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    with open(result_path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, ensure_ascii=False)

    return JSONResponse(result)


@router.get("/result/{session_id}")
async def get_result(session_id: str) -> JSONResponse:
    """Return the last pipeline result stored for a session."""

    path = _result_path(session_id)
    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"No pipeline result for session {session_id}. Run the analysis first.",
        )

    with open(path, encoding="utf-8") as handle:
        return JSONResponse(json.load(handle))


@router.get("/download/{session_id}")
async def download_result(session_id: str) -> FileResponse:
    """Download the stored pipeline result as a JSON file."""

    path = _result_path(session_id)
    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"No pipeline result for session {session_id}. Run the analysis first.",
        )

    return FileResponse(
        path,
        media_type="application/json",
        filename=f"final_analysis_{session_id}.json",
    )
