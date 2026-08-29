"""FastAPI routes for PART 3 — LLM Reasoning & Explainability.

Endpoints
---------
POST /api/l3/analyze
    Accept a SecurityAssessment JSON body (from PART 2).
    Run the full PART 3 pipeline and return FinalSecurityAssessment.

POST /api/l3/analyze/batch
    Accept a list of SecurityAssessment objects.
    Process each independently and return a list of FinalSecurityAssessment.

GET /api/l3/health
    Returns liveness status and OpenRouter configuration (without the key).

GET /api/l3/schema
    Returns the JSON Schema for SecurityAssessment (helps PART 2 integration).

Error handling
--------------
HTTP 422 — Pydantic validation failure on input (bad SecurityAssessment).
HTTP 500 — Unexpected internal error (should not occur due to orchestrator guards).
"""

from __future__ import annotations

import logging
import time

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from l3.config import OPENROUTER_MODEL, SCHEMA_VERSION
from l3.models.schemas import (
    FinalSecurityAssessment,
    SecurityAssessment,
)
from l3.orchestrator import Part3Orchestrator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/l3", tags=["L3 LLM Analysis"])

# Single shared orchestrator instance (stateless; thread-safe)
_orchestrator = Part3Orchestrator()


# ---------------------------------------------------------------------------
# POST /api/l3/analyze
# ---------------------------------------------------------------------------


@router.post(
    "/analyze",
    response_model=FinalSecurityAssessment,
    summary="Run PART 3 LLM analysis on a SecurityAssessment",
    description=(
        "Accepts a SecurityAssessment from PART 2 and runs the full PART 3 "
        "pipeline: XAI explanation → evidence-grounded LLM reasoning → "
        "deterministic validation. Returns a FinalSecurityAssessment. "
        "The deterministic risk score is never modified."
    ),
)
async def analyze(assessment: SecurityAssessment) -> FinalSecurityAssessment:
    """Main analysis endpoint."""
    start = time.perf_counter()
    logger.info("Received analysis request | alert_id=%s", assessment.alert_id)

    try:
        result = _orchestrator.analyze(assessment)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected error in orchestrator: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Internal analysis error: {exc}",
        ) from exc

    elapsed = time.perf_counter() - start
    logger.info(
        "Analysis complete | alert_id=%s | elapsed=%.2fs | status=%s",
        assessment.alert_id,
        elapsed,
        result.final_status.value,
    )
    return result


# ---------------------------------------------------------------------------
# POST /api/l3/analyze/batch
# ---------------------------------------------------------------------------


@router.post(
    "/analyze/batch",
    response_model=list[FinalSecurityAssessment],
    summary="Run PART 3 analysis on a batch of SecurityAssessments",
    description=(
        "Processes each SecurityAssessment independently. "
        "A failure on one item does not abort the batch — it returns a "
        "degraded result for that item instead."
    ),
)
async def analyze_batch(
    assessments: list[SecurityAssessment],
) -> list[FinalSecurityAssessment]:
    """Batch analysis endpoint."""
    if not assessments:
        raise HTTPException(status_code=400, detail="Empty batch provided.")
    if len(assessments) > 20:
        raise HTTPException(
            status_code=400,
            detail="Batch size exceeds maximum of 20 assessments per request.",
        )

    results: list[FinalSecurityAssessment] = []
    for assessment in assessments:
        try:
            result = _orchestrator.analyze(assessment)
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "Batch item failed | alert_id=%s: %s", assessment.alert_id, exc
            )
            # Produce a minimal failed result rather than aborting the batch
            from l3.models.schemas import (
                FinalStatus,
                LLMStatus,
                ValidationResult,
                ValidationStatus,
                XAIExplanation,
            )

            result = FinalSecurityAssessment(
                security_assessment=assessment,
                llm_analysis=None,
                llm_status=LLMStatus.UNAVAILABLE,
                validation=ValidationResult(
                    status=ValidationStatus.SKIPPED,
                    issues=[f"Analysis failed: {exc}"],
                    checks_run=[],
                    checks_passed=0,
                    checks_total=0,
                ),
                explanation=XAIExplanation(
                    why_alerted="Analysis failed.",
                    why_risk=f"Risk score: {assessment.risk.score:.1f}/100.",
                    supporting_factors=[],
                    context_influences=[],
                    uncertainty="Unknown — analysis failed.",
                    mitre_context="",
                    evidence_summary="",
                ),
                final_status=FinalStatus.LLM_UNAVAILABLE,
            )
        results.append(result)

    return results


# ---------------------------------------------------------------------------
# GET /api/l3/health
# ---------------------------------------------------------------------------


@router.get(
    "/health",
    summary="L3 liveness check",
)
async def health() -> JSONResponse:
    """Return health status and sanitised configuration."""
    from l3.config import OPENROUTER_API_KEY, OPENROUTER_BASE_URL

    key_configured = bool(OPENROUTER_API_KEY)
    return JSONResponse(
        {
            "status": "ok",
            "module": "L3",
            "schema_version": SCHEMA_VERSION,
            "openrouter": {
                "configured": key_configured,
                "model": OPENROUTER_MODEL,
                "base_url": OPENROUTER_BASE_URL,
                # The key itself is NEVER returned
            },
        }
    )


# ---------------------------------------------------------------------------
# GET /api/l3/schema
# ---------------------------------------------------------------------------


@router.get(
    "/schema",
    summary="JSON Schema for SecurityAssessment input",
    description="Returns the Pydantic-generated JSON Schema for the SecurityAssessment "
    "model so PART 2 can validate its output before sending.",
)
async def get_schema() -> JSONResponse:
    """Return the SecurityAssessment JSON Schema."""
    schema = SecurityAssessment.model_json_schema()
    return JSONResponse(schema)


# ---------------------------------------------------------------------------
# GET /api/l3/schema/output
# ---------------------------------------------------------------------------


@router.get(
    "/schema/output",
    summary="JSON Schema for FinalSecurityAssessment output",
)
async def get_output_schema() -> JSONResponse:
    """Return the FinalSecurityAssessment JSON Schema."""
    schema = FinalSecurityAssessment.model_json_schema()
    return JSONResponse(schema)
