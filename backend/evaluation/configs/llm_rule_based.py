"""Configuration D — LLM + Rule-Based.

Pipeline:  L2 enrichment → Part 2 rules + risk scoring → LLM interpretation
Disabled:  RAG, Judge, XAI

The LLM receives the deterministic rule findings. RAG is disabled.
Risk score is from the deterministic engine — clearly distinguished from any
LLM-derived conclusions.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from integration.part2_to_l3 import to_l3_assessment
from l2.enricher import enrich_event
from l2.models import ContextEnrichedEvent
from l3.models.schemas import SecurityAssessment as L3SecurityAssessment
from l3.reasoning.llm_engine import LLMEngine
from l3.reasoning.openrouter_client import LLMUnavailableError, OpenRouterClient
from part2.api.assessment_routes import assess_events
from part2.models.security_assessment import SecurityAssessment as Part2Assessment

logger = logging.getLogger(__name__)


def _index_enriched(
    enriched_list: list[ContextEnrichedEvent],
) -> dict[str, ContextEnrichedEvent]:
    index: dict[str, ContextEnrichedEvent] = {}
    for enriched in enriched_list:
        eid = enriched.event.get("event_id")
        if eid is not None:
            index[str(eid)] = enriched
    return index


def run(
    normalized_events: list[dict[str, Any]],
    llm_client: OpenRouterClient | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Run LLM + Rule-Based configuration. Returns (results, errors)."""
    errors: list[str] = []
    results: list[dict[str, Any]] = []
    client = llm_client or OpenRouterClient()
    llm_engine = LLMEngine(client=client)

    # Step 1: L2 enrichment
    try:
        enriched_list = [enrich_event(e) for e in normalized_events]
    except Exception as exc:
        err = f"[llm_rule_based] L2 enrichment failed: {exc}"
        logger.exception(err)
        errors.append(err)
        return [], errors

    # Step 2: Part 2 rules + risk scoring
    t0_rule = time.perf_counter()
    try:
        assessments = assess_events(enriched_list)
    except Exception as exc:
        err = f"[llm_rule_based] Part2 assessment failed: {exc}"
        logger.exception(err)
        errors.append(err)
        assessments = []
    rule_elapsed_ms = (time.perf_counter() - t0_rule) * 1000

    # Index assessments by event_id
    enriched_index = _index_enriched(enriched_list)
    alert_index: dict[str, list[Part2Assessment]] = {}
    for assessment in assessments:
        for eid in assessment.alert.event_ids:
            alert_index.setdefault(str(eid), []).append(assessment)

    per_event_rule_ms = rule_elapsed_ms / max(len(normalized_events), 1)

    for event in normalized_events:
        event_id = str(event.get("event_id", ""))
        matched_assessments = alert_index.get(event_id, [])

        if not matched_assessments:
            # No rule fired — no LLM call needed
            results.append(
                {
                    "event_id": event_id,
                    "alert_fired": False,
                    "rule_ids_fired": [],
                    "rule_names_fired": [],
                    "risk_score": None,
                    "risk_level": None,
                    "risk_score_source": "none",
                    "llm_status": "not_run",
                    "latency_ms": per_event_rule_ms,
                    "raw_output": {},
                }
            )
            continue

        # Use highest-risk assessment for LLM input
        best_assessment = max(matched_assessments, key=lambda a: a.risk.score)

        # Convert to L3 format WITHOUT RAG (no vector retrieval)
        t0 = time.perf_counter()
        try:
            l3_input = _to_l3_no_rag(best_assessment, enriched_index)
            llm_analysis, llm_status, llm_error = llm_engine.analyze(l3_input)
            latency_ms = (time.perf_counter() - t0) * 1000 + per_event_rule_ms

            results.append(
                {
                    "event_id": event_id,
                    "alert_fired": True,
                    "rule_ids_fired": [a.alert.rule_id for a in matched_assessments],
                    "rule_names_fired": [a.alert.rule_name for a in matched_assessments],
                    "risk_score": best_assessment.risk.score,
                    "risk_level": best_assessment.risk.level,
                    "risk_score_source": "deterministic",
                    "llm_summary": (
                        llm_analysis.summary if llm_analysis else None
                    ),
                    "llm_reasoning": (
                        llm_analysis.reasoning if llm_analysis else None
                    ),
                    "llm_status": llm_status.value,
                    "llm_model": client.model,
                    "llm_recommendation": (
                        llm_analysis.analyst_recommendation if llm_analysis else []
                    ),
                    "mitre_technique_id": best_assessment.mitre_attack.get(
                        "technique_id", ""
                    ),
                    "mitre_technique_name": best_assessment.mitre_attack.get(
                        "technique_name", ""
                    ),
                    "latency_ms": latency_ms,
                    "error": llm_error,
                    "raw_output": (
                        llm_analysis.model_dump(mode="json") if llm_analysis else {}
                    ),
                }
            )
        except Exception as exc:
            latency_ms = (time.perf_counter() - t0) * 1000 + per_event_rule_ms
            err = f"[llm_rule_based] LLM step failed for event {event_id}: {exc}"
            logger.exception(err)
            errors.append(err)
            results.append(
                {
                    "event_id": event_id,
                    "alert_fired": True,
                    "rule_ids_fired": [a.alert.rule_id for a in matched_assessments],
                    "rule_names_fired": [a.alert.rule_name for a in matched_assessments],
                    "risk_score": best_assessment.risk.score,
                    "risk_level": best_assessment.risk.level,
                    "risk_score_source": "deterministic",
                    "llm_status": "partial",
                    "latency_ms": latency_ms,
                    "error": str(exc),
                    "raw_output": {},
                }
            )

    return results, errors


def _to_l3_no_rag(
    assessment: Part2Assessment,
    enriched_index: dict[str, ContextEnrichedEvent],
) -> L3SecurityAssessment:
    """Convert Part2 assessment to L3 format but suppress RAG retrieval.

    We achieve this by passing the enriched index (for event context) but
    monkey-patching the integration function to skip the vector store call.
    The to_l3_assessment function calls _retrieve_vector_cti internally;
    we override it by importing the module and temporarily replacing the
    function at the module level.
    """
    import integration.part2_to_l3 as adapter_module

    original_retrieve = adapter_module._retrieve_vector_cti

    def _no_rag(assessment, limit=5):  # noqa: ANN001
        return []  # RAG disabled for this configuration

    adapter_module._retrieve_vector_cti = _no_rag
    try:
        result = to_l3_assessment(assessment, enriched_index)
    finally:
        adapter_module._retrieve_vector_cti = original_retrieve

    return result
