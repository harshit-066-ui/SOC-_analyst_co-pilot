"""Configuration E — Proposed Complete Framework.

Uses the existing production pipeline unchanged:
  L2 enrichment → Part 2 rules + risk scoring → RAG (BGE-M3/Qdrant) →
  LLM interpretation → Judge validation → deterministic XAI

This configuration IS the production pipeline (run_pipeline).
The deterministic risk score is never modified.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from pipeline.orchestrator import (
    DEFAULT_MAX_LLM_ALERTS,
    analyze_assessments,
    enrich_events,
    index_by_event_id,
)
from part2.api.assessment_routes import assess_events
from l3.models.schemas import FinalStatus

logger = logging.getLogger(__name__)


def run(
    normalized_events: list[dict[str, Any]],
    max_llm_alerts: int = DEFAULT_MAX_LLM_ALERTS,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Run the complete production pipeline. Returns (results, errors)."""
    errors: list[str] = []
    results: list[dict[str, Any]] = []

    # Step 1: L2 enrichment
    t0 = time.perf_counter()
    try:
        enriched = enrich_events(normalized_events)
    except Exception as exc:
        err = f"[full_framework] L2 enrichment failed: {exc}"
        logger.exception(err)
        errors.append(err)
        return [], errors

    # Step 2: Part 2 rules + risk scoring
    try:
        assessments = assess_events(enriched)
    except Exception as exc:
        err = f"[full_framework] Part2 assessment failed: {exc}"
        logger.exception(err)
        errors.append(err)
        assessments = []

    # Step 3: L3 (RAG + LLM + Judge + XAI) for triggered alerts
    enriched_index = index_by_event_id(enriched)
    final_assessments: list[dict[str, Any]] = []
    if assessments:
        try:
            final_assessments = analyze_assessments(
                assessments,
                enriched_index,
                max_alerts=max_llm_alerts,
            )
        except Exception as exc:
            err = f"[full_framework] L3 analysis failed: {exc}"
            logger.exception(err)
            errors.append(err)

    total_elapsed_ms = (time.perf_counter() - t0) * 1000

    # Build alert lookup (event_id -> FinalSecurityAssessment dict)
    alert_map: dict[str, dict[str, Any]] = {}
    for fa in final_assessments:
        # event_ids are in the Part2 assessment inside security_assessment
        sec = fa.get("security_assessment", {})
        alert = sec.get("alert", {})
        for eid in alert.get("event_ids", []):
            alert_map[str(eid)] = fa

    # Also map Part2 assessments that didn't reach L3 (batch limit)
    part2_map: dict[str, Any] = {}
    for assessment in assessments:
        for eid in assessment.alert.event_ids:
            part2_map[str(eid)] = assessment

    per_event_ms = total_elapsed_ms / max(len(normalized_events), 1)

    for event in normalized_events:
        event_id = str(event.get("event_id", ""))
        fa = alert_map.get(event_id)
        p2 = part2_map.get(event_id)

        if fa:
            sec = fa.get("security_assessment", {})
            alert = sec.get("alert", {})
            risk = sec.get("risk", {})
            validation = fa.get("validation", {})
            explanation = fa.get("explanation", {})
            llm_analysis = fa.get("llm_analysis")
            mitre = sec.get("mitre", {})

            # Gather retrieved evidence
            retrieved_evidence = []
            for cti in sec.get("retrieved_cti", []):
                retrieved_evidence.append(
                    {
                        "doc_id": str(cti.get("id", "")),
                        "title": cti.get("title", ""),
                        "source": cti.get("source", ""),
                        "score": cti.get("score", 0.0),
                        "technique_id": cti.get("technique_id", ""),
                        "snippet": str(cti.get("content", ""))[:300],
                    }
                )

            results.append(
                {
                    "event_id": event_id,
                    "alert_fired": True,
                    "rule_ids_fired": [alert.get("rule_id", "")],
                    "rule_names_fired": [alert.get("rule_name", "")],
                    "risk_score": risk.get("score"),
                    "risk_level": risk.get("level"),
                    "risk_score_source": "deterministic",
                    "retrieved_evidence": retrieved_evidence,
                    "rag_available": len(retrieved_evidence) > 0,
                    "llm_summary": (
                        llm_analysis.get("summary") if llm_analysis else None
                    ),
                    "llm_reasoning": (
                        llm_analysis.get("reasoning") if llm_analysis else None
                    ),
                    "llm_status": fa.get("llm_status", "not_run"),
                    "llm_model": (
                        llm_analysis.get("model_metadata", {}).get("model")
                        if llm_analysis
                        else None
                    ),
                    "llm_recommendation": (
                        llm_analysis.get("analyst_recommendation", [])
                        if llm_analysis
                        else []
                    ),
                    "judge_status": validation.get("status"),
                    "judge_issues": validation.get("issues", []),
                    "judge_checks_passed": validation.get("checks_passed"),
                    "judge_checks_total": validation.get("checks_total"),
                    "evidence_coverage": validation.get("evidence_coverage"),
                    "xai_why_alerted": explanation.get("why_alerted"),
                    "xai_why_risk": explanation.get("why_risk"),
                    "xai_uncertainty": explanation.get("uncertainty"),
                    "mitre_technique_id": mitre.get("technique_id"),
                    "mitre_technique_name": mitre.get("technique_name"),
                    "latency_ms": per_event_ms,
                    "raw_output": fa,
                }
            )
        elif p2:
            # Alert fired but didn't reach L3 (batch limit hit)
            results.append(
                {
                    "event_id": event_id,
                    "alert_fired": True,
                    "rule_ids_fired": [p2.alert.rule_id],
                    "rule_names_fired": [p2.alert.rule_name],
                    "risk_score": p2.risk.score,
                    "risk_level": p2.risk.level,
                    "risk_score_source": "deterministic",
                    "llm_status": "not_run",
                    "mitre_technique_id": p2.mitre_attack.get("technique_id"),
                    "mitre_technique_name": p2.mitre_attack.get("technique_name"),
                    "latency_ms": per_event_ms,
                    "raw_output": p2.model_dump(mode="json"),
                }
            )
        else:
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
                    "latency_ms": per_event_ms,
                    "raw_output": {},
                }
            )

    return results, errors
