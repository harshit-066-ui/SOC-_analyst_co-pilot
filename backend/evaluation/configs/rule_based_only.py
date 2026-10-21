"""Configuration A — Rule-Based Only.

Pipeline:  L2 enrichment → Part 2 rule engine + risk scoring
Disabled:  LLM, RAG, Judge, XAI
"""

from __future__ import annotations

import logging
import time
from typing import Any

from l2.enricher import enrich_event
from part2.api.assessment_routes import assess_events

logger = logging.getLogger(__name__)


def run(
    normalized_events: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Run Rule-Based Only configuration.

    Returns
    -------
    (results, errors)
      results: list of per-event result dicts (one entry per normalized event)
      errors:  list of error strings
    """
    errors: list[str] = []
    results: list[dict[str, Any]] = []

    # Build a lookup: event_id -> normalized event for quick access
    event_lookup: dict[str, dict[str, Any]] = {
        str(e.get("event_id", idx)): e
        for idx, e in enumerate(normalized_events)
    }

    # Step 1: L2 enrichment
    try:
        enriched = [enrich_event(e) for e in normalized_events]
    except Exception as exc:
        err = f"[rule_based_only] L2 enrichment failed: {exc}"
        logger.exception(err)
        errors.append(err)
        return [], errors

    # Step 2: Part 2 rule engine + risk scoring (batch)
    t0 = time.perf_counter()
    try:
        assessments = assess_events(enriched)
    except Exception as exc:
        err = f"[rule_based_only] Part2 assessment failed: {exc}"
        logger.exception(err)
        errors.append(err)
        assessments = []
    elapsed_total_ms = (time.perf_counter() - t0) * 1000

    # Index alerts by event_ids they cover
    alert_index: dict[str, list[Any]] = {}
    for assessment in assessments:
        for eid in assessment.alert.event_ids:
            alert_index.setdefault(str(eid), []).append(assessment)

    per_event_ms = elapsed_total_ms / max(len(normalized_events), 1)

    # Build one result per normalized event
    for event in normalized_events:
        event_id = str(event.get("event_id", ""))
        matched_assessments = alert_index.get(event_id, [])

        if matched_assessments:
            # Use the highest-risk assessment for this event
            best = max(matched_assessments, key=lambda a: a.risk.score)
            results.append(
                {
                    "event_id": event_id,
                    "alert_fired": True,
                    "rule_ids_fired": [a.alert.rule_id for a in matched_assessments],
                    "rule_names_fired": [a.alert.rule_name for a in matched_assessments],
                    "risk_score": best.risk.score,
                    "risk_level": best.risk.level,
                    "risk_score_source": "deterministic",
                    "mitre_technique_id": best.mitre_attack.get("technique_id", ""),
                    "mitre_technique_name": best.mitre_attack.get("technique_name", ""),
                    "latency_ms": per_event_ms,
                    "raw_output": best.model_dump(mode="json"),
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
                    "mitre_technique_id": None,
                    "mitre_technique_name": None,
                    "latency_ms": per_event_ms,
                    "raw_output": {},
                }
            )

    return results, errors
