"""End-to-end orchestration across the existing layers.

    NormalizedEvent[]      (L1)
        -> ContextEnrichedEvent[]   (L2 enricher)
        -> SecurityAssessment[]     (Part 2 rules + risk)
        -> FinalSecurityAssessment[] (L3 LLM + Judge + XAI)

No detection, enrichment, scoring or reasoning logic lives here — this module
only calls the modules that already implement those stages and carries the
data between them.
"""

from __future__ import annotations

import logging
from typing import Any

from integration.part2_to_l3 import to_l3_assessment
from l2.enricher import enrich_event
from l2.models import ContextEnrichedEvent
from l3.orchestrator import Part3Orchestrator
from part2.api.assessment_routes import assess_events
from part2.models.security_assessment import SecurityAssessment

logger = logging.getLogger(__name__)

DEFAULT_MAX_LLM_ALERTS = 20

_part3 = Part3Orchestrator()


def enrich_events(
    normalized_events: list[dict[str, Any]],
) -> list[ContextEnrichedEvent]:
    """L1 output -> L2 ContextEnrichedEvent list."""

    return [enrich_event(event) for event in normalized_events]


def index_by_event_id(
    enriched_events: list[ContextEnrichedEvent],
) -> dict[str, ContextEnrichedEvent]:
    """Index enriched events by the L1 event_id nested inside ``event``."""

    index: dict[str, ContextEnrichedEvent] = {}

    for enriched in enriched_events:
        event_id = enriched.event.get("event_id")
        if event_id is not None:
            index[str(event_id)] = enriched

    return index


def analyze_assessments(
    assessments: list[SecurityAssessment],
    enriched_index: dict[str, ContextEnrichedEvent],
    max_alerts: int = DEFAULT_MAX_LLM_ALERTS,
) -> list[dict[str, Any]]:
    """Part 2 assessments -> L3 FinalSecurityAssessment payloads."""

    results: list[dict[str, Any]] = []

    for assessment in assessments[:max_alerts]:
        l3_input = to_l3_assessment(assessment, enriched_index)
        results.append(_part3.analyze(l3_input).model_dump(mode="json"))

    return results


def run_pipeline(
    normalized_events: list[dict[str, Any]],
    run_llm: bool = True,
    max_alerts: int = DEFAULT_MAX_LLM_ALERTS,
) -> dict[str, Any]:
    """Run L2 -> Part 2 -> L3 over already normalized (L1) events."""

    enriched_events = enrich_events(normalized_events)
    assessments = assess_events(enriched_events)

    final_assessments: list[dict[str, Any]] = []
    if run_llm and assessments:
        final_assessments = analyze_assessments(
            assessments,
            index_by_event_id(enriched_events),
            max_alerts=max_alerts,
        )

    logger.info(
        "Pipeline complete | events=%d | alerts=%d | analyzed=%d",
        len(normalized_events),
        len(assessments),
        len(final_assessments),
    )

    return {
        "stages": {
            "l1": {"normalized_events": len(normalized_events)},
            "l2": {"enriched_events": len(enriched_events)},
            "part2": {"alerts": len(assessments)},
            "l3": {
                "analyzed": len(final_assessments),
                "skipped": max(0, len(assessments) - len(final_assessments)),
            },
        },
        "enriched_events": [
            enriched.model_dump(mode="json") for enriched in enriched_events
        ],
        "assessments": [
            assessment.model_dump(mode="json") for assessment in assessments
        ],
        "final_assessments": final_assessments,
    }
