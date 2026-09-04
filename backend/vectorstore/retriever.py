"""Retrieval entrypoint for the future LLM stage.

    SecurityAssessment -> assessment_to_text -> KnowledgeStore.search

Nothing here builds prompts or calls an LLM; it only returns the knowledge a
rule finding should be reasoned about with.
"""

from __future__ import annotations

from typing import Any

from embeddings import alert_to_text, assessment_to_text
from part2.models.security_alert import SecurityAlert
from part2.models.security_assessment import SecurityAssessment
from vectorstore.store import get_knowledge_store


def retrieve_for_text(
    text: str,
    top_k: int | None = None,
    filters: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Knowledge relevant to a free-form security query."""

    return get_knowledge_store().search(text, top_k=top_k, filters=filters)


def retrieve_for_alert(
    alert: SecurityAlert,
    top_k: int | None = None,
    filters: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Knowledge relevant to a Part 2 rule finding."""

    return retrieve_for_text(alert_to_text(alert), top_k=top_k, filters=filters)


def retrieve_for_assessment(
    assessment: SecurityAssessment,
    top_k: int | None = None,
    filters: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Knowledge relevant to a Part 2 security assessment."""

    return retrieve_for_text(
        assessment_to_text(assessment), top_k=top_k, filters=filters
    )
