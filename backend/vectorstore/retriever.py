"""Retrieval entrypoint used by the future LLM stage.

    SecurityAssessment -> assessment_to_text -> SecurityContextStore.search

Nothing here builds prompts or calls an LLM; it only returns the context
documents that a rule finding should be reasoned about with.
"""

from __future__ import annotations

from typing import Any

from embeddings import alert_to_text, assessment_to_text
from part2.models.security_alert import SecurityAlert
from part2.models.security_assessment import SecurityAssessment
from vectorstore.store import get_context_store


def retrieve_for_text(text: str, top_k: int | None = None) -> list[dict[str, Any]]:
    """Context documents relevant to a free-form security text."""

    return get_context_store().search(text, top_k=top_k)


def retrieve_for_alert(
    alert: SecurityAlert, top_k: int | None = None
) -> list[dict[str, Any]]:
    """Context documents relevant to a Part 2 rule finding."""

    return retrieve_for_text(alert_to_text(alert), top_k=top_k)


def retrieve_for_assessment(
    assessment: SecurityAssessment, top_k: int | None = None
) -> list[dict[str, Any]]:
    """Context documents relevant to a Part 2 security assessment."""

    return retrieve_for_text(assessment_to_text(assessment), top_k=top_k)
