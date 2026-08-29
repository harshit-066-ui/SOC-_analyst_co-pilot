"""LLM engine — orchestrates prompt construction, API call, and response parsing.

This module is the single entry point for LLM reasoning.  All callers should
use LLMEngine.analyze() and handle the returned LLMAnalysis or check for
llm_status == LLMStatus.UNAVAILABLE in FinalSecurityAssessment.

Failure contract
----------------
If the LLM is unreachable, returns a structured unavailability object so that
the rest of the pipeline (XAI, validation) can continue without the LLM.
The application will NEVER crash due to LLM failure.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from typing import Any

from l3.config import OPENROUTER_MODEL, SCHEMA_VERSION
from l3.models.schemas import (
    LLMAnalysis,
    LLMStatus,
    MitreInterpretation,
    ModelMetadata,
    SecurityAssessment,
    UncertaintyBlock,
    UncertaintyLevel,
)
from l3.reasoning.openrouter_client import LLMUnavailableError, OpenRouterClient
from l3.reasoning.prompt_builder import SYSTEM_PROMPT, PromptBuilder

logger = logging.getLogger(__name__)


class LLMEngine:
    """Drives the full LLM reasoning cycle for a single SecurityAssessment.

    Parameters
    ----------
    client:
        Injected OpenRouterClient.  Defaults to a fresh instance using config.
    """

    def __init__(self, client: OpenRouterClient | None = None) -> None:
        self._client = client or OpenRouterClient()
        self._prompt_builder = PromptBuilder()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self, assessment: SecurityAssessment
    ) -> tuple[LLMAnalysis | None, LLMStatus, str | None]:
        """Run LLM reasoning for the given SecurityAssessment.

        Returns
        -------
        (LLMAnalysis | None, LLMStatus, error_message | None)
            - LLMAnalysis is None when the LLM is unavailable.
            - LLMStatus reflects availability.
            - error_message is set when unavailable.
        """
        user_prompt = self._prompt_builder.build(assessment)

        logger.info(
            "Starting LLM analysis | alert_id=%s | model=%s",
            assessment.alert_id,
            self._client.model,
        )

        try:
            raw_text = self._client.complete(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=user_prompt,
                temperature=0.1,
                max_tokens=2048,
            )
        except LLMUnavailableError as exc:
            logger.warning("LLM unavailable: %s", exc)
            return None, LLMStatus.UNAVAILABLE, str(exc)

        # Parse and validate response
        try:
            llm_analysis = self._parse_response(raw_text, assessment)
            logger.info(
                "LLM analysis complete | alert_id=%s", assessment.alert_id
            )
            return llm_analysis, LLMStatus.AVAILABLE, None
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Failed to parse LLM response for alert_id=%s: %s",
                assessment.alert_id,
                exc,
            )
            # Return partial status — we got a response but couldn't parse it
            return None, LLMStatus.PARTIAL, (
                f"LLM response received but could not be parsed: {exc}"
            )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_response(
        self, raw_text: str, assessment: SecurityAssessment
    ) -> LLMAnalysis:
        """Parse LLM JSON text into a validated LLMAnalysis model."""
        data = self._extract_json(raw_text)

        # Build uncertainty block
        uncertainty_data = data.get("uncertainty", {})
        if isinstance(uncertainty_data, str):
            uncertainty_data = {"level": uncertainty_data, "reasons": []}
        uncertainty = UncertaintyBlock(
            level=self._coerce_uncertainty(
                uncertainty_data.get("level", "high")
            ),
            reasons=_ensure_str_list(uncertainty_data.get("reasons", [])),
        )

        # Build MITRE interpretation list — only from supplied mapping
        supplied_technique_id = assessment.mitre.technique_id
        supplied_technique_name = assessment.mitre.technique_name
        raw_mitre = data.get("mitre_interpretation", [])
        mitre_interps: list[MitreInterpretation] = []
        for item in raw_mitre if isinstance(raw_mitre, list) else []:
            if not isinstance(item, dict):
                continue
            tech_id = item.get("technique_id", "")
            # Only accept technique IDs that match the supplied mapping
            if tech_id and tech_id != supplied_technique_id:
                logger.warning(
                    "LLM returned unsupported technique_id=%s (expected %s) — discarding",
                    tech_id,
                    supplied_technique_id,
                )
                continue
            mitre_interps.append(
                MitreInterpretation(
                    technique_id=tech_id or supplied_technique_id,
                    technique_name=item.get("technique_name", supplied_technique_name),
                    relevance=str(item.get("relevance", "")),
                    evidence_basis=str(item.get("evidence_basis", "")),
                )
            )

        # Model metadata
        metadata = ModelMetadata(
            provider="OpenRouter",
            model=self._client.model,
            timestamp=datetime.utcnow().isoformat() + "Z",
            response_id=str(uuid.uuid4()),
        )

        return LLMAnalysis(
            alert_id=assessment.alert_id,
            summary=str(data.get("summary", "")).strip() or "No summary provided.",
            reasoning=str(data.get("reasoning", "")).strip() or "No reasoning provided.",
            supporting_evidence=_ensure_str_list(
                data.get("supporting_evidence", [])
            ),
            mitre_interpretation=mitre_interps,
            uncertainty=uncertainty,
            analyst_recommendation=_ensure_str_list(
                data.get("analyst_recommendation", [])
            ),
            possible_interpretations=_ensure_str_list(
                data.get("possible_interpretations", [])
            ),
            model_metadata=metadata,
            schema_version=SCHEMA_VERSION,
        )

    @staticmethod
    def _extract_json(raw_text: str) -> dict[str, Any]:
        """Extract a JSON object from the LLM's response text."""
        text = raw_text.strip()
        # Strip markdown code fences if present
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(
                line for line in lines if not line.strip().startswith("```")
            ).strip()
        try:
            data = json.loads(text)
            if not isinstance(data, dict):
                raise ValueError(f"Expected JSON object, got {type(data).__name__}")
            return data
        except json.JSONDecodeError as exc:
            raise ValueError(f"LLM response is not valid JSON: {exc}\n---\n{text[:300]}") from exc

    @staticmethod
    def _coerce_uncertainty(value: Any) -> UncertaintyLevel:
        """Map a raw string to UncertaintyLevel, defaulting to HIGH on failure."""
        try:
            return UncertaintyLevel(str(value).lower())
        except ValueError:
            return UncertaintyLevel.HIGH


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ensure_str_list(value: Any) -> list[str]:
    """Convert a raw value to a list of strings."""
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value] if value.strip() else []
    return []
