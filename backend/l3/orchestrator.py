"""PART 3 orchestrator — the single entry point for end-to-end analysis.

Data flow
---------
  SecurityAssessment (from PART 2)
      │
      ├─→ Explainer.explain()       → XAIExplanation      (always runs)
      │
      ├─→ LLMEngine.analyze()       → LLMAnalysis | None  (may be unavailable)
      │
      ├─→ Judge.validate()          → ValidationResult    (runs if LLM succeeded)
      │   (or build_skipped_validation() if LLM unavailable)
      │
      └─→ assemble FinalSecurityAssessment

Invariants
----------
- SecurityAssessment.risk.score is never modified.
- XAI always runs — it is independent of the LLM.
- Failure in any step produces a graceful degraded result, not an exception.
"""

from __future__ import annotations

import logging

from l3.models.schemas import (
    FinalSecurityAssessment,
    FinalStatus,
    LLMStatus,
    SecurityAssessment,
    ValidationStatus,
)
from l3.reasoning.llm_engine import LLMEngine
from l3.reasoning.openrouter_client import OpenRouterClient
from l3.validation.judge import Judge, build_skipped_validation
from l3.xai.explainer import Explainer

logger = logging.getLogger(__name__)


class Part3Orchestrator:
    """Drives the full PART 3 pipeline for a SecurityAssessment.

    Parameters
    ----------
    llm_client:
        Optional custom OpenRouterClient.  Defaults to a fresh instance
        configured via environment variables.
    """

    def __init__(self, llm_client: OpenRouterClient | None = None) -> None:
        self._engine = LLMEngine(client=llm_client)
        self._judge = Judge()
        self._explainer = Explainer()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, assessment: SecurityAssessment) -> FinalSecurityAssessment:
        """Produce a FinalSecurityAssessment for the given SecurityAssessment.

        This method NEVER raises — all errors are captured in the result.

        Parameters
        ----------
        assessment:
            The SecurityAssessment from PART 2.  Read-only.

        Returns
        -------
        FinalSecurityAssessment
            The complete analyst-facing result.
        """
        logger.info("PART 3 analysis started | alert_id=%s", assessment.alert_id)

        # Step 1: XAI — always runs, fully deterministic
        explanation = self._run_xai(assessment)

        # Step 2: LLM reasoning — may be unavailable
        llm_analysis, llm_status, llm_error = self._run_llm(assessment)

        # Step 3: Validation — runs only if we have LLM output
        if llm_analysis is not None:
            validation = self._run_validation(llm_analysis, assessment)
        else:
            validation = build_skipped_validation()
            if llm_error:
                validation.issues.insert(0, llm_error)

        # Step 4: Determine final_status
        final_status = self._derive_final_status(llm_status, validation.status)

        result = FinalSecurityAssessment(
            security_assessment=assessment,
            llm_analysis=llm_analysis,
            llm_status=llm_status,
            validation=validation,
            explanation=explanation,
            final_status=final_status,
        )

        logger.info(
            "PART 3 analysis complete | alert_id=%s | llm=%s | validation=%s | status=%s",
            assessment.alert_id,
            llm_status.value,
            validation.status.value,
            final_status.value,
        )
        return result

    # ------------------------------------------------------------------
    # Step implementations with isolated error handling
    # ------------------------------------------------------------------

    def _run_xai(self, assessment: SecurityAssessment):
        """Run XAI — catches unexpected errors to prevent pipeline crash."""
        try:
            return self._explainer.explain(assessment)
        except Exception as exc:  # noqa: BLE001
            logger.exception("XAI explainer raised unexpectedly: %s", exc)
            # Return minimal safe explanation
            from l3.models.schemas import XAIExplanation
            return XAIExplanation(
                why_alerted="XAI explanation could not be generated due to an internal error.",
                why_risk=(
                    f"Risk score: {assessment.risk.score:.1f}/100 "
                    f"(level: {assessment.risk.level}). XAI generation failed."
                ),
                supporting_factors=[],
                context_influences=[],
                uncertainty="Uncertainty unknown — XAI generation failed.",
                mitre_context="MITRE context unavailable.",
                evidence_summary="Evidence summary unavailable.",
            )

    def _run_llm(self, assessment: SecurityAssessment):
        """Run LLM reasoning — isolates all LLM errors."""
        try:
            return self._engine.analyze(assessment)
        except Exception as exc:  # noqa: BLE001
            logger.exception("LLMEngine raised unexpectedly: %s", exc)
            return None, LLMStatus.UNAVAILABLE, str(exc)

    def _run_validation(self, llm_analysis, assessment: SecurityAssessment):
        """Run the Judge — isolates validation errors."""
        try:
            return self._judge.validate(llm_analysis, assessment)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Judge raised unexpectedly: %s", exc)
            from l3.models.schemas import ValidationResult
            return ValidationResult(
                status=ValidationStatus.REVIEW,
                issues=[f"Validation raised an internal error: {exc}"],
                unsupported_claims=[],
                evidence_coverage=0.0,
                checks_run=[],
                checks_passed=0,
                checks_total=0,
            )

    # ------------------------------------------------------------------
    # Final status derivation
    # ------------------------------------------------------------------

    @staticmethod
    def _derive_final_status(
        llm_status: LLMStatus, validation_status: ValidationStatus
    ) -> FinalStatus:
        if llm_status == LLMStatus.UNAVAILABLE:
            return FinalStatus.LLM_UNAVAILABLE
        if validation_status == ValidationStatus.PASSED:
            return FinalStatus.VALIDATED
        return FinalStatus.REVIEW_REQUIRED
