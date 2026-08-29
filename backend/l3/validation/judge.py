"""PART 3 Validation / Judge layer.

The Judge is the authoritative layer over LLM output.  It runs ONLY
deterministic, rule-based checks — no LLM calls.

Checks performed
----------------
1.  SCHEMA_COMPLETENESS   — required LLMAnalysis fields are non-empty
2.  RISK_SCORE_UNCHANGED  — LLM did not embed an altered risk score
3.  MITRE_CONSISTENCY     — referenced technique IDs match the supplied mapping
4.  EVIDENCE_COVERAGE     — supporting_evidence items can be traced to assessment
5.  UNCERTAINTY_WARRANTED — uncertainty.level is "high" when evidence is sparse
6.  RECOMMENDATION_PRESENT— at least one analyst recommendation provided
7.  SCHEMA_VERSION        — output schema_version matches expected "1.0"
8.  NO_UNSUPPORTED_CLAIMS — heuristic scan for invented facts

Validation result
-----------------
  passed  — all checks passed; LLM output can be presented to the analyst
  review  — some checks flagged issues; present with warning banner
  failed  — critical checks failed; do not present LLM output as authoritative
  skipped — LLM was unavailable; nothing to validate
"""

from __future__ import annotations

import re
from typing import Any

from l3.config import LOW_EVIDENCE_THRESHOLD, SCHEMA_VERSION
from l3.models.schemas import (
    LLMAnalysis,
    SecurityAssessment,
    UncertaintyLevel,
    ValidationResult,
    ValidationStatus,
)


# ---------------------------------------------------------------------------
# Sentinel patterns that indicate an LLM may have invented facts
# ---------------------------------------------------------------------------

# These patterns appear in LLM-hallucinated content but are NEVER in the
# evidence unless PART 2 explicitly included them.
_INVENTED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bCVE-\d{4}-\d{4,}\b"),           # CVE identifiers
    re.compile(r"\bAPT\d+\b", re.IGNORECASE),        # APT group names
    re.compile(r"\bLazarus\b|\bCozy Bear\b|\bFancy Bear\b", re.IGNORECASE),
    re.compile(r"\bshodan\b|\bshodan\.io\b", re.IGNORECASE),
    re.compile(r"\b(?:malicious|known bad|blacklisted) IP\b", re.IGNORECASE),
]

_REQUIRED_FIELDS = [
    "summary",
    "reasoning",
    "supporting_evidence",
    "uncertainty",
    "analyst_recommendation",
    "schema_version",
]

_CRITICAL_CHECKS = {
    "SCHEMA_COMPLETENESS",
    "RISK_SCORE_UNCHANGED",
    "SCHEMA_VERSION",
}


class Judge:
    """Deterministic validation layer for LLMAnalysis output."""

    def validate(
        self,
        llm_analysis: LLMAnalysis,
        assessment: SecurityAssessment,
    ) -> ValidationResult:
        """Run all deterministic checks and return a ValidationResult.

        Parameters
        ----------
        llm_analysis:
            The output produced by LLMEngine.
        assessment:
            The original SecurityAssessment from PART 2 (reference ground truth).
        """
        issues: list[str] = []
        unsupported_claims: list[str] = []
        checks_run: list[str] = []
        checks_passed = 0

        def run_check(name: str, passed: bool, message: str) -> None:
            nonlocal checks_passed
            checks_run.append(name)
            if passed:
                checks_passed += 1
            else:
                issues.append(f"[{name}] {message}")

        # ------------------------------------------------------------------
        # 1. Schema completeness
        # ------------------------------------------------------------------
        run_check(
            "SCHEMA_COMPLETENESS",
            self._check_schema_completeness(llm_analysis),
            "One or more required output fields are missing or empty.",
        )

        # ------------------------------------------------------------------
        # 2. Schema version
        # ------------------------------------------------------------------
        run_check(
            "SCHEMA_VERSION",
            llm_analysis.schema_version == SCHEMA_VERSION,
            f"schema_version mismatch: got '{llm_analysis.schema_version}', "
            f"expected '{SCHEMA_VERSION}'.",
        )

        # ------------------------------------------------------------------
        # 3. Risk score unchanged
        # ------------------------------------------------------------------
        run_check(
            "RISK_SCORE_UNCHANGED",
            self._check_risk_score_not_mentioned(
                llm_analysis, assessment.risk.score
            ),
            "LLM output contains a risk score that conflicts with the "
            "deterministic assessment.",
        )

        # ------------------------------------------------------------------
        # 4. MITRE consistency
        # ------------------------------------------------------------------
        mitre_ok, mitre_msg = self._check_mitre_consistency(
            llm_analysis, assessment
        )
        run_check("MITRE_CONSISTENCY", mitre_ok, mitre_msg)

        # ------------------------------------------------------------------
        # 5. Evidence coverage
        # ------------------------------------------------------------------
        coverage = self._compute_evidence_coverage(llm_analysis, assessment)
        run_check(
            "EVIDENCE_COVERAGE",
            coverage > 0.0 or not assessment.evidence,
            "supporting_evidence does not reference any supplied evidence items.",
        )

        # ------------------------------------------------------------------
        # 6. Uncertainty warranted
        # ------------------------------------------------------------------
        run_check(
            "UNCERTAINTY_WARRANTED",
            self._check_uncertainty_warranted(llm_analysis, assessment),
            "Uncertainty level should be 'high' when evidence is sparse, "
            "but the LLM returned 'low' or 'medium'.",
        )

        # ------------------------------------------------------------------
        # 7. Recommendation present
        # ------------------------------------------------------------------
        run_check(
            "RECOMMENDATION_PRESENT",
            bool(llm_analysis.analyst_recommendation),
            "No analyst recommendations were provided.",
        )

        # ------------------------------------------------------------------
        # 8. Unsupported claim scan
        # ------------------------------------------------------------------
        unsupported_claims = self._scan_unsupported_claims(
            llm_analysis, assessment
        )
        run_check(
            "NO_UNSUPPORTED_CLAIMS",
            len(unsupported_claims) == 0,
            f"LLM may have invented {len(unsupported_claims)} unsupported claim(s).",
        )

        # ------------------------------------------------------------------
        # Determine final status
        # ------------------------------------------------------------------
        checks_total = len(checks_run)
        failed_critical = any(
            f"[{c}]" in " ".join(issues) for c in _CRITICAL_CHECKS
        )
        status = self._derive_status(
            issues=issues,
            failed_critical=failed_critical,
            unsupported_count=len(unsupported_claims),
        )

        return ValidationResult(
            status=status,
            issues=issues,
            unsupported_claims=unsupported_claims,
            evidence_coverage=round(coverage, 3),
            checks_run=checks_run,
            checks_passed=checks_passed,
            checks_total=checks_total,
        )

    # ------------------------------------------------------------------
    # Individual check implementations
    # ------------------------------------------------------------------

    @staticmethod
    def _check_schema_completeness(analysis: LLMAnalysis) -> bool:
        if not analysis.summary.strip():
            return False
        if not analysis.reasoning.strip():
            return False
        if analysis.uncertainty is None:
            return False
        return True

    @staticmethod
    def _check_risk_score_not_mentioned(
        analysis: LLMAnalysis, authoritative_score: float
    ) -> bool:
        """Check that the LLM's text does not quote a different risk score."""
        combined_text = (
            analysis.summary + " " + analysis.reasoning
        ).lower()

        # Look for numbers that look like a risk score quoted by the LLM
        score_pattern = re.compile(r"\brisk\s+score[:\s]+(\d+(?:\.\d+)?)")
        for match in score_pattern.finditer(combined_text):
            try:
                found_score = float(match.group(1))
                # Allow ±0.5 tolerance for floating-point representation
                if abs(found_score - authoritative_score) > 0.5:
                    return False
            except ValueError:
                pass
        return True

    @staticmethod
    def _check_mitre_consistency(
        analysis: LLMAnalysis, assessment: SecurityAssessment
    ) -> tuple[bool, str]:
        """All referenced technique IDs must be in the supplied mapping."""
        if not analysis.mitre_interpretation:
            return True, ""

        allowed = {assessment.mitre.technique_id} - {""}
        for interp in analysis.mitre_interpretation:
            if interp.technique_id and interp.technique_id not in allowed:
                return (
                    False,
                    f"LLM referenced technique '{interp.technique_id}' which "
                    f"is not in the supplied MITRE mapping ({allowed}).",
                )
        return True, ""

    @staticmethod
    def _compute_evidence_coverage(
        analysis: LLMAnalysis, assessment: SecurityAssessment
    ) -> float:
        """Ratio of supporting_evidence items that contain text from the assessment."""
        if not assessment.evidence:
            # No evidence was supplied — coverage is vacuously 1.0
            return 1.0
        if not analysis.supporting_evidence:
            return 0.0

        # Build a flat set of "known" evidence tokens from the assessment
        known_tokens: set[str] = set()
        _collect_tokens(assessment.model_dump(), known_tokens)

        matched = 0
        for claim in analysis.supporting_evidence:
            claim_lower = claim.lower()
            if any(tok in claim_lower for tok in known_tokens if len(tok) > 3):
                matched += 1

        return matched / len(analysis.supporting_evidence)

    @staticmethod
    def _check_uncertainty_warranted(
        analysis: LLMAnalysis, assessment: SecurityAssessment
    ) -> bool:
        """If evidence is sparse, uncertainty MUST be high."""
        evidence_count = len(assessment.evidence)
        # Below the threshold, uncertainty must be high
        if evidence_count == 0:
            return analysis.uncertainty.level == UncertaintyLevel.HIGH
        if evidence_count < 3:  # Very sparse
            return analysis.uncertainty.level in (
                UncertaintyLevel.HIGH,
                UncertaintyLevel.MEDIUM,
            )
        return True  # Sufficient evidence — any level is acceptable

    @staticmethod
    def _scan_unsupported_claims(
        analysis: LLMAnalysis, assessment: SecurityAssessment
    ) -> list[str]:
        """Heuristically detect invented facts not present in the assessment."""
        # Build a flat text of all known assessment content
        assessment_text = _flatten_to_text(assessment.model_dump()).lower()

        combined_llm_text = (
            analysis.summary
            + " "
            + analysis.reasoning
            + " "
            + " ".join(analysis.supporting_evidence)
        )

        found: list[str] = []
        for pattern in _INVENTED_PATTERNS:
            for match in pattern.finditer(combined_llm_text):
                value = match.group(0)
                if value.lower() not in assessment_text:
                    found.append(value)

        return list(dict.fromkeys(found))  # deduplicate, preserve order

    # ------------------------------------------------------------------
    # Status derivation
    # ------------------------------------------------------------------

    @staticmethod
    def _derive_status(
        issues: list[str],
        failed_critical: bool,
        unsupported_count: int,
    ) -> ValidationStatus:
        if not issues:
            return ValidationStatus.PASSED
        if failed_critical or unsupported_count > 0:
            return ValidationStatus.FAILED
        return ValidationStatus.REVIEW


# ---------------------------------------------------------------------------
# Skipped-validation helper (used when LLM was unavailable)
# ---------------------------------------------------------------------------


def build_skipped_validation() -> ValidationResult:
    """Return a ValidationResult indicating no validation was performed."""
    return ValidationResult(
        status=ValidationStatus.SKIPPED,
        issues=["LLM was unavailable — no output to validate."],
        unsupported_claims=[],
        evidence_coverage=0.0,
        checks_run=[],
        checks_passed=0,
        checks_total=0,
    )


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def _collect_tokens(obj: Any, tokens: set[str]) -> None:
    """Recursively extract all string leaf values for evidence matching."""
    if isinstance(obj, dict):
        for v in obj.values():
            _collect_tokens(v, tokens)
    elif isinstance(obj, list):
        for item in obj:
            _collect_tokens(item, tokens)
    elif isinstance(obj, str) and obj.strip():
        tokens.add(obj.lower().strip())


def _flatten_to_text(obj: Any) -> str:
    """Flatten a nested object into a single string for substring search."""
    parts: list[str] = []
    _collect_tokens(obj, {})

    def collect(o: Any) -> None:
        if isinstance(o, dict):
            for v in o.values():
                collect(v)
        elif isinstance(o, list):
            for item in o:
                collect(item)
        elif o is not None:
            parts.append(str(o))

    collect(obj)
    return " ".join(parts)
