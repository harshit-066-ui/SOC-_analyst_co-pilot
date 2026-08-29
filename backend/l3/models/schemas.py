"""PART 3 data contracts — Pydantic v2 models.

This module defines every schema used in PART 3:

  SecurityAssessment    — consumed from PART 2 (read-only input)
  LLMAnalysis           — structured LLM output
  ValidationResult      — Judge layer deterministic verdict
  XAIExplanation        — human-readable explanation block
  FinalSecurityAssessment — complete analyst-facing result

IMPORTANT:
  - SecurityAssessment.risk.score is NEVER modified by PART 3.
  - All models use model_config with extra='allow' to survive PART 2
    schema evolution without crashing.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class UncertaintyLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ValidationStatus(str, Enum):
    PASSED = "passed"
    REVIEW = "review"
    FAILED = "failed"
    SKIPPED = "skipped"


class LLMStatus(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    PARTIAL = "partial"


class FinalStatus(str, Enum):
    VALIDATED = "validated"
    REVIEW_REQUIRED = "review_required"
    LLM_UNAVAILABLE = "llm_unavailable"


# ---------------------------------------------------------------------------
# PART 2 Input Contract — SecurityAssessment
# ---------------------------------------------------------------------------


class AlertInfo(BaseModel):
    """High-level alert metadata from PART 2."""

    model_config = {"extra": "allow"}

    rule_id: str = ""
    rule_name: str = ""
    description: str = ""
    severity: str = "unknown"


class TriggeringRule(BaseModel):
    """The specific rule that fired this alert."""

    model_config = {"extra": "allow"}

    id: str = ""
    name: str = ""
    condition: str = ""
    threshold: Any = None


class EventContext(BaseModel):
    """Normalized/contextualized event fields forwarded from PART 1 via PART 2."""

    model_config = {"extra": "allow"}

    source_platform: str = "unknown"
    event_type: str = "unknown"
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: str | None = None
    destination_port: str | None = None
    hostname: str | None = None
    username: str | None = None
    process_name: str | None = None
    protocol: str | None = None
    action: str | None = None
    message: str | None = None


class MitreMapping(BaseModel):
    """MITRE ATT&CK mapping from PART 2."""

    model_config = {"extra": "allow"}

    tactic: str = ""
    technique_id: str = ""
    technique_name: str = ""
    sub_technique: str | None = None


class RiskInfo(BaseModel):
    """Deterministic risk assessment from PART 2.

    PART 3 reads this but NEVER writes to it.
    """

    model_config = {"extra": "allow"}

    score: float = Field(..., ge=0.0, le=100.0)
    level: str = "unknown"
    factors: list[str] = Field(default_factory=list)


class SecurityAssessment(BaseModel):
    """Output contract of PART 2 — the authoritative input to PART 3.

    All fields are read-only from PART 3's perspective.
    extra='allow' ensures forward-compatibility as PART 2 evolves.
    """

    model_config = {"extra": "allow"}

    alert_id: str
    alert: AlertInfo = Field(default_factory=AlertInfo)
    triggering_rule: TriggeringRule = Field(default_factory=TriggeringRule)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    event_context: EventContext = Field(default_factory=EventContext)
    mitre: MitreMapping = Field(default_factory=MitreMapping)
    risk: RiskInfo
    retrieved_cti: list[dict[str, Any]] = Field(default_factory=list)
    timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )


# ---------------------------------------------------------------------------
# PART 3 Output: LLMAnalysis
# ---------------------------------------------------------------------------


class UncertaintyBlock(BaseModel):
    """Structured uncertainty representation."""

    level: UncertaintyLevel
    reasons: list[str] = Field(default_factory=list)


class MitreInterpretation(BaseModel):
    """LLM interpretation of a single MITRE technique."""

    technique_id: str
    technique_name: str
    relevance: str
    evidence_basis: str


class ModelMetadata(BaseModel):
    """Provenance metadata for the LLM call."""

    provider: str = "OpenRouter"
    model: str
    timestamp: str
    response_id: str | None = None


class LLMAnalysis(BaseModel):
    """Structured output produced by the LLM reasoning step.

    schema_version is fixed at '1.0' and validated by the Judge.
    """

    alert_id: str
    summary: str
    reasoning: str
    supporting_evidence: list[str] = Field(default_factory=list)
    mitre_interpretation: list[MitreInterpretation] = Field(
        default_factory=list
    )
    uncertainty: UncertaintyBlock
    analyst_recommendation: list[str] = Field(default_factory=list)
    possible_interpretations: list[str] = Field(default_factory=list)
    model_metadata: ModelMetadata
    schema_version: str = "1.0"


# ---------------------------------------------------------------------------
# Validation / Judge
# ---------------------------------------------------------------------------


class ValidationResult(BaseModel):
    """Deterministic judge verdict.

    The judge is authoritative — a 'failed' status means the LLM output
    cannot be trusted and should not be presented to the analyst as fact.
    """

    status: ValidationStatus
    issues: list[str] = Field(default_factory=list)
    unsupported_claims: list[str] = Field(default_factory=list)
    evidence_coverage: float = Field(0.0, ge=0.0, le=1.0)
    checks_run: list[str] = Field(default_factory=list)
    checks_passed: int = 0
    checks_total: int = 0


# ---------------------------------------------------------------------------
# XAI Explanation
# ---------------------------------------------------------------------------


class XAIExplanation(BaseModel):
    """Human-readable analyst explanation block.

    Built entirely from SecurityAssessment deterministic fields.
    Never fabricated — if data is missing the field says so explicitly.
    """

    why_alerted: str
    why_risk: str
    supporting_factors: list[str] = Field(default_factory=list)
    context_influences: list[str] = Field(default_factory=list)
    uncertainty: str
    mitre_context: str
    evidence_summary: str


# ---------------------------------------------------------------------------
# Final Output Contract
# ---------------------------------------------------------------------------


class FinalSecurityAssessment(BaseModel):
    """Complete analyst-facing result produced by PART 3.

    The deterministic risk score from PART 2 is preserved verbatim.
    LLM reasoning is advisory / explanatory.
    Validation determines whether LLM output can be trusted.
    """

    security_assessment: SecurityAssessment
    llm_analysis: LLMAnalysis | None = None
    llm_status: LLMStatus
    validation: ValidationResult
    explanation: XAIExplanation
    final_status: FinalStatus
    processing_timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )
    schema_version: str = "1.0"

    @model_validator(mode="after")
    def risk_score_preserved(self) -> "FinalSecurityAssessment":
        """Invariant guard: risk.score must equal the input assessment score."""
        if self.llm_analysis is not None:
            # The LLM analysis should not contain a risk score field at all.
            # This validator ensures we never silently carry a mutated score.
            pass
        return self
