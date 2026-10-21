"""Evaluation Lab — Pydantic models for experiments, configurations, and metrics.

These models are self-contained and do not alter any existing production schema.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ConfigurationID(str, Enum):
    RULE_BASED_ONLY = "rule_based_only"
    LLM_ONLY = "llm_only"
    LLM_RAG = "llm_rag"
    LLM_RULE_BASED = "llm_rule_based"
    FULL_FRAMEWORK = "full_framework"


class ExperimentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"  # some configs succeeded, some failed


class CaseOutcome(str, Enum):
    TRUE_POSITIVE = "TP"
    FALSE_POSITIVE = "FP"
    TRUE_NEGATIVE = "TN"
    FALSE_NEGATIVE = "FN"
    UNKNOWN = "unknown"  # no ground truth label available


# ---------------------------------------------------------------------------
# Ground Truth
# ---------------------------------------------------------------------------


class GroundTruthLabel(BaseModel):
    """A single labelled event for evaluation."""

    event_id: str
    """The normalized event ID (fingerprint or sequential ID)."""

    label: str
    """'malicious' | 'benign' — the expected classification."""

    expected_rule_ids: list[str] = Field(default_factory=list)
    """Optional: the rule IDs that should fire for this event."""

    expected_risk_level: str | None = None
    """Optional: expected risk level ('low'|'medium'|'high'|'critical')."""

    notes: str = ""
    """Human-readable annotation for synthetic/test cases."""

    is_synthetic: bool = False
    """True when this label was manufactured for smoke testing."""


class GroundTruthDataset(BaseModel):
    """A labelled dataset for evaluation."""

    dataset_id: str
    name: str
    description: str = ""
    labels: list[GroundTruthLabel] = Field(default_factory=list)
    created_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )
    is_synthetic: bool = False

    def label_map(self) -> dict[str, GroundTruthLabel]:
        return {lbl.event_id: lbl for lbl in self.labels}


# ---------------------------------------------------------------------------
# Configuration descriptors
# ---------------------------------------------------------------------------


class ConfigurationSpec(BaseModel):
    """Static descriptor for one evaluation configuration."""

    config_id: ConfigurationID
    name: str
    description: str
    components: dict[str, bool]
    """e.g. {'rules': True, 'llm': False, 'rag': False, 'judge': False, 'xai': False}"""
    notes: str = ""


CONFIGURATION_REGISTRY: dict[ConfigurationID, ConfigurationSpec] = {
    ConfigurationID.RULE_BASED_ONLY: ConfigurationSpec(
        config_id=ConfigurationID.RULE_BASED_ONLY,
        name="Rule-Based Only",
        description=(
            "Deterministic detection using the existing rule engine and risk scorer. "
            "No LLM calls, no RAG retrieval."
        ),
        components={
            "l1_normalization": True,
            "l2_enrichment": True,
            "rules": True,
            "risk_scoring": True,
            "rag": False,
            "llm": False,
            "judge": False,
            "xai": False,
        },
        notes="Risk score is authoritative deterministic output.",
    ),
    ConfigurationID.LLM_ONLY: ConfigurationSpec(
        config_id=ConfigurationID.LLM_ONLY,
        name="LLM Only",
        description=(
            "LLM analysis of the normalized and enriched event directly, "
            "without deterministic rule findings or RAG evidence. "
            "Risk score is an LLM estimate, not the authoritative deterministic score."
        ),
        components={
            "l1_normalization": True,
            "l2_enrichment": True,
            "rules": False,
            "risk_scoring": False,
            "rag": False,
            "llm": True,
            "judge": False,
            "xai": False,
        },
        notes=(
            "LLM-derived risk estimate is clearly labelled. "
            "The authoritative deterministic score is NOT available in this configuration."
        ),
    ),
    ConfigurationID.LLM_RAG: ConfigurationSpec(
        config_id=ConfigurationID.LLM_RAG,
        name="LLM + RAG",
        description=(
            "LLM analysis augmented with semantically retrieved evidence from the "
            "Qdrant vector knowledge store (BGE-M3 embeddings). "
            "No deterministic rule findings are supplied to the LLM."
        ),
        components={
            "l1_normalization": True,
            "l2_enrichment": True,
            "rules": False,
            "risk_scoring": False,
            "rag": True,
            "llm": True,
            "judge": False,
            "xai": False,
        },
        notes="RAG evidence is included in the LLM prompt. Rule findings are withheld.",
    ),
    ConfigurationID.LLM_RULE_BASED: ConfigurationSpec(
        config_id=ConfigurationID.LLM_RULE_BASED,
        name="LLM + Rule-Based",
        description=(
            "Deterministic rule findings are supplied to the LLM for interpretation. "
            "RAG is disabled. Risk score from the deterministic engine is included. "
            "LLM conclusions are clearly distinguished from rule-derived findings."
        ),
        components={
            "l1_normalization": True,
            "l2_enrichment": True,
            "rules": True,
            "risk_scoring": True,
            "rag": False,
            "llm": True,
            "judge": False,
            "xai": False,
        },
        notes=(
            "Risk score is the authoritative deterministic score. "
            "LLM interprets rule findings but cannot alter the score."
        ),
    ),
    ConfigurationID.FULL_FRAMEWORK: ConfigurationSpec(
        config_id=ConfigurationID.FULL_FRAMEWORK,
        name="Proposed Complete Framework",
        description=(
            "The production pipeline: L1 normalization → L2 enrichment → "
            "deterministic rules + risk scoring → dense-vector RAG → "
            "LLM interpretation → Judge validation → deterministic XAI."
        ),
        components={
            "l1_normalization": True,
            "l2_enrichment": True,
            "rules": True,
            "risk_scoring": True,
            "rag": True,
            "llm": True,
            "judge": True,
            "xai": True,
        },
        notes="Deterministic risk score is immutable through all downstream stages.",
    ),
}


# ---------------------------------------------------------------------------
# Per-case result for a single configuration
# ---------------------------------------------------------------------------


class RetrievedEvidence(BaseModel):
    """A single RAG retrieval hit."""

    doc_id: str = ""
    title: str = ""
    source: str = ""
    score: float = 0.0
    technique_id: str = ""
    snippet: str = ""


class CaseConfigResult(BaseModel):
    """Output of running ONE configuration against ONE normalized event."""

    config_id: ConfigurationID
    event_id: str
    status: str = "completed"
    """'completed' | 'failed' | 'skipped'"""

    # --- detection ---
    alert_fired: bool = False
    rule_ids_fired: list[str] = Field(default_factory=list)
    rule_names_fired: list[str] = Field(default_factory=list)

    # --- risk ---
    risk_score: float | None = None
    risk_level: str | None = None
    risk_score_source: str = "none"
    """'deterministic' | 'llm_estimate' | 'none'"""

    # --- RAG ---
    retrieved_evidence: list[RetrievedEvidence] = Field(default_factory=list)
    rag_available: bool = False

    # --- LLM ---
    llm_summary: str | None = None
    llm_reasoning: str | None = None
    llm_status: str = "not_run"
    """'available' | 'unavailable' | 'partial' | 'not_run'"""
    llm_model: str | None = None
    llm_recommendation: list[str] = Field(default_factory=list)

    # --- Judge ---
    judge_status: str | None = None
    judge_issues: list[str] = Field(default_factory=list)
    judge_checks_passed: int | None = None
    judge_checks_total: int | None = None
    evidence_coverage: float | None = None

    # --- XAI ---
    xai_why_alerted: str | None = None
    xai_why_risk: str | None = None
    xai_uncertainty: str | None = None

    # --- MITRE ---
    mitre_technique_id: str | None = None
    mitre_technique_name: str | None = None

    # --- classification vs ground truth ---
    ground_truth_label: str | None = None
    outcome: CaseOutcome = CaseOutcome.UNKNOWN

    # --- performance ---
    latency_ms: float | None = None
    error: str | None = None

    # --- raw output (for inspection) ---
    raw_output: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Aggregate metrics for a configuration
# ---------------------------------------------------------------------------


class ConfigMetrics(BaseModel):
    """Aggregate evaluation metrics for one configuration over all cases."""

    config_id: ConfigurationID
    cases_total: int = 0
    cases_completed: int = 0
    cases_failed: int = 0

    # Classification counts (require ground truth)
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    # Derived metrics — None when ground truth is unavailable
    precision: float | None = None
    recall: float | None = None
    f1_score: float | None = None
    false_positive_rate: float | None = None
    false_negative_rate: float | None = None

    # Risk consistency
    risk_score_available_count: int = 0
    risk_score_mean: float | None = None
    risk_score_std: float | None = None

    # Latency (milliseconds)
    latency_mean_ms: float | None = None
    latency_p95_ms: float | None = None
    latency_min_ms: float | None = None
    latency_max_ms: float | None = None

    # LLM / RAG quality
    llm_available_count: int = 0
    llm_unavailable_count: int = 0
    rag_retrieved_count: int = 0
    evidence_grounding_rate: float | None = None

    # Judge outcomes (only for configurations that run the Judge)
    judge_passed_count: int | None = None
    judge_failed_count: int | None = None
    judge_review_count: int | None = None
    judge_pass_rate: float | None = None

    # Availability note
    metrics_note: str = ""
    """Explanation when a metric cannot be calculated."""


# ---------------------------------------------------------------------------
# Full experiment record
# ---------------------------------------------------------------------------


class DatasetInfo(BaseModel):
    """Metadata about the dataset used in an experiment."""

    dataset_id: str = ""
    name: str = ""
    input_format: str = ""
    raw_event_count: int = 0
    normalized_event_count: int = 0
    deduplicated_event_count: int = 0
    duplicates_removed: int = 0
    labelled_case_count: int = 0
    ground_truth_available: bool = False
    normalization_status: str = "ok"
    normalization_errors: int = 0
    fingerprint: str = ""
    """SHA-256 of the normalized event JSON for reproducibility."""

    def compute_fingerprint(self, events: list[dict[str, Any]]) -> str:
        canon = json.dumps(events, sort_keys=True, ensure_ascii=False)
        self.fingerprint = hashlib.sha256(canon.encode()).hexdigest()
        return self.fingerprint


class ExperimentConfig(BaseModel):
    """Settings used to run an experiment — recorded for reproducibility."""

    selected_configurations: list[ConfigurationID]
    batch_size: int = 10
    max_llm_alerts: int = 20
    model_id: str = ""
    rag_collection: str = ""
    embedding_model: str = ""
    rule_set_fingerprint: str = ""
    repeated_runs: int = 1
    ground_truth_dataset_id: str = ""
    notes: str = ""


class Experiment(BaseModel):
    """Complete experiment record — persisted to disk as JSON."""

    experiment_id: str
    created_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )
    completed_at: str | None = None

    status: ExperimentStatus = ExperimentStatus.PENDING

    dataset: DatasetInfo = Field(default_factory=DatasetInfo)
    config: ExperimentConfig

    # Per-case results keyed by config_id
    case_results: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    """config_id -> list of CaseConfigResult dicts"""

    # Aggregate metrics keyed by config_id
    metrics: dict[str, dict[str, Any]] = Field(default_factory=dict)
    """config_id -> ConfigMetrics dict"""

    # Execution log
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    # Software / reproducibility metadata
    schema_version: str = "1.0"
    software_version: str = "1.0.0"
