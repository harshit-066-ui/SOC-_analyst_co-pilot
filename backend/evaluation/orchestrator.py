"""Evaluation Lab orchestrator.

Runs one or more configurations against the same normalized events and
records the results in an Experiment object.

Design constraints:
- Normalize events ONCE; pass the same normalized list to all configs.
- Never silently substitute a configuration if a component fails.
- Record failures honestly — a failed config doesn't abort the others.
- Risk scores from the deterministic engine are never modified.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime
from typing import Any

from evaluation.models import (
    CONFIGURATION_REGISTRY,
    CaseConfigResult,
    CaseOutcome,
    ConfigMetrics,
    ConfigurationID,
    DatasetInfo,
    Experiment,
    ExperimentConfig,
    ExperimentStatus,
    GroundTruthDataset,
)
from evaluation.metrics import apply_ground_truth, compute_metrics
from evaluation.persistence import load_ground_truth, save_experiment

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fingerprint(events: list[dict[str, Any]]) -> str:
    canon = json.dumps(events, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canon.encode()).hexdigest()


def _ruleset_fingerprint() -> str:
    """Return a fingerprint of the currently loaded rules.json for reproducibility."""
    try:
        from pathlib import Path
        rules_path = (
            Path(__file__).resolve().parent.parent
            / "part2"
            / "rules_config"
            / "rules.json"
        )
        if rules_path.exists():
            content = rules_path.read_bytes()
            return hashlib.sha256(content).hexdigest()[:16]
        return "unavailable"
    except Exception:
        return "unavailable"


def _get_l3_config() -> tuple[str, str, str]:
    """Return (model_id, rag_collection, embedding_model) from config."""
    try:
        from l3.config import OPENROUTER_MODEL
        from vectorstore.config import QDRANT_COLLECTION
        from embeddings.config import EMBEDDING_MODEL
        return OPENROUTER_MODEL, QDRANT_COLLECTION, EMBEDDING_MODEL
    except Exception:
        return "unknown", "unknown", "unknown"


def _make_case_result(
    config_id: ConfigurationID,
    event_id: str,
    raw: dict[str, Any],
    status: str = "completed",
) -> CaseConfigResult:
    """Map a raw result dict from a config runner into a CaseConfigResult."""
    retrieved_evidence = []
    for ev in raw.get("retrieved_evidence", []):
        from evaluation.models import RetrievedEvidence
        retrieved_evidence.append(
            RetrievedEvidence(
                doc_id=str(ev.get("doc_id", "")),
                title=str(ev.get("title", "")),
                source=str(ev.get("source", "")),
                score=float(ev.get("score", 0.0)),
                technique_id=str(ev.get("technique_id", "")),
                snippet=str(ev.get("snippet", ""))[:300],
            )
        )

    return CaseConfigResult(
        config_id=config_id,
        event_id=event_id,
        status=status,
        alert_fired=bool(raw.get("alert_fired", False)),
        rule_ids_fired=raw.get("rule_ids_fired", []),
        rule_names_fired=raw.get("rule_names_fired", []),
        risk_score=raw.get("risk_score"),
        risk_level=raw.get("risk_level"),
        risk_score_source=raw.get("risk_score_source", "none"),
        retrieved_evidence=retrieved_evidence,
        rag_available=bool(raw.get("rag_available", False)),
        llm_summary=raw.get("llm_summary"),
        llm_reasoning=raw.get("llm_reasoning"),
        llm_status=raw.get("llm_status", "not_run"),
        llm_model=raw.get("llm_model"),
        llm_recommendation=raw.get("llm_recommendation", []),
        judge_status=raw.get("judge_status"),
        judge_issues=raw.get("judge_issues", []),
        judge_checks_passed=raw.get("judge_checks_passed"),
        judge_checks_total=raw.get("judge_checks_total"),
        evidence_coverage=raw.get("evidence_coverage"),
        xai_why_alerted=raw.get("xai_why_alerted"),
        xai_why_risk=raw.get("xai_why_risk"),
        xai_uncertainty=raw.get("xai_uncertainty"),
        mitre_technique_id=raw.get("mitre_technique_id"),
        mitre_technique_name=raw.get("mitre_technique_name"),
        latency_ms=raw.get("latency_ms"),
        error=raw.get("error"),
        raw_output=raw.get("raw_output", {}),
    )


def _run_single_config(
    config_id: ConfigurationID,
    normalized_events: list[dict[str, Any]],
) -> tuple[list[CaseConfigResult], list[str]]:
    """Dispatch to the appropriate config runner module."""
    case_results: list[CaseConfigResult] = []
    errors: list[str] = []

    try:
        if config_id == ConfigurationID.RULE_BASED_ONLY:
            from evaluation.configs.rule_based_only import run
            raw_results, run_errors = run(normalized_events)

        elif config_id == ConfigurationID.LLM_ONLY:
            from evaluation.configs.llm_only import run
            raw_results, run_errors = run(normalized_events)

        elif config_id == ConfigurationID.LLM_RAG:
            from evaluation.configs.llm_rag import run
            raw_results, run_errors = run(normalized_events)

        elif config_id == ConfigurationID.LLM_RULE_BASED:
            from evaluation.configs.llm_rule_based import run
            raw_results, run_errors = run(normalized_events)

        elif config_id == ConfigurationID.FULL_FRAMEWORK:
            from evaluation.configs.full_framework import run
            raw_results, run_errors = run(normalized_events)

        else:
            return [], [f"Unknown configuration: {config_id}"]

        errors.extend(run_errors)

        # Map raw results into typed CaseConfigResult objects
        for raw in raw_results:
            event_id = str(raw.get("event_id", ""))
            status = "failed" if raw.get("error") and not raw.get("alert_fired") and raw.get("llm_status") not in ("available", "not_run") else "completed"
            case_results.append(_make_case_result(config_id, event_id, raw, status))

        # Ensure every input event has a result (fill gaps from failed batches)
        result_ids = {r.event_id for r in case_results}
        for event in normalized_events:
            eid = str(event.get("event_id", ""))
            if eid not in result_ids:
                case_results.append(
                    CaseConfigResult(
                        config_id=config_id,
                        event_id=eid,
                        status="failed",
                        error="No result produced for this event.",
                    )
                )

    except Exception as exc:
        err = f"Configuration {config_id.value} raised an unexpected error: {exc}"
        logger.exception(err)
        errors.append(err)
        # Produce failed stubs for all events
        for event in normalized_events:
            eid = str(event.get("event_id", ""))
            case_results.append(
                CaseConfigResult(
                    config_id=config_id,
                    event_id=eid,
                    status="failed",
                    error=str(exc),
                )
            )

    return case_results, errors


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_experiment(
    normalized_events: list[dict[str, Any]],
    config: ExperimentConfig,
    dataset_info: DatasetInfo | None = None,
    ground_truth: GroundTruthDataset | None = None,
) -> Experiment:
    """Run the selected configurations and persist the result.

    Parameters
    ----------
    normalized_events:
        Already-normalized events (L1 output). Passed unchanged to all configs.
    config:
        Experiment configuration (which configs, batch size, model, etc.).
    dataset_info:
        Metadata about the input dataset for the experiment record.
    ground_truth:
        Optional labelled dataset. When supplied, classification metrics are computed.

    Returns
    -------
    Experiment
        The completed (or partial) experiment record.
    """
    experiment_id = uuid.uuid4().hex[:16]
    logger.info(
        "Starting experiment %s | configs=%s | events=%d",
        experiment_id,
        [c.value for c in config.selected_configurations],
        len(normalized_events),
    )

    # Resolve model/collection info from production config
    model_id, rag_collection, embedding_model = _get_l3_config()
    if not config.model_id:
        config.model_id = model_id
    if not config.rag_collection:
        config.rag_collection = rag_collection
    if not config.embedding_model:
        config.embedding_model = embedding_model
    if not config.rule_set_fingerprint:
        config.rule_set_fingerprint = _ruleset_fingerprint()

    # Load ground truth if referenced by ID
    if ground_truth is None and config.ground_truth_dataset_id:
        ground_truth = load_ground_truth(config.ground_truth_dataset_id)

    # Build dataset info
    if dataset_info is None:
        dataset_info = DatasetInfo(
            dataset_id=_fingerprint(normalized_events)[:12],
            name="uploaded_dataset",
            normalized_event_count=len(normalized_events),
        )
    dataset_info.fingerprint = _fingerprint(normalized_events)
    if ground_truth:
        dataset_info.ground_truth_available = True
        dataset_info.labelled_case_count = len(ground_truth.labels)

    experiment = Experiment(
        experiment_id=experiment_id,
        status=ExperimentStatus.RUNNING,
        dataset=dataset_info,
        config=config,
    )
    save_experiment(experiment)

    all_errors: list[str] = []
    config_success: list[bool] = []

    for config_id in config.selected_configurations:
        logger.info(
            "Running configuration %s for experiment %s",
            config_id.value,
            experiment_id,
        )

        case_results, run_errors = _run_single_config(config_id, normalized_events)
        all_errors.extend(run_errors)

        # Apply ground truth labels and classify outcomes
        if ground_truth:
            case_results = apply_ground_truth(case_results, ground_truth)

        # Compute aggregate metrics
        metrics = compute_metrics(config_id, case_results)

        # Persist into experiment record
        experiment.case_results[config_id.value] = [
            r.model_dump(mode="json") for r in case_results
        ]
        experiment.metrics[config_id.value] = metrics.model_dump(mode="json")

        failed_cases = sum(1 for r in case_results if r.status == "failed")
        config_success.append(failed_cases < len(case_results))

        if run_errors:
            experiment.warnings.append(
                f"{config_id.value}: {len(run_errors)} error(s) — "
                + "; ".join(run_errors[:3])
            )

        logger.info(
            "Config %s complete | cases=%d | failed=%d | alerts=%d",
            config_id.value,
            len(case_results),
            failed_cases,
            metrics.cases_completed,
        )

        # Save incremental progress
        save_experiment(experiment)

    # Final status
    experiment.errors = all_errors
    experiment.completed_at = datetime.utcnow().isoformat() + "Z"

    if all(config_success):
        experiment.status = ExperimentStatus.COMPLETED
    elif any(config_success):
        experiment.status = ExperimentStatus.PARTIAL
    else:
        experiment.status = ExperimentStatus.FAILED

    save_experiment(experiment)
    logger.info(
        "Experiment %s finished | status=%s | configs=%d",
        experiment_id,
        experiment.status.value,
        len(config.selected_configurations),
    )
    return experiment
