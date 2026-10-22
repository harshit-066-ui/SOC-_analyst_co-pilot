"""Evaluation metrics calculator.

Calculates classification, performance, and quality metrics from
per-case results. All metrics are clearly labelled as unavailable when
their required inputs are missing — no zero-substitution for absent data.
"""

from __future__ import annotations

import math
import statistics
from typing import Any

from evaluation.models import (
    CaseConfigResult,
    CaseOutcome,
    ConfigMetrics,
    ConfigurationID,
    GroundTruthDataset,
)


def classify_case(
    result: CaseConfigResult,
    label: str | None,
) -> CaseOutcome:
    """Assign TP/FP/TN/FN based on alert_fired and ground truth label.

    If no ground truth label is provided, or if the case failed execution/prediction,
    the outcome is UNKNOWN (excluded from TP/FP/TN/FN counts to prevent silent
    false-negative or true-negative bias).

    Parameters
    ----------
    result:
        The configuration result for this case.
    label:
        'malicious' or 'benign' (or None if no ground truth).
    """
    if label is None or result.status == "failed":
        return CaseOutcome.UNKNOWN
    fired = result.alert_fired
    positive = label == "malicious"
    if fired and positive:
        return CaseOutcome.TRUE_POSITIVE
    if fired and not positive:
        return CaseOutcome.FALSE_POSITIVE
    if not fired and not positive:
        return CaseOutcome.TRUE_NEGATIVE
    # not fired and positive
    return CaseOutcome.FALSE_NEGATIVE


def compute_metrics(
    config_id: ConfigurationID,
    case_results: list[CaseConfigResult],
) -> ConfigMetrics:
    """Compute all available metrics for one configuration.

    Metrics that require ground truth are set to None (not 0) when labels
    are unavailable. The metrics_note field explains any gaps or failure exclusions.
    """
    m = ConfigMetrics(
        config_id=config_id,
        cases_total=len(case_results),
    )

    notes: list[str] = []
    latencies: list[float] = []
    risk_scores: list[float] = []
    coverage_values: list[float] = []
    llm_available = 0
    llm_unavailable = 0
    rag_retrieved = 0
    judge_passed = 0
    judge_failed = 0
    judge_review = 0
    judge_run_count = 0

    has_ground_truth = any(
        r.ground_truth_label is not None for r in case_results
    )
    has_outcome = any(r.outcome != CaseOutcome.UNKNOWN for r in case_results)

    for r in case_results:
        if r.status == "completed":
            m.cases_completed += 1
        elif r.status == "failed":
            m.cases_failed += 1

        # Latency
        if r.latency_ms is not None:
            latencies.append(r.latency_ms)

        # Risk scores
        if r.risk_score is not None:
            risk_scores.append(float(r.risk_score))
            m.risk_score_available_count += 1

        # LLM availability
        if r.llm_status == "available":
            llm_available += 1
        elif r.llm_status in ("unavailable", "partial", "failed"):
            llm_unavailable += 1

        # RAG
        if r.rag_available:
            rag_retrieved += 1

        # Evidence coverage
        if r.evidence_coverage is not None:
            coverage_values.append(float(r.evidence_coverage))

        # Judge outcomes
        if r.judge_status is not None:
            judge_run_count += 1
            if r.judge_status == "passed":
                judge_passed += 1
            elif r.judge_status == "failed":
                judge_failed += 1
            elif r.judge_status == "review":
                judge_review += 1

        # Classification counts
        if r.outcome == CaseOutcome.TRUE_POSITIVE:
            m.tp += 1
        elif r.outcome == CaseOutcome.FALSE_POSITIVE:
            m.fp += 1
        elif r.outcome == CaseOutcome.TRUE_NEGATIVE:
            m.tn += 1
        elif r.outcome == CaseOutcome.FALSE_NEGATIVE:
            m.fn += 1

    # LLM / RAG
    m.llm_available_count = llm_available
    m.llm_unavailable_count = llm_unavailable
    m.rag_retrieved_count = rag_retrieved

    # Evidence grounding rate
    if coverage_values:
        m.evidence_grounding_rate = round(
            statistics.mean(coverage_values), 4
        )

    # Judge
    if judge_run_count > 0:
        m.judge_passed_count = judge_passed
        m.judge_failed_count = judge_failed
        m.judge_review_count = judge_review
        m.judge_pass_rate = judge_passed / judge_run_count

    # Latency
    if latencies:
        m.latency_mean_ms = round(statistics.mean(latencies), 2)
        m.latency_min_ms = round(min(latencies), 2)
        m.latency_max_ms = round(max(latencies), 2)
        sorted_lat = sorted(latencies)
        idx = max(0, math.ceil(0.95 * len(sorted_lat)) - 1)
        m.latency_p95_ms = round(sorted_lat[idx], 2)

    # Risk score stats
    if risk_scores:
        m.risk_score_mean = round(statistics.mean(risk_scores), 2)
        m.risk_score_std = (
            round(statistics.stdev(risk_scores), 2)
            if len(risk_scores) > 1
            else 0.0
        )

    # Document failure exclusions
    if m.cases_failed > 0:
        notes.append(
            f"{m.cases_failed} case(s) failed prediction/execution and were excluded from classification metrics."
        )

    # Classification metrics — only when ground truth is available
    if not has_outcome or not has_ground_truth:
        notes.append(
            "Precision, recall, F1, FPR, FNR: Not available — "
            "no ground truth labels or valid completed predictions provided for this run."
        )
    else:
        tp, fp, tn, fn = m.tp, m.fp, m.tn, m.fn

        # Precision
        if tp + fp > 0:
            m.precision = round(tp / (tp + fp), 4)
        else:
            m.precision = None
            notes.append("Precision: Not available — no positive predictions made.")

        # Recall (sensitivity)
        if tp + fn > 0:
            m.recall = round(tp / (tp + fn), 4)
        else:
            m.recall = None
            notes.append("Recall: Not available — no positive ground-truth cases.")

        # F1
        if m.precision is not None and m.recall is not None:
            p, r = m.precision, m.recall
            if p + r > 0:
                m.f1_score = round(2 * p * r / (p + r), 4)
            else:
                m.f1_score = 0.0
        else:
            m.f1_score = None
            notes.append("F1: Not available — precision or recall unavailable.")

        # False Positive Rate
        if fp + tn > 0:
            m.false_positive_rate = round(fp / (fp + tn), 4)
        else:
            m.false_positive_rate = None
            notes.append("FPR: Not available — no negative ground-truth cases.")

        # False Negative Rate
        if fn + tp > 0:
            m.false_negative_rate = round(fn / (fn + tp), 4)
        else:
            m.false_negative_rate = None
            notes.append("FNR: Not available — no positive ground-truth cases.")

    m.metrics_note = " | ".join(notes) if notes else "All applicable metrics computed."
    return m


def apply_ground_truth(
    case_results: list[CaseConfigResult],
    ground_truth: GroundTruthDataset | None,
) -> list[CaseConfigResult]:
    """Attach ground truth labels and outcomes to case results in-place."""
    if not ground_truth:
        return case_results

    label_map = ground_truth.label_map()
    for result in case_results:
        lbl = label_map.get(result.event_id)
        if lbl:
            result.ground_truth_label = lbl.label
            result.outcome = classify_case(result, lbl.label)
    return case_results


def results_to_csv_rows(
    case_results: list[CaseConfigResult],
) -> list[dict[str, Any]]:
    """Convert case results to flat dicts suitable for CSV export."""
    rows: list[dict[str, Any]] = []
    for r in case_results:
        rows.append(
            {
                "config_id": r.config_id.value,
                "event_id": r.event_id,
                "status": r.status,
                "alert_fired": r.alert_fired,
                "rule_ids": "|".join(r.rule_ids_fired),
                "risk_score": r.risk_score,
                "risk_level": r.risk_level,
                "risk_score_source": r.risk_score_source,
                "llm_status": r.llm_status,
                "llm_model": r.llm_model,
                "judge_status": r.judge_status,
                "judge_checks_passed": r.judge_checks_passed,
                "judge_checks_total": r.judge_checks_total,
                "evidence_coverage": r.evidence_coverage,
                "rag_hits": len(r.retrieved_evidence),
                "mitre_technique_id": r.mitre_technique_id,
                "ground_truth_label": r.ground_truth_label,
                "outcome": r.outcome.value,
                "latency_ms": r.latency_ms,
                "error": r.error,
            }
        )
    return rows
