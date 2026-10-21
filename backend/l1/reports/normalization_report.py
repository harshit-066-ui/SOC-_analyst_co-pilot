"""Normalization report generation."""

from __future__ import annotations

from typing import Any

from l1.config import SCHEMA_VERSION


def build_report(
    input_file: str,
    source_detected: str,
    total_events: int,
    successfully_normalized: int,
    failed_events: int,
    duplicate_events: int,
    unsupported_events: int = 0,
    missing_timestamp_count: int = 0,
    missing_source_count: int = 0,
    missing_event_type_count: int = 0,
    detection_confidence: float = 0.0,
    truncated: bool = False,
    source_hint: str | None = None,
) -> dict[str, Any]:
    return {
        "input_file": input_file,
        "source_detected": source_detected,
        "source_hint": source_hint,
        "detection_confidence": round(detection_confidence, 3),
        "total_events": total_events,
        "successfully_normalized": successfully_normalized,
        "failed_events": failed_events,
        "duplicate_events": duplicate_events,
        "unsupported_events": unsupported_events,
        "missing_timestamp_count": missing_timestamp_count,
        "missing_source_count": missing_source_count,
        "missing_event_type_count": missing_event_type_count,
        "schema_version": SCHEMA_VERSION,
        "truncated": truncated,
        "status": "completed" if failed_events == 0 else "completed_with_errors",
    }


def build_multi_report(
    overall_stats: dict[str, Any],
    sources: dict[str, dict[str, Any]],
    files: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a unified normalization report for multi-source ingestion.

    Includes backward-compatible top-level fields that mirror the single-file
    ``build_report`` contract (``source_detected``, ``total_events``,
    ``successfully_normalized``, etc.) while preserving the nested ``overall``,
    ``sources``, and ``files`` sections for multi-file consumers.
    """
    # Derive a single source_detected label for backward compatibility.
    detected_platforms = {
        f.get("source_detected")
        for f in files
        if f.get("source_detected")
    }
    if len(detected_platforms) == 1:
        source_detected = detected_platforms.pop()
    elif len(detected_platforms) > 1:
        source_detected = "mixed"
    else:
        source_detected = "unknown"

    return {
        # Backward-compatible top-level fields (mirror build_report)
        "source_detected": source_detected,
        "total_events": overall_stats.get("total_events", 0),
        "successfully_normalized": overall_stats.get("normalized_events", 0),
        "failed_events": overall_stats.get("failed_events", 0),
        "duplicate_events": overall_stats.get("duplicates_removed", 0),
        "duplicates_removed": overall_stats.get("duplicates_removed", 0),
        "truncated": overall_stats.get("truncated", False),
        # Nested multi-file sections (preserved for existing consumers)
        "schema_version": SCHEMA_VERSION,
        "overall": overall_stats,
        "sources": sources,
        "files": files,
        "status": "completed" if overall_stats.get("failed_events", 0) == 0 else "completed_with_errors",
    }
