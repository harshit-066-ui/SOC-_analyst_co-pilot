"""Turn Part 2 rule findings into the plain text that gets embedded.

Only the fields that carry retrieval signal are used; the event schema itself
is untouched. Output looks like::

    Rule ID: AUTH-001
    Finding: Multiple Failed Authentication Attempts
    Severity: high
    MITRE: T1110 Brute Force
    Risk: 80.25 (critical)
    Platform: linux
    Host: web-01
    User: root
"""

from __future__ import annotations

from typing import Any

from part2.models.security_alert import SecurityAlert
from part2.models.security_assessment import SecurityAssessment


def _line(label: str, value: Any) -> str | None:
    if value in (None, "", [], {}):
        return None
    return f"{label}: {value}"


def _mitre_text(mitre: dict[str, Any]) -> str:
    technique = " ".join(
        str(part)
        for part in (mitre.get("technique_id"), mitre.get("technique_name"))
        if part
    )
    return technique or ", ".join(str(t) for t in mitre.get("techniques") or [])


def alert_to_text(alert: SecurityAlert) -> str:
    """Retrieval text for a rule finding on its own."""

    lines = [
        _line("Rule ID", alert.rule_id),
        _line("Finding", alert.rule_name),
        _line("Severity", alert.severity),
        _line("MITRE", _mitre_text(alert.mitre_attack)),
        _line("Platform", alert.asset_context.get("platform")),
        _line("Host", alert.asset_context.get("hostname")),
        _line("User", alert.user_context.get("username")),
    ]
    return "\n".join(line for line in lines if line)


def assessment_to_text(assessment: SecurityAssessment) -> str:
    """Retrieval text for a rule finding plus its deterministic risk."""

    risk = f"{assessment.risk.score} ({assessment.risk.level})"
    return "\n".join([alert_to_text(assessment.alert), f"Risk: {risk}"])
