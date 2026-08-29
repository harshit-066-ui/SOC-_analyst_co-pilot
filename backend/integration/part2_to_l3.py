"""Adapter: Part 2 ``SecurityAssessment`` -> L3 ``SecurityAssessment``.

Part 2 and L3 were built against two different shapes of the same concept:

* Part 2 emits ``{alert: SecurityAlert, risk: RiskAssessment, evidence, mitre_attack}``
* L3 consumes ``{alert_id, alert, triggering_rule, evidence, event_context,
  mitre, risk, retrieved_cti, timestamp}``

This module performs the translation without modifying either layer. The
enriched events produced by L2 are used, when available, to fill
``event_context`` and ``retrieved_cti`` — the two fields Part 2 does not
carry on its own output contract.
"""

from __future__ import annotations

import re
from typing import Any

from l2.models import ContextEnrichedEvent
from l3.models.schemas import (
    AlertInfo,
    EventContext,
    MitreMapping,
    RiskInfo,
    SecurityAssessment as L3SecurityAssessment,
    TriggeringRule,
)
from part2.models.security_assessment import (
    RiskAssessment,
    SecurityAssessment as Part2SecurityAssessment,
)

MAX_CTI_ITEMS = 5

TECHNIQUE_PATTERN = re.compile(r"^\s*(T\d{4}(?:\.\d{3})?)\s*(?:[-–:]\s*(.*))?$")


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _first(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def _as_str(value: Any) -> str | None:
    return None if value in (None, "") else str(value)


def _split_technique(technique: str) -> tuple[str, str]:
    """Split an ``"T1110 - Brute Force"`` style string into id and name."""

    match = TECHNIQUE_PATTERN.match(technique)
    if not match:
        return "", technique.strip()
    return match.group(1), (match.group(2) or "").strip()


def _build_mitre(mitre_attack: dict[str, Any]) -> MitreMapping:
    """Accept both the rule-engine shape and the L2 enrichment shape."""

    technique_id = str(mitre_attack.get("technique_id") or "")
    technique_name = str(mitre_attack.get("technique_name") or "")

    techniques = mitre_attack.get("techniques") or []
    if not technique_id and techniques:
        technique_id, parsed_name = _split_technique(str(techniques[0]))
        technique_name = technique_name or parsed_name

    tactic = str(mitre_attack.get("tactic") or "")
    tactics = mitre_attack.get("tactics") or []
    if not tactic and tactics:
        tactic = str(tactics[0])

    return MitreMapping(
        tactic=tactic,
        technique_id=technique_id,
        technique_name=technique_name,
        sub_technique=_as_str(mitre_attack.get("sub_technique")),
    )


def _build_event_context(
    normalized_event: dict[str, Any],
    asset_context: dict[str, Any],
    user_context: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> EventContext:
    source = _as_dict(normalized_event.get("source"))
    destination = _as_dict(normalized_event.get("destination"))
    user = _as_dict(normalized_event.get("user"))
    process = _as_dict(normalized_event.get("process"))
    network = _as_dict(normalized_event.get("network"))
    first_evidence = evidence[0] if evidence else {}

    return EventContext(
        source_platform=str(
            _first(normalized_event.get("source_platform"), "unknown")
        ),
        event_type=str(
            _first(
                normalized_event.get("event_type"),
                first_evidence.get("event_type"),
                "unknown",
            )
        ),
        source_ip=_as_str(
            _first(source.get("ip"), first_evidence.get("source_ip"))
        ),
        destination_ip=_as_str(
            _first(destination.get("ip"), first_evidence.get("destination_ip"))
        ),
        source_port=_as_str(source.get("port")),
        destination_port=_as_str(destination.get("port")),
        hostname=_as_str(
            _first(
                source.get("hostname"),
                asset_context.get("hostname"),
                asset_context.get("asset_id"),
            )
        ),
        username=_as_str(
            _first(
                user.get("name"),
                user_context.get("username"),
                user_context.get("user_id"),
            )
        ),
        process_name=_as_str(process.get("name")),
        protocol=_as_str(network.get("protocol")),
        action=_as_str(normalized_event.get("action")),
        message=_as_str(
            _first(normalized_event.get("message"), first_evidence.get("message"))
        ),
    )


def _build_risk(risk: RiskAssessment) -> RiskInfo:
    factors = [
        f"{factor.get('factor', 'factor')}: value={factor.get('value')}, "
        f"weight={factor.get('weight')}, "
        f"contribution={factor.get('contribution')}"
        for factor in risk.factors
    ]

    return RiskInfo(
        score=max(0.0, min(100.0, float(risk.score))),
        level=risk.level,
        factors=factors,
    )


def _collect_cti(events: list[ContextEnrichedEvent]) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    seen: set[str] = set()

    for event in events:
        for item in event.retrieved_context:
            key = str(
                _first(item.get("id"), item.get("title"), item)
            )
            if key in seen:
                continue
            seen.add(key)
            collected.append(item)
            if len(collected) >= MAX_CTI_ITEMS:
                return collected

    return collected


def _describe_conditions(triggered_conditions: list[dict[str, Any]]) -> str:
    parts: list[str] = []

    for condition in triggered_conditions:
        if condition.get("type") == "threshold":
            nested = _describe_conditions(condition.get("conditions") or [])
            parts.append(
                f"count({condition.get('group_by', 'events')}) >= "
                f"{condition.get('threshold')} within "
                f"{condition.get('window_minutes')} minute(s)"
                + (f" where {nested}" if nested else "")
            )
            continue

        field = condition.get("field")
        if not field:
            continue
        parts.append(
            f"{field} {condition.get('operator', '==')} {condition.get('expected')}"
        )

    return " AND ".join(parts)


def _threshold_of(triggered_conditions: list[dict[str, Any]]) -> Any:
    for condition in triggered_conditions:
        if condition.get("threshold") is not None:
            return condition["threshold"]
    return None


def to_l3_assessment(
    assessment: Part2SecurityAssessment,
    enriched_events: dict[str, ContextEnrichedEvent] | None = None,
) -> L3SecurityAssessment:
    """Translate one Part 2 assessment into the L3 input contract."""

    alert = assessment.alert
    lookup = enriched_events or {}
    matched = [lookup[eid] for eid in alert.event_ids if eid in lookup]
    normalized_event = matched[0].event if matched else {}

    return L3SecurityAssessment(
        alert_id=alert.alert_id,
        alert=AlertInfo(
            rule_id=alert.rule_id,
            rule_name=alert.rule_name,
            description=_describe_conditions(alert.triggered_conditions),
            severity=alert.severity,
        ),
        triggering_rule=TriggeringRule(
            id=alert.rule_id,
            name=alert.rule_name,
            condition=_describe_conditions(alert.triggered_conditions),
            threshold=_threshold_of(alert.triggered_conditions),
        ),
        evidence=assessment.evidence,
        event_context=_build_event_context(
            normalized_event=normalized_event,
            asset_context=alert.asset_context,
            user_context=alert.user_context,
            evidence=assessment.evidence,
        ),
        mitre=_build_mitre(
            _first(assessment.mitre_attack, alert.mitre_attack) or {}
        ),
        risk=_build_risk(assessment.risk),
        retrieved_cti=_collect_cti(matched),
        timestamp=alert.timestamp,
    )
