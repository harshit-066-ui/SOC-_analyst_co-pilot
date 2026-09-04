"""Part 2 — Deterministic Rule Engine.

Consumes ContextEnrichedEvent objects from L2 and produces
SecurityAlert objects. Supports single-event conditions,
threshold rules, time windows, and group-by correlation.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from l2.models import ContextEnrichedEvent
from part2.models.security_alert import SecurityAlert

from .conditions import evaluate_condition, get_nested_value
from .rule_schema import RuleDefinition


DEFAULT_RULES_PATH = (
    Path(__file__).resolve().parent.parent
    / "rules_config"
    / "rules.json"
)


class RuleEngine:
    """
    Deterministic Rule Engine for ContextEnrichedEvent objects.

    Supports:
    - single-event conditions
    - threshold rules
    - time windows
    - group-by correlation
    - alert generation
    """

    def __init__(
        self,
        rules_path: str | Path | None = None,
    ) -> None:
        self.rules_path = Path(
            rules_path or DEFAULT_RULES_PATH
        )

        self.rules: list[RuleDefinition] = []

        self.load_rules()

    # =========================================================
    # RULE LOADING
    # =========================================================

    def load_rules(self) -> None:
        """Load and validate rules from rules.json."""

        if not self.rules_path.exists():
            raise FileNotFoundError(
                f"Rule configuration not found: {self.rules_path}"
            )

        with self.rules_path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            raw_rules = json.load(handle)

        if not isinstance(raw_rules, list):
            raise ValueError(
                "rules.json must contain a JSON array."
            )

        self.rules = [
            RuleDefinition.model_validate(rule)
            for rule in raw_rules
        ]

    def reload_rules(self) -> None:
        """Reload rules without restarting the application."""
        self.load_rules()

    # =========================================================
    # SERIALIZATION HELPERS
    # =========================================================

    @staticmethod
    def _event_to_dict(
        event: ContextEnrichedEvent | dict[str, Any],
    ) -> dict[str, Any]:
        """
        Convert a ContextEnrichedEvent to a flat dict suitable for
        rule evaluation.

        The existing L2 ContextEnrichedEvent stores event_id and
        timestamp inside the nested 'event' dict. This method promotes
        them to the top level so threshold/time-window logic and alert
        creation can access them directly.
        """
        if isinstance(event, ContextEnrichedEvent):
            d = event.model_dump()
        elif isinstance(event, dict):
            d = dict(event)
        else:
            d = dict(event)

        # Promote event_id and timestamp from the nested L1 event
        # to the top level for rule engine convenience.
        nested = d.get("event", {})
        if isinstance(nested, dict):
            if "event_id" not in d and "event_id" in nested:
                d["event_id"] = nested["event_id"]
            if "timestamp" not in d and "timestamp" in nested:
                d["timestamp"] = nested["timestamp"]

        return d

    @staticmethod
    def _parse_timestamp(
        value: str | datetime,
    ) -> datetime:
        """Convert an ISO timestamp to timezone-aware datetime."""

        if isinstance(value, datetime):
            parsed = value
        else:
            timestamp = value.strip()

            if timestamp.endswith("Z"):
                timestamp = timestamp[:-1] + "+00:00"

            parsed = datetime.fromisoformat(timestamp)

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed

    # =========================================================
    # CONDITION EVALUATION
    # =========================================================

    @staticmethod
    def _conditions_match(
        rule: RuleDefinition,
        event: dict[str, Any],
    ) -> bool:
        """All conditions in a rule must match."""

        if not rule.conditions:
            return True

        return all(
            evaluate_condition(
                event=event,
                field=condition.field,
                operator=condition.operator,
                expected=condition.value,
            )
            for condition in rule.conditions
        )

    # =========================================================
    # CONDITION AUDIT INFORMATION
    # =========================================================

    @staticmethod
    def _condition_results(
        rule: RuleDefinition,
        event: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Record exactly how each condition evaluated."""

        results: list[dict[str, Any]] = []

        for condition in rule.conditions:
            actual = get_nested_value(
                event,
                condition.field,
            )

            matched = evaluate_condition(
                event=event,
                field=condition.field,
                operator=condition.operator,
                expected=condition.value,
            )

            results.append(
                {
                    "field": condition.field,
                    "operator": condition.operator,
                    "expected": condition.value,
                    "actual": actual,
                    "matched": matched,
                }
            )

        return results

    # =========================================================
    # SINGLE EVENT EVALUATION
    # =========================================================

    def evaluate_event(
        self,
        event: ContextEnrichedEvent | dict[str, Any],
    ) -> list[SecurityAlert]:
        """
        Evaluate non-threshold rules against one event.
        Threshold rules are handled by evaluate_events().
        """

        event_dict = self._event_to_dict(event)

        alerts: list[SecurityAlert] = []

        for rule in self.rules:
            if not rule.enabled:
                continue

            if rule.threshold is not None:
                continue

            if rule.action != "generate_alert":
                continue

            if not self._conditions_match(rule, event_dict):
                continue

            alerts.append(
                self._create_alert(
                    rule=rule,
                    matched_events=[event_dict],
                    triggered_conditions=[
                        {
                            "type": "condition",
                            "results": self._condition_results(
                                rule, event_dict,
                            ),
                        }
                    ],
                )
            )

        return alerts

    # =========================================================
    # BATCH EVALUATION
    # =========================================================

    def evaluate_events(
        self,
        events: Iterable[
            ContextEnrichedEvent | dict[str, Any]
        ],
    ) -> list[SecurityAlert]:
        """
        Evaluate a complete event collection.

        This is the primary method for Part 2 because it supports:
        - ordinary event rules
        - threshold rules
        - time windows
        - grouping
        """

        event_dicts = [
            self._event_to_dict(event)
            for event in events
        ]

        alerts: list[SecurityAlert] = []

        for rule in self.rules:
            if not rule.enabled:
                continue

            if rule.action != "generate_alert":
                continue

            # Ordinary single-event rule
            if rule.threshold is None:
                for event_dict in event_dicts:

                    if not self._conditions_match(
                        rule, event_dict,
                    ):
                        continue

                    alerts.append(
                        self._create_alert(
                            rule=rule,
                            matched_events=[event_dict],
                            triggered_conditions=[
                                {
                                    "type": "condition",
                                    "results": self._condition_results(
                                        rule, event_dict,
                                    ),
                                }
                            ],
                        )
                    )

                continue

            # Threshold/time-window rule
            alerts.extend(
                self._evaluate_threshold_rule(
                    rule=rule,
                    events=event_dicts,
                )
            )

        return alerts

    # =========================================================
    # THRESHOLD RULE PROCESSING
    # =========================================================

    def _evaluate_threshold_rule(
        self,
        rule: RuleDefinition,
        events: list[dict[str, Any]],
    ) -> list[SecurityAlert]:
        """
        Evaluate a threshold rule.

        Example:
            5 failed authentications
            within 5 minutes
            grouped by source IP
        """

        if rule.threshold is None:
            return []

        matching_events = [
            event
            for event in events
            if self._conditions_match(rule, event)
        ]

        if len(matching_events) < rule.threshold:
            return []

        # Grouping
        groups: dict[Any, list[dict[str, Any]]] = {}

        if rule.group_by:
            for event in matching_events:

                group_value = get_nested_value(
                    event, rule.group_by,
                )

                if group_value is None:
                    group_value = "__missing__"

                groups.setdefault(
                    group_value, [],
                ).append(event)

        else:
            groups["__all__"] = matching_events

        alerts: list[SecurityAlert] = []

        # Evaluate every group
        for group_value, group_events in groups.items():

            group_events.sort(
                key=lambda event: self._parse_timestamp(
                    event["timestamp"]
                )
            )

            # No time window
            if rule.window_minutes is None:

                if len(group_events) < rule.threshold:
                    continue

                selected_events = group_events[
                    -rule.threshold:
                ]

                alerts.append(
                    self._create_alert(
                        rule=rule,
                        matched_events=selected_events,
                        triggered_conditions=[
                            self._threshold_result(
                                rule=rule,
                                matched_events=selected_events,
                                group_value=group_value,
                            )
                        ],
                    )
                )

                continue

            # Sliding time window
            window = timedelta(
                minutes=rule.window_minutes
            )

            for index, current_event in enumerate(
                group_events
            ):
                current_time = self._parse_timestamp(
                    current_event["timestamp"]
                )

                window_start = current_time - window

                window_events = [
                    candidate
                    for candidate in group_events[
                        : index + 1
                    ]
                    if (
                        window_start
                        <= self._parse_timestamp(
                            candidate["timestamp"]
                        )
                        <= current_time
                    )
                ]

                if len(window_events) < rule.threshold:
                    continue

                selected_events = window_events[
                    -rule.threshold:
                ]

                alerts.append(
                    self._create_alert(
                        rule=rule,
                        matched_events=selected_events,
                        triggered_conditions=[
                            self._threshold_result(
                                rule=rule,
                                matched_events=selected_events,
                                group_value=group_value,
                            )
                        ],
                    )
                )

                # One alert per rule/group for this batch.
                break

        return alerts

    # =========================================================
    # THRESHOLD AUDIT RESULT
    # =========================================================

    @staticmethod
    def _threshold_result(
        rule: RuleDefinition,
        matched_events: list[dict[str, Any]],
        group_value: Any,
    ) -> dict[str, Any]:
        timestamps = [
            event["timestamp"]
            for event in matched_events
            if event.get("timestamp") is not None
        ]

        return {
            "type": "threshold",
            "threshold": rule.threshold,
            "matched_count": len(matched_events),
            "window_minutes": rule.window_minutes,
            "group_by": rule.group_by,
            "group_value": group_value,
            "first_event_timestamp": (
                min(timestamps) if timestamps else None
            ),
            "last_event_timestamp": (
                max(timestamps) if timestamps else None
            ),
            "conditions": [
                {
                    "field": condition.field,
                    "operator": condition.operator,
                    "expected": condition.value,
                }
                for condition in rule.conditions
            ],
        }

    # =========================================================
    # ALERT CREATION
    # =========================================================

    @staticmethod
    def _create_alert(
        rule: RuleDefinition,
        matched_events: list[dict[str, Any]],
        triggered_conditions: list[dict[str, Any]],
    ) -> SecurityAlert:
        """
        Convert a successful rule evaluation into a SecurityAlert.
        """

        if not matched_events:
            raise ValueError(
                "Cannot create an alert without matched events."
            )

        first_event = matched_events[0]
        last_event = matched_events[-1]

        event_ids = [
            str(event["event_id"])
            for event in matched_events
            if event.get("event_id") is not None
        ]

        # Build evidence from matched events.
        # The normalized L1 event is nested under 'event'.
        evidence: list[dict[str, Any]] = []

        for event in matched_events:
            normalized = event.get("event", {})

            evidence.append(
                {
                    "type": "event",
                    "event_id": event.get("event_id"),
                    "timestamp": event.get("timestamp"),
                    "event_type": normalized.get("event_type"),
                    "severity": normalized.get("severity"),
                    "message": normalized.get("message"),
                    "source_ip": (
                        normalized
                        .get("source", {})
                        .get("ip")
                    ),
                    "destination_ip": (
                        normalized
                        .get("destination", {})
                        .get("ip")
                    ),
                }
            )

        # Rules that declare a technique win; otherwise the mapping L2 already
        # derived from the event is carried over instead of being dropped.
        mitre_attack = rule.mitre_attack or first_event.get(
            "mitre_attack", {}
        )

        return SecurityAlert(
            alert_id=(
                f"ALT-"
                f"{uuid.uuid4().hex[:12].upper()}"
            ),
            event_ids=event_ids,
            rule_id=rule.rule_id,
            rule_name=rule.rule_name,
            severity=rule.severity,
            confidence=rule.confidence,
            mitre_attack=mitre_attack,
            entities=first_event.get("entities", {}),
            asset_context=first_event.get("asset_context", {}),
            user_context=first_event.get("user_context", {}),
            threat_context=first_event.get("threat_context", {}),
            evidence=evidence,
            triggered_conditions=triggered_conditions,
            timestamp=last_event.get(
                "timestamp",
                datetime.now(timezone.utc).isoformat(),
            ),
            status="new",
        )
