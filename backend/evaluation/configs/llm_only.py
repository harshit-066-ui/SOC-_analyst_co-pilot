"""Configuration B — LLM Only.

Pipeline:  L2 enrichment → LLM direct analysis (no rule findings, no RAG)
Disabled:  Rule engine, Risk scoring, RAG, Judge, XAI

The LLM receives the enriched event context but NOT Part 2 rule findings.
Any risk estimate is clearly labelled as LLM-derived, not authoritative.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from evaluation.configs.common import (
    safe_dict,
    safe_list,
    safe_str,
    validate_evaluation_response,
)
from l2.enricher import enrich_event
from l2.models import ContextEnrichedEvent
from l3.config import OPENROUTER_MAX_TOKENS
from l3.reasoning.openrouter_client import LLMUnavailableError, OpenRouterClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LLM-Only system prompt — explicitly withholds rule engine findings
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a senior SOC analyst assistant reviewing a security event.
Analyze the event using ONLY the context fields provided.
You have NOT been given any deterministic rule-engine results or risk scores.
Do NOT invent:
  - threat actor names or CVE identifiers
  - risk scores (any score you provide is an estimate and must be labelled as such)
  - MITRE techniques not clearly evidenced by the data

Provide a concise, evidence-grounded assessment. Keep summary and reasoning to 1-2 sentences each.
Respond with ONLY a single valid JSON object adhering strictly to this schema:
{
  "classification": "<malicious|benign|uncertain>",
  "confidence": "<low|medium|high>",
  "summary": "<1-2 sentence concise overview>",
  "reasoning": "<1-2 sentence concise reasoning from evidence>",
  "estimated_severity": "<low|medium|high|critical>",
  "estimated_risk_score": <0-100 integer, clearly an LLM estimate>,
  "mitre_techniques": ["<technique if clearly evidenced, else empty list>"],
  "recommendations": ["<action 1>", "..."],
  "uncertainty_reasons": ["<reason>", "..."]
}

Strict Rules:
- classification MUST be exactly one of: "malicious", "benign", or "uncertain".
- estimated_risk_score is your estimate ONLY — it is NOT authoritative.
- Return ONLY the raw JSON object. Do not wrap in markdown or include conversational text.
"""


def _build_event_prompt(enriched: ContextEnrichedEvent) -> str:
    """Build a prompt from an enriched event without rule findings."""
    event = getattr(enriched, "event", {})
    if not isinstance(event, dict):
        event = {}

    asset = getattr(enriched, "asset_context", None)
    user = getattr(enriched, "user_context", None)
    threat = getattr(enriched, "threat_context", None)
    mitre = getattr(enriched, "mitre_attack", None)

    source_platform = safe_str(event.get("source_platform"), default="unknown")
    event_type = safe_str(event.get("event_type"), default="unknown")
    timestamp = safe_str(event.get("timestamp"), default="unknown")
    action = safe_str(event.get("action"), default="unknown")
    message = safe_str(event.get("message"), default="not available", max_len=300)

    lines = [
        "=== [EVENT CONTEXT] ===",
        f"Source Platform : {source_platform}",
        f"Event Type      : {event_type}",
        f"Timestamp       : {timestamp}",
        f"Action          : {action}",
        f"Message         : {message}",
    ]

    src = safe_dict(event.get("source"))
    dst = safe_dict(event.get("destination"))
    if src.get("ip"):
        lines.append(f"Source IP       : {safe_str(src['ip'])}")
    if dst.get("ip"):
        lines.append(f"Destination IP  : {safe_str(dst['ip'])}")
    if src.get("port") is not None:
        lines.append(f"Source Port     : {safe_str(src['port'])}")
    if dst.get("port") is not None:
        lines.append(f"Destination Port: {safe_str(dst['port'])}")

    usr_evt = safe_dict(event.get("user"))
    if usr_evt.get("name"):
        lines.append(f"Event User      : {safe_str(usr_evt['name'])}")

    proc_evt = safe_dict(event.get("process"))
    if proc_evt.get("name"):
        lines.append(f"Process Name    : {safe_str(proc_evt['name'])}")

    lines.append("")
    lines.append("=== [ASSET CONTEXT] ===")
    lines.append(f"Asset Criticality : {safe_str(getattr(asset, 'criticality', None), default='unknown')}")
    lines.append(f"Asset Type        : {safe_str(getattr(asset, 'asset_type', None), default='unknown')}")
    lines.append(f"Hostname          : {safe_str(getattr(asset, 'hostname', None), default='unknown')}")

    lines.append("")
    lines.append("=== [USER CONTEXT] ===")
    lines.append(f"Username          : {safe_str(getattr(user, 'username', None), default='unknown')}")
    lines.append(f"Privilege Level   : {safe_str(getattr(user, 'privilege_level', None), default='unknown')}")

    ioc_matches = getattr(threat, "ioc_matches", None)
    if isinstance(ioc_matches, list) and ioc_matches:
        lines.append("")
        lines.append("=== [THREAT INDICATORS] ===")
        for ioc in ioc_matches[:5]:
            lines.append(f"  IOC: {safe_str(ioc)}")

    techniques = getattr(mitre, "techniques", None)
    if isinstance(techniques, list) and techniques:
        lines.append("")
        lines.append("=== [L2 MITRE HINTS] ===")
        for t in techniques[:3]:
            lines.append(f"  {safe_str(t)}")

    lines.append("")
    lines.append("=== [INSTRUCTIONS] ===")
    lines.append("Analyze this event and provide your assessment as JSON.")
    lines.append(
        "NOTE: No deterministic rule engine has been run. This is a pure LLM assessment."
    )

    return "\n".join(lines)


def run(
    normalized_events: list[dict[str, Any]],
    llm_client: OpenRouterClient | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Run LLM-Only configuration.

    Returns (results, errors).
    """
    errors: list[str] = []
    results: list[dict[str, Any]] = []
    client = llm_client or OpenRouterClient()

    # Step 1: L2 enrichment
    try:
        enriched_list = [enrich_event(e) for e in normalized_events]
    except Exception as exc:
        err = f"[llm_only] L2 enrichment failed: {exc}"
        logger.exception(err)
        errors.append(err)
        return [], errors

    # Step 2: LLM analysis per event (no rule findings, no RAG)
    for event, enriched in zip(normalized_events, enriched_list):
        event_id = str(event.get("event_id", "")) if isinstance(event, dict) else ""
        t0 = time.perf_counter()
        try:
            prompt = _build_event_prompt(enriched)
            raw_text = client.complete(
                system_prompt=_SYSTEM_PROMPT,
                user_prompt=prompt,
                temperature=0.1,
                max_tokens=OPENROUTER_MAX_TOKENS,
                validator=validate_evaluation_response,
            )
            parsed = validate_evaluation_response(raw_text)
            latency_ms = (time.perf_counter() - t0) * 1000

            results.append(
                {
                    "event_id": event_id,
                    "status": "completed",
                    "alert_fired": parsed.get("classification") == "malicious",
                    "rule_ids_fired": [],
                    "rule_names_fired": [],
                    "risk_score": parsed.get("estimated_risk_score"),
                    "risk_level": parsed.get("estimated_severity"),
                    "risk_score_source": "llm_estimate",
                    "llm_summary": parsed.get("summary", ""),
                    "llm_reasoning": parsed.get("reasoning", ""),
                    "llm_status": "available",
                    "llm_model": client.model,
                    "llm_recommendation": parsed.get("recommendations", []),
                    "mitre_technique_id": (
                        parsed.get("mitre_techniques", [None])[0]
                        if parsed.get("mitre_techniques")
                        else None
                    ),
                    "latency_ms": latency_ms,
                    "raw_output": parsed,
                }
            )
        except LLMUnavailableError as exc:
            latency_ms = (time.perf_counter() - t0) * 1000
            err = f"[llm_only] LLM unavailable for event {event_id}: {exc}"
            logger.warning(err)
            errors.append(err)
            results.append(
                {
                    "event_id": event_id,
                    "status": "failed",
                    "alert_fired": False,
                    "rule_ids_fired": [],
                    "rule_names_fired": [],
                    "risk_score": None,
                    "risk_level": None,
                    "risk_score_source": "none",
                    "llm_status": "unavailable",
                    "llm_model": client.model,
                    "latency_ms": latency_ms,
                    "error": str(exc),
                    "raw_output": {},
                }
            )
        except Exception as exc:
            latency_ms = (time.perf_counter() - t0) * 1000
            err = f"[llm_only] Unexpected error for event {event_id}: {exc}"
            logger.exception(err)
            errors.append(err)
            results.append(
                {
                    "event_id": event_id,
                    "status": "failed",
                    "alert_fired": False,
                    "rule_ids_fired": [],
                    "rule_names_fired": [],
                    "risk_score": None,
                    "risk_level": None,
                    "risk_score_source": "none",
                    "llm_status": "failed",
                    "llm_model": getattr(client, "model", None),
                    "latency_ms": latency_ms,
                    "error": str(exc),
                    "raw_output": {},
                }
            )

    return results, errors
