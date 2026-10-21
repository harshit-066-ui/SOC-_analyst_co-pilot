"""Configuration B — LLM Only.

Pipeline:  L2 enrichment → LLM direct analysis (no rule findings, no RAG)
Disabled:  Rule engine, Risk scoring, RAG, Judge, XAI

The LLM receives the enriched event context but NOT Part 2 rule findings.
Any risk estimate is clearly labelled as LLM-derived, not authoritative.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from typing import Any

from l2.enricher import enrich_event
from l2.models import ContextEnrichedEvent
from l3.reasoning.openrouter_client import LLMUnavailableError, OpenRouterClient
from l3.config import OPENROUTER_MODEL

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

Respond with a single valid JSON object:
{
  "classification": "<malicious|benign|uncertain>",
  "confidence": "<low|medium|high>",
  "summary": "<1-2 sentence overview>",
  "reasoning": "<step-by-step reasoning from evidence>",
  "estimated_severity": "<low|medium|high|critical>",
  "estimated_risk_score": <0-100 integer, clearly an LLM estimate>,
  "mitre_techniques": ["<technique if clearly evidenced, else empty list>"],
  "recommendations": ["<action 1>", "..."],
  "uncertainty_reasons": ["<reason>", "..."]
}
Rules:
- estimated_risk_score is your estimate ONLY — it is NOT authoritative.
- Return ONLY the JSON object.
"""


def _build_event_prompt(enriched: ContextEnrichedEvent) -> str:
    """Build a prompt from an enriched event without rule findings."""
    event = enriched.event
    entities = enriched.entities
    asset = enriched.asset_context
    user = enriched.user_context
    threat = enriched.threat_context
    mitre = enriched.mitre_attack

    lines = [
        "=== [EVENT CONTEXT] ===",
        f"Source Platform : {event.get('source_platform', 'unknown')}",
        f"Event Type      : {event.get('event_type', 'unknown')}",
        f"Timestamp       : {event.get('timestamp', 'unknown')}",
        f"Action          : {event.get('action', 'unknown')}",
        f"Message         : {event.get('message', 'not available')[:300]}",
    ]
    src = event.get("source", {})
    dst = event.get("destination", {})
    if src.get("ip"):
        lines.append(f"Source IP       : {src['ip']}")
    if dst.get("ip"):
        lines.append(f"Destination IP  : {dst['ip']}")
    if src.get("port"):
        lines.append(f"Source Port     : {src['port']}")
    if dst.get("port"):
        lines.append(f"Destination Port: {dst['port']}")

    lines.append("")
    lines.append("=== [ASSET CONTEXT] ===")
    lines.append(f"Asset Criticality : {getattr(asset, 'criticality', 'unknown')}")
    lines.append(f"Asset Type        : {getattr(asset, 'asset_type', 'unknown')}")
    lines.append(f"Hostname          : {getattr(asset, 'hostname', 'unknown')}")

    lines.append("")
    lines.append("=== [USER CONTEXT] ===")
    lines.append(f"Username          : {getattr(user, 'username', 'unknown')}")
    lines.append(f"Privilege Level   : {getattr(user, 'privilege_level', 'unknown')}")

    if getattr(threat, "ioc_matches", None):
        lines.append("")
        lines.append("=== [THREAT INDICATORS] ===")
        for ioc in threat.ioc_matches[:5]:
            lines.append(f"  IOC: {ioc}")

    if getattr(mitre, "techniques", None):
        lines.append("")
        lines.append("=== [L2 MITRE HINTS] ===")
        for t in mitre.techniques[:3]:
            lines.append(f"  {t}")

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
        event_id = str(event.get("event_id", ""))
        t0 = time.perf_counter()
        try:
            prompt = _build_event_prompt(enriched)
            raw_text = client.complete(
                system_prompt=_SYSTEM_PROMPT,
                user_prompt=prompt,
                temperature=0.1,
                max_tokens=1024,
            )
            parsed = _parse_llm_response(raw_text)
            latency_ms = (time.perf_counter() - t0) * 1000

            results.append(
                {
                    "event_id": event_id,
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
                    "alert_fired": False,
                    "rule_ids_fired": [],
                    "rule_names_fired": [],
                    "risk_score": None,
                    "risk_level": None,
                    "risk_score_source": "none",
                    "llm_status": "partial",
                    "latency_ms": latency_ms,
                    "error": str(exc),
                    "raw_output": {},
                }
            )

    return results, errors


def _parse_llm_response(raw_text: str) -> dict[str, Any]:
    """Extract JSON from LLM response with fallback heuristics."""
    import re
    text = raw_text.strip()
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    # Markdown fence
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass

    # Direct parse
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass

    # Brace fallback
    fb = text.find("{")
    lb = text.rfind("}")
    if fb != -1 and lb > fb:
        try:
            obj = json.loads(text[fb : lb + 1])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    raise ValueError(f"No valid JSON found in LLM response: {text[:200]}")
