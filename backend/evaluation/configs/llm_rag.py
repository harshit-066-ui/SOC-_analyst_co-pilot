"""Configuration C — LLM + RAG.

Pipeline:  L2 enrichment → dense-vector RAG retrieval → LLM analysis
Disabled:  Rule engine, Risk scoring, Judge, XAI

RAG retrieval uses the existing BGE-M3 / Qdrant implementation.
Rule findings are withheld from the LLM prompt.
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

_SYSTEM_PROMPT = """\
You are a senior SOC analyst assistant reviewing a security event.
Analyze the event using the context and retrieved threat intelligence provided.
You have NOT been given deterministic rule-engine results or risk scores.
Do NOT invent:
  - threat actor names or CVE identifiers not present in the retrieved CTI
  - risk scores (any score is your estimate only and must be labelled as such)
  - MITRE techniques not evidenced in the data or CTI

Provide a concise, evidence-grounded assessment. Keep summary and reasoning to 1-2 sentences each.
Respond with ONLY a single valid JSON object adhering strictly to this schema:
{
  "classification": "<malicious|benign|uncertain>",
  "confidence": "<low|medium|high>",
  "summary": "<1-2 sentence concise overview>",
  "reasoning": "<1-2 sentence concise reasoning citing CTI items where relevant>",
  "estimated_severity": "<low|medium|high|critical>",
  "estimated_risk_score": <0-100 integer, clearly an LLM estimate>,
  "mitre_techniques": ["<technique if evidenced>"],
  "recommendations": ["<action 1>", "..."],
  "uncertainty_reasons": ["<reason>"],
  "cti_references_used": ["<title or ID of CTI items referenced>"]
}

Strict Rules:
- classification MUST be exactly one of: "malicious", "benign", or "uncertain".
- estimated_risk_score is your estimate ONLY — it is NOT authoritative.
- Return ONLY the raw JSON object. Do not wrap in markdown or include conversational commentary.
"""


def _retrieve_cti_for_event(
    event: dict[str, Any],
    enriched: ContextEnrichedEvent,
    top_k: int = 3,
) -> list[dict[str, Any]]:
    """Retrieve semantically relevant knowledge from Qdrant."""
    try:
        from vectorstore.retriever import retrieve_for_text

        parts: list[str] = []
        if isinstance(event, dict):
            if event.get("event_type"):
                parts.append(safe_str(event["event_type"]))
            msg = safe_str(event.get("message"), default="", max_len=200)
            if msg:
                parts.append(msg)
            src = safe_dict(event.get("source"))
            if src.get("ip"):
                parts.append(safe_str(src["ip"]))

        mitre = getattr(enriched, "mitre_attack", None)
        techniques = getattr(mitre, "techniques", [])
        if isinstance(techniques, list):
            for tech in techniques[:2]:
                parts.append(safe_str(tech))

        query = " ".join(parts) if parts else "security alert"
        hits = retrieve_for_text(query, top_k=top_k)
        results: list[dict[str, Any]] = []
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            payload = safe_dict(hit.get("payload"))
            results.append(
                {
                    "id": str(hit.get("id", "")),
                    "title": safe_str(payload.get("title")),
                    "source": safe_str(payload.get("source"), default="vectorstore"),
                    "score": float(hit.get("score", 0.0)),
                    "technique_id": safe_str(payload.get("technique_id"), default=""),
                    "snippet": safe_str(hit.get("text") or payload.get("text"), max_len=300),
                }
            )
        return results
    except Exception as exc:
        logger.warning("[llm_rag] RAG retrieval failed: %s", exc)
        return []


def _build_prompt(
    event: dict[str, Any],
    enriched: ContextEnrichedEvent,
    cti_hits: list[dict[str, Any]],
) -> str:
    if not isinstance(event, dict):
        event = {}

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

    asset = getattr(enriched, "asset_context", None)
    lines += [
        "",
        "=== [ASSET CONTEXT] ===",
        f"Asset Criticality : {safe_str(getattr(asset, 'criticality', None), default='unknown')}",
        f"Hostname          : {safe_str(getattr(asset, 'hostname', None), default='unknown')}",
    ]

    if cti_hits:
        lines += ["", "=== [RETRIEVED CTI] ==="]
        for i, hit in enumerate(cti_hits, 1):
            lines.append(
                f"[CTI-{i}] [{hit.get('title', 'unknown')}] "
                f"(score={hit.get('score', 0):.3f}) {hit.get('snippet', '')}"
            )
    else:
        lines += [
            "",
            "=== [RETRIEVED CTI] ===",
            "No CTI was retrieved for this event.",
        ]

    lines += [
        "",
        "=== [INSTRUCTIONS] ===",
        "Analyze this event using the context and CTI above. "
        "No deterministic rule engine has been run.",
        "Cite CTI items as [CTI-1], [CTI-2], etc. in your reasoning.",
    ]
    return "\n".join(lines)


def run(
    normalized_events: list[dict[str, Any]],
    llm_client: OpenRouterClient | None = None,
    rag_top_k: int = 3,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Run LLM + RAG configuration. Returns (results, errors)."""
    errors: list[str] = []
    results: list[dict[str, Any]] = []
    client = llm_client or OpenRouterClient()

    # L2 enrichment
    try:
        enriched_list = [enrich_event(e) for e in normalized_events]
    except Exception as exc:
        err = f"[llm_rag] L2 enrichment failed: {exc}"
        logger.exception(err)
        errors.append(err)
        return [], errors

    for event, enriched in zip(normalized_events, enriched_list):
        event_id = str(event.get("event_id", "")) if isinstance(event, dict) else ""
        t0 = time.perf_counter()
        try:
            cti_hits = _retrieve_cti_for_event(event, enriched, top_k=rag_top_k)
            rag_available = len(cti_hits) > 0

            prompt = _build_prompt(event, enriched, cti_hits)
            raw_text = client.complete(
                system_prompt=_SYSTEM_PROMPT,
                user_prompt=prompt,
                temperature=0.1,
                max_tokens=OPENROUTER_MAX_TOKENS,
                validator=validate_evaluation_response,
            )
            parsed = validate_evaluation_response(raw_text)
            latency_ms = (time.perf_counter() - t0) * 1000

            retrieved_evidence = [
                {
                    "doc_id": h.get("id", ""),
                    "title": h.get("title", ""),
                    "source": h.get("source", ""),
                    "score": h.get("score", 0.0),
                    "technique_id": h.get("technique_id", ""),
                    "snippet": h.get("snippet", ""),
                }
                for h in cti_hits
            ]

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
                    "retrieved_evidence": retrieved_evidence,
                    "rag_available": rag_available,
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
            err = f"[llm_rag] LLM unavailable for event {event_id}: {exc}"
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
            err = f"[llm_rag] Error for event {event_id}: {exc}"
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
