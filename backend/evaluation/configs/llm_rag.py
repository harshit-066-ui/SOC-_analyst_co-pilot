"""Configuration C — LLM + RAG.

Pipeline:  L2 enrichment → dense-vector RAG retrieval → LLM analysis
Disabled:  Rule engine, Risk scoring, Judge, XAI

RAG retrieval uses the existing BGE-M3 / Qdrant implementation.
Rule findings are withheld from the LLM prompt.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from l2.enricher import enrich_event
from l2.models import ContextEnrichedEvent
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

Respond with a single valid JSON object:
{
  "classification": "<malicious|benign|uncertain>",
  "confidence": "<low|medium|high>",
  "summary": "<1-2 sentence overview>",
  "reasoning": "<step-by-step reasoning citing CTI items where relevant>",
  "estimated_severity": "<low|medium|high|critical>",
  "estimated_risk_score": <0-100 integer, clearly an LLM estimate>,
  "mitre_techniques": ["<technique if evidenced>"],
  "recommendations": ["<action 1>", "..."],
  "uncertainty_reasons": ["<reason>"],
  "cti_references_used": ["<title or ID of CTI items referenced>"]
}
Return ONLY the JSON object.
"""


def _retrieve_cti_for_event(
    event: dict[str, Any],
    enriched: ContextEnrichedEvent,
    top_k: int = 3,
) -> list[dict[str, Any]]:
    """Retrieve semantically relevant knowledge from Qdrant."""
    try:
        from vectorstore.retriever import retrieve_for_text
        from embeddings.text_builder import alert_to_text

        # Build a query text from the event's key fields
        parts: list[str] = []
        if event.get("event_type"):
            parts.append(event["event_type"])
        if event.get("message"):
            parts.append(str(event["message"])[:200])
        if event.get("source", {}).get("ip"):
            parts.append(event["source"]["ip"])
        mitre = enriched.mitre_attack
        for tech in getattr(mitre, "techniques", [])[:2]:
            parts.append(str(tech))

        query = " ".join(parts) if parts else "security alert"
        hits = retrieve_for_text(query, top_k=top_k)
        results: list[dict[str, Any]] = []
        for hit in hits:
            payload = hit.get("payload", {})
            results.append(
                {
                    "id": str(hit.get("id", "")),
                    "title": payload.get("title", ""),
                    "source": payload.get("source", "vectorstore"),
                    "score": hit.get("score", 0.0),
                    "technique_id": payload.get("technique_id", ""),
                    "snippet": (hit.get("text") or payload.get("text", ""))[:300],
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
    lines = [
        "=== [EVENT CONTEXT] ===",
        f"Source Platform : {event.get('source_platform', 'unknown')}",
        f"Event Type      : {event.get('event_type', 'unknown')}",
        f"Timestamp       : {event.get('timestamp', 'unknown')}",
        f"Action          : {event.get('action', 'unknown')}",
        f"Message         : {str(event.get('message', 'not available'))[:300]}",
    ]
    src = event.get("source", {})
    dst = event.get("destination", {})
    if src.get("ip"):
        lines.append(f"Source IP       : {src['ip']}")
    if dst.get("ip"):
        lines.append(f"Destination IP  : {dst['ip']}")

    asset = enriched.asset_context
    lines += [
        "",
        "=== [ASSET CONTEXT] ===",
        f"Asset Criticality : {getattr(asset, 'criticality', 'unknown')}",
        f"Hostname          : {getattr(asset, 'hostname', 'unknown')}",
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


def _parse_llm_response(raw_text: str) -> dict[str, Any]:
    text = raw_text.strip()
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    fb, lb = text.find("{"), text.rfind("}")
    if fb != -1 and lb > fb:
        try:
            obj = json.loads(text[fb : lb + 1])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    raise ValueError(f"No valid JSON in LLM response: {text[:200]}")


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
        event_id = str(event.get("event_id", ""))
        t0 = time.perf_counter()
        try:
            cti_hits = _retrieve_cti_for_event(event, enriched, top_k=rag_top_k)
            rag_available = len(cti_hits) > 0

            prompt = _build_prompt(event, enriched, cti_hits)
            raw_text = client.complete(
                system_prompt=_SYSTEM_PROMPT,
                user_prompt=prompt,
                temperature=0.1,
                max_tokens=1024,
            )
            parsed = _parse_llm_response(raw_text)
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
                    "alert_fired": False,
                    "risk_score": None,
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
                    "alert_fired": False,
                    "risk_score": None,
                    "risk_score_source": "none",
                    "llm_status": "partial",
                    "latency_ms": latency_ms,
                    "error": str(exc),
                    "raw_output": {},
                }
            )

    return results, errors
