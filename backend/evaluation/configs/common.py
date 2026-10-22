"""Common utilities, field normalizers, and response parsers for evaluation configs.

Provides:
- Null-safe, type-safe extraction of event and context fields.
- Robust, strictly validated JSON response parsing for LLM evaluations.
- Shared helpers to prevent malformed events from crashing evaluation runs.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Allowed classification values for binary/tri-state evaluation
ALLOWED_CLASSIFICATIONS = {"malicious", "benign", "uncertain"}
ALLOWED_CONFIDENCE_LEVELS = {"low", "medium", "high"}
ALLOWED_SEVERITY_LEVELS = {"low", "medium", "high", "critical"}


def safe_str(val: Any, default: str = "unknown", max_len: int | None = None) -> str:
    """Safely convert any value to string, handling None and optional truncation."""
    if val is None:
        return default
    s = str(val).strip()
    if not s:
        return default
    if max_len is not None and len(s) > max_len:
        return s[:max_len]
    return s


def safe_dict(val: Any) -> dict[str, Any]:
    """Ensure value is a dictionary; return empty dict if None or wrong type."""
    return val if isinstance(val, dict) else {}


def safe_list(val: Any) -> list[Any]:
    """Ensure value is a list; return empty list if None or wrong type."""
    return val if isinstance(val, list) else []


def extract_json_dict(raw_text: str) -> dict[str, Any]:
    """Extract a JSON object from raw LLM output text.

    Handles:
    - Stripping <think>...</think> reasoning tags (e.g. DeepSeek / reasoning models).
    - Markdown code fences (```json ... ``` or ``` ... ```).
    - Direct JSON string parsing.
    - Outermost matching curly braces { ... }.

    Raises
    ------
    ValueError
        If no valid JSON object can be found or parsed.
    """
    if not raw_text or not raw_text.strip():
        raise ValueError("LLM returned an empty response.")

    text = raw_text.strip()

    # 1. Strip reasoning / chain-of-thought tags
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    # 2. Markdown code fences (greedy or non-greedy block match)
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if fence_match:
        candidate = fence_match.group(1).strip()
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    # 3. Direct parse
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # 4. Outermost brace matching
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace > first_brace:
        candidate = text[first_brace : last_brace + 1].strip()
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"LLM response contains incomplete or invalid JSON: {exc} | Preview: {candidate[:150]}"
            ) from exc

    preview = text[:200].replace("\n", " ")
    raise ValueError(f"No valid JSON object found in LLM response: {preview}")


def validate_evaluation_response(raw_text: str) -> dict[str, Any]:
    """Strictly parse and validate an LLM evaluation response.

    Enforces required fields, allowed classification values, and clean types.
    Does NOT invent missing classifications or repair broken syntax by guessing.

    Raises
    ------
    ValueError
        If required fields are missing, invalid, or corrupted.
    """
    data = extract_json_dict(raw_text)

    # 1. Validate required 'classification'
    raw_cls = data.get("classification")
    if raw_cls is None:
        raise ValueError("Missing required field 'classification' in LLM response.")
    classification = str(raw_cls).strip().lower()
    if classification not in ALLOWED_CLASSIFICATIONS:
        raise ValueError(
            f"Invalid classification '{raw_cls}'. Expected one of {sorted(ALLOWED_CLASSIFICATIONS)}."
        )
    data["classification"] = classification

    # 2. Validate required 'summary'
    summary = data.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        raise ValueError("Missing or empty required field 'summary' in LLM response.")
    data["summary"] = summary.strip()

    # 3. Validate required 'reasoning'
    reasoning = data.get("reasoning")
    if not isinstance(reasoning, str) or not reasoning.strip():
        raise ValueError("Missing or empty required field 'reasoning' in LLM response.")
    data["reasoning"] = reasoning.strip()

    # 4. Validate confidence
    raw_conf = data.get("confidence")
    if raw_conf is not None:
        conf = str(raw_conf).strip().lower()
        data["confidence"] = conf if conf in ALLOWED_CONFIDENCE_LEVELS else "low"
    else:
        data["confidence"] = "low"

    # 5. Validate estimated_risk_score (optional float/int in [0, 100])
    raw_score = data.get("estimated_risk_score")
    if raw_score is not None:
        try:
            score_num = float(raw_score)
            if 0.0 <= score_num <= 100.0:
                data["estimated_risk_score"] = round(score_num, 1)
            else:
                data["estimated_risk_score"] = None
        except (ValueError, TypeError):
            data["estimated_risk_score"] = None
    else:
        data["estimated_risk_score"] = None

    # 6. Validate estimated_severity
    raw_sev = data.get("estimated_severity")
    if raw_sev is not None:
        sev = str(raw_sev).strip().lower()
        data["estimated_severity"] = sev if sev in ALLOWED_SEVERITY_LEVELS else None
    else:
        data["estimated_severity"] = None

    # 7. Lists: mitre_techniques, recommendations, uncertainty_reasons
    data["mitre_techniques"] = [
        str(t).strip()
        for t in safe_list(data.get("mitre_techniques"))
        if str(t).strip()
    ]
    data["recommendations"] = [
        str(r).strip()
        for r in safe_list(data.get("recommendations"))
        if str(r).strip()
    ]
    data["uncertainty_reasons"] = [
        str(u).strip()
        for u in safe_list(data.get("uncertainty_reasons"))
        if str(u).strip()
    ]

    return data
