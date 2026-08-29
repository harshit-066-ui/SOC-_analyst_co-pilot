"""Evidence-grounded prompt builder for PART 3 LLM reasoning.

Design principles
-----------------
1. EVERY section in the prompt is explicitly labelled so the model can map
   its reasoning to a concrete evidence source.
2. Only data present in SecurityAssessment is included — the builder never
   synthesises facts or fills gaps with assumptions.
3. The instructions block explicitly prohibits the model from inventing:
     - IP reputation / geo-location
     - Attack attribution / threat actors
     - MITRE techniques not in the supplied mapping
     - CVEs not listed in evidence
     - Severity or risk scores
4. The expected output format is a strict JSON object matching LLMAnalysis.
"""

from __future__ import annotations

import json
from typing import Any

from l3.config import MAX_CTI_SNIPPETS, MAX_EVIDENCE_ITEM_CHARS
from l3.models.schemas import SecurityAssessment


# ---------------------------------------------------------------------------
# System prompt (constant, defines model behaviour)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a senior SOC analyst assistant.
Your role is to reason about a security alert using ONLY the evidence and context \
provided below. You must NOT invent or fabricate:
  - IP reputation, geo-location, or ASN information
  - Attack attribution or threat-actor names
  - MITRE ATT&CK techniques not present in the [MITRE MAPPING] section
  - CVE identifiers not present in [AVAILABLE EVIDENCE] or [RETRIEVED CTI]
  - Severity ratings or risk scores different from those in [RISK FACTORS]
  - Any claim that cannot be directly traced to the supplied data

If evidence for a claim is absent, explicitly state "Evidence unavailable for this \
assessment." Do not speculate.

You must respond with a single valid JSON object matching this exact schema:
{
  "summary": "<one or two sentence overview of the alert>",
  "reasoning": "<detailed step-by-step reasoning grounded in the evidence>",
  "supporting_evidence": ["<evidence item 1>", "..."],
  "mitre_interpretation": [
    {
      "technique_id": "<from supplied mapping>",
      "technique_name": "<from supplied mapping>",
      "relevance": "<how this technique relates to the event>",
      "evidence_basis": "<which evidence fields support this>"
    }
  ],
  "uncertainty": {
    "level": "<low|medium|high>",
    "reasons": ["<reason 1>", "..."]
  },
  "analyst_recommendation": ["<action 1>", "..."],
  "possible_interpretations": ["<alternative interpretation 1>", "..."]
}

Rules:
- uncertainty.level MUST be "high" when evidence is sparse or ambiguous.
- analyst_recommendation must contain at least one actionable item.
- Do not add any key outside the schema above.
- Do not include a risk score in your response.
"""


# ---------------------------------------------------------------------------
# User prompt builder
# ---------------------------------------------------------------------------


class PromptBuilder:
    """Constructs the structured user prompt payload from a SecurityAssessment."""

    def build(self, assessment: SecurityAssessment) -> str:
        """Return a fully-formed user prompt string.

        The prompt is divided into clearly separated sections so the model
        can attribute each claim to a specific evidence source.
        """
        sections: list[str] = [
            self._section_event(assessment),
            self._section_context(assessment),
            self._section_mitre(assessment),
            self._section_rule(assessment),
            self._section_risk_factors(assessment),
            self._section_cti(assessment),
            self._section_evidence(assessment),
            self._section_instructions(),
        ]
        return "\n\n".join(s for s in sections if s.strip())

    # ------------------------------------------------------------------
    # Individual sections
    # ------------------------------------------------------------------

    @staticmethod
    def _section_event(a: SecurityAssessment) -> str:
        lines = [
            "=== [EVENT] ===",
            f"Alert ID       : {a.alert_id}",
            f"Alert Name     : {a.alert.rule_name or 'N/A'}",
            f"Description    : {a.alert.description or 'N/A'}",
            f"Alert Severity : {a.alert.severity}",
            f"Timestamp      : {a.timestamp}",
        ]
        return "\n".join(lines)

    @staticmethod
    def _section_context(a: SecurityAssessment) -> str:
        ctx = a.event_context
        lines = [
            "=== [CONTEXT] ===",
            f"Source Platform    : {ctx.source_platform}",
            f"Event Type         : {ctx.event_type}",
            f"Source IP          : {ctx.source_ip or 'not available'}",
            f"Destination IP     : {ctx.destination_ip or 'not available'}",
            f"Source Port        : {ctx.source_port or 'not available'}",
            f"Destination Port   : {ctx.destination_port or 'not available'}",
            f"Hostname           : {ctx.hostname or 'not available'}",
            f"Username           : {ctx.username or 'not available'}",
            f"Process            : {ctx.process_name or 'not available'}",
            f"Protocol           : {ctx.protocol or 'not available'}",
            f"Action             : {ctx.action or 'not available'}",
            f"Message            : {ctx.message or 'not available'}",
        ]
        return "\n".join(lines)

    @staticmethod
    def _section_mitre(a: SecurityAssessment) -> str:
        m = a.mitre
        if not m.technique_id and not m.tactic:
            return (
                "=== [MITRE MAPPING] ===\n"
                "No MITRE ATT&CK mapping was provided for this alert. "
                "Do NOT infer or assign techniques."
            )
        lines = [
            "=== [MITRE MAPPING] ===",
            f"Tactic         : {m.tactic or 'N/A'}",
            f"Technique ID   : {m.technique_id or 'N/A'}",
            f"Technique Name : {m.technique_name or 'N/A'}",
        ]
        if m.sub_technique:
            lines.append(f"Sub-technique  : {m.sub_technique}")
        lines.append(
            "IMPORTANT: Only reference the technique_id listed above. "
            "Do not add or invent additional techniques."
        )
        return "\n".join(lines)

    @staticmethod
    def _section_rule(a: SecurityAssessment) -> str:
        r = a.triggering_rule
        lines = [
            "=== [RULE RESULT] ===",
            f"Rule ID        : {r.id or 'N/A'}",
            f"Rule Name      : {r.name or 'N/A'}",
            f"Condition      : {r.condition or 'N/A'}",
        ]
        if r.threshold is not None:
            lines.append(f"Threshold      : {r.threshold}")
        return "\n".join(lines)

    @staticmethod
    def _section_risk_factors(a: SecurityAssessment) -> str:
        risk = a.risk
        lines = [
            "=== [RISK FACTORS] ===",
            f"Risk Score : {risk.score:.1f} / 100  (AUTHORITATIVE — do not change)",
            f"Risk Level : {risk.level}",
            "Factors    :",
        ]
        if risk.factors:
            for factor in risk.factors:
                lines.append(f"  • {factor}")
        else:
            lines.append("  (No specific factors recorded)")
        lines.append(
            "IMPORTANT: Do not alter, recompute, or contradict the risk score above."
        )
        return "\n".join(lines)

    @staticmethod
    def _section_cti(a: SecurityAssessment) -> str:
        snippets = a.retrieved_cti[:MAX_CTI_SNIPPETS]
        if not snippets:
            return (
                "=== [RETRIEVED CTI] ===\n"
                "No threat intelligence was retrieved for this alert. "
                "Do NOT invent CTI, threat actors, or CVEs."
            )
        lines = ["=== [RETRIEVED CTI] ==="]
        for idx, item in enumerate(snippets, 1):
            # Truncate each snippet to avoid token bloat
            text = json.dumps(item, ensure_ascii=False)[:MAX_EVIDENCE_ITEM_CHARS]
            lines.append(f"[CTI-{idx}] {text}")
        return "\n".join(lines)

    @staticmethod
    def _section_evidence(a: SecurityAssessment) -> str:
        if not a.evidence:
            return (
                "=== [AVAILABLE EVIDENCE] ===\n"
                "No structured evidence was provided. "
                "Uncertainty level MUST be 'high'."
            )
        lines = ["=== [AVAILABLE EVIDENCE] ==="]
        for idx, item in enumerate(a.evidence, 1):
            text = _truncate_evidence(item)
            lines.append(f"[E-{idx}] {text}")
        return "\n".join(lines)

    @staticmethod
    def _section_instructions() -> str:
        return (
            "=== [INSTRUCTIONS] ===\n"
            "Analyse the alert using ONLY the information in the sections above.\n"
            "- Your summary must be 1–2 sentences.\n"
            "- Your reasoning must cite specific evidence items by their label (e.g., [E-1]).\n"
            "- supporting_evidence must list verbatim field values from the evidence.\n"
            "- mitre_interpretation must only reference the technique_id from [MITRE MAPPING].\n"
            "- If a field above shows 'not available', do not assume a value for it.\n"
            "- Return ONLY the JSON object. No preamble, no trailing text.\n"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _truncate_evidence(item: Any) -> str:
    """Serialise an evidence item and truncate to avoid prompt bloat."""
    if isinstance(item, dict):
        text = json.dumps(item, ensure_ascii=False)
    else:
        text = str(item)
    if len(text) > MAX_EVIDENCE_ITEM_CHARS:
        text = text[: MAX_EVIDENCE_ITEM_CHARS] + "…(truncated)"
    return text
