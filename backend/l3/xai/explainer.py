"""XAI Explanation generator — produces analyst-readable explanations.

Design principles
-----------------
- Reads ONLY from SecurityAssessment (PART 2 deterministic data).
- Never reads from LLMAnalysis — XAI is grounded in deterministic facts.
- Works correctly even when the LLM is unavailable.
- Every sentence is explicitly linked to a field in SecurityAssessment.
- Absent data is reported honestly ("not available") rather than inferred.

Explanation structure produced
-------------------------------
  WHY WAS THIS ALERT GENERATED?   → why_alerted
  WHY DID IT RECEIVE THIS RISK SCORE? → why_risk
  WHAT EVIDENCE SUPPORTS IT?      → supporting_factors
  WHAT CONTEXT INFLUENCED IT?     → context_influences
  WHAT IS UNCERTAIN?              → uncertainty
  MITRE ATT&CK CONTEXT            → mitre_context
  EVIDENCE SUMMARY                → evidence_summary
"""

from __future__ import annotations

from l3.models.schemas import SecurityAssessment, XAIExplanation


class Explainer:
    """Generates a deterministic, evidence-grounded XAI explanation."""

    def explain(self, assessment: SecurityAssessment) -> XAIExplanation:
        """Build the full XAI explanation from the SecurityAssessment.

        All text is constructed from assessment fields only — no LLM, no
        fabrication.
        """
        return XAIExplanation(
            why_alerted=self._why_alerted(assessment),
            why_risk=self._why_risk(assessment),
            supporting_factors=self._supporting_factors(assessment),
            context_influences=self._context_influences(assessment),
            uncertainty=self._uncertainty(assessment),
            mitre_context=self._mitre_context(assessment),
            evidence_summary=self._evidence_summary(assessment),
        )

    # ------------------------------------------------------------------
    # Section builders — each method is pure and independently testable
    # ------------------------------------------------------------------

    @staticmethod
    def _why_alerted(a: SecurityAssessment) -> str:
        """Explain why the triggering rule fired."""
        rule = a.triggering_rule
        alert = a.alert

        parts: list[str] = []

        rule_name = rule.name or alert.rule_name or "an unnamed rule"
        parts.append(f"This alert was generated because rule '{rule_name}' matched the incoming event.")

        if rule.condition:
            parts.append(f"The rule condition evaluated as: {rule.condition}.")

        if rule.threshold is not None:
            parts.append(f"The configured detection threshold was: {rule.threshold}.")

        if alert.description:
            parts.append(f"Alert description: {alert.description}.")

        if not any([rule.name, rule.condition, alert.description]):
            parts.append(
                "No detailed rule condition was available in the assessment."
            )

        return " ".join(parts)

    @staticmethod
    def _why_risk(a: SecurityAssessment) -> str:
        """Explain the deterministic risk score from PART 2."""
        risk = a.risk
        parts: list[str] = [
            f"The deterministic risk score is {risk.score:.1f}/100 (level: {risk.level}), "
            f"calculated by PART 2 using the rule engine."
        ]

        if risk.factors:
            parts.append(
                "The following factors contributed to this score: "
                + "; ".join(f"'{f}'" for f in risk.factors)
                + "."
            )
        else:
            parts.append(
                "No specific risk factor breakdown was provided in this assessment."
            )

        parts.append(
            "This score is authoritative and has not been modified by the LLM reasoning layer."
        )
        return " ".join(parts)

    @staticmethod
    def _supporting_factors(a: SecurityAssessment) -> list[str]:
        """Extract concrete supporting data points from the assessment."""
        factors: list[str] = []
        ctx = a.event_context

        if ctx.source_ip:
            factors.append(f"Source IP observed: {ctx.source_ip}")
        if ctx.destination_ip:
            factors.append(f"Destination IP: {ctx.destination_ip}")
        if ctx.source_port or ctx.destination_port:
            factors.append(
                f"Network ports — source: {ctx.source_port or 'N/A'}, "
                f"destination: {ctx.destination_port or 'N/A'}"
            )
        if ctx.username:
            factors.append(f"Associated username: {ctx.username}")
        if ctx.process_name:
            factors.append(f"Associated process: {ctx.process_name}")
        if ctx.action:
            factors.append(f"Observed action: {ctx.action}")
        if ctx.protocol:
            factors.append(f"Network protocol: {ctx.protocol}")
        if a.alert.severity:
            factors.append(f"Alert severity label: {a.alert.severity}")
        if a.risk.factors:
            for rf in a.risk.factors:
                factors.append(f"Risk factor: {rf}")
        if a.evidence:
            factors.append(
                f"{len(a.evidence)} structured evidence item(s) attached to this assessment."
            )
        if not factors:
            factors.append(
                "No structured supporting factors were available in the assessment."
            )
        return factors

    @staticmethod
    def _context_influences(a: SecurityAssessment) -> list[str]:
        """Identify context fields that influenced the analysis."""
        influences: list[str] = []
        ctx = a.event_context

        influences.append(
            f"Source platform: {ctx.source_platform} "
            f"(event type: {ctx.event_type})"
        )

        if ctx.hostname:
            influences.append(f"Originating host: {ctx.hostname}")

        if ctx.message:
            preview = ctx.message[:120] + ("…" if len(ctx.message) > 120 else "")
            influences.append(f"Raw log message preview: \"{preview}\"")

        if a.retrieved_cti:
            influences.append(
                f"{len(a.retrieved_cti)} threat intelligence snippet(s) were "
                "retrieved and provided to the LLM for context."
            )
        else:
            influences.append(
                "No threat intelligence was retrieved for this alert — "
                "CTI context was absent."
            )

        return influences

    @staticmethod
    def _uncertainty(a: SecurityAssessment) -> str:
        """Characterise uncertainty based on evidence completeness."""
        evidence_count = len(a.evidence)
        ctx = a.event_context

        missing: list[str] = []
        if not ctx.source_ip:
            missing.append("source IP")
        if not ctx.destination_ip:
            missing.append("destination IP")
        if not ctx.username:
            missing.append("username")
        if not ctx.process_name:
            missing.append("process name")

        if evidence_count == 0 and missing:
            return (
                f"Uncertainty is HIGH. No structured evidence was provided and "
                f"the following context fields were absent: {', '.join(missing)}. "
                "The analysis relies only on the rule match and event metadata."
            )
        if evidence_count < 3 or missing:
            field_note = (
                f" Missing context fields: {', '.join(missing)}." if missing else ""
            )
            return (
                f"Uncertainty is MEDIUM. Only {evidence_count} evidence item(s) "
                f"were available.{field_note} "
                "Additional investigation is recommended."
            )
        return (
            f"Uncertainty is LOW. {evidence_count} evidence item(s) were available "
            "with sufficient context to support analysis."
        )

    @staticmethod
    def _mitre_context(a: SecurityAssessment) -> str:
        """Provide a grounded MITRE ATT&CK context statement."""
        m = a.mitre
        if not m.technique_id and not m.tactic:
            return (
                "No MITRE ATT&CK mapping was associated with this alert by PART 2. "
                "The LLM was instructed not to infer techniques."
            )
        parts = [
            f"PART 2 mapped this alert to MITRE ATT&CK technique "
            f"{m.technique_id} — {m.technique_name}"
        ]
        if m.tactic:
            parts.append(f"under the '{m.tactic}' tactic")
        if m.sub_technique:
            parts.append(f"(sub-technique: {m.sub_technique})")
        parts.append(
            ". The LLM reasoning was constrained to interpret only this mapping."
        )
        return " ".join(parts) + "."

    @staticmethod
    def _evidence_summary(a: SecurityAssessment) -> str:
        """Summarise the evidence available to the analysis."""
        count = len(a.evidence)
        cti_count = len(a.retrieved_cti)

        if count == 0 and cti_count == 0:
            return (
                "No structured evidence or threat intelligence was provided. "
                "The analysis is based solely on the normalised event fields "
                "and rule match result."
            )

        parts = []
        if count > 0:
            parts.append(
                f"{count} structured evidence item(s) from PART 2 were included "
                "in the LLM prompt."
            )
        if cti_count > 0:
            parts.append(
                f"{cti_count} threat intelligence snippet(s) were provided for context."
            )
        return " ".join(parts)
