"""Regression tests for the end-to-end integrated pipeline.

Covers:
- Schema adaptation from Part 2 -> L3.
- End-to-end pipeline execution (L1 -> L2 -> Part 2 -> Retrieval -> L3).
- Risk score preservation invariant.
- XAI deterministic generation.
- Judge hallucination validation.
- Graceful degradation when LLM is unavailable.
"""

from __future__ import annotations

import pytest

from integration.part2_to_l3 import to_l3_assessment
from l2.models import ContextEnrichedEvent
from l3.models.schemas import (
    FinalSecurityAssessment,
    FinalStatus,
    LLMAnalysis,
    LLMStatus,
    ModelMetadata,
    UncertaintyBlock,
    UncertaintyLevel,
    ValidationStatus,
)
from l3.orchestrator import Part3Orchestrator
from l3.validation.judge import Judge
from part2.models.security_alert import SecurityAlert
from part2.models.security_assessment import (
    RiskAssessment,
    SecurityAssessment as Part2SecurityAssessment,
)
from pipeline.orchestrator import run_pipeline


@pytest.fixture
def sample_part2_assessment() -> Part2SecurityAssessment:
    """Fixture providing a well-formed Part 2 assessment."""
    alert = SecurityAlert(
        alert_id="ALT-TEST-001",
        event_ids=["evt-001"],
        rule_id="AUTH-001",
        rule_name="Multiple Failed Authentication Attempts",
        severity="high",
        confidence=0.90,
        mitre_attack={"technique_id": "T1110", "technique_name": "Brute Force"},
        asset_context={"hostname": "web-prod-01", "criticality": "High"},
        user_context={"username": "admin", "privilege_level": "Root"},
        threat_context={"ioc_matches": ["185.20.10.1"]},
        evidence=[
            {
                "event_type": "authentication_failure",
                "source_ip": "185.20.10.1",
                "destination_ip": "10.0.0.5",
                "message": "Failed password for admin",
            }
        ],
        triggered_conditions=[
            {
                "field": "event.event_type",
                "operator": "equals",
                "expected": "authentication_failure",
            }
        ],
        timestamp="2026-09-04T12:00:00Z",
    )
    risk = RiskAssessment(
        score=78.5,
        level="critical",
        factors=[
            {"factor": "severity", "contribution": 35.0},
            {"factor": "asset_criticality", "contribution": 20.0},
        ],
    )
    return Part2SecurityAssessment(
        alert=alert,
        risk=risk,
        evidence=alert.evidence,
        mitre_attack=alert.mitre_attack,
    )


class TestIntegrationAdapter:
    def test_part2_to_l3_schema_conversion(
        self, sample_part2_assessment: Part2SecurityAssessment
    ):
        l3_input = to_l3_assessment(sample_part2_assessment)
        assert l3_input.alert_id == "ALT-TEST-001"
        assert l3_input.alert.rule_id == "AUTH-001"
        assert l3_input.risk.score == 78.5
        assert l3_input.risk.level == "critical"
        assert l3_input.mitre.technique_id == "T1110"
        assert isinstance(l3_input.retrieved_cti, list)

    def test_risk_score_preserved_invariant(
        self, sample_part2_assessment: Part2SecurityAssessment
    ):
        l3_input = to_l3_assessment(sample_part2_assessment)
        orchestrator = Part3Orchestrator()
        result: FinalSecurityAssessment = orchestrator.analyze(l3_input)

        # Invariant: deterministic risk score must NEVER change
        assert result.security_assessment.risk.score == 78.5
        assert result.security_assessment.risk.level == "critical"
        assert "78.5" in result.explanation.why_risk

    def test_xai_runs_without_llm(
        self, sample_part2_assessment: Part2SecurityAssessment
    ):
        l3_input = to_l3_assessment(sample_part2_assessment)
        orchestrator = Part3Orchestrator()
        result = orchestrator.analyze(l3_input)

        assert result.explanation.why_alerted != ""
        assert result.explanation.why_risk != ""
        assert len(result.explanation.supporting_factors) > 0
        assert result.explanation.uncertainty != ""


class TestJudgeValidation:
    def test_judge_detects_invented_claims(
        self, sample_part2_assessment: Part2SecurityAssessment
    ):
        l3_input = to_l3_assessment(sample_part2_assessment)
        judge = Judge()

        # Synthetic LLM output that hallucinates a CVE and APT not in evidence
        hallucinated_analysis = LLMAnalysis(
            alert_id="ALT-TEST-001",
            summary="Attack attributed to Lazarus group via CVE-2023-38606 exploit.",
            reasoning="Observed C2 traffic matching APT28 infrastructure.",
            supporting_evidence=["185.20.10.1"],
            mitre_interpretation=[],
            uncertainty=UncertaintyBlock(level=UncertaintyLevel.HIGH, reasons=[]),
            analyst_recommendation=["Block IP 185.20.10.1"],
            possible_interpretations=["Targeted APT intrusion"],
            model_metadata=ModelMetadata(
                model="test-model", timestamp="2026-09-04T12:00:00Z"
            ),
        )

        val_result = judge.validate(hallucinated_analysis, l3_input)
        assert val_result.status == ValidationStatus.FAILED
        assert any("NO_UNSUPPORTED_CLAIMS" in issue for issue in val_result.issues)
        assert len(val_result.unsupported_claims) > 0


class TestEndToEndPipeline:
    def test_run_pipeline_without_llm(self):
        sample_events = [
            {
                "event_id": "evt-001",
                "timestamp": "2026-09-04T10:00:01Z",
                "source_platform": "wazuh",
                "source_type": "auth",
                "event_type": "authentication_failure",
                "action": "failed",
                "message": "sshd: Failed password for admin from 185.20.10.1",
                "source": {"ip": "185.20.10.1", "port": 48992},
                "destination": {"ip": "10.0.0.5", "port": 22},
                "user": {"name": "admin"},
            }
        ]

        result = run_pipeline(sample_events, run_llm=False)
        assert "stages" in result
        assert result["stages"]["l1"]["normalized_events"] == 1
        assert result["stages"]["l2"]["enriched_events"] == 1
        assert isinstance(result["assessments"], list)
        assert isinstance(result["final_assessments"], list)
