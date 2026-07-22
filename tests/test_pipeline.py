from __future__ import annotations

import unittest
from pathlib import Path

from agentsec.contracts import (
    AiMode,
    DecisionAction,
    EscalationLevel,
    ModelVerdict,
    PipelineStage,
    ResponseAction,
)
from agentsec.pipeline import SecurityPipeline
from agentsec.reasoning import ModelUnavailableError, RecordedCodexReasoner
from agentsec.scenarios import forge_scenarios
from agentsec.workflow import Judge, Triager


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scenarios = forge_scenarios()

    def test_benign_event_produces_no_security_alert(self) -> None:
        result = SecurityPipeline().process(self.scenarios["benign_inventory_read"])
        self.assertEqual(result.alerts, [])
        self.assertEqual(result.overall_action, DecisionAction.ALLOW)
        self.assertTrue(result.effect_allowed)

    def test_secret_egress_runs_complete_lifecycle_and_is_blocked(self) -> None:
        pipeline = SecurityPipeline()
        result = pipeline.process(self.scenarios["indirect_injection_secret_egress"])
        secret_alert = next(
            item for item in result.alerts if item.alert.alert_type == "secret_egress"
        )

        self.assertEqual(
            [entry.stage for entry in secret_alert.timeline],
            [
                PipelineStage.DETECTION,
                PipelineStage.INGESTION,
                PipelineStage.TRIAGE,
                PipelineStage.JUDGMENT,
                PipelineStage.ESCALATION,
                PipelineStage.RESPONSE,
            ],
        )
        self.assertEqual(secret_alert.judgment.action, DecisionAction.DENY)
        self.assertEqual(secret_alert.escalation.level, EscalationLevel.INCIDENT_PAGE)
        self.assertFalse(secret_alert.response.effect_allowed)
        self.assertIn(ResponseAction.BLOCK_EFFECT, secret_alert.response.actions)
        self.assertTrue(secret_alert.response.simulated)
        self.assertTrue(pipeline.ledger.verify())

    def test_multiple_findings_combine_to_most_restrictive_event_action(self) -> None:
        result = SecurityPipeline().process(
            self.scenarios["confused_deputy_authority_expansion"]
        )
        approval_finding = next(
            item
            for item in result.alerts
            if item.alert.alert_type == "destructive_action_without_approval"
        )

        self.assertEqual(result.overall_action, DecisionAction.DENY)
        self.assertFalse(result.effect_allowed)
        self.assertEqual(approval_finding.judgment.action, DecisionAction.DENY)
        self.assertIn(
            "EVENT_MOST_RESTRICTIVE_COMBINATION", approval_finding.judgment.reason_codes
        )

    def test_all_attack_families_are_detected_and_prevented(self) -> None:
        pipeline = SecurityPipeline()
        for name, event in self.scenarios.items():
            if name.startswith("benign_"):
                continue
            with self.subTest(scenario=name):
                result = pipeline.process(event)
                self.assertGreater(len(result.alerts), 0)
                self.assertTrue(
                    all(not item.response.effect_allowed for item in result.alerts),
                    "every detected malicious effect must be denied or held",
                )

    def test_ingestion_is_idempotent_for_same_alert_fingerprint(self) -> None:
        pipeline = SecurityPipeline()
        event = self.scenarios["mcp_schema_drift"]
        first = pipeline.process(event)
        count_after_first = pipeline.ledger.count
        second = pipeline.process(event)

        self.assertGreater(count_after_first, 0)
        self.assertEqual(pipeline.ledger.count, count_after_first)
        self.assertTrue(all(item.ingestion.duplicate for item in second.alerts))
        self.assertTrue(
            all(item.alert.alert_id == item.ingestion.alert_id for item in second.alerts)
        )
        self.assertTrue(pipeline.ledger.verify())

    def test_model_cannot_relax_deterministic_denial(self) -> None:
        event = self.scenarios["indirect_injection_secret_egress"]
        alert = next(
            alert
            for alert in SecurityPipeline().detector.detect(event)
            if alert.alert_type == "secret_egress"
        )
        triage = Triager().assess(alert)
        verdict = ModelVerdict(
            provider="codex",
            model_id="codex-current",
            action=DecisionAction.ALLOW,
            confidence=0.99,
            evidence_ids=[event.event_id],
            reason_codes=["MODEL_SUGGESTED_ALLOW"],
        )

        decision = Judge().decide(
            alert, triage, verdict, ai_mode=AiMode.SEMANTIC_HOLD
        )

        self.assertEqual(decision.action, DecisionAction.DENY)
        self.assertIn("MODEL_RELAXATION_REJECTED", decision.reason_codes)

    def test_model_can_tighten_approval_to_denial(self) -> None:
        event = self.scenarios["mcp_schema_drift"]
        alert = next(
            alert
            for alert in SecurityPipeline().detector.detect(event)
            if alert.alert_type == "mcp_schema_drift"
        )
        triage = Triager().assess(alert)
        verdict = ModelVerdict(
            provider="codex",
            model_id="codex-current",
            action=DecisionAction.DENY,
            confidence=0.98,
            evidence_ids=[event.event_id],
            reason_codes=["SEMANTIC_DESTINATION_MISMATCH"],
        )

        decision = Judge().decide(
            alert, triage, verdict, ai_mode=AiMode.SEMANTIC_HOLD
        )

        self.assertEqual(decision.deterministic_action, DecisionAction.REQUIRE_APPROVAL)
        self.assertEqual(decision.action, DecisionAction.DENY)
        self.assertIn("MODEL_TIGHTENED_DECISION", decision.reason_codes)

    def test_recorded_codex_verdict_runs_through_provider_contract(self) -> None:
        recording_path = Path("configs/codex-evaluation.json")
        reasoner = RecordedCodexReasoner.from_path(recording_path)
        pipeline = SecurityPipeline(reasoner=reasoner, ai_mode=AiMode.SEMANTIC_HOLD)

        result = pipeline.process(self.scenarios["mcp_schema_drift"])
        alert = next(item for item in result.alerts if item.alert.alert_type == "mcp_schema_drift")

        self.assertIsNotNone(alert.judgment.model_verdict)
        self.assertEqual(alert.judgment.model_verdict.provider, "codex")
        self.assertEqual(alert.judgment.action, DecisionAction.DENY)
        self.assertFalse(result.effect_allowed)

    def test_model_failure_preserves_deterministic_enforcement(self) -> None:
        class UnavailableReasoner:
            provider = "codex"
            model_id = "unavailable-test"

            def analyze(self, alert, triage):
                raise ModelUnavailableError("simulated model outage")

        result = SecurityPipeline(
            reasoner=UnavailableReasoner(), ai_mode=AiMode.SHADOW
        ).process(
            self.scenarios["indirect_injection_secret_egress"]
        )

        self.assertEqual(result.overall_action, DecisionAction.DENY)
        self.assertFalse(result.effect_allowed)
        self.assertTrue(
            any(
                entry.outcome == "model_unavailable_deterministic_fallback"
                for item in result.alerts
                for entry in item.timeline
            )
        )

    def test_codex_shadow_verdict_is_recorded_but_does_not_change_action(self) -> None:
        reasoner = RecordedCodexReasoner.from_path(Path("configs/codex-evaluation.json"))
        pipeline = SecurityPipeline(reasoner=reasoner, ai_mode=AiMode.SHADOW)

        result = pipeline.process(self.scenarios["mcp_schema_drift"])
        alert = result.alerts[0]

        self.assertEqual(alert.judgment.model_verdict.action, DecisionAction.DENY)
        self.assertEqual(alert.judgment.action, DecisionAction.REQUIRE_APPROVAL)
        self.assertEqual(alert.judgment.ai_mode, AiMode.SHADOW)
        self.assertIn("MODEL_SHADOW_ONLY", alert.judgment.reason_codes)


if __name__ == "__main__":
    unittest.main()
