from __future__ import annotations

import json
import unittest

from pydantic import ValidationError

from agentsec.contracts import FindingStatus
from agentsec.incidents import (
    IncidentDetail,
    IncidentStore,
    IncidentSummary,
    IncidentTransitionRequest,
    build_incident_detail,
)
from agentsec.pipeline import SecurityPipeline
from agentsec.scenarios import forge_scenarios


CANARY = "INCIDENT_DETAIL_RAW_CANARY_MUST_NOT_LEAK_92AF"


class IncidentDetailTests(unittest.TestCase):
    def setUp(self) -> None:
        event = forge_scenarios()["indirect_injection_secret_egress"].model_copy(
            update={
                "source_id": "document://external/%s" % CANARY,
                "resource": "secret://%s" % CANARY,
                "destination": "https://receiver.invalid/%s" % CANARY,
                "attributes": {
                    "raw_prompt": CANARY,
                    "authorization": "Bearer should-never-appear-in-detail",
                },
            }
        )
        self.pipeline = SecurityPipeline(incidents=IncidentStore(canaries={CANARY}))
        self.processed = self.pipeline.process(event)

    def test_detail_uses_only_the_authoritative_pipeline_result(self) -> None:
        result = self.processed.alerts[0]
        detail = build_incident_detail(result)

        self.assertEqual(detail.schema_version, "2.0.0")
        self.assertEqual(detail.trace_mode, "authoritative")
        self.assertEqual(detail.detail_availability, "complete")
        self.assertEqual(detail.incident_id, result.finding.finding_id)
        self.assertEqual(detail.detection.alert_id, result.alert.alert_id)
        self.assertEqual(detail.triage.risk_score, result.triage.risk_score)
        self.assertEqual(detail.judgment.final_action, result.judgment.action.value)
        self.assertEqual(detail.ingestion.sequence, result.ingestion.sequence)
        self.assertEqual(
            [item.stage for item in detail.timeline],
            [
                "detection",
                "ingestion",
                "enrichment",
                "triage",
                "judgment",
                "escalation",
                "response",
            ],
        )
        self.assertTrue(detail.validation.authoritative_pipeline_result)
        self.assertTrue(detail.validation.ledger_verified)

    def test_triage_and_enrichment_are_recorded_not_reconstructed(self) -> None:
        for result in self.processed.alerts:
            detail = self.pipeline.incidents.get(result.finding.finding_id)
            self.assertEqual(
                detail.triage.contributions,
                result.triage.contributions,
            )
            self.assertEqual(
                sum(item.delta for item in detail.triage.contributions),
                detail.triage.risk_score,
            )
            self.assertEqual(detail.enrichment.total_sources, 9)
            self.assertEqual(
                [item.source for item in detail.enrichment.sources],
                [item.source for item in result.enrichment.sources],
            )
            for source in detail.enrichment.sources:
                self.assertTrue(source.observed_at)
                self.assertGreaterEqual(source.confidence, 0.0)
                self.assertLessEqual(source.confidence, 1.0)
                self.assertTrue(source.failure_effect)

    def test_allowlisted_detail_excludes_raw_sensitive_inputs(self) -> None:
        encoded = json.dumps(
            [
                self.pipeline.incidents.get(item.finding.finding_id).model_dump(mode="json")
                for item in self.processed.alerts
            ],
            sort_keys=True,
        )

        self.assertNotIn(CANARY, encoded)
        self.assertNotIn('"raw_prompt":', encoded)
        self.assertNotIn("should-never-appear", encoded)
        self.assertNotIn("receiver.invalid", encoded)
        self.assertIn("_sha256:", encoded)
        self.assertIn('"raw_prompts_included": false', encoded)
        self.assertIn('"ingest_tokens_included": false', encoded)
        self.assertIn('"credentials_included": false', encoded)
        self.assertIn('"full_sensitive_content_included": false', encoded)

    def test_store_indexes_and_audited_transitions(self) -> None:
        result = self.processed.alerts[0]
        finding_id = result.finding.finding_id
        self.assertEqual(
            self.pipeline.incidents.list(alert_type=result.alert.alert_type)[0].finding_id,
            finding_id,
        )
        updated = self.pipeline.transition_incident(
            finding_id,
            IncidentTransitionRequest(
                action="start_investigation",
                actor="analyst://alice",
                reason="Reviewing the complete evidence chain",
            ).action,
            actor="analyst://alice",
            reason="Reviewing the complete evidence chain",
        )
        self.assertEqual(updated.finding.status, FindingStatus.INVESTIGATING.value)
        self.assertEqual(updated.finding.audit[-1].from_status, FindingStatus.CONTAINED.value)
        self.assertEqual(updated.finding.audit[-1].to_status, FindingStatus.INVESTIGATING.value)
        self.assertEqual(updated.finding.audit[-1].actor, "analyst://alice")

    def test_summary_only_history_never_fabricates_detail(self) -> None:
        store = IncidentStore()
        summary = IncidentSummary(
            finding_id="fnd_historical1234",
            event_id="evt_old",
            flow_id="flow_old",
            alert_type="secret_egress",
            title="Historical secret egress",
            agent_id="agent-old",
            severity="critical",
            priority="P0",
            status="closed",
            decision="deny",
            effect_status="blocked",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T01:00:00Z",
            detail_availability="summary_only",
        )
        detail = store.add_summary(summary)
        self.assertEqual(detail.detail_availability, "summary_only")
        self.assertIsNone(detail.triage)
        self.assertIsNone(detail.enrichment)
        self.assertEqual(detail.timeline, [])
        self.assertEqual(detail.risk_contributions, [])

        invalid = detail.model_dump(mode="json")
        invalid["risk_contributions"] = [
            {
                "category": "fabricated",
                "label": "Fabricated score",
                "delta": 100,
                "evidence_refs": ["fake_sha256:abc"],
                "rationale": "Must be rejected",
            }
        ]
        with self.assertRaises(ValidationError):
            IncidentDetail.model_validate(invalid)

    def test_unknown_incident_and_transition_fields_are_rejected(self) -> None:
        detail = self.pipeline.incidents.get(self.processed.alerts[0].finding.finding_id)
        payload = detail.model_dump(mode="json")
        payload["fabricated_score"] = 100
        with self.assertRaises(ValidationError):
            IncidentDetail.model_validate(payload)
        incomplete = detail.model_dump(mode="json")
        incomplete["enrichment"] = None
        with self.assertRaises(ValidationError):
            IncidentDetail.model_validate(incomplete)
        privacy_violation = detail.model_dump(mode="json")
        privacy_violation["privacy"]["raw_prompts_included"] = True
        with self.assertRaises(ValidationError):
            IncidentDetail.model_validate(privacy_violation)
        availability_mismatch = detail.model_dump(mode="json")
        availability_mismatch["summary"]["detail_availability"] = "summary_only"
        with self.assertRaises(ValidationError):
            IncidentDetail.model_validate(availability_mismatch)
        with self.assertRaises(ValidationError):
            IncidentTransitionRequest.model_validate(
                {
                    "action": "close",
                    "actor": "analyst://alice",
                    "reason": "Reviewed and closed",
                    "command": "arbitrary",
                }
            )


if __name__ == "__main__":
    unittest.main()
