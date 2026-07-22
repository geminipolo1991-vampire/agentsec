from __future__ import annotations

import json
import unittest

from agentsec.incidents import build_incident_detail
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
        self.processed = SecurityPipeline().process(event)

    def test_detail_uses_the_exact_authoritative_pipeline_result(self) -> None:
        result = self.processed.alerts[0]
        detail = build_incident_detail(result)

        self.assertEqual(detail.trace_mode, "authoritative")
        self.assertEqual(detail.incident_id, result.finding.finding_id)
        self.assertEqual(detail.alert.alert_id, result.alert.alert_id)
        self.assertEqual(detail.triage.risk_score, result.triage.risk_score)
        self.assertEqual(detail.judgment.action, result.judgment.action.value)
        self.assertEqual(detail.ingestion.sequence, result.ingestion.sequence)
        self.assertEqual(
            [item.stage for item in detail.timeline],
            ["detection", "ingestion", "triage", "judgment", "escalation", "response"],
        )
        self.assertTrue(detail.validation.authoritative_pipeline_result)
        self.assertTrue(detail.validation.deterministic_match)

    def test_triage_score_is_reproducible_and_enrichment_is_complete(self) -> None:
        for result in self.processed.alerts:
            detail = build_incident_detail(result)
            self.assertEqual(
                sum(item.delta for item in detail.risk_contributions),
                detail.triage.risk_score,
            )
            self.assertTrue(detail.triage.score_reproduced)
            self.assertEqual(len(detail.enrichment), 6)
            self.assertEqual(
                {item.kind for item in detail.enrichment},
                {
                    "Source provenance",
                    "Authority intersection",
                    "Data classification",
                    "Destination analysis",
                    "Tool contract",
                    "Memory persistence",
                },
            )

    def test_allowlisted_detail_hashes_raw_evidence_and_excludes_prompts(self) -> None:
        encoded = json.dumps(
            [build_incident_detail(item).model_dump(mode="json") for item in self.processed.alerts],
            sort_keys=True,
        )

        self.assertNotIn(CANARY, encoded)
        self.assertNotIn('"raw_prompt":', encoded)
        self.assertNotIn("should-never-appear", encoded)
        self.assertNotIn("receiver.invalid", encoded)
        self.assertIn("ref_sha256:", encoded)
        self.assertIn('"raw_prompts_included": false', encoded)


if __name__ == "__main__":
    unittest.main()
