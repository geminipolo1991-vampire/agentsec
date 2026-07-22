from __future__ import annotations

import unittest

from agentsec.contracts import FindingStatus
from agentsec.ingestion import InMemoryAlertLedger
from agentsec.pipeline import SecurityPipeline
from agentsec.scenarios import forge_scenarios


class LedgerTamperTests(unittest.TestCase):
    def _populated(self):
        pipeline = SecurityPipeline()
        pipeline.process(forge_scenarios()["indirect_injection_secret_egress"])
        pipeline.process(forge_scenarios()["mcp_schema_drift"])
        return pipeline.ledger

    def test_alert_mutation_is_detected_at_first_sequence(self) -> None:
        ledger = self._populated()
        ledger._ordered_alerts[0] = ledger._ordered_alerts[0].model_copy(
            update={"title": "tampered title"}
        )

        result = ledger.verify_detailed()

        self.assertFalse(result.valid)
        self.assertEqual(result.first_broken_sequence, 1)
        self.assertEqual(result.reason, "current_hash_mismatch")

    def test_alert_deletion_is_detected(self) -> None:
        ledger = self._populated()
        ledger._ordered_alerts.pop(0)

        result = ledger.verify_detailed()

        self.assertFalse(result.valid)
        self.assertEqual(result.first_broken_sequence, 1)

    def test_alert_reordering_is_detected(self) -> None:
        ledger = self._populated()
        ledger._ordered_alerts[0], ledger._ordered_alerts[1] = (
            ledger._ordered_alerts[1],
            ledger._ordered_alerts[0],
        )

        result = ledger.verify_detailed()

        self.assertFalse(result.valid)
        self.assertEqual(result.first_broken_sequence, 1)


class FindingLifecycleTests(unittest.TestCase):
    def test_denied_effect_creates_contained_finding_with_audit(self) -> None:
        pipeline = SecurityPipeline()
        result = pipeline.process(
            forge_scenarios()["persistent_memory_poisoning"]
        )
        finding = result.alerts[0].finding

        self.assertEqual(finding.status, FindingStatus.CONTAINED)
        self.assertEqual(
            [entry.to_status for entry in finding.audit],
            [FindingStatus.OPEN, FindingStatus.CONTAINED],
        )

    def test_approval_finding_can_follow_analyst_lifecycle(self) -> None:
        pipeline = SecurityPipeline()
        result = pipeline.process(forge_scenarios()["mcp_schema_drift"])
        finding_id = result.alerts[0].finding.finding_id

        acknowledged = pipeline.findings.transition(
            finding_id,
            FindingStatus.ACKNOWLEDGED,
            actor="human://analyst/alice",
            reason="accepted for review",
        )
        investigating = pipeline.findings.transition(
            finding_id,
            FindingStatus.INVESTIGATING,
            actor="human://analyst/alice",
            reason="validating manifest change",
        )
        closed = pipeline.findings.transition(
            finding_id,
            FindingStatus.CLOSED,
            actor="human://analyst/alice",
            reason="approved migration documented",
        )

        self.assertEqual(acknowledged.status, FindingStatus.ACKNOWLEDGED)
        self.assertEqual(investigating.status, FindingStatus.INVESTIGATING)
        self.assertEqual(closed.status, FindingStatus.CLOSED)
        with self.assertRaisesRegex(ValueError, "invalid finding transition"):
            pipeline.findings.transition(
                finding_id,
                FindingStatus.OPEN,
                actor="human://analyst/alice",
                reason="invalid reopen",
            )

    def test_duplicate_alert_does_not_duplicate_finding(self) -> None:
        pipeline = SecurityPipeline()
        event = forge_scenarios()["mcp_schema_drift"]

        first = pipeline.process(event)
        second = pipeline.process(event)

        self.assertEqual(pipeline.findings.count, 1)
        self.assertEqual(
            first.alerts[0].finding.finding_id,
            second.alerts[0].finding.finding_id,
        )


if __name__ == "__main__":
    unittest.main()
