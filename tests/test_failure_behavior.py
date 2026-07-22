from __future__ import annotations

import unittest

from agentsec.errors import SecurityControlUnavailable
from agentsec.pipeline import SecurityPipeline
from agentsec.scenarios import forge_scenarios
from agentsec.synthetic import ControlledToolGateway


class FailingLedger:
    def ingest(self, alert):
        raise SecurityControlUnavailable("ledger unavailable")


class FailureBehaviorTests(unittest.TestCase):
    def test_ingestion_failure_returns_explicit_fail_closed_result(self) -> None:
        pipeline = SecurityPipeline(ledger=FailingLedger())
        gateway = ControlledToolGateway(pipeline=pipeline)
        event = forge_scenarios()["indirect_injection_secret_egress"]

        result = gateway.execute(event, protected=True)

        self.assertFalse(result.completed)
        self.assertIsNone(result.security_result)
        self.assertEqual(result.security_error, "ledger unavailable")
        self.assertEqual(
            result.output_metadata["status"],
            "security_control_unavailable_fail_closed",
        )
        self.assertEqual(
            [item.phase for item in gateway.tools.observations], ["attempted"]
        )


if __name__ == "__main__":
    unittest.main()
