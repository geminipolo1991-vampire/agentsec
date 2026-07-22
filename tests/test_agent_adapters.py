from __future__ import annotations

import unittest

from agentsec.adapters import (
    AdapterWorkflowRunner,
    CallbackFrameworkAdapter,
    CustomAgentAdapter,
)
from agentsec.synthetic import forge_scenario_definitions


class AgentAdapterContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.definitions = forge_scenario_definitions()
        self.custom = CustomAgentAdapter()
        self.framework = CallbackFrameworkAdapter()

    def test_both_implementations_emit_identical_canonical_events(self) -> None:
        for name, definition in self.definitions.items():
            with self.subTest(scenario=name):
                custom = self.custom.normalize(definition)
                framework = self.framework.normalize(definition)

                self.assertEqual(
                    custom.model_dump(mode="json"), framework.model_dump(mode="json")
                )

    def test_both_implementations_have_identical_security_outcomes(self) -> None:
        for name, definition in self.definitions.items():
            with self.subTest(scenario=name):
                custom = AdapterWorkflowRunner(self.custom).run(definition)
                framework = AdapterWorkflowRunner(self.framework).run(definition)

                self.assertEqual(
                    custom.execution.security_result.overall_action,
                    framework.execution.security_result.overall_action,
                )
                self.assertEqual(
                    custom.ground_truth.observed_alert_types,
                    framework.ground_truth.observed_alert_types,
                )
                self.assertEqual(custom.execution.completed, framework.execution.completed)
                self.assertTrue(custom.ground_truth.passed)
                self.assertTrue(framework.ground_truth.passed)


if __name__ == "__main__":
    unittest.main()
