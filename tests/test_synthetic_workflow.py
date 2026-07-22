from __future__ import annotations

import unittest

from agentsec.contracts import DecisionAction, PipelineStage
from agentsec.synthetic import (
    ControlledToolGateway,
    SyntheticSocWorkflow,
    forge_scenario_definitions,
)


class SyntheticWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.definitions = forge_scenario_definitions()

    def test_four_agent_roles_participate_in_every_workflow(self) -> None:
        run = SyntheticSocWorkflow().run(self.definitions["benign_inventory_read"])

        self.assertEqual(
            [step.role for step in run.trace],
            ["coordinator", "triage", "enrichment", "response"],
        )
        self.assertTrue(run.execution.completed)
        self.assertTrue(run.ground_truth.passed)

    def test_unprotected_attack_reaches_only_local_fake_tool(self) -> None:
        definition = self.definitions["indirect_injection_secret_egress"]
        gateway = ControlledToolGateway()

        run = SyntheticSocWorkflow(gateway).run(definition, protected=False)

        self.assertTrue(run.execution.completed)
        self.assertFalse(run.ground_truth.passed)
        self.assertIn("external.send", run.ground_truth.unexpected_forbidden_effects)
        self.assertEqual(run.execution.output_metadata["status"], "fake_receiver_recorded")

    def test_protected_attacks_are_detected_before_tool_completion(self) -> None:
        for name, definition in self.definitions.items():
            if name.startswith("benign_"):
                continue
            with self.subTest(scenario=name):
                gateway = ControlledToolGateway()
                run = SyntheticSocWorkflow(gateway).run(definition, protected=True)

                self.assertTrue(run.ground_truth.passed)
                self.assertTrue(run.execution.attempted)
                self.assertFalse(run.execution.completed)
                self.assertEqual(
                    gateway.tools.completed_operations(definition.event.event_id), set()
                )
                self.assertEqual(
                    run.execution.security_result.overall_action,
                    definition.ground_truth.expected_protected_action,
                )

    def test_security_response_precedes_any_allowed_tool_completion(self) -> None:
        definition = self.definitions["benign_inventory_read"]
        gateway = ControlledToolGateway()

        run = SyntheticSocWorkflow(gateway).run(definition, protected=True)

        self.assertEqual(run.execution.security_result.overall_action, DecisionAction.ALLOW)
        self.assertTrue(run.execution.completed)
        self.assertEqual(
            [item.phase for item in gateway.tools.observations], ["attempted", "completed"]
        )

    def test_each_protected_alert_contains_complete_stage_order(self) -> None:
        definition = self.definitions["persistent_memory_poisoning"]
        run = SyntheticSocWorkflow().run(definition, protected=True)
        alert = run.execution.security_result.alerts[0]

        self.assertEqual(
            [entry.stage for entry in alert.timeline],
            [
                PipelineStage.DETECTION,
                PipelineStage.INGESTION,
                PipelineStage.TRIAGE,
                PipelineStage.JUDGMENT,
                PipelineStage.ESCALATION,
                PipelineStage.RESPONSE,
            ],
        )


if __name__ == "__main__":
    unittest.main()
