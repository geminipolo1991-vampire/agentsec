from __future__ import annotations

import json
import unittest

from agentsec.adapters import (
    CallbackFrameworkAdapter,
    CustomAgentAdapter,
    framework_proposal_from_event,
)
from agentsec.observation import ObservationReconciler, SdkEffectReport
from agentsec.pipeline import SecurityPipeline
from agentsec.privacy import PrivacyTransformer
from agentsec.scenarios import forge_scenarios
from agentsec.splunk import SplunkHecClient, validate_hec_endpoint
from agentsec.synthetic import ControlledToolGateway


class RecordingHecTransport:
    def __init__(self, response=None, error=None):
        self.response = response or {"text": "Success", "code": 0}
        self.error = error
        self.calls = []

    def post(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise RuntimeError(self.error)
        return self.response


class AdapterContractTests(unittest.TestCase):
    def test_custom_and_callback_framework_emit_identical_events(self) -> None:
        original = forge_scenarios()["mcp_schema_drift"]
        custom = CustomAgentAdapter().normalize_tool_proposal(
            original.model_dump(mode="json")
        )
        framework = CallbackFrameworkAdapter().normalize_tool_proposal(
            framework_proposal_from_event(original)
        )

        self.assertEqual(custom, framework)
        self.assertEqual(
            SecurityPipeline().detector.detect(custom),
            SecurityPipeline().detector.detect(framework),
        )


class IndependentObservationTests(unittest.TestCase):
    def test_gateway_completion_without_sdk_completion_is_detected(self) -> None:
        event = forge_scenarios()["benign_inventory_read"]
        gateway = ControlledToolGateway()
        execution = gateway.execute(event, protected=False)

        findings = ObservationReconciler().reconcile(
            event.event_id,
            [
                SdkEffectReport(
                    event_id=event.event_id,
                    operation=event.operation,
                    resource=event.resource,
                    phase="attempted",
                )
            ],
            gateway.tools.observations,
        )

        self.assertTrue(execution.completed)
        self.assertEqual(findings[0].finding_type, "missing_agent_telemetry")

    def test_sdk_claim_without_gateway_effect_is_detected(self) -> None:
        event = forge_scenarios()["mcp_schema_drift"]
        gateway = ControlledToolGateway()
        execution = gateway.execute(event, protected=True)

        findings = ObservationReconciler().reconcile(
            event.event_id,
            [
                SdkEffectReport(
                    event_id=event.event_id,
                    operation=event.operation,
                    resource=event.resource,
                    phase="completed",
                )
            ],
            gateway.tools.observations,
        )

        self.assertFalse(execution.completed)
        self.assertEqual(findings[0].finding_type, "contradictory_effect_telemetry")

    def test_matching_observations_create_no_integrity_finding(self) -> None:
        event = forge_scenarios()["benign_inventory_read"]
        gateway = ControlledToolGateway()
        gateway.execute(event, protected=False)
        reports = [
            SdkEffectReport(
                event_id=event.event_id,
                operation=event.operation,
                resource=event.resource,
                phase=phase,
            )
            for phase in ["attempted", "completed"]
        ]

        findings = ObservationReconciler().reconcile(
            event.event_id, reports, gateway.tools.observations
        )

        self.assertEqual(findings, [])


class SplunkTests(unittest.TestCase):
    def _export(self):
        pipeline = SecurityPipeline()
        result = pipeline.process(
            forge_scenarios()["indirect_injection_secret_egress"]
        )
        return PrivacyTransformer().soc_export(
            result.alerts[0], ledger_valid=pipeline.ledger.verify()
        )

    def test_allowlisted_export_uses_hec_contract_and_is_idempotent(self) -> None:
        transport = RecordingHecTransport()
        client = SplunkHecClient(
            endpoint="https://splunk.example.test:8088/services/collector/event",
            token="splunk-test-token-never-log",
            allowed_hosts={"splunk.example.test"},
            index="agentsec_test",
            transport=transport,
        )
        export = self._export()

        first = client.export(export)
        duplicate = client.export(export)
        encoded = json.dumps(transport.calls[0]["payload"], sort_keys=True)

        self.assertEqual(first.status, "sent")
        self.assertEqual(duplicate.status, "duplicate")
        self.assertEqual(len(transport.calls), 1)
        self.assertNotIn("splunk-test-token-never-log", encoded)
        self.assertNotIn("receiver.invalid", encoded)
        self.assertEqual(
            transport.calls[0]["headers"]["Authorization"],
            "Splunk splunk-test-token-never-log",
        )

    def test_failure_creates_allowlisted_dead_letter(self) -> None:
        client = SplunkHecClient(
            endpoint="https://splunk.example.test:8088/services/collector/event",
            token="test-token",
            allowed_hosts={"splunk.example.test"},
            index="agentsec_test",
            transport=RecordingHecTransport(error="simulated outage"),
        )

        receipt = client.export(self._export())

        self.assertEqual(receipt.status, "dead_letter")
        self.assertEqual(len(client.dead_letters), 1)
        self.assertNotIn("raw_prompt", client.dead_letters[0].model_dump_json())

    def test_hec_endpoint_rejects_metadata_host_and_plain_http(self) -> None:
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            validate_hec_endpoint(
                "http://splunk.example.test:8088/services/collector/event",
                {"splunk.example.test"},
            )
        with self.assertRaisesRegex(ValueError, "allowlisted"):
            validate_hec_endpoint(
                "https://169.254.169.254/services/collector/event",
                {"splunk.example.test"},
            )


if __name__ == "__main__":
    unittest.main()
