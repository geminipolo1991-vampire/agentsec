from __future__ import annotations

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "tools" / "live_ui_bridge.py"
SPEC = importlib.util.spec_from_file_location("live_ui_bridge", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
bridge_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge_module)


class LiveUiBridgeTests(unittest.TestCase):
    def test_make_event_accepts_only_allowlisted_presets(self) -> None:
        event = bridge_module.make_event("mcp_schema_drift")
        self.assertTrue(event["event_id"].startswith("evt_live_"))
        self.assertEqual(event["attributes"]["live_ui_preset"], "mcp_schema_drift")
        self.assertNotEqual(
            event["declared_tool_schema_digest"], event["observed_tool_schema_digest"]
        )
        with self.assertRaisesRegex(ValueError, "unknown forge preset"):
            bridge_module.make_event("arbitrary_remote_command")

    def test_parses_sanitized_authorization_response_from_ssm(self) -> None:
        authorization = {
            "schema_version": "1.0.0",
            "event_id": "evt_live_test",
            "overall_action": "deny",
            "effect_allowed": False,
            "ledger_verified": True,
            "alerts": [
                {
                    "alert_id": "alr_test",
                    "finding_id": "fnd_test",
                    "alert_type": "authority_violation",
                    "severity": "high",
                    "decision": "deny",
                    "escalation": "soc_urgent",
                }
            ],
        }
        alerts, ledger = bridge_module.alerts_from_invocations(
            [
                {
                    "CommandId": "12345678-1234-1234-1234-123456789012",
                    "RequestedDateTime": "2026-07-22T19:50:29+09:00",
                    "CommandPlugins": [{"Output": json.dumps(authorization)}],
                }
            ]
        )
        self.assertTrue(ledger)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["id"], "alr_test")
        self.assertEqual(alerts[0]["decision"], "DENY")
        self.assertEqual(alerts[0]["time"], "19:50:29")

    def test_aws_cli_uses_argument_lists_and_never_embeds_a_token(self) -> None:
        calls = []

        def runner(args, **kwargs):
            calls.append((args, kwargs))
            return subprocess.CompletedProcess(
                args,
                0,
                stdout=json.dumps({"CommandInvocations": []}),
                stderr="",
            )

        client = bridge_module.AwsSsmClient(
            profile="agentsec-deploy",
            region="ap-northeast-1",
            instance_id="i-082370aa89a20ff93",
            runner=runner,
        )
        payload = client.list_alerts()
        self.assertEqual(payload["alerts"], [])
        self.assertFalse(calls[0][1]["shell"])
        rendered = " ".join(calls[0][0])
        self.assertNotIn("AGENTSEC_INGEST_TOKEN", rendered)
        self.assertIn("list-command-invocations", rendered)

    def test_configuration_rejects_shell_metacharacters(self) -> None:
        with self.assertRaisesRegex(ValueError, "profile"):
            bridge_module.validate_config("agentsec;whoami", "ap-northeast-1", "i-082370aa89a20ff93")

    def test_remote_command_contains_only_fixed_runner_and_base64_payloads(self) -> None:
        command = bridge_module.build_remote_command(
            bridge_module.make_event("persistent_memory_poisoning")
        )
        self.assertTrue(command.startswith("printf '%s' '"))
        self.assertIn("docker exec -i agentsec python -", command)
        self.assertNotIn("suspected-adversarial", command)
        self.assertNotIn("Bearer ", command)

    def test_rich_trace_is_attached_to_matching_alert_type(self) -> None:
        wrapper = {
            "agentsec_live_ui": "1",
            "event": {"operation": "external.send"},
            "authorization": {
                "event_id": "evt_rich",
                "overall_action": "deny",
                "effect_allowed": False,
                "ledger_verified": True,
                "alerts": [
                    {
                        "alert_id": "alr_rich",
                        "finding_id": "fnd_rich",
                        "alert_type": "secret_egress",
                        "severity": "critical",
                        "decision": "deny",
                        "escalation": "incident_page",
                    }
                ],
            },
            "incident_details": [
                {
                    "alert_type": "secret_egress",
                    "alert": {"title": "Live title", "reason_codes": ["LIVE_REASON"]},
                    "triage": {"risk_score": 100, "priority": "P0"},
                    "enrichment": [{"kind": "Destination analysis"}],
                    "timeline": [{"stage": "detection"}],
                }
            ],
        }
        alerts, ledger = bridge_module.alerts_from_invocations(
            [
                {
                    "CommandId": "12345678-1234-1234-1234-123456789012",
                    "RequestedDateTime": "2026-07-22T20:00:00+09:00",
                    "CommandPlugins": [{"Output": json.dumps(wrapper)}],
                }
            ]
        )
        self.assertTrue(ledger)
        self.assertEqual(alerts[0]["detailAvailability"], "mvp_replay")
        self.assertEqual(alerts[0]["detail"]["triage"]["priority"], "P0")
        self.assertEqual(alerts[0]["risk"], 100)

        wrapper["incident_details"][0]["trace_mode"] = "authoritative"
        authoritative_alerts, _ = bridge_module.alerts_from_invocations(
            [
                {
                    "CommandId": "12345678-1234-1234-1234-123456789012",
                    "RequestedDateTime": "2026-07-22T20:00:00+09:00",
                    "CommandPlugins": [{"Output": json.dumps(wrapper)}],
                }
            ]
        )
        self.assertEqual(
            authoritative_alerts[0]["detailAvailability"], "authoritative"
        )

    def test_recent_rich_alerts_survive_truncated_ssm_list_output(self) -> None:
        class FakeClient:
            def list_alerts(self):
                return {"alerts": [], "ledger_verified": True, "checked_at": "now"}

            def forge(self, _preset):
                return {"alerts": [{"id": "alr_recent", "detailAvailability": "mvp_replay"}]}

        live = bridge_module.LiveBridge(FakeClient(), cache_seconds=0)
        live.forge("mcp_schema_drift")
        payload = live.alerts()
        self.assertEqual(payload["alerts"][0]["id"], "alr_recent")


if __name__ == "__main__":
    unittest.main()
