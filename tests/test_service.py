from __future__ import annotations

import json
import unittest

from agentsec.scenarios import forge_scenarios
from agentsec.service import (
    AuthorizationApplication,
    bearer_is_valid,
    health_payload,
    make_handler,
)


TOKEN = "service-test-token-at-least-thirty-two-characters"


class ServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.application = AuthorizationApplication()

    def test_health_endpoint_exposes_no_sensitive_state(self) -> None:
        self.assertEqual(
            health_payload(),
            {"service": "agentsec-authorization", "status": "ok"},
        )

    def test_authorization_requires_bearer_token(self) -> None:
        self.assertFalse(bearer_is_valid("", TOKEN))
        self.assertFalse(bearer_is_valid("Bearer wrong", TOKEN))
        self.assertTrue(bearer_is_valid("Bearer %s" % TOKEN, TOKEN))
        self.assertTrue(make_handler(self.application, TOKEN))

    def test_violation_is_processed_without_echoing_raw_event(self) -> None:
        event = forge_scenarios()["indirect_injection_secret_egress"].model_copy(
            update={"attributes": {"raw_prompt": "CANARY_RAW_PROMPT"}}
        )
        response = self.application.authorize(event.model_dump(mode="json"))
        encoded = response.model_dump_json()
        payload = json.loads(encoded)

        self.assertEqual(payload["overall_action"], "deny")
        self.assertFalse(payload["effect_allowed"])
        self.assertTrue(payload["ledger_verified"])
        self.assertNotIn("CANARY_RAW_PROMPT", encoded)
        self.assertNotIn("attributes", encoded)
        self.assertEqual(
            {item["alert_type"] for item in payload["alerts"]},
            {"indirect_prompt_injection", "secret_egress"},
        )
        self.assertEqual(payload["schema_version"], "1.1.0")
        self.assertEqual(
            {item["alert_type"] for item in payload["incidents"]},
            {"indirect_prompt_injection", "secret_egress"},
        )
        for incident in payload["incidents"]:
            self.assertEqual(incident["trace_mode"], "authoritative")
            self.assertTrue(incident["validation"]["authoritative_pipeline_result"])
            self.assertEqual(
                sum(item["delta"] for item in incident["risk_contributions"]),
                incident["triage"]["risk_score"],
            )


if __name__ == "__main__":
    unittest.main()
