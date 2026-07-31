from __future__ import annotations

import json
import unittest
from email.message import Message
from io import BytesIO

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
        self.assertEqual(payload["schema_version"], "2.0.0")
        self.assertEqual(
            {item["alert_type"] for item in payload["incidents"]},
            {"indirect_prompt_injection", "secret_egress"},
        )
        for incident in payload["incidents"]:
            self.assertEqual(incident["trace_mode"], "authoritative")
            self.assertEqual(incident["detail_availability"], "complete")
            self.assertTrue(incident["validation"]["authoritative_pipeline_result"])
            self.assertEqual(
                sum(item["delta"] for item in incident["triage"]["contributions"]),
                incident["triage"]["risk_score"],
            )

    def test_incident_query_timeline_and_transition_methods(self) -> None:
        event = forge_scenarios()["mcp_schema_drift"]
        authorization = self.application.authorize(event.model_dump(mode="json"))
        finding_id = authorization.alerts[0].finding_id

        listed = self.application.list_incidents({"alert_type": "mcp_schema_drift"})
        self.assertEqual(listed.count, 1)
        self.assertEqual(listed.incidents[0].finding_id, finding_id)
        detail = self.application.get_incident(finding_id)
        self.assertEqual(detail.detail_availability, "complete")
        self.assertEqual(len(self.application.get_timeline(finding_id)), 7)

        updated = self.application.transition_incident(
            finding_id,
            {
                "action": "start_investigation",
                "actor": "analyst://service-test",
                "reason": "Investigating observed MCP contract drift",
            },
        )
        self.assertEqual(updated.finding.status, "investigating")
        self.assertEqual(updated.finding.audit[-1].actor, "analyst://service-test")

    def test_private_http_incident_routes_return_recorded_data(self) -> None:
        handler_type = make_handler(self.application, TOKEN)

        def request(method, path, body=None, *, authorized=True):
            handler = handler_type.__new__(handler_type)
            handler.path = path
            handler.command = method
            handler.request_version = "HTTP/1.1"
            handler.headers = Message()
            if authorized:
                handler.headers["Authorization"] = "Bearer %s" % TOKEN
            encoded = b""
            if body is not None:
                encoded = json.dumps(body).encode("utf-8")
                handler.headers["Content-Type"] = "application/json"
                handler.headers["Content-Length"] = str(len(encoded))
            handler.rfile = BytesIO(encoded)
            handler.wfile = BytesIO()
            captured = {"status": None, "headers": {}}
            handler.send_response = lambda status: captured.update(status=status)
            handler.send_header = (
                lambda key, value: captured["headers"].update({key: value})
            )
            handler.end_headers = lambda: None
            getattr(handler, "do_%s" % method)()
            return captured["status"], json.loads(handler.wfile.getvalue())

        event = forge_scenarios()["mcp_schema_drift"].model_dump(mode="json")
        status, authorized = request("POST", "/v1/authorize", event)
        self.assertEqual(status, 200)
        finding_id = authorized["alerts"][0]["finding_id"]

        status, listed = request(
            "GET", "/v1/incidents?alert_type=mcp_schema_drift"
        )
        self.assertEqual(status, 200)
        self.assertEqual(listed["incidents"][0]["finding_id"], finding_id)

        status, detail = request("GET", "/v1/incidents/%s" % finding_id)
        self.assertEqual(status, 200)
        self.assertEqual(detail["detail_availability"], "complete")
        self.assertEqual(detail["timeline"][2]["stage"], "enrichment")

        status, timeline = request(
            "GET", "/v1/incidents/%s/timeline" % finding_id
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(timeline["timeline"]), 7)

        status, transitioned = request(
            "POST",
            "/v1/incidents/%s/transition" % finding_id,
            {
                "action": "start_investigation",
                "actor": "analyst://http-test",
                "reason": "Reviewing the recorded contract drift evidence",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(transitioned["finding"]["status"], "investigating")

        status, _ = request(
            "POST",
            "/v1/incidents/%s/transition" % finding_id,
            {
                "action": "close",
                "actor": "analyst://http-test",
                "reason": "Invalid extra mutation must be rejected",
                "owner": "attacker-controlled",
            },
        )
        self.assertEqual(status, 400)
        status, _ = request(
            "GET", "/v1/incidents/%s" % finding_id, authorized=False
        )
        self.assertEqual(status, 401)

if __name__ == "__main__":
    unittest.main()
