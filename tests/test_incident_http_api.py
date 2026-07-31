from __future__ import annotations

import json
from io import BytesIO
import unittest

from agentsec.scenarios import forge_scenarios
from agentsec.service import AuthorizationApplication, make_handler


TOKEN = "incident-http-test-token-at-least-thirty-two-characters"


class IncidentHttpApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.application = AuthorizationApplication()
        self.handler = make_handler(self.application, TOKEN)

    def request(
        self, path: str, *, method: str = "GET", body: object = None, auth: bool = True
    ) -> tuple[int, dict]:
        headers = ["Host: 127.0.0.1"]
        if auth:
            headers.append("Authorization: Bearer %s" % TOKEN)
        encoded = b""
        if body is not None:
            encoded = json.dumps(body).encode("utf-8")
            headers.extend(
                [
                    "Content-Type: application/json",
                    "Content-Length: %d" % len(encoded),
                ]
            )
        raw = (
            "%s %s HTTP/1.1\r\n%s\r\n\r\n" % (method, path, "\r\n".join(headers))
        ).encode("ascii") + encoded

        class FakeSocket:
            def __init__(self, incoming: bytes) -> None:
                self.reader = BytesIO(incoming)
                self.sent = BytesIO()

            def makefile(self, mode: str, *_args, **_kwargs):
                return self.reader if "r" in mode else self.sent

            def sendall(self, data: bytes) -> None:
                self.sent.write(data)

        class FakeServer:
            server_name = "agentsec-test"
            server_port = 80

        connection = FakeSocket(raw)
        self.handler(connection, ("127.0.0.1", 12345), FakeServer())
        head, response_body = connection.sent.getvalue().split(b"\r\n\r\n", 1)
        status = int(head.splitlines()[0].split()[1])
        return status, json.loads(response_body.decode("utf-8"))

    def authorize_violation(self) -> str:
        event = forge_scenarios()["mcp_schema_drift"]
        status, payload = self.request(
            "/v1/authorize",
            method="POST",
            body=event.model_dump(mode="json"),
        )
        self.assertEqual(status, 200)
        return payload["alerts"][0]["finding_id"]

    def test_incident_list_detail_timeline_and_transition_endpoints(self) -> None:
        finding_id = self.authorize_violation()

        status, listed = self.request("/v1/incidents?alert_type=mcp_schema_drift")
        self.assertEqual(status, 200)
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["incidents"][0]["finding_id"], finding_id)

        status, detail = self.request("/v1/incidents/%s" % finding_id)
        self.assertEqual(status, 200)
        self.assertEqual(detail["detail_availability"], "complete")
        self.assertEqual(detail["incident_id"], finding_id)

        status, timeline = self.request("/v1/incidents/%s/timeline" % finding_id)
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["stage"] for item in timeline["timeline"]],
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

        status, updated = self.request(
            "/v1/incidents/%s/transition" % finding_id,
            method="POST",
            body={
                "action": "start_investigation",
                "actor": "analyst://http-test",
                "reason": "Reviewing authoritative incident evidence",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(updated["finding"]["status"], "investigating")
        self.assertEqual(updated["finding"]["audit"][-1]["actor"], "analyst://http-test")

    def test_authentication_filters_and_transition_schema_fail_closed(self) -> None:
        finding_id = self.authorize_violation()
        status, payload = self.request("/v1/incidents", auth=False)
        self.assertEqual((status, payload["error"]), (401, "unauthorized"))

        status, payload = self.request("/v1/incidents?raw_prompt=anything")
        self.assertEqual((status, payload["error"]), (400, "invalid_filter"))

        status, payload = self.request(
            "/v1/incidents/%s/transition" % finding_id,
            method="POST",
            body={
                "action": "close",
                "actor": "analyst://http-test",
                "reason": "Reviewed",
                "command": "whoami",
            },
        )
        self.assertEqual((status, payload["error"]), (400, "invalid_request"))


if __name__ == "__main__":
    unittest.main()
