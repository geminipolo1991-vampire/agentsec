from __future__ import annotations

from email.message import Message
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest

from agentsec.integrations import (
    EXTERNAL_CAPABILITIES,
    EXTERNAL_EVENTS_READ,
    EXTERNAL_FINDINGS_READ,
    EXTERNAL_INTEGRATIONS_READ,
    EXTERNAL_SEARCH,
    ExternalApiAccessPolicy,
    ExternalApiAuthenticator,
    ExternalApiClientSpec,
    integration_service_from_config,
)
from agentsec.scenarios import forge_scenarios
from agentsec.service import AuthorizationApplication, make_handler


PRIVATE_TOKEN = "private-service-token-at-least-thirty-two-bytes"
READ_TOKEN = "public-read-token-at-least-thirty-two-bytes"
SEARCH_TOKEN = "public-search-token-at-least-thirty-two-bytes"
OTHER_TOKEN = "public-other-tenant-token-at-least-thirty-two-bytes"


class ExternalApiHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        database = str(Path(self.temporary.name) / "integrations.sqlite3")
        service, principal = integration_service_from_config(
            database,
            "configs/external-integrations.example.json",
            cursor_secret="public-api-integration-cursor-at-least-32-bytes",
            environment={},
        )
        self.addCleanup(service.close)
        self.application = AuthorizationApplication(
            integration_service=service,
            integration_principal=principal,
        )
        policy = ExternalApiAccessPolicy(
            policy_version="external-api-http-test.1",
            clients=[
                ExternalApiClientSpec(
                    client_id="client://read-only-siem",
                    tenant_id="tenant-lab",
                    token_env="AGENTSEC_TEST_READ_TOKEN",
                    scopes={
                        EXTERNAL_CAPABILITIES,
                        EXTERNAL_EVENTS_READ,
                        EXTERNAL_FINDINGS_READ,
                        EXTERNAL_INTEGRATIONS_READ,
                    },
                ),
                ExternalApiClientSpec(
                    client_id="client://search-only-siem",
                    tenant_id="tenant-lab",
                    token_env="AGENTSEC_TEST_SEARCH_TOKEN",
                    scopes={EXTERNAL_SEARCH},
                ),
                ExternalApiClientSpec(
                    client_id="client://other-tenant",
                    tenant_id="tenant-other",
                    token_env="AGENTSEC_TEST_OTHER_TOKEN",
                    scopes={EXTERNAL_CAPABILITIES},
                ),
            ],
        )
        authenticator = ExternalApiAuthenticator(
            policy,
            environment={
                "AGENTSEC_TEST_READ_TOKEN": READ_TOKEN,
                "AGENTSEC_TEST_SEARCH_TOKEN": SEARCH_TOKEN,
                "AGENTSEC_TEST_OTHER_TOKEN": OTHER_TOKEN,
            },
        )
        self.handler_type = make_handler(
            self.application,
            PRIVATE_TOKEN,
            external_api_authenticator=authenticator,
        )

    def request(self, method: str, path: str, *, token: str, body=None):
        handler = self.handler_type.__new__(self.handler_type)
        handler.path = path
        handler.command = method
        handler.request_version = "HTTP/1.1"
        handler.headers = Message()
        handler.headers["Authorization"] = "Bearer %s" % token
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

    def test_pipeline_exports_privacy_safe_events_to_scoped_stream(self) -> None:
        event = forge_scenarios()["indirect_injection_secret_egress"].model_copy(
            update={"attributes": {"raw_prompt": "PUBLIC-API-RAW-CANARY"}}
        )
        authorization = self.application.authorize(event.model_dump(mode="json"))

        status, capabilities = self.request(
            "GET", "/api/v1/capabilities", token=READ_TOKEN
        )
        self.assertEqual(status, 200)
        self.assertEqual(capabilities["api_version"], "v1")
        status, stream = self.request(
            "GET", "/api/v1/events/stream?limit=10", token=READ_TOKEN
        )
        self.assertEqual(status, 200)
        self.assertEqual(stream["count"], len(authorization.alerts))
        encoded = json.dumps(stream, sort_keys=True)
        self.assertNotIn("PUBLIC-API-RAW-CANARY", encoded)
        self.assertNotIn("raw_prompt", encoded)
        self.assertNotIn(READ_TOKEN, encoded)

        status, findings = self.request(
            "GET", "/api/v1/findings?limit=10", token=READ_TOKEN
        )
        self.assertEqual(status, 200)
        self.assertEqual(findings["total"], len(authorization.alerts))

    def test_public_and_private_credentials_are_not_interchangeable(self) -> None:
        status, _ = self.request(
            "GET", "/api/v1/capabilities", token=PRIVATE_TOKEN
        )
        self.assertEqual(status, 401)
        status, _ = self.request(
            "GET", "/v1/external/capabilities", token=READ_TOKEN
        )
        self.assertEqual(status, 401)

    def test_scope_and_tenant_checks_fail_closed(self) -> None:
        status, _ = self.request(
            "POST",
            "/api/v1/search",
            token=READ_TOKEN,
            body={"query": "*"},
        )
        self.assertEqual(status, 403)

        status, payload = self.request(
            "POST",
            "/api/v1/search",
            token=SEARCH_TOKEN,
            body={"query": "*"},
        )
        self.assertEqual(status, 503)
        self.assertEqual(payload["error"], "search_not_configured")

        status, _ = self.request(
            "GET", "/api/v1/capabilities", token=OTHER_TOKEN
        )
        self.assertEqual(status, 403)

    def test_public_integration_status_is_bounded_and_inert(self) -> None:
        status, payload = self.request(
            "GET", "/api/v1/integrations", token=READ_TOKEN
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["health"]["status"], "healthy")
        self.assertTrue(
            all(not destination["enabled"] for destination in payload["destinations"])
        )
        encoded = json.dumps(payload, sort_keys=True)
        self.assertNotIn("token_env", encoded)
        self.assertNotIn("AGENTSEC_SPLUNK_HEC_TOKEN", encoded)
        self.assertNotIn(READ_TOKEN, encoded)


if __name__ == "__main__":
    unittest.main()
