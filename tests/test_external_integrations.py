from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
import unittest
from email.message import Message
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from agentsec.integrations import (
    EXTERNAL_CAPABILITIES,
    EXTERNAL_EVENTS_READ,
    EXTERNAL_INTEGRATIONS_READ,
    EXTERNAL_SEARCH,
    INTEGRATION_ADMIN,
    INTEGRATION_DELIVER,
    INTEGRATION_READ,
    INTEGRATION_REDRIVE,
    AgentSecExternalApiClient,
    ConnectorOutcome,
    ExternalSecurityEvent,
    ExternalApiAccessPolicy,
    ExternalApiAuthenticator,
    ExternalApiAuthorizationError,
    ExternalApiClientSpec,
    GovernedIntegrationConnector,
    IntegrationAuthorizationError,
    IntegrationConflictError,
    IntegrationDeliveryState,
    IntegrationDestinationSpec,
    IntegrationKind,
    IntegrationPolicy,
    IntegrationPrincipal,
    IntegrationService,
    IntegrationTransportResponse,
    integration_service_from_config,
    render_cef,
    render_elastic_bulk,
    render_otlp_logs,
    render_rfc5424,
    render_splunk_event,
    render_webhook,
    validate_integration_endpoint,
)
from agentsec.pipeline import SecurityPipeline
from agentsec.scenarios import forge_scenarios
from agentsec.service import (
    AuthorizationApplication,
    application_from_environment,
    make_handler,
)


TOKEN = "external-http-token-at-least-thirty-two-characters"


class RecordingTransport:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.posts = []
        self.lines = []

    def post(self, **kwargs):
        self.posts.append(kwargs)
        if self.fail:
            raise RuntimeError("integration_test_outage")
        url = kwargs["url"]
        if url.endswith("/services/collector/event"):
            return IntegrationTransportResponse(
                status_code=200,
                body={"text": "Success", "code": 0, "ackId": 17},
                receipt="1" * 64,
            )
        if url.endswith("/services/collector/ack"):
            return IntegrationTransportResponse(
                status_code=200,
                body={"acks": {"17": True}},
                receipt="2" * 64,
            )
        if url.endswith("/_bulk"):
            return IntegrationTransportResponse(
                status_code=200,
                body={"errors": False, "items": [{"create": {"status": 201}}]},
                receipt="3" * 64,
            )
        if url.endswith("/v1/logs"):
            return IntegrationTransportResponse(
                status_code=200,
                body={"partialSuccess": {"rejectedLogRecords": "0"}},
                receipt="4" * 64,
            )
        return IntegrationTransportResponse(
            status_code=202, body={"accepted": True}, receipt="5" * 64
        )

    def send_line(self, **kwargs):
        self.lines.append(kwargs)
        if self.fail:
            raise RuntimeError("integration_test_outage")
        return IntegrationTransportResponse(status_code=200, receipt="6" * 64)


class RecordingApiTransport:
    def __init__(self) -> None:
        self.calls = []

    def request(self, **kwargs):
        self.calls.append(kwargs)
        return {"schema_version": "1.0.0"}


class ExternalIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        pipeline = SecurityPipeline()
        result = pipeline.process(
            forge_scenarios()["indirect_injection_secret_egress"]
        )
        self.event = ExternalSecurityEvent.from_pipeline(
            result.alerts[0], ledger_valid=pipeline.ledger.verify()
        )

    @staticmethod
    def principal(tenant: str = "tenant-lab", *, permissions=None):
        return IntegrationPrincipal(
            tenant_id=tenant,
            actor_id="system://integration-test",
            permissions=permissions
            or {
                INTEGRATION_READ,
                INTEGRATION_DELIVER,
                INTEGRATION_REDRIVE,
                INTEGRATION_ADMIN,
            },
        )

    @staticmethod
    def destination(kind: IntegrationKind, **updates):
        defaults = {
            IntegrationKind.SPLUNK_HEC: dict(
                destination_id="integration://splunk",
                name="Splunk test",
                endpoint="https://splunk.example.test:8088/services/collector/event",
                allowed_hosts=["splunk.example.test"],
                credential_env="TEST_SPLUNK_TOKEN",
                index="agentsec-test",
                indexer_ack=True,
            ),
            IntegrationKind.ELASTIC_BULK: dict(
                destination_id="integration://elastic",
                name="Elastic test",
                endpoint="https://elastic.example.test:9243/_bulk",
                allowed_hosts=["elastic.example.test"],
                credential_env="TEST_ELASTIC_KEY",
                index="agentsec-test",
            ),
            IntegrationKind.SIGNED_WEBHOOK: dict(
                destination_id="integration://webhook",
                name="Webhook test",
                endpoint="https://webhook.example.test/v1/events",
                allowed_hosts=["webhook.example.test"],
                credential_env="TEST_WEBHOOK_SECRET",
            ),
            IntegrationKind.SYSLOG_TLS: dict(
                destination_id="integration://syslog",
                name="Syslog test",
                endpoint="tls://syslog.example.test:6514",
                allowed_hosts=["syslog.example.test"],
            ),
            IntegrationKind.CEF_TLS: dict(
                destination_id="integration://cef",
                name="CEF test",
                endpoint="tls://cef.example.test:6514",
                allowed_hosts=["cef.example.test"],
            ),
            IntegrationKind.OTLP_HTTP_JSON: dict(
                destination_id="integration://otlp",
                name="OTLP test",
                endpoint="https://otel.example.test:4318/v1/logs",
                allowed_hosts=["otel.example.test"],
            ),
        }[kind]
        defaults.update(updates)
        return IntegrationDestinationSpec(kind=kind, **defaults)

    def service(self, destinations, *, transport=None, environment=None):
        policy = IntegrationPolicy(
            policy_version="integration-test-1",
            tenant_id="tenant-lab",
            destinations=destinations,
        )
        service = IntegrationService(
            str(Path(self.tempdir.name) / "integrations.sqlite3"),
            cursor_secret=b"integration-cursor-secret-32-bytes-minimum",
            policy=policy,
            connector=GovernedIntegrationConnector(transport or RecordingTransport()),
            environment=environment or {},
        )
        self.addCleanup(service.close)
        return service

    def test_external_event_is_digest_bound_allowlist_only(self) -> None:
        payload = self.event.model_dump(mode="json")

        self.assertEqual(payload["event_type"], "finding")
        self.assertEqual(payload["ledger_integrity"], "verified")
        encoded = json.dumps(payload, sort_keys=True)
        for prohibited in (
            "raw_prompt",
            "tool_arguments",
            "tool_result",
            "provider_response",
            "receiver.invalid",
        ):
            self.assertNotIn(prohibited, encoded)
        with self.assertRaisesRegex(ValueError, "digest"):
            ExternalSecurityEvent.model_validate({**payload, "decision": "allow"})

    def test_all_export_formats_are_bounded_and_protocol_shaped(self) -> None:
        splunk = self.destination(IntegrationKind.SPLUNK_HEC)
        elastic = self.destination(IntegrationKind.ELASTIC_BULK)

        splunk_payload = json.loads(render_splunk_event(self.event, splunk))
        elastic_lines = render_elastic_bulk(self.event, elastic).decode().splitlines()
        webhook = json.loads(render_webhook(self.event))
        otlp = json.loads(render_otlp_logs(self.event))
        syslog = render_rfc5424(self.event)
        cef = render_cef(self.event)

        self.assertEqual(splunk_payload["fields"]["event_id"], self.event.event_id)
        self.assertEqual(json.loads(elastic_lines[0])["create"]["_id"], self.event.event_id)
        self.assertEqual(json.loads(elastic_lines[1])["event_id"], self.event.event_id)
        self.assertTrue(render_elastic_bulk(self.event, elastic).endswith(b"\n"))
        self.assertEqual(webhook["event_type"], "agentsec.finding.v1")
        record = otlp["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
        self.assertEqual(record["eventName"], "agentsec.finding")
        self.assertTrue(syslog.startswith("<"))
        self.assertIn("[agentsec@32473", syslog)
        self.assertRegex(
            syslog,
            r"^<\d+>1 \S+ agentsec agentsec - - \[agentsec@32473 ",
        )
        self.assertTrue(cef.startswith("CEF:0|OpenAI-Labs|AgentSec|1.0|"))

    def test_endpoints_reject_plaintext_metadata_and_wrong_paths(self) -> None:
        with self.assertRaisesRegex(ValueError, "transport"):
            validate_integration_endpoint(
                IntegrationKind.SPLUNK_HEC,
                "http://splunk.example.test/services/collector/event",
                ["splunk.example.test"],
            )
        with self.assertRaisesRegex(ValueError, "allowlisted"):
            validate_integration_endpoint(
                IntegrationKind.OTLP_HTTP_JSON,
                "https://169.254.169.254/v1/logs",
                ["otel.example.test"],
            )
        with self.assertRaisesRegex(ValueError, "_bulk"):
            self.destination(
                IntegrationKind.ELASTIC_BULK,
                endpoint="https://elastic.example.test:9243/search",
            )

    def test_durable_outbox_delivers_all_formats_and_polls_splunk_ack(self) -> None:
        transport = RecordingTransport()
        destinations = [self.destination(kind) for kind in IntegrationKind]
        environment = {
            "TEST_SPLUNK_TOKEN": "splunk-token-not-persisted",
            "TEST_ELASTIC_KEY": "elastic-key-not-persisted",
            "TEST_WEBHOOK_SECRET": "webhook-secret-not-persisted-at-least-32-bytes",
        }
        service = self.service(
            destinations, transport=transport, environment=environment
        )

        created = service.enqueue(self.principal(), self.event)
        duplicate = service.enqueue(self.principal(), self.event)
        first = service.process_due(self.principal(), limit=10)
        service._connection.execute(  # Make the explicit acknowledgment poll due.
            "UPDATE integration_deliveries SET next_attempt_at = '2000-01-01T00:00:00Z' "
            "WHERE state = 'ack_pending'"
        )
        second = service.process_due(self.principal(), limit=10)
        health = service.health(self.principal())

        self.assertEqual(len(created), 6)
        self.assertEqual(duplicate, [])
        self.assertEqual(first.delivered, 5)
        self.assertEqual(first.ack_pending, 1)
        self.assertEqual(second.delivered, 1)
        self.assertEqual(health.delivered, 6)
        self.assertEqual(health.dead_letter, 0)
        self.assertEqual(len(transport.lines), 2)
        database = Path(self.tempdir.name, "integrations.sqlite3").read_bytes()
        for secret in environment.values():
            self.assertNotIn(secret.encode(), database)
        splunk_calls = [
            call
            for call in transport.posts
            if "/services/collector/" in call["url"]
        ]
        self.assertEqual(len(splunk_calls), 2)
        self.assertEqual(
            splunk_calls[0]["headers"]["X-Splunk-Request-Channel"],
            splunk_calls[1]["headers"]["X-Splunk-Request-Channel"],
        )
        webhook_call = next(
            call for call in transport.posts if call["url"].endswith("/v1/events")
        )
        webhook_body = webhook_call["body"]
        webhook_headers = webhook_call["headers"]
        self.assertEqual(
            webhook_headers["X-AgentSec-Content-SHA256"],
            hashlib.sha256(webhook_body).hexdigest(),
        )
        expected_signature = hmac.new(
            environment["TEST_WEBHOOK_SECRET"].encode("utf-8"),
            webhook_headers["X-AgentSec-Timestamp"].encode("ascii")
            + b"."
            + webhook_body,
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(
            webhook_headers["X-AgentSec-Signature"],
            "v1=" + expected_signature,
        )

    def test_outbox_survives_restart_without_duplicate_delivery(self) -> None:
        database_path = str(Path(self.tempdir.name) / "restart.sqlite3")
        destination = self.destination(IntegrationKind.SYSLOG_TLS)
        policy = IntegrationPolicy(
            policy_version="restart-test-1",
            tenant_id="tenant-lab",
            destinations=[destination],
        )
        first = IntegrationService(
            database_path,
            cursor_secret=b"restart-cursor-secret-at-least-32-bytes",
            policy=policy,
            connector=GovernedIntegrationConnector(RecordingTransport()),
            environment={},
        )
        first.enqueue(self.principal(), self.event)
        first.close()

        transport = RecordingTransport()
        reopened = IntegrationService(
            database_path,
            cursor_secret=b"restart-cursor-secret-at-least-32-bytes",
            policy=policy,
            connector=GovernedIntegrationConnector(transport),
            environment={},
        )
        self.addCleanup(reopened.close)

        self.assertEqual(reopened.enqueue(self.principal(), self.event), [])
        self.assertEqual(reopened.stream_events(self.principal()).count, 1)
        self.assertEqual(reopened.process_due(self.principal()).delivered, 1)
        self.assertEqual(len(transport.lines), 1)

    def test_missing_credentials_and_provider_item_rejections_fail_closed(self) -> None:
        missing = self.service(
            [self.destination(IntegrationKind.SIGNED_WEBHOOK, max_attempts=1)],
            transport=RecordingTransport(),
            environment={},
        )
        missing_delivery = missing.enqueue(self.principal(), self.event)[0]
        self.assertEqual(missing.process_due(self.principal()).dead_lettered, 1)
        self.assertEqual(
            missing.get_delivery(self.principal(), missing_delivery.delivery_id)
            .attempts[0]
            .error_code,
            "integration_credential_unavailable",
        )

        class RejectingItemTransport(RecordingTransport):
            def post(self, **kwargs):
                self.posts.append(kwargs)
                if kwargs["url"].endswith("/_bulk"):
                    return IntegrationTransportResponse(
                        status_code=200,
                        body={
                            "errors": True,
                            "items": [{"create": {"status": 429}}],
                        },
                        receipt="8" * 64,
                    )
                if kwargs["url"].endswith("/v1/logs"):
                    return IntegrationTransportResponse(
                        status_code=200,
                        body={"partialSuccess": {"rejectedLogRecords": "1"}},
                        receipt="9" * 64,
                    )
                return super().post(**kwargs)

        rejected = self.service(
            [
                self.destination(IntegrationKind.ELASTIC_BULK, max_attempts=1),
                self.destination(IntegrationKind.OTLP_HTTP_JSON, max_attempts=1),
            ],
            transport=RejectingItemTransport(),
            environment={"TEST_ELASTIC_KEY": "elastic-test-key"},
        )
        deliveries = rejected.enqueue(self.principal(), self.event)
        self.assertEqual(rejected.process_due(self.principal()).dead_lettered, 2)
        errors = {
            rejected.get_delivery(self.principal(), item.delivery_id)
            .attempts[0]
            .error_code
            for item in deliveries
        }
        self.assertEqual(errors, {"elastic_bulk_rejected", "otlp_logs_rejected"})

    def test_failure_dead_letters_and_governed_redrive_is_durable(self) -> None:
        destination = self.destination(
            IntegrationKind.SIGNED_WEBHOOK, max_attempts=1
        )
        transport = RecordingTransport(fail=True)
        service = self.service(
            [destination],
            transport=transport,
            environment={
                "TEST_WEBHOOK_SECRET": "test-webhook-secret-at-least-32-bytes"
            },
        )
        delivery = service.enqueue(self.principal(), self.event)[0]

        result = service.process_due(self.principal())
        detail = service.get_delivery(self.principal(), delivery.delivery_id)
        redriven = service.redrive(
            self.principal(), delivery.delivery_id, reason="operator reviewed outage"
        )

        self.assertEqual(result.dead_lettered, 1)
        self.assertEqual(detail.delivery.state, IntegrationDeliveryState.DEAD_LETTER)
        self.assertEqual(detail.attempts[0].error_code, "integration_test_outage")
        self.assertEqual(redriven.state, IntegrationDeliveryState.QUEUED)
        self.assertEqual(redriven.redrive_count, 1)
        with self.assertRaises(IntegrationConflictError):
            service.redrive(
                self.principal(), delivery.delivery_id, reason="not dead any longer"
            )
        transport.fail = False
        recovered = service.process_due(self.principal())
        recovered_detail = service.get_delivery(self.principal(), delivery.delivery_id)
        self.assertEqual(recovered.delivered, 1)
        self.assertEqual(recovered_detail.delivery.attempts, 2)
        self.assertEqual(
            [item.sequence for item in recovered_detail.attempts], [1, 2]
        )

    def test_splunk_ack_poll_is_bounded_and_dead_letters_when_missing(self) -> None:
        class PendingAckTransport(RecordingTransport):
            def post(self, **kwargs):
                response = super().post(**kwargs)
                if kwargs["url"].endswith("/services/collector/ack"):
                    return IntegrationTransportResponse(
                        status_code=200,
                        body={"acks": {"17": False}},
                        receipt="7" * 64,
                    )
                return response

        service = self.service(
            [self.destination(IntegrationKind.SPLUNK_HEC, max_attempts=2)],
            transport=PendingAckTransport(),
            environment={"TEST_SPLUNK_TOKEN": "splunk-test-token"},
        )
        delivery = service.enqueue(self.principal(), self.event)[0]
        first = service.process_due(self.principal())
        service._connection.execute(
            "UPDATE integration_deliveries SET next_attempt_at = '2000-01-01T00:00:00Z' "
            "WHERE delivery_id = ?",
            (delivery.delivery_id,),
        )
        second = service.process_due(self.principal())
        detail = service.get_delivery(self.principal(), delivery.delivery_id)

        self.assertEqual(first.ack_pending, 1)
        self.assertEqual(second.dead_lettered, 1)
        self.assertEqual(detail.delivery.state, IntegrationDeliveryState.DEAD_LETTER)
        self.assertEqual(detail.attempts[-1].operation, "ack_poll")

    def test_stream_cursor_is_signed_tenant_and_filter_bound(self) -> None:
        service = self.service([self.destination(IntegrationKind.SYSLOG_TLS)])
        service.enqueue(self.principal(), self.event)
        second_payload = self.event.model_dump(mode="json", exclude={"record_sha256"})
        second_payload["event_id"] = "xevt_" + "a" * 32
        second_payload["finding_id"] = "fnd_second"
        from agentsec.integrations import _sha256

        second_payload["record_sha256"] = _sha256(second_payload)
        service.enqueue(
            self.principal(), ExternalSecurityEvent.model_validate(second_payload)
        )

        first = service.stream_events(self.principal(), limit=1)
        second = service.stream_events(
            self.principal(), limit=1, cursor=first.next_cursor
        )

        self.assertEqual(first.count, 1)
        self.assertIsNotNone(first.next_cursor)
        self.assertEqual(second.events[0].finding_id, "fnd_second")
        with self.assertRaisesRegex(ValueError, "cursor"):
            service.stream_events(
                self.principal(), limit=1, cursor=str(first.next_cursor) + "x"
            )
        with self.assertRaisesRegex(ValueError, "cursor"):
            service.stream_events(
                self.principal(),
                limit=1,
                cursor=first.next_cursor,
                event_types=["finding"],
            )

    def test_permissions_and_tenants_fail_closed(self) -> None:
        service = self.service([self.destination(IntegrationKind.SYSLOG_TLS)])
        reader = self.principal(permissions={INTEGRATION_READ})

        with self.assertRaises(IntegrationAuthorizationError):
            service.enqueue(reader, self.event)
        with self.assertRaises(IntegrationAuthorizationError):
            service.health(self.principal("tenant-other"))

    def test_audit_chain_detects_mutation(self) -> None:
        service = self.service([self.destination(IntegrationKind.SYSLOG_TLS)])
        service.enqueue(self.principal(), self.event)
        self.assertGreaterEqual(len(service.audit(self.principal())), 2)

        service._connection.execute(
            "UPDATE integration_audit SET object_id = 'tampered' WHERE sequence = 1"
        )
        with self.assertRaisesRegex(ValueError, "audit ledger"):
            service.audit(self.principal())

    def test_capability_manifest_covers_the_external_product_contract(self) -> None:
        service = self.service([self.destination(IntegrationKind.SYSLOG_TLS)])

        manifest = service.capabilities(self.principal())
        resources = {item.resource for item in manifest.capabilities}

        self.assertEqual(
            resources,
            {
                "ingestion",
                "event_stream",
                "search",
                "entities",
                "rules",
                "findings",
                "incidents",
                "integrations",
            },
        )
        self.assertEqual(set(manifest.export_formats), set(IntegrationKind))
        self.assertFalse(manifest.raw_content_exported)
        by_resource = {item.resource: item for item in manifest.capabilities}
        self.assertEqual(
            by_resource["event_stream"].paths,
            ["/api/v1/events", "/api/v1/events/stream"],
        )
        self.assertEqual(by_resource["search"].paths, ["/api/v1/search"])

    def test_python_consumer_sdk_uses_only_fixed_routes_and_header_token(self) -> None:
        transport = RecordingApiTransport()
        client = AgentSecExternalApiClient(
            endpoint="http://127.0.0.1:8080",
            token="external-api-test-token-at-least-32-bytes",
            transport=transport,
            allow_loopback_http=True,
        )

        client.capabilities()
        client.stream_events(limit=25, event_types=["finding"])
        client.search({"query": {"match_all": True}})
        client.list_entities(limit=25, offset=0)
        client.list_rules()
        client.list_findings()
        client.list_incidents()
        client.get_entity("cmp_entity1")
        client.get_finding("fnd_finding1")
        client.get_incident("inc_incident1")
        client.integrations()
        client.deliveries(state=IntegrationDeliveryState.DEAD_LETTER, limit=25)
        client.process_integrations(limit=10)
        client.redrive_delivery(
            "idl_" + "a" * 32, reason="operator reviewed failed delivery"
        )

        self.assertEqual(len(transport.calls), 14)
        self.assertEqual(
            transport.calls[0]["url"],
            "http://127.0.0.1:8080/api/v1/capabilities",
        )
        self.assertIn("/api/v1/events/stream?", transport.calls[1]["url"])
        self.assertEqual(
            transport.calls[-1]["url"],
            "http://127.0.0.1:8080/api/v1/integrations/deliveries/idl_"
            + "a" * 32
            + "/redrive",
        )
        encoded = json.dumps(
            [
                {
                    "url": item["url"],
                    "payload": item["payload"],
                }
                for item in transport.calls
            ],
            sort_keys=True,
        )
        self.assertNotIn("external-api-test-token-at-least-32-bytes", encoded)
        for call in transport.calls:
            self.assertEqual(
                call["headers"]["Authorization"],
                "Bearer external-api-test-token-at-least-32-bytes",
            )
        with self.assertRaisesRegex(ValueError, "event types"):
            client.stream_events(event_types=["unsupported"])
        with self.assertRaisesRegex(ValueError, "page"):
            client.list_findings(offset=1_000_001)

    def test_checked_in_config_is_inert_and_secret_name_only(self) -> None:
        database_path = str(Path(self.tempdir.name) / "from-config.sqlite3")
        service, principal = integration_service_from_config(
            database_path,
            "configs/external-integrations.example.json",
            cursor_secret="integration-config-cursor-secret-at-least-32",
            connector=GovernedIntegrationConnector(RecordingTransport()),
            environment={},
        )
        self.addCleanup(service.close)

        health = service.health(principal)

        self.assertEqual(health.status, "healthy")
        self.assertTrue(all(not item.enabled for item in health.destinations))
        config = Path("configs/external-integrations.example.json").read_text()
        self.assertNotIn("Authorization", config)
        self.assertNotIn("Bearer ", config)

        public_access = ExternalApiAuthenticator.from_config(
            "configs/external-api-clients.example.json", environment={}
        )
        with self.assertRaisesRegex(PermissionError, "authentication"):
            public_access.authenticate("Bearer " + "x" * 32)

    def test_delivery_digest_detects_database_mutation(self) -> None:
        service = self.service([self.destination(IntegrationKind.SYSLOG_TLS)])
        delivery = service.enqueue(self.principal(), self.event)[0]
        service._connection.execute(
            "UPDATE integration_deliveries SET state = 'delivered' WHERE delivery_id = ?",
            (delivery.delivery_id,),
        )

        with self.assertRaisesRegex(ValueError, "storage digest"):
            service.get_delivery(self.principal(), delivery.delivery_id)

    def test_pipeline_and_authenticated_http_api_publish_live_external_state(self) -> None:
        transport = RecordingTransport()
        service = self.service(
            [self.destination(IntegrationKind.SYSLOG_TLS)], transport=transport
        )
        application = AuthorizationApplication(
            integration_service=service,
            integration_principal=self.principal(),
        )
        handler_type = make_handler(application, TOKEN)

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

        status, authorization = request(
            "POST",
            "/v1/authorize",
            forge_scenarios()["indirect_injection_secret_egress"].model_dump(
                mode="json"
            ),
        )
        self.assertEqual(status, 200)
        self.assertEqual(authorization["overall_action"], "deny")

        for path, expected_key in (
            ("/v1/external/capabilities", "capabilities"),
            ("/v1/external/events?limit=10&event_types=finding", "events"),
            ("/v1/external/destinations", "destinations"),
            ("/v1/external/deliveries", "deliveries"),
            ("/v1/external/health", "destinations"),
            ("/v1/external/audit", "audit"),
        ):
            route_status, payload = request("GET", path)
            self.assertEqual(route_status, 200, path)
            self.assertIn(expected_key, payload, path)
        status, processed = request("POST", "/v1/external/process", {"limit": 10})
        self.assertEqual(status, 200)
        self.assertEqual(processed["delivered"], 2)
        status, _ = request(
            "GET", "/v1/external/events?unknown=true"
        )
        self.assertEqual(status, 400)
        status, _ = request(
            "GET", "/v1/external/events", authorized=False
        )
        self.assertEqual(status, 401)

    def test_export_outage_is_visible_and_cannot_change_enforcement(self) -> None:
        service = self.service([self.destination(IntegrationKind.SYSLOG_TLS)])

        def fail_enqueue(*args, **kwargs):
            raise RuntimeError("simulated durable outbox outage")

        service.enqueue_pipeline_result = fail_enqueue  # type: ignore[method-assign]
        application = AuthorizationApplication(
            integration_service=service,
            integration_principal=self.principal(),
        )

        authorization = application.authorize(
            forge_scenarios()["mcp_schema_drift"].model_dump(mode="json")
        )
        health = application.external_health()

        self.assertEqual(authorization.overall_action, "require_approval")
        self.assertFalse(authorization.effect_allowed)
        self.assertEqual(health.status, "degraded")
        self.assertEqual(health.pipeline_enqueue_error, "integration_enqueue_failed")

    def test_environment_assembly_requires_complete_explicit_configuration(self) -> None:
        with patch.dict(
            "os.environ",
            {"AGENTSEC_INTEGRATION_DB": str(Path(self.tempdir.name) / "partial.sqlite3")},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "external integrations require"):
                application_from_environment(SecurityPipeline())

        with patch.dict(
            "os.environ",
            {
                "AGENTSEC_INTEGRATION_DB": str(Path(self.tempdir.name) / "runtime.sqlite3"),
                "AGENTSEC_INTEGRATION_CONFIG": "configs/external-integrations.example.json",
                "AGENTSEC_INTEGRATION_CURSOR_SECRET": "runtime-integration-cursor-secret-32-bytes",
                "AGENTSEC_INTEGRATION_TENANT": "tenant-lab",
            },
            clear=True,
        ):
            application = application_from_environment(SecurityPipeline())
            self.addCleanup(application.integration_service.close)

        self.assertEqual(application.external_health().status, "healthy")

    def test_external_api_authentication_is_tenant_and_scope_bound(self) -> None:
        token = "external-siem-reader-token-at-least-32-bytes"
        policy = ExternalApiAccessPolicy(
            policy_version="external-api-test-1",
            clients=[
                ExternalApiClientSpec(
                    client_id="client://reader",
                    tenant_id="tenant-lab",
                    token_env="TEST_EXTERNAL_READER_TOKEN",
                    scopes={EXTERNAL_CAPABILITIES, EXTERNAL_EVENTS_READ},
                )
            ],
        )
        authenticator = ExternalApiAuthenticator(
            policy, environment={"TEST_EXTERNAL_READER_TOKEN": token}
        )

        principal = authenticator.authenticate("Bearer %s" % token)

        self.assertEqual(principal.tenant_id, "tenant-lab")
        authenticator.authorize(principal, EXTERNAL_EVENTS_READ)
        with self.assertRaises(ExternalApiAuthorizationError):
            authenticator.authorize(principal, EXTERNAL_SEARCH)
        with self.assertRaisesRegex(PermissionError, "authentication"):
            authenticator.authenticate("Bearer wrong-token")
        self.assertNotIn(token, policy.model_dump_json())

    def test_scoped_public_api_uses_separate_client_authentication(self) -> None:
        external_token = "public-api-reader-token-at-least-thirty-two-bytes"
        service = self.service([self.destination(IntegrationKind.SYSLOG_TLS)])
        application = AuthorizationApplication(
            integration_service=service,
            integration_principal=self.principal(),
        )
        access = ExternalApiAuthenticator(
            ExternalApiAccessPolicy(
                policy_version="public-api-test-1",
                clients=[
                    ExternalApiClientSpec(
                        client_id="client://public-reader",
                        tenant_id="tenant-lab",
                        token_env="TEST_PUBLIC_API_TOKEN",
                        scopes={
                            EXTERNAL_CAPABILITIES,
                            EXTERNAL_EVENTS_READ,
                            EXTERNAL_INTEGRATIONS_READ,
                        },
                    )
                ],
            ),
            environment={"TEST_PUBLIC_API_TOKEN": external_token},
        )
        handler_type = make_handler(application, TOKEN, external_api_authenticator=access)

        def request(method, path, *, token, body=None):
            handler = handler_type.__new__(handler_type)
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
            captured = {"status": None}
            handler.send_response = lambda status: captured.update(status=status)
            handler.send_header = lambda key, value: None
            handler.end_headers = lambda: None
            getattr(handler, "do_%s" % method)()
            return captured["status"], json.loads(handler.wfile.getvalue())

        status, _ = request(
            "POST",
            "/v1/authorize",
            token=TOKEN,
            body=forge_scenarios()["mcp_schema_drift"].model_dump(mode="json"),
        )
        self.assertEqual(status, 200)
        status, capabilities = request(
            "GET", "/api/v1/capabilities", token=external_token
        )
        self.assertEqual(status, 200)
        self.assertFalse(capabilities["raw_content_exported"])
        status, events = request(
            "GET", "/api/v1/events/stream?limit=10", token=external_token
        )
        self.assertEqual(status, 200)
        self.assertEqual(events["count"], 1)
        status, integrations = request(
            "GET", "/api/v1/integrations", token=external_token
        )
        self.assertEqual(status, 200)
        self.assertIn("destinations", integrations)
        status, _ = request(
            "POST", "/api/v1/search", token=external_token, body={}
        )
        self.assertEqual(status, 403)
        status, _ = request(
            "GET", "/api/v1/events", token=TOKEN
        )
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
