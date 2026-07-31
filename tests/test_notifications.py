from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
from io import BytesIO
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from agentsec.notifications import (
    NOTIFICATION_ACK,
    NOTIFICATION_ADMIN,
    NOTIFICATION_DELIVER,
    NOTIFICATION_READ,
    NOTIFICATION_ROUTE,
    AcknowledgmentState,
    ConnectorResult,
    DeliveryStatus,
    EmailNotificationConnector,
    HttpNotificationConnector,
    NotificationAuthorizationError,
    NotificationConflictError,
    NotificationPrincipal,
    NotificationService,
    TicketNotificationConnector,
    load_notification_policy,
    notification_service_from_environment,
    validate_notification_endpoint,
)
from agentsec.pipeline import SecurityPipeline
from agentsec.scenarios import forge_scenarios
from agentsec.service import AuthorizationApplication, application_from_environment, make_handler


ALL_PERMISSIONS = {
    NOTIFICATION_READ,
    NOTIFICATION_ROUTE,
    NOTIFICATION_DELIVER,
    NOTIFICATION_ACK,
    NOTIFICATION_ADMIN,
}


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value


class RecordingConnector:
    def __init__(self, result: ConnectorResult) -> None:
        self.result = result
        self.calls = []

    def send(self, destination, message):
        self.calls.append((destination, message))
        return self.result


class RecordingTransport:
    def __init__(self, response=None, error=None) -> None:
        self.response = response or {
            "accepted": True,
            "acknowledged": True,
            "reference": "provider-reference",
            "receipt": "provider-receipt",
        }
        self.error = error
        self.calls = []

    def post(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise RuntimeError(self.error)
        return self.response


class NotificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.policy = load_notification_policy("configs/notification-policy.example.json")
        self.connectors = {}
        for destination in self.policy.destinations:
            acknowledged = destination.channel.value == "ticket"
            self.connectors[destination.destination_id] = RecordingConnector(
                ConnectorResult(
                    accepted=True,
                    acknowledged=acknowledged,
                    provider_reference="reference-%s" % destination.channel.value,
                    provider_receipt="receipt-%s" % destination.channel.value,
                )
            )
        self.service = NotificationService(
            self.temp.name + "/notifications.sqlite3",
            policy=self.policy,
            connectors=self.connectors,
            clock=self.clock,
        )
        self.principal = NotificationPrincipal(
            tenant_id="tenant-lab",
            actor_id="system://notification-test",
            permissions=ALL_PERMISSIONS,
        )

    def tearDown(self) -> None:
        self.service.close()
        self.temp.cleanup()

    @staticmethod
    def result(name: str = "indirect_injection_secret_egress"):
        return SecurityPipeline().process(forge_scenarios()[name]).alerts[0]

    def enqueue(self, name: str = "indirect_injection_secret_egress"):
        result = self.result(name)
        return self.service.enqueue_from_pipeline(
            self.principal,
            result,
            case_id=result.escalation.case_id,
        )

    def test_policy_routes_four_channels_templates_on_call_and_is_idempotent(self) -> None:
        record = self.enqueue()
        self.assertIsNotNone(record)
        assert record is not None
        repeated = self.enqueue()
        self.assertEqual(repeated.notification_id, record.notification_id)
        detail = self.service.get(self.principal, record.notification_id)
        self.assertEqual(len(detail.deliveries), 4)
        self.assertEqual(
            {item.channel.value for item in detail.deliveries},
            {"on_call", "ticket", "email", "messaging"},
        )
        self.assertEqual(record.on_call_actor, "analyst://backup-on-call")
        self.assertEqual(record.audit_count, 1)
        encoded = detail.model_dump_json().lower()
        source = self.result().event.source_id.lower()
        resource = self.result().event.resource.lower()
        self.assertNotIn(source, encoded)
        self.assertNotIn(resource, encoded)
        self.assertNotIn("authorization", encoded)
        self.assertNotIn("agentsec_notification_on_call_token", encoded)

        self.service.close()
        self.service = NotificationService(
            self.temp.name + "/notifications.sqlite3",
            policy=self.policy,
            connectors=self.connectors,
            clock=self.clock,
        )
        restarted = self.service.get(self.principal, record.notification_id)
        self.assertEqual(restarted.notification.record_sha256, record.record_sha256)

    def test_delivery_provider_ack_human_ack_and_health(self) -> None:
        record = self.enqueue()
        assert record is not None
        outcome = self.service.process_due(self.principal, limit=10)
        self.assertEqual((outcome.claimed, outcome.ack_pending), (4, 2))
        detail = self.service.get(self.principal, record.notification_id)
        on_call = next(item for item in detail.deliveries if item.channel.value == "on_call")
        self.assertEqual(on_call.status, DeliveryStatus.ACK_PENDING)
        receipt_sha256 = hashlib.sha256(b"callback-receipt").hexdigest()
        on_call = self.service.acknowledge_provider_delivery(
            self.principal,
            on_call.delivery_id,
            provider_receipt_sha256=receipt_sha256,
        )
        self.assertEqual(on_call.status, DeliveryStatus.ACKNOWLEDGED)

        analyst = NotificationPrincipal(
            tenant_id="tenant-lab",
            actor_id=record.on_call_actor,
            permissions={NOTIFICATION_READ, NOTIFICATION_ACK},
        )
        record = self.service.acknowledge(
            analyst,
            record.notification_id,
            expected_version=self.service.get(analyst, record.notification_id).notification.version,
            note="I own the AI-security investigation and response coordination.",
        )
        self.assertEqual(record.acknowledgment_state, AcknowledgmentState.ACKNOWLEDGED)
        self.assertEqual(record.acknowledged_by, analyst.actor_id)
        health = self.service.health(self.principal)
        self.assertEqual((health.dead_letters, health.human_ack_breaches), (0, 0))

    def test_retry_dead_letter_redrive_and_attempt_audit(self) -> None:
        route = self.policy.routes[0].model_copy(
            update={
                "destination_templates": {
                    "destination://ticket/primary": "template://ticket/critical"
                },
                "max_attempts": 2,
                "retry_base_seconds": 1,
            }
        )
        policy = self.policy.model_copy(
            update={"routes": [route], "policy_sha256": "0" * 64}
        )
        failure = RecordingConnector(
            ConnectorResult(accepted=False, error_code="simulated_outage")
        )
        self.service.close()
        self.service = NotificationService(
            self.temp.name + "/retry.sqlite3",
            policy=policy,
            connectors={"destination://ticket/primary": failure},
            clock=self.clock,
        )
        record = self.enqueue()
        assert record is not None
        first = self.service.process_due(self.principal)
        self.assertEqual(first.retry_scheduled, 1)
        self.clock.value += timedelta(seconds=2)
        second = self.service.process_due(self.principal)
        self.assertEqual(second.dead_lettered, 1)
        detail = self.service.get(self.principal, record.notification_id)
        delivery = detail.deliveries[0]
        self.assertEqual((delivery.status, len(detail.attempts)), (DeliveryStatus.DEAD_LETTER, 2))
        self.service.redrive(
            self.principal,
            delivery.delivery_id,
            reason="Connector recovery was validated before replay.",
        )
        self.service.connectors[delivery.destination_id] = RecordingConnector(
            ConnectorResult(
                accepted=True,
                acknowledged=True,
                provider_reference="recovered-reference",
                provider_receipt="recovered-receipt",
            )
        )
        final = self.service.process_due(self.principal)
        self.assertEqual(final.delivered, 1)
        detail = self.service.get(self.principal, record.notification_id)
        self.assertEqual(detail.deliveries[0].redrive_count, 1)
        self.assertIn("delivery_redriven", [item.action for item in detail.audit])

    def test_stale_in_flight_claim_is_recovered_with_same_idempotency_key(self) -> None:
        record = self.enqueue()
        assert record is not None
        detail = self.service.get(self.principal, record.notification_id)
        delivery = detail.deliveries[0]
        stale_time = self.clock.value - timedelta(seconds=61)
        unsigned = delivery.model_copy(
            update={
                "status": DeliveryStatus.IN_FLIGHT,
                "updated_at": stale_time,
                "delivery_sha256": "0" * 64,
            }
        )
        signed = self.service._signed(unsigned, "delivery_sha256")
        self.service._persist_delivery(signed)
        result = self.service.process_due(self.principal, limit=1)
        self.assertEqual(result.claimed, 1)
        recovered = self.service.get(self.principal, record.notification_id)
        self.assertIn("delivery_lease_recovered", [item.action for item in recovered.audit])

    def test_concurrent_workers_deliver_each_outbox_item_once(self) -> None:
        route = self.policy.routes[0].model_copy(
            update={
                "destination_templates": {
                    "destination://email/security": "template://email/security"
                }
            }
        )
        policy = self.policy.model_copy(
            update={"routes": [route], "policy_sha256": "0" * 64}
        )
        connector = RecordingConnector(
            ConnectorResult(
                accepted=True,
                provider_reference="single-reference",
                provider_receipt="single-receipt",
            )
        )
        self.service.close()
        path = self.temp.name + "/workers.sqlite3"
        self.service = NotificationService(
            path,
            policy=policy,
            connectors={"destination://email/security": connector},
            clock=self.clock,
        )
        self.enqueue()
        second = NotificationService(
            path,
            policy=policy,
            connectors={"destination://email/security": connector},
            clock=self.clock,
        )
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                list(pool.map(lambda service: service.process_due(self.principal, limit=1), [self.service, second]))
            self.assertEqual(len(connector.calls), 1)
        finally:
            second.close()

    def test_permissions_tenant_page_count_sla_and_tamper_fail_closed(self) -> None:
        records = [
            self.enqueue(name)
            for name in (
                "indirect_injection_secret_egress",
                "persistent_memory_poisoning",
                "mcp_schema_drift",
            )
        ]
        page = self.service.list(self.principal, limit=1)
        self.assertEqual((len(page.notifications), page.count), (1, 3))
        reader = self.principal.model_copy(update={"permissions": {NOTIFICATION_READ}})
        with self.assertRaises(NotificationAuthorizationError):
            self.service.process_due(reader)
        outsider = self.principal.model_copy(update={"tenant_id": "tenant-other"})
        with self.assertRaises(KeyError):
            self.service.get(outsider, records[0].notification_id)
        self.clock.value = records[0].acknowledgment_due_at + timedelta(seconds=1)
        breached = self.service.get(self.principal, records[0].notification_id)
        self.assertEqual(breached.notification.acknowledgment_state, AcknowledgmentState.BREACHED)

        self.service._connection.execute(
            "DELETE FROM notification_audit WHERE tenant_id=? AND notification_id=? AND sequence=1",
            (self.principal.tenant_id, records[0].notification_id),
        )
        with self.assertRaises(ValueError):
            self.service.get(self.principal, records[0].notification_id)

    def test_http_connectors_are_typed_bounded_and_secret_safe(self) -> None:
        destination = next(
            item for item in self.policy.destinations if item.channel.value == "email"
        )
        record = self.enqueue()
        assert record is not None
        message = self.service._render(
            record,
            destination,
            next(item for item in self.policy.templates if item.channel.value == "email"),
        )
        transport = RecordingTransport()
        connector = EmailNotificationConnector(
            credential="email-test-token-never-serialize",
            transport=transport,
        )
        result = connector.send(destination, message)
        self.assertTrue(result.acknowledged)
        encoded = json.dumps(transport.calls[0]["payload"])
        self.assertNotIn("email-test-token-never-serialize", encoded)
        self.assertIn("email-test-token-never-serialize", transport.calls[0]["headers"]["Authorization"])
        wrong = TicketNotificationConnector(
            credential="ticket-test-token-long-enough", transport=transport
        ).send(destination, message)
        self.assertEqual(wrong.error_code, "notification_channel_mismatch")

        with self.assertRaises(ValueError):
            validate_notification_endpoint("http://mail.example.invalid/v1/events", ["mail.example.invalid"])
        with self.assertRaises(ValueError):
            validate_notification_endpoint("https://169.254.169.254/v1/events", ["169.254.169.254"])
        invalid = HttpNotificationConnector(
            credential="generic-test-token-long-enough",
            transport=RecordingTransport(response={"accepted": True, "unexpected": "secret"}),
        ).send(destination, message)
        self.assertEqual(invalid.error_code, "notification_response_invalid")

    def test_environment_factory_exposes_missing_credentials_as_not_ready(self) -> None:
        service, principal = notification_service_from_environment(
            self.temp.name + "/environment.sqlite3",
            policy_path="configs/notification-policy.example.json",
            tenant_id="tenant-lab",
            environment={},
        )
        try:
            health = service.health(principal)
            self.assertEqual(
                (health.configured_destinations, health.ready_destinations), (4, 0)
            )
        finally:
            service.close()

    def test_pipeline_enqueues_after_decision_and_outage_is_non_executive(self) -> None:
        pipeline = SecurityPipeline(
            notification_service=self.service,
            notification_principal=self.principal,
        )
        result = pipeline.process(
            forge_scenarios()["indirect_injection_secret_egress"]
        )
        self.assertFalse(result.effect_allowed)
        self.assertIsNone(pipeline.last_notification_error)
        self.assertEqual(self.service.list(self.principal).count, 2)

        class BrokenNotifications:
            def enqueue_from_pipeline(self, *_args, **_kwargs):
                raise RuntimeError("private connector failure")

        broken = SecurityPipeline(
            notification_service=BrokenNotifications(),  # type: ignore[arg-type]
            notification_principal=self.principal,
        )
        blocked = broken.process(forge_scenarios()["mcp_schema_drift"])
        self.assertFalse(blocked.effect_allowed)
        self.assertEqual(
            broken.last_notification_error, "notification_routing_unavailable"
        )
        self.assertNotIn("private connector failure", blocked.model_dump_json())

    def test_authenticated_notification_http_api_is_strict_and_secret_safe(self) -> None:
        token = "module-eighteen-http-token-at-least-32-characters"
        application = AuthorizationApplication(
            notification_service=self.service,
            notification_principal=self.principal,
        )
        handler = make_handler(application, token)

        def request(path: str, *, method: str = "GET", body=None, auth: bool = True):
            headers = ["Host: 127.0.0.1"]
            if auth:
                headers.append("Authorization: Bearer %s" % token)
            encoded = b""
            if body is not None:
                encoded = json.dumps(body).encode()
                headers.extend(
                    ["Content-Type: application/json", "Content-Length: %d" % len(encoded)]
                )
            raw = (
                "%s %s HTTP/1.1\r\n%s\r\n\r\n" % (method, path, "\r\n".join(headers))
            ).encode() + encoded

            class Socket:
                def __init__(self):
                    self.reader, self.sent = BytesIO(raw), BytesIO()

                def makefile(self, mode, *_args, **_kwargs):
                    return self.reader if "r" in mode else self.sent

                def sendall(self, data):
                    self.sent.write(data)

            connection = Socket()
            handler(
                connection,
                ("127.0.0.1", 12345),
                type("Server", (), {"server_name": "test", "server_port": 80})(),
            )
            head, payload = connection.sent.getvalue().split(b"\r\n\r\n", 1)
            return int(head.splitlines()[0].split()[1]), json.loads(payload)

        self.assertEqual(request("/v1/notifications", auth=False)[0], 401)
        event = forge_scenarios()["mcp_schema_drift"]
        self.assertEqual(
            request(
                "/v1/authorize",
                method="POST",
                body=event.model_dump(mode="json"),
            )[0],
            200,
        )
        status, page = request("/v1/notifications")
        self.assertEqual((status, page["count"]), (200, 1))
        notification = page["notifications"][0]
        status, detail = request(
            "/v1/notifications/%s" % notification["notification_id"]
        )
        self.assertEqual((status, len(detail["deliveries"])), (200, 2))
        status, destinations = request("/v1/notification-destinations")
        self.assertEqual((status, len(destinations["destinations"])), (200, 4))
        self.assertNotIn("credential_env", json.dumps(destinations))
        status, invalid = request(
            "/v1/notifications/process",
            method="POST",
            body={"limit": 5, "actor_id": "analyst://spoofed"},
        )
        self.assertEqual((status, invalid["error"]), (400, "invalid_request"))

    def test_application_environment_assembles_notification_store(self) -> None:
        values = {
            "AGENTSEC_NOTIFICATION_DB": self.temp.name + "/environment.sqlite3",
            "AGENTSEC_NOTIFICATION_CONFIG": "configs/notification-policy.example.json",
            "AGENTSEC_NOTIFICATION_TENANT": "tenant-lab",
            "AGENTSEC_ON_CALL_CONNECTOR_TOKEN": "on-call-environment-token-long-enough",
            "AGENTSEC_TICKET_CONNECTOR_TOKEN": "ticket-environment-token-long-enough",
            "AGENTSEC_EMAIL_CONNECTOR_TOKEN": "email-environment-token-long-enough",
            "AGENTSEC_MESSAGE_CONNECTOR_TOKEN": "message-environment-token-long-enough",
        }
        with patch.dict(os.environ, values, clear=True):
            application = application_from_environment()
        try:
            health = application.notification_health()
            self.assertEqual((health.configured_destinations, health.ready_destinations), (4, 4))
        finally:
            application.notification_service.close()


if __name__ == "__main__":
    unittest.main()
