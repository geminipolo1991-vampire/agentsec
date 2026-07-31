from __future__ import annotations

import json
from email.message import Message
from io import BytesIO
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
from typing import Optional
import unittest
from unittest.mock import patch

from agentsec.gateway import (
    DurableGatewayStore,
    GatewayAuthenticationError,
    GatewayEventStatus,
    IngestionGateway,
    TokenBucketRateLimiter,
    WorkloadAuthenticator,
    WorkloadCredential,
    gateway_from_environment,
    sign_workload_request,
)
from agentsec.service import AuthorizationApplication, make_handler
from agentsec.telemetry import CollectorConfig, TelemetryCollector, TelemetryEventKind, TelemetryInput


SECRET = "gateway-test-secret-that-is-at-least-thirty-two-characters"
CANARY = "RAW-GATEWAY-CONTENT-MUST-NOT-BE-PERSISTED"


class IngestionGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp.name) / "gateway.sqlite3")
        self.credential = WorkloadCredential(
            credential_id="sdk-test-key",
            secret=SECRET,
            tenant_id="tenant-a",
            source_id="sdk://python/app-a",
            application_ids={"app-a"},
        )
        self.store = DurableGatewayStore(self.database, max_queue_depth=20)
        self.authenticator = WorkloadAuthenticator([self.credential], self.store)
        self.gateway = IngestionGateway(
            store=self.store,
            authenticator=self.authenticator,
            collector=TelemetryCollector(
                CollectorConfig(allowed_attribute_keys={"provider_status"})
            ),
            rate_limiter=TokenBucketRateLimiter(capacity=20, refill_per_second=20),
        )
        self.principal = self.credential.principal

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def event(self, event_id: str = "tel_gateway_001", **overrides: object) -> TelemetryInput:
        payload = {
            "event_id": event_id,
            "context": {
                "tenant_id": "tenant-a",
                "application_id": "app-a",
                "agent_id": "agent-a",
                "session_id": "session-a",
                "trace_id": "trace-a",
                "source_id": "sdk://python/app-a",
                "source_type": "python-sdk",
                "collector_id": "collector-a",
            },
            "kind": TelemetryEventKind.MODEL_REQUEST,
            "operation": "model.generate",
            "resource": "model://test/model-a",
            "attributes": {"provider_status": "started"},
            "content": {"input": CANARY},
        }
        payload.update(overrides)
        return TelemetryInput.model_validate(payload)

    def authenticate(
        self,
        event: TelemetryInput,
        *,
        nonce: str = "nonce-authentication-0001",
        timestamp: Optional[int] = None,
        path: str = "/v1/telemetry",
    ):
        body = json.dumps(
            event.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        headers = sign_workload_request(
            self.credential,
            method="POST",
            path=path,
            body=body,
            timestamp=timestamp,
            nonce=nonce,
        )
        return self.gateway.authenticate(
            method="POST", path=path, headers=headers, body=body
        )

    def test_signed_authentication_binds_body_time_and_nonce(self) -> None:
        event = self.event()
        body = json.dumps(
            event.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        now = int(time.time())
        headers = sign_workload_request(
            self.credential,
            method="POST",
            path="/v1/telemetry",
            body=body,
            timestamp=now,
            nonce="nonce-authentication-0002",
        )
        principal = self.authenticator.authenticate(
            method="POST",
            path="/v1/telemetry",
            headers=headers,
            body=body,
            now_epoch=now,
        )
        self.assertEqual(principal.tenant_id, "tenant-a")
        with self.assertRaisesRegex(GatewayAuthenticationError, "request_replay_detected"):
            self.authenticator.authenticate(
                method="POST",
                path="/v1/telemetry",
                headers=headers,
                body=body,
                now_epoch=now,
            )

        stale_headers = sign_workload_request(
            self.credential,
            method="POST",
            path="/v1/telemetry",
            body=body,
            timestamp=now - 301,
            nonce="nonce-authentication-0003",
        )
        with self.assertRaisesRegex(
            GatewayAuthenticationError, "request_timestamp_outside_window"
        ):
            self.authenticator.authenticate(
                method="POST",
                path="/v1/telemetry",
                headers=stale_headers,
                body=body,
                now_epoch=now,
            )
        tampered = dict(headers)
        tampered["X-AgentSec-Nonce"] = "nonce-authentication-0004"
        with self.assertRaisesRegex(GatewayAuthenticationError, "invalid_workload_signature"):
            self.authenticator.authenticate(
                method="POST",
                path="/v1/telemetry",
                headers=tampered,
                body=body,
                now_epoch=now,
            )

    def test_tenant_source_and_application_are_resolved_from_credential(self) -> None:
        cases = [
            ("tenant_binding_mismatch", {"tenant_id": "tenant-b"}),
            ("source_binding_mismatch", {"source_id": "sdk://attacker"}),
            ("application_binding_mismatch", {"application_id": "app-b"}),
        ]
        for index, (reason, context_update) in enumerate(cases):
            base = self.event("tel_binding_%d" % index)
            context = base.context.model_copy(update=context_update)
            receipt = self.gateway.ingest_one(
                self.principal,
                base.model_copy(update={"context": context}).model_dump(mode="json"),
            )
            self.assertEqual(receipt.status, GatewayEventStatus.REJECTED)
            self.assertEqual(receipt.reason_codes, [reason])
        self.assertEqual(self.store.queue_summary().pending, 0)

    def test_safe_envelope_is_durable_and_raw_content_is_not_persisted(self) -> None:
        receipt = self.gateway.ingest_one(
            self.principal, self.event().model_dump(mode="json")
        )
        self.assertEqual(receipt.status, GatewayEventStatus.ACCEPTED)
        self.assertIsNotNone(receipt.queue_id)
        self.assertEqual(self.store.queue_summary().pending, 1)

        connection = sqlite3.connect(self.database)
        stored = connection.execute(
            "SELECT envelope_json, request_hash FROM gateway_events"
        ).fetchone()
        connection.close()
        self.assertNotIn(CANARY, stored[0])
        self.assertNotIn(CANARY, stored[1])
        envelope = json.loads(stored[0])
        self.assertEqual(envelope["content_evidence"][0]["byte_length"], len(json.dumps(CANARY)))
        self.assertEqual(envelope["collection_mode"], "metadata_only")

    def test_durable_idempotency_survives_restart_and_conflicts_fail_closed(self) -> None:
        event = self.event()
        first = self.gateway.ingest_one(self.principal, event.model_dump(mode="json"))
        self.assertEqual(first.status, GatewayEventStatus.ACCEPTED)
        self.store.close()

        reopened = DurableGatewayStore(self.database, max_queue_depth=20)
        self.store = reopened
        gateway = IngestionGateway(
            store=reopened,
            authenticator=WorkloadAuthenticator([self.credential], reopened),
            collector=TelemetryCollector(
                CollectorConfig(allowed_attribute_keys={"provider_status"})
            ),
        )
        duplicate = gateway.ingest_one(self.principal, event.model_dump(mode="json"))
        self.assertEqual(duplicate.status, GatewayEventStatus.DUPLICATE)
        changed = event.model_copy(update={"operation": "model.delete"})
        conflict = gateway.ingest_one(self.principal, changed.model_dump(mode="json"))
        self.assertEqual(conflict.status, GatewayEventStatus.CONFLICT)
        self.assertEqual(conflict.reason_codes, ["event_id_conflict"])
        self.assertEqual(reopened.queue_summary().pending, 1)

    def test_concurrent_duplicate_is_committed_once(self) -> None:
        payload = self.event().model_dump(mode="json")
        statuses: list[GatewayEventStatus] = []
        lock = threading.Lock()

        def ingest() -> None:
            status = self.gateway.ingest_one(self.principal, payload).status
            with lock:
                statuses.append(status)

        threads = [threading.Thread(target=ingest) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(statuses.count(GatewayEventStatus.ACCEPTED), 1)
        self.assertEqual(statuses.count(GatewayEventStatus.DUPLICATE), 7)
        self.assertEqual(self.store.queue_summary().pending, 1)

    def test_capacity_backpressure_and_rate_limits_are_observable(self) -> None:
        self.store.close()
        limited_store = DurableGatewayStore(self.database, max_queue_depth=1)
        self.store = limited_store
        gateway = IngestionGateway(
            store=limited_store,
            authenticator=WorkloadAuthenticator([self.credential], limited_store),
            collector=TelemetryCollector(
                CollectorConfig(allowed_attribute_keys={"provider_status"})
            ),
            rate_limiter=TokenBucketRateLimiter(capacity=1, refill_per_second=0.0001),
        )
        allowed, _ = gateway.admit(self.principal, cost=1)
        denied, retry_after = gateway.admit(self.principal, cost=1)
        self.assertTrue(allowed)
        self.assertFalse(denied)
        self.assertGreaterEqual(retry_after, 1)

        first = gateway.ingest_one(
            self.principal, self.event("tel_capacity_1").model_dump(mode="json")
        )
        second = gateway.ingest_one(
            self.principal, self.event("tel_capacity_2").model_dump(mode="json")
        )
        self.assertEqual(first.status, GatewayEventStatus.ACCEPTED)
        self.assertEqual(second.status, GatewayEventStatus.BACKPRESSURE)
        health = limited_store.health_for(self.principal)
        self.assertEqual(health.rate_limited_requests, 1)
        self.assertEqual(health.backpressured_events, 1)
        self.assertEqual(health.status, "degraded")

    def test_batch_is_bounded_and_reports_partial_outcomes(self) -> None:
        first = self.event("tel_batch_1").model_dump(mode="json")
        invalid = {"event_id": "tel_batch_invalid", "unknown": True}
        batch = self.gateway.ingest_batch(self.principal, [first, first, invalid])
        self.assertEqual(batch.accepted, 1)
        self.assertEqual(batch.duplicates, 1)
        self.assertEqual(batch.rejected, 1)
        self.assertEqual(len(batch.receipts), 3)
        with self.assertRaisesRegex(ValueError, "1 to 1000"):
            self.gateway.ingest_batch(self.principal, [])

    def test_queue_retry_dead_letter_redrive_and_success(self) -> None:
        receipt = self.gateway.ingest_one(
            self.principal, self.event().model_dump(mode="json")
        )
        self.assertEqual(receipt.status, GatewayEventStatus.ACCEPTED)

        succeeded, failed = self.gateway.process_once(
            lambda _event: (_ for _ in ()).throw(RuntimeError("CANARY-DOWNSTREAM-DETAIL")),
            max_attempts=2,
        )
        self.assertEqual((succeeded, failed), (0, 1))
        self.assertEqual(self.store.queue_summary().pending, 1)
        time.sleep(1.05)
        self.gateway.process_once(
            lambda _event: (_ for _ in ()).throw(RuntimeError("different raw failure")),
            max_attempts=2,
        )
        summary = self.store.queue_summary()
        self.assertEqual(summary.dead_letter, 1)
        health = self.store.health_for(self.principal)
        self.assertEqual(health.last_error_code, "downstream_processing_failed")
        self.assertNotIn("CANARY-DOWNSTREAM-DETAIL", health.model_dump_json())

        self.store.redrive(receipt.queue_id or 0)
        succeeded, failed = self.gateway.process_once(lambda _event: None)
        self.assertEqual((succeeded, failed), (1, 0))
        self.assertEqual(self.store.queue_summary().succeeded, 1)
        self.assertEqual(self.store.health_for(self.principal).processed_events, 1)

    def test_http_routes_require_workload_signature_and_expose_admin_health(self) -> None:
        token = "gateway-admin-token-at-least-thirty-two-characters"
        handler_type = make_handler(AuthorizationApplication(), token, self.gateway)

        def request(
            method: str,
            path: str,
            body: object = None,
            *,
            nonce: Optional[str] = None,
            admin: bool = False,
        ):
            handler = handler_type.__new__(handler_type)
            handler.path = path
            handler.command = method
            handler.request_version = "HTTP/1.1"
            handler.headers = Message()
            encoded = b""
            if body is not None:
                encoded = json.dumps(body, separators=(",", ":"), sort_keys=True).encode(
                    "utf-8"
                )
                handler.headers["Content-Type"] = "application/json"
                handler.headers["Content-Length"] = str(len(encoded))
            if nonce is not None:
                for key, value in sign_workload_request(
                    self.credential,
                    method=method,
                    path=path,
                    body=encoded,
                    nonce=nonce,
                ).items():
                    handler.headers[key] = value
            if admin:
                handler.headers["Authorization"] = "Bearer %s" % token
            handler.rfile = BytesIO(encoded)
            handler.wfile = BytesIO()
            captured = {"status": None, "headers": {}}
            handler.send_response = lambda status: captured.update(status=status)
            handler.send_header = (
                lambda key, value: captured["headers"].update({key: value})
            )
            handler.end_headers = lambda: None
            getattr(handler, "do_%s" % method)()
            return captured, json.loads(handler.wfile.getvalue())

        payload = self.event("tel_http_gateway_1").model_dump(mode="json")
        unauthorized, error = request("POST", "/v1/telemetry", payload)
        self.assertEqual(unauthorized["status"], 401)
        self.assertEqual(error["error"], "workload_authentication_failed")

        accepted, receipt = request(
            "POST",
            "/v1/telemetry",
            payload,
            nonce="nonce-http-telemetry-0001",
        )
        self.assertEqual(accepted["status"], 202)
        self.assertEqual(receipt["status"], "accepted")
        replayed, _ = request(
            "POST",
            "/v1/telemetry",
            payload,
            nonce="nonce-http-telemetry-0001",
        )
        self.assertEqual(replayed["status"], 401)
        duplicate, duplicate_receipt = request(
            "POST",
            "/v1/telemetry",
            payload,
            nonce="nonce-http-telemetry-0002",
        )
        self.assertEqual(duplicate["status"], 200)
        self.assertEqual(duplicate_receipt["status"], "duplicate")

        second = self.event("tel_http_gateway_2").model_dump(mode="json")
        batch, batch_response = request(
            "POST",
            "/v1/telemetry/batch",
            {"events": [second]},
            nonce="nonce-http-batch-000001",
        )
        self.assertEqual(batch["status"], 202)
        self.assertEqual(batch_response["accepted"], 1)

        health, sources = request(
            "GET", "/v1/telemetry/sources?tenant_id=tenant-a", admin=True
        )
        self.assertEqual(health["status"], 200)
        self.assertEqual(sources["sources"][0]["accepted_events"], 2)
        queue, summary = request("GET", "/v1/telemetry/queue", admin=True)
        self.assertEqual(queue["status"], 200)
        self.assertEqual(summary["pending"], 2)

    def test_environment_gateway_is_explicit_and_invalid_configuration_fails_closed(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(gateway_from_environment())

        configuration = json.dumps(
            [
                {
                    "credential_id": "environment-sdk",
                    "secret": SECRET,
                    "tenant_id": "tenant-a",
                    "source_id": "sdk://python/app-a",
                    "application_ids": ["app-a"],
                }
            ]
        )
        environment_database = str(Path(self.temp.name) / "environment.sqlite3")
        with patch.dict(
            os.environ,
            {
                "AGENTSEC_WORKLOAD_CREDENTIALS_JSON": configuration,
                "AGENTSEC_GATEWAY_DB": environment_database,
                "AGENTSEC_GATEWAY_QUEUE_DEPTH": "25",
            },
            clear=True,
        ):
            gateway = gateway_from_environment()
        self.assertIsNotNone(gateway)
        assert gateway is not None
        self.assertEqual(gateway.store.queue_summary().capacity, 25)
        gateway.store.close()

        with patch.dict(
            os.environ,
            {"AGENTSEC_WORKLOAD_CREDENTIALS_JSON": "not-json-SECRET-CANARY"},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "AGENTSEC.*invalid") as raised:
                gateway_from_environment()
        self.assertNotIn("SECRET-CANARY", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
