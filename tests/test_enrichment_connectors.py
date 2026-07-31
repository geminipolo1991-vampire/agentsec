from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from email.message import Message
from io import BytesIO
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from agentsec.contracts import DecisionAction, EnrichmentStatus
from agentsec.enrichment import (
    ENRICHMENT_ADMIN,
    ENRICHMENT_EXECUTE,
    ENRICHMENT_READ,
    CallableEnrichmentConnector,
    CircuitState,
    EnrichmentAuthorizationError,
    EnrichmentConnectorPayload,
    EnrichmentConnectorSpec,
    EnrichmentEngine,
    EnrichmentPrincipal,
    HttpJsonEnrichmentConnector,
    evidence_ref,
)
from agentsec.scenarios import forge_scenarios
from agentsec.pipeline import SecurityPipeline
from agentsec.service import application_from_environment, make_handler


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 24, 12, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


def principal(tenant_id: str, *connector_names: str) -> EnrichmentPrincipal:
    return EnrichmentPrincipal(
        tenant_id=tenant_id,
        actor_id="system://enrichment-test",
        permissions={ENRICHMENT_READ, ENRICHMENT_EXECUTE, ENRICHMENT_ADMIN},
        allowed_connectors=set(connector_names),
        allowed_input_fields={
            "event_ref", "agent_ref", "destination_ref", "operation",
            "resource_class", "source_trust", "data_classes",
        },
    )


def spec(name: str, **updates: object) -> EnrichmentConnectorSpec:
    values = {
        "name": name,
        "version": "1.0.0",
        "description": "Test metadata enrichment connector",
        "required_fields": {"agent_ref"},
        "allowed_fact_keys": {"known", "risk_level"},
        "timeout_ms": 500,
        "cache_ttl_seconds": 10,
        "max_stale_seconds": 60,
    }
    values.update(updates)
    return EnrichmentConnectorSpec.model_validate(values)


def payload(name: str, observed_at: datetime) -> EnrichmentConnectorPayload:
    return EnrichmentConnectorPayload(
        source=name,
        status=EnrichmentStatus.COMPLETE,
        facts={"known": True, "risk_level": "low"},
        evidence_refs=[evidence_ref("agent", "agent-1")],
        affects_triage=False,
        observed_at=observed_at,
    )


class EnrichmentConnectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.event = forge_scenarios()["indirect_injection_secret_egress"]
        self.clock = MutableClock()

    def test_connectors_execute_concurrently_and_receive_only_allowlisted_metadata(self) -> None:
        barrier = threading.Barrier(2)
        requests = []

        def callback(request):
            requests.append(request)
            barrier.wait(timeout=1)
            return payload(request.connector, self.clock())

        names = ("asset_inventory", "threat_reputation")
        connectors = [CallableEnrichmentConnector(spec(name), callback) for name in names]
        engine = EnrichmentEngine(
            connectors=connectors,
            principal=principal(self.event.tenant_id, *names),
            max_workers=2,
            clock=self.clock,
        )
        try:
            snapshot = engine.collect(self.event, repeat_count=1)
        finally:
            engine.close()
        self.assertEqual(snapshot.connector_sources, 2)
        self.assertEqual(snapshot.total_sources, 11)
        self.assertEqual(len(requests), 2)
        for request in requests:
            self.assertNotIn("resource", request.fields)
            self.assertNotIn("destination", request.fields)
            self.assertNotIn(self.event.agent_id, json.dumps(request.fields))
            self.assertTrue(str(request.fields["agent_ref"]).startswith("agent_sha256:"))

    def test_policy_denial_is_visible_and_cross_tenant_health_is_forbidden(self) -> None:
        called = False

        def callback(request):
            nonlocal called
            called = True
            return payload(request.connector, self.clock())

        connector = CallableEnrichmentConnector(spec("asset_inventory"), callback)
        execution = principal(self.event.tenant_id)
        engine = EnrichmentEngine(
            connectors=[connector], principal=execution, clock=self.clock
        )
        try:
            snapshot = engine.collect(self.event, repeat_count=1)
            result = snapshot.sources[-1]
            self.assertFalse(called)
            self.assertEqual(result.status, EnrichmentStatus.UNAVAILABLE)
            self.assertEqual(result.policy_decision, "policy_denied")
            with self.assertRaises(EnrichmentAuthorizationError):
                engine.health(principal("other-tenant", "asset_inventory"))
        finally:
            engine.close()

    def test_fresh_cache_then_stale_on_failure_preserves_freshness_evidence(self) -> None:
        calls = 0

        def callback(request):
            nonlocal calls
            calls += 1
            if calls > 1:
                raise RuntimeError("source unavailable")
            return payload(request.connector, self.clock())

        name = "asset_inventory"
        engine = EnrichmentEngine(
            connectors=[CallableEnrichmentConnector(spec(name), callback)],
            principal=principal(self.event.tenant_id, name),
            clock=self.clock,
        )
        try:
            first = engine.collect(self.event, repeat_count=1).sources[-1]
            second_snapshot = engine.collect(self.event, repeat_count=2)
            second = second_snapshot.sources[-1]
            self.clock.advance(11)
            third_snapshot = engine.collect(self.event, repeat_count=3)
            third = third_snapshot.sources[-1]
            health = engine.health(principal(self.event.tenant_id, name))
        finally:
            engine.close()
        self.assertEqual(first.cache_status.value, "miss")
        self.assertEqual(second.cache_status.value, "fresh")
        self.assertEqual(third.cache_status.value, "stale")
        self.assertEqual(third.status, EnrichmentStatus.PARTIAL)
        self.assertEqual(third.freshness_seconds, 11)
        self.assertEqual(second_snapshot.cache_hits, 1)
        self.assertEqual(third_snapshot.stale_fallbacks, 1)
        self.assertEqual(calls, 2)
        self.assertEqual(health.connectors[0].failures, 1)

    def test_timeout_opens_circuit_and_prevents_repeated_calls(self) -> None:
        calls = 0

        def callback(request):
            nonlocal calls
            calls += 1
            time.sleep(0.08)
            return payload(request.connector, self.clock())

        name = "slow_reputation"
        connector = CallableEnrichmentConnector(
            spec(name, timeout_ms=10, cache_ttl_seconds=0, max_stale_seconds=0),
            callback,
        )
        engine = EnrichmentEngine(
            connectors=[connector],
            principal=principal(self.event.tenant_id, name),
            max_workers=2,
            circuit_failure_threshold=2,
            clock=self.clock,
        )
        try:
            one = engine.collect(self.event, repeat_count=1)
            two = engine.collect(self.event, repeat_count=2)
            three = engine.collect(self.event, repeat_count=3)
            health = engine.health(principal(self.event.tenant_id, name))
        finally:
            engine.close()
        self.assertEqual(one.timed_out_sources, 1)
        self.assertEqual(two.timed_out_sources, 1)
        self.assertEqual(three.sources[-1].policy_decision, "circuit_open")
        self.assertEqual(calls, 2)
        self.assertEqual(health.open_circuits, 1)
        self.assertEqual(health.connectors[0].circuit_state, CircuitState.OPEN)
        self.assertEqual(health.connectors[0].timeouts, 2)

    def test_cache_and_health_survive_engine_restart(self) -> None:
        name = "asset_inventory"
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "enrichment.db")
            execution = principal(self.event.tenant_id, name)
            first = EnrichmentEngine(
                connectors=[CallableEnrichmentConnector(
                    spec(name), lambda request: payload(name, self.clock())
                )],
                principal=execution,
                database_path=database,
                clock=self.clock,
            )
            first.collect(self.event, repeat_count=1)
            first.close()
            calls = 0

            def unavailable(request):
                nonlocal calls
                calls += 1
                raise RuntimeError("must not be called while cache is fresh")

            second = EnrichmentEngine(
                connectors=[CallableEnrichmentConnector(spec(name), unavailable)],
                principal=execution,
                database_path=database,
                clock=self.clock,
            )
            try:
                snapshot = second.collect(self.event, repeat_count=2)
                health = second.health(execution)
            finally:
                second.close()
        self.assertEqual(calls, 0)
        self.assertEqual(snapshot.sources[-1].cache_status.value, "fresh")
        self.assertEqual(health.connectors[0].successes, 1)
        self.assertEqual(health.connectors[0].cache_hits, 1)

    def test_async_facade_and_output_contract_validation(self) -> None:
        name = "asset_inventory"
        connector = CallableEnrichmentConnector(
            spec(name), lambda request: payload(name, self.clock())
        )
        engine = EnrichmentEngine(
            connectors=[connector],
            principal=principal(self.event.tenant_id, name),
            clock=self.clock,
        )
        try:
            snapshot = asyncio.run(
                engine.collect_async(self.event, repeat_count=1)
            )
        finally:
            engine.close()
        self.assertEqual(snapshot.sources[-1].policy_decision, "success")
        self.assertRegex(snapshot.policy_digest or "", r"^[0-9a-f]{64}$")

        bad = CallableEnrichmentConnector(
            spec("bad_connector"),
            lambda request: EnrichmentConnectorPayload(
                source="bad_connector",
                status=EnrichmentStatus.COMPLETE,
                facts={"not_allowed": "value"},
                observed_at=self.clock(),
            ),
        )
        bad_engine = EnrichmentEngine(
            connectors=[bad],
            principal=principal(self.event.tenant_id, "bad_connector"),
            clock=self.clock,
        )
        try:
            result = bad_engine.collect(self.event, repeat_count=1).sources[-1]
        finally:
            bad_engine.close()
        self.assertEqual(result.status, EnrichmentStatus.FAILED)
        self.assertEqual(result.policy_decision, "failed")

    def test_http_json_adapter_uses_bounded_governed_contract(self) -> None:
        name = "threat_reputation"
        captured = {}

        def transport(endpoint, body, headers, timeout):
            captured.update(
                endpoint=endpoint,
                request=json.loads(body),
                authorization=headers.get("Authorization"),
                timeout=timeout,
            )
            return payload(name, self.clock()).model_dump_json().encode("utf-8")

        connector = HttpJsonEnrichmentConnector(
            spec(name),
            endpoint="https://reputation.example.test/v1/enrich",
            bearer_token="test-secret-token",
            transport=transport,
        )
        engine = EnrichmentEngine(
            connectors=[connector],
            principal=principal(self.event.tenant_id, name),
            clock=self.clock,
        )
        try:
            result = engine.collect(self.event, repeat_count=1).sources[-1]
        finally:
            engine.close()
        self.assertEqual(result.status, EnrichmentStatus.COMPLETE)
        self.assertEqual(captured["authorization"], "Bearer test-secret-token")
        self.assertNotIn("test-secret-token", json.dumps(captured["request"]))
        self.assertEqual(captured["timeout"], 0.5)
        with self.assertRaises(ValueError):
            HttpJsonEnrichmentConnector(
                spec(name), endpoint="http://127.0.0.1/enrich"
            )

    def test_registration_requires_admin_and_connector_setup_requires_principal(self) -> None:
        connector = CallableEnrichmentConnector(
            spec("asset_inventory"), lambda request: payload("asset_inventory", self.clock())
        )
        with self.assertRaises(ValueError):
            EnrichmentEngine(connectors=[connector])
        execution = principal(self.event.tenant_id)
        engine = EnrichmentEngine(principal=execution, clock=self.clock)
        denied = execution.model_copy(
            update={"permissions": {ENRICHMENT_READ, ENRICHMENT_EXECUTE}}
        )
        try:
            with self.assertRaises(EnrichmentAuthorizationError):
                engine.register_connector(denied, connector)
            engine.register_connector(execution, connector)
        finally:
            engine.close()

    def test_connector_outage_cannot_relax_pipeline_enforcement(self) -> None:
        name = "threat_reputation"
        connector = CallableEnrichmentConnector(
            spec(name, mandatory=True),
            lambda request: (_ for _ in ()).throw(RuntimeError("connector outage")),
        )
        engine = EnrichmentEngine(
            connectors=[connector],
            principal=principal(self.event.tenant_id, name),
            clock=self.clock,
        )
        pipeline = SecurityPipeline(enricher=engine)
        try:
            result = pipeline.process(self.event)
        finally:
            engine.close()
        self.assertTrue(result.alerts)
        self.assertEqual(result.overall_action, DecisionAction.DENY)
        self.assertFalse(result.effect_allowed)
        self.assertEqual(
            result.alerts[0].enrichment.sources[-1].status,
            EnrichmentStatus.FAILED,
        )
        detail = pipeline.incidents.get(result.alerts[0].finding.finding_id)
        self.assertEqual(detail.enrichment.connector_sources, 1)
        self.assertEqual(detail.enrichment.sources[-1].policy_decision, "failed")
        self.assertEqual(detail.enrichment.sources[-1].cache_status, "miss")

    def test_environment_assembly_and_authenticated_health_api(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "connectors.json"
            database_path = Path(directory) / "enrichment.db"
            config_path.write_text(
                json.dumps(
                    {
                        "allowed_input_fields": ["agent_ref"],
                        "connectors": [
                            {
                                "connector": spec("asset_inventory").model_dump(
                                    mode="json"
                                ),
                                "endpoint": "https://inventory.example.test/v1/enrich",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            environment = {
                "AGENTSEC_ENRICHMENT_DB": str(database_path),
                "AGENTSEC_ENRICHMENT_CONFIG": str(config_path),
                "AGENTSEC_ENRICHMENT_TENANT": self.event.tenant_id,
            }
            with patch.dict(os.environ, environment, clear=True):
                application = application_from_environment()
            try:
                token = "enrichment-health-token-at-least-32-characters"
                handler_type = make_handler(application, token)
                handler = handler_type.__new__(handler_type)
                handler.path = "/v1/enrichment/health"
                handler.command = "GET"
                handler.request_version = "HTTP/1.1"
                handler.headers = Message()
                handler.headers["Authorization"] = "Bearer %s" % token
                handler.rfile = BytesIO()
                handler.wfile = BytesIO()
                captured = {"status": None}
                handler.send_response = lambda status: captured.update(status=status)
                handler.send_header = lambda key, value: None
                handler.end_headers = lambda: None
                handler.do_GET()
                response = json.loads(handler.wfile.getvalue())
            finally:
                application.pipeline.enricher.close()
        self.assertEqual(captured["status"], 200)
        self.assertEqual(response["connector_count"], 1)
        self.assertEqual(response["connectors"][0]["connector"], "asset_inventory")


if __name__ == "__main__":
    unittest.main()
