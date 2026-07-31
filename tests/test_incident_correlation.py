from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from io import BytesIO
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from agentsec.correlation import (
    CORRELATION_ADMIN,
    CORRELATION_READ,
    CORRELATION_WRITE,
    CorrelationAuthorizationError,
    CorrelationIncidentStatus,
    CorrelationOutcome,
    CorrelationPrincipal,
    IncidentCorrelationService,
)
from agentsec.pipeline import SecurityPipeline
from agentsec.scenarios import forge_scenarios
from agentsec.service import AuthorizationApplication, application_from_environment, make_handler


HTTP_TOKEN = "module-twelve-correlation-http-token-at-least-32-characters"


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 24, 10, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value


class IncidentCorrelationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.service = IncidentCorrelationService(
            self.temp.name + "/correlation.sqlite3", clock=self.clock
        )
        self.principal = CorrelationPrincipal(
            tenant_id="tenant-lab",
            actor_id="system://correlation-test",
            permissions={CORRELATION_READ, CORRELATION_WRITE, CORRELATION_ADMIN},
        )
        self.pipeline = SecurityPipeline()

    def tearDown(self) -> None:
        self.service.close()
        self.temp.cleanup()

    def results(self, scenario: str):
        return self.pipeline.process(forge_scenarios()[scenario]).alerts

    def test_same_flow_findings_form_explainable_multi_finding_incident(self) -> None:
        results = self.results("indirect_injection_secret_egress")
        decisions = [self.service.correlate(self.principal, item) for item in results]
        self.assertEqual(
            [item.outcome for item in decisions],
            [CorrelationOutcome.CREATED, CorrelationOutcome.ATTACHED],
        )
        self.assertIn("same_flow", decisions[1].reasons)
        incident = self.service.get(self.principal, decisions[0].incident_id)
        self.assertEqual(incident.finding_count, 2)
        self.assertEqual(
            [item.finding_id for item in incident.attack_sequence],
            [item.finding.finding_id for item in results],
        )
        self.assertGreaterEqual(incident.risk_score, max(item.triage.risk_score for item in results))
        self.assertEqual({item.stage.value for item in incident.attack_sequence}, {"initial_access", "exfiltration"})
        encoded = incident.model_dump_json()
        self.assertNotIn("receiver.invalid", encoded)
        self.assertNotIn("document://", encoded)
        self.assertIn("_sha256:", encoded)

    def test_closed_incident_reopens_on_new_matching_finding(self) -> None:
        first = self.results("mcp_schema_drift")[0]
        decision = self.service.correlate(self.principal, first)
        self.service.transition(
            self.principal,
            decision.incident_id,
            CorrelationIncidentStatus.CLOSED,
            reason="Reviewed schema change and closed the incident.",
        )
        event = forge_scenarios()["mcp_schema_drift"].model_copy(
            update={
                "event_id": "evt_correlation_reopen",
                "resource": "diagnostic://bundle/reopened",
                "occurred_at": self.clock.value + timedelta(minutes=5),
            }
        )
        second = SecurityPipeline().process(event).alerts[0]
        reopened = self.service.correlate(self.principal, second)
        self.assertEqual(reopened.outcome, CorrelationOutcome.REOPENED)
        incident = self.service.get(self.principal, decision.incident_id)
        self.assertEqual(incident.status, CorrelationIncidentStatus.OPEN)
        self.assertEqual(incident.reopened_count, 1)
        self.assertIsNone(incident.closed_at)

    def test_time_bounded_suppression_records_decision_without_incident(self) -> None:
        rule = self.service.create_suppression(
            self.principal,
            alert_type="mcp_schema_drift",
            reason="Approved test tenant emits this known schema migration signal.",
            expires_at=self.clock.value + timedelta(days=2),
        )
        result = self.results("mcp_schema_drift")[0]
        decision = self.service.correlate(self.principal, result)
        self.assertEqual(decision.outcome, CorrelationOutcome.SUPPRESSED)
        self.assertEqual(decision.suppression_id, rule.suppression_id)
        self.assertIsNone(decision.incident_id)
        self.assertEqual(self.service.health(self.principal).suppressed_findings, 1)
        revoked = self.service.revoke_suppression(
            self.principal, rule.suppression_id, reason="Schema migration completed."
        )
        self.assertFalse(revoked.active)

    def test_merge_and_split_preserve_links_history_and_risk_rollup(self) -> None:
        one = self.results("persistent_memory_poisoning")[0]
        two = self.results("mcp_schema_drift")[0]
        first = self.service.correlate(self.principal, one)
        second = self.service.correlate(self.principal, two)
        self.assertNotEqual(first.incident_id, second.incident_id)
        merged = self.service.merge(
            self.principal,
            [first.incident_id, second.incident_id],
            reason="Analyst evidence confirms one coordinated campaign.",
        )
        self.assertEqual(merged.finding_count, 2)
        source_id = second.incident_id if merged.incident_id == first.incident_id else first.incident_id
        self.assertEqual(
            self.service.get(self.principal, source_id).status,
            CorrelationIncidentStatus.MERGED,
        )
        retained, child = self.service.split(
            self.principal,
            merged.incident_id,
            [two.finding.finding_id],
            reason="Independent evidence shows the schema event is unrelated.",
        )
        self.assertEqual((retained.finding_count, child.finding_count), (1, 1))
        self.assertEqual(child.parent_incident_id, retained.incident_id)

    def test_durable_digest_tenant_permissions_and_idempotency_fail_closed(self) -> None:
        result = self.results("mcp_schema_drift")[0]
        reader = self.principal.model_copy(update={"permissions": {CORRELATION_READ}})
        with self.assertRaises(CorrelationAuthorizationError):
            self.service.correlate(reader, result)
        other = self.principal.model_copy(update={"tenant_id": "tenant-other"})
        with self.assertRaises(CorrelationAuthorizationError):
            self.service.correlate(other, result)

        def correlate(_index):
            return self.service.correlate(self.principal, result).decision_id

        with ThreadPoolExecutor(max_workers=6) as pool:
            identifiers = list(pool.map(correlate, range(10)))
        self.assertEqual(len(set(identifiers)), 1)
        decision = self.service.correlate(self.principal, result)
        incident_id = decision.incident_id
        self.service.close()
        self.service = IncidentCorrelationService(
            self.temp.name + "/correlation.sqlite3", clock=self.clock
        )
        self.assertEqual(self.service.get(self.principal, incident_id).finding_count, 1)
        row = self.service._connection.execute(
            "SELECT incident_json FROM correlated_incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        self.service._connection.execute(
            "UPDATE correlated_incidents SET incident_json = ? WHERE incident_id = ?",
            (row["incident_json"].replace('"risk_score":', '"risk_score":9'), incident_id),
        )
        with self.assertRaises((ValueError, Exception)):
            self.service.get(self.principal, incident_id)

    def test_bounds_and_invalid_governance_requests_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.service.create_suppression(
                self.principal,
                alert_type="mcp_schema_drift",
                reason="Expiry exceeds the bounded suppression horizon.",
                expires_at=self.clock.value + timedelta(days=91),
            )
        with self.assertRaises(ValueError):
            self.service.merge(self.principal, ["inc_one"], reason="Not enough incidents")
        with self.assertRaises(ValueError):
            self.service.list_incidents(self.principal, limit=201)

    def test_pipeline_and_authenticated_api_expose_first_class_incidents(self) -> None:
        application = AuthorizationApplication(
            correlation_service=self.service,
            correlation_principal=self.principal,
        )
        handler = make_handler(application, HTTP_TOKEN)

        def request(path: str, *, method: str = "GET", body=None, auth: bool = True):
            headers = ["Host: 127.0.0.1"]
            if auth:
                headers.append("Authorization: Bearer %s" % HTTP_TOKEN)
            encoded = b""
            if body is not None:
                encoded = json.dumps(body).encode()
                headers.extend(["Content-Type: application/json", "Content-Length: %d" % len(encoded)])
            raw = ("%s %s HTTP/1.1\r\n%s\r\n\r\n" % (method, path, "\r\n".join(headers))).encode() + encoded

            class Socket:
                def __init__(self):
                    self.reader, self.sent = BytesIO(raw), BytesIO()
                def makefile(self, mode, *_args, **_kwargs):
                    return self.reader if "r" in mode else self.sent
                def sendall(self, data):
                    self.sent.write(data)
            connection = Socket()
            handler(connection, ("127.0.0.1", 12345), type("Server", (), {"server_name": "test", "server_port": 80})())
            head, payload = connection.sent.getvalue().split(b"\r\n\r\n", 1)
            return int(head.splitlines()[0].split()[1]), json.loads(payload)

        status, unauthorized = request("/v1/correlation/health", auth=False)
        self.assertEqual((status, unauthorized["error"]), (401, "unauthorized"))
        event = forge_scenarios()["indirect_injection_secret_egress"]
        status, authorized = request("/v1/authorize", method="POST", body=event.model_dump(mode="json"))
        self.assertEqual(status, 200)
        self.assertEqual(len(authorized["alerts"]), 2)
        status, listed = request("/v1/correlation/incidents")
        self.assertEqual((status, len(listed["incidents"])), (200, 1))
        incident_id = listed["incidents"][0]["incident_id"]
        self.assertEqual(listed["incidents"][0]["finding_count"], 2)
        status, detail = request("/v1/correlation/incidents/%s" % incident_id)
        self.assertEqual((status, detail["incident_id"]), (200, incident_id))
        status, decisions = request("/v1/correlation/decisions")
        self.assertEqual((status, len(decisions["decisions"])), (200, 2))
        status, closed = request(
            "/v1/correlation/incidents/%s/transition" % incident_id,
            method="POST",
            body={"status": "closed", "reason": "Analyst verified and closed the campaign."},
        )
        self.assertEqual((status, closed["status"]), (200, "closed"))

    def test_correlation_environment_is_explicit_and_outage_is_non_executive(self) -> None:
        path = self.temp.name + "/environment-correlation.sqlite3"
        with patch.dict(
            os.environ,
            {"AGENTSEC_CORRELATION_DB": path, "AGENTSEC_CORRELATION_TENANT": "tenant-lab"},
            clear=True,
        ):
            application = application_from_environment()
        try:
            self.assertEqual(application.correlation_health().tenant_id, "tenant-lab")
        finally:
            application.correlation_service.close()

        class BrokenCorrelation:
            def correlate(self, _principal, _result):
                raise RuntimeError("private database detail")

        pipeline = SecurityPipeline(
            correlation_service=BrokenCorrelation(),  # type: ignore[arg-type]
            correlation_principal=self.principal,
        )
        result = pipeline.process(forge_scenarios()["mcp_schema_drift"])
        self.assertFalse(result.effect_allowed)
        self.assertEqual(pipeline.last_correlation_error, "incident_correlation_unavailable")
        self.assertNotIn("private database detail", result.model_dump_json())


if __name__ == "__main__":
    unittest.main()
