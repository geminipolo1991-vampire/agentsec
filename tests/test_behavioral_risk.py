from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from io import BytesIO
import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

from pydantic import ValidationError

from agentsec.behavior import (
    BEHAVIOR_ADMIN,
    BEHAVIOR_ANALYZE,
    BEHAVIOR_READ,
    BaselineState,
    BehaviorAuthorizationError,
    BehaviorPrincipal,
    BehaviorTuningInput,
    BehavioralRiskService,
    DriftState,
    LearningStatus,
)
from agentsec.contracts import AgentEvent, TrustClass
from agentsec.pipeline import SecurityPipeline
from agentsec.service import AuthorizationApplication, application_from_environment, make_handler


HTTP_TOKEN = "module-eleven-behavior-http-token-at-least-32-characters"


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 24, 8, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value


class BehavioralRiskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.clock = MutableClock()
        self.path = self.temp.name + "/behavior.sqlite3"
        self.service = BehavioralRiskService(self.path, clock=self.clock)
        self.principal = BehaviorPrincipal(
            tenant_id="tenant-lab",
            actor_id="system://behavior-test",
            permissions={BEHAVIOR_READ, BEHAVIOR_ANALYZE, BEHAVIOR_ADMIN},
        )
        self.service.install_default(self.principal)

    def tearDown(self) -> None:
        self.service.close()
        self.temp.cleanup()

    def event(self, suffix: str, **updates) -> AgentEvent:
        payload = {
            "event_id": "evt_behavior_%s" % suffix,
            "occurred_at": self.clock.value,
            "tenant_id": "tenant-lab",
            "flow_id": "flow-behavior-%s" % suffix,
            "agent_id": "agent-behavior",
            "operation": "asset.read",
            "resource": "asset://inventory/host",
            "source_type": "user",
            "source_id": "user://behavior-analyst",
            "source_trust": TrustClass.AUTHENTICATED_USER,
            "authority_operations": {"asset.read"},
            "is_effectful": False,
        }
        payload.update(updates)
        return AgentEvent(**payload)

    def learn_benign(self, count: int = 5) -> None:
        for index in range(count):
            event = self.event("train_%02d" % index)
            assessment = self.service.analyze(self.principal, event)
            learned = self.service.learn(
                self.principal,
                event,
                assessment,
                eligible=True,
                reason="Allowed test event contains no security alert.",
            )
            self.assertEqual(learned.learning_status, LearningStatus.LEARNED)
            self.clock.value += timedelta(minutes=1)

    def anomalous_event(self, suffix: str = "anomaly") -> AgentEvent:
        return self.event(
            suffix,
            operation="external.send",
            resource="secret://credential/report",
            destination="https://receiver.invalid/collect",
            source_trust=TrustClass.EXTERNAL_UNTRUSTED,
            data_classes={"secret"},
            authority_operations={"asset.read"},
            is_effectful=True,
        )

    def test_evaluate_before_learn_produces_explainable_composite_anomaly(self) -> None:
        self.learn_benign()
        assessment = self.service.analyze(self.principal, self.anomalous_event())
        self.assertTrue(assessment.is_anomaly)
        self.assertFalse(assessment.cold_start)
        self.assertGreaterEqual(assessment.anomaly_score, 55)
        self.assertGreaterEqual(assessment.composite_risk_score, assessment.anomaly_score)
        factors = {item.factor for item in assessment.factors}
        self.assertIn("rare_operation", factors)
        self.assertIn("rare_destination", factors)
        self.assertIn("rare_authority_gap", factors)
        self.assertTrue(all("receiver.invalid" not in item.observed for item in assessment.factors))
        alert = self.service.alert_for(assessment, self.anomalous_event())
        self.assertEqual(alert.alert_type, "behavioral_anomaly")
        self.assertIn(alert.recommended_action.value, {"require_approval", "deny"})

    def test_cold_start_never_alerts_and_learning_eligibility_is_final(self) -> None:
        event = self.anomalous_event("cold")
        assessment = self.service.analyze(self.principal, event)
        self.assertTrue(assessment.cold_start)
        self.assertFalse(assessment.is_anomaly)
        self.assertIsNone(self.service.alert_for(assessment, event))
        rejected = self.service.learn(
            self.principal,
            event,
            assessment,
            eligible=False,
            reason="Restrictive security outcome excludes this event from learning.",
        )
        self.assertEqual(rejected.learning_status, LearningStatus.REJECTED)
        self.assertEqual(self.service.health(self.principal).total_baselines, 0)
        same = self.service.learn(
            self.principal,
            event,
            assessment,
            eligible=False,
            reason="Restrictive security outcome excludes this event from learning.",
        )
        self.assertEqual(same.learning_status, LearningStatus.REJECTED)
        with self.assertRaisesRegex(ValueError, "already final"):
            self.service.learn(
                self.principal,
                event,
                assessment,
                eligible=True,
                reason="Attempted contradictory learning decision is refused.",
            )

    def test_baselines_are_durable_versioned_hashed_and_privacy_safe(self) -> None:
        self.learn_benign()
        baselines = self.service.list_baselines(self.principal)
        self.assertEqual(len(baselines), 2)
        self.assertTrue(all(item.state == BaselineState.ACTIVE for item in baselines))
        self.assertTrue(all(item.observation_count == 5 for item in baselines))
        serialized = "".join(item.model_dump_json() for item in baselines)
        self.assertNotIn("user://behavior-analyst", serialized)
        self.assertNotIn("agent-behavior", serialized)

        digest = baselines[0].baseline_sha256
        self.service.close()
        self.service = BehavioralRiskService(self.path, clock=self.clock)
        self.assertEqual(self.service.list_baselines(self.principal)[0].baseline_sha256, digest)
        row = self.service._connection.execute(
            "SELECT entity_ref, baseline_json FROM behavior_baselines LIMIT 1"
        ).fetchone()
        tampered = row["baseline_json"].replace('"observation_count":5', '"observation_count":6')
        self.service._connection.execute(
            "UPDATE behavior_baselines SET baseline_json = ? WHERE entity_ref = ?",
            (tampered, row["entity_ref"]),
        )
        with self.assertRaisesRegex(ValueError, "digest"):
            self.service.list_baselines(self.principal)

    def test_config_tuning_is_bounded_versioned_and_tamper_evident(self) -> None:
        current = self.service.active_config(self.principal)
        tuned = self.service.register_config(
            self.principal,
            BehaviorTuningInput(
                version="1.1.0",
                anomaly_threshold=60,
                drift_warning_rate=0.2,
                drift_critical_rate=0.45,
            ),
            reason="Reduce alert noise after a reviewed deterministic replay.",
        )
        self.assertEqual(tuned.version, "1.1.0")
        self.assertNotEqual(tuned.config_sha256, current.config_sha256)
        self.assertEqual(len(self.service.config_history(self.principal)), 2)
        with self.assertRaisesRegex(ValueError, "must increase"):
            self.service.register_config(
                self.principal,
                BehaviorTuningInput(version="1.0.1"),
                reason="Stale tuning versions must never reactivate old policy.",
            )
        with self.assertRaises(ValidationError):
            BehaviorTuningInput(version="2.0.0", operation_weight=24)

    def test_drift_health_tracks_recent_anomaly_rate(self) -> None:
        self.learn_benign(6)
        for index in range(5):
            event = self.anomalous_event("drift_%02d" % index)
            assessment = self.service.analyze(self.principal, event)
            self.service.learn(
                self.principal,
                event,
                assessment,
                eligible=False,
                reason="Anomalous event is excluded from baseline learning.",
            )
            self.clock.value += timedelta(minutes=1)
        drift = self.service.drift(self.principal)
        self.assertIn(drift.state, {DriftState.WARNING, DriftState.CRITICAL})
        self.assertGreaterEqual(drift.anomaly_count, 5)
        entity_ref = self.service.list_baselines(self.principal)[0].entity_ref
        self.assertGreaterEqual(self.service.drift(self.principal, entity_ref=entity_ref).window_size, 5)
        health = self.service.health(self.principal)
        self.assertEqual(health.anomalies, 5)
        self.assertEqual(health.rejected_learning, 5)

    def test_pipeline_adds_behavior_alert_and_visible_triage_evidence(self) -> None:
        self.learn_benign()
        pipeline = SecurityPipeline(
            behavior_service=self.service,
            behavior_principal=self.principal,
        )
        result = pipeline.process(self.anomalous_event("pipeline"))
        behavior_results = [
            item for item in result.alerts if item.alert.alert_type == "behavioral_anomaly"
        ]
        self.assertEqual(len(behavior_results), 1)
        item = behavior_results[0]
        self.assertIsNotNone(item.triage.behavior_assessment_id)
        self.assertGreaterEqual(item.triage.behavior_anomaly_score, 55)
        self.assertIn(
            "BEHAVIORAL_ANOMALY",
            {contribution.category.upper() for contribution in item.triage.contributions},
        )
        stored = self.service.get_assessment(
            self.principal, item.triage.behavior_assessment_id
        )
        self.assertEqual(stored.learning_status, LearningStatus.REJECTED)
        self.assertFalse(result.effect_allowed)

    def test_pipeline_learns_only_allowed_no_alert_events(self) -> None:
        pipeline = SecurityPipeline(
            behavior_service=self.service,
            behavior_principal=self.principal,
        )
        benign = pipeline.process(self.event("pipeline_benign"))
        self.assertTrue(benign.effect_allowed)
        assessment = self.service.list_assessments(self.principal)[0]
        self.assertEqual(assessment.learning_status, LearningStatus.LEARNED)

    def test_behavior_outage_cannot_suppress_deterministic_enforcement(self) -> None:
        class UnavailableBehaviorService:
            def analyze(self, _principal, _event):
                raise RuntimeError("sensitive internal outage detail")

        pipeline = SecurityPipeline(
            behavior_service=UnavailableBehaviorService(),  # type: ignore[arg-type]
            behavior_principal=self.principal,
        )
        result = pipeline.process(self.anomalous_event("outage"))
        self.assertFalse(result.effect_allowed)
        self.assertEqual(pipeline.last_behavior_error, "behavior_analysis_unavailable")
        self.assertGreater(len(result.alerts), 0)
        for item in result.alerts:
            categories = {entry.category for entry in item.triage.contributions}
            self.assertIn("behavioral_context_unavailable", categories)
            self.assertIn(
                "behavioral_analytics:unavailable",
                item.triage.missing_context_warnings,
            )
            self.assertNotIn("sensitive internal outage detail", item.model_dump_json())

    def test_tenant_permissions_conflicts_and_shape_fail_closed(self) -> None:
        reader = self.principal.model_copy(update={"permissions": {BEHAVIOR_READ}})
        with self.assertRaises(BehaviorAuthorizationError):
            self.service.analyze(reader, self.event("forbidden"))
        other = self.principal.model_copy(update={"tenant_id": "tenant-other"})
        with self.assertRaises(BehaviorAuthorizationError):
            self.service.analyze(other, self.event("cross_tenant"))
        event = self.event("conflict")
        self.service.analyze(self.principal, event)
        with self.assertRaisesRegex(ValueError, "conflicts"):
            self.service.analyze(
                self.principal, event.model_copy(update={"operation": "different.operation"})
            )
        with self.assertRaisesRegex(ValueError, "entity reference"):
            self.service.drift(self.principal, entity_ref="agent:unhashed")

    def test_authenticated_behavior_api_exposes_live_evidence_and_tuning(self) -> None:
        application = AuthorizationApplication(
            behavior_service=self.service,
            behavior_principal=self.principal,
        )
        handler = make_handler(application, HTTP_TOKEN)

        def request(path: str, *, method: str = "GET", body=None, auth: bool = True):
            headers = ["Host: 127.0.0.1"]
            if auth:
                headers.append("Authorization: Bearer %s" % HTTP_TOKEN)
            encoded = b""
            if body is not None:
                encoded = json.dumps(body).encode("utf-8")
                headers.extend(
                    ["Content-Type: application/json", "Content-Length: %d" % len(encoded)]
                )
            raw = (
                "%s %s HTTP/1.1\r\n%s\r\n\r\n"
                % (method, path, "\r\n".join(headers))
            ).encode("ascii") + encoded

            class FakeSocket:
                def __init__(self, incoming):
                    self.reader = BytesIO(incoming)
                    self.sent = BytesIO()

                def makefile(self, mode, *_args, **_kwargs):
                    return self.reader if "r" in mode else self.sent

                def sendall(self, data):
                    self.sent.write(data)

            class FakeServer:
                server_name = "agentsec-behavior-test"
                server_port = 80

            connection = FakeSocket(raw)
            handler(connection, ("127.0.0.1", 12345), FakeServer())
            head, response_body = connection.sent.getvalue().split(b"\r\n\r\n", 1)
            return int(head.splitlines()[0].split()[1]), json.loads(response_body)

        status, unauthorized = request("/v1/behavior/health", auth=False)
        self.assertEqual((status, unauthorized["error"]), (401, "unauthorized"))
        for index in range(5):
            status, allowed = request(
                "/v1/authorize",
                method="POST",
                body=self.event("api_train_%02d" % index).model_dump(mode="json"),
            )
            self.assertEqual((status, allowed["overall_action"]), (200, "allow"))
            self.clock.value += timedelta(minutes=1)
        status, anomalous = request(
            "/v1/authorize",
            method="POST",
            body=self.anomalous_event("api_anomaly").model_dump(mode="json"),
        )
        self.assertEqual(status, 200)
        self.assertIn("behavioral_anomaly", {item["alert_type"] for item in anomalous["alerts"]})
        status, assessments = request(
            "/v1/behavior/assessments?anomalies_only=true&limit=20&offset=0"
        )
        self.assertEqual((status, len(assessments["assessments"])), (200, 1))
        assessment_id = assessments["assessments"][0]["assessment_id"]
        status, detail = request("/v1/behavior/assessments/%s" % assessment_id)
        self.assertEqual((status, detail["event_id"]), (200, "evt_behavior_api_anomaly"))
        status, baselines = request("/v1/behavior/baselines?state=active")
        self.assertEqual((status, len(baselines["baselines"])), (200, 2))
        status, health = request("/v1/behavior/health")
        self.assertEqual((status, health["anomalies"]), (200, 1))
        status, drift = request("/v1/behavior/drift")
        self.assertEqual(status, 200)
        self.assertIn(drift["state"], {"stable", "warning", "critical"})
        tuning = BehaviorTuningInput(version="1.1.0", anomaly_threshold=60)
        status, configured = request(
            "/v1/behavior/config",
            method="POST",
            body={
                "config": tuning.model_dump(mode="json"),
                "reason": "Reviewed replay supports a slightly higher alert threshold.",
            },
        )
        self.assertEqual((status, configured["version"]), (200, "1.1.0"))
        status, rejected = request(
            "/v1/behavior/config",
            method="POST",
            body={"config": tuning.model_dump(mode="json"), "reason": "valid reason", "force": True},
        )
        self.assertEqual((status, rejected["error"]), (400, "invalid_request"))

    def test_behavior_environment_is_explicit_and_tenant_aligned(self) -> None:
        with patch.dict(
            os.environ,
            {
                "AGENTSEC_BEHAVIOR_DB": self.temp.name + "/environment-behavior.sqlite3",
                "AGENTSEC_BEHAVIOR_TENANT": "tenant-lab",
            },
            clear=True,
        ):
            application = application_from_environment()
        try:
            self.assertIsNotNone(application.behavior_service)
            self.assertEqual(application.behavior_health().tenant_id, "tenant-lab")
        finally:
            application.behavior_service.close()
        with patch.dict(
            os.environ,
            {"AGENTSEC_BEHAVIOR_DB": self.temp.name + "/missing-tenant.sqlite3"},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "requires AGENTSEC_BEHAVIOR_TENANT"):
                application_from_environment()

    def test_bounded_scale_and_concurrent_event_idempotency(self) -> None:
        self.learn_benign()
        started = time.perf_counter()
        for index in range(300):
            event = self.event("scale_%04d" % index)
            assessment = self.service.analyze(self.principal, event)
            self.service.learn(
                self.principal,
                event,
                assessment,
                eligible=True,
                reason="Allowed scale event contains no security alert.",
            )
        self.assertLess(time.perf_counter() - started, 6.0)
        duplicate = self.event("concurrent")

        def analyze(_index):
            return self.service.analyze(self.principal, duplicate).assessment_id

        with ThreadPoolExecutor(max_workers=6) as pool:
            identifiers = list(pool.map(analyze, range(10)))
        self.assertEqual(len(set(identifiers)), 1)
        with self.assertRaises(ValueError):
            self.service.list_assessments(self.principal, limit=201)


if __name__ == "__main__":
    unittest.main()
