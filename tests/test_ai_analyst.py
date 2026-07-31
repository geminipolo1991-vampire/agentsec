from __future__ import annotations

import hashlib
import json
from email.message import Message
from io import BytesIO
from pathlib import Path
import sqlite3
import tempfile
import time
from typing import Optional
import unittest
from unittest.mock import patch

from agentsec.analyst import (
    ANALYST_FEEDBACK,
    ANALYST_READ,
    ANALYST_RUN,
    AiAnalystService,
    AnalystAuthorizationError,
    AnalystPrincipal,
    RecordedCodexAnalystReasoner,
)
from agentsec.contracts import (
    AiMode,
    AnalystAlternative,
    AnalystDisagreementKind,
    AnalystFeedbackRating,
    AnalystRole,
    AnalystRoleResult,
    AnalystRoleStatus,
    DecisionAction,
    JudgmentValidationStatus,
)
from agentsec.crypto import canonical_bytes
from agentsec.pipeline import SecurityPipeline
from agentsec.redaction import Redactor
from agentsec.scenarios import forge_scenarios
from agentsec.service import (
    AuthorizationApplication,
    application_from_environment,
    make_handler,
)


TOKEN = "ai-analyst-test-token-at-least-thirty-two-characters"


def full_principal(tenant_id: str = "tenant-lab") -> AnalystPrincipal:
    return AnalystPrincipal(
        tenant_id=tenant_id,
        actor_id="analyst://unit-test",
        permissions={ANALYST_READ, ANALYST_RUN, ANALYST_FEEDBACK},
    )


def recorded_reasoner() -> RecordedCodexAnalystReasoner:
    return RecordedCodexAnalystReasoner.from_path(
        Path("configs/codex-analyst-evaluation.json")
    )


class ControlledReasoner:
    provider = "codex"
    model_id = "controlled-test"
    recording_id = "controlled-test-recording"

    def __init__(
        self,
        *,
        judge_action: DecisionAction = DecisionAction.DENY,
        abstain_role: Optional[AnalystRole] = None,
        invalid_citation: bool = False,
        delay_seconds: float = 0.0,
        canary: Optional[str] = None,
        non_judge_action: Optional[DecisionAction] = None,
    ) -> None:
        self.judge_action = judge_action
        self.abstain_role = abstain_role
        self.invalid_citation = invalid_citation
        self.delay_seconds = delay_seconds
        self.canary = canary
        self.non_judge_action = non_judge_action

    def analyze_role(self, request):
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        if request.role == self.abstain_role:
            return AnalystRoleResult(
                role=request.role,
                status=AnalystRoleStatus.ABSTAINED,
                provider=self.provider,
                model_id=self.model_id,
                abstention_reason="Insufficient independent evidence for a conclusion.",
                uncertainties=["A human must resolve the evidence gap."],
            )
        evidence_ids = [request.evidence[0].evidence_id]
        if self.invalid_citation:
            evidence_ids = ["outside_sha256:" + "a" * 24]
        summary = "Completed bounded analysis using only cited evidence."
        if self.canary:
            summary = "Completed analysis with api_key=%s" % self.canary
        return AnalystRoleResult(
            role=request.role,
            status=AnalystRoleStatus.COMPLETED,
            provider=self.provider,
            model_id=self.model_id,
            summary=summary,
            hypothesis="The detector hypothesis remains plausible under the recorded facts.",
            recommended_action=(
                self.judge_action
                if request.role == AnalystRole.JUDGE
                else self.non_judge_action
            ),
            confidence=0.9,
            evidence_ids=evidence_ids,
            reason_codes=["CONTROLLED_TEST_RESULT"],
            alternatives=[
                AnalystAlternative(
                    title="Preserve deterministic policy",
                    rationale="A human can review the cited evidence before any change.",
                    recommended_action=request.deterministic_action,
                    evidence_ids=evidence_ids,
                )
            ],
            uncertainties=["Metadata is not proof of compromise."],
        )


class AiAnalystEngineTests(unittest.TestCase):
    def test_recorded_codex_runs_five_roles_with_evidence_receipts_and_ui_detail(self) -> None:
        service = AiAnalystService(":memory:", reasoner=recorded_reasoner())
        principal = full_principal()
        pipeline = SecurityPipeline(
            analyst_service=service,
            analyst_principal=principal,
            ai_mode=AiMode.SHADOW,
        )
        try:
            result = pipeline.process(
                forge_scenarios()["indirect_injection_secret_egress"]
            )
            item = next(
                alert for alert in result.alerts if alert.alert.alert_type == "secret_egress"
            )
            run = item.analyst_run
            self.assertIsNotNone(run)
            assert run is not None
            self.assertEqual(run.provider, "codex")
            self.assertEqual(run.recording_id, "codex-analyst-2026-07-24-loop-14")
            self.assertEqual([entry.role for entry in run.role_results], list(AnalystRole))
            self.assertEqual([entry.role for entry in run.tool_receipts], list(AnalystRole))
            self.assertTrue(all(entry.result_count > 0 for entry in run.tool_receipts))
            self.assertTrue(all(entry.alternatives for entry in run.role_results))
            self.assertFalse(run.executive_authority)
            self.assertIsNotNone(run.validation)
            self.assertEqual(run.validation.machine_action, item.judgment.action)
            self.assertFalse(run.validation.automation_eligible)
            self.assertIn(
                run.validation.status,
                {JudgmentValidationStatus.PASSED, JudgmentValidationStatus.HUMAN_REVIEW},
            )
            self.assertEqual(len(run.validation.claim_results), len(AnalystRole))
            self.assertEqual(run.deterministic_action, item.judgment.action)
            self.assertEqual(result.overall_action, DecisionAction.DENY)
            incident = pipeline.incident(item.finding.finding_id)
            self.assertEqual(incident.analyst_run.run_id, run.run_id)
            self.assertEqual(service.health(principal).completed_runs, len(result.alerts))
        finally:
            service.close()

    def test_model_relaxation_is_recorded_but_cannot_change_enforcement(self) -> None:
        service = AiAnalystService(
            ":memory:", reasoner=ControlledReasoner(judge_action=DecisionAction.ALLOW)
        )
        pipeline = SecurityPipeline(
            analyst_service=service,
            analyst_principal=full_principal(),
            ai_mode=AiMode.SHADOW,
        )
        try:
            result = pipeline.process(
                forge_scenarios()["indirect_injection_secret_egress"]
            )
            run = result.alerts[0].analyst_run
            assert run is not None
            self.assertEqual(run.advisory_action, DecisionAction.DENY)
            self.assertIn(
                AnalystDisagreementKind.RELAXATION_REJECTED,
                {item.kind for item in run.disagreements},
            )
            self.assertTrue(run.human_review_required)
            self.assertEqual(result.overall_action, DecisionAction.DENY)
            self.assertFalse(result.effect_allowed)
        finally:
            service.close()

    def test_tightening_and_cross_role_conflict_remain_advisory(self) -> None:
        service = AiAnalystService(
            ":memory:",
            reasoner=ControlledReasoner(
                judge_action=DecisionAction.DENY,
                non_judge_action=DecisionAction.ALLOW,
            ),
        )
        pipeline = SecurityPipeline(
            analyst_service=service,
            analyst_principal=full_principal(),
            ai_mode=AiMode.SHADOW,
        )
        try:
            result = pipeline.process(forge_scenarios()["mcp_schema_drift"])
            run = result.alerts[0].analyst_run
            assert run is not None
            kinds = {item.kind for item in run.disagreements}
            self.assertIn(AnalystDisagreementKind.TIGHTENING_PROPOSED, kinds)
            self.assertIn(AnalystDisagreementKind.CROSS_ROLE_CONFLICT, kinds)
            self.assertEqual(run.advisory_action, DecisionAction.DENY)
            self.assertEqual(result.overall_action, DecisionAction.REQUIRE_APPROVAL)
            self.assertFalse(result.effect_allowed)
        finally:
            service.close()

    def test_analyst_service_outage_cannot_change_deterministic_denial(self) -> None:
        class UnavailableAnalystService:
            def analyze(self, _principal, _result):
                raise RuntimeError("provider detail must not escape")

        pipeline = SecurityPipeline(
            analyst_service=UnavailableAnalystService(),  # type: ignore[arg-type]
            analyst_principal=full_principal(),
            ai_mode=AiMode.SHADOW,
        )
        result = pipeline.process(
            forge_scenarios()["indirect_injection_secret_egress"]
        )
        self.assertEqual(result.overall_action, DecisionAction.DENY)
        self.assertFalse(result.effect_allowed)
        self.assertTrue(all(item.analyst_run is None for item in result.alerts))
        self.assertEqual(pipeline.last_analyst_error, "ai_analyst_unavailable")

    def test_abstention_timeout_and_invalid_citation_fail_to_partial_not_allow(self) -> None:
        cases = [
            ControlledReasoner(abstain_role=AnalystRole.JUDGE),
            ControlledReasoner(delay_seconds=0.04),
            ControlledReasoner(invalid_citation=True),
        ]
        for index, reasoner in enumerate(cases):
            with self.subTest(index=index):
                service = AiAnalystService(
                    ":memory:", reasoner=reasoner, role_timeout_seconds=0.01
                )
                pipeline = SecurityPipeline(
                    analyst_service=service,
                    analyst_principal=full_principal(),
                    ai_mode=AiMode.SHADOW,
                )
                try:
                    result = pipeline.process(forge_scenarios()["mcp_schema_drift"])
                    run = result.alerts[0].analyst_run
                    assert run is not None
                    self.assertNotEqual(run.status.value, "completed")
                    self.assertTrue(run.human_review_required)
                    self.assertEqual(run.advisory_action, run.deterministic_action)
                    self.assertFalse(result.effect_allowed)
                finally:
                    service.close()

    def test_provider_prose_is_redacted_before_durable_storage(self) -> None:
        canary = "MODEL-ONLY-CANARY-987654"
        service = AiAnalystService(
            ":memory:",
            reasoner=ControlledReasoner(canary=canary),
            redactor=Redactor(canaries=[canary]),
        )
        pipeline = SecurityPipeline(
            analyst_service=service,
            analyst_principal=full_principal(),
            ai_mode=AiMode.SHADOW,
        )
        try:
            run = pipeline.process(forge_scenarios()["mcp_schema_drift"]).alerts[0].analyst_run
            assert run is not None
            encoded = run.model_dump_json()
            self.assertNotIn(canary, encoded)
            self.assertIn("[REDACTED]", encoded)
            self.assertNotIn("secret://", encoded)
            self.assertNotIn("receiver.invalid", encoded)
        finally:
            service.close()

    def test_durable_idempotency_integrity_tenant_permissions_and_inert_feedback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "analyst.db")
            principal = full_principal()
            service = AiAnalystService(database, reasoner=recorded_reasoner())
            base = SecurityPipeline().process(
                forge_scenarios()["mcp_schema_drift"]
            ).alerts[0]
            try:
                first = service.analyze(principal, base)
                second = service.analyze(principal, base)
                self.assertEqual(first.run_id, second.run_id)
                feedback = service.record_feedback(
                    principal,
                    first.run_id,
                    rating=AnalystFeedbackRating.INCOMPLETE,
                    role=AnalystRole.INVESTIGATION,
                    reason="Needs independent scope confirmation before closure.",
                )
                self.assertFalse(feedback.applied_to_model)
                self.assertEqual(service.health(principal).feedback_records, 1)
                self.assertEqual(service.get(principal, first.run_id).run_sha256, first.run_sha256)
                with self.assertRaises(AnalystAuthorizationError):
                    service.get(
                        AnalystPrincipal(
                            tenant_id="tenant-lab",
                            actor_id="analyst://no-access",
                            permissions=set(),
                        ),
                        first.run_id,
                    )
                with self.assertRaises(AnalystAuthorizationError):
                    service.analyze(full_principal("other-tenant"), base)
                with sqlite3.connect(database) as connection:
                    connection.execute(
                        "UPDATE analyst_runs SET run_json = replace(run_json, 'completed', 'partial') WHERE run_id = ?",
                        (first.run_id,),
                    )
                with self.assertRaises(ValueError):
                    service.get(principal, first.run_id)
            finally:
                service.close()

    def test_nested_validation_digest_survives_outer_digest_recalculation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "analyst.db")
            principal = full_principal()
            service = AiAnalystService(database, reasoner=recorded_reasoner())
            base = SecurityPipeline().process(
                forge_scenarios()["mcp_schema_drift"]
            ).alerts[0]
            try:
                run = service.analyze(principal, base)
                with sqlite3.connect(database) as connection:
                    row = connection.execute(
                        "SELECT run_json FROM analyst_runs WHERE run_id = ?",
                        (run.run_id,),
                    ).fetchone()
                    payload = json.loads(row[0])
                    payload["validation"]["calibrated_confidence"] = 0.0
                    outer = dict(payload)
                    outer.pop("run_sha256")
                    payload["run_sha256"] = hashlib.sha256(
                        canonical_bytes(outer)
                    ).hexdigest()
                    connection.execute(
                        "UPDATE analyst_runs SET run_json = ?, run_sha256 = ? WHERE run_id = ?",
                        (json.dumps(payload), payload["run_sha256"], run.run_id),
                    )
                with self.assertRaisesRegex(ValueError, "judgment validation report integrity"):
                    service.get(principal, run.run_id)
            finally:
                service.close()

    def test_authenticated_analyst_api_lists_runs_health_and_feedback(self) -> None:
        service = AiAnalystService(":memory:", reasoner=recorded_reasoner())
        principal = full_principal()
        pipeline = SecurityPipeline(
            analyst_service=service,
            analyst_principal=principal,
            ai_mode=AiMode.SHADOW,
        )
        application = AuthorizationApplication(
            pipeline,
            analyst_service=service,
            analyst_principal=principal,
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
            captured = {"status": None}
            handler.send_response = lambda status: captured.update(status=status)
            handler.send_header = lambda _key, _value: None
            handler.end_headers = lambda: None
            getattr(handler, "do_%s" % method)()
            return captured["status"], json.loads(handler.wfile.getvalue())

        try:
            event = forge_scenarios()["mcp_schema_drift"].model_dump(mode="json")
            status, authorized = request("POST", "/v1/authorize", event)
            self.assertEqual(status, 200)
            finding_id = authorized["alerts"][0]["finding_id"]
            status, run = request("GET", "/v1/analyst/findings/%s" % finding_id)
            self.assertEqual(status, 200)
            status, listing = request("GET", "/v1/analyst/runs?limit=10")
            self.assertEqual(status, 200)
            self.assertEqual(listing["runs"][0]["run_id"], run["run_id"])
            status, health = request("GET", "/v1/analyst/health")
            self.assertEqual(status, 200)
            self.assertEqual(health["total_runs"], 1)
            status, feedback = request(
                "POST",
                "/v1/analyst/runs/%s/feedback" % run["run_id"],
                {"rating": "helpful", "reason": "Citations support the assessment."},
            )
            self.assertEqual(status, 200)
            self.assertFalse(feedback["applied_to_model"])
            status, _ = request("GET", "/v1/analyst/health", authorized=False)
            self.assertEqual(status, 401)
        finally:
            service.close()

    def test_environment_assembly_requires_explicit_shadow_mode_and_tenant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            values = {
                "AGENTSEC_AI_MODE": "shadow",
                "AGENTSEC_MODEL_REGISTRY": "configs/model-profiles.json",
                "AGENTSEC_CODEX_RECORDING": "configs/codex-evaluation.json",
                "AGENTSEC_ANALYST_DB": str(Path(directory) / "analyst.db"),
                "AGENTSEC_ANALYST_RECORDING": "configs/codex-analyst-evaluation.json",
                "AGENTSEC_ANALYST_TENANT": "tenant-lab",
            }
            with patch.dict("os.environ", values, clear=True):
                application = application_from_environment()
            try:
                self.assertIsNotNone(application.analyst_service)
                self.assertIsNone(application.pipeline.reasoner)
                response = application.authorize(
                    forge_scenarios()["mcp_schema_drift"].model_dump(mode="json")
                )
                run = application.analyst_run_for_finding(
                    response.alerts[0].finding_id
                )
                self.assertEqual(run.provider, "codex")
            finally:
                assert application.analyst_service is not None
                application.analyst_service.close()

            off_values = dict(values, AGENTSEC_AI_MODE="off")
            with patch.dict("os.environ", off_values, clear=True):
                with self.assertRaisesRegex(ValueError, "AI analyst requires"):
                    application_from_environment()


if __name__ == "__main__":
    unittest.main()
