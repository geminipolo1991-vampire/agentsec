from __future__ import annotations

import tempfile
import unittest
import json
from datetime import datetime, timezone
from email.message import Message
from io import BytesIO
from pathlib import Path

from pydantic import ValidationError

from agentsec.continuous_evaluation import (
    CandidateKind,
    ContinuousEvaluationEngine,
    ContinuousEvaluationReport,
    ContinuousEvaluationService,
    EvaluationAuthorizationError,
    EvaluationBaselineApprovalRequest,
    EvaluationCandidateMetadata,
    EvaluationConflictError,
    EvaluationFeedbackPromotionRequest,
    EvaluationFeedbackProposalRequest,
    EvaluationFeedbackReviewRequest,
    EvaluationFeedbackState,
    EvaluationGateState,
    EvaluationGroundTruth,
    EvaluationPrediction,
    EvaluationPrincipal,
    EvaluationRunRequest,
    EvaluationThresholdPolicy,
    built_in_evaluation_dataset,
    default_evaluation_policy,
    deterministic_candidate,
    live_model_candidate,
    recorded_codex_candidate,
)
from agentsec.contracts import DecisionAction, Severity
from agentsec.service import AuthorizationApplication, make_handler


ROOT = Path(__file__).resolve().parents[1]
FIXED_TIME = datetime(2026, 7, 24, tzinfo=timezone.utc)
TOKEN = "continuous-evaluation-test-token-32-characters"


class _WeakCandidate:
    metadata = EvaluationCandidateMetadata(
        candidate_id="weak_candidate",
        kind=CandidateKind.DETERMINISTIC,
        provider="test",
        exact_model_id="allow-everything",
        route_sha256="1" * 64,
        qualification_sha256="2" * 64,
        qualified=True,
        live_provider_calls=False,
    )

    def predict(self, case):
        return EvaluationPrediction(
            predicted_alert_types=[],
            predicted_severity=None,
            proposed_action=DecisionAction.ALLOW,
            enforced_action=DecisionAction.ALLOW,
            effect_allowed=True,
            confidence=0.99,
            cited_evidence_refs=[],
            model_invoked=False,
            model_completed=False,
            abstained=False,
            latency_ms=1,
        )


class _UnavailableCandidate:
    metadata = EvaluationCandidateMetadata(
        candidate_id="unavailable_model",
        kind=CandidateKind.RECORDED_MODEL,
        provider="test",
        exact_model_id="unavailable",
        route_sha256="3" * 64,
        qualification_sha256="4" * 64,
        qualified=True,
        live_provider_calls=False,
    )

    def predict(self, case):
        raise RuntimeError("provider unavailable")


class _FabricatingCandidate:
    metadata = EvaluationCandidateMetadata(
        candidate_id="fabricating_model",
        kind=CandidateKind.RECORDED_MODEL,
        provider="test",
        exact_model_id="fabricated-citation",
        route_sha256="5" * 64,
        qualification_sha256="6" * 64,
        qualified=True,
        live_provider_calls=False,
    )

    def predict(self, case):
        return EvaluationPrediction(
            predicted_alert_types=["indirect_prompt_injection"],
            predicted_severity=Severity.HIGH,
            proposed_action=DecisionAction.DENY,
            enforced_action=DecisionAction.DENY,
            effect_allowed=False,
            confidence=0.99,
            cited_evidence_refs=["evd_fabricated"],
            model_invoked=True,
            model_completed=True,
            abstained=False,
            latency_ms=1,
        )


class ContinuousEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = built_in_evaluation_dataset()
        cls.engine = ContinuousEvaluationEngine()
        cls.report = cls.engine.run(
            cls.dataset,
            recorded_codex_candidate(ROOT / "configs" / "codex-evaluation.json"),
            evaluated_at=FIXED_TIME,
        )

    def test_dataset_is_large_variant_complete_and_evaluator_blind(self) -> None:
        manifest = self.dataset.manifest()
        self.assertEqual(manifest.case_count, 42)
        self.assertEqual(manifest.use_case_count, 6)
        self.assertEqual(
            manifest.splits,
            {"development": 6, "holdout": 24, "validation": 12},
        )
        self.assertTrue(manifest.blind_execution)
        self.assertFalse(manifest.raw_content_retained)
        self.assertEqual(
            {len(item.variants) for item in manifest.profiles}, {7}
        )
        candidate_fields = set(type(self.dataset.cases[0].blind).model_fields)
        self.assertFalse(
            candidate_fields
            & {"attack", "expected_alert_types", "expected_action", "ground_truth"}
        )

        payload = self.dataset.model_dump(mode="json")
        payload["cases"][0]["blind"]["stimulus_sha256"] = "0" * 64
        with self.assertRaises(ValidationError):
            type(self.dataset).model_validate(payload)

    def test_recorded_codex_passes_all_absolute_quality_gates(self) -> None:
        metrics = self.report.metrics
        self.assertEqual(self.report.gate.state, EvaluationGateState.PASS)
        self.assertEqual(self.report.gate.reasons, [])
        self.assertEqual(metrics.cases, 42)
        self.assertEqual(metrics.alert_precision, 1.0)
        self.assertEqual(metrics.detector_recall, 1.0)
        self.assertEqual(metrics.forbidden_effect_attack_success_rate, 0.0)
        self.assertEqual(metrics.benign_task_completion_rate, 1.0)
        self.assertEqual(metrics.severity_exact_agreement_rate, 1.0)
        self.assertEqual(metrics.evidence_validity_rate, 1.0)
        self.assertEqual(metrics.safe_action_agreement_rate, 1.0)
        self.assertEqual(metrics.abstention_rate, 0.0)
        self.assertLess(metrics.brier_score, 0.01)
        self.assertEqual(set(self.report.use_case_metrics), {
            "authority_expansion", "benign_control", "mcp_supply_chain_drift",
            "memory_poisoning", "prompt_injection_egress",
            "rag_multistage_exfiltration",
        })
        self.assertEqual(
            set(self.report.split_metrics),
            {"development", "validation", "holdout"},
        )
        self.assertTrue(all(item.passed for item in self.report.gate.checks))

    def test_weak_candidate_and_regression_drift_block_release(self) -> None:
        baseline = self.engine.run(
            self.dataset, deterministic_candidate(), evaluated_at=FIXED_TIME
        )
        weak = self.engine.run(
            self.dataset,
            _WeakCandidate(),
            evaluated_at=FIXED_TIME,
            baseline=baseline,
        )
        self.assertEqual(weak.gate.state, EvaluationGateState.BLOCK)
        self.assertEqual(weak.metrics.detector_recall, 0.0)
        self.assertEqual(weak.metrics.forbidden_effect_attack_success_rate, 1.0)
        self.assertIsNotNone(weak.gate.drift)
        self.assertFalse(weak.gate.drift.passed)
        self.assertIn("baseline_drift", weak.gate.reasons)

    def test_model_outage_and_fabricated_evidence_fail_closed(self) -> None:
        outage = self.engine.run(
            self.dataset, _UnavailableCandidate(), evaluated_at=FIXED_TIME
        )
        self.assertEqual(outage.gate.state, EvaluationGateState.BLOCK)
        self.assertEqual(outage.metrics.schema_validity_rate, 0.0)
        self.assertEqual(outage.metrics.abstention_rate, 1.0)
        self.assertTrue(all(not item.effect_allowed for item in outage.cases))

        fabricated = self.engine.run(
            self.dataset, _FabricatingCandidate(), evaluated_at=FIXED_TIME
        )
        self.assertEqual(fabricated.gate.state, EvaluationGateState.BLOCK)
        self.assertEqual(fabricated.metrics.evidence_validity_rate, 0.0)
        self.assertTrue(any(item.unknown_evidence_refs for item in fabricated.cases))

    def test_live_candidate_requires_explicit_qualification_commitment(self) -> None:
        with self.assertRaises(TypeError):
            live_model_candidate(
                candidate_id="live_openai",
                provider="openai",
                exact_model_id="future-model",
                route_sha256="7" * 64,
                reasoner_factory=lambda: None,
            )
        candidate = live_model_candidate(
            candidate_id="live_openai",
            provider="openai",
            exact_model_id="future-model",
            route_sha256="7" * 64,
            qualification_sha256="8" * 64,
            reasoner_factory=lambda: None,
        )
        self.assertEqual(candidate.metadata.kind, CandidateKind.LIVE_MODEL)
        self.assertTrue(candidate.metadata.qualified)
        self.assertTrue(candidate.metadata.live_provider_calls)
        self.assertFalse(candidate.metadata.runtime_authority)

    def test_policy_and_report_tampering_are_rejected(self) -> None:
        policy = default_evaluation_policy().model_dump(mode="json")
        policy["minimum_detector_recall"] = 0.5
        with self.assertRaises(ValidationError):
            EvaluationThresholdPolicy.model_validate(policy)

        report = self.report.model_dump(mode="json")
        report["metrics"]["detector_recall"] = 0.5
        with self.assertRaises(ValidationError):
            ContinuousEvaluationReport.model_validate(report)

    def test_durable_runs_baselines_drift_and_tenant_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = str(Path(temp_dir) / "evaluation.sqlite3")
            candidates = [
                deterministic_candidate(),
                recorded_codex_candidate(
                    ROOT / "configs" / "codex-evaluation.json"
                ),
            ]
            service = ContinuousEvaluationService(
                path,
                tenant_id="tenant-a",
                candidates=candidates,
                policy=default_evaluation_policy(),
                now=lambda: FIXED_TIME,
            )
            operator = EvaluationPrincipal(
                tenant_id="tenant-a",
                actor_id="analyst://operator",
                permissions={"evaluation:read", "evaluation:run"},
            )
            request = EvaluationRunRequest(
                request_id="req_12345678",
                dataset_version="benchmark-2026.07.24.1",
                candidate_id="recorded_codex",
            )
            first = service.run(operator, request)
            self.assertEqual(first.report.gate.state, EvaluationGateState.PASS)
            self.assertEqual(service.run(operator, request), first)
            with self.assertRaises(EvaluationConflictError):
                service.run(
                    operator,
                    request.model_copy(update={"candidate_id": "deterministic"}),
                )

            reviewer = EvaluationPrincipal(
                tenant_id="tenant-a",
                actor_id="analyst://baseline-reviewer",
                permissions={"evaluation:read", "evaluation:review"},
            )
            baseline = service.approve_baseline(
                reviewer,
                first.run_id,
                EvaluationBaselineApprovalRequest(reason_sha256="9" * 64),
            )
            self.assertTrue(baseline.active)
            second = service.run(
                operator,
                EvaluationRunRequest(
                    request_id="req_87654321",
                    dataset_version="benchmark-2026.07.24.1",
                    candidate_id="recorded_codex",
                ),
            )
            self.assertIsNotNone(second.report.gate.drift)
            self.assertTrue(second.report.gate.drift.passed)
            self.assertEqual(service.list_runs(operator).total, 2)
            health = service.health(operator)
            self.assertTrue(health.audit_valid)
            self.assertEqual(health.passing_runs, 2)
            self.assertEqual(health.active_baselines, 1)
            self.assertFalse(health.direct_learning_enabled)
            self.assertFalse(health.runtime_policy_mutation_enabled)
            audit_admin = reviewer.model_copy(
                update={"permissions": {"evaluation:admin"}}
            )
            self.assertTrue(service.verify_audit(audit_admin))
            service.close()

            reopened = ContinuousEvaluationService(
                path,
                tenant_id="tenant-a",
                candidates=candidates,
                now=lambda: FIXED_TIME,
            )
            self.assertEqual(
                reopened.get_run(operator, first.run_id).record_sha256,
                first.record_sha256,
            )
            other_tenant = operator.model_copy(update={"tenant_id": "tenant-b"})
            with self.assertRaises(EvaluationAuthorizationError):
                reopened.list_runs(other_tenant)
            reopened.close()

    def test_private_http_evaluation_routes_are_authenticated_and_exact(self) -> None:
        service = ContinuousEvaluationService(
            ":memory:",
            tenant_id="tenant-a",
            candidates=[deterministic_candidate()],
            now=lambda: FIXED_TIME,
        )
        principal = EvaluationPrincipal(
            tenant_id="tenant-a",
            actor_id="system://evaluation-http-test",
            permissions={
                "evaluation:read", "evaluation:run", "evaluation:feedback",
                "evaluation:review", "evaluation:admin",
            },
        )
        application = AuthorizationApplication(
            evaluation_service=service, evaluation_principal=principal
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
            handler.send_header = lambda key, value: None
            handler.end_headers = lambda: None
            getattr(handler, "do_%s" % method)()
            return captured["status"], json.loads(handler.wfile.getvalue())

        status, catalog = request("GET", "/v1/evaluations/catalog")
        self.assertEqual(status, 200)
        self.assertEqual(catalog["latest_dataset"]["case_count"], 42)
        status, run = request(
            "POST",
            "/v1/evaluations/runs",
            {
                "request_id": "req_http0001",
                "dataset_version": "benchmark-2026.07.24.1",
                "candidate_id": "deterministic",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(run["report"]["gate"]["state"], "pass")
        status, detail = request(
            "GET", "/v1/evaluations/runs/%s" % run["run_id"]
        )
        self.assertEqual(status, 200)
        self.assertEqual(detail["record_sha256"], run["record_sha256"])
        status, _ = request(
            "GET", "/v1/evaluations/catalog", authorized=False
        )
        self.assertEqual(status, 401)
        status, _ = request("GET", "/v1/evaluations/catalog?unexpected=1")
        self.assertEqual(status, 400)
        service.close()

    def test_feedback_requires_submitter_reviewer_publisher_separation(self) -> None:
        service = ContinuousEvaluationService(
            ":memory:",
            tenant_id="tenant-a",
            candidates=[deterministic_candidate()],
            now=lambda: FIXED_TIME,
        )
        read = EvaluationPrincipal(
            tenant_id="tenant-a",
            actor_id="analyst://reader",
            permissions={"evaluation:read"},
        )
        dataset = service.get_dataset(read, "benchmark-2026.07.24.1")
        benign = next(item for item in dataset.cases if not item.ground_truth.attack)
        proposal_truth = EvaluationGroundTruth(
            attack=True,
            expected_alert_types=["reviewed_false_negative"],
            expected_severity=Severity.HIGH,
            expected_action=DecisionAction.DENY,
            forbidden_effect=True,
            allowed_evidence_refs=[],
        )
        submitter = EvaluationPrincipal(
            tenant_id="tenant-a",
            actor_id="analyst://submitter",
            permissions={"evaluation:feedback"},
        )
        request = EvaluationFeedbackProposalRequest(
            request_id="req_feed0001",
            dataset_version=dataset.dataset_version,
            target_case_id=benign.blind.case_id,
            source_feedback_id="aif_feedback01",
            source_run_id="air_" + "1" * 32,
            source_feedback_sha256="2" * 64,
            source_rating="incorrect",
            proposed_ground_truth=proposal_truth,
            rationale_sha256="3" * 64,
        )
        proposal = service.submit_feedback(submitter, request)
        self.assertEqual(proposal.state, EvaluationFeedbackState.CANDIDATE)
        self.assertFalse(proposal.source_applied_to_model)
        self.assertFalse(proposal.applied_to_model)
        self.assertFalse(proposal.applied_to_runtime_policy)
        self.assertEqual(service.submit_feedback(submitter, request), proposal)
        with self.assertRaises(EvaluationConflictError):
            service.submit_feedback(
                submitter,
                request.model_copy(
                    update={"source_feedback_sha256": "4" * 64}
                ),
            )

        with self.assertRaises(EvaluationAuthorizationError):
            service.review_feedback(
                submitter.model_copy(
                    update={"permissions": {"evaluation:review"}}
                ),
                proposal.proposal_id,
                EvaluationFeedbackReviewRequest(
                    decision="approve", reason_sha256="5" * 64
                ),
            )
        reviewer = EvaluationPrincipal(
            tenant_id="tenant-a",
            actor_id="analyst://reviewer",
            permissions={"evaluation:read", "evaluation:review"},
        )
        approved = service.review_feedback(
            reviewer,
            proposal.proposal_id,
            EvaluationFeedbackReviewRequest(
                decision="approve", reason_sha256="5" * 64
            ),
        )
        self.assertEqual(approved.state, EvaluationFeedbackState.APPROVED)

        with self.assertRaises(EvaluationAuthorizationError):
            service.promote_feedback(
                reviewer.model_copy(
                    update={"permissions": {"evaluation:read", "evaluation:admin"}}
                ),
                proposal.proposal_id,
                EvaluationFeedbackPromotionRequest(
                    new_dataset_version="benchmark-2026.07.24.2",
                    reason_sha256="6" * 64,
                ),
            )
        publisher = EvaluationPrincipal(
            tenant_id="tenant-a",
            actor_id="analyst://publisher",
            permissions={"evaluation:read", "evaluation:admin"},
        )
        promoted, manifest = service.promote_feedback(
            publisher,
            proposal.proposal_id,
            EvaluationFeedbackPromotionRequest(
                new_dataset_version="benchmark-2026.07.24.2",
                reason_sha256="6" * 64,
            ),
        )
        self.assertEqual(promoted.state, EvaluationFeedbackState.PROMOTED)
        self.assertFalse(promoted.applied_to_model)
        self.assertFalse(promoted.applied_to_runtime_policy)
        self.assertEqual(manifest.parent_dataset_sha256, dataset.dataset_sha256)
        self.assertNotEqual(manifest.dataset_sha256, dataset.dataset_sha256)
        self.assertFalse(benign.ground_truth.attack)
        self.assertEqual(
            service.get_dataset(publisher, manifest.dataset_version).dataset_sha256,
            manifest.dataset_sha256,
        )
        self.assertEqual(
            service.list_feedback(publisher).proposals[0].state,
            EvaluationFeedbackState.PROMOTED,
        )
        self.assertTrue(service.verify_audit(publisher))
        service.close()
if __name__ == "__main__":
    unittest.main()
