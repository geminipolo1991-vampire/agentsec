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

from agentsec.content import (
    CONTENT_ADMIN,
    CONTENT_PUBLISH,
    CONTENT_READ,
    CONTENT_REVIEW,
    CONTENT_WRITE,
    ContentAuthorizationError,
    ContentPrincipal,
    DetectionContentService,
    ReviewDecision,
    RuleContentStatus,
    RuleTestSuite,
    SignedContentPack,
)
from agentsec.contracts import AgentEvent, DecisionAction, Severity, TrustClass
from agentsec.crypto import PocHmacSigner
from agentsec.detection import (
    DETECTION_ADMIN,
    DETECTION_READ,
    DETECTION_RUN,
    DetectionCondition,
    DetectionEventField,
    DetectionExecutionMode,
    DetectionOperator,
    DetectionPredicate,
    DetectionPrincipal,
    DetectionRuleDefinition,
    DetectionRuleKind,
    DetectionService,
)
from agentsec.service import AuthorizationApplication, application_from_environment, make_handler


HTTP_TOKEN = "module-ten-content-http-token-at-least-32-characters"


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 24, 4, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value


class DetectionContentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.clock = MutableClock()
        self.detection = DetectionService(
            self.temp.name + "/detection.sqlite3", clock=self.clock
        )
        self.detection_principal = DetectionPrincipal(
            tenant_id="tenant-lab",
            actor_id="system://content-target",
            permissions={DETECTION_READ, DETECTION_RUN, DETECTION_ADMIN},
        )
        self.signer = PocHmacSigner(b"module-ten-content-signing-key-32-bytes-minimum")
        self.content_path = self.temp.name + "/content.sqlite3"
        self.content = DetectionContentService(
            self.content_path,
            detection_service=self.detection,
            detection_principal=self.detection_principal,
            signer=self.signer,
            clock=self.clock,
        )
        permissions = {
            CONTENT_READ, CONTENT_WRITE, CONTENT_REVIEW,
            CONTENT_PUBLISH, CONTENT_ADMIN,
        }
        self.author = ContentPrincipal(
            tenant_id="tenant-lab", actor_id="analyst://author",
            permissions=permissions,
        )
        self.reviewer = self.author.model_copy(update={"actor_id": "analyst://reviewer"})
        self.publisher = self.author.model_copy(update={"actor_id": "analyst://publisher"})

    def tearDown(self) -> None:
        self.content.close()
        self.detection.close()
        self.temp.cleanup()

    def definition(self, version: str = "1.0.0", **updates) -> DetectionRuleDefinition:
        payload = {
            "rule_id": "DET-CONTENT-EGRESS-001",
            "version": version,
            "name": "Content-managed external send",
            "description": "Detects external sends managed through reviewed content.",
            "kind": DetectionRuleKind.EVENT,
            "execution_mode": DetectionExecutionMode.BOTH,
            "alert_type": "content_external_send",
            "title": "Content-managed external send detected",
            "severity": Severity.HIGH,
            "confidence": 0.91,
            "recommended_action": DecisionAction.DENY,
            "reason_codes": ["CONTENT_EXTERNAL_SEND"],
            "framework_mappings": ["OWASP-LLM02"],
            "predicate": DetectionPredicate(
                all_conditions=[
                    DetectionCondition(
                        field=DetectionEventField.OPERATION,
                        operator=DetectionOperator.EQUALS,
                        value="external.send",
                    )
                ]
            ),
        }
        payload.update(updates)
        return DetectionRuleDefinition(**payload)

    def event(self, suffix: str, operation: str = "external.send") -> AgentEvent:
        return AgentEvent(
            event_id="evt_content_%s" % suffix,
            occurred_at=self.clock.value,
            tenant_id="tenant-lab",
            flow_id="flow-content-%s" % suffix,
            agent_id="agent-content",
            operation=operation,
            resource="asset://content/%s" % suffix,
            source_type="user",
            source_id="user://content-test",
            source_trust=TrustClass.AUTHENTICATED_USER,
            authority_operations={"external.send", "asset.read"},
        )

    def suite(self) -> RuleTestSuite:
        matching = self.event("match")
        benign = self.event("benign", operation="asset.read")
        return RuleTestSuite(
            name="External send positive and benign control",
            events=[matching, benign],
            expected_alert_event_ids={matching.event_id},
        )

    def publish_definition(self, definition=None):
        record = self.content.create_draft(self.author, definition or self.definition())
        record = self.content.validate(self.author, record.content_id, self.suite())
        record = self.content.backtest(
            self.author, record.content_id, self.suite().events
        )
        record = self.content.submit(self.author, record.content_id)
        record = self.content.review(
            self.reviewer, record.content_id, ReviewDecision.APPROVE,
            "Independent review confirms the evidence and expected outcome.",
        )
        record = self.content.deploy_shadow(self.publisher, record.content_id)
        record = self.content.backtest(
            self.publisher, record.content_id, self.suite().events, shadow=True
        )
        return self.content.publish(
            self.publisher,
            record.content_id,
            expected_definition_sha256=record.shadow_result.definition_sha256,
        )

    def test_full_four_eyes_lifecycle_publishes_signed_rule_and_health(self) -> None:
        draft = self.content.create_draft(self.author, self.definition())
        validated = self.content.validate(self.author, draft.content_id, self.suite())
        self.assertTrue(validated.validation.passed)
        with self.assertRaises(ContentAuthorizationError):
            submitted = self.content.submit(self.author, draft.content_id)
            self.content.review(
                self.author, submitted.content_id, ReviewDecision.APPROVE, "Self approval"
            )
        submitted = self.content.get(self.author, draft.content_id)
        approved = self.content.review(
            self.reviewer, submitted.content_id, ReviewDecision.APPROVE,
            "Independent reviewer approved deterministic rule behavior.",
        )
        self.assertEqual(approved.status, RuleContentStatus.APPROVED)
        shadow = self.content.deploy_shadow(self.publisher, approved.content_id)
        shadow = self.content.backtest(
            self.publisher, shadow.content_id, self.suite().events, shadow=True
        )
        published = self.content.publish(
            self.publisher,
            shadow.content_id,
            expected_definition_sha256=shadow.shadow_result.definition_sha256,
        )
        self.assertEqual(published.status, RuleContentStatus.PUBLISHED)
        live = self.detection.stream(
            self.detection_principal, self.event("live")
        )
        self.assertEqual([item.alert_type for item in live.alerts], ["content_external_send"])
        health = self.content.health(self.author)
        self.assertEqual(health.published, 1)
        self.assertEqual(health.rule_health[0].match_count, 1)
        self.assertGreaterEqual(len(self.content.history(self.author, draft.content_id)), 6)

        self.content.close()
        self.content = DetectionContentService(
            self.content_path,
            detection_service=self.detection,
            detection_principal=self.detection_principal,
            signer=self.signer,
            clock=self.clock,
        )
        self.assertEqual(
            self.content.get(self.author, published.content_id).record_sha256,
            published.record_sha256,
        )

    def test_failed_validation_blocks_review_and_edits_reset_evidence(self) -> None:
        draft = self.content.create_draft(self.author, self.definition())
        wrong = RuleTestSuite(
            name="Incorrect expected outcome",
            events=[self.event("wrong")],
            expected_alert_event_ids=set(),
        )
        failed = self.content.validate(self.author, draft.content_id, wrong)
        self.assertFalse(failed.validation.passed)
        with self.assertRaisesRegex(ValueError, "passing validation"):
            self.content.submit(self.author, draft.content_id)
        edited = self.content.update_draft(
            self.author,
            draft.content_id,
            self.definition(description="Edited rule requires a fresh test result."),
        )
        self.assertIsNone(edited.validation)

    def test_rejection_rework_and_digest_acknowledgement_fail_closed(self) -> None:
        draft = self.content.create_draft(self.author, self.definition())
        draft = self.content.validate(self.author, draft.content_id, self.suite())
        submitted = self.content.submit(self.author, draft.content_id)
        rejected = self.content.review(
            self.reviewer, submitted.content_id, ReviewDecision.REJECT,
            "Add clearer description before publication.",
        )
        self.assertEqual(rejected.status, RuleContentStatus.REJECTED)
        edited = self.content.update_draft(
            self.author,
            rejected.content_id,
            self.definition(description="Clearer reviewed external-send detection description."),
        )
        edited = self.content.validate(self.author, edited.content_id, self.suite())
        edited = self.content.submit(self.author, edited.content_id)
        edited = self.content.review(
            self.reviewer, edited.content_id, ReviewDecision.APPROVE,
            "Description and deterministic test evidence are complete.",
        )
        edited = self.content.deploy_shadow(self.publisher, edited.content_id)
        edited = self.content.backtest(
            self.publisher, edited.content_id, self.suite().events, shadow=True
        )
        with self.assertRaisesRegex(ValueError, "acknowledgement"):
            self.content.publish(
                self.publisher, edited.content_id,
                expected_definition_sha256="0" * 64,
            )

    def test_rollback_clones_prior_approved_content_under_new_version(self) -> None:
        first = self.publish_definition(self.definition("1.0.0"))
        second = self.publish_definition(
            self.definition(
                "1.1.0",
                description="Second version that will be rolled back.",
                confidence=0.95,
            )
        )
        self.assertEqual(
            self.content.get(self.author, first.content_id).status,
            RuleContentStatus.RETIRED,
        )
        rolled = self.content.rollback(
            self.publisher,
            first.content_id,
            new_version="1.2.0",
            reason="Second version produced unacceptable operational noise.",
        )
        self.assertEqual(rolled.status, RuleContentStatus.PUBLISHED)
        self.assertEqual(rolled.definition.version, "1.2.0")
        self.assertEqual(rolled.definition.confidence, first.definition.confidence)
        self.assertEqual(
            self.content.get(self.author, second.content_id).status,
            RuleContentStatus.RETIRED,
        )
        active = self.detection.list_rules(self.detection_principal)[0]
        self.assertEqual(active.definition.version, "1.2.0")

    def test_signed_content_pack_detects_tamper_and_imports_as_draft(self) -> None:
        published = self.publish_definition()
        pack = self.content.export_pack(
            self.publisher,
            [published.content_id],
            name="AI egress detections",
            description="Reviewed AI-agent egress detection content.",
            version="1.0.0",
        )
        self.content.verify_pack(pack)
        tampered_payload = pack.model_dump(mode="python")
        tampered_payload["name"] = "Tampered pack"
        with self.assertRaisesRegex(ValueError, "digest"):
            self.content.verify_pack(SignedContentPack.model_validate(tampered_payload))

        other_detection = DetectionService(
            self.temp.name + "/import-detection.sqlite3", clock=self.clock
        )
        other_content = DetectionContentService(
            self.temp.name + "/import-content.sqlite3",
            detection_service=other_detection,
            detection_principal=self.detection_principal,
            signer=self.signer,
            clock=self.clock,
        )
        try:
            imported = other_content.import_pack(self.author, pack)
            self.assertEqual(imported[0].status, RuleContentStatus.DRAFT)
            self.assertEqual(imported[0].source_pack_id, pack.pack_id)
        finally:
            other_content.close()
            other_detection.close()

    def test_permissions_tenant_integrity_and_concurrent_duplicates(self) -> None:
        reader = self.author.model_copy(update={"permissions": {CONTENT_READ}})
        with self.assertRaises(ContentAuthorizationError):
            self.content.create_draft(reader, self.definition())
        with self.assertRaises(ContentAuthorizationError):
            self.content.create_draft(
                self.author.model_copy(update={"tenant_id": "tenant-other"}),
                self.definition(),
            )

        def create(_index):
            try:
                return self.content.create_draft(self.author, self.definition()).content_id
            except ValueError:
                return None

        with ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(create, range(8)))
        self.assertEqual(len([item for item in results if item is not None]), 1)
        row = self.content._connection.execute(
            "SELECT content_json FROM detection_content WHERE current = 1"
        ).fetchone()
        corrupted = row["content_json"].replace("Content-managed", "Tampered", 1)
        self.content._connection.execute(
            "UPDATE detection_content SET content_json = ? WHERE current = 1",
            (corrupted,),
        )
        with self.assertRaises(ValueError):
            self.content.list(self.author)

    def test_backtest_is_bounded_at_product_scale(self) -> None:
        draft = self.content.create_draft(self.author, self.definition())
        events = [
            self.event("scale_%04d" % index, "external.send" if index % 2 else "asset.read")
            .model_copy(update={"occurred_at": self.clock.value + timedelta(milliseconds=index)})
            for index in range(400)
        ]
        started = time.perf_counter()
        result = self.content.backtest(self.author, draft.content_id, events)
        self.assertLess(time.perf_counter() - started, 5.0)
        self.assertEqual(result.backtest.event_count, 400)
        self.assertEqual(result.backtest.alert_count, 200)
        with self.assertRaises(ValueError):
            self.content.backtest(
                self.author, draft.content_id, events * 3
            )

    def test_authenticated_content_api_runs_reviewed_lifecycle(self) -> None:
        application = AuthorizationApplication(
            detection_service=self.detection,
            detection_principal=self.detection_principal,
            content_service=self.content,
            content_principal=self.author,
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
                server_name = "agentsec-content-test"
                server_port = 80

            connection = FakeSocket(raw)
            handler(connection, ("127.0.0.1", 12345), FakeServer())
            head, response_body = connection.sent.getvalue().split(b"\r\n\r\n", 1)
            return int(head.splitlines()[0].split()[1]), json.loads(response_body)

        status, unauthorized = request("/v1/detection/content", auth=False)
        self.assertEqual((status, unauthorized["error"]), (401, "unauthorized"))
        status, draft = request(
            "/v1/detection/content",
            method="POST",
            body={"definition": self.definition().model_dump(mode="json")},
        )
        self.assertEqual((status, draft["status"]), (200, "draft"))
        content_id = draft["content_id"]
        edited_definition = self.definition(
            description="Content-managed external send with explicit API lifecycle coverage."
        )
        status, edited = request(
            "/v1/detection/content/%s" % content_id,
            method="PUT",
            body={"definition": edited_definition.model_dump(mode="json")},
        )
        self.assertEqual((status, edited["revision"]), (200, 2))
        suite = self.suite()
        status, validated = request(
            "/v1/detection/content/%s/validate" % content_id,
            method="POST",
            body={"suite": suite.model_dump(mode="json")},
        )
        self.assertEqual((status, validated["validation"]["passed"]), (200, True))
        status, backtested = request(
            "/v1/detection/content/%s/backtest" % content_id,
            method="POST",
            body={"events": [item.model_dump(mode="json") for item in suite.events]},
        )
        self.assertEqual((status, backtested["backtest"]["alert_count"]), (200, 1))
        status, submitted = request(
            "/v1/detection/content/%s/submit" % content_id,
            method="POST",
            body={},
        )
        self.assertEqual((status, submitted["status"]), (200, "in_review"))
        status, approved = request(
            "/v1/detection/content/%s/review" % content_id,
            method="POST",
            body={
                "decision": "approve",
                "comment": "Independent service reviewer confirms deterministic evidence.",
            },
        )
        self.assertEqual((status, approved["status"]), (200, "approved"))
        self.assertNotEqual(approved["author_id"], approved["reviewer_id"])
        status, shadow = request(
            "/v1/detection/content/%s/shadow" % content_id,
            method="POST",
            body={},
        )
        self.assertEqual((status, shadow["status"]), (200, "shadow"))
        status, shadowed = request(
            "/v1/detection/content/%s/shadow-evaluate" % content_id,
            method="POST",
            body={"events": [item.model_dump(mode="json") for item in suite.events]},
        )
        expected_digest = shadowed["shadow_result"]["definition_sha256"]
        status, published = request(
            "/v1/detection/content/%s/publish" % content_id,
            method="POST",
            body={"expected_definition_sha256": expected_digest},
        )
        self.assertEqual((status, published["status"]), (200, "published"))
        status, detail = request("/v1/detection/content/%s" % content_id)
        self.assertEqual((status, detail["record_sha256"]), (200, published["record_sha256"]))
        status, history = request("/v1/detection/content/%s/history" % content_id)
        self.assertGreaterEqual(len(history["history"]), 8)
        status, health = request("/v1/detection/content/health")
        self.assertEqual((status, health["published"]), (200, 1))
        status, rejected = request(
            "/v1/detection/content/%s/publish" % content_id,
            method="POST",
            body={"expected_definition_sha256": expected_digest, "force": True},
        )
        self.assertEqual((status, rejected["error"]), (400, "invalid_request"))

    def test_content_environment_configuration_is_explicit(self) -> None:
        environment = {
            "AGENTSEC_DETECTION_DB": self.temp.name + "/env-detection.sqlite3",
            "AGENTSEC_DETECTION_TENANT": "tenant-lab",
            "AGENTSEC_CONTENT_DB": self.temp.name + "/env-content.sqlite3",
            "AGENTSEC_CONTENT_SIGNING_KEY": "module-ten-environment-signing-key-at-least-32-bytes",
        }
        with patch.dict(os.environ, environment, clear=True):
            application = application_from_environment()
        try:
            self.assertIsNotNone(application.content_service)
            self.assertEqual(application.content_health().tenant_id, "tenant-lab")
        finally:
            application.content_service.close()
            application.detection_service.close()

        with patch.dict(
            os.environ,
            {"AGENTSEC_CONTENT_DB": self.temp.name + "/orphan-content.sqlite3"},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "requires AGENTSEC_DETECTION_DB"):
                application_from_environment()


if __name__ == "__main__":
    unittest.main()
