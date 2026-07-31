from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from io import BytesIO
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from agentsec.cases import (
    CASE_ADMIN,
    CASE_ASSIGN,
    CASE_ATTACH,
    CASE_COMMENT,
    CASE_READ,
    CASE_REVIEW,
    CASE_TASK,
    CASE_WRITE,
    AttachmentScanStatus,
    CaseAuthorizationError,
    CaseConflictError,
    CasePrincipal,
    CaseRelationshipKind,
    CaseReviewDecision,
    CaseService,
    CaseStatus,
    CaseTaskStatus,
)
from agentsec.pipeline import SecurityPipeline
from agentsec.scenarios import forge_scenarios
from agentsec.service import (
    AuthorizationApplication,
    application_from_environment,
    make_handler,
)


HTTP_TOKEN = "module-seventeen-case-http-token-at-least-32-characters"
ALL_PERMISSIONS = {
    CASE_READ,
    CASE_WRITE,
    CASE_ASSIGN,
    CASE_COMMENT,
    CASE_TASK,
    CASE_ATTACH,
    CASE_REVIEW,
    CASE_ADMIN,
}


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 24, 10, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value


class CaseManagementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.service = CaseService(self.temp.name + "/cases.sqlite3", clock=self.clock)
        self.principal = CasePrincipal(
            tenant_id="tenant-lab",
            actor_id="analyst://alice",
            permissions=ALL_PERMISSIONS,
            team_ids={"team://soc"},
        )
        self.service.create_team(
            self.principal,
            team_id="team://soc",
            name="AI security SOC",
            description="Authenticated analysts responsible for AI security cases.",
            member_ids=["analyst://alice", "analyst://bob"],
        )

    def tearDown(self) -> None:
        self.service.close()
        self.temp.cleanup()

    @staticmethod
    def pipeline_result(name: str = "mcp_schema_drift"):
        return SecurityPipeline().process(forge_scenarios()[name]).alerts[0]

    def create_case(self, name: str = "mcp_schema_drift"):
        return self.service.create_from_pipeline(
            self.principal, self.pipeline_result(name)
        )

    def test_pipeline_case_is_durable_redacted_and_idempotent(self) -> None:
        result = self.pipeline_result()
        case = self.service.create_from_pipeline(self.principal, result)
        repeated = self.service.create_from_pipeline(self.principal, result)
        self.assertEqual(repeated.case_id, case.case_id)
        self.assertEqual(case.audit_count, 1)
        self.assertNotEqual(case.audit_head_sha256, "0" * 64)
        self.assertEqual(case.finding_ids, [result.finding.finding_id])
        self.assertLess(case.acknowledgment_due_at, case.due_at)

        self.service.close()
        self.service = CaseService(self.temp.name + "/cases.sqlite3", clock=self.clock)
        detail = self.service.get(self.principal, case.case_id)
        self.assertEqual(detail.case.case_id, case.case_id)
        self.assertEqual(detail.audit[-1].audit_sha256, detail.case.audit_head_sha256)
        self.assertNotIn("authorization", detail.model_dump_json().lower())

    def test_complete_collaboration_review_close_and_reopen(self) -> None:
        case = self.create_case()
        case = self.service.assign(
            self.principal,
            case.case_id,
            expected_version=case.version,
            assigned_to="analyst://alice",
            team_id="team://soc",
        )
        replayed = self.service.assign(
            self.principal,
            case.case_id,
            expected_version=case.version - 1,
            assigned_to="analyst://alice",
            team_id="team://soc",
        )
        self.assertEqual(replayed.record_sha256, case.record_sha256)
        case = self.service.acknowledge(
            self.principal, case.case_id, expected_version=case.version
        )
        case = self.service.start_investigation(
            self.principal, case.case_id, expected_version=case.version
        )
        comment = self.service.add_comment(
            self.principal,
            case.case_id,
            expected_version=case.version,
            body="Reviewed detector, triage, judgment, and ledger evidence.",
        )
        repeated_comment = self.service.add_comment(
            self.principal,
            case.case_id,
            expected_version=case.version,
            body="Reviewed detector, triage, judgment, and ledger evidence.",
        )
        self.assertEqual(comment.comment_id, repeated_comment.comment_id)
        case = self.service.get(self.principal, case.case_id).case
        task = self.service.create_task(
            self.principal,
            case.case_id,
            expected_version=case.version,
            title="Validate evidence",
            description="Confirm the governed evidence supports the final disposition.",
            assigned_to="analyst://alice",
        )
        case = self.service.get(self.principal, case.case_id).case
        task = self.service.transition_task(
            self.principal,
            case.case_id,
            task.task_id,
            expected_version=case.version,
            status=CaseTaskStatus.IN_PROGRESS,
        )
        case = self.service.get(self.principal, case.case_id).case
        self.service.transition_task(
            self.principal,
            case.case_id,
            task.task_id,
            expected_version=case.version,
            status=CaseTaskStatus.DONE,
        )
        case = self.service.get(self.principal, case.case_id).case
        with self.assertRaises(ValueError):
            self.service.add_attachment(
                self.principal,
                case.case_id,
                expected_version=case.version,
                display_name="../evidence.json",
                media_type="application/json",
                size_bytes=20,
                content_sha256="a" * 64,
                evidence_ref="evidence_sha256:" + "b" * 24,
            )
        attachment = self.service.add_attachment(
            self.principal,
            case.case_id,
            expected_version=case.version,
            display_name="evidence.json",
            media_type="application/json",
            size_bytes=20,
            content_sha256="a" * 64,
            evidence_ref="evidence_sha256:" + "b" * 24,
        )
        case = self.service.get(self.principal, case.case_id).case
        case = self.service.request_review(
            self.principal, case.case_id, expected_version=case.version
        )
        reviewer = self.principal.model_copy(update={"actor_id": "analyst://bob"})
        with self.assertRaises(CaseConflictError):
            self.service.review(
                reviewer,
                case.case_id,
                expected_version=case.version,
                decision=CaseReviewDecision.APPROVE,
                comment="Pending attachment metadata cannot support closure.",
            )
        case = self.service.review(
            reviewer,
            case.case_id,
            expected_version=case.version,
            decision=CaseReviewDecision.REQUEST_CHANGES,
            comment="Scan the registered attachment before requesting approval.",
        )
        self.service.record_attachment_scan(
            self.principal,
            case.case_id,
            attachment.attachment_id,
            expected_version=case.version,
            status=AttachmentScanStatus.CLEAN,
            scanner_ref="scanner_sha256:" + "c" * 24,
        )
        case = self.service.get(self.principal, case.case_id).case
        case = self.service.request_review(
            self.principal, case.case_id, expected_version=case.version
        )
        with self.assertRaises(CaseAuthorizationError):
            self.service.review(
                self.principal,
                case.case_id,
                expected_version=case.version,
                decision=CaseReviewDecision.APPROVE,
                comment="The same analyst cannot approve this closure.",
            )
        case = self.service.review(
            reviewer,
            case.case_id,
            expected_version=case.version,
            decision=CaseReviewDecision.APPROVE,
            comment="Independent review confirms evidence and tasks support closure.",
        )
        case = self.service.close_case(
            reviewer, case.case_id, expected_version=case.version
        )
        self.assertEqual(case.status, CaseStatus.CLOSED)
        case = self.service.start_investigation(
            reviewer, case.case_id, expected_version=case.version
        )
        self.assertEqual(case.status, CaseStatus.INVESTIGATING)
        self.assertIn("case_reopened", [item.action for item in self.service.get(reviewer, case.case_id).audit])

    def test_permissions_tenant_team_and_concurrency_fail_closed(self) -> None:
        case = self.create_case()
        reader = self.principal.model_copy(update={"permissions": {CASE_READ}})
        with self.assertRaises(CaseAuthorizationError):
            self.service.add_comment(
                reader, case.case_id, expected_version=case.version, body="Not allowed."
            )
        outsider = self.principal.model_copy(update={"tenant_id": "tenant-other"})
        with self.assertRaises(KeyError):
            self.service.get(outsider, case.case_id)
        with self.assertRaises((KeyError, CaseAuthorizationError)):
            self.service.assign(
                self.principal,
                case.case_id,
                expected_version=case.version,
                assigned_to="analyst://mallory",
                team_id="team://soc",
            )

        def update(index: int) -> str:
            try:
                return self.service.add_comment(
                    self.principal,
                    case.case_id,
                    expected_version=case.version,
                    body="Concurrent analyst note %d." % index,
                ).comment_id
            except CaseConflictError:
                return "conflict"

        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(update, range(4)))
        self.assertEqual(sum(item != "conflict" for item in outcomes), 1)

    def test_team_creation_is_replay_safe_and_conflicting_redefinition_fails(self) -> None:
        repeated = self.service.create_team(
            self.principal,
            team_id="team://soc",
            name="AI security SOC",
            description="Authenticated analysts responsible for AI security cases.",
            member_ids=["analyst://alice", "analyst://bob"],
        )
        self.assertEqual(repeated.team_id, "team://soc")
        with self.assertRaises(CaseConflictError):
            self.service.create_team(
                self.principal,
                team_id="team://soc",
                name="Different team",
                description="A conflicting definition must not replace the durable team.",
                member_ids=["analyst://alice"],
            )

    def test_cross_service_version_conflict_and_audit_tail_deletion_fail_closed(self) -> None:
        case = self.create_case()
        second = CaseService(self.temp.name + "/cases.sqlite3", clock=self.clock)
        try:
            def update(service_and_note) -> str:
                service, note = service_and_note
                try:
                    return service.add_comment(
                        self.principal,
                        case.case_id,
                        expected_version=case.version,
                        body=note,
                    ).comment_id
                except CaseConflictError:
                    return "conflict"

            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(
                    pool.map(
                        update,
                        [
                            (self.service, "First independent service note."),
                            (second, "Second independent service note."),
                        ],
                    )
                )
            self.assertEqual(sum(item != "conflict" for item in outcomes), 1)
        finally:
            second.close()

        current = self.service.get(self.principal, case.case_id).case
        self.service._connection.execute(
            "DELETE FROM case_audit WHERE tenant_id = ? AND case_id = ? AND item_sha256 = ?",
            (
                self.principal.tenant_id,
                case.case_id,
                current.audit_head_sha256,
            ),
        )
        with self.assertRaisesRegex(ValueError, "complete audit trail"):
            self.service.get(self.principal, case.case_id)

    def test_relationship_validation_duplicate_and_parent_cycle(self) -> None:
        one = self.create_case("mcp_schema_drift")
        two = self.create_case("persistent_memory_poisoning")
        relation = self.service.add_relationship(
            self.principal,
            one.case_id,
            expected_version=one.version,
            kind=CaseRelationshipKind.PARENT,
            target_type="case",
            target_id=two.case_id,
            reason="Evidence shows the second case is a child investigation.",
        )
        self.assertEqual(relation.target_id, two.case_id)
        one = self.service.get(self.principal, one.case_id).case
        replay = self.service.add_relationship(
            self.principal,
            one.case_id,
            expected_version=one.version - 1,
            kind=CaseRelationshipKind.PARENT,
            target_type="case",
            target_id=two.case_id,
            reason="Evidence shows the second case is a child investigation.",
        )
        self.assertEqual(replay.relationship_id, relation.relationship_id)
        with self.assertRaises(CaseConflictError):
            self.service.add_relationship(
                self.principal,
                two.case_id,
                expected_version=two.version,
                kind=CaseRelationshipKind.PARENT,
                target_type="case",
                target_id=one.case_id,
                reason="This reverse link would create a parent cycle.",
            )
        with self.assertRaises(ValueError):
            self.service.add_relationship(
                self.principal,
                two.case_id,
                expected_version=two.version,
                kind=CaseRelationshipKind.RELATED,
                target_type="finding",
                target_id="../../secret",
            )

    def test_sla_and_nested_audit_tamper_are_visible(self) -> None:
        case = self.create_case()
        self.clock.value = case.acknowledgment_due_at + timedelta(seconds=1)
        case = self.service.acknowledge(
            self.principal, case.case_id, expected_version=case.version
        )
        self.assertEqual(case.sla_state.value, "breached")
        health = self.service.health(self.principal)
        self.assertEqual(health.acknowledgment_breaches, 1)
        row = self.service._connection.execute(
            "SELECT item_json FROM case_audit WHERE tenant_id = ? AND case_id = ?",
            (self.principal.tenant_id, case.case_id),
        ).fetchone()
        self.service._connection.execute(
            "UPDATE case_audit SET item_json = ? WHERE tenant_id = ? AND case_id = ?",
            (
                row["item_json"].replace("case_created", "case_deleted"),
                self.principal.tenant_id,
                case.case_id,
            ),
        )
        with self.assertRaises(ValueError):
            self.service.get(self.principal, case.case_id)

    def test_case_child_capacity_is_bounded_and_fail_closed(self) -> None:
        case = self.create_case()
        with patch("agentsec.cases.MAX_CASE_COMMENTS", 1):
            self.service.add_comment(
                self.principal,
                case.case_id,
                expected_version=case.version,
                body="First bounded analyst note.",
            )
            current = self.service.get(self.principal, case.case_id).case
            with self.assertRaises(CaseConflictError):
                self.service.add_comment(
                    self.principal,
                    case.case_id,
                    expected_version=current.version,
                    body="This note exceeds the configured case capacity.",
                )

    def test_authenticated_http_api_exposes_real_case_collaboration(self) -> None:
        application = AuthorizationApplication(
            case_service=self.service, case_principal=self.principal
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

        self.assertEqual(request("/v1/cases", auth=False)[0], 401)
        event = forge_scenarios()["mcp_schema_drift"]
        self.assertEqual(
            request("/v1/authorize", method="POST", body=event.model_dump(mode="json"))[0],
            200,
        )
        status, page = request("/v1/cases")
        self.assertEqual((status, page["count"]), (200, 1))
        case = page["cases"][0]
        status, teams = request("/v1/case-teams")
        self.assertEqual((status, teams["teams"][0]["team_id"]), (200, "team://soc"))
        status, acknowledged = request(
            "/v1/cases/%s/acknowledge" % case["case_id"],
            method="POST",
            body={"expected_version": case["version"]},
        )
        self.assertEqual((status, acknowledged["acknowledged_at"] is not None), (200, True))
        status, invalid = request(
            "/v1/cases/%s/comments" % case["case_id"],
            method="POST",
            body={"expected_version": acknowledged["version"], "body": "Audit note.", "actor_id": "analyst://spoofed"},
        )
        self.assertEqual((status, invalid["error"]), (400, "invalid_request"))

    def test_environment_is_explicit_and_case_outage_is_non_executive(self) -> None:
        path = self.temp.name + "/environment-cases.sqlite3"
        with patch.dict(
            os.environ,
            {"AGENTSEC_CASE_DB": path, "AGENTSEC_CASE_TENANT": "tenant-lab"},
            clear=True,
        ):
            application = application_from_environment()
        try:
            self.assertEqual(application.case_health().tenant_id, "tenant-lab")
            self.assertEqual(application.case_teams()[0].team_id, "team://local-security")
        finally:
            application.case_service.close()

        class BrokenCase:
            def create_from_pipeline(self, *_args, **_kwargs):
                raise RuntimeError("private database detail")

        pipeline = SecurityPipeline(
            case_service=BrokenCase(),  # type: ignore[arg-type]
            case_principal=self.principal,
        )
        result = pipeline.process(forge_scenarios()["mcp_schema_drift"])
        self.assertFalse(result.effect_allowed)
        self.assertEqual(pipeline.last_case_error, "case_management_unavailable")
        self.assertNotIn("private database detail", result.model_dump_json())


if __name__ == "__main__":
    unittest.main()
