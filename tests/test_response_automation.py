from __future__ import annotations

from io import BytesIO
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from agentsec.pipeline import SecurityPipeline
from agentsec.response import (
    ApprovalScope,
    ExecutionStatus,
    HttpResponseConnector,
    PlaybookStatus,
    PlaybookStepDefinition,
    PlaybookTrigger,
    RESPONSE_ADMIN,
    RESPONSE_APPROVE,
    RESPONSE_AUTHOR,
    RESPONSE_EXECUTE,
    RESPONSE_OPERATE,
    RESPONSE_READ,
    RESPONSE_REVIEW,
    ResponseAutomationService,
    ResponseAutomationPolicy,
    ResponseAuthorizationError,
    ResponseConflictError,
    ResponseConnectorRequest,
    ResponseConnectorResult,
    ResponseExecutionError,
    ResponseOperation,
    ResponsePlaybookDefinition,
    ResponsePrincipal,
    ResponseVerificationResult,
    StepStatus,
    TargetSelector,
    load_response_policy,
    response_service_from_environment,
)
from agentsec.scenarios import forge_scenarios
from agentsec.service import AuthorizationApplication, application_from_environment, make_handler


ALL = {
    RESPONSE_READ,
    RESPONSE_AUTHOR,
    RESPONSE_REVIEW,
    RESPONSE_OPERATE,
    RESPONSE_APPROVE,
    RESPONSE_EXECUTE,
    RESPONSE_ADMIN,
}


class RecordingConnector:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ResponseConnectorRequest]] = []
        self.verification_failure = False

    def execute(self, spec, request):
        self.calls.append(("execute", request))
        return ResponseConnectorResult(
            accepted=True,
            provider_reference="provider-private-reference",
            observed_state=request.expected_state,
        )

    def verify(self, spec, request):
        self.calls.append(("verify", request))
        if self.verification_failure:
            return ResponseVerificationResult(
                verified=False,
                error_code="simulated_state_mismatch",
            )
        return ResponseVerificationResult(
            verified=True,
            observed_state=request.expected_state,
            evidence_reference="provider-private-verification-evidence",
        )

    def rollback(self, spec, request):
        self.calls.append(("rollback", request))
        return ResponseConnectorResult(
            accepted=True,
            provider_reference="provider-private-rollback-reference",
            observed_state=request.expected_state,
        )


class ResponseAutomationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.policy = load_response_policy("configs/response-playbooks.example.json")
        self.connector = RecordingConnector()
        self.connectors = {
            spec.connector_id: self.connector for spec in self.policy.connectors
        }
        self.service = ResponseAutomationService(
            self.temp.name + "/response.sqlite3",
            policy=self.policy,
            connectors=self.connectors,
        )
        self.system = self.principal("system://response-test", ALL)

    def tearDown(self) -> None:
        self.service.close()
        self.temp.cleanup()

    @staticmethod
    def principal(actor: str, permissions=ALL, tenant: str = "tenant-lab"):
        return ResponsePrincipal(
            tenant_id=tenant,
            actor_id=actor,
            permissions=set(permissions),
        )

    @staticmethod
    def result():
        return SecurityPipeline().process(
            forge_scenarios()["indirect_injection_secret_egress"]
        ).alerts[0]

    def plan(self):
        item = self.result()
        execution = self.service.create_from_pipeline(
            self.system,
            item,
            case_id=item.escalation.case_id,
            correlation_incident_id=None,
        )
        assert execution is not None
        return execution

    def test_pipeline_creates_inert_idempotent_private_durable_dry_run(self) -> None:
        item = self.result()
        execution = self.service.create_from_pipeline(
            self.system,
            item,
            case_id=item.escalation.case_id,
            correlation_incident_id=None,
        )
        assert execution is not None
        repeated = self.service.create_from_pipeline(
            self.system,
            item,
            case_id=item.escalation.case_id,
            correlation_incident_id=None,
        )
        assert repeated is not None
        self.assertEqual(execution.execution_id, repeated.execution_id)
        self.assertEqual(execution.status, ExecutionStatus.DRY_RUN_SUCCEEDED)
        self.assertTrue(execution.live_eligible)
        self.assertEqual(self.connector.calls, [])
        encoded = self.service.get(self.system, execution.execution_id).model_dump_json()
        self.assertNotIn(item.event.agent_id, encoded)
        self.assertNotIn(item.event.flow_id, encoded)
        self.assertNotIn(item.event.destination or "", encoded)
        self.assertNotIn("provider-private", encoded)
        self.service.close()
        self.service = ResponseAutomationService(
            self.temp.name + "/response.sqlite3",
            policy=self.policy,
            connectors=self.connectors,
        )
        restarted = self.service.get(self.system, execution.execution_id)
        self.assertEqual(restarted.execution.record_sha256, execution.record_sha256)

    def test_request_approval_execute_verify_and_independent_rollback(self) -> None:
        execution = self.plan()
        operator = self.principal(
            "analyst://response-operator", {RESPONSE_READ, RESPONSE_OPERATE}
        )
        approver = self.principal(
            "analyst://response-approver", {RESPONSE_READ, RESPONSE_APPROVE}
        )
        executor = self.principal(
            "system://response-executor", {RESPONSE_READ, RESPONSE_EXECUTE}
        )
        execution = self.service.request_live(
            operator,
            execution.execution_id,
            expected_version=execution.version,
            reason="Exact targets, reversible steps, and connector readiness were reviewed.",
        )
        self.assertEqual(execution.status, ExecutionStatus.AWAITING_APPROVAL)
        with self.assertRaises(ResponseAuthorizationError):
            self.service.approve(
                operator.model_copy(update={"permissions": {RESPONSE_APPROVE}}),
                execution.execution_id,
                scope=ApprovalScope.EXECUTE,
                expected_version=execution.version,
                reason="A requester cannot self-approve.",
            )
        approval = self.service.approve(
            approver,
            execution.execution_id,
            scope=ApprovalScope.EXECUTE,
            expected_version=execution.version,
            reason="Independent reviewer approved the exact immutable execution plan.",
        )
        self.assertEqual(approval.scope, ApprovalScope.EXECUTE)
        with self.assertRaises(ResponseAuthorizationError):
            self.service.execute(
                approver.model_copy(
                    update={"permissions": {RESPONSE_READ, RESPONSE_EXECUTE}}
                ),
                execution.execution_id,
            )
        execution = self.service.execute(executor, execution.execution_id)
        self.assertEqual(execution.status, ExecutionStatus.SUCCEEDED)
        self.assertTrue(all(step.status == StepStatus.SUCCEEDED for step in execution.steps))
        detail = self.service.get(self.system, execution.execution_id)
        self.assertEqual(
            [item.phase.value for item in detail.attempts],
            ["execute", "verify", "execute", "verify"],
        )
        self.assertNotIn("provider-private", detail.model_dump_json())

        execution = self.service.request_rollback(
            operator,
            execution.execution_id,
            expected_version=execution.version,
            reason="Restore the isolated targets after containment evidence was captured.",
        )
        rollback_approval = self.service.approve(
            approver,
            execution.execution_id,
            scope=ApprovalScope.ROLLBACK,
            expected_version=execution.version,
            reason="Independent reviewer approved the exact compensating plan.",
        )
        self.assertEqual(rollback_approval.scope, ApprovalScope.ROLLBACK)
        execution = self.service.rollback(executor, execution.execution_id)
        self.assertEqual(execution.status, ExecutionStatus.ROLLED_BACK)
        self.assertTrue(all(step.status == StepStatus.ROLLED_BACK for step in execution.steps))
        rolled_back_detail = self.service.get(self.system, execution.execution_id)
        self.assertEqual(
            sum(
                entry.action == "rollback_step_verified"
                for entry in rolled_back_detail.audit
            ),
            2,
        )
        self.assertEqual(self.service.health(self.system).rolled_back, 1)

    def test_terminal_step_checkpoints_bind_attempt_membership(self) -> None:
        execution = self.plan()
        operator = self.principal("analyst://attempt-operator", {RESPONSE_OPERATE})
        approver = self.principal("analyst://attempt-approver", {RESPONSE_APPROVE})
        executor = self.principal("system://attempt-executor", {RESPONSE_EXECUTE})
        execution = self.service.request_live(
            operator,
            execution.execution_id,
            expected_version=execution.version,
            reason="Validate signed attempt membership after terminal execution.",
        )
        self.service.approve(
            approver,
            execution.execution_id,
            scope=ApprovalScope.EXECUTE,
            expected_version=execution.version,
            reason="Approve the exact reversible attempt-integrity test plan.",
        )
        execution = self.service.execute(executor, execution.execution_id)
        detail = self.service.get(self.system, execution.execution_id)
        self.assertEqual(
            len(detail.attempts),
            sum(step.attempt_count for step in detail.execution.steps),
        )
        removed = detail.attempts[0]
        self.service._connection.execute(
            "DELETE FROM response_attempts WHERE tenant_id=? AND attempt_id=?",
            (removed.tenant_id, removed.attempt_id),
        )
        with self.assertRaises(Exception):
            self.service.get(self.system, execution.execution_id)
        with self.assertRaises(Exception):
            self.service.health(self.system)

    def test_verification_failure_and_kill_switch_are_visible_and_safe(self) -> None:
        execution = self.plan()
        operator = self.principal("analyst://operator", {RESPONSE_OPERATE})
        approver = self.principal("analyst://approver", {RESPONSE_APPROVE})
        executor = self.principal("system://executor", {RESPONSE_EXECUTE})
        control = self.service._control("tenant-lab")
        control = self.service.set_kill_switch(
            self.system,
            active=True,
            expected_version=control.version,
            reason="Emergency stop exercised before a live request.",
        )
        with self.assertRaises(ResponseExecutionError):
            self.service.request_live(
                operator,
                execution.execution_id,
                expected_version=execution.version,
                reason="Kill switch must reject this request.",
            )
        control = self.service.set_kill_switch(
            self.system,
            active=False,
            expected_version=control.version,
            reason="Isolated connector and operator approval path revalidated.",
        )
        execution = self.service.request_live(
            operator,
            execution.execution_id,
            expected_version=execution.version,
            reason="Request the exact reversible plan after revalidation.",
        )
        self.service.approve(
            approver,
            execution.execution_id,
            scope=ApprovalScope.EXECUTE,
            expected_version=execution.version,
            reason="Approve verification-failure test plan independently.",
        )
        self.connector.verification_failure = True
        execution = self.service.execute(executor, execution.execution_id)
        self.assertEqual(execution.status, ExecutionStatus.FAILED)
        self.assertEqual(execution.steps[0].last_error_code, "simulated_state_mismatch")
        health = self.service.health(self.system)
        self.assertGreaterEqual(health.failed, 1)
        self.assertGreaterEqual(health.verification_failures, 1)

    def test_playbook_editor_enforces_author_review_activation_separation(self) -> None:
        definition = ResponsePlaybookDefinition(
            playbook_id="playbook://response/test-pause-agent",
            version=1,
            name="Test pause agent",
            description="Reversibly pause one opaque agent reference after review.",
            trigger=PlaybookTrigger(
                priorities=["P0"],
                escalation_levels=["incident_page"],
                decisions=["deny"],
            ),
            steps=[
                PlaybookStepDefinition(
                    step_id="step://test/pause-agent",
                    name="Pause exact agent",
                    operation=ResponseOperation.AGENT_PAUSE,
                    connector_id="connector://response/control-plane",
                    target_selector=TargetSelector.AGENT,
                    expected_state="paused",
                    rollback_operation=ResponseOperation.AGENT_RESUME,
                    rollback_expected_state="active",
                    timeout_seconds=5,
                    requires_approval=True,
                )
            ],
        )
        author = self.principal("analyst://playbook-author", {RESPONSE_AUTHOR})
        reviewer = self.principal("analyst://playbook-reviewer", {RESPONSE_REVIEW})
        publisher = self.principal("system://playbook-publisher", {RESPONSE_ADMIN})
        record = self.service.create_playbook_draft(author, definition)
        record = self.service.playbook_action(
            author,
            definition.playbook_id,
            definition.version,
            action="submit",
            expected_revision=record.revision,
            comment="Submit the exact immutable action and rollback pair.",
        )
        with self.assertRaises(ResponseAuthorizationError):
            self.service.playbook_action(
                author.model_copy(update={"permissions": {RESPONSE_REVIEW}}),
                definition.playbook_id,
                definition.version,
                action="approve",
                expected_revision=record.revision,
                comment="Self-review must fail.",
            )
        record = self.service.playbook_action(
            reviewer,
            definition.playbook_id,
            definition.version,
            action="approve",
            expected_revision=record.revision,
            comment="Independent connector, target, verification, and rollback review passed.",
        )
        self.assertEqual(record.status, PlaybookStatus.APPROVED)
        record = self.service.playbook_action(
            publisher,
            definition.playbook_id,
            definition.version,
            action="activate",
            expected_revision=record.revision,
            comment="Activate independently reviewed immutable playbook.",
        )
        self.assertEqual(record.status, PlaybookStatus.ACTIVE)

    def test_permissions_tenant_audit_and_missing_connectors_fail_closed(self) -> None:
        execution = self.plan()
        with self.assertRaises((ResponseAuthorizationError, KeyError)):
            self.service.get(
                self.principal("analyst://wrong", {RESPONSE_READ}, tenant="other"),
                execution.execution_id,
            )
        with self.assertRaises(ResponseAuthorizationError):
            self.service.list(self.principal("analyst://none", set()))
        with self.assertRaises(ValueError):
            self.service.list(self.system, limit=1000)
        self.service._connection.execute(
            "DELETE FROM response_audit WHERE tenant_id=? AND execution_id=? AND sequence=?",
            ("tenant-lab", execution.execution_id, execution.audit_count),
        )
        with self.assertRaises(Exception):
            self.service.get(self.system, execution.execution_id)

        empty, principal = response_service_from_environment(
            self.temp.name + "/environment.sqlite3",
            "configs/response-playbooks.example.json",
            tenant_id="tenant-lab",
            environment={},
        )
        statuses = empty.connectors_status(principal)
        self.assertEqual(len(statuses), 4)
        self.assertTrue(all(not item.ready for item in statuses))
        self.assertNotIn("credential", str([item.model_dump() for item in statuses]).lower())
        planned = empty.create_from_pipeline(
            principal,
            self.result(),
            case_id=self.result().escalation.case_id,
            correlation_incident_id=None,
        )
        assert planned is not None
        self.assertFalse(planned.live_eligible)
        with self.assertRaises(ResponseExecutionError):
            empty.request_live(
                principal,
                planned.execution_id,
                expected_version=planned.version,
                reason="A missing connector must fail closed.",
            )
        empty.close()

    def test_pipeline_integration_is_post_response_and_outage_is_non_executive(self) -> None:
        pipeline = SecurityPipeline(
            response_service=self.service,
            response_principal=self.system,
        )
        result = pipeline.process(
            forge_scenarios()["indirect_injection_secret_egress"]
        )
        self.assertFalse(result.effect_allowed)
        self.assertGreaterEqual(self.service.list(self.system).count, 1)
        self.assertEqual(self.connector.calls, [])
        self.assertIsNone(pipeline.last_response_automation_error)

        class BrokenResponseService:
            def create_from_pipeline(self, *_args, **_kwargs):
                raise RuntimeError("private response failure")

        broken = SecurityPipeline(
            response_service=BrokenResponseService(),
            response_principal=self.system,
        )
        blocked = broken.process(forge_scenarios()["mcp_schema_drift"])
        self.assertFalse(blocked.effect_allowed)
        self.assertEqual(
            broken.last_response_automation_error,
            "response_automation_unavailable",
        )
        self.assertNotIn("private response failure", blocked.model_dump_json())

    def test_authenticated_response_http_api_is_fixed_and_actor_safe(self) -> None:
        token = "module-nineteen-http-token-at-least-32-characters"
        application = AuthorizationApplication(
            response_service=self.service,
            response_principal=self.system,
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

        self.assertEqual(request("/v1/response/executions", auth=False)[0], 401)
        event = forge_scenarios()["indirect_injection_secret_egress"]
        self.assertEqual(
            request(
                "/v1/authorize",
                method="POST",
                body=event.model_dump(mode="json"),
            )[0],
            200,
        )
        status, page = request("/v1/response/executions")
        self.assertEqual((status, page["count"]), (200, 2))
        execution = page["executions"][0]
        execution_id = execution["execution_id"]
        self.assertEqual(request("/v1/response/health")[0], 200)
        status, connectors = request("/v1/response/connectors")
        self.assertEqual((status, len(connectors["connectors"])), (200, 4))
        self.assertNotIn("credential_env", json.dumps(connectors))
        self.assertEqual(request("/v1/response/control")[0], 200)
        self.assertEqual(request("/v1/response/playbooks")[0], 200)
        self.assertEqual(
            request("/v1/response/executions/%s" % execution_id)[0], 200
        )
        status, invalid = request(
            "/v1/response/executions/%s/request-live" % execution_id,
            method="POST",
            body={
                "expected_version": execution["version"],
                "reason": "Exact plan reviewed.",
                "actor_id": "analyst://spoofed",
            },
        )
        self.assertEqual((status, invalid["error"]), (400, "invalid_request"))

    def test_application_environment_assembles_response_store(self) -> None:
        values = {
            "AGENTSEC_RESPONSE_DB": self.temp.name + "/application.sqlite3",
            "AGENTSEC_RESPONSE_CONFIG": "configs/response-playbooks.example.json",
            "AGENTSEC_RESPONSE_TENANT": "tenant-lab",
            "AGENTSEC_RESPONSE_CONTROL_TOKEN": "response-control-token-long-enough",
            "AGENTSEC_RESPONSE_IDENTITY_TOKEN": "response-identity-token-long-enough",
            "AGENTSEC_RESPONSE_NETWORK_TOKEN": "response-network-token-long-enough",
            "AGENTSEC_RESPONSE_TICKET_TOKEN": "response-ticket-token-long-enough",
        }
        with patch.dict(os.environ, values, clear=True):
            application = application_from_environment()
        try:
            health = application.response_health()
            self.assertEqual(
                (health.configured_connectors, health.ready_connectors),
                (4, 4),
            )
            self.assertEqual(
                application.response_principal.permissions,
                {RESPONSE_READ, RESPONSE_OPERATE},
            )
            self.assertNotIn(
                RESPONSE_APPROVE, application.response_principal.permissions
            )
        finally:
            application.response_service.close()

    def test_health_counts_the_complete_tenant_not_only_the_first_page(self) -> None:
        for _index in range(205):
            base = self.result()
            item = base.model_copy(
                update={
                    "finding": base.finding.model_copy(
                        update={"finding_id": "fnd_scale%03d" % _index}
                    ),
                    "alert": base.alert.model_copy(
                        update={"alert_id": "alr_scale%03d" % _index}
                    ),
                }
            )
            execution = self.service.create_from_pipeline(
                self.system,
                item,
                case_id=item.escalation.case_id,
                correlation_incident_id=None,
            )
            self.assertIsNotNone(execution)

        health = self.service.health(self.system)
        self.assertEqual(health.total_executions, 205)
        self.assertEqual(health.dry_runs, 205)
        self.assertEqual(health.awaiting_approval, 0)

    def test_matching_uses_explicit_playbook_priority_not_input_order(self) -> None:
        primary = self.policy.playbooks[0]
        secondary_payload = self.policy.playbooks[1].model_dump(mode="json")
        secondary_payload.update(
            {
                "playbook_id": "playbook://response/lower-precedence-overlap",
                "priority": primary.priority + 50,
                "trigger": primary.trigger.model_dump(mode="json"),
                "definition_sha256": "0" * 64,
            }
        )
        secondary = ResponsePlaybookDefinition.model_validate(secondary_payload)
        policy_payload = self.policy.model_dump(mode="json")
        policy_payload.update(
            {
                "playbooks": [
                    secondary.model_dump(mode="json"),
                    primary.model_dump(mode="json"),
                ],
                "policy_sha256": "0" * 64,
            }
        )
        policy = ResponseAutomationPolicy.model_validate(policy_payload)
        service = ResponseAutomationService(
            self.temp.name + "/priority.sqlite3",
            policy=policy,
            connectors=self.connectors,
        )
        try:
            item = self.result()
            execution = service.create_from_pipeline(
                self.system,
                item,
                case_id=item.escalation.case_id,
                correlation_incident_id=None,
            )
            self.assertIsNotNone(execution)
            self.assertEqual(execution.playbook_id, primary.playbook_id)
        finally:
            service.close()


if __name__ == "__main__":
    unittest.main()
