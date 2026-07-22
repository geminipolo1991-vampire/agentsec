from __future__ import annotations

import unittest
from datetime import timedelta

from agentsec.approval import ApprovalService
from agentsec.authority import AuthorityError, AuthorityService
from agentsec.contracts import TrustClass
from agentsec.crypto import PocHmacSigner
from agentsec.provenance import ProvenanceStore
from agentsec.scenarios import forge_scenarios
from agentsec.synthetic import ControlledToolGateway


TEST_KEY = b"local-test-key-material-is-at-least-32-bytes"


class AuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = AuthorityService(PocHmacSigner(TEST_KEY))
        self.root = self.service.issue_root(
            issuer="human://analyst/alice",
            subject="response-agent",
            tenant_id="tenant-lab",
            environment="test",
            operations={"asset.read", "host.isolate"},
            resources={"asset://host/*"},
            data_classes={"internal"},
            max_delegation_depth=2,
            max_execution_count=2,
        )

    def test_child_grant_can_only_narrow_authority(self) -> None:
        child = self.service.delegate(
            self.root,
            subject="isolation-agent",
            operations={"host.isolate"},
            resources={"asset://host/lab-*"},
            data_classes=set(),
            max_execution_count=1,
        )

        self.assertEqual(child.parent_grant_id, self.root.grant_id)
        self.assertEqual(child.operations, {"host.isolate"})
        self.assertTrue(self.service.verify_signature(child))

    def test_operation_expansion_is_rejected(self) -> None:
        with self.assertRaisesRegex(AuthorityError, "expand operations"):
            self.service.delegate(
                self.root,
                subject="isolation-agent",
                operations={"host.isolate", "external.send"},
                resources={"asset://host/lab-*"},
            )

    def test_resource_expansion_is_rejected(self) -> None:
        with self.assertRaisesRegex(AuthorityError, "expand resource"):
            self.service.delegate(
                self.root,
                subject="isolation-agent",
                operations={"host.isolate"},
                resources={"secret://*"},
            )

    def test_execution_count_is_enforced(self) -> None:
        event = forge_scenarios()["benign_inventory_read"].model_copy(
            update={"agent_id": "response-agent", "data_classes": set()}
        )
        self.assertTrue(self.service.authorize(self.root, event, consume=True))
        self.assertTrue(self.service.authorize(self.root, event, consume=True))
        self.assertFalse(self.service.authorize(self.root, event, consume=True))

    def test_gateway_ignores_agent_self_asserted_authority(self) -> None:
        event = forge_scenarios()["indirect_injection_secret_egress"].model_copy(
            update={"indicators": set(), "data_classes": set()}
        )
        gateway = ControlledToolGateway(authority_service=self.service)

        result = gateway.execute(event, authority_grant=self.root)

        self.assertFalse(result.authority_verified)
        self.assertFalse(result.completed)
        self.assertEqual(result.security_result.overall_action.value, "deny")

    def test_valid_signed_authority_is_consumed_at_execution(self) -> None:
        event = forge_scenarios()["benign_inventory_read"]
        gateway = ControlledToolGateway(authority_service=self.service)

        first = gateway.execute(event, authority_grant=self.root)

        self.assertTrue(first.authority_verified)
        self.assertTrue(first.completed)


class ProvenanceTests(unittest.TestCase):
    def test_transform_and_memory_retain_worst_trust_and_labels(self) -> None:
        store = ProvenanceStore()
        trusted = store.add_source(
            tenant_id="tenant-lab",
            source_type="control",
            source_id="control://task",
            trust_class=TrustClass.TRUSTED_CONTROL,
            content=b"investigate incident",
            confidentiality_labels={"internal"},
        )
        untrusted = store.add_source(
            tenant_id="tenant-lab",
            source_type="document",
            source_id="document://external/7",
            trust_class=TrustClass.EXTERNAL_UNTRUSTED,
            content=b"synthetic hostile instruction",
            confidentiality_labels={"external"},
            integrity_labels={"untrusted-instruction"},
        )
        tool_result = store.transform(
            tenant_id="tenant-lab",
            source_type="tool_result",
            source_id="tool://document-parser",
            parent_ids=[untrusted.provenance_id],
            output_content=b"parsed synthetic result",
            transform_type="tool_result",
        )
        summary = store.transform(
            tenant_id="tenant-lab",
            source_type="agent",
            source_id="agent://triage-to-response-handoff",
            parent_ids=[trusted.provenance_id, tool_result.provenance_id],
            output_content=b"summary digest source",
            transform_type="agent_handoff",
            sanitizer_attestation_id="sanitize-test-1",
        )
        memory = store.write_memory(
            memory_id="memory-1",
            tenant_id="tenant-lab",
            value=b"stored summary",
            provenance_ids=[summary.provenance_id],
        )

        self.assertEqual(summary.trust_class, TrustClass.EXTERNAL_UNTRUSTED)
        self.assertEqual(summary.confidentiality_labels, {"internal", "external"})
        self.assertEqual(summary.integrity_labels, {"untrusted-instruction"})
        self.assertEqual(tool_result.parent_provenance_ids, [untrusted.provenance_id])
        self.assertIn(tool_result.provenance_id, summary.parent_provenance_ids)
        self.assertEqual(
            store.read_memory("memory-1", "tenant-lab").provenance_ids,
            memory.provenance_ids,
        )

    def test_transform_without_parent_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least one parent"):
            ProvenanceStore().transform(
                tenant_id="tenant-lab",
                source_type="agent",
                source_id="agent://triage",
                parent_ids=[],
                output_content=b"orphaned",
                transform_type="summary",
            )


class ApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.approvals = ApprovalService(PocHmacSigner(TEST_KEY))
        self.event = forge_scenarios()["mcp_schema_drift"]

    def test_exact_approval_allows_once_through_mock_gateway(self) -> None:
        gateway = ControlledToolGateway(approval_service=self.approvals)
        token = self.approvals.issue(
            self.event,
            approver_id="human://security/bob",
            policy_version=gateway.pipeline.judge.policy_version,
        )

        first = gateway.execute(self.event, approval_token=token)
        replay = gateway.execute(self.event, approval_token=token)

        self.assertTrue(first.approval_verified)
        self.assertTrue(first.completed)
        self.assertFalse(replay.approval_verified)
        self.assertFalse(replay.completed)

    def test_mutated_action_does_not_match_approval(self) -> None:
        gateway = ControlledToolGateway(approval_service=self.approvals)
        token = self.approvals.issue(
            self.event,
            approver_id="human://security/bob",
            policy_version=gateway.pipeline.judge.policy_version,
        )
        mutated = self.event.model_copy(
            update={"destination": "https://different.invalid/upload"}
        )

        result = gateway.execute(mutated, approval_token=token)

        self.assertFalse(result.approval_verified)
        self.assertFalse(result.completed)

    def test_expired_approval_is_rejected(self) -> None:
        gateway = ControlledToolGateway(approval_service=self.approvals)
        token = self.approvals.issue(
            self.event,
            approver_id="human://security/bob",
            policy_version=gateway.pipeline.judge.policy_version,
            ttl=timedelta(seconds=-1),
        )

        result = gateway.execute(self.event, approval_token=token)

        self.assertFalse(result.approval_verified)
        self.assertFalse(result.completed)


if __name__ == "__main__":
    unittest.main()
