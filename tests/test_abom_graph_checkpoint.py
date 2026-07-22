from __future__ import annotations

import unittest

from agentsec.abom import AbomManifest, AbomRegistry, ToolManifestEntry
from agentsec.checkpoints import CheckpointAnchor
from agentsec.crypto import PocHmacSigner
from agentsec.graph import CausalGraph
from agentsec.pipeline import SecurityPipeline
from agentsec.scenarios import forge_scenarios


TEST_KEY = b"abom-and-checkpoint-test-key-at-least-32-bytes"


def approved_manifest(registry: AbomRegistry) -> AbomManifest:
    manifest = AbomManifest(
        tenant_id="tenant-lab",
        agent_id="response-agent",
        owner_id="human://security/alice",
        build_digest="sha256:build-v1",
        system_instruction_digest="sha256:system-v1",
        model_profile_ids={"codex-recorded-shadow"},
        tools=[
            ToolManifestEntry(
                tool_name="upload_diagnostics",
                operation="external.upload",
                schema_digest="sha256:approved-v1",
                allowed_destinations={"https://approved.invalid/upload"},
            ),
            ToolManifestEntry(
                tool_name="diagnostic_upload",
                operation="external.send",
                schema_digest="sha256:send-v1",
                allowed_destinations={"https://approved.invalid/collect"},
            ),
        ],
        allowed_data_classes={"internal"},
        allowed_destinations={
            "https://approved.invalid/upload",
            "https://approved.invalid/collect",
        },
        policy_bundle_digest="sha256:policy-v1",
    )
    signed = registry.sign(manifest)
    registry.approve(signed)
    return signed


class AbomTests(unittest.TestCase):
    def test_observed_mcp_change_produces_evidence_backed_diff(self) -> None:
        registry = AbomRegistry(PocHmacSigner(TEST_KEY))
        manifest = approved_manifest(registry)

        diff = registry.observe(forge_scenarios()["mcp_schema_drift"])

        self.assertTrue(diff.drifted)
        self.assertEqual(diff.manifest_id, manifest.manifest_id)
        self.assertEqual(diff.changed_tool_schemas, {"upload_diagnostics"})
        self.assertEqual(
            diff.new_destinations, {"https://new-destination.invalid/upload"}
        )

    def test_unknown_agent_is_observed_but_never_approved(self) -> None:
        registry = AbomRegistry(PocHmacSigner(TEST_KEY))
        event = forge_scenarios()["benign_inventory_read"].model_copy(
            update={"agent_id": "shadow-agent"}
        )

        diff = registry.observe(event)

        self.assertTrue(diff.unknown_agent)
        self.assertIsNone(registry.approved("tenant-lab", "shadow-agent"))
        self.assertEqual(registry.observation_count, 1)

    def test_tampered_manifest_signature_is_rejected(self) -> None:
        registry = AbomRegistry(PocHmacSigner(TEST_KEY))
        manifest = registry.sign(
            AbomManifest(
                tenant_id="tenant-lab",
                agent_id="response-agent",
                owner_id="owner",
                build_digest="sha256:one",
                system_instruction_digest="sha256:two",
                model_profile_ids=set(),
                tools=[],
                allowed_data_classes=set(),
                allowed_destinations=set(),
                policy_bundle_digest="sha256:three",
            )
        ).model_copy(update={"build_digest": "sha256:tampered"})

        with self.assertRaisesRegex(ValueError, "signature"):
            registry.approve(manifest)


class GraphTests(unittest.TestCase):
    def test_source_to_external_sink_path_requires_no_raw_prompt(self) -> None:
        pipeline = SecurityPipeline()
        result = pipeline.process(
            forge_scenarios()["indirect_injection_secret_egress"]
        )
        graph = CausalGraph()
        graph.ingest(result)
        source = "source:%s" % result.event.source_id
        sink = "destination:%s" % result.event.destination

        path = graph.path(source, sink, result.event.flow_id)

        self.assertIsNotNone(path)
        self.assertEqual(path.node_ids[0], source)
        self.assertEqual(path.node_ids[-1], sink)
        self.assertIn("agent:response-agent", path.node_ids)
        self.assertNotIn("raw_prompt", str(path.model_dump()))


class CheckpointTests(unittest.TestCase):
    def test_signed_external_checkpoint_verifies_intact_ledger(self) -> None:
        pipeline = SecurityPipeline()
        pipeline.process(forge_scenarios()["indirect_injection_secret_egress"])
        anchor = CheckpointAnchor(PocHmacSigner(TEST_KEY))

        checkpoint = anchor.create(pipeline.ledger, "pipeline-test")
        result = anchor.verify(checkpoint, pipeline.ledger)

        self.assertTrue(result.valid)
        self.assertEqual(checkpoint.sequence, pipeline.ledger.count)
        self.assertEqual(anchor.count, 1)

    def test_mutation_after_checkpoint_reports_first_broken_sequence(self) -> None:
        pipeline = SecurityPipeline()
        pipeline.process(forge_scenarios()["indirect_injection_secret_egress"])
        anchor = CheckpointAnchor(PocHmacSigner(TEST_KEY))
        checkpoint = anchor.create(pipeline.ledger, "pipeline-test")
        pipeline.ledger._ordered_alerts[0] = pipeline.ledger._ordered_alerts[0].model_copy(
            update={"title": "tampered after checkpoint"}
        )

        result = anchor.verify(checkpoint, pipeline.ledger)

        self.assertFalse(result.valid)
        self.assertEqual(result.sequence, 1)
        self.assertIn("current_hash_mismatch", result.reason)

    def test_checkpoint_signature_mutation_is_rejected(self) -> None:
        pipeline = SecurityPipeline()
        pipeline.process(forge_scenarios()["mcp_schema_drift"])
        anchor = CheckpointAnchor(PocHmacSigner(TEST_KEY))
        checkpoint = anchor.create(pipeline.ledger, "pipeline-test").model_copy(
            update={"current_hash": "0" * 64}
        )

        result = anchor.verify(checkpoint, pipeline.ledger)

        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "checkpoint_signature_invalid")


if __name__ == "__main__":
    unittest.main()
