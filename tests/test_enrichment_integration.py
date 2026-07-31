from __future__ import annotations

import unittest

from agentsec.abom import AbomManifest, AbomRegistry, ToolManifestEntry
from agentsec.authority import AuthorityService
from agentsec.contracts import TrustClass
from agentsec.crypto import PocHmacSigner
from agentsec.enrichment import EnrichmentContext, EnrichmentEngine
from agentsec.observation import SdkEffectReport
from agentsec.pipeline import SecurityPipeline
from agentsec.provenance import ProvenanceStore
from agentsec.scenarios import forge_scenarios
from agentsec.synthetic import EffectObservation


TEST_KEY = b"enrichment-integration-key-at-least-32-bytes"


class EnrichmentIntegrationTests(unittest.TestCase):
    def test_trusted_security_subsystems_feed_the_primary_pipeline(self) -> None:
        event = forge_scenarios()["mcp_schema_drift"]

        registry = AbomRegistry(PocHmacSigner(TEST_KEY))
        manifest = registry.sign(
            AbomManifest(
                tenant_id=event.tenant_id,
                agent_id=event.agent_id,
                owner_id="human://security/alice",
                build_digest="sha256:build-v1",
                system_instruction_digest="sha256:instruction-v1",
                model_profile_ids={"codex-recorded-shadow"},
                tools=[
                    ToolManifestEntry(
                        tool_name="upload_diagnostics",
                        operation="external.upload",
                        schema_digest="sha256:approved-v1",
                        allowed_destinations={"https://approved.invalid/upload"},
                    )
                ],
                allowed_data_classes=set(),
                allowed_destinations={"https://approved.invalid/upload"},
                policy_bundle_digest="sha256:policy-v1",
            )
        )
        registry.approve(manifest)

        provenance = ProvenanceStore()
        source = provenance.add_source(
            tenant_id=event.tenant_id,
            source_type=event.source_type,
            source_id=event.source_id,
            trust_class=TrustClass.UNKNOWN,
            content=b"metadata-only integration fixture",
        )

        authority = AuthorityService(PocHmacSigner(TEST_KEY))
        grant = authority.issue_root(
            issuer="human://security/alice",
            subject=event.agent_id,
            tenant_id=event.tenant_id,
            environment="test",
            operations={event.operation},
            resources={"diagnostic://bundle/*"},
            destinations={event.destination},
            data_classes=set(),
            max_execution_count=2,
        )

        seed_pipeline = SecurityPipeline()
        seed_pipeline.process(event)
        causal_path = seed_pipeline.causal_graph.path(
            "source:%s" % event.source_id,
            "destination:%s" % event.destination,
            event.flow_id,
        )
        self.assertIsNotNone(causal_path)

        sdk_reports = [
            SdkEffectReport(
                event_id=event.event_id,
                operation=event.operation,
                resource=event.resource,
                phase=phase,
            )
            for phase in ("attempted", "completed")
        ]
        gateway_observations = [
            EffectObservation(
                sequence=index,
                event_id=event.event_id,
                operation=event.operation,
                resource=event.resource,
                phase=phase,
            )
            for index, phase in enumerate(("attempted", "completed"), start=1)
        ]

        pipeline = SecurityPipeline(
            enricher=EnrichmentEngine(
                abom_registry=registry,
                provenance_store=provenance,
                authority_service=authority,
            )
        )
        processed = pipeline.process(
            event,
            enrichment_context=EnrichmentContext(
                authority_grant=grant,
                provenance_ids=[source.provenance_id],
                sdk_reports=sdk_reports,
                gateway_observations=gateway_observations,
                causal_path=causal_path,
                agent_owner="human://security/alice",
                approved_model_profile="codex-recorded-shadow",
                observed_model_profile="codex-recorded-shadow",
                asset_criticality="high",
            ),
        )

        item = processed.alerts[0]
        self.assertEqual(item.enrichment.status.value, "complete")
        self.assertEqual(item.enrichment.completed_sources, 9)
        sources = {source.source: source for source in item.enrichment.sources}
        self.assertTrue(sources["abom_tool_drift"].facts["drifted"])
        self.assertTrue(sources["effective_authority"].facts["full_scope_allowed"])
        self.assertEqual(sources["provenance"].facts["lineage_depth"], 1)
        self.assertEqual(
            sources["independent_observations"].facts["integrity_findings"], []
        )
        self.assertEqual(sources["causal_path"].facts["path_scope"], "recorded")
        self.assertIn(
            "tool_drift",
            {contribution.category for contribution in item.triage.contributions},
        )


if __name__ == "__main__":
    unittest.main()
