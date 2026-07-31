from __future__ import annotations

from datetime import timedelta
from io import BytesIO
import json
from pathlib import Path
import tempfile
import threading
from time import perf_counter
import unittest
from unittest.mock import patch

from agentsec.abom import AbomManifest, ToolManifestEntry
from agentsec.contracts import Severity
from agentsec.crypto import PocHmacSigner
from agentsec.inventory import (
    INVENTORY_ADMIN,
    INVENTORY_DISCOVER,
    INVENTORY_READ,
    INVENTORY_WRITE,
    ComponentKind,
    ComponentStatus,
    ComponentUpsert,
    InventoryAuthorizationError,
    InventoryObservation,
    InventoryPrincipal,
    InventoryService,
    InventorySource,
)
from agentsec.model_registry import ModelRegistry
from agentsec.scenarios import forge_scenarios
from agentsec.service import AuthorizationApplication, application_from_environment, make_handler
from agentsec.telemetry import (
    CollectionMode,
    TelemetryContext,
    TelemetryEnvelope,
    TelemetryEventKind,
)


ABOM_KEY = b"module-six-abom-signing-test-key-at-least-32-bytes"
HTTP_TOKEN = "module-six-inventory-http-token-at-least-32-characters"


class InventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = self.temp.name + "/inventory.sqlite3"
        self.service = InventoryService(self.path)
        self.principal = InventoryPrincipal(
            tenant_id="tenant-lab",
            actor_id="inventory://test-admin",
            permissions={
                INVENTORY_READ,
                INVENTORY_DISCOVER,
                INVENTORY_WRITE,
                INVENTORY_ADMIN,
            },
        )

    def tearDown(self) -> None:
        self.service.close()
        self.temp.cleanup()

    def observation(self, suffix: str = "one", **updates) -> InventoryObservation:
        payload = {
            "observation_id": "iobs_%s" % suffix,
            "tenant_id": self.principal.tenant_id,
            "source_ref": "sdk://python/support-app",
            "source_type": "python-sdk",
            "application_external_id": "support-app",
            "application_name": "Support application",
            "agent_external_id": "support-agent",
            "agent_name": "Support agent",
            "environment": "test",
            "model_provider": "openai",
            "model_id": "gpt-test-pinned",
            "model_profile_id": "openai-test-profile",
            "tool_name": "ticket_lookup",
            "tool_schema_digest": "sha256:tool-v1",
            "operation": "ticket.read",
            "resource_scope": "ticket://tenant/*",
        }
        payload.update(updates)
        return InventoryObservation(**payload)

    def test_discovery_persists_application_agent_model_tool_and_relationships(self) -> None:
        result = self.service.discover(self.principal, self.observation())
        self.assertFalse(result.duplicate)
        self.assertEqual(len(result.component_ids), 4)
        self.assertEqual(result.relationship_count, 3)
        summary = self.service.summary(self.principal)
        self.assertEqual(summary.total_components, 4)
        self.assertEqual(summary.by_kind[ComponentKind.APPLICATION], 1)
        self.assertEqual(summary.by_kind[ComponentKind.AGENT], 1)
        self.assertEqual(summary.by_kind[ComponentKind.MODEL], 1)
        self.assertEqual(summary.by_kind[ComponentKind.TOOL], 1)
        application = self.service.list_components(
            self.principal, kind=ComponentKind.APPLICATION
        ).components[0]
        self.assertEqual(len(self.service.relationships(self.principal, application.component_id)), 1)

        self.service.close()
        self.service = InventoryService(self.path)
        restored = self.service.get_component(self.principal, application.component_id)
        self.assertEqual(restored.name, "Support application")
        self.assertEqual(restored.status, ComponentStatus.UNMANAGED)

    def test_duplicate_and_conflicting_observation_ids_are_fail_closed_and_concurrent(self) -> None:
        observation = self.observation("concurrent")
        results = []
        errors = []
        lock = threading.Lock()

        def discover() -> None:
            try:
                result = self.service.discover(self.principal, observation)
                with lock:
                    results.append(result)
            except Exception as exc:  # pragma: no cover - asserted empty
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=discover) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(sum(not result.duplicate for result in results), 1)
        self.assertEqual(sum(result.duplicate for result in results), 11)
        with self.assertRaisesRegex(ValueError, "reused"):
            self.service.discover(
                self.principal,
                observation.model_copy(update={"source_ref": "sdk://changed"}),
            )

    def test_untrusted_discovery_cannot_override_governance_and_risk_rolls_up(self) -> None:
        result = self.service.discover(
            self.principal,
            self.observation(
                "effectful",
                operation="external.send",
                resource_scope="https://external.invalid/upload",
            ),
        )
        agent_id = result.component_ids[1]
        governed = self.service.set_governance(
            self.principal,
            agent_id,
            owner_ref="team://soc",
            criticality=Severity.CRITICAL,
            status=ComponentStatus.ACTIVE,
        )
        self.assertEqual(governed.owner_ref, "team://soc")
        second = self.observation(
            "effectful-two",
            operation="ticket.write",
            resource_scope="ticket://tenant/*",
            observed_at=self.observation("effectful").observed_at + timedelta(seconds=1),
        )
        self.service.discover(self.principal, second)
        current = self.service.get_component(self.principal, agent_id)
        self.assertEqual(current.owner_ref, "team://soc")
        self.assertEqual(current.criticality, Severity.CRITICAL)
        self.assertEqual(current.status, ComponentStatus.ACTIVE)
        self.assertEqual({item.operation for item in current.permissions}, {"external.send", "ticket.write"})
        application_id = result.component_ids[0]
        rollup = self.service.risk_rollup(self.principal, application_id)
        self.assertGreaterEqual(rollup.score, 60)
        self.assertGreaterEqual(rollup.unapproved_permissions, 2)

    def test_configuration_history_is_versioned_and_safe(self) -> None:
        first = self.service.discover(self.principal, self.observation("schema-one"))
        tool_id = first.component_ids[-1]
        second = self.observation(
            "schema-two",
            tool_schema_digest="sha256:tool-v2",
            observed_at=self.observation("schema-one").observed_at + timedelta(seconds=1),
        )
        self.service.discover(self.principal, second)
        history = self.service.configuration_history(self.principal, tool_id)
        self.assertEqual([item.version for item in history], [1, 2])
        self.assertEqual(history[1].previous_digest, history[0].configuration_digest)
        self.assertEqual(history[1].changed_fields, ["schema_digest"])
        self.assertNotIn("raw_prompt", str(history))
        with self.assertRaisesRegex(ValueError, "not allowlisted"):
            self.service.upsert_component(
                self.principal,
                ComponentUpsert(
                    kind=ComponentKind.AGENT,
                    name="unsafe",
                    external_ref="agent://unsafe",
                    source=InventorySource.DECLARED,
                    configuration={"api_key": "must-not-enter-inventory"},
                ),
            )

    def test_signed_abom_and_model_registry_import_supply_declared_inventory(self) -> None:
        signer = PocHmacSigner(ABOM_KEY)
        unsigned = AbomManifest(
            tenant_id=self.principal.tenant_id,
            agent_id="declared-agent",
            owner_id="team://ai-platform",
            build_digest="sha256:build-v1",
            system_instruction_digest="sha256:system-v1",
            model_profile_ids={"codex-recorded-shadow"},
            tools=[
                ToolManifestEntry(
                    tool_name="approved_tool",
                    operation="ticket.read",
                    schema_digest="sha256:schema-v1",
                    allowed_destinations={"ticket://tenant/*"},
                )
            ],
            allowed_data_classes={"internal"},
            allowed_destinations={"ticket://tenant/*"},
            policy_bundle_digest="sha256:policy-v1",
        )
        manifest = unsigned.model_copy(
            update={"signature": signer.sign(unsigned.unsigned_payload())}
        )
        imported = self.service.import_abom(
            self.principal,
            manifest,
            signer,
            application_external_id="declared-app",
        )
        self.assertEqual({item.kind for item in imported}, {ComponentKind.APPLICATION, ComponentKind.AGENT, ComponentKind.TOOL})
        agent = next(item for item in imported if item.kind == ComponentKind.AGENT)
        self.assertEqual(agent.owner_ref, "team://ai-platform")
        self.assertTrue(all(item.approved for item in agent.permissions))
        with self.assertRaisesRegex(ValueError, "signature"):
            self.service.import_abom(
                self.principal,
                manifest.model_copy(update={"build_digest": "sha256:tampered"}),
                signer,
                application_external_id="tampered-app",
            )

        models = self.service.import_model_registry(
            self.principal, ModelRegistry.from_path(Path("configs/model-profiles.json"))
        )
        self.assertEqual(sum(item.kind == ComponentKind.MODEL for item in models), 3)
        self.assertNotIn("api_key", str(models).lower())

    def test_telemetry_and_agent_event_adapters_exclude_content(self) -> None:
        envelope = TelemetryEnvelope(
            event_id="tel_inventory_adapter",
            occurred_at=self.observation().observed_at,
            observed_at=self.observation().observed_at,
            context=TelemetryContext(
                tenant_id=self.principal.tenant_id,
                application_id="telemetry-app",
                agent_id="telemetry-agent",
                session_id="session-one",
                trace_id="trace-one",
                source_id="sdk://telemetry",
                source_type="sdk",
                collector_id="collector-one",
                environment="test",
                provider="openai",
                model_id="gpt-test",
            ),
            kind=TelemetryEventKind.TOOL_CALL_REQUEST,
            operation="ticket.read",
            resource="ticket://one",
            tool_name="ticket_lookup",
            attributes={"raw_prompt": "THIS_ATTRIBUTE_MUST_NOT_BE_COPIED"},
            content_evidence=[],
            collection_mode=CollectionMode.METADATA_ONLY,
        )
        result = self.service.observe_telemetry(self.principal, envelope)
        self.assertEqual(len(result.component_ids), 4)
        encoded = str(
            self.service.list_components(self.principal, limit=200).model_dump(mode="json")
        )
        self.assertNotIn("THIS_ATTRIBUTE_MUST_NOT_BE_COPIED", encoded)
        event = forge_scenarios()["mcp_schema_drift"]
        self.service.observe_agent_event(self.principal, event)
        self.assertGreater(self.service.summary(self.principal).total_components, 4)

    def test_tenant_permissions_filters_pagination_and_indexed_performance(self) -> None:
        reader = InventoryPrincipal(
            tenant_id=self.principal.tenant_id,
            actor_id="inventory://reader",
            permissions={INVENTORY_READ},
        )
        with self.assertRaises(InventoryAuthorizationError):
            self.service.discover(reader, self.observation())
        other = self.principal.model_copy(update={"tenant_id": "tenant-other"})
        with self.assertRaises(InventoryAuthorizationError):
            self.service.discover(other, self.observation())
        self.assertEqual(self.service.summary(other).total_components, 0)

        for index in range(400):
            self.service.upsert_component(
                self.principal,
                ComponentUpsert(
                    kind=ComponentKind.AGENT,
                    name="load-agent-%04d" % index,
                    external_ref="agent://load-%04d" % index,
                    owner_ref="team://load" if index % 2 else None,
                    criticality=Severity.HIGH if index % 5 == 0 else Severity.LOW,
                    source=InventorySource.IMPORTED,
                    configuration={"version": index},
                ),
            )
        started = perf_counter()
        page = self.service.list_components(
            reader,
            kind=ComponentKind.AGENT,
            minimum_risk=20,
            limit=50,
            offset=10,
        )
        elapsed = perf_counter() - started
        self.assertEqual(len(page.components), 50)
        self.assertGreater(page.total, 50)
        self.assertLess(elapsed, 3.0)
        with self.assertRaises(ValueError):
            self.service.list_components(reader, limit=201)

    def test_authenticated_inventory_api_and_live_authorization_discovery(self) -> None:
        application = AuthorizationApplication(
            inventory_service=self.service,
            inventory_principal=self.principal,
            inventory_application_id="live-authorization-app",
        )
        handler = make_handler(application, HTTP_TOKEN)

        def request(path: str, *, method: str = "GET", body: object = None, auth: bool = True):
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
                "%s %s HTTP/1.1\r\n%s\r\n\r\n" % (method, path, "\r\n".join(headers))
            ).encode("ascii") + encoded

            class FakeSocket:
                def __init__(self, incoming: bytes) -> None:
                    self.reader = BytesIO(incoming)
                    self.sent = BytesIO()

                def makefile(self, mode: str, *_args, **_kwargs):
                    return self.reader if "r" in mode else self.sent

                def sendall(self, data: bytes) -> None:
                    self.sent.write(data)

            class FakeServer:
                server_name = "agentsec-inventory-test"
                server_port = 80

            connection = FakeSocket(raw)
            handler(connection, ("127.0.0.1", 12345), FakeServer())
            head, response_body = connection.sent.getvalue().split(b"\r\n\r\n", 1)
            return int(head.splitlines()[0].split()[1]), json.loads(response_body)

        status, unauthorized = request("/v1/inventory", auth=False)
        self.assertEqual((status, unauthorized["error"]), (401, "unauthorized"))
        status, discovered = request(
            "/v1/inventory/discover",
            method="POST",
            body=self.observation("http").model_dump(mode="json"),
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(discovered["component_ids"]), 4)
        status, summary = request("/v1/inventory/summary")
        self.assertEqual((status, summary["total_components"]), (200, 4))
        status, listed = request("/v1/inventory?kind=agent&minimum_risk=20&limit=10")
        self.assertEqual(status, 200)
        self.assertEqual(listed["total"], 1)
        component_id = listed["components"][0]["component_id"]
        status, detail = request("/v1/inventory/%s" % component_id)
        self.assertEqual(status, 200)
        self.assertEqual(detail["component"]["component_id"], component_id)
        self.assertTrue(detail["configuration_history"])
        status, governed = request(
            "/v1/inventory/%s/governance" % component_id,
            method="POST",
            body={
                "owner_ref": "team://soc",
                "criticality": "high",
                "status": "active",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(governed["owner_ref"], "team://soc")
        status, rejected = request(
            "/v1/inventory/%s/governance" % component_id,
            method="POST",
            body={
                "owner_ref": "team://soc",
                "criticality": "high",
                "status": "active",
                "command": "arbitrary",
            },
        )
        self.assertEqual((status, rejected["error"]), (400, "invalid_request"))

        event = forge_scenarios()["mcp_schema_drift"]
        status, authorization = request(
            "/v1/authorize", method="POST", body=event.model_dump(mode="json")
        )
        self.assertEqual(status, 200)
        self.assertTrue(authorization["alerts"])
        status, live = request("/v1/inventory?kind=tool")
        self.assertEqual(status, 200)
        self.assertIn("upload_diagnostics", {item["name"] for item in live["components"]})

    def test_environment_inventory_is_explicit_and_invalid_configuration_fails_closed(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "AGENTSEC_INVENTORY_DB": self.temp.name + "/environment-inventory.sqlite3",
                "AGENTSEC_INVENTORY_TENANT": self.principal.tenant_id,
                "AGENTSEC_INVENTORY_APPLICATION_ID": "environment-app",
            },
            clear=True,
        ):
            application = application_from_environment()
        self.assertIsNotNone(application.inventory_service)
        self.assertEqual(application.inventory_principal.tenant_id, self.principal.tenant_id)
        assert application.inventory_service is not None
        application.inventory_service.close()
        with patch.dict(
            "os.environ",
            {"AGENTSEC_INVENTORY_DB": self.temp.name + "/invalid.sqlite3"},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "INVENTORY_TENANT"):
                application_from_environment()


if __name__ == "__main__":
    unittest.main()
