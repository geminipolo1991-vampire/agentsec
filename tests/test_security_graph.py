from __future__ import annotations

from datetime import datetime, timedelta, timezone
from io import BytesIO
import json
import os
import tempfile
import threading
from time import perf_counter
import unittest
from unittest.mock import patch

from pydantic import ValidationError

from agentsec.contracts import Severity
from agentsec.graph import (
    GRAPH_ANALYZE,
    GRAPH_READ,
    GRAPH_WRITE,
    GraphAuthorizationError,
    GraphEdgeInput,
    GraphNodeInput,
    GraphPrincipal,
    SecurityEdgeType,
    SecurityGraphService,
    SecurityNodeType,
)
from agentsec.pipeline import SecurityPipeline
from agentsec.scenarios import forge_scenarios
from agentsec.service import AuthorizationApplication, application_from_environment, make_handler
from agentsec.inventory import (
    INVENTORY_ADMIN,
    INVENTORY_DISCOVER,
    INVENTORY_READ,
    INVENTORY_WRITE,
    InventoryPrincipal,
    InventoryService,
)


FIXTURE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)
HTTP_TOKEN = "module-seven-graph-http-token-at-least-32-characters"


class SecurityGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = self.temp.name + "/security-graph.sqlite3"
        self.service = SecurityGraphService(self.path)
        self.principal = GraphPrincipal(
            tenant_id="tenant-lab",
            actor_id="graph://test-admin",
            permissions={GRAPH_READ, GRAPH_WRITE, GRAPH_ANALYZE},
        )

    def tearDown(self) -> None:
        self.service.close()
        self.temp.cleanup()

    @staticmethod
    def node(
        node_id: str,
        *,
        risk_score: int = 10,
        observed_at: datetime = FIXTURE_TIME,
        node_type: SecurityNodeType = SecurityNodeType.AGENT,
    ) -> GraphNodeInput:
        return GraphNodeInput(
            node_id=node_id,
            node_type=node_type,
            name=node_id,
            risk_score=risk_score,
            criticality=Severity.HIGH if risk_score >= 60 else Severity.LOW,
            labels={"environment": "test"},
            source_ref="test://module-seven",
            observed_at=observed_at,
        )

    @staticmethod
    def edge(
        edge_id: str,
        source: str,
        target: str,
        *,
        weight: float = 10.0,
        observed_at: datetime = FIXTURE_TIME,
    ) -> GraphEdgeInput:
        return GraphEdgeInput(
            edge_id=edge_id,
            source_node_id=source,
            target_node_id=target,
            edge_type=SecurityEdgeType.CALLS,
            weight=weight,
            risk_factors=["TEST_EXPOSURE"],
            evidence_refs=["event://fixture"],
            source_ref="test://module-seven",
            observed_at=observed_at,
        )

    def test_event_graph_is_durable_and_reconstructs_source_to_destination(self) -> None:
        processed = SecurityPipeline().process(
            forge_scenarios()["indirect_injection_secret_egress"]
        )
        written = self.service.ingest_processing_result(self.principal, processed)
        self.assertGreaterEqual(written.node_versions_created, 4)
        self.assertGreaterEqual(written.edge_versions_created, 3)
        source = "source:%s" % processed.event.source_id
        destination = "destination:%s" % processed.event.destination
        paths = self.service.attack_paths(self.principal, source, destination)
        self.assertEqual(paths.paths[0].node_ids[0], source)
        self.assertEqual(paths.paths[0].node_ids[-1], destination)
        self.assertTrue(any(node_id.startswith("decision:") for node_id in paths.paths[0].node_ids))
        self.assertIn("UNTRUSTED_INFLUENCE", paths.paths[0].risk_factors)
        self.assertIn("SECURITY_DECISION_DENY", paths.paths[0].risk_factors)
        self.assertEqual(paths.paths[0].exposure_score, 0)
        self.assertNotIn("raw_prompt", str(paths.model_dump()).lower())

        self.service.close()
        self.service = SecurityGraphService(self.path)
        self.assertEqual(self.service.summary(self.principal).node_count, written.nodes_written)

    def test_repeated_entity_observations_and_maximum_length_metadata_are_safe(self) -> None:
        pipeline = SecurityPipeline()
        first = pipeline.process(forge_scenarios()["benign_inventory_read"])
        second_event = forge_scenarios()["mcp_schema_drift"].model_copy(
            update={"resource": "r" * 512, "destination": "d" * 512}
        )
        second = pipeline.process(second_event)
        self.service.ingest_processing_result(self.principal, first)
        self.service.ingest_processing_result(self.principal, second)
        snapshot = self.service.snapshot(self.principal)
        self.assertEqual(
            len([node for node in snapshot.nodes if node.node_id == "agent:response-agent"]),
            1,
        )
        self.assertTrue(any(node.node_id.startswith("resource:sha256:") for node in snapshot.nodes))
        self.assertTrue(any(node.node_id.startswith("destination:sha256:") for node in snapshot.nodes))

    def test_weighted_paths_are_ordered_and_cycles_are_not_traversed(self) -> None:
        nodes = [self.node(item) for item in ("agent:a", "tool:b", "tool:c", "data:d")]
        edges = [
            self.edge("edge:ab", "agent:a", "tool:b", weight=2),
            self.edge("edge:bd", "tool:b", "data:d", weight=3),
            self.edge("edge:ac", "agent:a", "tool:c", weight=8),
            self.edge("edge:cd", "tool:c", "data:d", weight=5),
            self.edge("edge:ba", "tool:b", "agent:a", weight=1),
        ]
        self.service.ingest(self.principal, nodes, edges)
        result = self.service.attack_paths(
            self.principal, "agent:a", "data:d", max_paths=5, max_depth=8
        )
        self.assertEqual([item.total_weight for item in result.paths], [5.0, 13.0])
        self.assertTrue(all(len(path.node_ids) == len(set(path.node_ids)) for path in result.paths))
        with self.assertRaisesRegex(ValueError, "safety limit"):
            self.service.attack_paths(
                self.principal, "agent:a", "data:d", max_states=50001
            )

    def test_reachability_and_blast_radius_are_bounded_and_bidirectional(self) -> None:
        nodes = [self.node("node:%d" % index, risk_score=index * 20) for index in range(5)]
        edges = [
            self.edge("edge:%d" % index, "node:%d" % index, "node:%d" % (index + 1))
            for index in range(4)
        ]
        self.service.ingest(self.principal, nodes, edges)
        outbound = self.service.reachability(
            self.principal, "node:0", max_depth=2
        )
        self.assertEqual([item.node_id for item in outbound.reachable], ["node:1", "node:2"])
        self.assertTrue(outbound.truncated)
        inbound = self.service.reachability(
            self.principal, "node:4", direction="inbound", max_depth=8
        )
        self.assertEqual(len(inbound.reachable), 4)
        blast = self.service.blast_radius(self.principal, "node:0", max_depth=8)
        self.assertEqual(blast.impacted_count, 4)
        self.assertEqual(blast.high_risk_count, 2)
        self.assertEqual(blast.maximum_risk_score, 80)

    def test_historical_snapshots_preserve_node_and_edge_revisions(self) -> None:
        later = FIXTURE_TIME + timedelta(hours=1)
        self.service.ingest(
            self.principal,
            [self.node("agent:a", risk_score=10), self.node("tool:b")],
            [self.edge("edge:ab", "agent:a", "tool:b", weight=20)],
        )
        update = self.service.ingest(
            self.principal,
            [self.node("agent:a", risk_score=90, observed_at=later)],
            [self.edge("edge:ab", "agent:a", "tool:b", weight=2, observed_at=later)],
        )
        self.assertEqual((update.node_versions_created, update.edge_versions_created), (1, 1))
        old = self.service.snapshot(self.principal, as_of=FIXTURE_TIME + timedelta(minutes=30))
        current = self.service.snapshot(self.principal, as_of=later)
        self.assertEqual(next(item for item in old.nodes if item.node_id == "agent:a").risk_score, 10)
        self.assertEqual(next(item for item in current.nodes if item.node_id == "agent:a").risk_score, 90)
        self.assertEqual(old.edges[0].weight, 20)
        self.assertEqual(current.edges[0].weight, 2)
        with self.assertRaisesRegex(ValueError, "chronological"):
            self.service.ingest(
                self.principal,
                [self.node("agent:a", risk_score=50, observed_at=FIXTURE_TIME)],
                [],
            )
        with self.assertRaisesRegex(ValueError, "timezone"):
            self.service.snapshot(self.principal, as_of=datetime(2026, 1, 1))

    def test_tenants_and_permissions_are_isolated(self) -> None:
        reader = self.principal.model_copy(update={"permissions": {GRAPH_READ}})
        with self.assertRaises(GraphAuthorizationError):
            self.service.ingest(reader, [self.node("agent:no")], [])
        with self.assertRaises(GraphAuthorizationError):
            self.service.reachability(reader, "agent:no")
        other = self.principal.model_copy(update={"tenant_id": "tenant-other"})
        self.service.ingest(self.principal, [self.node("agent:private")], [])
        self.assertEqual(self.service.summary(other).node_count, 0)
        processed = SecurityPipeline().process(
            forge_scenarios()["benign_inventory_read"]
        )
        with self.assertRaises(GraphAuthorizationError):
            self.service.ingest_processing_result(other, processed)

    def test_invalid_edges_labels_and_identity_changes_fail_closed(self) -> None:
        with self.assertRaises(ValidationError):
            GraphNodeInput(
                node_id="agent:unsafe",
                node_type=SecurityNodeType.AGENT,
                name="unsafe",
                labels={"api_key": "must-never-enter"},
                source_ref="test://unsafe",
            )
        self.service.ingest(
            self.principal, [self.node("agent:a"), self.node("tool:b")], []
        )
        with self.assertRaisesRegex(ValueError, "unknown"):
            self.service.ingest(
                self.principal, [], [self.edge("edge:missing", "agent:a", "tool:missing")]
            )
        self.service.ingest(
            self.principal, [], [self.edge("edge:stable", "agent:a", "tool:b")]
        )
        with self.assertRaisesRegex(ValueError, "identity"):
            self.service.ingest(
                self.principal,
                [self.node("tool:c", observed_at=FIXTURE_TIME + timedelta(seconds=1))],
                [
                    self.edge(
                        "edge:stable",
                        "agent:a",
                        "tool:c",
                        observed_at=FIXTURE_TIME + timedelta(seconds=1),
                    )
                ],
            )

    def test_concurrent_duplicate_ingest_creates_one_version(self) -> None:
        results = []
        errors = []
        lock = threading.Lock()

        def ingest() -> None:
            try:
                result = self.service.ingest(self.principal, [self.node("agent:once")], [])
                with lock:
                    results.append(result)
            except Exception as exc:  # pragma: no cover - asserted empty
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=ingest) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(sum(item.node_versions_created for item in results), 1)
        self.assertEqual(self.service.summary(self.principal).node_count, 1)

    def test_indexed_snapshot_and_bounded_reachability_scale(self) -> None:
        count = 800
        nodes = [self.node("load:%04d" % index, risk_score=index % 100) for index in range(count)]
        edges = [
            self.edge("load-edge:%04d" % index, "load:%04d" % index, "load:%04d" % (index + 1))
            for index in range(count - 1)
        ]
        started = perf_counter()
        self.service.ingest(self.principal, nodes, edges)
        result = self.service.reachability(
            self.principal, "load:0000", max_depth=20, max_nodes=100
        )
        self.assertEqual(len(result.reachable), 20)
        self.assertLess(perf_counter() - started, 3.0)

    def test_inventory_topology_and_authenticated_live_graph_api(self) -> None:
        inventory = InventoryService(self.temp.name + "/inventory.sqlite3")
        inventory_principal = InventoryPrincipal(
            tenant_id=self.principal.tenant_id,
            actor_id="inventory://graph-test",
            permissions={
                INVENTORY_READ,
                INVENTORY_DISCOVER,
                INVENTORY_WRITE,
                INVENTORY_ADMIN,
            },
        )
        application = AuthorizationApplication(
            inventory_service=inventory,
            inventory_principal=inventory_principal,
            inventory_application_id="graph-test-app",
            graph_service=self.service,
            graph_principal=self.principal,
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
                server_name = "agentsec-graph-test"
                server_port = 80

            connection = FakeSocket(raw)
            handler(connection, ("127.0.0.1", 12345), FakeServer())
            head, response_body = connection.sent.getvalue().split(b"\r\n\r\n", 1)
            return int(head.splitlines()[0].split()[1]), json.loads(response_body)

        status, error = request("/v1/graph", auth=False)
        self.assertEqual((status, error["error"]), (401, "unauthorized"))
        event = forge_scenarios()["indirect_injection_secret_egress"]
        status, authorization = request(
            "/v1/authorize", method="POST", body=event.model_dump(mode="json")
        )
        self.assertEqual(status, 200)
        self.assertTrue(authorization["alerts"])
        status, summary = request("/v1/graph/summary")
        self.assertEqual(status, 200)
        self.assertGreater(summary["node_count"], 8)
        self.assertGreaterEqual(summary["by_node_type"]["application"], 1)
        status, snapshot = request("/v1/graph")
        self.assertEqual(status, 200)
        self.assertEqual(snapshot["tenant_id"], self.principal.tenant_id)
        source = "source:%s" % event.source_id
        destination = "destination:%s" % event.destination
        status, paths = request(
            "/v1/graph/attack-paths",
            method="POST",
            body={"source_node_id": source, "target_node_id": destination},
        )
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(paths["paths"]), 1)
        status, blast = request(
            "/v1/graph/blast-radius",
            method="POST",
            body={"origin_node_id": source, "max_depth": 8},
        )
        self.assertEqual(status, 200)
        self.assertGreaterEqual(blast["impacted_count"], 3)
        status, rejected = request(
            "/v1/graph/reachability",
            method="POST",
            body={"origin_node_id": source, "command": "arbitrary"},
        )
        self.assertEqual((status, rejected["error"]), (400, "invalid_request"))
        inventory.close()

    def test_graph_environment_is_explicit_and_fails_closed(self) -> None:
        database = self.temp.name + "/environment-graph.sqlite3"
        with patch.dict(
            os.environ,
            {"AGENTSEC_GRAPH_DB": database, "AGENTSEC_GRAPH_TENANT": "tenant-lab"},
            clear=True,
        ):
            application = application_from_environment()
        self.assertIsNotNone(application.graph_service)
        self.assertEqual(application.graph_principal.tenant_id, "tenant-lab")
        application.graph_service.close()
        with patch.dict(os.environ, {"AGENTSEC_GRAPH_DB": database}, clear=True):
            with self.assertRaisesRegex(ValueError, "live graph requires"):
                application_from_environment()
        with self.assertRaisesRegex(ValueError, "configured together"):
            AuthorizationApplication(graph_service=SecurityGraphService(":memory:"))


if __name__ == "__main__":
    unittest.main()
