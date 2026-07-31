from __future__ import annotations

from datetime import timedelta
from io import BytesIO
import json
import tempfile
import threading
from time import perf_counter
import unittest

from agentsec.datamodel import (
    EntityRecord,
    EntityType,
    IncidentRecord,
    InvestigationRecord,
    InvestigationStatus,
    RecordType,
    canonical_bundle_from_pipeline,
)
from agentsec.pipeline import SecurityPipeline
from agentsec.scenarios import forge_scenarios
from agentsec.search import (
    EVIDENCE_READ_PERMISSION,
    HUNT_WRITE_PERMISSION,
    INDEX_PERMISSION,
    READ_PERMISSION,
    SearchAuthorizationError,
    SearchPrincipal,
    SearchQueryError,
    SearchRequest,
    SearchService,
)
from agentsec.service import AuthorizationApplication, make_handler
from agentsec.storage import CanonicalRepository


CURSOR_SECRET = b"module-five-search-cursor-test-key-32-bytes-minimum"
HTTP_TOKEN = "module-five-http-token-at-least-thirty-two-characters"


class SearchThreatHuntingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repository = CanonicalRepository(self.temp.name + "/canonical.sqlite3")
        self.service = SearchService(
            self.temp.name + "/search.sqlite3", cursor_secret=CURSOR_SECRET
        )
        self.principal = SearchPrincipal(
            tenant_id="tenant-demo",
            actor_id="analyst://lead",
            permissions={
                READ_PERMISSION,
                INDEX_PERMISSION,
                HUNT_WRITE_PERMISSION,
                EVIDENCE_READ_PERMISSION,
            },
        )
        event = forge_scenarios()["indirect_injection_secret_egress"].model_copy(
            update={"tenant_id": self.principal.tenant_id}
        )
        result = SecurityPipeline().process(event).alerts[0]
        self.bundle = canonical_bundle_from_pipeline(result)
        self.repository.commit_bundle(self.bundle)
        incident = next(
            record for record in self.bundle.records if isinstance(record, IncidentRecord)
        )
        evidence_ids = [
            record.evidence_id
            for record in self.bundle.records
            if record.record_type == RecordType.EVIDENCE
        ]
        self.investigation = InvestigationRecord(
            tenant_id=self.principal.tenant_id,
            investigation_id="inv_module_five_test",
            incident_id=incident.incident_id,
            status=InvestigationStatus.RUNNING,
            hypothesis="An untrusted prompt attempted secret exfiltration",
            evidence_ids=evidence_ids,
            assigned_to=self.principal.actor_id,
        )
        self.repository.commit(self.investigation)
        self.stats = self.service.synchronize(self.principal, self.repository)

    def tearDown(self) -> None:
        self.service.close()
        self.repository.close()
        self.temp.cleanup()

    def test_indexes_all_canonical_types_and_runs_typed_boolean_queries(self) -> None:
        self.assertGreaterEqual(self.stats.indexed_records, 9)
        all_records = self.service.search(
            self.principal, SearchRequest(query="*", page_size=200)
        )
        self.assertEqual({item.record_type for item in all_records.hits}, set(RecordType))
        page = self.service.search(
            self.principal,
            SearchRequest(
                query='(record_type = "alert" AND severity >= "high") '
                'OR (record_type = "investigation" AND status = "running")',
                sort_by="record_type",
                sort_order="asc",
            ),
        )
        self.assertEqual(
            {item.record_type for item in page.hits},
            {RecordType.ALERT, RecordType.INVESTIGATION},
        )
        title = self.service.search(
            self.principal,
            SearchRequest(query='title ~ "untrusted content"'),
        )
        self.assertTrue(title.hits)
        self.assertTrue(all("attributes" not in item.projection for item in page.hits))

    def test_query_language_rejects_injection_unknown_fields_types_and_cost(self) -> None:
        bad_queries = [
            'record_type = "alert"; DROP TABLE search_documents',
            'tenant_id = "tenant-other"',
            'severity = "urgent"',
            'risk_score = "high"',
            'status > "open"',
            'NOTHING = "value"',
        ]
        for query in bad_queries:
            with self.subTest(query=query):
                with self.assertRaises(SearchQueryError):
                    self.service.search(self.principal, SearchRequest(query=query))
        excessive = " AND ".join('status = "open"' for _ in range(129))
        with self.assertRaises((SearchQueryError, ValueError)):
            self.service.search(self.principal, SearchRequest(query=excessive))

    def test_tenant_and_permission_boundaries_fail_closed(self) -> None:
        reader = SearchPrincipal(
            tenant_id=self.principal.tenant_id,
            actor_id="analyst://reader",
            permissions={READ_PERMISSION},
        )
        self.assertGreater(self.service.search(reader, SearchRequest()).total, 0)
        with self.assertRaises(SearchAuthorizationError):
            self.service.synchronize(reader, self.repository)
        other = self.principal.model_copy(update={"tenant_id": "tenant-other"})
        self.assertEqual(self.service.search(other, SearchRequest()).total, 0)
        record = self.bundle.records[0]
        with self.assertRaises(SearchAuthorizationError):
            self.service.index_record(other, record)
        no_read = self.principal.model_copy(update={"permissions": {INDEX_PERMISSION}})
        with self.assertRaises(SearchAuthorizationError):
            self.service.search(no_read, SearchRequest())

    def test_concurrent_indexing_is_idempotent_and_indexed_query_is_bounded(self) -> None:
        shared = EntityRecord(
            tenant_id=self.principal.tenant_id,
            entity_id="entity://agent/concurrent-search-test",
            entity_type=EntityType.AGENT,
            name="concurrent-search-test",
        )
        failures = []

        def index_shared() -> None:
            try:
                self.service.index_record(self.principal, shared)
            except Exception as exc:  # pragma: no cover - asserted empty below
                failures.append(exc)

        threads = [threading.Thread(target=index_shared) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])
        exact = self.service.search(
            self.principal,
            SearchRequest(query='entity_id = "entity://agent/concurrent-search-test"'),
        )
        self.assertEqual(exact.total, 1)

        for index in range(600):
            self.service.index_record(
                self.principal,
                EntityRecord(
                    tenant_id=self.principal.tenant_id,
                    entity_id="entity://agent/load-%04d" % index,
                    entity_type=EntityType.AGENT,
                    name="load-%04d" % index,
                ),
            )
        started = perf_counter()
        page = self.service.search(
            self.principal,
            SearchRequest(
                query='entity_type = "agent" AND name ~ "load-"', page_size=200
            ),
        )
        wall_seconds = perf_counter() - started
        self.assertEqual(page.total, 600)
        self.assertLess(wall_seconds, 3.0)

    def test_signed_pagination_cursor_binds_tenant_query_sort_and_expiry(self) -> None:
        first = self.service.search(
            self.principal, SearchRequest(query="*", page_size=2, sort_by="record_id")
        )
        self.assertEqual(len(first.hits), 2)
        self.assertIsNotNone(first.next_cursor)
        second = self.service.search(
            self.principal,
            SearchRequest(
                query="*", page_size=2, sort_by="record_id", cursor=first.next_cursor
            ),
        )
        self.assertFalse({hit.record_id for hit in first.hits} & {hit.record_id for hit in second.hits})
        tampered = first.next_cursor[:-1] + ("A" if first.next_cursor[-1] != "A" else "B")
        with self.assertRaises(SearchQueryError):
            self.service.search(
                self.principal,
                SearchRequest(query="*", page_size=2, sort_by="record_id", cursor=tampered),
            )
        with self.assertRaises(SearchQueryError):
            self.service.search(
                self.principal,
                SearchRequest(
                    query='record_type = "alert"',
                    page_size=2,
                    sort_by="record_id",
                    cursor=first.next_cursor,
                ),
            )
        other = self.principal.model_copy(update={"tenant_id": "tenant-other"})
        with self.assertRaises(SearchQueryError):
            self.service.search(
                other,
                SearchRequest(query="*", page_size=2, sort_by="record_id", cursor=first.next_cursor),
            )

    def test_aggregations_saved_hunts_and_owner_controls(self) -> None:
        result = self.service.aggregate(
            self.principal, query="*", field="record_type", limit=20
        )
        self.assertEqual(sum(item.count for item in result.buckets), self.stats.indexed_records)
        hunt = self.service.save_hunt(
            self.principal,
            name="High-confidence alerts",
            description="SOC queue",
            query='record_type = "alert" AND confidence >= 0.8',
            sort_by="confidence",
        )
        self.assertEqual(self.service.get_hunt(self.principal, hunt.hunt_id), hunt)
        self.assertEqual(len(self.service.list_hunts(self.principal)), 1)
        self.assertEqual(self.service.execute_hunt(self.principal, hunt.hunt_id).total, 1)
        updated = self.service.update_hunt(
            self.principal,
            hunt.hunt_id,
            name="All security alerts",
            query='record_type = "alert"',
        )
        self.assertEqual(updated.name, "All security alerts")
        coworker = self.principal.model_copy(update={"actor_id": "analyst://coworker"})
        with self.assertRaises(SearchAuthorizationError):
            self.service.update_hunt(
                coworker, hunt.hunt_id, name="Hijacked", query="*"
            )
        self.service.delete_hunt(self.principal, hunt.hunt_id)
        with self.assertRaises(KeyError):
            self.service.get_hunt(self.principal, hunt.hunt_id)

    def test_evidence_pivot_returns_metadata_and_links_but_no_protected_blob(self) -> None:
        evidence_id = self.investigation.evidence_ids[0]
        pivot = self.service.evidence_pivot(
            self.principal, self.repository, evidence_id
        )
        self.assertEqual(pivot.evidence_id, evidence_id)
        self.assertFalse(pivot.protected_content_included)
        self.assertGreaterEqual(len(pivot.related_records), 4)
        encoded = json.dumps(pivot.model_dump(mode="json")).lower()
        self.assertNotIn("ciphertext", encoded)
        self.assertNotIn("key_reference", encoded)
        no_evidence = self.principal.model_copy(
            update={"permissions": {READ_PERMISSION}}
        )
        with self.assertRaises(SearchAuthorizationError):
            self.service.evidence_pivot(no_evidence, self.repository, evidence_id)

    def test_sync_replaces_mutable_revision_without_stale_index_values(self) -> None:
        incident = next(
            record for record in self.bundle.records if isinstance(record, IncidentRecord)
        )
        revised = incident.model_copy(
            update={
                "risk_score": max(0, incident.risk_score - 7),
                "updated_at": incident.updated_at + timedelta(seconds=1),
            }
        )
        self.repository.commit(revised)
        self.service.synchronize(self.principal, self.repository)
        new_score = self.service.search(
            self.principal,
            SearchRequest(
                query='record_type = "incident" AND risk_score = %d' % revised.risk_score
            ),
        )
        old_score = self.service.search(
            self.principal,
            SearchRequest(
                query='record_type = "incident" AND risk_score = %d' % incident.risk_score
            ),
        )
        self.assertEqual(new_score.total, 1)
        self.assertEqual(old_score.total, 0)

    def test_sync_refuses_a_canonical_repository_that_fails_integrity(self) -> None:
        self.repository._connection.execute(
            "UPDATE canonical_records SET record_json = ? WHERE tenant_id = ? AND record_type = 'event'",
            ('{"tampered":true}', self.principal.tenant_id),
        )
        with self.assertRaisesRegex(ValueError, "failed verification"):
            self.service.synchronize(self.principal, self.repository)

    def test_authenticated_product_api_indexes_live_decisions_and_exposes_hunts(self) -> None:
        application = AuthorizationApplication(
            canonical_repository=self.repository,
            search_service=self.service,
            search_principal=self.principal,
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
                server_name = "agentsec-search-test"
                server_port = 80

            connection = FakeSocket(raw)
            handler(connection, ("127.0.0.1", 12345), FakeServer())
            head, response_body = connection.sent.getvalue().split(b"\r\n\r\n", 1)
            return int(head.splitlines()[0].split()[1]), json.loads(response_body)

        status, unauthorized = request(
            "/v1/search", method="POST", body={"query": "*"}, auth=False
        )
        self.assertEqual((status, unauthorized["error"]), (401, "unauthorized"))
        status, searched = request(
            "/v1/search",
            method="POST",
            body={"query": 'record_type = "alert"', "page_size": 10},
        )
        self.assertEqual(status, 200)
        self.assertGreaterEqual(searched["total"], 1)
        status, aggregated = request(
            "/v1/search/aggregate",
            method="POST",
            body={"query": "*", "field": "severity"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(aggregated["buckets"])
        status, hunt = request(
            "/v1/hunts",
            method="POST",
            body={"name": "API alerts", "query": 'record_type = "alert"'},
        )
        self.assertEqual(status, 200)
        status, hunts = request("/v1/hunts")
        self.assertEqual(status, 200)
        self.assertIn(hunt["hunt_id"], {item["hunt_id"] for item in hunts["hunts"]})
        status, executed = request(
            "/v1/hunts/%s/execute" % hunt["hunt_id"], method="POST", body={}
        )
        self.assertEqual(status, 200)
        self.assertGreaterEqual(executed["total"], 1)
        status, updated = request(
            "/v1/hunts/%s" % hunt["hunt_id"],
            method="PUT",
            body={"name": "API alerts updated"},
        )
        self.assertEqual((status, updated["name"]), (200, "API alerts updated"))
        evidence_id = self.investigation.evidence_ids[0]
        status, pivot = request("/v1/evidence/%s/pivot" % evidence_id)
        self.assertEqual(status, 200)
        self.assertFalse(pivot["protected_content_included"])
        status, deleted = request(
            "/v1/hunts/%s" % hunt["hunt_id"], method="DELETE"
        )
        self.assertEqual((status, deleted["deleted"]), (200, hunt["hunt_id"]))

        live_event = forge_scenarios()["mcp_schema_drift"].model_copy(
            update={"tenant_id": self.principal.tenant_id}
        )
        status, authorization = request(
            "/v1/authorize",
            method="POST",
            body=live_event.model_dump(mode="json"),
        )
        self.assertEqual(status, 200)
        status, live_search = request(
            "/v1/search",
            method="POST",
            body={"query": 'alert_type = "mcp_schema_drift"'},
        )
        self.assertEqual(status, 200)
        self.assertEqual(live_search["total"], len(authorization["alerts"]))


if __name__ == "__main__":
    unittest.main()
