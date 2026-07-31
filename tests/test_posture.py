from __future__ import annotations

from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

from agentsec.contracts import Severity
from agentsec.inventory import (
    INVENTORY_ADMIN,
    INVENTORY_DISCOVER,
    INVENTORY_READ,
    INVENTORY_WRITE,
    ComponentStatus,
    ComponentKind,
    InventoryComponent,
    InventoryObservation,
    InventoryPrincipal,
    InventoryService,
    InventorySource,
)
from agentsec.posture import (
    DEFAULT_POSTURE_CHECKS,
    POSTURE_ADMIN,
    POSTURE_READ,
    POSTURE_SCAN,
    PostureAuthorizationError,
    PostureFindingStatus,
    PosturePrincipal,
    PostureService,
)
from agentsec.service import AuthorizationApplication, application_from_environment, make_handler


HTTP_TOKEN = "module-eight-posture-http-token-at-least-32-characters"


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 23, 1, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value


class PostureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.clock = MutableClock()
        self.posture_path = self.temp.name + "/posture.sqlite3"
        self.posture = PostureService(self.posture_path, clock=self.clock)
        self.principal = PosturePrincipal(
            tenant_id="tenant-lab",
            actor_id="posture://test-admin",
            permissions={POSTURE_READ, POSTURE_SCAN, POSTURE_ADMIN},
        )
        self.posture.install_defaults(self.principal)
        self.inventory = InventoryService(self.temp.name + "/inventory.sqlite3")
        self.inventory_principal = InventoryPrincipal(
            tenant_id="tenant-lab",
            actor_id="inventory://posture-test",
            permissions={INVENTORY_READ, INVENTORY_DISCOVER, INVENTORY_WRITE, INVENTORY_ADMIN},
        )

    def tearDown(self) -> None:
        self.posture.close()
        self.inventory.close()
        self.temp.cleanup()

    def observation(self, suffix: str = "one", **updates) -> InventoryObservation:
        payload = {
            "observation_id": "iobs_posture_%s" % suffix,
            "tenant_id": "tenant-lab",
            "source_ref": "sdk://posture-test",
            "source_type": "python-sdk",
            "observed_at": self.clock.value,
            "application_external_id": "posture-app",
            "application_name": "Posture application",
            "agent_external_id": "posture-agent",
            "agent_name": "Posture agent",
            "environment": "test",
            "model_provider": "openai",
            "model_id": "gpt-pinned-test",
            "model_profile_id": "openai-test-profile",
            "tool_name": "external_sender",
            "operation": "external.send",
            "resource_scope": "https://external.invalid/upload",
        }
        payload.update(updates)
        return InventoryObservation(**payload)

    def components(self):
        return self.inventory.list_components(
            self.inventory_principal, limit=200
        ).components

    def test_default_checks_are_versioned_immutable_and_durable(self) -> None:
        self.assertEqual(len(self.posture.list_checks(self.principal)), 8)
        original = DEFAULT_POSTURE_CHECKS[0]
        duplicate = self.posture.register_check(self.principal, original)
        current = next(
            item for item in self.posture.list_checks(self.principal)
            if item.check_id == original.check_id
        )
        self.assertEqual(duplicate.definition_sha256, current.definition_sha256)
        with self.assertRaisesRegex(ValueError, "immutable"):
            self.posture.register_check(
                self.principal,
                original.model_copy(update={"description": "Changed under an immutable version"}),
            )
        updated = original.model_copy(
            update={"version": "2026.07.2", "description": "Accountable owner is required for every AI component."}
        )
        self.posture.register_check(self.principal, updated)
        numeric_update = original.model_copy(
            update={"version": "2026.07.10", "description": "Numeric check versions increase naturally."}
        )
        self.posture.register_check(self.principal, numeric_update)
        history = [item for item in self.posture.list_checks(self.principal, history=True) if item.check_id == original.check_id]
        self.assertEqual([item.version for item in history], ["2026.07.10", "2026.07.2", "2026.07.1"])
        self.assertIsNotNone(history[2].superseded_at)

        self.posture.close()
        self.posture = PostureService(self.posture_path, clock=self.clock)
        self.assertEqual(len(self.posture.list_checks(self.principal)), 8)

    def test_inventory_scan_creates_explainable_findings_and_trends(self) -> None:
        self.inventory.discover(self.inventory_principal, self.observation())
        result = self.posture.scan(self.principal, self.components())
        self.assertEqual(result.component_count, 4)
        self.assertGreater(result.evaluations, 4)
        self.assertGreater(result.failing, 0)
        self.assertLess(result.posture_score, 100)
        page = self.posture.list_findings(self.principal)
        self.assertEqual(page.total, result.failing)
        self.assertTrue(all(item.evidence_refs[0].startswith("inventory://") for item in page.findings))
        self.assertNotIn("external.invalid", str(page.model_dump(mode="json")))
        detail = self.posture.detail(self.principal, page.findings[0].finding_id)
        self.assertTrue(detail.finding.remediation)
        self.assertTrue(detail.check.framework_mappings)
        summary = self.posture.summary(self.principal)
        self.assertEqual(summary.open_findings, page.total)
        self.assertEqual(self.posture.trends(self.principal).points[0].scan_id, result.scan_id)

        self.posture.close()
        self.posture = PostureService(self.posture_path, clock=self.clock)
        self.assertEqual(self.posture.summary(self.principal).open_findings, page.total)

    def test_rescan_resolves_fixed_posture_without_deleting_history(self) -> None:
        discovered = self.inventory.discover(self.inventory_principal, self.observation("resolve"))
        application_id = discovered.component_ids[0]
        self.posture.scan(
            self.principal, self.components(), check_ids=["PST-OWNER-REQUIRED"]
        )
        finding = next(
            item for item in self.posture.list_findings(self.principal).findings
            if item.component_id == application_id
        )
        self.inventory.set_governance(
            self.inventory_principal,
            application_id,
            owner_ref="team://ai-platform",
            criticality=Severity.HIGH,
            status=ComponentStatus.ACTIVE,
        )
        second = self.posture.scan(
            self.principal, self.components(), check_ids=["PST-OWNER-REQUIRED"]
        )
        self.assertGreaterEqual(second.resolved_findings, 1)
        resolved = self.posture.detail(self.principal, finding.finding_id).finding
        self.assertEqual(resolved.status, PostureFindingStatus.RESOLVED)
        self.assertIsNotNone(resolved.resolved_at)

    def test_exception_is_time_bounded_expires_and_can_be_revoked(self) -> None:
        self.inventory.discover(self.inventory_principal, self.observation("exception"))
        self.posture.scan(
            self.principal, self.components(), check_ids=["PST-OWNER-REQUIRED"]
        )
        finding = self.posture.list_findings(self.principal).findings[0]
        exception = self.posture.create_exception(
            self.principal,
            finding.finding_id,
            reason="Temporary demo component awaits ownership review",
            owner_ref="team://security",
            approved_by="analyst://alice",
            expires_at=self.clock.value + timedelta(days=7),
        )
        self.assertEqual(
            self.posture.detail(self.principal, finding.finding_id).finding.status,
            PostureFindingStatus.ACCEPTED_EXCEPTION,
        )
        with self.assertRaisesRegex(ValueError, "already has an active exception"):
            self.posture.create_exception(
                self.principal,
                finding.finding_id,
                reason="Second active exception must be rejected",
                owner_ref="team://security",
                approved_by="analyst://alice",
                expires_at=self.clock.value + timedelta(days=8),
            )
        revoked = self.posture.revoke_exception(
            self.principal, exception.exception_id, reason="Risk acceptance withdrawn"
        )
        self.assertEqual(revoked.status.value, "revoked")
        self.assertEqual(
            self.posture.detail(self.principal, finding.finding_id).finding.status,
            PostureFindingStatus.OPEN,
        )
        replacement = self.posture.create_exception(
            self.principal,
            finding.finding_id,
            reason="Short-lived exception for expiry verification",
            owner_ref="team://security",
            approved_by="analyst://alice",
            expires_at=self.clock.value + timedelta(hours=1),
        )
        self.clock.value += timedelta(hours=2)
        detail = self.posture.detail(self.principal, finding.finding_id)
        self.assertEqual(detail.finding.status, PostureFindingStatus.OPEN)
        expired = self.posture._connection.execute(
            "SELECT status FROM posture_exceptions WHERE exception_id = ?",
            (replacement.exception_id,),
        ).fetchone()["status"]
        self.assertEqual(expired, "expired")

    def test_tenant_permissions_selection_and_pagination_fail_closed(self) -> None:
        self.inventory.discover(self.inventory_principal, self.observation("auth"))
        reader = self.principal.model_copy(update={"permissions": {POSTURE_READ}})
        with self.assertRaises(PostureAuthorizationError):
            self.posture.scan(reader, self.components())
        with self.assertRaises(PostureAuthorizationError):
            self.posture.scan(
                self.principal.model_copy(update={"tenant_id": "tenant-other"}),
                self.components(),
            )
        self.assertEqual(
            self.posture.summary(
                self.principal.model_copy(update={"tenant_id": "tenant-other"})
            ).total_findings,
            0,
        )
        with self.assertRaises(KeyError):
            self.posture.scan(
                self.principal, self.components(), check_ids=["PST-NOT-REGISTERED"]
            )
        with self.assertRaises(ValueError):
            self.posture.list_findings(self.principal, limit=201)

    def test_scan_is_bounded_at_product_scale_and_serializes_concurrent_writers(self) -> None:
        components = [
            InventoryComponent(
                component_id="cmp_perf_%04d" % index,
                tenant_id="tenant-lab",
                kind=ComponentKind.APPLICATION,
                name="Performance component %04d" % index,
                external_ref="application://performance/%04d" % index,
                owner_ref=None,
                criticality=Severity.MEDIUM,
                status=ComponentStatus.UNMANAGED,
                source=InventorySource.OBSERVED,
                permissions=[],
                configuration={"environment": "performance"},
                configuration_digest=("%064x" % (index + 1)),
                configuration_version=1,
                tags={"performance"},
                risk_score=50,
                risk_reasons=["unmanaged"],
                first_seen_at=self.clock.value,
                last_seen_at=self.clock.value,
                updated_at=self.clock.value,
            )
            for index in range(400)
        ]
        started = time.perf_counter()
        result = self.posture.scan(self.principal, components)
        self.assertLess(time.perf_counter() - started, 5.0)
        self.assertEqual(result.component_count, 400)
        self.assertEqual(result.evaluations, 1200)
        with ThreadPoolExecutor(max_workers=3) as pool:
            scans = list(pool.map(lambda _: self.posture.scan(self.principal, components), range(3)))
        self.assertEqual(len({item.scan_id for item in scans}), 3)
        self.assertTrue(all(item.failing == result.failing for item in scans))

    def test_authenticated_posture_api_scans_details_exceptions_and_trends(self) -> None:
        self.inventory.discover(self.inventory_principal, self.observation("http"))
        application = AuthorizationApplication(
            inventory_service=self.inventory,
            inventory_principal=self.inventory_principal,
            posture_service=self.posture,
            posture_principal=self.principal,
        )
        handler = make_handler(application, HTTP_TOKEN)

        def request(path: str, *, method: str = "GET", body=None, auth: bool = True):
            headers = ["Host: 127.0.0.1"]
            if auth:
                headers.append("Authorization: Bearer %s" % HTTP_TOKEN)
            encoded = b""
            if body is not None:
                encoded = json.dumps(body).encode("utf-8")
                headers.extend(["Content-Type: application/json", "Content-Length: %d" % len(encoded)])
            raw = ("%s %s HTTP/1.1\r\n%s\r\n\r\n" % (method, path, "\r\n".join(headers))).encode("ascii") + encoded

            class FakeSocket:
                def __init__(self, incoming: bytes) -> None:
                    self.reader = BytesIO(incoming)
                    self.sent = BytesIO()

                def makefile(self, mode: str, *_args, **_kwargs):
                    return self.reader if "r" in mode else self.sent

                def sendall(self, data: bytes) -> None:
                    self.sent.write(data)

            class FakeServer:
                server_name = "agentsec-posture-test"
                server_port = 80

            connection = FakeSocket(raw)
            handler(connection, ("127.0.0.1", 12345), FakeServer())
            head, response_body = connection.sent.getvalue().split(b"\r\n\r\n", 1)
            return int(head.splitlines()[0].split()[1]), json.loads(response_body)

        status, unauthorized = request("/v1/posture/summary", auth=False)
        self.assertEqual((status, unauthorized["error"]), (401, "unauthorized"))
        status, checks = request("/v1/posture/checks")
        self.assertEqual((status, len(checks["checks"])), (200, 8))
        status, scan = request("/v1/posture/scans", method="POST", body={})
        self.assertEqual(status, 200)
        self.assertGreater(scan["failing"], 0)
        status, findings = request("/v1/posture/findings?status=open&limit=10")
        self.assertEqual(status, 200)
        finding_id = findings["findings"][0]["finding_id"]
        status, detail = request("/v1/posture/findings/%s" % finding_id)
        self.assertEqual(status, 200)
        self.assertTrue(detail["finding"]["remediation"])
        status, exception = request(
            "/v1/posture/findings/%s/exceptions" % finding_id,
            method="POST",
            body={
                "reason": "Temporary accepted risk during an approved migration",
                "owner_ref": "team://security",
                "approved_by": "analyst://alice",
                "expires_at": (self.clock.value + timedelta(days=5)).isoformat(),
            },
        )
        self.assertEqual((status, exception["status"]), (200, "active"))
        status, summary = request("/v1/posture/summary")
        self.assertEqual(status, 200)
        self.assertEqual(summary["accepted_exceptions"], 1)
        status, trend = request("/v1/posture/trends?limit=5")
        self.assertEqual((status, len(trend["points"])), (200, 1))
        status, revoked = request(
            "/v1/posture/exceptions/%s/revoke" % exception["exception_id"],
            method="POST",
            body={"reason": "Approved migration completed"},
        )
        self.assertEqual((status, revoked["status"]), (200, "revoked"))
        status, summary = request("/v1/posture/summary")
        self.assertEqual(summary["accepted_exceptions"], 0)
        status, rejected = request(
            "/v1/posture/scans", method="POST", body={"command": "arbitrary"}
        )
        self.assertEqual((status, rejected["error"]), (400, "invalid_request"))

    def test_posture_environment_requires_matching_inventory(self) -> None:
        inventory_path = self.temp.name + "/environment-inventory.sqlite3"
        posture_path = self.temp.name + "/environment-posture.sqlite3"
        with patch.dict(
            os.environ,
            {
                "AGENTSEC_INVENTORY_DB": inventory_path,
                "AGENTSEC_INVENTORY_TENANT": "tenant-lab",
                "AGENTSEC_POSTURE_DB": posture_path,
            },
            clear=True,
        ):
            application = application_from_environment()
        self.assertIsNotNone(application.posture_service)
        self.assertEqual(len(application.posture_service.list_checks(application.posture_principal)), 8)
        application.posture_service.close()
        application.inventory_service.close()
        with patch.dict(os.environ, {"AGENTSEC_POSTURE_DB": posture_path}, clear=True):
            with self.assertRaisesRegex(ValueError, "requires AGENTSEC_INVENTORY_DB"):
                application_from_environment()


if __name__ == "__main__":
    unittest.main()
