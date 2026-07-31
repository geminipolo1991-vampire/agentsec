from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from email.message import Message
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from agentsec.administration import (
    AdministrationAuthorizationError,
    AdministrationConflictError,
    AdministrationService,
    HumanRole,
    IdentityAssertionVerifier,
    KeyState,
    RecoveryDrillRecord,
    ServiceLevelObjective,
    ServiceLevelMeasurement,
    SignedIdentityAssertion,
    SupplyChainAttestation,
    administration_service_from_environment,
    local_administration_principal,
)
from agentsec.contracts import new_id
from agentsec.crypto import PocHmacSigner
from agentsec.service import AuthorizationApplication, make_handler


ROOT = Path(__file__).resolve().parents[1]
FIXED_TIME = datetime(2026, 7, 24, 6, 0, tzinfo=timezone.utc)
TENANT = "tenant-lab"
TOKEN = "administration-http-test-token-32-characters"


class AdministrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp.name) / "administration.sqlite3")
        self.verifier = IdentityAssertionVerifier(
            b"identity-assertion-test-key-32-bytes-minimum",
            issuer="https://idp.example.invalid",
            audience="agentsec-administration",
            now=lambda: FIXED_TIME,
        )
        self.service = AdministrationService(
            self.database,
            tenant_id=TENANT,
            assertion_verifier=self.verifier,
            checkpoint_signer=PocHmacSigner(
                b"administration-checkpoint-key-32-byte-minimum"
            ),
            now=lambda: FIXED_TIME,
        )
        self.admin = local_administration_principal(
            TENANT,
            "analyst://alice",
            {HumanRole.PLATFORM_ADMINISTRATOR},
            now=FIXED_TIME,
        )
        self.auditor = local_administration_principal(
            TENANT,
            "analyst://auditor",
            {HumanRole.SECURITY_AUDITOR, HumanRole.PLATFORM_ADMINISTRATOR},
            now=FIXED_TIME,
        )
        self.policy = self.service.put_tenant_policy(
            self.admin,
            display_name="AgentSec laboratory",
            residency_region="ap-northeast-1",
            allowed_processing_regions={"ap-northeast-1"},
            retention_days=365,
            evidence_retention_days=730,
            legal_hold=False,
            managed_key_reference="keyref://tenant-lab/data",
            expected_version=0,
        )
        self.alice = self.service.upsert_identity(
            self.admin,
            subject="analyst://alice",
            display_name="Alice Administrator",
            email_sha256=hashlib.sha256(b"alice@example.invalid").hexdigest(),
            roles={HumanRole.PLATFORM_ADMINISTRATOR},
            enabled=True,
            expected_version=0,
        )
        self.bob = self.service.upsert_identity(
            self.admin,
            subject="analyst://bob",
            display_name="Bob Independent Reviewer",
            email_sha256=hashlib.sha256(b"bob@example.invalid").hexdigest(),
            roles={HumanRole.PLATFORM_ADMINISTRATOR, HumanRole.SECURITY_AUDITOR},
            enabled=True,
            expected_version=0,
        )

    def tearDown(self) -> None:
        self.service.close()
        self.temp.cleanup()

    def assertion(
        self,
        *,
        subject: str = "analyst://alice",
        roles=None,
        step_up: bool = True,
        tenant_id: str = TENANT,
    ) -> SignedIdentityAssertion:
        assertion = SignedIdentityAssertion(
            assertion_id=new_id("assertion"),
            issuer="https://idp.example.invalid",
            audience="agentsec-administration",
            tenant_id=tenant_id,
            subject=subject,
            session_id=new_id("session"),
            roles=roles or {HumanRole.PLATFORM_ADMINISTRATOR},
            mfa_verified=step_up,
            authentication_context="step_up" if step_up else "standard",
            issued_at=FIXED_TIME - timedelta(seconds=5),
            expires_at=FIXED_TIME + timedelta(minutes=30),
        )
        return self.verifier.sign_for_test(assertion)

    def test_signed_federated_assertion_is_provisioned_mfa_and_replay_bound(self) -> None:
        assertion = self.assertion()
        principal = self.service.authenticate_assertion(assertion)
        self.assertEqual(principal.authentication_method, "sso_assertion")
        self.assertTrue(principal.mfa_verified)
        self.assertIsNotNone(principal.step_up_until)
        with self.assertRaises(AdministrationAuthorizationError):
            self.service.authenticate_assertion(assertion)

        forged = self.assertion().model_copy(update={"signature": "0" * 64})
        with self.assertRaises(AdministrationAuthorizationError):
            self.service.authenticate_assertion(forged)
        with self.assertRaises(AdministrationAuthorizationError):
            self.service.authenticate_assertion(
                self.assertion(tenant_id="tenant-other")
            )
        with self.assertRaises(AdministrationAuthorizationError):
            self.service.authenticate_assertion(
                self.assertion(roles={HumanRole.PLATFORM_ADMINISTRATOR, HumanRole.POLICY_OWNER})
            )

    def test_high_impact_operations_require_fresh_mfa_and_optimistic_versions(self) -> None:
        no_step_up = local_administration_principal(
            TENANT,
            "analyst://alice",
            {HumanRole.PLATFORM_ADMINISTRATOR},
            now=FIXED_TIME,
            step_up=False,
        )
        with self.assertRaises(AdministrationAuthorizationError):
            self.service.put_tenant_policy(
                no_step_up,
                display_name="Denied update",
                residency_region="ap-northeast-1",
                allowed_processing_regions={"ap-northeast-1"},
                retention_days=365,
                evidence_retention_days=730,
                legal_hold=False,
                managed_key_reference="keyref://tenant-lab/data",
                expected_version=1,
            )
        with self.assertRaises(AdministrationConflictError):
            self.service.put_tenant_policy(
                self.admin,
                display_name="Stale update",
                residency_region="ap-northeast-1",
                allowed_processing_regions={"ap-northeast-1"},
                retention_days=365,
                evidence_retention_days=730,
                legal_hold=False,
                managed_key_reference="keyref://tenant-lab/data",
                expected_version=0,
            )
        with self.assertRaises(ValueError):
            self.service.put_tenant_policy(
                self.admin,
                display_name="Invalid residency",
                residency_region="ap-northeast-1",
                allowed_processing_regions={"eu-west-1"},
                retention_days=365,
                evidence_retention_days=730,
                legal_hold=False,
                managed_key_reference="keyref://tenant-lab/data",
                expected_version=1,
            )

    def test_workload_identity_rotation_and_revocation_never_store_credentials(self) -> None:
        first = self.service.register_workload(
            self.admin,
            workload_id="workload://authorization-api",
            display_name="Authorization API",
            credential_reference="credentialref://spiffe/authorization-api",
            credential_fingerprint="1" * 64,
            scopes={"telemetry:write", "decision:write"},
            expires_at=FIXED_TIME + timedelta(days=30),
        )
        self.assertEqual(first.version, 1)
        rotated = self.service.register_workload(
            self.admin,
            workload_id="workload://authorization-api",
            display_name="Authorization API",
            credential_reference="credentialref://spiffe/authorization-api/v2",
            credential_fingerprint="2" * 64,
            scopes={"telemetry:write", "decision:write"},
            expires_at=FIXED_TIME + timedelta(days=60),
            expected_version=1,
        )
        self.assertEqual(rotated.version, 2)
        self.assertIsNotNone(rotated.rotated_at)
        with self.assertRaises(AdministrationConflictError):
            self.service.register_workload(
                self.admin,
                workload_id="workload://authorization-api",
                display_name="Authorization API",
                credential_reference="credentialref://spiffe/reuse",
                credential_fingerprint="2" * 64,
                scopes={"telemetry:write"},
                expires_at=FIXED_TIME + timedelta(days=60),
                expected_version=2,
            )
        revoked = self.service.revoke_workload(
            self.admin, first.workload_id, expected_version=2
        )
        self.assertIsNotNone(revoked.revoked_at)
        database_bytes = Path(self.database).read_bytes()
        self.assertNotIn(b"credential-secret-value", database_bytes)

    def test_managed_key_metadata_requires_independent_activation(self) -> None:
        pending = self.service.register_key(
            self.admin,
            key_id="managed-key://tenant-lab/audit-v1",
            purpose="checkpoint",
            provider_reference="keyref://kms/tenant-lab/audit-v1",
            fingerprint="3" * 64,
            rotation_due_at=FIXED_TIME + timedelta(days=90),
        )
        self.assertEqual(pending.state, KeyState.PENDING)
        with self.assertRaises(AdministrationAuthorizationError):
            self.service.transition_key(
                self.admin,
                pending.key_id,
                target_state=KeyState.ACTIVE,
                expected_version=1,
            )
        active = self.service.transition_key(
            self.auditor,
            pending.key_id,
            target_state=KeyState.ACTIVE,
            expected_version=1,
        )
        self.assertEqual(active.state, KeyState.ACTIVE)
        self.assertEqual(active.approved_by, self.auditor.actor_id)
        self.assertNotIn("material", active.model_dump())

    def test_independent_access_review_and_self_review_are_enforced(self) -> None:
        with self.assertRaises(AdministrationAuthorizationError):
            self.service.certify_access(
                self.admin,
                "analyst://alice",
                decision="certified",
                rationale_sha256=hashlib.sha256(
                    b"Alice cannot review her own administrator role"
                ).hexdigest(),
            )
        rationale = "Role is required for the approved administration duty"
        review = self.service.certify_access(
            self.auditor,
            "analyst://alice",
            decision="certified",
            rationale_sha256=hashlib.sha256(rationale.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(review.reviewer_id, "analyst://auditor")
        self.assertEqual(review.roles, {HumanRole.PLATFORM_ADMINISTRATOR})
        self.assertNotIn(rationale.encode("utf-8"), Path(self.database).read_bytes())

    def test_slo_restore_and_supply_chain_receipts_gate_health_honestly(self) -> None:
        self.service.register_key(
            self.admin,
            key_id="managed-key://tenant-lab/data-v1",
            purpose="encryption",
            provider_reference="keyref://kms/tenant-lab/data-v1",
            fingerprint="4" * 64,
            rotation_due_at=FIXED_TIME + timedelta(days=90),
        )
        self.service.transition_key(
            self.auditor,
            "managed-key://tenant-lab/data-v1",
            target_state=KeyState.ACTIVE,
            expected_version=1,
        )
        objective = ServiceLevelObjective(
            objective_id="slo://authorization/availability",
            name="Authorization availability",
            metric="availability",
            comparison="gte",
            target=0.999,
            window_minutes=43200,
        )
        measurement = self.service.record_slo_measurement(
            self.admin, objective, observed=0.9999, error_budget_remaining=0.8
        )
        self.assertTrue(measurement.passed)
        drill = self.service.record_recovery_drill(
            self.admin,
            backup_manifest_sha256="5" * 64,
            source_checkpoint_sha256="6" * 64,
            restored_checkpoint_sha256="6" * 64,
            backup_created_at=FIXED_TIME - timedelta(minutes=4),
            observed_rpo_minutes=4,
            observed_rto_minutes=12,
            target_rpo_minutes=5,
            target_rto_minutes=15,
            integrity_verified=True,
        )
        self.assertTrue(drill.passed)
        attestation = self.service.record_supply_chain_attestation(
            self.admin,
            release_id="release-2026.07.24.1",
            artifact_sha256="7" * 64,
            sbom_sha256="8" * 64,
            provenance_sha256="9" * 64,
            dependency_scan_passed=True,
            secret_scan_passed=True,
            signature_verified=True,
            builder_id="system://independent-builder",
        )
        self.assertTrue(attestation.passed)
        snapshot = self.service.snapshot(self.admin)
        self.assertEqual(snapshot.health.status, "healthy")
        self.assertTrue(snapshot.health.audit_valid)
        self.assertFalse(snapshot.health.production_ready)
        self.assertFalse(snapshot.health.external_idp_federated)
        self.assertFalse(snapshot.health.external_key_custody_verified)
        self.assertFalse(snapshot.health.distributed_ha_verified)

        with self.assertRaisesRegex(ValueError, "SLO pass state"):
            ServiceLevelMeasurement.model_validate(
                measurement.model_dump(mode="json") | {"passed": False}
            )
        with self.assertRaisesRegex(ValueError, "recovery pass state"):
            RecoveryDrillRecord.model_validate(
                drill.model_dump(mode="json") | {"passed": False}
            )
        with self.assertRaisesRegex(ValueError, "supply-chain pass state"):
            SupplyChainAttestation.model_validate(
                attestation.model_dump(mode="json") | {"passed": False}
            )

    def test_audit_is_append_only_checkpointed_and_detects_database_tamper(self) -> None:
        checkpoint = self.service.create_audit_checkpoint(self.auditor)
        verification = self.service.verify_audit(checkpoint)
        self.assertTrue(verification.valid)
        connection = sqlite3.connect(self.database)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE administration_audit SET action = 'tampered' WHERE sequence = 1"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM administration_audit WHERE sequence = 1")
        connection.close()
        self.assertTrue(self.service.verify_audit(checkpoint).valid)

    def test_restart_tenant_boundary_and_record_digest_validation(self) -> None:
        checkpoint = self.service.create_audit_checkpoint(self.auditor)
        self.service.close()
        self.service = AdministrationService(
            self.database,
            tenant_id=TENANT,
            assertion_verifier=self.verifier,
            checkpoint_signer=PocHmacSigner(
                b"administration-checkpoint-key-32-byte-minimum"
            ),
            now=lambda: FIXED_TIME,
        )
        self.assertTrue(self.service.verify_audit(checkpoint).valid)
        self.assertEqual(self.service.snapshot(self.admin).tenant.policy_version, 1)
        wrong = self.admin.model_copy(update={"tenant_id": "tenant-other"})
        with self.assertRaises(AdministrationAuthorizationError):
            self.service.snapshot(wrong)
        self.service._connection.execute(
            "UPDATE administration_objects SET record_sha256 = ? "
            "WHERE tenant_id = ? AND kind = 'tenant'",
            ("0" * 64, TENANT),
        )
        with self.assertRaises(ValueError):
            self.service.snapshot(self.admin)

    def test_environment_factory_requires_explicit_keys_and_safe_config(self) -> None:
        environment = {
            "AGENTSEC_ADMIN_ASSERTION_KEY": "assertion-key-with-at-least-32-characters",
            "AGENTSEC_ADMIN_CHECKPOINT_KEY": "checkpoint-key-with-at-least-32-characters",
            "AGENTSEC_ADMIN_ASSERTION_ISSUER": "https://idp.example.invalid",
            "AGENTSEC_ADMIN_ASSERTION_AUDIENCE": "agentsec-administration",
        }
        path = str(Path(self.temp.name) / "environment.sqlite3")
        with patch.dict(os.environ, environment, clear=False):
            service, principal = administration_service_from_environment(
                path,
                tenant_id=TENANT,
                config_path=str(ROOT / "configs" / "administration.example.json"),
            )
            try:
                snapshot = service.snapshot(principal)
                self.assertEqual(snapshot.tenant.residency_region, "ap-northeast-1")
                self.assertFalse(snapshot.health.production_ready)
            finally:
                service.close()
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                administration_service_from_environment(path, tenant_id=TENANT)

    def test_authenticated_private_http_surface_is_read_only_and_exact(self) -> None:
        application = AuthorizationApplication(
            administration_service=self.service,
            administration_principal=self.auditor,
        )
        handler_type = make_handler(application, TOKEN)

        def request(method, path, body=None, *, authorized=True):
            handler = handler_type.__new__(handler_type)
            handler.path = path
            handler.command = method
            handler.request_version = "HTTP/1.1"
            handler.headers = Message()
            if authorized:
                handler.headers["Authorization"] = "Bearer %s" % TOKEN
            encoded = b""
            if body is not None:
                encoded = json.dumps(body).encode("utf-8")
                handler.headers["Content-Type"] = "application/json"
                handler.headers["Content-Length"] = str(len(encoded))
            handler.rfile = BytesIO(encoded)
            handler.wfile = BytesIO()
            captured = {"status": None}
            handler.send_response = lambda status: captured.update(status=status)
            handler.send_header = lambda key, value: None
            handler.end_headers = lambda: None
            getattr(handler, "do_%s" % method)()
            return captured["status"], json.loads(handler.wfile.getvalue())

        status, snapshot = request("GET", "/v1/administration")
        self.assertEqual(status, 200)
        self.assertEqual(snapshot["tenant"]["tenant_id"], TENANT)
        self.assertFalse(snapshot["health"]["production_ready"])
        status, health = request("GET", "/v1/administration/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["audit_valid"])
        status, audit = request("GET", "/v1/administration/audit?limit=20")
        self.assertEqual(status, 200)
        self.assertGreater(audit["count"], 0)
        status, checkpoint = request(
            "POST", "/v1/administration/checkpoints", {}
        )
        self.assertEqual(status, 200)
        self.assertTrue(checkpoint["signature"])
        status, _ = request("GET", "/v1/administration?unexpected=1")
        self.assertEqual(status, 400)
        status, _ = request(
            "GET", "/v1/administration/health", authorized=False
        )
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
