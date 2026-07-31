"""Tenant administration, identity, audit, privacy, and assurance control plane.

The implementation is deliberately provider neutral.  It verifies a bounded signed
assertion contract and stores references to externally managed credentials/keys;
it never stores raw passwords, API keys, or encryption key material.  Production
IdP federation, KMS/HSM custody, geographic placement, and multi-node failover are
deployment integrations rather than properties inferred by this local adapter.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import Enum
import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Mapping, Optional, Sequence, Set

from pydantic import Field, field_validator, model_validator

from .contracts import StrictModel, new_id, utc_now
from .crypto import PocHmacSigner, canonical_bytes


ADMIN_READ = "administration:read"
ADMIN_TENANT = "administration:tenant"
ADMIN_IDENTITY = "administration:identity"
ADMIN_WORKLOAD = "administration:workload"
ADMIN_KEYS = "administration:keys"
ADMIN_PRIVACY = "administration:privacy"
ADMIN_AUDIT = "administration:audit"
ADMIN_ASSURANCE = "administration:assurance"
ADMIN_ACCESS_REVIEW = "administration:access-review"
ZERO_SHA256 = "0" * 64


class AdministrationAuthorizationError(PermissionError):
    """Raised when a tenant, role, MFA, or separation boundary is denied."""


class AdministrationConflictError(RuntimeError):
    """Raised for stale versions or conflicting immutable identities."""


class HumanRole(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    INCIDENT_COMMANDER = "incident_commander"
    POLICY_OWNER = "policy_owner"
    PLATFORM_ADMINISTRATOR = "platform_administrator"
    SECURITY_AUDITOR = "security_auditor"


ROLE_PERMISSIONS: Dict[HumanRole, Set[str]] = {
    HumanRole.VIEWER: {ADMIN_READ},
    HumanRole.ANALYST: {ADMIN_READ},
    HumanRole.INCIDENT_COMMANDER: {ADMIN_READ},
    HumanRole.POLICY_OWNER: {ADMIN_READ, ADMIN_ACCESS_REVIEW},
    HumanRole.PLATFORM_ADMINISTRATOR: {
        ADMIN_READ,
        ADMIN_TENANT,
        ADMIN_IDENTITY,
        ADMIN_WORKLOAD,
        ADMIN_KEYS,
        ADMIN_PRIVACY,
        ADMIN_ASSURANCE,
    },
    HumanRole.SECURITY_AUDITOR: {
        ADMIN_READ,
        ADMIN_AUDIT,
        ADMIN_ACCESS_REVIEW,
    },
}


def _iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return value.isoformat().replace("+00:00", "Z")


def _canonical_value(value: Any) -> Any:
    if isinstance(value, StrictModel):
        value = value.model_dump(mode="python")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return _iso(value)
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        normalized = [_canonical_value(item) for item in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        )
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    return value


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(_canonical_value(value))).hexdigest()


def _stable_id(prefix: str, *parts: str) -> str:
    return "%s_%s" % (
        prefix,
        hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:32],
    )


class AdministrationPrincipal(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(pattern=r"^(analyst|system)://[A-Za-z0-9_.@/-]+$")
    session_id: str = Field(pattern=r"^session_[0-9a-f]{32}$")
    roles: Set[HumanRole] = Field(min_length=1, max_length=6)
    authentication_method: str = Field(pattern=r"^(sso_assertion|local_test_adapter)$")
    mfa_verified: bool
    authenticated_at: datetime
    expires_at: datetime
    step_up_until: Optional[datetime] = None

    @model_validator(mode="after")
    def valid_session_window(self) -> "AdministrationPrincipal":
        _iso(self.authenticated_at)
        _iso(self.expires_at)
        if self.expires_at <= self.authenticated_at:
            raise ValueError("administration session expiry is invalid")
        if self.step_up_until is not None:
            _iso(self.step_up_until)
            if not self.mfa_verified or self.step_up_until > self.expires_at:
                raise ValueError("step-up requires MFA and cannot outlive the session")
        return self

    @property
    def permissions(self) -> Set[str]:
        result: Set[str] = set()
        for role in self.roles:
            result.update(ROLE_PERMISSIONS[role])
        return result


class SignedIdentityAssertion(StrictModel):
    schema_version: str = "1.0.0"
    assertion_id: str = Field(pattern=r"^assertion_[0-9a-f]{32}$")
    issuer: str = Field(min_length=3, max_length=256)
    audience: str = Field(min_length=3, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    subject: str = Field(pattern=r"^analyst://[A-Za-z0-9_.@/-]+$")
    session_id: str = Field(pattern=r"^session_[0-9a-f]{32}$")
    roles: Set[HumanRole] = Field(min_length=1, max_length=6)
    mfa_verified: bool
    authentication_context: str = Field(pattern=r"^(standard|step_up)$")
    issued_at: datetime
    expires_at: datetime
    signature_algorithm: str = PocHmacSigner.algorithm
    signature: str = ""

    @model_validator(mode="after")
    def valid_assertion(self) -> "SignedIdentityAssertion":
        _iso(self.issued_at)
        _iso(self.expires_at)
        if self.expires_at <= self.issued_at or self.expires_at - self.issued_at > timedelta(hours=12):
            raise ValueError("identity assertion validity window is invalid")
        if self.authentication_context == "step_up" and not self.mfa_verified:
            raise ValueError("step-up assertion requires MFA")
        return self

    def unsigned_payload(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature"})


class IdentityAssertionVerifier:
    """Provider-neutral assertion verifier; HMAC is a local test adapter only."""

    def __init__(
        self,
        signing_key: bytes,
        *,
        issuer: str,
        audience: str,
        now: Callable[[], datetime] = utc_now,
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError("identity assertion key must contain at least 32 bytes")
        self.signer = PocHmacSigner(signing_key)
        self.issuer = issuer
        self.audience = audience
        self._now = now

    def sign_for_test(self, assertion: SignedIdentityAssertion) -> SignedIdentityAssertion:
        unsigned = assertion.model_copy(update={"signature": ""})
        return unsigned.model_copy(
            update={"signature": self.signer.sign(unsigned.unsigned_payload())}
        )

    def verify(self, assertion: SignedIdentityAssertion) -> None:
        now = self._now()
        if assertion.issuer != self.issuer or assertion.audience != self.audience:
            raise AdministrationAuthorizationError("identity assertion trust boundary denied")
        if not self.signer.verify(assertion.unsigned_payload(), assertion.signature):
            raise AdministrationAuthorizationError("identity assertion signature is invalid")
        if assertion.issued_at > now + timedelta(minutes=2) or not assertion.issued_at <= now < assertion.expires_at:
            raise AdministrationAuthorizationError("identity assertion is outside its validity window")


class TenantSecurityPolicy(StrictModel):
    schema_version: str = "1.0.0"
    tenant_id: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=2, max_length=128)
    status: str = Field(pattern=r"^(active|suspended)$")
    residency_region: str = Field(pattern=r"^[a-z]{2}-[a-z]+-[0-9]+$")
    allowed_processing_regions: Set[str] = Field(min_length=1, max_length=16)
    retention_days: int = Field(ge=1, le=36500)
    evidence_retention_days: int = Field(ge=1, le=36500)
    legal_hold: bool = False
    encryption_required: bool = True
    managed_key_reference: str = Field(pattern=r"^keyref://[A-Za-z0-9_.@/-]+$")
    policy_version: int = Field(ge=1)
    updated_by: str
    updated_at: datetime
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def valid_policy(self) -> "TenantSecurityPolicy":
        if self.residency_region not in self.allowed_processing_regions:
            raise ValueError("residency region must be an allowed processing region")
        if self.evidence_retention_days < self.retention_days:
            raise ValueError("evidence retention cannot be shorter than record retention")
        _iso(self.updated_at)
        body = self.model_dump(mode="python", exclude={"record_sha256"})
        if self.record_sha256 != _digest(body):
            raise ValueError("tenant policy digest is invalid")
        return self


class HumanIdentityRecord(StrictModel):
    schema_version: str = "1.0.0"
    tenant_id: str
    subject: str = Field(pattern=r"^analyst://[A-Za-z0-9_.@/-]+$")
    display_name: str = Field(min_length=2, max_length=128)
    email_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    roles: Set[HumanRole] = Field(min_length=1, max_length=6)
    enabled: bool
    granted_by: str
    created_at: datetime
    updated_at: datetime
    version: int = Field(ge=1)
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class WorkloadIdentityRecord(StrictModel):
    schema_version: str = "1.0.0"
    tenant_id: str
    workload_id: str = Field(pattern=r"^workload://[A-Za-z0-9_.@/-]+$")
    display_name: str = Field(min_length=2, max_length=128)
    credential_reference: str = Field(pattern=r"^credentialref://[A-Za-z0-9_.@/-]+$")
    credential_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    scopes: Set[str] = Field(min_length=1, max_length=64)
    issued_at: datetime
    expires_at: datetime
    rotated_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    version: int = Field(ge=1)
    updated_by: str
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("scopes")
    @classmethod
    def valid_scopes(cls, value: Set[str]) -> Set[str]:
        if any(
            re.fullmatch(r"[a-z][a-z0-9_.-]{1,63}:[a-z][a-z0-9_.-]{1,63}", item)
            is None
            for item in value
        ):
            raise ValueError("workload scopes must be bounded resource:action names")
        return value

    @model_validator(mode="after")
    def valid_lifecycle(self) -> "WorkloadIdentityRecord":
        _iso(self.issued_at)
        _iso(self.expires_at)
        if self.expires_at <= self.issued_at:
            raise ValueError("workload credential expiry is invalid")
        for value in (self.rotated_at, self.revoked_at):
            if value is not None:
                _iso(value)
        return self


class KeyState(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class ManagedKeyRecord(StrictModel):
    schema_version: str = "1.0.0"
    tenant_id: str
    key_id: str = Field(pattern=r"^managed-key://[A-Za-z0-9_.@/-]+$")
    purpose: str = Field(pattern=r"^(signing|encryption|connector|checkpoint)$")
    provider_reference: str = Field(pattern=r"^keyref://[A-Za-z0-9_.@/-]+$")
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: KeyState
    version: int = Field(ge=1)
    previous_key_id: Optional[str] = None
    rotation_due_at: datetime
    registered_by: str
    approved_by: Optional[str] = None
    updated_at: datetime
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def valid_lifecycle(self) -> "ManagedKeyRecord":
        _iso(self.rotation_due_at)
        _iso(self.updated_at)
        if self.rotation_due_at <= self.updated_at:
            raise ValueError("managed key rotation must be scheduled in the future")
        if self.state == KeyState.ACTIVE and not self.approved_by:
            raise ValueError("active managed keys require an independent approval")
        return self


class AccessReviewRecord(StrictModel):
    schema_version: str = "1.0.0"
    review_id: str = Field(pattern=r"^access-review_[0-9a-f]{32}$")
    tenant_id: str
    subject: str
    roles: Set[HumanRole]
    decision: str = Field(pattern=r"^(certified|revoke_required)$")
    rationale_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_id: str
    reviewed_at: datetime
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ServiceLevelObjective(StrictModel):
    objective_id: str = Field(pattern=r"^slo://[A-Za-z0-9_.@/-]+$")
    name: str = Field(min_length=3, max_length=128)
    metric: str = Field(pattern=r"^(availability|latency_ms|durability|detector_lag_ms)$")
    comparison: str = Field(pattern=r"^(gte|lte)$")
    target: float = Field(gt=0)
    window_minutes: int = Field(ge=1, le=525600)


class ServiceLevelMeasurement(StrictModel):
    measurement_id: str = Field(pattern=r"^slo-measurement_[0-9a-f]{32}$")
    tenant_id: str
    objective: ServiceLevelObjective
    observed: float = Field(ge=0)
    passed: bool
    error_budget_remaining: float = Field(ge=0, le=1)
    measured_at: datetime
    measured_by: str
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def valid_result(self) -> "ServiceLevelMeasurement":
        expected = (
            self.observed >= self.objective.target
            if self.objective.comparison == "gte"
            else self.observed <= self.objective.target
        )
        if self.passed != expected:
            raise ValueError("SLO pass state does not match the objective")
        _iso(self.measured_at)
        return self


class RecoveryDrillRecord(StrictModel):
    drill_id: str = Field(pattern=r"^recovery-drill_[0-9a-f]{32}$")
    tenant_id: str
    backup_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_checkpoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    restored_checkpoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    backup_created_at: datetime
    drill_completed_at: datetime
    observed_rpo_minutes: float = Field(ge=0)
    observed_rto_minutes: float = Field(ge=0)
    target_rpo_minutes: float = Field(gt=0)
    target_rto_minutes: float = Field(gt=0)
    integrity_verified: bool
    passed: bool
    performed_by: str
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def valid_result(self) -> "RecoveryDrillRecord":
        _iso(self.backup_created_at)
        _iso(self.drill_completed_at)
        if self.backup_created_at > self.drill_completed_at:
            raise ValueError("backup cannot be newer than the recovery drill")
        expected = (
            self.integrity_verified
            and hmac.compare_digest(
                self.source_checkpoint_sha256, self.restored_checkpoint_sha256
            )
            and self.observed_rpo_minutes <= self.target_rpo_minutes
            and self.observed_rto_minutes <= self.target_rto_minutes
        )
        if self.passed != expected:
            raise ValueError("recovery pass state does not match the drill evidence")
        return self


class SupplyChainAttestation(StrictModel):
    attestation_id: str = Field(pattern=r"^attestation_[0-9a-f]{32}$")
    tenant_id: str
    release_id: str = Field(min_length=3, max_length=128)
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sbom_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provenance_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    dependency_scan_passed: bool
    secret_scan_passed: bool
    signature_verified: bool
    builder_id: str
    verifier_id: str
    verified_at: datetime
    passed: bool
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def valid_result(self) -> "SupplyChainAttestation":
        _iso(self.verified_at)
        if self.builder_id == self.verifier_id:
            raise ValueError("release builder and verifier must be independent")
        expected = (
            self.dependency_scan_passed
            and self.secret_scan_passed
            and self.signature_verified
        )
        if self.passed != expected:
            raise ValueError("supply-chain pass state does not match the evidence")
        return self


class AdministrationAuditEntry(StrictModel):
    sequence: int = Field(ge=1)
    tenant_id: str
    actor_id: str
    action: str
    object_id: str
    detail_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    occurred_at: datetime
    previous_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    entry_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AdministrationAuditCheckpoint(StrictModel):
    checkpoint_id: str = Field(pattern=r"^admin-checkpoint_[0-9a-f]{32}$")
    tenant_id: str
    sequence: int = Field(ge=0)
    current_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    created_by: str
    signature_algorithm: str = PocHmacSigner.algorithm
    signature: str = ""

    def unsigned_payload(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature"})


class AdministrationAuditVerification(StrictModel):
    valid: bool
    reason: str
    first_broken_sequence: int = Field(ge=0)
    entries: int = Field(ge=0)
    checkpoint_sequence: int = Field(ge=0)


class AdministrationHealth(StrictModel):
    schema_version: str = "1.0.0"
    tenant_id: str
    status: str = Field(pattern=r"^(healthy|attention_required)$")
    identities: int = Field(ge=0)
    workloads: int = Field(ge=0)
    active_keys: int = Field(ge=0)
    access_reviews: int = Field(ge=0)
    audit_entries: int = Field(ge=0)
    audit_valid: bool
    latest_slos_passed: bool
    latest_recovery_drill_passed: bool
    latest_supply_chain_attestation_passed: bool
    legal_hold: bool
    local_identity_adapter: Literal[True] = True
    external_idp_federated: Literal[False] = False
    external_key_custody_verified: Literal[False] = False
    geographic_residency_verified: Literal[False] = False
    distributed_ha_verified: Literal[False] = False
    production_ready: Literal[False] = False
    boundaries: List[str]
    calculated_at: datetime


class AdministrationSnapshot(StrictModel):
    schema_version: str = "1.0.0"
    tenant: TenantSecurityPolicy
    identities: List[HumanIdentityRecord]
    workloads: List[WorkloadIdentityRecord]
    keys: List[ManagedKeyRecord]
    access_reviews: List[AccessReviewRecord]
    slo_measurements: List[ServiceLevelMeasurement]
    recovery_drills: List[RecoveryDrillRecord]
    supply_chain_attestations: List[SupplyChainAttestation]
    latest_audit_checkpoint: Optional[AdministrationAuditCheckpoint]
    health: AdministrationHealth


class AdministrationService:
    """Durable tenant-scoped administration service with append-only audit."""

    def __init__(
        self,
        database_path: str,
        *,
        tenant_id: str,
        assertion_verifier: IdentityAssertionVerifier,
        checkpoint_signer: PocHmacSigner,
        now: Callable[[], datetime] = utc_now,
    ) -> None:
        self.tenant_id = tenant_id
        self.assertion_verifier = assertion_verifier
        self.checkpoint_signer = checkpoint_signer
        self._now = now
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            database_path, check_same_thread=False, isolation_level=None
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._create_schema()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS administration_objects (
                tenant_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                object_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                active INTEGER NOT NULL,
                record_sha256 TEXT NOT NULL,
                record_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, kind, object_id)
            );
            CREATE INDEX IF NOT EXISTS idx_administration_objects
                ON administration_objects(tenant_id, kind, active, updated_at);
            CREATE TABLE IF NOT EXISTS administration_assertion_replay (
                tenant_id TEXT NOT NULL,
                assertion_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, assertion_id)
            );
            CREATE TABLE IF NOT EXISTS administration_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                action TEXT NOT NULL,
                object_id TEXT NOT NULL,
                detail_sha256 TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                previous_sha256 TEXT NOT NULL,
                entry_sha256 TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_administration_audit
                ON administration_audit(tenant_id, sequence);
            CREATE TRIGGER IF NOT EXISTS administration_audit_no_update
                BEFORE UPDATE ON administration_audit
                BEGIN SELECT RAISE(ABORT, 'administration audit is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS administration_audit_no_delete
                BEFORE DELETE ON administration_audit
                BEGIN SELECT RAISE(ABORT, 'administration audit is append-only'); END;
            CREATE TABLE IF NOT EXISTS administration_checkpoints (
                tenant_id TEXT NOT NULL,
                checkpoint_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                checkpoint_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, checkpoint_id)
            );
            """
        )

    def _authorize(
        self,
        principal: AdministrationPrincipal,
        permission: str,
        *,
        high_impact: bool = False,
    ) -> None:
        now = self._now()
        if principal.tenant_id != self.tenant_id:
            raise AdministrationAuthorizationError("administration tenant denied")
        if not principal.authenticated_at <= now < principal.expires_at:
            raise AdministrationAuthorizationError("administration session expired")
        if permission not in principal.permissions:
            raise AdministrationAuthorizationError("administration permission denied")
        if high_impact and (
            not principal.mfa_verified
            or principal.step_up_until is None
            or principal.step_up_until <= now
        ):
            raise AdministrationAuthorizationError("fresh MFA step-up is required")

    def authenticate_assertion(
        self, assertion: SignedIdentityAssertion
    ) -> AdministrationPrincipal:
        self.assertion_verifier.verify(assertion)
        if assertion.tenant_id != self.tenant_id:
            raise AdministrationAuthorizationError("identity assertion tenant denied")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._connection.execute(
                    "SELECT 1 FROM administration_assertion_replay WHERE tenant_id = ? AND assertion_id = ?",
                    (self.tenant_id, assertion.assertion_id),
                ).fetchone()
                if replay is not None:
                    raise AdministrationAuthorizationError("identity assertion replay denied")
                row = self._object_row("identity", assertion.subject)
                if row is None:
                    raise AdministrationAuthorizationError("identity is not provisioned")
                identity = HumanIdentityRecord.model_validate_json(str(row["record_json"]))
                if not identity.enabled or not assertion.roles.issubset(identity.roles):
                    raise AdministrationAuthorizationError("identity role grant denied")
                self._connection.execute(
                    "INSERT INTO administration_assertion_replay VALUES (?, ?, ?)",
                    (self.tenant_id, assertion.assertion_id, _iso(assertion.expires_at)),
                )
                self._audit_raw(
                    assertion.subject,
                    "administration.session_authenticated",
                    assertion.session_id,
                    {
                        "assertion_id": assertion.assertion_id,
                        "roles": sorted(role.value for role in assertion.roles),
                        "mfa_verified": assertion.mfa_verified,
                        "authentication_context": assertion.authentication_context,
                    },
                    assertion.issued_at,
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        step_up = (
            min(assertion.expires_at, self._now() + timedelta(minutes=15))
            if assertion.authentication_context == "step_up"
            else None
        )
        return AdministrationPrincipal(
            tenant_id=self.tenant_id,
            actor_id=assertion.subject,
            session_id=assertion.session_id,
            roles=assertion.roles,
            authentication_method="sso_assertion",
            mfa_verified=assertion.mfa_verified,
            authenticated_at=assertion.issued_at,
            expires_at=assertion.expires_at,
            step_up_until=step_up,
        )

    def _object_row(self, kind: str, object_id: str) -> Optional[sqlite3.Row]:
        return self._connection.execute(
            "SELECT * FROM administration_objects WHERE tenant_id = ? AND kind = ? AND object_id = ?",
            (self.tenant_id, kind, object_id),
        ).fetchone()

    def _store_object(
        self,
        kind: str,
        object_id: str,
        version: int,
        record: StrictModel,
        updated_at: datetime,
        *,
        active: bool = True,
    ) -> None:
        digest = str(getattr(record, "record_sha256"))
        existing = self._object_row(kind, object_id)
        if existing is not None and int(existing["version"]) >= version:
            raise AdministrationConflictError("administration object version is stale")
        self._connection.execute(
            "INSERT INTO administration_objects VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(tenant_id, kind, object_id) DO UPDATE SET "
            "version=excluded.version, active=excluded.active, record_sha256=excluded.record_sha256, "
            "record_json=excluded.record_json, updated_at=excluded.updated_at",
            (
                self.tenant_id,
                kind,
                object_id,
                version,
                int(active),
                digest,
                record.model_dump_json(),
                _iso(updated_at),
            ),
        )

    def _audit_raw(
        self,
        actor_id: str,
        action: str,
        object_id: str,
        details: Mapping[str, Any],
        occurred_at: Optional[datetime] = None,
    ) -> None:
        prior = self._connection.execute(
            "SELECT entry_sha256 FROM administration_audit WHERE tenant_id = ? ORDER BY sequence DESC LIMIT 1",
            (self.tenant_id,),
        ).fetchone()
        previous = str(prior["entry_sha256"]) if prior else ZERO_SHA256
        timestamp = _iso(occurred_at or self._now())
        detail_sha256 = _digest(dict(details))
        latest_sequence = self._connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) AS n FROM administration_audit"
        ).fetchone()
        sequence = int(latest_sequence["n"]) + 1
        body = {
            "sequence": sequence,
            "tenant_id": self.tenant_id,
            "actor_id": actor_id,
            "action": action,
            "object_id": object_id,
            "detail_sha256": detail_sha256,
            "occurred_at": timestamp,
            "previous_sha256": previous,
        }
        self._connection.execute(
            "INSERT INTO administration_audit "
            "(sequence, tenant_id, actor_id, action, object_id, detail_sha256, occurred_at, previous_sha256, entry_sha256) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                sequence,
                self.tenant_id,
                actor_id,
                action,
                object_id,
                detail_sha256,
                timestamp,
                previous,
                _digest(body),
            ),
        )

    @staticmethod
    def _record(model: type[StrictModel], body: Dict[str, Any]) -> StrictModel:
        material = dict(body)
        if model is not TenantSecurityPolicy:
            provisional = model.model_validate(
                {**material, "record_sha256": ZERO_SHA256}
            )
            material = provisional.model_dump(
                mode="python", exclude={"record_sha256"}
            )
        material["record_sha256"] = _digest(material)
        return model.model_validate(material)

    def put_tenant_policy(
        self,
        principal: AdministrationPrincipal,
        *,
        display_name: str,
        residency_region: str,
        allowed_processing_regions: Set[str],
        retention_days: int,
        evidence_retention_days: int,
        legal_hold: bool,
        managed_key_reference: str,
        expected_version: int,
    ) -> TenantSecurityPolicy:
        self._authorize(principal, ADMIN_PRIVACY, high_impact=True)
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                current = self._object_row("tenant", self.tenant_id)
                current_version = int(current["version"]) if current else 0
                if current_version != expected_version:
                    raise AdministrationConflictError("tenant policy version conflict")
                body = {
                    "schema_version": "1.0.0",
                    "tenant_id": self.tenant_id,
                    "display_name": display_name,
                    "status": "active",
                    "residency_region": residency_region,
                    "allowed_processing_regions": sorted(allowed_processing_regions),
                    "retention_days": retention_days,
                    "evidence_retention_days": evidence_retention_days,
                    "legal_hold": legal_hold,
                    "encryption_required": True,
                    "managed_key_reference": managed_key_reference,
                    "policy_version": current_version + 1,
                    "updated_by": principal.actor_id,
                    "updated_at": _iso(now),
                }
                record = self._record(TenantSecurityPolicy, body)
                assert isinstance(record, TenantSecurityPolicy)
                self._store_object("tenant", self.tenant_id, record.policy_version, record, now)
                self._audit_raw(principal.actor_id, "administration.tenant_policy_updated", self.tenant_id, {"record_sha256": record.record_sha256, "version": record.policy_version})
                self._connection.execute("COMMIT")
                return record
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def upsert_identity(
        self,
        principal: AdministrationPrincipal,
        *,
        subject: str,
        display_name: str,
        email_sha256: str,
        roles: Set[HumanRole],
        enabled: bool,
        expected_version: int,
    ) -> HumanIdentityRecord:
        self._authorize(principal, ADMIN_IDENTITY, high_impact=True)
        if subject == principal.actor_id and (not enabled or HumanRole.PLATFORM_ADMINISTRATOR not in roles):
            raise AdministrationAuthorizationError("administrator cannot remove own active administration grant")
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                current = self._object_row("identity", subject)
                version = int(current["version"]) if current else 0
                if version != expected_version:
                    raise AdministrationConflictError("identity version conflict")
                body = {
                    "schema_version": "1.0.0", "tenant_id": self.tenant_id,
                    "subject": subject, "display_name": display_name,
                    "email_sha256": email_sha256, "roles": sorted(role.value for role in roles),
                    "enabled": enabled, "granted_by": principal.actor_id,
                    "created_at": str(current["updated_at"]) if current else _iso(now),
                    "updated_at": _iso(now), "version": version + 1,
                }
                record = self._record(HumanIdentityRecord, body)
                assert isinstance(record, HumanIdentityRecord)
                self._store_object("identity", subject, record.version, record, now, active=enabled)
                self._audit_raw(principal.actor_id, "administration.identity_updated", subject, {"roles": sorted(role.value for role in roles), "enabled": enabled, "record_sha256": record.record_sha256})
                self._connection.execute("COMMIT")
                return record
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def register_workload(
        self,
        principal: AdministrationPrincipal,
        *,
        workload_id: str,
        display_name: str,
        credential_reference: str,
        credential_fingerprint: str,
        scopes: Set[str],
        expires_at: datetime,
        expected_version: int = 0,
    ) -> WorkloadIdentityRecord:
        self._authorize(principal, ADMIN_WORKLOAD, high_impact=True)
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                current = self._object_row("workload", workload_id)
                version = int(current["version"]) if current else 0
                if version != expected_version:
                    raise AdministrationConflictError("workload version conflict")
                previous = WorkloadIdentityRecord.model_validate_json(str(current["record_json"])) if current else None
                if previous is not None and hmac.compare_digest(previous.credential_fingerprint, credential_fingerprint):
                    raise AdministrationConflictError("workload rotation must change the credential fingerprint")
                body = {
                    "schema_version": "1.0.0", "tenant_id": self.tenant_id,
                    "workload_id": workload_id, "display_name": display_name,
                    "credential_reference": credential_reference,
                    "credential_fingerprint": credential_fingerprint,
                    "scopes": sorted(scopes), "issued_at": _iso(now), "expires_at": _iso(expires_at),
                    "rotated_at": _iso(now) if previous else None, "revoked_at": None,
                    "version": version + 1, "updated_by": principal.actor_id,
                }
                record = self._record(WorkloadIdentityRecord, body)
                assert isinstance(record, WorkloadIdentityRecord)
                self._store_object("workload", workload_id, record.version, record, now)
                self._audit_raw(principal.actor_id, "administration.workload_rotated" if previous else "administration.workload_registered", workload_id, {"credential_fingerprint": credential_fingerprint, "scopes": sorted(scopes), "record_sha256": record.record_sha256})
                self._connection.execute("COMMIT")
                return record
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def revoke_workload(
        self, principal: AdministrationPrincipal, workload_id: str, *, expected_version: int
    ) -> WorkloadIdentityRecord:
        self._authorize(principal, ADMIN_WORKLOAD, high_impact=True)
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._object_row("workload", workload_id)
                if row is None:
                    raise KeyError(workload_id)
                prior = WorkloadIdentityRecord.model_validate_json(str(row["record_json"]))
                if prior.version != expected_version or prior.revoked_at is not None:
                    raise AdministrationConflictError("workload revocation conflicts")
                body = prior.model_dump(mode="json", exclude={"record_sha256"})
                body.update({"revoked_at": _iso(now), "version": prior.version + 1, "updated_by": principal.actor_id})
                record = self._record(WorkloadIdentityRecord, body)
                assert isinstance(record, WorkloadIdentityRecord)
                self._store_object("workload", workload_id, record.version, record, now, active=False)
                self._audit_raw(principal.actor_id, "administration.workload_revoked", workload_id, {"version": record.version, "record_sha256": record.record_sha256})
                self._connection.execute("COMMIT")
                return record
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def register_key(
        self,
        principal: AdministrationPrincipal,
        *,
        key_id: str,
        purpose: str,
        provider_reference: str,
        fingerprint: str,
        rotation_due_at: datetime,
        previous_key_id: Optional[str] = None,
    ) -> ManagedKeyRecord:
        self._authorize(principal, ADMIN_KEYS, high_impact=True)
        now = self._now()
        if self._object_row("key", key_id) is not None:
            raise AdministrationConflictError("managed key already exists")
        body = {
            "schema_version": "1.0.0", "tenant_id": self.tenant_id,
            "key_id": key_id, "purpose": purpose, "provider_reference": provider_reference,
            "fingerprint": fingerprint, "state": KeyState.PENDING.value, "version": 1,
            "previous_key_id": previous_key_id, "rotation_due_at": _iso(rotation_due_at),
            "registered_by": principal.actor_id, "approved_by": None, "updated_at": _iso(now),
        }
        record = self._record(ManagedKeyRecord, body)
        assert isinstance(record, ManagedKeyRecord)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._store_object("key", key_id, 1, record, now)
                self._audit_raw(principal.actor_id, "administration.key_registered", key_id, {"provider_reference": provider_reference, "fingerprint": fingerprint, "record_sha256": record.record_sha256})
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return record

    def transition_key(
        self,
        principal: AdministrationPrincipal,
        key_id: str,
        *,
        target_state: KeyState,
        expected_version: int,
    ) -> ManagedKeyRecord:
        self._authorize(principal, ADMIN_KEYS, high_impact=True)
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._object_row("key", key_id)
                if row is None:
                    raise KeyError(key_id)
                prior = ManagedKeyRecord.model_validate_json(str(row["record_json"]))
                if prior.version != expected_version:
                    raise AdministrationConflictError("managed key version conflict")
                if target_state == KeyState.ACTIVE:
                    if prior.state != KeyState.PENDING or prior.registered_by == principal.actor_id:
                        raise AdministrationAuthorizationError("key activation requires an independent approver")
                elif target_state in {KeyState.RETIRED, KeyState.REVOKED}:
                    if prior.state != KeyState.ACTIVE:
                        raise AdministrationConflictError("only an active key can be retired or revoked")
                else:
                    raise AdministrationConflictError("managed key transition is invalid")
                body = prior.model_dump(mode="json", exclude={"record_sha256"})
                body.update({"state": target_state.value, "version": prior.version + 1, "approved_by": principal.actor_id, "updated_at": _iso(now)})
                record = self._record(ManagedKeyRecord, body)
                assert isinstance(record, ManagedKeyRecord)
                self._store_object("key", key_id, record.version, record, now, active=target_state in {KeyState.PENDING, KeyState.ACTIVE})
                self._audit_raw(principal.actor_id, "administration.key_%s" % target_state.value, key_id, {"version": record.version, "record_sha256": record.record_sha256})
                self._connection.execute("COMMIT")
                return record
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def certify_access(
        self,
        principal: AdministrationPrincipal,
        subject: str,
        *,
        decision: str,
        rationale_sha256: str,
    ) -> AccessReviewRecord:
        self._authorize(principal, ADMIN_ACCESS_REVIEW, high_impact=True)
        if subject == principal.actor_id:
            raise AdministrationAuthorizationError("access review must be independent")
        row = self._object_row("identity", subject)
        if row is None:
            raise KeyError(subject)
        identity = HumanIdentityRecord.model_validate_json(str(row["record_json"]))
        if identity.granted_by == principal.actor_id:
            raise AdministrationAuthorizationError("access grantor cannot certify the same access")
        now = self._now()
        review_id = _stable_id("access-review", self.tenant_id, subject, _iso(now))
        body = {
            "schema_version": "1.0.0", "review_id": review_id,
            "tenant_id": self.tenant_id, "subject": subject,
            "roles": sorted(role.value for role in identity.roles), "decision": decision,
            "rationale_sha256": rationale_sha256,
            "reviewer_id": principal.actor_id, "reviewed_at": _iso(now),
        }
        record = self._record(AccessReviewRecord, body)
        assert isinstance(record, AccessReviewRecord)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._store_object("access_review", review_id, 1, record, now)
                self._audit_raw(principal.actor_id, "administration.access_review_completed", subject, {"review_id": review_id, "decision": decision, "record_sha256": record.record_sha256})
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return record

    def record_slo_measurement(
        self,
        principal: AdministrationPrincipal,
        objective: ServiceLevelObjective,
        *,
        observed: float,
        error_budget_remaining: float,
    ) -> ServiceLevelMeasurement:
        self._authorize(principal, ADMIN_ASSURANCE, high_impact=True)
        now = self._now()
        passed = observed >= objective.target if objective.comparison == "gte" else observed <= objective.target
        measurement_id = _stable_id("slo-measurement", self.tenant_id, objective.objective_id, _iso(now))
        body = {
            "measurement_id": measurement_id, "tenant_id": self.tenant_id,
            "objective": objective.model_dump(mode="json"), "observed": observed,
            "passed": passed, "error_budget_remaining": error_budget_remaining,
            "measured_at": _iso(now), "measured_by": principal.actor_id,
        }
        record = self._record(ServiceLevelMeasurement, body)
        assert isinstance(record, ServiceLevelMeasurement)
        self._persist_assurance(principal, "slo", measurement_id, record, "administration.slo_measured", passed)
        return record

    def record_recovery_drill(
        self,
        principal: AdministrationPrincipal,
        *,
        backup_manifest_sha256: str,
        source_checkpoint_sha256: str,
        restored_checkpoint_sha256: str,
        backup_created_at: datetime,
        observed_rpo_minutes: float,
        observed_rto_minutes: float,
        target_rpo_minutes: float,
        target_rto_minutes: float,
        integrity_verified: bool,
    ) -> RecoveryDrillRecord:
        self._authorize(principal, ADMIN_ASSURANCE, high_impact=True)
        now = self._now()
        passed = (
            integrity_verified
            and hmac.compare_digest(source_checkpoint_sha256, restored_checkpoint_sha256)
            and observed_rpo_minutes <= target_rpo_minutes
            and observed_rto_minutes <= target_rto_minutes
        )
        drill_id = _stable_id("recovery-drill", self.tenant_id, backup_manifest_sha256, _iso(now))
        body = {
            "drill_id": drill_id, "tenant_id": self.tenant_id,
            "backup_manifest_sha256": backup_manifest_sha256,
            "source_checkpoint_sha256": source_checkpoint_sha256,
            "restored_checkpoint_sha256": restored_checkpoint_sha256,
            "backup_created_at": _iso(backup_created_at), "drill_completed_at": _iso(now),
            "observed_rpo_minutes": observed_rpo_minutes, "observed_rto_minutes": observed_rto_minutes,
            "target_rpo_minutes": target_rpo_minutes, "target_rto_minutes": target_rto_minutes,
            "integrity_verified": integrity_verified, "passed": passed, "performed_by": principal.actor_id,
        }
        record = self._record(RecoveryDrillRecord, body)
        assert isinstance(record, RecoveryDrillRecord)
        self._persist_assurance(principal, "recovery_drill", drill_id, record, "administration.recovery_drill_recorded", passed)
        return record

    def record_supply_chain_attestation(
        self,
        principal: AdministrationPrincipal,
        *,
        release_id: str,
        artifact_sha256: str,
        sbom_sha256: str,
        provenance_sha256: str,
        dependency_scan_passed: bool,
        secret_scan_passed: bool,
        signature_verified: bool,
        builder_id: str,
    ) -> SupplyChainAttestation:
        self._authorize(principal, ADMIN_ASSURANCE, high_impact=True)
        if builder_id == principal.actor_id:
            raise AdministrationAuthorizationError("release attestation requires an independent verifier")
        now = self._now()
        passed = dependency_scan_passed and secret_scan_passed and signature_verified
        attestation_id = _stable_id("attestation", self.tenant_id, release_id, artifact_sha256)
        body = {
            "attestation_id": attestation_id, "tenant_id": self.tenant_id,
            "release_id": release_id, "artifact_sha256": artifact_sha256,
            "sbom_sha256": sbom_sha256, "provenance_sha256": provenance_sha256,
            "dependency_scan_passed": dependency_scan_passed, "secret_scan_passed": secret_scan_passed,
            "signature_verified": signature_verified, "builder_id": builder_id,
            "verifier_id": principal.actor_id, "verified_at": _iso(now), "passed": passed,
        }
        record = self._record(SupplyChainAttestation, body)
        assert isinstance(record, SupplyChainAttestation)
        self._persist_assurance(principal, "attestation", attestation_id, record, "administration.release_attested", passed)
        return record

    def _persist_assurance(
        self,
        principal: AdministrationPrincipal,
        kind: str,
        object_id: str,
        record: StrictModel,
        action: str,
        passed: bool,
    ) -> None:
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._store_object(kind, object_id, 1, record, now)
                self._audit_raw(principal.actor_id, action, object_id, {"passed": passed, "record_sha256": getattr(record, "record_sha256")})
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def list_audit(
        self, principal: AdministrationPrincipal, *, limit: int = 200
    ) -> List[AdministrationAuditEntry]:
        self._authorize(principal, ADMIN_AUDIT)
        if not 1 <= limit <= 2000:
            raise ValueError("administration audit limit is invalid")
        rows = self._connection.execute(
            "SELECT * FROM administration_audit WHERE tenant_id = ? ORDER BY sequence DESC LIMIT ?",
            (self.tenant_id, limit),
        ).fetchall()
        return [AdministrationAuditEntry.model_validate(dict(row)) for row in rows]

    def create_audit_checkpoint(
        self, principal: AdministrationPrincipal
    ) -> AdministrationAuditCheckpoint:
        self._authorize(principal, ADMIN_AUDIT, high_impact=True)
        with self._lock:
            row = self._connection.execute(
                "SELECT sequence, entry_sha256 FROM administration_audit WHERE tenant_id = ? ORDER BY sequence DESC LIMIT 1",
                (self.tenant_id,),
            ).fetchone()
            sequence = int(row["sequence"]) if row else 0
            current = str(row["entry_sha256"]) if row else ZERO_SHA256
            now = self._now()
            checkpoint_id = _stable_id("admin-checkpoint", self.tenant_id, str(sequence), current)
            unsigned = AdministrationAuditCheckpoint(
                checkpoint_id=checkpoint_id, tenant_id=self.tenant_id,
                sequence=sequence, current_sha256=current, created_at=now,
                created_by=principal.actor_id,
            )
            checkpoint = unsigned.model_copy(update={"signature": self.checkpoint_signer.sign(unsigned.unsigned_payload())})
            self._connection.execute(
                "INSERT OR IGNORE INTO administration_checkpoints VALUES (?, ?, ?, ?, ?)",
                (self.tenant_id, checkpoint_id, sequence, checkpoint.model_dump_json(), _iso(now)),
            )
            return checkpoint

    def verify_audit(
        self, checkpoint: Optional[AdministrationAuditCheckpoint] = None
    ) -> AdministrationAuditVerification:
        rows = self._connection.execute(
            "SELECT * FROM administration_audit WHERE tenant_id = ? ORDER BY sequence",
            (self.tenant_id,),
        ).fetchall()
        previous = ZERO_SHA256
        expected_sequence = int(rows[0]["sequence"]) if rows else 1
        for row in rows:
            sequence = int(row["sequence"])
            if sequence != expected_sequence or str(row["previous_sha256"]) != previous:
                return AdministrationAuditVerification(valid=False, reason="audit_sequence_or_chain_broken", first_broken_sequence=sequence, entries=len(rows), checkpoint_sequence=checkpoint.sequence if checkpoint else 0)
            body = {
                "sequence": sequence, "tenant_id": str(row["tenant_id"]),
                "actor_id": str(row["actor_id"]), "action": str(row["action"]),
                "object_id": str(row["object_id"]), "detail_sha256": str(row["detail_sha256"]),
                "occurred_at": str(row["occurred_at"]), "previous_sha256": str(row["previous_sha256"]),
            }
            if not hmac.compare_digest(_digest(body), str(row["entry_sha256"])):
                return AdministrationAuditVerification(valid=False, reason="audit_entry_digest_invalid", first_broken_sequence=sequence, entries=len(rows), checkpoint_sequence=checkpoint.sequence if checkpoint else 0)
            previous = str(row["entry_sha256"])
            expected_sequence += 1
        if checkpoint is not None:
            if checkpoint.tenant_id != self.tenant_id or not self.checkpoint_signer.verify(checkpoint.unsigned_payload(), checkpoint.signature):
                return AdministrationAuditVerification(valid=False, reason="checkpoint_signature_invalid", first_broken_sequence=checkpoint.sequence, entries=len(rows), checkpoint_sequence=checkpoint.sequence)
            if not rows or int(rows[-1]["sequence"]) < checkpoint.sequence:
                return AdministrationAuditVerification(valid=False, reason="audit_tail_deleted", first_broken_sequence=len(rows) + 1, entries=len(rows), checkpoint_sequence=checkpoint.sequence)
            matched = next((row for row in rows if int(row["sequence"]) == checkpoint.sequence), None)
            if matched is None or str(matched["entry_sha256"]) != checkpoint.current_sha256:
                return AdministrationAuditVerification(valid=False, reason="checkpoint_hash_mismatch", first_broken_sequence=checkpoint.sequence, entries=len(rows), checkpoint_sequence=checkpoint.sequence)
        return AdministrationAuditVerification(valid=True, reason="ok", first_broken_sequence=0, entries=len(rows), checkpoint_sequence=checkpoint.sequence if checkpoint else 0)

    def _records(self, kind: str, model: type[StrictModel]) -> List[Any]:
        rows = self._connection.execute(
            "SELECT record_sha256, record_json FROM administration_objects WHERE tenant_id = ? AND kind = ? ORDER BY updated_at DESC, object_id",
            (self.tenant_id, kind),
        ).fetchall()
        records: List[Any] = []
        for row in rows:
            record = model.model_validate_json(str(row["record_json"]))
            payload = record.model_dump(mode="python", exclude={"record_sha256"})
            if (
                not hmac.compare_digest(str(row["record_sha256"]), str(getattr(record, "record_sha256")))
                or not hmac.compare_digest(_digest(payload), str(getattr(record, "record_sha256")))
            ):
                raise ValueError("administration object digest is invalid")
            records.append(record)
        return records

    def latest_checkpoint(self) -> Optional[AdministrationAuditCheckpoint]:
        row = self._connection.execute(
            "SELECT checkpoint_json FROM administration_checkpoints WHERE tenant_id = ? ORDER BY sequence DESC, created_at DESC LIMIT 1",
            (self.tenant_id,),
        ).fetchone()
        return AdministrationAuditCheckpoint.model_validate_json(str(row["checkpoint_json"])) if row else None

    def snapshot(self, principal: AdministrationPrincipal) -> AdministrationSnapshot:
        self._authorize(principal, ADMIN_READ)
        tenant_rows = self._records("tenant", TenantSecurityPolicy)
        if not tenant_rows:
            raise KeyError(self.tenant_id)
        identities = self._records("identity", HumanIdentityRecord)
        workloads = self._records("workload", WorkloadIdentityRecord)
        keys = self._records("key", ManagedKeyRecord)
        reviews = self._records("access_review", AccessReviewRecord)
        slos = self._records("slo", ServiceLevelMeasurement)
        drills = self._records("recovery_drill", RecoveryDrillRecord)
        attestations = self._records("attestation", SupplyChainAttestation)
        checkpoint = self.latest_checkpoint()
        audit = self.verify_audit(checkpoint)
        latest_by_objective: Dict[str, ServiceLevelMeasurement] = {}
        for item in slos:
            latest_by_objective.setdefault(item.objective.objective_id, item)
        slos_passed = bool(latest_by_objective) and all(item.passed for item in latest_by_objective.values())
        recovery_passed = bool(drills) and drills[0].passed
        supply_chain_passed = bool(attestations) and attestations[0].passed
        healthy = audit.valid and slos_passed and recovery_passed and supply_chain_passed
        health = AdministrationHealth(
            tenant_id=self.tenant_id, status="healthy" if healthy else "attention_required",
            identities=len(identities), workloads=len(workloads),
            active_keys=sum(item.state == KeyState.ACTIVE for item in keys),
            access_reviews=len(reviews), audit_entries=audit.entries, audit_valid=audit.valid,
            latest_slos_passed=slos_passed,
            latest_recovery_drill_passed=recovery_passed,
            latest_supply_chain_attestation_passed=supply_chain_passed,
            legal_hold=tenant_rows[0].legal_hold,
            boundaries=[
                "Signed HMAC assertions are the local test adapter, not enterprise IdP federation.",
                "Managed credentials and keys are external references; custody is not claimed.",
                "Residency is policy metadata until deployment controls independently attest placement.",
                "Recovery drills are evidence records; this process is not a distributed HA cluster.",
            ], calculated_at=self._now(),
        )
        return AdministrationSnapshot(
            tenant=tenant_rows[0], identities=identities, workloads=workloads, keys=keys,
            access_reviews=reviews, slo_measurements=slos, recovery_drills=drills,
            supply_chain_attestations=attestations, latest_audit_checkpoint=checkpoint,
            health=health,
        )


def local_administration_principal(
    tenant_id: str,
    actor_id: str,
    roles: Set[HumanRole],
    *,
    now: Optional[datetime] = None,
    step_up: bool = True,
) -> AdministrationPrincipal:
    """Create an explicit local-test principal; never presented as federated SSO."""
    timestamp = now or utc_now()
    return AdministrationPrincipal(
        tenant_id=tenant_id, actor_id=actor_id,
        session_id=new_id("session"), roles=roles,
        authentication_method="local_test_adapter", mfa_verified=step_up,
        authenticated_at=timestamp, expires_at=timestamp + timedelta(hours=1),
        step_up_until=timestamp + timedelta(minutes=15) if step_up else None,
    )


def administration_service_from_environment(
    database_path: str,
    *,
    tenant_id: str,
    config_path: Optional[str] = None,
) -> tuple[AdministrationService, AdministrationPrincipal]:
    assertion_key = os.environ.get("AGENTSEC_ADMIN_ASSERTION_KEY", "")
    checkpoint_key = os.environ.get("AGENTSEC_ADMIN_CHECKPOINT_KEY", "")
    if len(assertion_key.encode("utf-8")) < 32 or len(checkpoint_key.encode("utf-8")) < 32:
        raise ValueError("administration assertion and checkpoint keys must each contain at least 32 bytes")
    verifier = IdentityAssertionVerifier(
        assertion_key.encode("utf-8"),
        issuer=os.environ.get("AGENTSEC_ADMIN_ASSERTION_ISSUER", "agentsec-local-test-idp"),
        audience=os.environ.get("AGENTSEC_ADMIN_ASSERTION_AUDIENCE", "agentsec-administration"),
    )
    service = AdministrationService(
        database_path, tenant_id=tenant_id, assertion_verifier=verifier,
        checkpoint_signer=PocHmacSigner(checkpoint_key.encode("utf-8")),
    )
    principal = local_administration_principal(
        tenant_id, "system://administration-runtime",
        {HumanRole.PLATFORM_ADMINISTRATOR, HumanRole.SECURITY_AUDITOR},
    )
    if config_path and not service._records("tenant", TenantSecurityPolicy):
        payload = json.loads(Path(config_path).read_text(encoding="utf-8"))
        if payload.get("schema_version") != "1.0.0" or payload.get("tenant_id") != tenant_id:
            raise ValueError("administration bootstrap configuration is invalid")
        policy = payload["tenant_policy"]
        service.put_tenant_policy(
            principal, display_name=policy["display_name"],
            residency_region=policy["residency_region"],
            allowed_processing_regions=set(policy["allowed_processing_regions"]),
            retention_days=int(policy["retention_days"]),
            evidence_retention_days=int(policy["evidence_retention_days"]),
            legal_hold=bool(policy.get("legal_hold", False)),
            managed_key_reference=policy["managed_key_reference"], expected_version=0,
        )
    return service, principal


__all__ = [
    "ADMIN_ACCESS_REVIEW", "ADMIN_ASSURANCE", "ADMIN_AUDIT", "ADMIN_IDENTITY",
    "ADMIN_KEYS", "ADMIN_PRIVACY", "ADMIN_READ", "ADMIN_TENANT", "ADMIN_WORKLOAD",
    "AccessReviewRecord", "AdministrationAuditCheckpoint", "AdministrationAuditEntry",
    "AdministrationAuditVerification", "AdministrationAuthorizationError",
    "AdministrationConflictError", "AdministrationHealth", "AdministrationPrincipal",
    "AdministrationService", "AdministrationSnapshot", "HumanIdentityRecord", "HumanRole",
    "IdentityAssertionVerifier", "KeyState", "ManagedKeyRecord", "RecoveryDrillRecord",
    "ServiceLevelMeasurement", "ServiceLevelObjective", "SignedIdentityAssertion",
    "SupplyChainAttestation", "TenantSecurityPolicy", "WorkloadIdentityRecord",
    "administration_service_from_environment", "local_administration_principal",
]
