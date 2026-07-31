"""Persistent discovery-backed inventory for AI applications and components."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from pydantic import Field, field_validator, model_validator

from .abom import AbomManifest
from .contracts import AgentEvent, Severity, StrictModel, new_id, utc_now
from .crypto import PocHmacSigner
from .model_registry import ModelRegistry
from .telemetry import TelemetryEnvelope


INVENTORY_READ = "inventory:read"
INVENTORY_DISCOVER = "inventory:discover"
INVENTORY_WRITE = "inventory:write"
INVENTORY_ADMIN = "inventory:admin"
MAX_INVENTORY_PAGE = 200
MAX_INVENTORY_OFFSET = 100000


class InventoryAuthorizationError(PermissionError):
    """Raised when an inventory principal lacks authority."""


class ComponentKind(str, Enum):
    APPLICATION = "application"
    AGENT = "agent"
    MODEL = "model"
    TOOL = "tool"
    DATA_STORE = "data_store"


class ComponentStatus(str, Enum):
    ACTIVE = "active"
    UNMANAGED = "unmanaged"
    RETIRED = "retired"


class InventorySource(str, Enum):
    DECLARED = "declared"
    OBSERVED = "observed"
    IMPORTED = "imported"


class RelationshipType(str, Enum):
    CONTAINS = "contains"
    USES_MODEL = "uses_model"
    USES_TOOL = "uses_tool"
    ACCESSES = "accesses"


class PermissionEffect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class InventoryPrincipal(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=1, max_length=256)
    permissions: Set[str] = Field(default_factory=set, max_length=32)

    @field_validator("permissions")
    @classmethod
    def valid_permissions(cls, value: Set[str]) -> Set[str]:
        if any(not re.fullmatch(r"[a-z]+:[a-z]+", item) for item in value):
            raise ValueError("inventory permissions must use namespace:operation")
        return value


class ComponentPermission(StrictModel):
    operation: str = Field(min_length=1, max_length=128)
    resource_scope: str = Field(min_length=1, max_length=512)
    effect: PermissionEffect = PermissionEffect.ALLOW
    approved: bool = False
    source_ref: str = Field(min_length=1, max_length=512)


SAFE_CONFIGURATION_KEYS = {
    "build_digest",
    "enabled",
    "endpoint_host",
    "environment",
    "framework",
    "model_id",
    "policy_bundle_digest",
    "prompt_version",
    "provider",
    "schema_digest",
    "source_type",
    "system_instruction_digest",
    "version",
}
SENSITIVE_CONFIGURATION_PATTERN = re.compile(
    r"(?:secret|token|password|credential|authorization|api[_-]?key)", re.IGNORECASE
)


def _validate_configuration(value: Dict[str, Any]) -> Dict[str, Any]:
    if len(value) > 32:
        raise ValueError("inventory configuration is limited to 32 fields")
    for key, item in value.items():
        if key not in SAFE_CONFIGURATION_KEYS:
            raise ValueError("inventory configuration field is not allowlisted: %s" % key)
        if SENSITIVE_CONFIGURATION_PATTERN.search(key):
            raise ValueError("sensitive configuration fields are forbidden")
        if item is not None and not isinstance(item, (str, int, float, bool)):
            raise ValueError("inventory configuration values must be scalar")
        if isinstance(item, str) and len(item) > 512:
            raise ValueError("inventory configuration value is too long")
    return value


class ComponentUpsert(StrictModel):
    component_id: Optional[str] = Field(default=None, min_length=5, max_length=128)
    kind: ComponentKind
    name: str = Field(min_length=1, max_length=256)
    external_ref: str = Field(min_length=1, max_length=512)
    application_id: Optional[str] = Field(default=None, min_length=5, max_length=128)
    owner_ref: Optional[str] = Field(default=None, max_length=256)
    criticality: Severity = Severity.MEDIUM
    status: ComponentStatus = ComponentStatus.ACTIVE
    source: InventorySource
    permissions: List[ComponentPermission] = Field(default_factory=list, max_length=256)
    configuration: Dict[str, Any] = Field(default_factory=dict)
    tags: Set[str] = Field(default_factory=set, max_length=64)
    observed_at: datetime = Field(default_factory=utc_now)

    @field_validator("configuration")
    @classmethod
    def configuration_is_safe(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        return _validate_configuration(value)

    @field_validator("tags")
    @classmethod
    def tags_are_bounded(cls, value: Set[str]) -> Set[str]:
        if any(not 1 <= len(item) <= 128 for item in value):
            raise ValueError("inventory tags must contain 1 to 128 characters")
        return value

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("inventory observation time must include a timezone")
        return value


class InventoryComponent(StrictModel):
    component_id: str = Field(min_length=5, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    kind: ComponentKind
    name: str
    external_ref: str
    application_id: Optional[str] = None
    owner_ref: Optional[str] = None
    criticality: Severity
    status: ComponentStatus
    source: InventorySource
    permissions: List[ComponentPermission]
    configuration: Dict[str, Any]
    configuration_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    configuration_version: int = Field(ge=1)
    tags: Set[str]
    risk_score: int = Field(ge=0, le=100)
    risk_reasons: List[str]
    first_seen_at: datetime
    last_seen_at: datetime
    updated_at: datetime


class ConfigurationRevision(StrictModel):
    component_id: str
    tenant_id: str
    version: int = Field(ge=1)
    configuration_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    previous_digest: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    configuration: Dict[str, Any]
    changed_fields: List[str]
    source: InventorySource
    observed_at: datetime
    recorded_at: datetime


class InventoryRelationship(StrictModel):
    tenant_id: str
    source_component_id: str
    relationship: RelationshipType
    target_component_id: str
    source_ref: str
    first_seen_at: datetime
    last_seen_at: datetime


class InventoryObservation(StrictModel):
    observation_id: str = Field(default_factory=lambda: new_id("iobs"), min_length=5, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    source_ref: str = Field(min_length=1, max_length=512)
    source_type: str = Field(min_length=1, max_length=64)
    observed_at: datetime = Field(default_factory=utc_now)
    application_external_id: str = Field(min_length=1, max_length=256)
    application_name: Optional[str] = Field(default=None, max_length=256)
    agent_external_id: str = Field(min_length=1, max_length=256)
    agent_name: Optional[str] = Field(default=None, max_length=256)
    environment: str = Field(default="unknown", min_length=1, max_length=64)
    model_provider: Optional[str] = Field(default=None, max_length=64)
    model_id: Optional[str] = Field(default=None, max_length=256)
    model_profile_id: Optional[str] = Field(default=None, max_length=128)
    tool_name: Optional[str] = Field(default=None, max_length=128)
    tool_schema_digest: Optional[str] = Field(default=None, max_length=256)
    operation: Optional[str] = Field(default=None, max_length=128)
    resource_scope: Optional[str] = Field(default=None, max_length=512)

    @field_validator("observed_at")
    @classmethod
    def time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("inventory discovery time must include a timezone")
        return value

    @model_validator(mode="after")
    def model_is_coherent(self) -> "InventoryObservation":
        if bool(self.model_provider) != bool(self.model_id):
            raise ValueError("model provider and model ID must be observed together")
        if self.tool_schema_digest and not self.tool_name:
            raise ValueError("tool schema digest requires a tool name")
        return self


class DiscoveryResult(StrictModel):
    observation_id: str
    duplicate: bool
    component_ids: List[str]
    relationship_count: int = Field(ge=0)
    configuration_revisions: int = Field(ge=0)
    recorded_at: datetime


class InventoryRiskRollup(StrictModel):
    component_id: str
    tenant_id: str
    score: int = Field(ge=0, le=100)
    component_count: int = Field(ge=1)
    high_risk_components: int = Field(ge=0)
    unowned_components: int = Field(ge=0)
    unapproved_permissions: int = Field(ge=0)
    reasons: List[str]
    calculated_at: datetime


class InventorySummary(StrictModel):
    tenant_id: str
    total_components: int = Field(ge=0)
    by_kind: Dict[ComponentKind, int]
    active_components: int = Field(ge=0)
    unmanaged_components: int = Field(ge=0)
    unowned_components: int = Field(ge=0)
    high_risk_components: int = Field(ge=0)
    maximum_risk_score: int = Field(ge=0, le=100)
    calculated_at: datetime


class InventoryPage(StrictModel):
    components: List[InventoryComponent]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=MAX_INVENTORY_PAGE)
    offset: int = Field(ge=0, le=MAX_INVENTORY_OFFSET)


class InventoryDetail(StrictModel):
    component: InventoryComponent
    configuration_history: List[ConfigurationRevision]
    relationships: List[InventoryRelationship]
    risk_rollup: InventoryRiskRollup


def _digest(configuration: Dict[str, Any]) -> str:
    encoded = json.dumps(
        configuration, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _stable_component_id(kind: ComponentKind, tenant_id: str, external_ref: str) -> str:
    digest = hashlib.sha256(
        (tenant_id + "\x00" + kind.value + "\x00" + external_ref).encode("utf-8")
    ).hexdigest()
    return "cmp_%s" % digest[:32]


def _risk(upsert: ComponentUpsert, version: int) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    if not upsert.owner_ref:
        score += 25
        reasons.append("OWNER_MISSING")
    if upsert.status == ComponentStatus.UNMANAGED:
        score += 20
        reasons.append("UNMANAGED_DISCOVERY")
    if upsert.criticality in {Severity.HIGH, Severity.CRITICAL}:
        score += 10
        reasons.append("HIGH_CRITICALITY")
    unapproved = [item for item in upsert.permissions if not item.approved]
    if unapproved:
        score += min(35, 10 + len(unapproved) * 5)
        reasons.append("UNAPPROVED_PERMISSIONS")
    effectful = {
        item.operation
        for item in upsert.permissions
        if any(token in item.operation.lower() for token in ("admin", "delete", "write", "send", "upload"))
    }
    if effectful:
        score += 10
        reasons.append("EFFECTFUL_PERMISSION")
    if version > 1:
        score += min(10, version - 1)
        reasons.append("CONFIGURATION_CHANGED")
    return min(100, score), reasons


class InventoryService:
    """Transactional local inventory with discovery, history, and risk rollups."""

    def __init__(
        self,
        path: str,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.path = path
        self.clock = clock
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
        self._migrate()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("inventory clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    def _migrate(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS inventory_components (
                tenant_id TEXT NOT NULL,
                component_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                external_ref TEXT NOT NULL,
                application_id TEXT,
                owner_ref TEXT,
                criticality TEXT NOT NULL,
                status TEXT NOT NULL,
                source TEXT NOT NULL,
                permissions_json TEXT NOT NULL,
                configuration_json TEXT NOT NULL,
                configuration_digest TEXT NOT NULL,
                configuration_version INTEGER NOT NULL,
                tags_json TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_reasons_json TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, component_id),
                UNIQUE (tenant_id, kind, external_ref)
            );
            CREATE TABLE IF NOT EXISTS inventory_configuration_history (
                tenant_id TEXT NOT NULL,
                component_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                configuration_digest TEXT NOT NULL,
                previous_digest TEXT,
                configuration_json TEXT NOT NULL,
                changed_fields_json TEXT NOT NULL,
                source TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, component_id, version),
                FOREIGN KEY (tenant_id, component_id)
                    REFERENCES inventory_components(tenant_id, component_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS inventory_relationships (
                tenant_id TEXT NOT NULL,
                source_component_id TEXT NOT NULL,
                relationship TEXT NOT NULL,
                target_component_id TEXT NOT NULL,
                source_ref TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, source_component_id, relationship, target_component_id),
                FOREIGN KEY (tenant_id, source_component_id)
                    REFERENCES inventory_components(tenant_id, component_id) ON DELETE CASCADE,
                FOREIGN KEY (tenant_id, target_component_id)
                    REFERENCES inventory_components(tenant_id, component_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS inventory_observations (
                tenant_id TEXT NOT NULL,
                observation_id TEXT NOT NULL,
                observation_digest TEXT NOT NULL,
                source_ref TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, observation_id)
            );
            CREATE TABLE IF NOT EXISTS inventory_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                action TEXT NOT NULL,
                subject TEXT NOT NULL,
                occurred_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS inventory_components_filter
                ON inventory_components(tenant_id, kind, status, risk_score DESC);
            CREATE INDEX IF NOT EXISTS inventory_components_application
                ON inventory_components(tenant_id, application_id, kind);
            CREATE INDEX IF NOT EXISTS inventory_components_owner
                ON inventory_components(tenant_id, owner_ref, criticality);
            CREATE INDEX IF NOT EXISTS inventory_history_time
                ON inventory_configuration_history(tenant_id, component_id, version DESC);
            """
        )

    @staticmethod
    def _require(principal: InventoryPrincipal, permission: str) -> None:
        if permission not in principal.permissions:
            raise InventoryAuthorizationError("missing permission: %s" % permission)

    def _audit(self, principal: InventoryPrincipal, action: str, subject: str) -> None:
        self._connection.execute(
            "INSERT INTO inventory_audit(tenant_id, actor_id, action, subject, occurred_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (principal.tenant_id, principal.actor_id, action, subject[:512], self._now().isoformat()),
        )

    @staticmethod
    def _row_component(row: sqlite3.Row) -> InventoryComponent:
        return InventoryComponent(
            component_id=row["component_id"],
            tenant_id=row["tenant_id"],
            kind=row["kind"],
            name=row["name"],
            external_ref=row["external_ref"],
            application_id=row["application_id"],
            owner_ref=row["owner_ref"],
            criticality=row["criticality"],
            status=row["status"],
            source=row["source"],
            permissions=json.loads(row["permissions_json"]),
            configuration=json.loads(row["configuration_json"]),
            configuration_digest=row["configuration_digest"],
            configuration_version=row["configuration_version"],
            tags=set(json.loads(row["tags_json"])),
            risk_score=row["risk_score"],
            risk_reasons=json.loads(row["risk_reasons_json"]),
            first_seen_at=row["first_seen_at"],
            last_seen_at=row["last_seen_at"],
            updated_at=row["updated_at"],
        )

    def _upsert_in_transaction(
        self,
        principal: InventoryPrincipal,
        upsert: ComponentUpsert,
        *,
        trusted_governance: bool,
    ) -> Tuple[InventoryComponent, bool]:
        component_id = upsert.component_id or _stable_component_id(
            upsert.kind, principal.tenant_id, upsert.external_ref
        )
        existing = self._connection.execute(
            "SELECT * FROM inventory_components WHERE tenant_id = ? AND component_id = ?",
            (principal.tenant_id, component_id),
        ).fetchone()
        by_natural = self._connection.execute(
            "SELECT component_id FROM inventory_components WHERE tenant_id = ? AND kind = ? AND external_ref = ?",
            (principal.tenant_id, upsert.kind.value, upsert.external_ref),
        ).fetchone()
        if by_natural is not None and by_natural["component_id"] != component_id:
            raise ValueError("inventory external identity already belongs to another component")
        if existing is not None and (
            existing["kind"] != upsert.kind.value or existing["external_ref"] != upsert.external_ref
        ):
            raise ValueError("inventory component identity cannot change kind or external reference")

        configuration = dict(upsert.configuration)
        digest = _digest(configuration)
        previous_configuration = json.loads(existing["configuration_json"]) if existing else {}
        changed = sorted(
            key
            for key in set(previous_configuration) | set(configuration)
            if previous_configuration.get(key) != configuration.get(key)
        )
        revision_created = existing is None or existing["configuration_digest"] != digest
        version = 1 if existing is None else int(existing["configuration_version"])
        if existing is not None and revision_created:
            version += 1

        if existing is not None and not trusted_governance:
            owner_ref = existing["owner_ref"]
            criticality = Severity(existing["criticality"])
            if existing["status"] == ComponentStatus.RETIRED.value:
                status = ComponentStatus.RETIRED
            else:
                status = ComponentStatus(existing["status"])
            current_permissions = [
                ComponentPermission.model_validate(item)
                for item in json.loads(existing["permissions_json"])
            ]
            merged_permissions = {
                (item.operation, item.resource_scope, item.effect.value): item
                for item in [*current_permissions, *upsert.permissions]
            }
            permissions = list(merged_permissions.values())
        else:
            owner_ref = upsert.owner_ref
            criticality = upsert.criticality
            status = upsert.status
            permissions = upsert.permissions
        effective = upsert.model_copy(
            update={
                "component_id": component_id,
                "owner_ref": owner_ref,
                "criticality": criticality,
                "status": status,
                "permissions": permissions,
            }
        )
        risk_score, risk_reasons = _risk(effective, version)
        now = self._now()
        first_seen = existing["first_seen_at"] if existing else upsert.observed_at.astimezone(timezone.utc).isoformat()
        last_seen = max(
            upsert.observed_at.astimezone(timezone.utc),
            datetime.fromisoformat(existing["last_seen_at"]) if existing else upsert.observed_at.astimezone(timezone.utc),
        ).isoformat()
        source = (
            existing["source"]
            if existing and existing["source"] == InventorySource.DECLARED.value and not trusted_governance
            else upsert.source.value
        )
        values = (
            principal.tenant_id,
            component_id,
            upsert.kind.value,
            upsert.name,
            upsert.external_ref,
            upsert.application_id,
            owner_ref,
            criticality.value,
            status.value,
            source,
            json.dumps([item.model_dump(mode="json") for item in permissions], sort_keys=True),
            json.dumps(configuration, sort_keys=True, separators=(",", ":")),
            digest,
            version,
            json.dumps(sorted(upsert.tags)),
            risk_score,
            json.dumps(risk_reasons),
            first_seen,
            last_seen,
            now.isoformat(),
        )
        self._connection.execute(
            "INSERT INTO inventory_components(tenant_id, component_id, kind, name, external_ref, "
            "application_id, owner_ref, criticality, status, source, permissions_json, "
            "configuration_json, configuration_digest, configuration_version, tags_json, risk_score, "
            "risk_reasons_json, first_seen_at, last_seen_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(tenant_id, component_id) DO UPDATE SET name=excluded.name, "
            "application_id=COALESCE(excluded.application_id, inventory_components.application_id), "
            "owner_ref=excluded.owner_ref, criticality=excluded.criticality, status=excluded.status, "
            "source=excluded.source, permissions_json=excluded.permissions_json, "
            "configuration_json=excluded.configuration_json, configuration_digest=excluded.configuration_digest, "
            "configuration_version=excluded.configuration_version, tags_json=excluded.tags_json, "
            "risk_score=excluded.risk_score, risk_reasons_json=excluded.risk_reasons_json, "
            "last_seen_at=excluded.last_seen_at, updated_at=excluded.updated_at",
            values,
        )
        if revision_created:
            self._connection.execute(
                "INSERT INTO inventory_configuration_history(tenant_id, component_id, version, "
                "configuration_digest, previous_digest, configuration_json, changed_fields_json, "
                "source, observed_at, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    principal.tenant_id,
                    component_id,
                    version,
                    digest,
                    existing["configuration_digest"] if existing else None,
                    json.dumps(configuration, sort_keys=True, separators=(",", ":")),
                    json.dumps(changed),
                    upsert.source.value,
                    upsert.observed_at.astimezone(timezone.utc).isoformat(),
                    now.isoformat(),
                ),
            )
        row = self._connection.execute(
            "SELECT * FROM inventory_components WHERE tenant_id = ? AND component_id = ?",
            (principal.tenant_id, component_id),
        ).fetchone()
        return self._row_component(row), revision_created

    def upsert_component(
        self, principal: InventoryPrincipal, upsert: ComponentUpsert
    ) -> InventoryComponent:
        self._require(principal, INVENTORY_WRITE)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                component, _ = self._upsert_in_transaction(
                    principal, upsert, trusted_governance=True
                )
                self._audit(principal, "component.upsert", component.component_id)
                self._connection.execute("COMMIT")
                return component
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def _relationship_in_transaction(
        self,
        principal: InventoryPrincipal,
        source_id: str,
        relationship: RelationshipType,
        target_id: str,
        source_ref: str,
        observed_at: datetime,
    ) -> None:
        if source_id == target_id:
            raise ValueError("inventory relationship cannot point to itself")
        for component_id in (source_id, target_id):
            exists = self._connection.execute(
                "SELECT 1 FROM inventory_components WHERE tenant_id = ? AND component_id = ?",
                (principal.tenant_id, component_id),
            ).fetchone()
            if exists is None:
                raise ValueError("inventory relationship component does not exist")
        timestamp = observed_at.astimezone(timezone.utc).isoformat()
        self._connection.execute(
            "INSERT INTO inventory_relationships(tenant_id, source_component_id, relationship, "
            "target_component_id, source_ref, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(tenant_id, source_component_id, relationship, target_component_id) "
            "DO UPDATE SET source_ref=excluded.source_ref, last_seen_at=MAX(last_seen_at, excluded.last_seen_at)",
            (
                principal.tenant_id, source_id, relationship.value, target_id,
                source_ref, timestamp, timestamp,
            ),
        )

    def discover(
        self, principal: InventoryPrincipal, observation: InventoryObservation
    ) -> DiscoveryResult:
        self._require(principal, INVENTORY_DISCOVER)
        if observation.tenant_id != principal.tenant_id:
            raise InventoryAuthorizationError("cross-tenant discovery is forbidden")
        encoded = json.dumps(
            observation.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                previous = self._connection.execute(
                    "SELECT observation_digest, recorded_at FROM inventory_observations "
                    "WHERE tenant_id = ? AND observation_id = ?",
                    (principal.tenant_id, observation.observation_id),
                ).fetchone()
                if previous is not None:
                    if previous["observation_digest"] != digest:
                        raise ValueError("inventory observation ID was reused with different content")
                    self._connection.execute("COMMIT")
                    components = self._component_ids_for_observation(principal, observation)
                    return DiscoveryResult(
                        observation_id=observation.observation_id,
                        duplicate=True,
                        component_ids=components,
                        relationship_count=max(0, len(components) - 1),
                        configuration_revisions=0,
                        recorded_at=previous["recorded_at"],
                    )
                result = self._apply_observation(principal, observation)
                recorded = self._now()
                self._connection.execute(
                    "INSERT INTO inventory_observations(tenant_id, observation_id, observation_digest, "
                    "source_ref, observed_at, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        principal.tenant_id, observation.observation_id, digest,
                        observation.source_ref, observation.observed_at.astimezone(timezone.utc).isoformat(),
                        recorded.isoformat(),
                    ),
                )
                self._audit(principal, "discovery.observe", observation.observation_id)
                self._connection.execute("COMMIT")
                return DiscoveryResult(
                    observation_id=observation.observation_id,
                    duplicate=False,
                    component_ids=result[0],
                    relationship_count=result[1],
                    configuration_revisions=result[2],
                    recorded_at=recorded,
                )
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _component_ids_for_observation(
        principal: InventoryPrincipal, observation: InventoryObservation
    ) -> List[str]:
        identities = [
            (ComponentKind.APPLICATION, "application://%s" % observation.application_external_id),
            (ComponentKind.AGENT, "agent://%s" % observation.agent_external_id),
        ]
        if observation.model_id:
            identities.append(
                (
                    ComponentKind.MODEL,
                    "model://%s/%s" % (observation.model_provider, observation.model_id),
                )
            )
        if observation.tool_name:
            identities.append((ComponentKind.TOOL, "tool://%s" % observation.tool_name))
        return [
            _stable_component_id(kind, principal.tenant_id, external_ref)
            for kind, external_ref in identities
        ]

    def _apply_observation(
        self, principal: InventoryPrincipal, observation: InventoryObservation
    ) -> Tuple[List[str], int, int]:
        application_ref = "application://%s" % observation.application_external_id
        agent_ref = "agent://%s" % observation.agent_external_id
        application_id = _stable_component_id(
            ComponentKind.APPLICATION, principal.tenant_id, application_ref
        )
        agent_id = _stable_component_id(ComponentKind.AGENT, principal.tenant_id, agent_ref)
        components: List[ComponentUpsert] = [
            ComponentUpsert(
                component_id=application_id,
                kind=ComponentKind.APPLICATION,
                name=observation.application_name or observation.application_external_id,
                external_ref=application_ref,
                status=ComponentStatus.UNMANAGED,
                source=InventorySource.OBSERVED,
                configuration={
                    "environment": observation.environment,
                    "source_type": observation.source_type,
                },
                observed_at=observation.observed_at,
            ),
            ComponentUpsert(
                component_id=agent_id,
                kind=ComponentKind.AGENT,
                name=observation.agent_name or observation.agent_external_id,
                external_ref=agent_ref,
                application_id=application_id,
                status=ComponentStatus.UNMANAGED,
                source=InventorySource.OBSERVED,
                permissions=(
                    [
                        ComponentPermission(
                            operation=observation.operation,
                            resource_scope=observation.resource_scope or "resource://unknown",
                            approved=False,
                            source_ref=observation.source_ref,
                        )
                    ]
                    if observation.operation
                    else []
                ),
                configuration={
                    "environment": observation.environment,
                    "source_type": observation.source_type,
                },
                observed_at=observation.observed_at,
            ),
        ]
        relationships: List[Tuple[str, RelationshipType, str]] = [
            (application_id, RelationshipType.CONTAINS, agent_id)
        ]
        if observation.model_id:
            model_ref = "model://%s/%s" % (
                observation.model_provider,
                observation.model_id,
            )
            model_component_id = _stable_component_id(
                ComponentKind.MODEL, principal.tenant_id, model_ref
            )
            components.append(
                ComponentUpsert(
                    component_id=model_component_id,
                    kind=ComponentKind.MODEL,
                    name=observation.model_profile_id or observation.model_id,
                    external_ref=model_ref,
                    application_id=application_id,
                    status=ComponentStatus.UNMANAGED,
                    source=InventorySource.OBSERVED,
                    configuration={
                        "provider": observation.model_provider,
                        "model_id": observation.model_id,
                        "environment": observation.environment,
                    },
                    observed_at=observation.observed_at,
                )
            )
            relationships.append((agent_id, RelationshipType.USES_MODEL, model_component_id))
        if observation.tool_name:
            tool_ref = "tool://%s" % observation.tool_name
            tool_id = _stable_component_id(ComponentKind.TOOL, principal.tenant_id, tool_ref)
            configuration: Dict[str, Any] = {"environment": observation.environment}
            if observation.tool_schema_digest:
                configuration["schema_digest"] = observation.tool_schema_digest
            components.append(
                ComponentUpsert(
                    component_id=tool_id,
                    kind=ComponentKind.TOOL,
                    name=observation.tool_name,
                    external_ref=tool_ref,
                    application_id=application_id,
                    status=ComponentStatus.UNMANAGED,
                    source=InventorySource.OBSERVED,
                    permissions=(
                        [
                            ComponentPermission(
                                operation=observation.operation,
                                resource_scope=observation.resource_scope or "resource://unknown",
                                approved=False,
                                source_ref=observation.source_ref,
                            )
                        ]
                        if observation.operation
                        else []
                    ),
                    configuration=configuration,
                    observed_at=observation.observed_at,
                )
            )
            relationships.append((agent_id, RelationshipType.USES_TOOL, tool_id))
        component_ids: List[str] = []
        revisions = 0
        for component in components:
            persisted, created = self._upsert_in_transaction(
                principal, component, trusted_governance=False
            )
            component_ids.append(persisted.component_id)
            revisions += int(created)
        for source_id, relationship, target_id in relationships:
            self._relationship_in_transaction(
                principal,
                source_id,
                relationship,
                target_id,
                observation.source_ref,
                observation.observed_at,
            )
        return component_ids, len(relationships), revisions

    def observe_telemetry(
        self, principal: InventoryPrincipal, envelope: TelemetryEnvelope
    ) -> DiscoveryResult:
        return self.discover(
            principal,
            InventoryObservation(
                observation_id="iobs_%s" % envelope.event_id,
                tenant_id=envelope.context.tenant_id,
                source_ref=envelope.context.source_id,
                source_type=envelope.context.source_type,
                observed_at=envelope.observed_at,
                application_external_id=envelope.context.application_id,
                agent_external_id=envelope.context.agent_id,
                environment=envelope.context.environment,
                model_provider=envelope.context.provider,
                model_id=envelope.context.model_id,
                tool_name=envelope.tool_name,
                operation=envelope.operation,
                resource_scope=envelope.resource or envelope.destination,
            ),
        )

    def observe_agent_event(
        self,
        principal: InventoryPrincipal,
        event: AgentEvent,
        *,
        application_id: str = "authorization-service",
    ) -> DiscoveryResult:
        return self.discover(
            principal,
            InventoryObservation(
                observation_id="iobs_%s" % event.event_id,
                tenant_id=event.tenant_id,
                source_ref=event.source_id,
                source_type=event.source_type,
                observed_at=event.occurred_at,
                application_external_id=application_id,
                agent_external_id=event.agent_id,
                tool_name=event.tool_name,
                tool_schema_digest=event.observed_tool_schema_digest,
                operation=event.operation,
                resource_scope=event.resource,
            ),
        )

    def import_abom(
        self,
        principal: InventoryPrincipal,
        manifest: AbomManifest,
        signer: PocHmacSigner,
        *,
        application_external_id: str,
    ) -> List[InventoryComponent]:
        self._require(principal, INVENTORY_WRITE)
        if manifest.tenant_id != principal.tenant_id:
            raise InventoryAuthorizationError("cross-tenant ABOM import is forbidden")
        if not signer.verify(manifest.unsigned_payload(), manifest.signature):
            raise ValueError("ABOM signature is invalid")
        application_ref = "application://%s" % application_external_id
        application_id = _stable_component_id(
            ComponentKind.APPLICATION, principal.tenant_id, application_ref
        )
        components = [
            ComponentUpsert(
                component_id=application_id,
                kind=ComponentKind.APPLICATION,
                name=application_external_id,
                external_ref=application_ref,
                owner_ref=manifest.owner_id,
                source=InventorySource.DECLARED,
                configuration={"policy_bundle_digest": manifest.policy_bundle_digest},
                observed_at=manifest.created_at,
            ),
            ComponentUpsert(
                kind=ComponentKind.AGENT,
                name=manifest.agent_id,
                external_ref="agent://%s" % manifest.agent_id,
                application_id=application_id,
                owner_ref=manifest.owner_id,
                source=InventorySource.DECLARED,
                permissions=[
                    ComponentPermission(
                        operation=tool.operation,
                        resource_scope=(
                            sorted(tool.allowed_destinations)[0]
                            if tool.allowed_destinations
                            else "resource://declared"
                        ),
                        approved=True,
                        source_ref="abom://%s" % manifest.manifest_id,
                    )
                    for tool in manifest.tools
                ],
                configuration={
                    "build_digest": manifest.build_digest,
                    "system_instruction_digest": manifest.system_instruction_digest,
                    "policy_bundle_digest": manifest.policy_bundle_digest,
                },
                observed_at=manifest.created_at,
            ),
        ]
        for tool in manifest.tools:
            components.append(
                ComponentUpsert(
                    kind=ComponentKind.TOOL,
                    name=tool.tool_name,
                    external_ref="tool://%s" % tool.tool_name,
                    application_id=application_id,
                    owner_ref=manifest.owner_id,
                    source=InventorySource.DECLARED,
                    permissions=[
                        ComponentPermission(
                            operation=tool.operation,
                            resource_scope=destination,
                            approved=True,
                            source_ref="abom://%s" % manifest.manifest_id,
                        )
                        for destination in sorted(tool.allowed_destinations)
                    ],
                    configuration={"schema_digest": tool.schema_digest},
                    observed_at=manifest.created_at,
                )
            )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                persisted = [
                    self._upsert_in_transaction(
                        principal, item, trusted_governance=True
                    )[0]
                    for item in components
                ]
                agent = persisted[1]
                self._relationship_in_transaction(
                    principal,
                    application_id,
                    RelationshipType.CONTAINS,
                    agent.component_id,
                    "abom://%s" % manifest.manifest_id,
                    manifest.created_at,
                )
                for tool in persisted[2:]:
                    self._relationship_in_transaction(
                        principal,
                        agent.component_id,
                        RelationshipType.USES_TOOL,
                        tool.component_id,
                        "abom://%s" % manifest.manifest_id,
                        manifest.created_at,
                    )
                self._audit(principal, "abom.import", manifest.manifest_id)
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return persisted

    def import_model_registry(
        self,
        principal: InventoryPrincipal,
        registry: ModelRegistry,
        *,
        application_external_id: str = "agentsec-model-gateway",
    ) -> List[InventoryComponent]:
        self._require(principal, INVENTORY_WRITE)
        application_upsert = ComponentUpsert(
                kind=ComponentKind.APPLICATION,
                name=application_external_id,
                external_ref="application://%s" % application_external_id,
                owner_ref="team://ai-security",
                source=InventorySource.IMPORTED,
                configuration={"source_type": "model_registry"},
            )
        application_id = _stable_component_id(
            ComponentKind.APPLICATION,
            principal.tenant_id,
            application_upsert.external_ref,
        )
        model_upserts: List[ComponentUpsert] = []
        for profile in registry.profiles:
            model_upserts.append(
                ComponentUpsert(
                    kind=ComponentKind.MODEL,
                    name=profile.profile_id,
                    external_ref="model-profile://%s" % profile.profile_id,
                    application_id=application_id,
                    owner_ref="team://ai-security",
                    source=InventorySource.IMPORTED,
                    configuration={
                        "provider": profile.provider,
                        "enabled": profile.enabled,
                        "prompt_version": profile.prompt_version,
                    },
                )
            )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                application = self._upsert_in_transaction(
                    principal,
                    application_upsert.model_copy(update={"component_id": application_id}),
                    trusted_governance=True,
                )[0]
                persisted = [application]
                for upsert in model_upserts:
                    component = self._upsert_in_transaction(
                        principal, upsert, trusted_governance=True
                    )[0]
                    persisted.append(component)
                    self._relationship_in_transaction(
                        principal,
                        application.component_id,
                        RelationshipType.USES_MODEL,
                        component.component_id,
                        "model-registry://%s" % registry.schema_version,
                        self._now(),
                    )
                self._audit(principal, "model_registry.import", registry.schema_version)
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return persisted

    def get_component(
        self, principal: InventoryPrincipal, component_id: str
    ) -> InventoryComponent:
        self._require(principal, INVENTORY_READ)
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM inventory_components WHERE tenant_id = ? AND component_id = ?",
                (principal.tenant_id, component_id),
            ).fetchone()
        if row is None:
            raise KeyError(component_id)
        return self._row_component(row)

    def list_components(
        self,
        principal: InventoryPrincipal,
        *,
        kind: Optional[ComponentKind] = None,
        status: Optional[ComponentStatus] = None,
        owner_ref: Optional[str] = None,
        application_id: Optional[str] = None,
        minimum_risk: int = 0,
        limit: int = 100,
        offset: int = 0,
    ) -> InventoryPage:
        self._require(principal, INVENTORY_READ)
        if not 1 <= limit <= MAX_INVENTORY_PAGE or not 0 <= offset <= MAX_INVENTORY_OFFSET:
            raise ValueError("inventory pagination is invalid")
        if not 0 <= minimum_risk <= 100:
            raise ValueError("minimum inventory risk is invalid")
        clauses = ["tenant_id = ?", "risk_score >= ?"]
        values: List[Any] = [principal.tenant_id, minimum_risk]
        for column, value in (
            ("kind", kind.value if kind else None),
            ("status", status.value if status else None),
            ("owner_ref", owner_ref),
            ("application_id", application_id),
        ):
            if value is not None:
                clauses.append("%s = ?" % column)
                values.append(value)
        where = " AND ".join(clauses)
        with self._lock:
            total = self._connection.execute(
                "SELECT COUNT(*) AS total FROM inventory_components WHERE " + where,
                tuple(values),
            ).fetchone()["total"]
            rows = self._connection.execute(
                "SELECT * FROM inventory_components WHERE " + where
                + " ORDER BY risk_score DESC, kind, name, component_id LIMIT ? OFFSET ?",
                (*values, limit, offset),
            ).fetchall()
            self._audit(principal, "component.list", "filters")
        return InventoryPage(
            components=[self._row_component(row) for row in rows],
            total=total,
            limit=limit,
            offset=offset,
        )

    def configuration_history(
        self, principal: InventoryPrincipal, component_id: str
    ) -> List[ConfigurationRevision]:
        self._require(principal, INVENTORY_READ)
        self.get_component(principal, component_id)
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM inventory_configuration_history WHERE tenant_id = ? "
                "AND component_id = ? ORDER BY version",
                (principal.tenant_id, component_id),
            ).fetchall()
        return [
            ConfigurationRevision(
                component_id=row["component_id"],
                tenant_id=row["tenant_id"],
                version=row["version"],
                configuration_digest=row["configuration_digest"],
                previous_digest=row["previous_digest"],
                configuration=json.loads(row["configuration_json"]),
                changed_fields=json.loads(row["changed_fields_json"]),
                source=row["source"],
                observed_at=row["observed_at"],
                recorded_at=row["recorded_at"],
            )
            for row in rows
        ]

    def relationships(
        self, principal: InventoryPrincipal, component_id: str
    ) -> List[InventoryRelationship]:
        self._require(principal, INVENTORY_READ)
        self.get_component(principal, component_id)
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM inventory_relationships WHERE tenant_id = ? AND "
                "(source_component_id = ? OR target_component_id = ?) "
                "ORDER BY relationship, source_component_id, target_component_id",
                (principal.tenant_id, component_id, component_id),
            ).fetchall()
        return [InventoryRelationship(**dict(row)) for row in rows]

    def all_relationships(
        self, principal: InventoryPrincipal, *, limit: int = 50000
    ) -> List[InventoryRelationship]:
        """Return a bounded tenant topology export for the security graph."""

        self._require(principal, INVENTORY_READ)
        if not 1 <= limit <= 50000:
            raise ValueError("inventory relationship export limit is invalid")
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM inventory_relationships WHERE tenant_id = ? "
                "ORDER BY relationship, source_component_id, target_component_id LIMIT ?",
                (principal.tenant_id, limit + 1),
            ).fetchall()
            self._audit(principal, "relationship.export", str(limit))
        if len(rows) > limit:
            raise ValueError("inventory relationship export exceeds the safety limit")
        return [InventoryRelationship(**dict(row)) for row in rows]

    def risk_rollup(
        self, principal: InventoryPrincipal, component_id: str
    ) -> InventoryRiskRollup:
        self._require(principal, INVENTORY_READ)
        root = self.get_component(principal, component_id)
        with self._lock:
            if root.kind == ComponentKind.APPLICATION:
                rows = self._connection.execute(
                    "SELECT * FROM inventory_components WHERE tenant_id = ? AND "
                    "(component_id = ? OR application_id = ?)",
                    (principal.tenant_id, component_id, component_id),
                ).fetchall()
            else:
                rows = self._connection.execute(
                    "SELECT * FROM inventory_components WHERE tenant_id = ? AND component_id = ?",
                    (principal.tenant_id, component_id),
                ).fetchall()
        components = [self._row_component(row) for row in rows]
        unapproved = sum(
            not permission.approved
            for component in components
            for permission in component.permissions
        )
        reasons = sorted(
            set(reason for component in components for reason in component.risk_reasons)
        )
        return InventoryRiskRollup(
            component_id=component_id,
            tenant_id=principal.tenant_id,
            score=max(component.risk_score for component in components),
            component_count=len(components),
            high_risk_components=sum(component.risk_score >= 60 for component in components),
            unowned_components=sum(component.owner_ref is None for component in components),
            unapproved_permissions=unapproved,
            reasons=reasons,
            calculated_at=self._now(),
        )

    def summary(self, principal: InventoryPrincipal) -> InventorySummary:
        self._require(principal, INVENTORY_READ)
        with self._lock:
            rows = self._connection.execute(
                "SELECT kind, status, owner_ref, risk_score FROM inventory_components WHERE tenant_id = ?",
                (principal.tenant_id,),
            ).fetchall()
        by_kind = {kind: 0 for kind in ComponentKind}
        for row in rows:
            by_kind[ComponentKind(row["kind"])] += 1
        return InventorySummary(
            tenant_id=principal.tenant_id,
            total_components=len(rows),
            by_kind=by_kind,
            active_components=sum(row["status"] == ComponentStatus.ACTIVE.value for row in rows),
            unmanaged_components=sum(row["status"] == ComponentStatus.UNMANAGED.value for row in rows),
            unowned_components=sum(row["owner_ref"] is None for row in rows),
            high_risk_components=sum(row["risk_score"] >= 60 for row in rows),
            maximum_risk_score=max((row["risk_score"] for row in rows), default=0),
            calculated_at=self._now(),
        )

    def set_governance(
        self,
        principal: InventoryPrincipal,
        component_id: str,
        *,
        owner_ref: Optional[str],
        criticality: Severity,
        status: ComponentStatus,
    ) -> InventoryComponent:
        self._require(principal, INVENTORY_ADMIN)
        current = self.get_component(
            principal.model_copy(update={"permissions": principal.permissions | {INVENTORY_READ}}),
            component_id,
        )
        upsert = ComponentUpsert(
            component_id=current.component_id,
            kind=current.kind,
            name=current.name,
            external_ref=current.external_ref,
            application_id=current.application_id,
            owner_ref=owner_ref,
            criticality=criticality,
            status=status,
            source=current.source,
            permissions=current.permissions,
            configuration=current.configuration,
            tags=current.tags,
            observed_at=current.last_seen_at,
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                component, _ = self._upsert_in_transaction(
                    principal, upsert, trusted_governance=True
                )
                self._audit(principal, "component.governance", component_id)
                self._connection.execute("COMMIT")
                return component
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def detail(
        self, principal: InventoryPrincipal, component_id: str
    ) -> InventoryDetail:
        return InventoryDetail(
            component=self.get_component(principal, component_id),
            configuration_history=self.configuration_history(principal, component_id),
            relationships=self.relationships(principal, component_id),
            risk_rollup=self.risk_rollup(principal, component_id),
        )


__all__ = [
    "ComponentKind",
    "ComponentPermission",
    "ComponentStatus",
    "ComponentUpsert",
    "ConfigurationRevision",
    "DiscoveryResult",
    "INVENTORY_ADMIN",
    "INVENTORY_DISCOVER",
    "INVENTORY_READ",
    "INVENTORY_WRITE",
    "InventoryAuthorizationError",
    "InventoryComponent",
    "InventoryDetail",
    "InventoryObservation",
    "InventoryPage",
    "InventoryPrincipal",
    "InventoryRelationship",
    "InventoryRiskRollup",
    "InventoryService",
    "InventorySource",
    "InventorySummary",
    "PermissionEffect",
    "RelationshipType",
]
