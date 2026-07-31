"""Versioned AI security posture checks, findings, exceptions, and trends."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import re
import sqlite3
import threading
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from pydantic import Field, field_validator, model_validator

from .contracts import Severity, StrictModel, new_id, utc_now
from .inventory import ComponentKind, ComponentStatus, InventoryComponent


POSTURE_READ = "posture:read"
POSTURE_SCAN = "posture:scan"
POSTURE_ADMIN = "posture:admin"
MAX_POSTURE_PAGE = 200


class PostureAuthorizationError(PermissionError):
    """Raised when a posture principal lacks a required permission."""


class PostureEvaluator(str, Enum):
    OWNER_REQUIRED = "owner_required"
    MANAGED_STATUS_REQUIRED = "managed_status_required"
    NO_UNAPPROVED_PERMISSIONS = "no_unapproved_permissions"
    EFFECTFUL_PERMISSION_REVIEW = "effectful_permission_review"
    TOOL_SCHEMA_REQUIRED = "tool_schema_required"
    MODEL_PROMPT_VERSION_REQUIRED = "model_prompt_version_required"
    AGENT_POLICY_BINDING_REQUIRED = "agent_policy_binding_required"
    MAX_COMPONENT_RISK = "max_component_risk"


class PostureFindingStatus(str, Enum):
    OPEN = "open"
    ACCEPTED_EXCEPTION = "accepted_exception"
    RESOLVED = "resolved"


class PostureExceptionStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class PosturePrincipal(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=1, max_length=256)
    permissions: Set[str] = Field(default_factory=set, max_length=16)

    @field_validator("permissions")
    @classmethod
    def valid_permissions(cls, value: Set[str]) -> Set[str]:
        if any(re.fullmatch(r"[a-z]+:[a-z]+", item) is None for item in value):
            raise ValueError("posture permissions must use namespace:operation")
        return value


class PostureCheckDefinition(StrictModel):
    check_id: str = Field(pattern=r"^PST-[A-Z0-9-]{3,64}$")
    version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    title: str = Field(min_length=3, max_length=256)
    description: str = Field(min_length=3, max_length=1024)
    evaluator: PostureEvaluator
    severity: Severity
    applicable_kinds: Set[ComponentKind] = Field(min_length=1, max_length=5)
    parameters: Dict[str, int] = Field(default_factory=dict, max_length=8)
    remediation: List[str] = Field(min_length=1, max_length=16)
    framework_mappings: List[str] = Field(default_factory=list, max_length=32)
    enabled: bool = True

    @field_validator("remediation", "framework_mappings")
    @classmethod
    def bounded_strings(cls, value: List[str]) -> List[str]:
        if any(not 1 <= len(item) <= 512 for item in value):
            raise ValueError("posture check text is invalid")
        return value

    @model_validator(mode="after")
    def validate_parameters(self) -> "PostureCheckDefinition":
        allowed = {"maximum"} if self.evaluator == PostureEvaluator.MAX_COMPONENT_RISK else set()
        if set(self.parameters) != allowed:
            raise ValueError("posture evaluator parameters are invalid")
        if "maximum" in self.parameters and not 0 <= self.parameters["maximum"] <= 100:
            raise ValueError("posture maximum risk is invalid")
        return self


class PostureCheckRecord(StrictModel):
    tenant_id: str
    check_id: str
    version: str
    title: str
    description: str
    evaluator: PostureEvaluator
    severity: Severity
    applicable_kinds: Set[ComponentKind]
    parameters: Dict[str, int]
    remediation: List[str]
    framework_mappings: List[str]
    enabled: bool
    definition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    superseded_at: Optional[datetime] = None


class PostureFinding(StrictModel):
    finding_id: str = Field(pattern=r"^pstf_[0-9a-f]{32}$")
    tenant_id: str
    check_id: str
    check_version: str
    component_id: str
    component_kind: ComponentKind
    component_name: str
    title: str
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    status: PostureFindingStatus
    evidence_refs: List[str]
    observed: Dict[str, str]
    remediation: List[str]
    framework_mappings: List[str]
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: Optional[datetime] = None
    active_exception_id: Optional[str] = None


class PostureException(StrictModel):
    exception_id: str = Field(pattern=r"^pste_[A-Za-z0-9]+$")
    tenant_id: str
    finding_id: str
    reason: str
    owner_ref: str
    approved_by: str
    status: PostureExceptionStatus
    created_at: datetime
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None
    revoke_reason: Optional[str] = None


class PostureFindingDetail(StrictModel):
    finding: PostureFinding
    exception: Optional[PostureException]
    check: PostureCheckRecord


class PostureFindingPage(StrictModel):
    findings: List[PostureFinding]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=MAX_POSTURE_PAGE)
    offset: int = Field(ge=0, le=100000)


class PostureScanResult(StrictModel):
    scan_id: str = Field(pattern=r"^psts_[A-Za-z0-9]+$")
    tenant_id: str
    check_count: int = Field(ge=0)
    component_count: int = Field(ge=0)
    evaluations: int = Field(ge=0)
    failing: int = Field(ge=0)
    passing: int = Field(ge=0)
    open_findings: int = Field(ge=0)
    accepted_exceptions: int = Field(ge=0)
    resolved_findings: int = Field(ge=0)
    posture_score: int = Field(ge=0, le=100)
    started_at: datetime
    completed_at: datetime


class PostureSummary(StrictModel):
    tenant_id: str
    enabled_checks: int = Field(ge=0)
    total_findings: int = Field(ge=0)
    open_findings: int = Field(ge=0)
    accepted_exceptions: int = Field(ge=0)
    resolved_findings: int = Field(ge=0)
    critical_open_findings: int = Field(ge=0)
    posture_score: int = Field(ge=0, le=100)
    latest_scan_at: Optional[datetime]
    calculated_at: datetime


class PostureTrendPoint(StrictModel):
    scan_id: str
    completed_at: datetime
    posture_score: int = Field(ge=0, le=100)
    failing: int = Field(ge=0)
    passing: int = Field(ge=0)
    open_findings: int = Field(ge=0)
    accepted_exceptions: int = Field(ge=0)


class PostureTrendSeries(StrictModel):
    tenant_id: str
    points: List[PostureTrendPoint]


DEFAULT_POSTURE_CHECKS: Tuple[PostureCheckDefinition, ...] = (
    PostureCheckDefinition(
        check_id="PST-OWNER-REQUIRED", version="2026.07.1",
        title="AI component must have an accountable owner",
        description="Every governed AI application and dependency needs an owner for risk acceptance and remediation.",
        evaluator=PostureEvaluator.OWNER_REQUIRED, severity=Severity.HIGH,
        applicable_kinds=set(ComponentKind),
        remediation=["Assign the component to an accountable team or service owner."],
        framework_mappings=["OWASP-LLM-GOVERNANCE", "NIST-AI-RMF-GOVERN"],
    ),
    PostureCheckDefinition(
        check_id="PST-MANAGED-STATUS", version="2026.07.1",
        title="Observed AI component must enter managed lifecycle",
        description="Unmanaged discoveries must be reviewed, owned, and explicitly activated or retired.",
        evaluator=PostureEvaluator.MANAGED_STATUS_REQUIRED, severity=Severity.MEDIUM,
        applicable_kinds=set(ComponentKind),
        remediation=["Review the discovery and set its lifecycle to active or retired."],
        framework_mappings=["NIST-AI-RMF-MAP"],
    ),
    PostureCheckDefinition(
        check_id="PST-PERMISSION-APPROVAL", version="2026.07.1",
        title="Agent and tool permissions must be approved",
        description="Observed effective permissions require explicit governance approval.",
        evaluator=PostureEvaluator.NO_UNAPPROVED_PERMISSIONS, severity=Severity.HIGH,
        applicable_kinds={ComponentKind.AGENT, ComponentKind.TOOL},
        remediation=["Review each observed operation and resource scope.", "Approve the least-privilege scope or remove the permission."],
        framework_mappings=["OWASP-LLM08", "MITRE-ATLAS-AML.T0051"],
    ),
    PostureCheckDefinition(
        check_id="PST-EFFECTFUL-REVIEW", version="2026.07.1",
        title="Effectful permissions require explicit approval",
        description="Write, delete, send, upload, isolate, admin, and revoke operations must not remain unapproved.",
        evaluator=PostureEvaluator.EFFECTFUL_PERMISSION_REVIEW, severity=Severity.CRITICAL,
        applicable_kinds={ComponentKind.AGENT, ComponentKind.TOOL},
        remediation=["Narrow the operation and resource scope.", "Require an exact approval gate before execution."],
        framework_mappings=["OWASP-LLM06", "OWASP-LLM08"],
    ),
    PostureCheckDefinition(
        check_id="PST-TOOL-SCHEMA", version="2026.07.1",
        title="Tool contract must have a pinned schema digest",
        description="Tool discovery must be bound to a reviewed schema digest to detect MCP or tool drift.",
        evaluator=PostureEvaluator.TOOL_SCHEMA_REQUIRED, severity=Severity.HIGH,
        applicable_kinds={ComponentKind.TOOL},
        remediation=["Generate and review the tool schema digest.", "Declare the digest in the signed ABOM."],
        framework_mappings=["OWASP-LLM03", "MITRE-ATLAS-AML.T0080"],
    ),
    PostureCheckDefinition(
        check_id="PST-MODEL-PROMPT-VERSION", version="2026.07.1",
        title="Model profile must pin a prompt version",
        description="Model profiles need a versioned prompt contract for reproducible review and rollback.",
        evaluator=PostureEvaluator.MODEL_PROMPT_VERSION_REQUIRED, severity=Severity.MEDIUM,
        applicable_kinds={ComponentKind.MODEL},
        remediation=["Assign a reviewed prompt version to the model profile."],
        framework_mappings=["NIST-AI-RMF-MEASURE"],
    ),
    PostureCheckDefinition(
        check_id="PST-AGENT-POLICY-BINDING", version="2026.07.1",
        title="Agent must bind a signed policy bundle",
        description="An agent build should declare the exact policy bundle evaluated at its effect boundary.",
        evaluator=PostureEvaluator.AGENT_POLICY_BINDING_REQUIRED, severity=Severity.HIGH,
        applicable_kinds={ComponentKind.AGENT},
        remediation=["Declare the policy bundle digest in the signed Agent Bill of Materials."],
        framework_mappings=["NIST-AI-RMF-MANAGE"],
    ),
    PostureCheckDefinition(
        check_id="PST-HIGH-RISK-REVIEW", version="2026.07.1",
        title="High-risk component requires remediation review",
        description="Inventory risk at or above the configured ceiling requires tracked remediation or accepted risk.",
        evaluator=PostureEvaluator.MAX_COMPONENT_RISK, severity=Severity.HIGH,
        applicable_kinds=set(ComponentKind), parameters={"maximum": 59},
        remediation=["Resolve the inventory risk reasons or create a time-bounded approved exception."],
        framework_mappings=["NIST-AI-RMF-MANAGE"],
    ),
)


def _definition_digest(item: PostureCheckDefinition) -> str:
    return hashlib.sha256(
        json.dumps(item.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _version_key(value: str) -> Tuple[Tuple[int, Any], ...]:
    """Compare human-readable check versions without lexical numeric mistakes."""
    return tuple(
        (0, int(token)) if token.isdigit() else (1, token.casefold())
        for token in re.findall(r"[0-9]+|[A-Za-z]+", value)
    )


def _finding_id(tenant_id: str, check_id: str, component_id: str) -> str:
    digest = hashlib.sha256((tenant_id + "\x00" + check_id + "\x00" + component_id).encode("utf-8")).hexdigest()
    return "pstf_%s" % digest[:32]


def _risk_score(severity: Severity, component_risk: int) -> int:
    base = {Severity.INFO: 10, Severity.LOW: 25, Severity.MEDIUM: 45, Severity.HIGH: 70, Severity.CRITICAL: 90}[severity]
    return min(100, base + component_risk // 10)


def _evaluate(
    check: PostureCheckRecord, component: InventoryComponent
) -> Optional[Dict[str, str]]:
    permissions = component.permissions
    if check.evaluator == PostureEvaluator.OWNER_REQUIRED:
        return {"owner": "missing"} if not component.owner_ref else None
    if check.evaluator == PostureEvaluator.MANAGED_STATUS_REQUIRED:
        return {"status": component.status.value} if component.status == ComponentStatus.UNMANAGED else None
    if check.evaluator == PostureEvaluator.NO_UNAPPROVED_PERMISSIONS:
        count = sum(not item.approved for item in permissions)
        return {"unapproved_permissions": str(count)} if count else None
    if check.evaluator == PostureEvaluator.EFFECTFUL_PERMISSION_REVIEW:
        effectful = [
            item for item in permissions
            if not item.approved and any(token in item.operation.lower() for token in (
                "admin", "delete", "write", "send", "upload", "isolate", "revoke"
            ))
        ]
        return {"unapproved_effectful_permissions": str(len(effectful))} if effectful else None
    if check.evaluator == PostureEvaluator.TOOL_SCHEMA_REQUIRED:
        return {"schema_digest": "missing"} if not component.configuration.get("schema_digest") else None
    if check.evaluator == PostureEvaluator.MODEL_PROMPT_VERSION_REQUIRED:
        return {"prompt_version": "missing"} if not component.configuration.get("prompt_version") else None
    if check.evaluator == PostureEvaluator.AGENT_POLICY_BINDING_REQUIRED:
        return {"policy_bundle_digest": "missing"} if not component.configuration.get("policy_bundle_digest") else None
    if check.evaluator == PostureEvaluator.MAX_COMPONENT_RISK:
        maximum = check.parameters["maximum"]
        return {"component_risk": str(component.risk_score), "maximum": str(maximum)} if component.risk_score > maximum else None
    raise ValueError("unsupported posture evaluator")


class PostureService:
    """Durable deterministic posture engine over privacy-safe inventory state."""

    def __init__(self, path: str, *, clock: Callable[[], datetime] = utc_now) -> None:
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
            raise ValueError("posture clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    def _migrate(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS posture_checks (
                tenant_id TEXT NOT NULL, check_id TEXT NOT NULL, version TEXT NOT NULL,
                definition_json TEXT NOT NULL, definition_sha256 TEXT NOT NULL,
                enabled INTEGER NOT NULL, created_at TEXT NOT NULL, superseded_at TEXT,
                PRIMARY KEY (tenant_id, check_id, version)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS posture_current_check
                ON posture_checks(tenant_id, check_id) WHERE superseded_at IS NULL;
            CREATE TABLE IF NOT EXISTS posture_findings (
                tenant_id TEXT NOT NULL, finding_id TEXT NOT NULL, check_id TEXT NOT NULL,
                check_version TEXT NOT NULL, component_id TEXT NOT NULL, component_kind TEXT NOT NULL,
                component_name TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
                risk_score INTEGER NOT NULL, status TEXT NOT NULL, evidence_refs_json TEXT NOT NULL,
                observed_json TEXT NOT NULL, remediation_json TEXT NOT NULL,
                framework_mappings_json TEXT NOT NULL, first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL, resolved_at TEXT, active_exception_id TEXT,
                PRIMARY KEY (tenant_id, finding_id),
                UNIQUE (tenant_id, check_id, component_id)
            );
            CREATE TABLE IF NOT EXISTS posture_exceptions (
                tenant_id TEXT NOT NULL, exception_id TEXT NOT NULL, finding_id TEXT NOT NULL,
                reason TEXT NOT NULL, owner_ref TEXT NOT NULL, approved_by TEXT NOT NULL,
                status TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                revoked_at TEXT, revoked_by TEXT, revoke_reason TEXT,
                PRIMARY KEY (tenant_id, exception_id)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS posture_active_exception
                ON posture_exceptions(tenant_id, finding_id) WHERE status = 'active';
            CREATE TABLE IF NOT EXISTS posture_scans (
                tenant_id TEXT NOT NULL, scan_id TEXT NOT NULL, check_count INTEGER NOT NULL,
                component_count INTEGER NOT NULL, evaluations INTEGER NOT NULL, failing INTEGER NOT NULL,
                passing INTEGER NOT NULL, open_findings INTEGER NOT NULL,
                accepted_exceptions INTEGER NOT NULL, resolved_findings INTEGER NOT NULL,
                posture_score INTEGER NOT NULL, started_at TEXT NOT NULL, completed_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, scan_id)
            );
            CREATE TABLE IF NOT EXISTS posture_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL,
                actor_id TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL,
                occurred_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS posture_finding_filter
                ON posture_findings(tenant_id, status, severity, risk_score DESC, last_seen_at DESC);
            CREATE INDEX IF NOT EXISTS posture_finding_component
                ON posture_findings(tenant_id, component_id, check_id);
            CREATE INDEX IF NOT EXISTS posture_scan_trend
                ON posture_scans(tenant_id, completed_at DESC);
            CREATE INDEX IF NOT EXISTS posture_exception_expiry
                ON posture_exceptions(tenant_id, status, expires_at);
            """
        )

    @staticmethod
    def _require(principal: PosturePrincipal, permission: str) -> None:
        if permission not in principal.permissions:
            raise PostureAuthorizationError("missing permission: %s" % permission)

    def _audit(self, principal: PosturePrincipal, action: str, subject: str) -> None:
        self._connection.execute(
            "INSERT INTO posture_audit(tenant_id, actor_id, action, subject, occurred_at) VALUES (?, ?, ?, ?, ?)",
            (principal.tenant_id, principal.actor_id, action, subject[:512], self._now().isoformat()),
        )

    @staticmethod
    def _check_row(row: sqlite3.Row) -> PostureCheckRecord:
        definition = PostureCheckDefinition.model_validate_json(row["definition_json"])
        return PostureCheckRecord(
            tenant_id=row["tenant_id"], **definition.model_dump(),
            definition_sha256=row["definition_sha256"], created_at=row["created_at"],
            superseded_at=row["superseded_at"],
        )

    @staticmethod
    def _finding_row(row: sqlite3.Row) -> PostureFinding:
        return PostureFinding(
            finding_id=row["finding_id"], tenant_id=row["tenant_id"], check_id=row["check_id"],
            check_version=row["check_version"], component_id=row["component_id"],
            component_kind=row["component_kind"], component_name=row["component_name"],
            title=row["title"], severity=row["severity"], risk_score=row["risk_score"],
            status=row["status"], evidence_refs=json.loads(row["evidence_refs_json"]),
            observed=json.loads(row["observed_json"]), remediation=json.loads(row["remediation_json"]),
            framework_mappings=json.loads(row["framework_mappings_json"]),
            first_seen_at=row["first_seen_at"], last_seen_at=row["last_seen_at"],
            resolved_at=row["resolved_at"], active_exception_id=row["active_exception_id"],
        )

    @staticmethod
    def _exception_row(row: sqlite3.Row) -> PostureException:
        return PostureException(**dict(row))

    def register_check(
        self, principal: PosturePrincipal, definition: PostureCheckDefinition
    ) -> PostureCheckRecord:
        self._require(principal, POSTURE_ADMIN)
        digest = _definition_digest(definition)
        now = self._now().isoformat()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                same = self._connection.execute(
                    "SELECT * FROM posture_checks WHERE tenant_id = ? AND check_id = ? AND version = ?",
                    (principal.tenant_id, definition.check_id, definition.version),
                ).fetchone()
                if same is not None:
                    if same["definition_sha256"] != digest:
                        raise ValueError("posture check version is immutable")
                    self._connection.execute("COMMIT")
                    return self._check_row(same)
                current = self._connection.execute(
                    "SELECT * FROM posture_checks WHERE tenant_id = ? AND check_id = ? AND superseded_at IS NULL",
                    (principal.tenant_id, definition.check_id),
                ).fetchone()
                if current is not None and _version_key(definition.version) <= _version_key(current["version"]):
                    raise ValueError("posture check version must increase")
                if current is not None:
                    self._connection.execute(
                        "UPDATE posture_checks SET superseded_at = ? WHERE tenant_id = ? AND check_id = ? AND superseded_at IS NULL",
                        (now, principal.tenant_id, definition.check_id),
                    )
                self._connection.execute(
                    "INSERT INTO posture_checks(tenant_id, check_id, version, definition_json, definition_sha256, enabled, created_at, superseded_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
                    (principal.tenant_id, definition.check_id, definition.version,
                     definition.model_dump_json(), digest, int(definition.enabled), now),
                )
                self._audit(principal, "posture.check.register", "%s:%s" % (definition.check_id, definition.version))
                row = self._connection.execute(
                    "SELECT * FROM posture_checks WHERE tenant_id = ? AND check_id = ? AND version = ?",
                    (principal.tenant_id, definition.check_id, definition.version),
                ).fetchone()
                self._connection.execute("COMMIT")
                return self._check_row(row)
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def install_defaults(self, principal: PosturePrincipal) -> List[PostureCheckRecord]:
        return [self.register_check(principal, item) for item in DEFAULT_POSTURE_CHECKS]

    def list_checks(self, principal: PosturePrincipal, *, history: bool = False) -> List[PostureCheckRecord]:
        self._require(principal, POSTURE_READ)
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM posture_checks WHERE tenant_id = ? "
                + ("" if history else "AND superseded_at IS NULL ")
                + "ORDER BY check_id, created_at DESC, version DESC",
                (principal.tenant_id,),
            ).fetchall()
            self._audit(principal, "posture.check.list", "history" if history else "current")
        records = [self._check_row(row) for row in rows]
        records.sort(key=lambda item: _version_key(item.version), reverse=True)
        records.sort(key=lambda item: item.check_id)
        return records

    def _expire_exceptions(self, principal: PosturePrincipal, at: datetime) -> None:
        encoded = at.isoformat()
        expired = self._connection.execute(
            "SELECT exception_id, finding_id FROM posture_exceptions WHERE tenant_id = ? AND status = 'active' AND expires_at <= ?",
            (principal.tenant_id, encoded),
        ).fetchall()
        for row in expired:
            self._connection.execute(
                "UPDATE posture_exceptions SET status = 'expired' WHERE tenant_id = ? AND exception_id = ?",
                (principal.tenant_id, row["exception_id"]),
            )
            self._connection.execute(
                "UPDATE posture_findings SET status = CASE WHEN resolved_at IS NULL THEN 'open' ELSE 'resolved' END, active_exception_id = NULL WHERE tenant_id = ? AND finding_id = ?",
                (principal.tenant_id, row["finding_id"]),
            )
            self._audit(principal, "posture.exception.expire", row["exception_id"])

    def scan(
        self,
        principal: PosturePrincipal,
        components: Sequence[InventoryComponent],
        *,
        check_ids: Optional[Sequence[str]] = None,
    ) -> PostureScanResult:
        self._require(principal, POSTURE_SCAN)
        if any(item.tenant_id != principal.tenant_id for item in components):
            raise PostureAuthorizationError("cross-tenant posture scan is forbidden")
        if len(components) > 10000:
            raise ValueError("posture scan component limit exceeded")
        selected_ids = set(check_ids or [])
        if len(selected_ids) > 256 or any(re.fullmatch(r"PST-[A-Z0-9-]{3,64}", item) is None for item in selected_ids):
            raise ValueError("posture scan check selection is invalid")
        started = self._now()
        scan_id = new_id("psts")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._expire_exceptions(principal, started)
                rows = self._connection.execute(
                    "SELECT * FROM posture_checks WHERE tenant_id = ? AND superseded_at IS NULL AND enabled = 1 ORDER BY check_id",
                    (principal.tenant_id,),
                ).fetchall()
                checks = [self._check_row(row) for row in rows]
                if selected_ids:
                    checks = [item for item in checks if item.check_id in selected_ids]
                    if {item.check_id for item in checks} != selected_ids:
                        raise KeyError("unknown or disabled posture check")
                if not checks:
                    raise ValueError("posture scan has no enabled checks")
                seen: Set[str] = set()
                evaluations = 0
                failing = 0
                for check in checks:
                    for component in components:
                        if component.kind not in check.applicable_kinds or component.status == ComponentStatus.RETIRED:
                            continue
                        evaluations += 1
                        observed = _evaluate(check, component)
                        if observed is None:
                            continue
                        failing += 1
                        finding_id = _finding_id(principal.tenant_id, check.check_id, component.component_id)
                        seen.add(finding_id)
                        active_exception = self._connection.execute(
                            "SELECT exception_id FROM posture_exceptions WHERE tenant_id = ? AND finding_id = ? AND status = 'active' AND expires_at > ?",
                            (principal.tenant_id, finding_id, started.isoformat()),
                        ).fetchone()
                        status = PostureFindingStatus.ACCEPTED_EXCEPTION if active_exception else PostureFindingStatus.OPEN
                        evidence = ["inventory://%s" % component.component_id, "config-sha256:%s" % component.configuration_digest]
                        self._connection.execute(
                            "INSERT INTO posture_findings(tenant_id, finding_id, check_id, check_version, component_id, component_kind, component_name, title, severity, risk_score, status, evidence_refs_json, observed_json, remediation_json, framework_mappings_json, first_seen_at, last_seen_at, resolved_at, active_exception_id) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?) "
                            "ON CONFLICT(tenant_id, finding_id) DO UPDATE SET check_version=excluded.check_version, component_name=excluded.component_name, title=excluded.title, severity=excluded.severity, risk_score=excluded.risk_score, status=excluded.status, evidence_refs_json=excluded.evidence_refs_json, observed_json=excluded.observed_json, remediation_json=excluded.remediation_json, framework_mappings_json=excluded.framework_mappings_json, last_seen_at=excluded.last_seen_at, resolved_at=NULL, active_exception_id=excluded.active_exception_id",
                            (principal.tenant_id, finding_id, check.check_id, check.version,
                             component.component_id, component.kind.value, component.name, check.title,
                             check.severity.value, _risk_score(check.severity, component.risk_score),
                             status.value, json.dumps(evidence), json.dumps(observed, sort_keys=True),
                             json.dumps(check.remediation), json.dumps(check.framework_mappings),
                             started.isoformat(), started.isoformat(),
                             active_exception["exception_id"] if active_exception else None),
                        )
                component_ids = {item.component_id for item in components}
                resolved = 0
                if component_ids:
                    candidates = self._connection.execute(
                        "SELECT finding_id, check_id, component_id, status FROM posture_findings WHERE tenant_id = ? AND resolved_at IS NULL",
                        (principal.tenant_id,),
                    ).fetchall()
                    evaluated_checks = {item.check_id for item in checks}
                    for row in candidates:
                        if row["check_id"] in evaluated_checks and row["component_id"] in component_ids and row["finding_id"] not in seen:
                            self._connection.execute(
                                "UPDATE posture_findings SET status = 'resolved', resolved_at = ?, active_exception_id = NULL WHERE tenant_id = ? AND finding_id = ?",
                                (started.isoformat(), principal.tenant_id, row["finding_id"]),
                            )
                            resolved += 1
                counts = self._connection.execute(
                    "SELECT SUM(status = 'open') AS open_count, SUM(status = 'accepted_exception') AS excepted_count FROM posture_findings WHERE tenant_id = ?",
                    (principal.tenant_id,),
                ).fetchone()
                open_count = int(counts["open_count"] or 0)
                excepted_count = int(counts["excepted_count"] or 0)
                passing = evaluations - failing
                score = round(100 * passing / evaluations) if evaluations else 100
                completed = self._now()
                self._connection.execute(
                    "INSERT INTO posture_scans(tenant_id, scan_id, check_count, component_count, evaluations, failing, passing, open_findings, accepted_exceptions, resolved_findings, posture_score, started_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (principal.tenant_id, scan_id, len(checks), len(components), evaluations,
                     failing, passing, open_count, excepted_count, resolved, score,
                     started.isoformat(), completed.isoformat()),
                )
                self._audit(principal, "posture.scan", scan_id)
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return PostureScanResult(
            scan_id=scan_id, tenant_id=principal.tenant_id, check_count=len(checks),
            component_count=len(components), evaluations=evaluations, failing=failing,
            passing=passing, open_findings=open_count, accepted_exceptions=excepted_count,
            resolved_findings=resolved, posture_score=score, started_at=started, completed_at=completed,
        )

    def list_findings(
        self, principal: PosturePrincipal, *, status: Optional[PostureFindingStatus] = None,
        severity: Optional[Severity] = None, check_id: Optional[str] = None,
        component_id: Optional[str] = None, limit: int = 100, offset: int = 0,
    ) -> PostureFindingPage:
        self._require(principal, POSTURE_READ)
        if not 1 <= limit <= MAX_POSTURE_PAGE or not 0 <= offset <= 100000:
            raise ValueError("posture finding pagination is invalid")
        clauses = ["tenant_id = ?"]
        values: List[Any] = [principal.tenant_id]
        for column, value in (("status", status.value if status else None),
                              ("severity", severity.value if severity else None),
                              ("check_id", check_id), ("component_id", component_id)):
            if value is not None:
                clauses.append("%s = ?" % column)
                values.append(value)
        where = " AND ".join(clauses)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._expire_exceptions(principal, self._now())
                total = self._connection.execute(
                    "SELECT COUNT(*) AS total FROM posture_findings WHERE " + where, tuple(values)
                ).fetchone()["total"]
                rows = self._connection.execute(
                    "SELECT * FROM posture_findings WHERE " + where
                    + " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, risk_score DESC, last_seen_at DESC LIMIT ? OFFSET ?",
                    (*values, limit, offset),
                ).fetchall()
                self._audit(principal, "posture.finding.list", "filters")
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return PostureFindingPage(findings=[self._finding_row(row) for row in rows], total=total, limit=limit, offset=offset)

    def detail(self, principal: PosturePrincipal, finding_id: str) -> PostureFindingDetail:
        self._require(principal, POSTURE_READ)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._expire_exceptions(principal, self._now())
                row = self._connection.execute(
                    "SELECT * FROM posture_findings WHERE tenant_id = ? AND finding_id = ?",
                    (principal.tenant_id, finding_id),
                ).fetchone()
                if row is None:
                    raise KeyError(finding_id)
                check_row = self._connection.execute(
                    "SELECT * FROM posture_checks WHERE tenant_id = ? AND check_id = ? AND version = ?",
                    (principal.tenant_id, row["check_id"], row["check_version"]),
                ).fetchone()
                exception_row = None
                if row["active_exception_id"]:
                    exception_row = self._connection.execute(
                        "SELECT * FROM posture_exceptions WHERE tenant_id = ? AND exception_id = ?",
                        (principal.tenant_id, row["active_exception_id"]),
                    ).fetchone()
                self._audit(principal, "posture.finding.read", finding_id)
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return PostureFindingDetail(
            finding=self._finding_row(row),
            exception=self._exception_row(exception_row) if exception_row else None,
            check=self._check_row(check_row),
        )

    def create_exception(
        self, principal: PosturePrincipal, finding_id: str, *, reason: str,
        owner_ref: str, approved_by: str, expires_at: datetime,
    ) -> PostureException:
        self._require(principal, POSTURE_ADMIN)
        if not 10 <= len(reason.strip()) <= 1024:
            raise ValueError("posture exception reason is invalid")
        if not re.fullmatch(r"[A-Za-z0-9_.:/@-]{3,256}", owner_ref) or not re.fullmatch(
            r"[A-Za-z0-9_.:/@-]{3,256}", approved_by
        ):
            raise ValueError("posture exception owner or approver is invalid")
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise ValueError("posture exception expiry must include a timezone")
        now = self._now()
        expiry = expires_at.astimezone(timezone.utc)
        if not now < expiry <= now + timedelta(days=366):
            raise ValueError("posture exception expiry is outside the allowed window")
        exception_id = new_id("pste")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._expire_exceptions(principal, now)
                finding = self._connection.execute(
                    "SELECT status FROM posture_findings WHERE tenant_id = ? AND finding_id = ?",
                    (principal.tenant_id, finding_id),
                ).fetchone()
                if finding is None:
                    raise KeyError(finding_id)
                if finding["status"] == PostureFindingStatus.RESOLVED.value:
                    raise ValueError("resolved posture finding cannot receive an exception")
                active = self._connection.execute(
                    "SELECT exception_id FROM posture_exceptions "
                    "WHERE tenant_id = ? AND finding_id = ? AND status = 'active'",
                    (principal.tenant_id, finding_id),
                ).fetchone()
                if active is not None:
                    raise ValueError("posture finding already has an active exception")
                self._connection.execute(
                    "INSERT INTO posture_exceptions(tenant_id, exception_id, finding_id, reason, owner_ref, approved_by, status, created_at, expires_at, revoked_at, revoked_by, revoke_reason) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, NULL, NULL, NULL)",
                    (principal.tenant_id, exception_id, finding_id, reason.strip(), owner_ref,
                     approved_by, now.isoformat(), expiry.isoformat()),
                )
                self._connection.execute(
                    "UPDATE posture_findings SET status = 'accepted_exception', active_exception_id = ? WHERE tenant_id = ? AND finding_id = ?",
                    (exception_id, principal.tenant_id, finding_id),
                )
                self._audit(principal, "posture.exception.create", exception_id)
                row = self._connection.execute(
                    "SELECT * FROM posture_exceptions WHERE tenant_id = ? AND exception_id = ?",
                    (principal.tenant_id, exception_id),
                ).fetchone()
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return self._exception_row(row)

    def revoke_exception(
        self, principal: PosturePrincipal, exception_id: str, *, reason: str
    ) -> PostureException:
        self._require(principal, POSTURE_ADMIN)
        if not 3 <= len(reason.strip()) <= 512:
            raise ValueError("posture exception revoke reason is invalid")
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT * FROM posture_exceptions WHERE tenant_id = ? AND exception_id = ?",
                    (principal.tenant_id, exception_id),
                ).fetchone()
                if row is None:
                    raise KeyError(exception_id)
                if row["status"] != PostureExceptionStatus.ACTIVE.value:
                    raise ValueError("only an active posture exception can be revoked")
                self._connection.execute(
                    "UPDATE posture_exceptions SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoke_reason = ? WHERE tenant_id = ? AND exception_id = ?",
                    (now.isoformat(), principal.actor_id, reason.strip(), principal.tenant_id, exception_id),
                )
                self._connection.execute(
                    "UPDATE posture_findings SET status = 'open', active_exception_id = NULL WHERE tenant_id = ? AND finding_id = ? AND resolved_at IS NULL",
                    (principal.tenant_id, row["finding_id"]),
                )
                self._audit(principal, "posture.exception.revoke", exception_id)
                updated = self._connection.execute(
                    "SELECT * FROM posture_exceptions WHERE tenant_id = ? AND exception_id = ?",
                    (principal.tenant_id, exception_id),
                ).fetchone()
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return self._exception_row(updated)

    def summary(self, principal: PosturePrincipal) -> PostureSummary:
        self._require(principal, POSTURE_READ)
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._expire_exceptions(principal, now)
                counts = self._connection.execute(
                    "SELECT COUNT(*) AS total, SUM(status = 'open') AS open_count, SUM(status = 'accepted_exception') AS exception_count, SUM(status = 'resolved') AS resolved_count, SUM(status = 'open' AND severity = 'critical') AS critical_count FROM posture_findings WHERE tenant_id = ?",
                    (principal.tenant_id,),
                ).fetchone()
                checks = self._connection.execute(
                    "SELECT COUNT(*) AS total FROM posture_checks WHERE tenant_id = ? AND superseded_at IS NULL AND enabled = 1",
                    (principal.tenant_id,),
                ).fetchone()["total"]
                latest = self._connection.execute(
                    "SELECT completed_at, posture_score FROM posture_scans WHERE tenant_id = ? ORDER BY completed_at DESC LIMIT 1",
                    (principal.tenant_id,),
                ).fetchone()
                self._audit(principal, "posture.summary", "current")
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return PostureSummary(
            tenant_id=principal.tenant_id, enabled_checks=checks, total_findings=counts["total"],
            open_findings=int(counts["open_count"] or 0),
            accepted_exceptions=int(counts["exception_count"] or 0),
            resolved_findings=int(counts["resolved_count"] or 0),
            critical_open_findings=int(counts["critical_count"] or 0),
            posture_score=int(latest["posture_score"]) if latest else 100,
            latest_scan_at=latest["completed_at"] if latest else None, calculated_at=now,
        )

    def trends(self, principal: PosturePrincipal, *, limit: int = 30) -> PostureTrendSeries:
        self._require(principal, POSTURE_READ)
        if not 1 <= limit <= 365:
            raise ValueError("posture trend limit is invalid")
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM posture_scans WHERE tenant_id = ? ORDER BY completed_at DESC LIMIT ?",
                (principal.tenant_id, limit),
            ).fetchall()
            self._audit(principal, "posture.trends", str(limit))
        points = [PostureTrendPoint(**{key: row[key] for key in (
            "scan_id", "completed_at", "posture_score", "failing", "passing",
            "open_findings", "accepted_exceptions"
        )}) for row in reversed(rows)]
        return PostureTrendSeries(tenant_id=principal.tenant_id, points=points)


__all__ = [
    "DEFAULT_POSTURE_CHECKS", "MAX_POSTURE_PAGE", "POSTURE_ADMIN", "POSTURE_READ",
    "POSTURE_SCAN", "PostureAuthorizationError", "PostureCheckDefinition",
    "PostureCheckRecord", "PostureEvaluator", "PostureException",
    "PostureExceptionStatus", "PostureFinding", "PostureFindingDetail",
    "PostureFindingPage", "PostureFindingStatus", "PosturePrincipal",
    "PostureScanResult", "PostureService", "PostureSummary", "PostureTrendPoint",
    "PostureTrendSeries",
]
