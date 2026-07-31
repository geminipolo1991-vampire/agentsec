"""Durable, tenant-scoped incident case collaboration and review controls."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import re
import sqlite3
import threading
from typing import Any, Callable, Dict, List, Optional, Sequence, Set

from pydantic import Field, field_validator, model_validator

from .contracts import PipelineResult, StrictModel, new_id, utc_now
from .crypto import canonical_bytes
from .redaction import Redactor


CASE_READ = "case:read"
CASE_WRITE = "case:write"
CASE_ASSIGN = "case:assign"
CASE_COMMENT = "case:comment"
CASE_TASK = "case:task"
CASE_ATTACH = "case:attach"
CASE_REVIEW = "case:review"
CASE_ADMIN = "case:admin"
CASE_POLICY_VERSION = "case-management-2026-07-24.1"
MAX_CASE_PAGE = 200
MAX_CASE_COMMENTS = 500
MAX_CASE_TASKS = 500
MAX_CASE_ATTACHMENTS = 200
MAX_CASE_RELATIONSHIPS = 200
MAX_CASE_REVIEWS = 100
MAX_CASE_AUDIT = 1000
ZERO_SHA256 = "0" * 64


class CaseAuthorizationError(PermissionError):
    """Raised when a case principal crosses tenant, team, or permission scope."""


class CaseConflictError(RuntimeError):
    """Raised when optimistic version or lifecycle state is stale."""


class CaseStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    PENDING_REVIEW = "pending_review"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CaseSlaState(str, Enum):
    ON_TRACK = "on_track"
    AT_RISK = "at_risk"
    BREACHED = "breached"
    MET = "met"


class CaseTaskStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    CANCELLED = "cancelled"


class CaseReviewDecision(str, Enum):
    APPROVE = "approve"
    REQUEST_CHANGES = "request_changes"
    ESCALATE = "escalate"


class CaseRelationshipKind(str, Enum):
    RELATED = "related"
    PARENT = "parent"
    CHILD = "child"
    DUPLICATE = "duplicate"
    BLOCKS = "blocks"


class AttachmentScanStatus(str, Enum):
    PENDING = "pending"
    CLEAN = "clean"
    QUARANTINED = "quarantined"


class CasePrincipal(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(
        min_length=3,
        max_length=256,
        pattern=r"^(analyst|system|workload)://[A-Za-z0-9_.@/-]+$",
    )
    permissions: Set[str] = Field(default_factory=set, max_length=16)
    team_ids: Set[str] = Field(default_factory=set, max_length=32)

    @field_validator("permissions")
    @classmethod
    def valid_permissions(cls, value: Set[str]) -> Set[str]:
        if any(re.fullmatch(r"case:[a-z]+", item) is None for item in value):
            raise ValueError("case permissions must use case:operation")
        return value

    @field_validator("team_ids")
    @classmethod
    def valid_teams(cls, value: Set[str]) -> Set[str]:
        if any(re.fullmatch(r"team://[A-Za-z0-9_.@/-]+", item) is None for item in value):
            raise ValueError("case team IDs must use team:// identifiers")
        return value


class CaseTeam(StrictModel):
    schema_version: str = "1.0.0"
    tenant_id: str = Field(min_length=1, max_length=128)
    team_id: str = Field(pattern=r"^team://[A-Za-z0-9_.@/-]+$")
    name: str = Field(min_length=3, max_length=128)
    description: str = Field(min_length=3, max_length=512)
    member_ids: List[str] = Field(min_length=1, max_length=100)
    created_by: str = Field(
        pattern=r"^(analyst|system|workload)://[A-Za-z0-9_.@/-]+$"
    )
    created_at: datetime
    team_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("member_ids")
    @classmethod
    def valid_members(cls, value: List[str]) -> List[str]:
        if len(set(value)) != len(value) or any(
            re.fullmatch(r"^(analyst|system|workload)://[A-Za-z0-9_.@/-]+$", item)
            is None
            for item in value
        ):
            raise ValueError("case team members must be unique authenticated identities")
        return value

class CaseRecord(StrictModel):
    schema_version: str = "1.0.0"
    case_id: str = Field(default_factory=lambda: new_id("case"), pattern=r"^case_[0-9a-f]{32}$")
    tenant_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=3, max_length=256)
    summary: str = Field(min_length=3, max_length=512)
    finding_ids: List[str] = Field(min_length=1, max_length=128)
    correlation_incident_ids: List[str] = Field(default_factory=list, max_length=32)
    status: CaseStatus = CaseStatus.OPEN
    priority: str = Field(pattern=r"^P[0-3]$")
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    queue: Optional[str] = Field(default=None, max_length=128)
    assigned_to: Optional[str] = Field(
        default=None,
        max_length=256,
        pattern=r"^(analyst|system|workload)://[A-Za-z0-9_.@/-]+$",
    )
    team_id: Optional[str] = Field(
        default=None,
        max_length=256,
        pattern=r"^team://[A-Za-z0-9_.@/-]+$",
    )
    sla_minutes: int = Field(ge=1, le=43200)
    acknowledgment_due_at: datetime
    due_at: datetime
    sla_state: CaseSlaState = CaseSlaState.ON_TRACK
    acknowledged_at: Optional[datetime] = None
    resolution_requested_by: Optional[str] = Field(default=None, max_length=256)
    resolution_requested_at: Optional[datetime] = None
    approved_by: Optional[str] = Field(default=None, max_length=256)
    approved_at: Optional[datetime] = None
    closed_by: Optional[str] = Field(default=None, max_length=256)
    closed_at: Optional[datetime] = None
    version: int = Field(default=1, ge=1)
    policy_version: str = CASE_POLICY_VERSION
    created_at: datetime
    updated_at: datetime
    audit_count: int = Field(default=0, ge=0, le=MAX_CASE_AUDIT)
    audit_head_sha256: str = Field(default=ZERO_SHA256, pattern=r"^[0-9a-f]{64}$")
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("finding_ids", "correlation_incident_ids")
    @classmethod
    def unique_references(cls, value: List[str]) -> List[str]:
        if len(set(value)) != len(value):
            raise ValueError("case references must be unique")
        return value

    @field_validator("finding_ids")
    @classmethod
    def valid_findings(cls, value: List[str]) -> List[str]:
        if any(re.fullmatch(r"fnd_[A-Za-z0-9]+", item) is None for item in value):
            raise ValueError("case finding references are invalid")
        return value

    @field_validator("correlation_incident_ids")
    @classmethod
    def valid_correlation_incidents(cls, value: List[str]) -> List[str]:
        if any(re.fullmatch(r"inc_[A-Za-z0-9]+", item) is None for item in value):
            raise ValueError("case correlation incident references are invalid")
        return value

    @model_validator(mode="after")
    def coherent_lifecycle(self) -> "CaseRecord":
        timestamps = [
            self.acknowledgment_due_at,
            self.due_at,
            self.created_at,
            self.updated_at,
            *[
                item
                for item in (
                    self.acknowledged_at,
                    self.resolution_requested_at,
                    self.approved_at,
                    self.closed_at,
                )
                if item is not None
            ],
        ]
        if any(item.tzinfo is None or item.utcoffset() is None for item in timestamps):
            raise ValueError("case timestamps must be timezone aware")
        if self.updated_at < self.created_at or self.due_at < self.created_at:
            raise ValueError("case timestamps are not ordered")
        if not self.created_at <= self.acknowledgment_due_at < self.due_at:
            raise ValueError("case acknowledgment and resolution deadlines are not ordered")
        if self.audit_count == 0 and self.audit_head_sha256 != ZERO_SHA256:
            raise ValueError("empty case audit must use the zero hash")
        if self.audit_count > 0 and self.audit_head_sha256 == ZERO_SHA256:
            raise ValueError("non-empty case audit requires a head hash")
        if self.status in {CaseStatus.PENDING_REVIEW, CaseStatus.RESOLVED, CaseStatus.CLOSED}:
            if not self.resolution_requested_by or self.resolution_requested_at is None:
                raise ValueError("reviewed case states require a resolution request")
        if self.status in {CaseStatus.RESOLVED, CaseStatus.CLOSED}:
            if not self.approved_by or self.approved_at is None:
                raise ValueError("resolved case requires independent approval")
        if self.status == CaseStatus.CLOSED:
            if not self.closed_by or self.closed_at is None:
                raise ValueError("closed case requires attributed closure")
        return self


class CaseComment(StrictModel):
    comment_id: str = Field(default_factory=lambda: new_id("cmt"), pattern=r"^cmt_[0-9a-f]{32}$")
    case_id: str = Field(pattern=r"^case_[0-9a-f]{32}$")
    tenant_id: str
    actor_id: str = Field(
        pattern=r"^(analyst|system|workload)://[A-Za-z0-9_.@/-]+$"
    )
    body: str = Field(min_length=1, max_length=2048)
    created_at: datetime
    comment_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CaseTask(StrictModel):
    task_id: str = Field(default_factory=lambda: new_id("ctk"), pattern=r"^ctk_[0-9a-f]{32}$")
    case_id: str = Field(pattern=r"^case_[0-9a-f]{32}$")
    tenant_id: str
    title: str = Field(min_length=3, max_length=256)
    description: str = Field(min_length=3, max_length=1024)
    status: CaseTaskStatus = CaseTaskStatus.OPEN
    assigned_to: Optional[str] = Field(
        default=None,
        max_length=256,
        pattern=r"^(analyst|system|workload)://[A-Za-z0-9_.@/-]+$",
    )
    due_at: Optional[datetime] = None
    created_by: str
    completed_by: Optional[str] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    task_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def coherent_task(self) -> "CaseTask":
        timestamps = [self.created_at, self.updated_at]
        if self.due_at is not None:
            timestamps.append(self.due_at)
        if self.completed_at is not None:
            timestamps.append(self.completed_at)
        if any(item.tzinfo is None or item.utcoffset() is None for item in timestamps):
            raise ValueError("case task timestamps must be timezone aware")
        if self.updated_at < self.created_at:
            raise ValueError("case task timestamps are not ordered")
        if self.status == CaseTaskStatus.DONE:
            if not self.completed_by or self.completed_at is None:
                raise ValueError("completed task requires actor and timestamp")
        elif self.completed_by is not None or self.completed_at is not None:
            raise ValueError("non-completed task cannot carry completion fields")
        return self


class CaseAttachment(StrictModel):
    attachment_id: str = Field(default_factory=lambda: new_id("cat"), pattern=r"^cat_[0-9a-f]{32}$")
    case_id: str = Field(pattern=r"^case_[0-9a-f]{32}$")
    tenant_id: str
    display_name: str = Field(min_length=1, max_length=256)
    media_type: str = Field(
        pattern=r"^(application/pdf|application/json|text/plain|image/png|image/jpeg)$"
    )
    size_bytes: int = Field(ge=1, le=10 * 1024 * 1024)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_ref: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,31}_sha256:[0-9a-f]{24}$")
    scan_status: AttachmentScanStatus = AttachmentScanStatus.PENDING
    scanner_ref: Optional[str] = Field(
        default=None, pattern=r"^scanner_sha256:[0-9a-f]{24}$"
    )
    scanned_at: Optional[datetime] = None
    uploaded_by: str
    created_at: datetime
    attachment_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("display_name")
    @classmethod
    def safe_display_name(cls, value: str) -> str:
        if (
            value in {".", ".."}
            or "/" in value
            or "\\" in value
            or any(ord(character) < 32 for character in value)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,255}", value) is None
        ):
            raise ValueError("attachment display name must be a safe basename")
        return value

    @model_validator(mode="after")
    def coherent_scan(self) -> "CaseAttachment":
        if self.scan_status == AttachmentScanStatus.PENDING:
            if self.scanner_ref is not None or self.scanned_at is not None:
                raise ValueError("pending attachment cannot carry a scanner verdict")
        elif self.scanner_ref is None or self.scanned_at is None:
            raise ValueError("completed attachment scan requires scanner attribution")
        return self


class CaseRelationship(StrictModel):
    relationship_id: str = Field(default_factory=lambda: new_id("crl"), pattern=r"^crl_[0-9a-f]{32}$")
    case_id: str = Field(pattern=r"^case_[0-9a-f]{32}$")
    tenant_id: str
    kind: CaseRelationshipKind
    target_type: str = Field(pattern=r"^(case|finding|incident)$")
    target_id: str = Field(min_length=5, max_length=128)
    reason: str = Field(min_length=10, max_length=512)
    created_by: str
    created_at: datetime
    relationship_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def not_self_related(self) -> "CaseRelationship":
        if self.target_type == "case" and self.target_id == self.case_id:
            raise ValueError("case cannot relate to itself")
        patterns = {
            "case": r"^case_[0-9a-f]{32}$",
            "finding": r"^fnd_[A-Za-z0-9]+$",
            "incident": r"^inc_[A-Za-z0-9]+$",
        }
        if re.fullmatch(patterns[self.target_type], self.target_id) is None:
            raise ValueError("case relationship target does not match its type")
        return self


class CaseReview(StrictModel):
    review_id: str = Field(default_factory=lambda: new_id("crv"), pattern=r"^crv_[0-9a-f]{32}$")
    case_id: str = Field(pattern=r"^case_[0-9a-f]{32}$")
    tenant_id: str
    decision: CaseReviewDecision
    reviewer_id: str
    comment: str = Field(min_length=3, max_length=1024)
    created_at: datetime
    review_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CaseAuditEntry(StrictModel):
    audit_id: str = Field(default_factory=lambda: new_id("cau"), pattern=r"^cau_[0-9a-f]{32}$")
    case_id: str = Field(pattern=r"^case_[0-9a-f]{32}$")
    tenant_id: str
    actor_id: str
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    from_status: Optional[CaseStatus] = None
    to_status: Optional[CaseStatus] = None
    details_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    occurred_at: datetime
    sequence: int = Field(ge=1, le=10000)
    previous_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    audit_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CaseDetail(StrictModel):
    case: CaseRecord
    comments: List[CaseComment] = Field(default_factory=list, max_length=MAX_CASE_COMMENTS)
    tasks: List[CaseTask] = Field(default_factory=list, max_length=MAX_CASE_TASKS)
    attachments: List[CaseAttachment] = Field(default_factory=list, max_length=MAX_CASE_ATTACHMENTS)
    relationships: List[CaseRelationship] = Field(default_factory=list, max_length=MAX_CASE_RELATIONSHIPS)
    reviews: List[CaseReview] = Field(default_factory=list, max_length=MAX_CASE_REVIEWS)
    audit: List[CaseAuditEntry] = Field(default_factory=list, max_length=MAX_CASE_AUDIT)


class CasePage(StrictModel):
    cases: List[CaseRecord]
    count: int = Field(ge=0)
    limit: int = Field(ge=1, le=MAX_CASE_PAGE)
    offset: int = Field(ge=0)


class CaseHealth(StrictModel):
    tenant_id: str
    total_cases: int = Field(ge=0)
    open_cases: int = Field(ge=0)
    pending_review: int = Field(ge=0)
    breached_sla: int = Field(ge=0)
    acknowledgment_breaches: int = Field(ge=0)
    resolution_breaches: int = Field(ge=0)
    unassigned_cases: int = Field(ge=0)
    closed_cases: int = Field(ge=0)
    open_tasks: int = Field(ge=0)
    calculated_at: datetime


class CaseAssignmentRequest(StrictModel):
    expected_version: int = Field(ge=1)
    assigned_to: Optional[str] = Field(
        default=None,
        max_length=256,
        pattern=r"^(analyst|system|workload)://[A-Za-z0-9_.@/-]+$",
    )
    team_id: Optional[str] = Field(
        default=None,
        max_length=256,
        pattern=r"^team://[A-Za-z0-9_.@/-]+$",
    )


class CaseCommentRequest(StrictModel):
    expected_version: int = Field(ge=1)
    body: str = Field(min_length=1, max_length=2048)


class CaseTaskCreateRequest(StrictModel):
    expected_version: int = Field(ge=1)
    title: str = Field(min_length=3, max_length=256)
    description: str = Field(min_length=3, max_length=1024)
    assigned_to: Optional[str] = Field(
        default=None,
        max_length=256,
        pattern=r"^(analyst|system|workload)://[A-Za-z0-9_.@/-]+$",
    )
    due_at: Optional[datetime] = None

    @field_validator("due_at")
    @classmethod
    def aware_due_at(cls, value: Optional[datetime]) -> Optional[datetime]:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("case task due time must be timezone aware")
        return value


class CaseTaskTransitionRequest(StrictModel):
    expected_version: int = Field(ge=1)
    status: CaseTaskStatus


class CaseAttachmentRequest(StrictModel):
    expected_version: int = Field(ge=1)
    display_name: str = Field(min_length=1, max_length=256)
    media_type: str = Field(
        pattern=r"^(application/pdf|application/json|text/plain|image/png|image/jpeg)$"
    )
    size_bytes: int = Field(ge=1, le=10 * 1024 * 1024)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_ref: str = Field(
        pattern=r"^[a-z][a-z0-9_-]{1,31}_sha256:[0-9a-f]{24}$"
    )


class CaseAttachmentScanRequest(StrictModel):
    expected_version: int = Field(ge=1)
    status: AttachmentScanStatus
    scanner_ref: str = Field(pattern=r"^scanner_sha256:[0-9a-f]{24}$")


class CaseRelationshipRequest(StrictModel):
    expected_version: int = Field(ge=1)
    kind: CaseRelationshipKind
    target_type: str = Field(pattern=r"^(case|finding|incident)$")
    target_id: str = Field(min_length=5, max_length=128)
    reason: str = Field(
        default="Evidence-backed analyst relationship.", min_length=10, max_length=512
    )


class CaseLifecycleRequest(StrictModel):
    expected_version: int = Field(ge=1)


class CaseTeamCreateRequest(StrictModel):
    team_id: str = Field(pattern=r"^team://[A-Za-z0-9_.@/-]+$")
    name: str = Field(min_length=3, max_length=128)
    description: str = Field(min_length=3, max_length=512)
    member_ids: List[str] = Field(min_length=1, max_length=100)


class CaseReviewRequest(StrictModel):
    expected_version: int = Field(ge=1)
    decision: CaseReviewDecision
    comment: str = Field(min_length=3, max_length=1024)


def _digest(model: StrictModel, field: str) -> str:
    return hashlib.sha256(
        canonical_bytes(model.model_dump(mode="json", exclude={field}))
    ).hexdigest()


class CaseService:
    """SQLite collaboration service with optimistic version and four-eyes review."""

    def __init__(
        self,
        path: str,
        *,
        clock: Callable[[], datetime] = utc_now,
        redactor: Optional[Redactor] = None,
    ) -> None:
        self.path = path
        self.clock = clock
        self.redactor = redactor or Redactor()
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                tenant_id TEXT NOT NULL, case_id TEXT NOT NULL, status TEXT NOT NULL,
                priority TEXT NOT NULL, assigned_to TEXT, team_id TEXT, due_at TEXT NOT NULL,
                updated_at TEXT NOT NULL, version INTEGER NOT NULL, case_json TEXT NOT NULL,
                record_sha256 TEXT NOT NULL, PRIMARY KEY (tenant_id, case_id)
            );
            CREATE INDEX IF NOT EXISTS case_listing ON cases(tenant_id, updated_at DESC, case_id);
            CREATE INDEX IF NOT EXISTS case_status ON cases(tenant_id, status, updated_at DESC);
            CREATE INDEX IF NOT EXISTS case_assignment ON cases(tenant_id, assigned_to, team_id);
            CREATE TABLE IF NOT EXISTS case_teams (
                tenant_id TEXT NOT NULL, team_id TEXT NOT NULL, name TEXT NOT NULL,
                created_at TEXT NOT NULL, item_json TEXT NOT NULL, item_sha256 TEXT NOT NULL,
                PRIMARY KEY (tenant_id, team_id)
            );
            CREATE TABLE IF NOT EXISTS case_findings (
                tenant_id TEXT NOT NULL, finding_id TEXT NOT NULL, case_id TEXT NOT NULL,
                PRIMARY KEY (tenant_id, finding_id),
                FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id)
            );
            CREATE TABLE IF NOT EXISTS case_comments (
                tenant_id TEXT NOT NULL, case_id TEXT NOT NULL, comment_id TEXT NOT NULL,
                created_at TEXT NOT NULL, item_json TEXT NOT NULL, item_sha256 TEXT NOT NULL,
                PRIMARY KEY (tenant_id, comment_id),
                FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id)
            );
            CREATE TABLE IF NOT EXISTS case_tasks (
                tenant_id TEXT NOT NULL, case_id TEXT NOT NULL, task_id TEXT NOT NULL,
                status TEXT NOT NULL, updated_at TEXT NOT NULL, item_json TEXT NOT NULL,
                item_sha256 TEXT NOT NULL, PRIMARY KEY (tenant_id, task_id),
                FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id)
            );
            CREATE TABLE IF NOT EXISTS case_attachments (
                tenant_id TEXT NOT NULL, case_id TEXT NOT NULL, attachment_id TEXT NOT NULL,
                created_at TEXT NOT NULL, item_json TEXT NOT NULL, item_sha256 TEXT NOT NULL,
                PRIMARY KEY (tenant_id, attachment_id),
                FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id)
            );
            CREATE TABLE IF NOT EXISTS case_relationships (
                tenant_id TEXT NOT NULL, case_id TEXT NOT NULL, relationship_id TEXT NOT NULL,
                created_at TEXT NOT NULL, item_json TEXT NOT NULL, item_sha256 TEXT NOT NULL,
                PRIMARY KEY (tenant_id, relationship_id),
                FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id)
            );
            CREATE TABLE IF NOT EXISTS case_reviews (
                tenant_id TEXT NOT NULL, case_id TEXT NOT NULL, review_id TEXT NOT NULL,
                created_at TEXT NOT NULL, item_json TEXT NOT NULL, item_sha256 TEXT NOT NULL,
                PRIMARY KEY (tenant_id, review_id),
                FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id)
            );
            CREATE TABLE IF NOT EXISTS case_audit (
                tenant_id TEXT NOT NULL, case_id TEXT NOT NULL, audit_id TEXT NOT NULL,
                occurred_at TEXT NOT NULL, item_json TEXT NOT NULL, item_sha256 TEXT NOT NULL,
                PRIMARY KEY (tenant_id, audit_id),
                FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS case_relationship_unique
                ON case_relationships(tenant_id, case_id, relationship_id);
            CREATE TABLE IF NOT EXISTS case_operations (
                tenant_id TEXT NOT NULL, operation_key TEXT NOT NULL,
                action TEXT NOT NULL, case_id TEXT NOT NULL,
                request_sha256 TEXT NOT NULL, result_type TEXT NOT NULL,
                result_json TEXT NOT NULL, result_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, operation_key)
            );
            """
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("case clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _require(principal: CasePrincipal, permission: str) -> None:
        if permission not in principal.permissions:
            raise CaseAuthorizationError("missing case permission: %s" % permission)

    @staticmethod
    def _verify(model: StrictModel, field: str) -> None:
        if _digest(model, field) != getattr(model, field):
            raise ValueError("case record integrity verification failed")

    def _authorize_case(self, principal: CasePrincipal, case: CaseRecord) -> None:
        if case.tenant_id != principal.tenant_id:
            raise CaseAuthorizationError("cross-tenant case access is forbidden")
        if (
            CASE_ADMIN not in principal.permissions
            and case.team_id is not None
            and case.team_id not in principal.team_ids
        ):
            raise CaseAuthorizationError("case team access is forbidden")

    def _load(self, principal: CasePrincipal, case_id: str) -> CaseRecord:
        row = self._connection.execute(
            "SELECT case_json FROM cases WHERE tenant_id = ? AND case_id = ?",
            (principal.tenant_id, case_id),
        ).fetchone()
        if row is None:
            raise KeyError(case_id)
        case = CaseRecord.model_validate_json(row["case_json"])
        self._verify(case, "record_sha256")
        self._authorize_case(principal, case)
        self._verify_audit_state(case)
        return self._with_sla(case)

    def _verify_audit_state(self, case: CaseRecord) -> None:
        rows = self._connection.execute(
            "SELECT item_json FROM case_audit WHERE tenant_id = ? AND case_id = ? ORDER BY occurred_at, rowid",
            (case.tenant_id, case.case_id),
        ).fetchall()
        previous = ZERO_SHA256
        for sequence, row in enumerate(rows, 1):
            entry = CaseAuditEntry.model_validate_json(row["item_json"])
            self._verify(entry, "audit_sha256")
            if entry.sequence != sequence or entry.previous_sha256 != previous:
                raise ValueError("case audit chain integrity verification failed")
            previous = entry.audit_sha256
        if len(rows) != case.audit_count or previous != case.audit_head_sha256:
            raise ValueError("case record does not bind its complete audit trail")

    def _with_sla(self, case: CaseRecord) -> CaseRecord:
        now = self._now()
        acknowledgment_breached = (
            (case.acknowledged_at or now) > case.acknowledgment_due_at
        )
        if case.status in {CaseStatus.RESOLVED, CaseStatus.CLOSED}:
            resolution_breached = (case.approved_at or case.updated_at) > case.due_at
            state = (
                CaseSlaState.BREACHED
                if acknowledgment_breached or resolution_breached
                else CaseSlaState.MET
            )
        else:
            remaining = (case.due_at - now).total_seconds()
            state = (
                CaseSlaState.BREACHED
                if acknowledgment_breached or remaining < 0
                else CaseSlaState.AT_RISK
                if remaining <= max(900, case.sla_minutes * 12)
                else CaseSlaState.ON_TRACK
            )
        if case.sla_state == state:
            return case
        derived = case.model_copy(
            update={"sla_state": state, "record_sha256": "0" * 64}
        )
        signed = self._signed(derived, "record_sha256")
        assert isinstance(signed, CaseRecord)
        return signed

    @staticmethod
    def _signed(model: StrictModel, field: str) -> StrictModel:
        return model.model_copy(update={field: _digest(model, field)})

    @staticmethod
    def _operation_identity(
        principal: CasePrincipal,
        action: str,
        case_id: str,
        expected_version: int,
        payload: Dict[str, Any],
    ) -> tuple[str, str]:
        request = {
            "tenant_id": principal.tenant_id,
            "actor_id": principal.actor_id,
            "action": action,
            "case_id": case_id,
            "expected_version": expected_version,
            "payload": payload,
        }
        request_sha256 = hashlib.sha256(canonical_bytes(request)).hexdigest()
        return "cop_%s" % request_sha256[:32], request_sha256

    def _replay_operation(
        self,
        principal: CasePrincipal,
        operation_key: str,
        *,
        action: str,
        case_id: str,
        request_sha256: str,
        model_type,
        digest_field: str,
    ):
        row = self._connection.execute(
            "SELECT action, case_id, request_sha256, result_type, result_json, result_sha256 FROM case_operations WHERE tenant_id = ? AND operation_key = ?",
            (principal.tenant_id, operation_key),
        ).fetchone()
        if row is None:
            return None
        if (
            row["action"] != action
            or row["case_id"] != case_id
            or row["request_sha256"] != request_sha256
            or row["result_type"] != model_type.__name__
        ):
            raise CaseConflictError("case operation identity conflict")
        if hashlib.sha256(row["result_json"].encode("utf-8")).hexdigest() != row["result_sha256"]:
            raise ValueError("case operation result integrity verification failed")
        result = model_type.model_validate_json(row["result_json"])
        self._verify(result, digest_field)
        return result

    def _record_operation(
        self,
        principal: CasePrincipal,
        operation_key: str,
        *,
        action: str,
        case_id: str,
        request_sha256: str,
        result: StrictModel,
    ) -> None:
        result_json = result.model_dump_json()
        self._connection.execute(
            "INSERT INTO case_operations(tenant_id, operation_key, action, case_id, request_sha256, result_type, result_json, result_sha256, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                principal.tenant_id,
                operation_key,
                action,
                case_id,
                request_sha256,
                type(result).__name__,
                result_json,
                hashlib.sha256(result_json.encode("utf-8")).hexdigest(),
                self._now().isoformat(),
            ),
        )

    def create_team(
        self,
        principal: CasePrincipal,
        *,
        team_id: str,
        name: str,
        description: str,
        member_ids: Sequence[str],
    ) -> CaseTeam:
        self._require(principal, CASE_ADMIN)
        safe = self.redactor.redact(
            {"name": name, "description": description}
        ).value
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT item_json FROM case_teams WHERE tenant_id = ? AND team_id = ?",
                    (principal.tenant_id, team_id),
                ).fetchone()
                if row is not None:
                    existing = CaseTeam.model_validate_json(row["item_json"])
                    self._verify(existing, "team_sha256")
                    if (
                        existing.name != str(safe["name"])
                        or existing.description != str(safe["description"])
                        or existing.member_ids != list(member_ids)
                    ):
                        raise CaseConflictError(
                            "case team identifier already has a different definition"
                        )
                    self._connection.execute("COMMIT")
                    return existing

                unsigned = CaseTeam(
                    tenant_id=principal.tenant_id,
                    team_id=team_id,
                    name=str(safe["name"]),
                    description=str(safe["description"]),
                    member_ids=list(member_ids),
                    created_by=principal.actor_id,
                    created_at=self._now(),
                    team_sha256=ZERO_SHA256,
                )
                team = self._signed(unsigned, "team_sha256")
                assert isinstance(team, CaseTeam)
                self._connection.execute(
                    "INSERT INTO case_teams(tenant_id, team_id, name, created_at, item_json, item_sha256) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        team.tenant_id,
                        team.team_id,
                        team.name,
                        team.created_at.isoformat(),
                        team.model_dump_json(),
                        team.team_sha256,
                    ),
                )
                self._connection.execute("COMMIT")
                return team
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def ensure_team(
        self,
        principal: CasePrincipal,
        *,
        team_id: str,
        name: str,
        description: str,
        member_ids: Sequence[str],
    ) -> CaseTeam:
        self._require(principal, CASE_ADMIN)
        with self._lock:
            row = self._connection.execute(
                "SELECT item_json FROM case_teams WHERE tenant_id = ? AND team_id = ?",
                (principal.tenant_id, team_id),
            ).fetchone()
        if row is not None:
            team = CaseTeam.model_validate_json(row["item_json"])
            self._verify(team, "team_sha256")
            return team
        return self.create_team(
            principal,
            team_id=team_id,
            name=name,
            description=description,
            member_ids=member_ids,
        )

    def list_teams(self, principal: CasePrincipal) -> List[CaseTeam]:
        self._require(principal, CASE_READ)
        with self._lock:
            rows = self._connection.execute(
                "SELECT item_json FROM case_teams WHERE tenant_id = ? ORDER BY name, team_id",
                (principal.tenant_id,),
            ).fetchall()
        teams = [CaseTeam.model_validate_json(row["item_json"]) for row in rows]
        for team in teams:
            self._verify(team, "team_sha256")
        if CASE_ADMIN in principal.permissions:
            return teams
        return [team for team in teams if team.team_id in principal.team_ids]

    def _team(self, principal: CasePrincipal, team_id: str) -> CaseTeam:
        row = self._connection.execute(
            "SELECT item_json FROM case_teams WHERE tenant_id = ? AND team_id = ?",
            (principal.tenant_id, team_id),
        ).fetchone()
        if row is None:
            raise KeyError(team_id)
        team = CaseTeam.model_validate_json(row["item_json"])
        self._verify(team, "team_sha256")
        return team

    def _store_case(self, case: CaseRecord) -> CaseRecord:
        signed = self._signed(case, "record_sha256")
        assert isinstance(signed, CaseRecord)
        self._connection.execute(
            """INSERT INTO cases(tenant_id, case_id, status, priority, assigned_to, team_id, due_at, updated_at, version, case_json, record_sha256)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(tenant_id, case_id) DO UPDATE SET status=excluded.status,
               priority=excluded.priority, assigned_to=excluded.assigned_to, team_id=excluded.team_id,
               due_at=excluded.due_at, updated_at=excluded.updated_at, version=excluded.version,
               case_json=excluded.case_json, record_sha256=excluded.record_sha256""",
            (
                signed.tenant_id, signed.case_id, signed.status.value, signed.priority,
                signed.assigned_to, signed.team_id, signed.due_at.isoformat(),
                signed.updated_at.isoformat(), signed.version, signed.model_dump_json(),
                signed.record_sha256,
            ),
        )
        return signed

    def _audit(
        self,
        principal: CasePrincipal,
        case_id: str,
        action: str,
        *,
        details: Dict[str, Any],
        from_status: Optional[CaseStatus] = None,
        to_status: Optional[CaseStatus] = None,
    ) -> CaseAuditEntry:
        count = self._connection.execute(
            "SELECT COUNT(*) AS total FROM case_audit WHERE tenant_id = ? AND case_id = ?",
            (principal.tenant_id, case_id),
        ).fetchone()["total"]
        if int(count) >= MAX_CASE_AUDIT:
            raise CaseConflictError("case audit capacity has been reached")
        row = self._connection.execute(
            "SELECT item_json FROM case_audit WHERE tenant_id = ? AND case_id = ? ORDER BY occurred_at DESC, rowid DESC LIMIT 1",
            (principal.tenant_id, case_id),
        ).fetchone()
        previous = ZERO_SHA256
        sequence = 1
        if row is not None:
            prior = CaseAuditEntry.model_validate_json(row["item_json"])
            self._verify(prior, "audit_sha256")
            previous = prior.audit_sha256
            sequence = prior.sequence + 1
        unsigned = CaseAuditEntry(
            case_id=case_id, tenant_id=principal.tenant_id, actor_id=principal.actor_id,
            action=action, from_status=from_status, to_status=to_status,
            details_sha256=hashlib.sha256(canonical_bytes(details)).hexdigest(),
            occurred_at=self._now(), sequence=sequence, previous_sha256=previous,
            audit_sha256=ZERO_SHA256,
        )
        item = self._signed(unsigned, "audit_sha256")
        assert isinstance(item, CaseAuditEntry)
        self._connection.execute(
            "INSERT INTO case_audit VALUES (?, ?, ?, ?, ?, ?)",
            (item.tenant_id, item.case_id, item.audit_id, item.occurred_at.isoformat(), item.model_dump_json(), item.audit_sha256),
        )
        return item

    def _ensure_child_capacity(
        self,
        principal: CasePrincipal,
        case_id: str,
        table: str,
        limit: int,
        label: str,
    ) -> None:
        allowed = {
            "case_comments",
            "case_tasks",
            "case_attachments",
            "case_relationships",
            "case_reviews",
        }
        if table not in allowed:
            raise ValueError("unsupported case child table")
        count = self._connection.execute(
            "SELECT COUNT(*) AS total FROM %s WHERE tenant_id = ? AND case_id = ?"
            % table,
            (principal.tenant_id, case_id),
        ).fetchone()["total"]
        if int(count) >= limit:
            raise CaseConflictError("case %s capacity has been reached" % label)

    def create_from_pipeline(
        self,
        principal: CasePrincipal,
        result: PipelineResult,
        *,
        correlation_incident_id: Optional[str] = None,
    ) -> CaseRecord:
        self._require(principal, CASE_WRITE)
        if result.event.tenant_id != principal.tenant_id:
            raise CaseAuthorizationError("cross-tenant case creation is forbidden")
        finding_id = result.finding.finding_id
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT case_id FROM case_findings WHERE tenant_id = ? AND finding_id = ?",
                    (principal.tenant_id, finding_id),
                ).fetchone()
                if existing is not None:
                    case = self._load(principal, existing["case_id"])
                    self._connection.execute("COMMIT")
                    return case
                now = self._now()
                safe = self.redactor.redact(
                    {"title": result.alert.title, "summary": "Security finding %s requires %s review." % (result.alert.alert_type, result.triage.priority)}
                ).value
                resolution_minutes = max(1, result.triage.sla_minutes)
                acknowledgment_seconds = max(
                    1, min(15 * 60, int(resolution_minutes * 60 * 0.25))
                )
                unsigned = CaseRecord(
                    case_id=result.escalation.case_id or new_id("case"),
                    tenant_id=principal.tenant_id,
                    title=str(safe["title"]), summary=str(safe["summary"]),
                    finding_ids=[finding_id],
                    correlation_incident_ids=(
                        [correlation_incident_id] if correlation_incident_id else []
                    ),
                    status=CaseStatus.OPEN,
                    priority=result.triage.priority, severity=result.alert.severity.value,
                    queue=result.escalation.queue, sla_minutes=resolution_minutes,
                    acknowledgment_due_at=now + timedelta(seconds=acknowledgment_seconds),
                    due_at=now + timedelta(minutes=resolution_minutes),
                    created_at=now, updated_at=now, record_sha256=ZERO_SHA256,
                )
                provisional = self._store_case(unsigned)
                self._connection.execute(
                    "INSERT INTO case_findings VALUES (?, ?, ?)",
                    (principal.tenant_id, finding_id, provisional.case_id),
                )
                audit = self._audit(
                    principal, provisional.case_id, "case_created",
                    details={"finding_id": finding_id},
                    to_status=CaseStatus.OPEN,
                )
                case = self._store_case(
                    provisional.model_copy(
                        update={"audit_count": 1, "audit_head_sha256": audit.audit_sha256}
                    )
                )
                self._connection.execute("COMMIT")
                return case
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def get(self, principal: CasePrincipal, case_id: str) -> CaseDetail:
        self._require(principal, CASE_READ)
        with self._lock:
            case = self._load(principal, case_id)
            return CaseDetail(
                case=case,
                comments=self._children(CaseComment, "case_comments", principal, case_id, "comment_sha256"),
                tasks=self._children(CaseTask, "case_tasks", principal, case_id, "task_sha256"),
                attachments=self._children(CaseAttachment, "case_attachments", principal, case_id, "attachment_sha256"),
                relationships=self._children(CaseRelationship, "case_relationships", principal, case_id, "relationship_sha256"),
                reviews=self._children(CaseReview, "case_reviews", principal, case_id, "review_sha256"),
                audit=self._children(CaseAuditEntry, "case_audit", principal, case_id, "audit_sha256"),
            )

    def _children(self, model_type, table: str, principal: CasePrincipal, case_id: str, digest_field: str):
        order_column = {
            "case_audit": "occurred_at",
            "case_tasks": "updated_at",
        }.get(table, "created_at")
        rows = self._connection.execute(
            "SELECT item_json FROM %s WHERE tenant_id = ? AND case_id = ? ORDER BY %s, rowid" % (
                table, order_column
            ),
            (principal.tenant_id, case_id),
        ).fetchall()
        items = [model_type.model_validate_json(row["item_json"]) for row in rows]
        for item in items:
            self._verify(item, digest_field)
        if table == "case_audit":
            previous = ZERO_SHA256
            for sequence, item in enumerate(items, 1):
                if item.sequence != sequence or item.previous_sha256 != previous:
                    raise ValueError("case audit chain integrity verification failed")
                previous = item.audit_sha256
        return items

    def list(
        self,
        principal: CasePrincipal,
        *,
        status: Optional[CaseStatus] = None,
        priority: Optional[str] = None,
        assigned_to: Optional[str] = None,
        team_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> CasePage:
        self._require(principal, CASE_READ)
        if not 1 <= limit <= MAX_CASE_PAGE or offset < 0:
            raise ValueError("case pagination bounds are invalid")
        if priority is not None and re.fullmatch(r"P[0-3]", priority) is None:
            raise ValueError("case priority filter is invalid")
        if assigned_to is not None and re.fullmatch(
            r"^(analyst|system|workload)://[A-Za-z0-9_.@/-]+$", assigned_to
        ) is None:
            raise ValueError("case assignee filter is invalid")
        if team_id is not None and re.fullmatch(
            r"^team://[A-Za-z0-9_.@/-]+$", team_id
        ) is None:
            raise ValueError("case team filter is invalid")
        clauses = ["tenant_id = ?"]
        values: List[Any] = [principal.tenant_id]
        for column, value in (("status", status.value if status else None), ("priority", priority), ("assigned_to", assigned_to), ("team_id", team_id)):
            if value is not None:
                clauses.append("%s = ?" % column)
                values.append(value)
        if CASE_ADMIN not in principal.permissions:
            if not principal.team_ids:
                clauses.append("team_id IS NULL")
            else:
                placeholders = ",".join("?" for _ in principal.team_ids)
                clauses.append("(team_id IS NULL OR team_id IN (%s))" % placeholders)
                values.extend(sorted(principal.team_ids))
        where = " AND ".join(clauses)
        with self._lock:
            rows = self._connection.execute(
                "SELECT case_json FROM cases WHERE %s ORDER BY updated_at DESC, case_id LIMIT ? OFFSET ?" % where,
                (*values, limit, offset),
            ).fetchall()
            count = self._connection.execute(
                "SELECT COUNT(*) AS total FROM cases WHERE %s" % where, values
            ).fetchone()["total"]
        cases = [CaseRecord.model_validate_json(row["case_json"]) for row in rows]
        for item in cases:
            self._verify(item, "record_sha256")
            self._verify_audit_state(item)
        return CasePage(cases=[self._with_sla(item) for item in cases], count=int(count), limit=limit, offset=offset)

    def _mutate(self, principal: CasePrincipal, case_id: str, expected_version: int, updates: Dict[str, Any], action: str, permission: str) -> CaseRecord:
        self._require(principal, permission)
        operation_key, request_sha256 = self._operation_identity(
            principal, action, case_id, expected_version, updates
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._replay_operation(
                    principal,
                    operation_key,
                    action=action,
                    case_id=case_id,
                    request_sha256=request_sha256,
                    model_type=CaseRecord,
                    digest_field="record_sha256",
                )
                if replay is not None:
                    self._connection.execute("COMMIT")
                    return replay
                current = self._load(principal, case_id)
                if current.version != expected_version:
                    raise CaseConflictError("case version conflict")
                result = self._mutate_in_transaction(
                    principal, current, updates, action
                )
                self._record_operation(
                    principal,
                    operation_key,
                    action=action,
                    case_id=case_id,
                    request_sha256=request_sha256,
                    result=result,
                )
                self._connection.execute("COMMIT")
                return result
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def assign(self, principal: CasePrincipal, case_id: str, *, expected_version: int, assigned_to: Optional[str], team_id: Optional[str]) -> CaseRecord:
        if team_id is not None and re.fullmatch(r"team://[A-Za-z0-9_.@/-]+", team_id) is None:
            raise ValueError("invalid case team ID")
        if assigned_to is not None and re.fullmatch(r"^(analyst|system|workload)://[A-Za-z0-9_.@/-]+$", assigned_to) is None:
            raise ValueError("invalid case assignee")
        if CASE_ADMIN not in principal.permissions and team_id is not None and team_id not in principal.team_ids:
            raise CaseAuthorizationError("cannot assign a case outside the principal's teams")
        if team_id is None and assigned_to is not None:
            raise ValueError("case assignee requires a durable owner team")
        if team_id is not None:
            team = self._team(principal, team_id)
            if assigned_to is not None and assigned_to not in team.member_ids:
                raise CaseAuthorizationError("case assignee is not an authenticated team member")
        return self._mutate(principal, case_id, expected_version, {"assigned_to": assigned_to, "team_id": team_id}, "case_assigned", CASE_ASSIGN)

    def acknowledge(
        self, principal: CasePrincipal, case_id: str, *, expected_version: int
    ) -> CaseRecord:
        current = self._load(principal, case_id)
        if current.status in {CaseStatus.RESOLVED, CaseStatus.CLOSED}:
            raise CaseConflictError("resolved case cannot be acknowledged")
        if current.acknowledged_at is not None:
            raise CaseConflictError("case is already acknowledged")
        return self._mutate(
            principal,
            case_id,
            expected_version,
            {"acknowledged_at": self._now()},
            "case_acknowledged",
            CASE_WRITE,
        )

    def add_comment(self, principal: CasePrincipal, case_id: str, *, expected_version: int, body: str) -> CaseComment:
        self._require(principal, CASE_COMMENT)
        safe = str(self.redactor.redact(body).value)
        operation_key, request_sha256 = self._operation_identity(
            principal, "comment_added", case_id, expected_version, {"body": safe}
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._replay_operation(
                    principal, operation_key, action="comment_added", case_id=case_id,
                    request_sha256=request_sha256, model_type=CaseComment,
                    digest_field="comment_sha256",
                )
                if replay is not None:
                    self._connection.execute("COMMIT")
                    return replay
                case = self._load(principal, case_id)
                if case.version != expected_version:
                    raise CaseConflictError("case version conflict")
                self._ensure_child_capacity(
                    principal,
                    case_id,
                    "case_comments",
                    MAX_CASE_COMMENTS,
                    "comment",
                )
                unsigned = CaseComment(case_id=case_id, tenant_id=principal.tenant_id, actor_id=principal.actor_id, body=safe, created_at=self._now(), comment_sha256=ZERO_SHA256)
                item = self._signed(unsigned, "comment_sha256")
                assert isinstance(item, CaseComment)
                self._connection.execute("INSERT INTO case_comments VALUES (?, ?, ?, ?, ?, ?)", (item.tenant_id, item.case_id, item.comment_id, item.created_at.isoformat(), item.model_dump_json(), item.comment_sha256))
                self._mutate_in_transaction(principal, case, {}, "comment_added")
                self._record_operation(
                    principal, operation_key, action="comment_added", case_id=case_id,
                    request_sha256=request_sha256, result=item,
                )
                self._connection.execute("COMMIT")
                return item
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def _mutate_in_transaction(self, principal: CasePrincipal, current: CaseRecord, updates: Dict[str, Any], action: str) -> CaseRecord:
        updated = CaseRecord.model_validate(
            current.model_copy(
                update={
                    **updates,
                    "version": current.version + 1,
                    "updated_at": self._now(),
                    "record_sha256": ZERO_SHA256,
                }
            ).model_dump(mode="python")
        )
        audit = self._audit(
            principal,
            current.case_id,
            action,
            details={key: str(value) for key, value in updates.items()},
            from_status=current.status,
            to_status=updated.status,
        )
        return self._store_case(
            updated.model_copy(
                update={
                    "audit_count": audit.sequence,
                    "audit_head_sha256": audit.audit_sha256,
                }
            )
        )

    def create_task(self, principal: CasePrincipal, case_id: str, *, expected_version: int, title: str, description: str, assigned_to: Optional[str] = None, due_at: Optional[datetime] = None) -> CaseTask:
        self._require(principal, CASE_TASK)
        safe = self.redactor.redact({"title": title, "description": description}).value
        operation_key, request_sha256 = self._operation_identity(
            principal, "task_created", case_id, expected_version,
            {"title": safe["title"], "description": safe["description"], "assigned_to": assigned_to, "due_at": due_at},
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._replay_operation(
                    principal, operation_key, action="task_created", case_id=case_id,
                    request_sha256=request_sha256, model_type=CaseTask,
                    digest_field="task_sha256",
                )
                if replay is not None:
                    self._connection.execute("COMMIT")
                    return replay
                case = self._load(principal, case_id)
                if case.version != expected_version:
                    raise CaseConflictError("case version conflict")
                self._ensure_child_capacity(
                    principal, case_id, "case_tasks", MAX_CASE_TASKS, "task"
                )
                if assigned_to is not None:
                    if case.team_id is None:
                        raise CaseAuthorizationError("assigned task requires a case team")
                    if assigned_to not in self._team(principal, case.team_id).member_ids:
                        raise CaseAuthorizationError("task assignee is not a case-team member")
                unsigned = CaseTask(case_id=case_id, tenant_id=principal.tenant_id, title=str(safe["title"]), description=str(safe["description"]), assigned_to=assigned_to, due_at=due_at, created_by=principal.actor_id, created_at=self._now(), updated_at=self._now(), task_sha256=ZERO_SHA256)
                item = self._signed(unsigned, "task_sha256")
                assert isinstance(item, CaseTask)
                self._connection.execute("INSERT INTO case_tasks VALUES (?, ?, ?, ?, ?, ?, ?)", (item.tenant_id, item.case_id, item.task_id, item.status.value, item.updated_at.isoformat(), item.model_dump_json(), item.task_sha256))
                self._mutate_in_transaction(principal, case, {}, "task_created")
                self._record_operation(
                    principal, operation_key, action="task_created", case_id=case_id,
                    request_sha256=request_sha256, result=item,
                )
                self._connection.execute("COMMIT")
                return item
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def transition_task(self, principal: CasePrincipal, case_id: str, task_id: str, *, expected_version: int, status: CaseTaskStatus) -> CaseTask:
        self._require(principal, CASE_TASK)
        operation_key, request_sha256 = self._operation_identity(
            principal, "task_transitioned", case_id, expected_version,
            {"task_id": task_id, "status": status.value},
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._replay_operation(
                    principal, operation_key, action="task_transitioned", case_id=case_id,
                    request_sha256=request_sha256, model_type=CaseTask,
                    digest_field="task_sha256",
                )
                if replay is not None:
                    self._connection.execute("COMMIT")
                    return replay
                case = self._load(principal, case_id)
                if case.version != expected_version:
                    raise CaseConflictError("case version conflict")
                row = self._connection.execute("SELECT item_json FROM case_tasks WHERE tenant_id = ? AND case_id = ? AND task_id = ?", (principal.tenant_id, case_id, task_id)).fetchone()
                if row is None:
                    raise KeyError(task_id)
                current = CaseTask.model_validate_json(row["item_json"])
                self._verify(current, "task_sha256")
                allowed = {CaseTaskStatus.OPEN: {CaseTaskStatus.IN_PROGRESS, CaseTaskStatus.CANCELLED}, CaseTaskStatus.IN_PROGRESS: {CaseTaskStatus.DONE, CaseTaskStatus.CANCELLED}, CaseTaskStatus.DONE: set(), CaseTaskStatus.CANCELLED: set()}
                if status not in allowed[current.status]:
                    raise CaseConflictError("invalid case task transition")
                now = self._now()
                unsigned = current.model_copy(update={"status": status, "completed_by": principal.actor_id if status == CaseTaskStatus.DONE else None, "completed_at": now if status == CaseTaskStatus.DONE else None, "updated_at": now, "task_sha256": ZERO_SHA256})
                item = self._signed(CaseTask.model_validate(unsigned.model_dump(mode="python")), "task_sha256")
                assert isinstance(item, CaseTask)
                self._connection.execute("UPDATE case_tasks SET status=?, updated_at=?, item_json=?, item_sha256=? WHERE tenant_id=? AND task_id=?", (item.status.value, item.updated_at.isoformat(), item.model_dump_json(), item.task_sha256, item.tenant_id, item.task_id))
                self._mutate_in_transaction(principal, case, {}, "task_transitioned")
                self._record_operation(
                    principal, operation_key, action="task_transitioned", case_id=case_id,
                    request_sha256=request_sha256, result=item,
                )
                self._connection.execute("COMMIT")
                return item
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def add_attachment(self, principal: CasePrincipal, case_id: str, *, expected_version: int, display_name: str, media_type: str, size_bytes: int, content_sha256: str, evidence_ref: str) -> CaseAttachment:
        self._require(principal, CASE_ATTACH)
        safe_name = str(self.redactor.redact(display_name).value)
        payload = {"display_name": safe_name, "media_type": media_type, "size_bytes": size_bytes, "content_sha256": content_sha256, "evidence_ref": evidence_ref}
        operation_key, request_sha256 = self._operation_identity(
            principal, "attachment_registered", case_id, expected_version, payload
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._replay_operation(
                    principal, operation_key, action="attachment_registered",
                    case_id=case_id, request_sha256=request_sha256,
                    model_type=CaseAttachment, digest_field="attachment_sha256",
                )
                if replay is not None:
                    self._connection.execute("COMMIT")
                    return replay
                case = self._load(principal, case_id)
                if case.version != expected_version:
                    raise CaseConflictError("case version conflict")
                self._ensure_child_capacity(
                    principal,
                    case_id,
                    "case_attachments",
                    MAX_CASE_ATTACHMENTS,
                    "attachment",
                )
                duplicate = self._connection.execute(
                    "SELECT 1 FROM case_attachments WHERE tenant_id = ? AND case_id = ? AND json_extract(item_json, '$.content_sha256') = ?",
                    (principal.tenant_id, case_id, content_sha256),
                ).fetchone()
                if duplicate is not None:
                    raise CaseConflictError("attachment content digest already exists")
                unsigned = CaseAttachment(case_id=case_id, tenant_id=principal.tenant_id, display_name=safe_name, media_type=media_type, size_bytes=size_bytes, content_sha256=content_sha256, evidence_ref=evidence_ref, uploaded_by=principal.actor_id, created_at=self._now(), attachment_sha256=ZERO_SHA256)
                item = self._signed(unsigned, "attachment_sha256")
                assert isinstance(item, CaseAttachment)
                self._connection.execute("INSERT INTO case_attachments VALUES (?, ?, ?, ?, ?, ?)", (item.tenant_id, item.case_id, item.attachment_id, item.created_at.isoformat(), item.model_dump_json(), item.attachment_sha256))
                self._mutate_in_transaction(principal, case, {}, "attachment_registered")
                self._record_operation(
                    principal, operation_key, action="attachment_registered",
                    case_id=case_id, request_sha256=request_sha256, result=item,
                )
                self._connection.execute("COMMIT")
                return item
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def record_attachment_scan(
        self,
        principal: CasePrincipal,
        case_id: str,
        attachment_id: str,
        *,
        expected_version: int,
        status: AttachmentScanStatus,
        scanner_ref: str,
    ) -> CaseAttachment:
        self._require(principal, CASE_ADMIN)
        if status == AttachmentScanStatus.PENDING:
            raise ValueError("attachment scan verdict cannot remain pending")
        operation_key, request_sha256 = self._operation_identity(
            principal, "attachment_scan_recorded", case_id, expected_version,
            {"attachment_id": attachment_id, "status": status.value, "scanner_ref": scanner_ref},
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._replay_operation(
                    principal, operation_key, action="attachment_scan_recorded",
                    case_id=case_id, request_sha256=request_sha256,
                    model_type=CaseAttachment, digest_field="attachment_sha256",
                )
                if replay is not None:
                    self._connection.execute("COMMIT")
                    return replay
                case = self._load(principal, case_id)
                if case.version != expected_version:
                    raise CaseConflictError("case version conflict")
                row = self._connection.execute(
                    "SELECT item_json FROM case_attachments WHERE tenant_id = ? AND case_id = ? AND attachment_id = ?",
                    (principal.tenant_id, case_id, attachment_id),
                ).fetchone()
                if row is None:
                    raise KeyError(attachment_id)
                current = CaseAttachment.model_validate_json(row["item_json"])
                self._verify(current, "attachment_sha256")
                if current.scan_status != AttachmentScanStatus.PENDING:
                    raise CaseConflictError("attachment scan verdict is already final")
                unsigned = current.model_copy(
                    update={
                        "scan_status": status,
                        "scanner_ref": scanner_ref,
                        "scanned_at": self._now(),
                        "attachment_sha256": ZERO_SHA256,
                    }
                )
                item = self._signed(
                    CaseAttachment.model_validate(unsigned.model_dump(mode="python")),
                    "attachment_sha256",
                )
                assert isinstance(item, CaseAttachment)
                self._connection.execute(
                    "UPDATE case_attachments SET item_json = ?, item_sha256 = ? WHERE tenant_id = ? AND attachment_id = ?",
                    (
                        item.model_dump_json(),
                        item.attachment_sha256,
                        item.tenant_id,
                        item.attachment_id,
                    ),
                )
                self._mutate_in_transaction(
                    principal,
                    case,
                    {},
                    "attachment_scan_recorded",
                )
                self._record_operation(
                    principal, operation_key, action="attachment_scan_recorded",
                    case_id=case_id, request_sha256=request_sha256, result=item,
                )
                self._connection.execute("COMMIT")
                return item
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def add_relationship(self, principal: CasePrincipal, case_id: str, *, expected_version: int, kind: CaseRelationshipKind, target_type: str, target_id: str, reason: str = "Evidence-backed analyst relationship.") -> CaseRelationship:
        self._require(principal, CASE_WRITE)
        safe_reason = str(self.redactor.redact(reason).value)
        operation_key, request_sha256 = self._operation_identity(
            principal, "relationship_added", case_id, expected_version,
            {"kind": kind.value, "target_type": target_type, "target_id": target_id, "reason": safe_reason},
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._replay_operation(
                    principal, operation_key, action="relationship_added",
                    case_id=case_id, request_sha256=request_sha256,
                    model_type=CaseRelationship, digest_field="relationship_sha256",
                )
                if replay is not None:
                    self._connection.execute("COMMIT")
                    return replay
                case = self._load(principal, case_id)
                if case.version != expected_version:
                    raise CaseConflictError("case version conflict")
                self._ensure_child_capacity(
                    principal,
                    case_id,
                    "case_relationships",
                    MAX_CASE_RELATIONSHIPS,
                    "relationship",
                )
                if target_type == "case":
                    self._load(principal, target_id)
                existing = self._connection.execute(
                    "SELECT item_json FROM case_relationships WHERE tenant_id = ? AND case_id = ?",
                    (principal.tenant_id, case_id),
                ).fetchall()
                relationships = [CaseRelationship.model_validate_json(row["item_json"]) for row in existing]
                if any(item.kind == kind and item.target_type == target_type and item.target_id == target_id for item in relationships):
                    raise CaseConflictError("case relationship already exists")
                if kind == CaseRelationshipKind.PARENT and target_type == "case" and self._parent_relationship_cycle(principal, case_id, target_id):
                    raise CaseConflictError("parent relationship would create a cycle")
                unsigned = CaseRelationship(case_id=case_id, tenant_id=principal.tenant_id, kind=kind, target_type=target_type, target_id=target_id, reason=safe_reason, created_by=principal.actor_id, created_at=self._now(), relationship_sha256=ZERO_SHA256)
                item = self._signed(unsigned, "relationship_sha256")
                assert isinstance(item, CaseRelationship)
                self._connection.execute("INSERT INTO case_relationships VALUES (?, ?, ?, ?, ?, ?)", (item.tenant_id, item.case_id, item.relationship_id, item.created_at.isoformat(), item.model_dump_json(), item.relationship_sha256))
                self._mutate_in_transaction(principal, case, {}, "relationship_added")
                self._record_operation(
                    principal, operation_key, action="relationship_added",
                    case_id=case_id, request_sha256=request_sha256, result=item,
                )
                self._connection.execute("COMMIT")
                return item
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def _parent_relationship_cycle(
        self, principal: CasePrincipal, source_case_id: str, target_case_id: str
    ) -> bool:
        rows = self._connection.execute(
            "SELECT item_json FROM case_relationships WHERE tenant_id = ?",
            (principal.tenant_id,),
        ).fetchall()
        graph: Dict[str, Set[str]] = {}
        for row in rows:
            relation = CaseRelationship.model_validate_json(row["item_json"])
            self._verify(relation, "relationship_sha256")
            if relation.kind == CaseRelationshipKind.PARENT and relation.target_type == "case":
                graph.setdefault(relation.case_id, set()).add(relation.target_id)
        graph.setdefault(source_case_id, set()).add(target_case_id)
        pending = [target_case_id]
        visited: Set[str] = set()
        while pending:
            node = pending.pop()
            if node == source_case_id:
                return True
            if node not in visited:
                visited.add(node)
                pending.extend(graph.get(node, set()))
        return False

    def start_investigation(self, principal: CasePrincipal, case_id: str, *, expected_version: int) -> CaseRecord:
        current = self._load(principal, case_id)
        if current.status not in {CaseStatus.OPEN, CaseStatus.CLOSED}:
            raise CaseConflictError("case cannot start investigation from current state")
        now = self._now()
        reopening = current.status == CaseStatus.CLOSED
        resolution_minutes = current.sla_minutes
        acknowledgment_seconds = max(
            1, min(15 * 60, int(resolution_minutes * 60 * 0.25))
        )
        return self._mutate(
            principal,
            case_id,
            expected_version,
            {
                "status": CaseStatus.INVESTIGATING,
                "resolution_requested_by": None,
                "resolution_requested_at": None,
                "approved_by": None,
                "approved_at": None,
                "closed_by": None,
                "closed_at": None,
                "acknowledged_at": now,
                **(
                    {
                        "acknowledgment_due_at": now + timedelta(seconds=acknowledgment_seconds),
                        "due_at": now + timedelta(minutes=resolution_minutes),
                    }
                    if reopening
                    else {}
                ),
            },
            "case_reopened" if reopening else "investigation_started",
            CASE_WRITE,
        )

    def request_review(self, principal: CasePrincipal, case_id: str, *, expected_version: int) -> CaseRecord:
        current = self._load(principal, case_id)
        if current.status != CaseStatus.INVESTIGATING:
            raise CaseConflictError("case review requires investigation state")
        return self._mutate(principal, case_id, expected_version, {"status": CaseStatus.PENDING_REVIEW, "acknowledged_at": current.acknowledged_at or self._now(), "resolution_requested_by": principal.actor_id, "resolution_requested_at": self._now(), "approved_by": None, "approved_at": None}, "review_requested", CASE_WRITE)

    def review(self, principal: CasePrincipal, case_id: str, *, expected_version: int, decision: CaseReviewDecision, comment: str) -> CaseRecord:
        self._require(principal, CASE_REVIEW)
        safe_comment = str(self.redactor.redact(comment).value)
        operation_key, request_sha256 = self._operation_identity(
            principal,
            "case_reviewed",
            case_id,
            expected_version,
            {"decision": decision.value, "comment": safe_comment},
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._replay_operation(
                    principal,
                    operation_key,
                    action="case_reviewed",
                    case_id=case_id,
                    request_sha256=request_sha256,
                    model_type=CaseRecord,
                    digest_field="record_sha256",
                )
                if replay is not None:
                    self._connection.execute("COMMIT")
                    return replay
                case = self._load(principal, case_id)
                if case.version != expected_version:
                    raise CaseConflictError("case version conflict")
                if case.status != CaseStatus.PENDING_REVIEW:
                    raise CaseConflictError("case is not pending review")
                if case.resolution_requested_by == principal.actor_id:
                    raise CaseAuthorizationError("case review requires a different actor")
                self._ensure_child_capacity(
                    principal,
                    case_id,
                    "case_reviews",
                    MAX_CASE_REVIEWS,
                    "review",
                )
                open_tasks = self._connection.execute("SELECT COUNT(*) AS total FROM case_tasks WHERE tenant_id=? AND case_id=? AND status IN ('open','in_progress')", (principal.tenant_id, case_id)).fetchone()["total"]
                if decision == CaseReviewDecision.APPROVE and int(open_tasks) > 0:
                    raise CaseConflictError("open case tasks block resolution approval")
                attachments = self._connection.execute(
                    "SELECT item_json FROM case_attachments WHERE tenant_id=? AND case_id=?",
                    (principal.tenant_id, case_id),
                ).fetchall()
                unsafe_attachments = 0
                for row in attachments:
                    attachment = CaseAttachment.model_validate_json(row["item_json"])
                    self._verify(attachment, "attachment_sha256")
                    unsafe_attachments += attachment.scan_status != AttachmentScanStatus.CLEAN
                if decision == CaseReviewDecision.APPROVE and unsafe_attachments:
                    raise CaseConflictError("unscanned or quarantined attachments block resolution approval")
                unsigned = CaseReview(case_id=case_id, tenant_id=principal.tenant_id, decision=decision, reviewer_id=principal.actor_id, comment=safe_comment, created_at=self._now(), review_sha256=ZERO_SHA256)
                review = self._signed(unsigned, "review_sha256")
                assert isinstance(review, CaseReview)
                updates: Dict[str, Any]
                if decision == CaseReviewDecision.APPROVE:
                    updates = {"status": CaseStatus.RESOLVED, "approved_by": principal.actor_id, "approved_at": self._now()}
                elif decision == CaseReviewDecision.REQUEST_CHANGES:
                    updates = {"status": CaseStatus.INVESTIGATING, "resolution_requested_by": None, "resolution_requested_at": None, "approved_by": None, "approved_at": None}
                else:
                    next_priority = {"P3": "P2", "P2": "P1", "P1": "P0", "P0": "P0"}[case.priority]
                    updates = {"status": CaseStatus.INVESTIGATING, "priority": next_priority, "resolution_requested_by": None, "resolution_requested_at": None, "approved_by": None, "approved_at": None}
                self._connection.execute("INSERT INTO case_reviews VALUES (?, ?, ?, ?, ?, ?)", (review.tenant_id, review.case_id, review.review_id, review.created_at.isoformat(), review.model_dump_json(), review.review_sha256))
                result = self._mutate_in_transaction(principal, case, updates, "case_reviewed")
                self._record_operation(
                    principal,
                    operation_key,
                    action="case_reviewed",
                    case_id=case_id,
                    request_sha256=request_sha256,
                    result=result,
                )
                self._connection.execute("COMMIT")
                return result
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def close_case(self, principal: CasePrincipal, case_id: str, *, expected_version: int) -> CaseRecord:
        current = self._load(principal, case_id)
        if current.status != CaseStatus.RESOLVED:
            raise CaseConflictError("only an independently approved case can close")
        return self._mutate(principal, case_id, expected_version, {"status": CaseStatus.CLOSED, "closed_by": principal.actor_id, "closed_at": self._now()}, "case_closed", CASE_REVIEW)

    def health(self, principal: CasePrincipal) -> CaseHealth:
        self._require(principal, CASE_READ)
        cases: List[CaseRecord] = []
        offset = 0
        total = 0
        while True:
            page = self.list(principal, limit=MAX_CASE_PAGE, offset=offset)
            total = page.count
            cases.extend(page.cases)
            offset += len(page.cases)
            if offset >= total or not page.cases:
                break
        task_clauses = ["t.tenant_id = ?", "t.status IN ('open','in_progress')"]
        task_values: List[Any] = [principal.tenant_id]
        if CASE_ADMIN not in principal.permissions:
            if principal.team_ids:
                placeholders = ",".join("?" for _ in principal.team_ids)
                task_clauses.append(
                    "(c.team_id IS NULL OR c.team_id IN (%s))" % placeholders
                )
                task_values.extend(sorted(principal.team_ids))
            else:
                task_clauses.append("c.team_id IS NULL")
        with self._lock:
            open_tasks = self._connection.execute(
                "SELECT COUNT(*) AS total FROM case_tasks t "
                "JOIN cases c ON c.tenant_id=t.tenant_id AND c.case_id=t.case_id "
                "WHERE %s" % " AND ".join(task_clauses),
                task_values,
            ).fetchone()["total"]
        return CaseHealth(
            tenant_id=principal.tenant_id,
            total_cases=total,
            open_cases=sum(item.status not in {CaseStatus.RESOLVED, CaseStatus.CLOSED} for item in cases),
            pending_review=sum(item.status == CaseStatus.PENDING_REVIEW for item in cases),
            breached_sla=sum(item.sla_state == CaseSlaState.BREACHED for item in cases),
            acknowledgment_breaches=sum(
                (item.acknowledged_at or self._now()) > item.acknowledgment_due_at
                for item in cases
            ),
            resolution_breaches=sum(
                (item.approved_at or self._now()) > item.due_at
                for item in cases
            ),
            unassigned_cases=sum(
                item.assigned_to is None
                for item in cases
                if item.status not in {CaseStatus.RESOLVED, CaseStatus.CLOSED}
            ),
            closed_cases=sum(item.status == CaseStatus.CLOSED for item in cases),
            open_tasks=int(open_tasks),
            calculated_at=self._now(),
        )


def case_service_from_environment(
    database_path: str, *, tenant_id: str
) -> tuple[CaseService, CasePrincipal]:
    service = CaseService(database_path)
    principal = CasePrincipal(
        tenant_id=tenant_id,
        actor_id="system://local-case-service",
        permissions={CASE_READ, CASE_WRITE, CASE_ASSIGN, CASE_COMMENT, CASE_TASK, CASE_ATTACH, CASE_REVIEW, CASE_ADMIN},
        team_ids={"team://local-security"},
    )
    service.ensure_team(
        principal,
        team_id="team://local-security",
        name="Local security operations",
        description="Default bounded team for the local AgentSec case service.",
        member_ids={
            "system://local-case-service",
            "system://local-case-requester",
            "system://local-case-reviewer",
        },
    )
    return service, principal


__all__ = [
    "CASE_ADMIN", "CASE_ASSIGN", "CASE_ATTACH", "CASE_COMMENT", "CASE_READ",
    "CASE_REVIEW", "CASE_TASK", "CASE_WRITE", "AttachmentScanStatus",
    "CaseAssignmentRequest", "CaseAttachment", "CaseAttachmentRequest",
    "CaseAttachmentScanRequest",
    "CaseAuditEntry", "CaseAuthorizationError", "CaseComment", "CaseConflictError",
    "CaseCommentRequest", "CaseDetail", "CaseHealth", "CaseLifecycleRequest", "CasePage",
    "CasePrincipal", "CaseRecord", "CaseRelationship", "CaseRelationshipKind", "CaseTeam",
    "CaseRelationshipRequest", "CaseReview", "CaseReviewDecision", "CaseReviewRequest",
    "CaseService", "CaseSlaState", "CaseStatus", "CaseTask", "CaseTaskCreateRequest",
    "CaseTaskStatus", "CaseTaskTransitionRequest", "CaseTeamCreateRequest",
    "case_service_from_environment",
]
