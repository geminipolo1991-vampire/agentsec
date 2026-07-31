"""Signed detection-content lifecycle, validation, shadowing, and packs."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
import sqlite3
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from pydantic import Field, field_validator, model_validator

from .contracts import AgentEvent, SecurityAlert, StrictModel, new_id, utc_now
from .crypto import PocHmacSigner, canonical_bytes
from .detection import (
    DETECTION_ADMIN,
    DETECTION_READ,
    DETECTION_RUN,
    DetectionExecutionMode,
    DetectionPrincipal,
    DetectionRuleDefinition,
    DetectionRuleHealth,
    DetectionService,
)


CONTENT_READ = "content:read"
CONTENT_WRITE = "content:write"
CONTENT_REVIEW = "content:review"
CONTENT_PUBLISH = "content:publish"
CONTENT_ADMIN = "content:admin"
MAX_CONTENT_EVENTS = 1000


class ContentAuthorizationError(PermissionError):
    """Raised when a content principal lacks a required permission."""


class RuleContentStatus(str, Enum):
    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    SHADOW = "shadow"
    PUBLISHED = "published"
    RETIRED = "retired"


class ReviewDecision(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"


class ContentPrincipal(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=3, max_length=256)
    permissions: Set[str] = Field(default_factory=set, max_length=16)

    @field_validator("permissions")
    @classmethod
    def valid_permissions(cls, value: Set[str]) -> Set[str]:
        if any(re.fullmatch(r"[a-z]+:[a-z]+", item) is None for item in value):
            raise ValueError("content permissions must use namespace:operation")
        return value


class RuleTestSuite(StrictModel):
    name: str = Field(min_length=3, max_length=256)
    events: List[AgentEvent] = Field(min_length=1, max_length=MAX_CONTENT_EVENTS)
    expected_alert_event_ids: Set[str] = Field(default_factory=set, max_length=MAX_CONTENT_EVENTS)

    @model_validator(mode="after")
    def expected_events_exist(self) -> "RuleTestSuite":
        event_ids = {item.event_id for item in self.events}
        if len(event_ids) != len(self.events):
            raise ValueError("content test event IDs must be unique")
        if not self.expected_alert_event_ids.issubset(event_ids):
            raise ValueError("expected alert IDs must refer to supplied events")
        if len({item.tenant_id for item in self.events}) != 1:
            raise ValueError("content test suite must use one tenant")
        return self


class RuleValidationResult(StrictModel):
    suite_name: str
    definition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_count: int = Field(ge=1, le=MAX_CONTENT_EVENTS)
    expected_alert_event_ids: List[str]
    actual_alert_event_ids: List[str]
    false_positive_event_ids: List[str]
    false_negative_event_ids: List[str]
    errors: List[str]
    passed: bool
    duration_ms: int = Field(ge=0)
    completed_at: datetime


class RuleBacktestResult(StrictModel):
    definition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_count: int = Field(ge=1, le=MAX_CONTENT_EVENTS)
    alert_count: int = Field(ge=0)
    matched_event_ids: List[str]
    alert_types: List[str]
    errors: List[str]
    match_rate: float = Field(ge=0.0, le=1.0)
    result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    duration_ms: int = Field(ge=0)
    completed_at: datetime


class RuleContentRecord(StrictModel):
    content_id: str = Field(pattern=r"^drc_[A-Za-z0-9]+$")
    tenant_id: str
    revision: int = Field(ge=1)
    status: RuleContentStatus
    definition: DetectionRuleDefinition
    author_id: str
    created_at: datetime
    updated_at: datetime
    submitted_at: Optional[datetime] = None
    reviewed_at: Optional[datetime] = None
    reviewer_id: Optional[str] = None
    review_comment: Optional[str] = None
    shadowed_at: Optional[datetime] = None
    published_at: Optional[datetime] = None
    retired_at: Optional[datetime] = None
    source_pack_id: Optional[str] = None
    validation: Optional[RuleValidationResult] = None
    backtest: Optional[RuleBacktestResult] = None
    shadow_result: Optional[RuleBacktestResult] = None
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature_algorithm: str
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")


class ContentPackEntry(StrictModel):
    definition: DetectionRuleDefinition
    definition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SignedContentPack(StrictModel):
    schema_version: str = "1.0.0"
    pack_id: str = Field(pattern=r"^dpack_[A-Za-z0-9]+$")
    version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    tenant_id: str
    name: str = Field(min_length=3, max_length=256)
    description: str = Field(min_length=3, max_length=1024)
    entries: List[ContentPackEntry] = Field(min_length=1, max_length=256)
    created_by: str
    created_at: datetime
    pack_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature_algorithm: str
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def unique_rule_versions(self) -> "SignedContentPack":
        identities = [
            (item.definition.rule_id, item.definition.version)
            for item in self.entries
        ]
        if len(set(identities)) != len(identities):
            raise ValueError("content pack rule versions must be unique")
        return self


class ContentHealthSummary(StrictModel):
    tenant_id: str
    total_content: int = Field(ge=0)
    draft: int = Field(ge=0)
    in_review: int = Field(ge=0)
    approved: int = Field(ge=0)
    shadow: int = Field(ge=0)
    published: int = Field(ge=0)
    rejected: int = Field(ge=0)
    retired: int = Field(ge=0)
    validation_failures: int = Field(ge=0)
    rule_health: List[DetectionRuleHealth]
    calculated_at: datetime


def _definition_digest(definition: DetectionRuleDefinition) -> str:
    return hashlib.sha256(
        canonical_bytes(definition.model_dump(mode="json"))
    ).hexdigest()


def _version_key(value: str) -> Tuple[Tuple[int, Any], ...]:
    return tuple(
        (0, int(token)) if token.isdigit() else (1, token.casefold())
        for token in re.findall(r"[0-9]+|[A-Za-z]+", value)
    )


class DetectionContentService:
    """Append-only signed content workflow in front of a DetectionService."""

    def __init__(
        self,
        path: str,
        *,
        detection_service: DetectionService,
        detection_principal: DetectionPrincipal,
        signer: PocHmacSigner,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if not {DETECTION_READ, DETECTION_RUN, DETECTION_ADMIN}.issubset(
            detection_principal.permissions
        ):
            raise ValueError("content target detection principal lacks required permissions")
        self.path = path
        self.detection_service = detection_service
        self.detection_principal = detection_principal
        self.signer = signer
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
            raise ValueError("content clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _require(principal: ContentPrincipal, permission: str) -> None:
        if permission not in principal.permissions:
            raise ContentAuthorizationError("missing content permission: %s" % permission)

    def _tenant(self, principal: ContentPrincipal) -> None:
        if principal.tenant_id != self.detection_principal.tenant_id:
            raise ContentAuthorizationError("content and detection tenants do not match")

    def _migrate(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS detection_content (
                tenant_id TEXT NOT NULL, content_id TEXT NOT NULL, revision INTEGER NOT NULL,
                rule_id TEXT NOT NULL, rule_version TEXT NOT NULL, status TEXT NOT NULL,
                author_id TEXT NOT NULL, content_json TEXT NOT NULL,
                record_sha256 TEXT NOT NULL, signature TEXT NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL, current INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, content_id, revision)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS detection_content_current
                ON detection_content(tenant_id, content_id) WHERE current = 1;
            CREATE INDEX IF NOT EXISTS detection_content_status
                ON detection_content(tenant_id, status, updated_at);
            CREATE TABLE IF NOT EXISTS detection_content_packs (
                tenant_id TEXT NOT NULL, pack_id TEXT NOT NULL, version TEXT NOT NULL,
                pack_json TEXT NOT NULL, pack_sha256 TEXT NOT NULL, signature TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, pack_id, version)
            );
            CREATE TABLE IF NOT EXISTS detection_content_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL,
                actor_id TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL,
                occurred_at TEXT NOT NULL
            );
            """
        )

    def _audit(self, principal: ContentPrincipal, action: str, subject: str) -> None:
        self._connection.execute(
            "INSERT INTO detection_content_audit(tenant_id, actor_id, action, subject, occurred_at) VALUES (?, ?, ?, ?, ?)",
            (principal.tenant_id, principal.actor_id, action, subject[:512], self._now().isoformat()),
        )

    def _seal(self, payload: Dict[str, Any]) -> RuleContentRecord:
        candidate = RuleContentRecord.model_validate({
            **payload,
            "record_sha256": "0" * 64,
            "signature_algorithm": self.signer.algorithm,
            "signature": "0" * 64,
        })
        unsigned = candidate.model_dump(
            mode="json",
            exclude={"record_sha256", "signature_algorithm", "signature"},
        )
        digest = hashlib.sha256(canonical_bytes(unsigned)).hexdigest()
        signed = dict(unsigned)
        signed["record_sha256"] = digest
        signature = self.signer.sign(signed)
        signed["signature_algorithm"] = self.signer.algorithm
        signed["signature"] = signature
        return RuleContentRecord.model_validate(signed)

    def _verify_record(self, record: RuleContentRecord) -> None:
        payload = record.model_dump(mode="json")
        signature = payload.pop("signature")
        algorithm = payload.pop("signature_algorithm")
        digest = payload.pop("record_sha256")
        if algorithm != self.signer.algorithm:
            raise ValueError("content signature algorithm is invalid")
        if hashlib.sha256(canonical_bytes(payload)).hexdigest() != digest:
            raise ValueError("content record digest is invalid")
        payload["record_sha256"] = digest
        if not self.signer.verify(payload, signature):
            raise ValueError("content record signature is invalid")

    def _row(self, row: sqlite3.Row) -> RuleContentRecord:
        record = RuleContentRecord.model_validate_json(row["content_json"])
        self._verify_record(record)
        return record

    def _append(
        self,
        principal: ContentPrincipal,
        payload: Dict[str, Any],
        action: str,
    ) -> RuleContentRecord:
        record = self._seal(payload)
        current = self._connection.execute(
            "SELECT revision FROM detection_content WHERE tenant_id = ? AND content_id = ? AND current = 1",
            (principal.tenant_id, record.content_id),
        ).fetchone()
        expected_revision = 1 if current is None else int(current["revision"]) + 1
        if record.revision != expected_revision:
            raise ValueError("content revision is not monotonic")
        if current is not None:
            self._connection.execute(
                "UPDATE detection_content SET current = 0 WHERE tenant_id = ? AND content_id = ? AND current = 1",
                (principal.tenant_id, record.content_id),
            )
        self._connection.execute(
            "INSERT INTO detection_content(tenant_id, content_id, revision, rule_id, rule_version, status, author_id, content_json, record_sha256, signature, created_at, updated_at, current) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
            (
                principal.tenant_id, record.content_id, record.revision,
                record.definition.rule_id, record.definition.version, record.status.value,
                record.author_id, record.model_dump_json(), record.record_sha256,
                record.signature, record.created_at.isoformat(), record.updated_at.isoformat(),
            ),
        )
        self._audit(principal, action, "%s:r%d" % (record.content_id, record.revision))
        return record

    def _current(self, principal: ContentPrincipal, content_id: str) -> RuleContentRecord:
        if re.fullmatch(r"drc_[A-Za-z0-9]+", content_id) is None:
            raise ValueError("content ID is invalid")
        row = self._connection.execute(
            "SELECT * FROM detection_content WHERE tenant_id = ? AND content_id = ? AND current = 1",
            (principal.tenant_id, content_id),
        ).fetchone()
        if row is None:
            raise KeyError(content_id)
        return self._row(row)

    def create_draft(
        self,
        principal: ContentPrincipal,
        definition: DetectionRuleDefinition,
        *,
        source_pack_id: Optional[str] = None,
    ) -> RuleContentRecord:
        self._require(principal, CONTENT_WRITE)
        self._tenant(principal)
        if not definition.enabled:
            raise ValueError("draft definition must be enabled before publication workflow")
        now = self._now()
        content_id = new_id("drc")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                exists = self._connection.execute(
                    "SELECT 1 FROM detection_content WHERE tenant_id = ? AND rule_id = ? AND rule_version = ? LIMIT 1",
                    (principal.tenant_id, definition.rule_id, definition.version),
                ).fetchone()
                if exists is not None:
                    raise ValueError("content for this rule version already exists")
                record = self._append(
                    principal,
                    {
                        "content_id": content_id, "tenant_id": principal.tenant_id,
                        "revision": 1, "status": RuleContentStatus.DRAFT,
                        "definition": definition, "author_id": principal.actor_id,
                        "created_at": now, "updated_at": now,
                        "source_pack_id": source_pack_id,
                    },
                    "content.create",
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return record

    def update_draft(
        self,
        principal: ContentPrincipal,
        content_id: str,
        definition: DetectionRuleDefinition,
    ) -> RuleContentRecord:
        self._require(principal, CONTENT_WRITE)
        self._tenant(principal)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                current = self._current(principal, content_id)
                if current.status not in {RuleContentStatus.DRAFT, RuleContentStatus.REJECTED}:
                    raise ValueError("only draft or rejected content can be edited")
                if current.author_id != principal.actor_id and CONTENT_ADMIN not in principal.permissions:
                    raise ContentAuthorizationError("only the author or content admin can edit")
                if (
                    definition.rule_id != current.definition.rule_id
                    or definition.version != current.definition.version
                ):
                    raise ValueError("draft rule identity and version are immutable")
                payload = current.model_dump(mode="python", exclude={
                    "record_sha256", "signature_algorithm", "signature"
                })
                payload.update({
                    "revision": current.revision + 1,
                    "status": RuleContentStatus.DRAFT,
                    "definition": definition,
                    "updated_at": self._now(),
                    "submitted_at": None, "reviewed_at": None,
                    "reviewer_id": None, "review_comment": None,
                    "shadowed_at": None, "published_at": None, "retired_at": None,
                    "validation": None, "backtest": None, "shadow_result": None,
                })
                record = self._append(principal, payload, "content.update")
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return record

    def get(self, principal: ContentPrincipal, content_id: str) -> RuleContentRecord:
        self._require(principal, CONTENT_READ)
        self._tenant(principal)
        with self._lock:
            record = self._current(principal, content_id)
            self._audit(principal, "content.read", content_id)
        return record

    def list(
        self,
        principal: ContentPrincipal,
        *,
        status: Optional[RuleContentStatus] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[RuleContentRecord]:
        self._require(principal, CONTENT_READ)
        self._tenant(principal)
        if not 1 <= limit <= 200 or not 0 <= offset <= 100000:
            raise ValueError("content pagination is invalid")
        clauses = ["tenant_id = ?", "current = 1"]
        values: List[Any] = [principal.tenant_id]
        if status is not None:
            clauses.append("status = ?")
            values.append(status.value)
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM detection_content WHERE " + " AND ".join(clauses)
                + " ORDER BY updated_at DESC, content_id LIMIT ? OFFSET ?",
                (*values, limit, offset),
            ).fetchall()
            self._audit(principal, "content.list", status.value if status else "all")
        return [self._row(row) for row in rows]

    def history(
        self, principal: ContentPrincipal, content_id: str
    ) -> List[RuleContentRecord]:
        self._require(principal, CONTENT_READ)
        self._tenant(principal)
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM detection_content WHERE tenant_id = ? AND content_id = ? ORDER BY revision",
                (principal.tenant_id, content_id),
            ).fetchall()
        if not rows:
            raise KeyError(content_id)
        return [self._row(row) for row in rows]

    def _evaluate(
        self,
        definition: DetectionRuleDefinition,
        events: Sequence[AgentEvent],
    ) -> Tuple[List[SecurityAlert], List[str]]:
        temporary = DetectionService(":memory:", semantic_provider=self.detection_service.semantic_provider, clock=self.clock)
        principal = DetectionPrincipal(
            tenant_id=self.detection_principal.tenant_id,
            actor_id="system://content-validation",
            permissions={DETECTION_READ, DETECTION_RUN, DETECTION_ADMIN},
        )
        try:
            temporary.register_rule(principal, definition)
            alerts: List[SecurityAlert] = []
            errors: List[str] = []
            ordered = sorted(events, key=lambda item: (item.occurred_at, item.event_id))
            if definition.execution_mode == DetectionExecutionMode.SCHEDULED:
                for event in ordered:
                    temporary.capture_event(principal, event)
                result = temporary.run_scheduled(
                    principal, as_of=ordered[-1].occurred_at,
                    rule_ids=[definition.rule_id],
                )
                alerts.extend(result.alerts)
                errors.extend(result.errors)
            else:
                for event in ordered:
                    result = temporary.stream(
                        principal, event, rule_ids=[definition.rule_id]
                    )
                    alerts.extend(result.alerts)
                    errors.extend(result.errors)
            return list({item.fingerprint: item for item in alerts}.values()), errors
        finally:
            temporary.close()

    def validate(
        self,
        principal: ContentPrincipal,
        content_id: str,
        suite: RuleTestSuite,
    ) -> RuleContentRecord:
        self._require(principal, CONTENT_WRITE)
        self._tenant(principal)
        if suite.events[0].tenant_id != principal.tenant_id:
            raise ContentAuthorizationError("content test tenant is forbidden")
        with self._lock:
            current = self._current(principal, content_id)
        if current.status not in {RuleContentStatus.DRAFT, RuleContentStatus.REJECTED}:
            raise ValueError("only draft or rejected content can be tested")
        started = time.perf_counter()
        alerts, errors = self._evaluate(current.definition, suite.events)
        actual = {item.event_id for item in alerts}
        expected = set(suite.expected_alert_event_ids)
        result = RuleValidationResult(
            suite_name=suite.name,
            definition_sha256=_definition_digest(current.definition),
            event_count=len(suite.events),
            expected_alert_event_ids=sorted(expected),
            actual_alert_event_ids=sorted(actual),
            false_positive_event_ids=sorted(actual - expected),
            false_negative_event_ids=sorted(expected - actual),
            errors=errors,
            passed=not errors and actual == expected,
            duration_ms=max(0, round((time.perf_counter() - started) * 1000)),
            completed_at=self._now(),
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                latest = self._current(principal, content_id)
                if latest.revision != current.revision:
                    raise ValueError("content changed during validation")
                payload = latest.model_dump(mode="python", exclude={
                    "record_sha256", "signature_algorithm", "signature"
                })
                payload.update({
                    "revision": latest.revision + 1,
                    "status": RuleContentStatus.DRAFT,
                    "validation": result,
                    "updated_at": self._now(),
                })
                record = self._append(principal, payload, "content.validate")
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return record

    def backtest(
        self,
        principal: ContentPrincipal,
        content_id: str,
        events: Sequence[AgentEvent],
        *,
        shadow: bool = False,
    ) -> RuleContentRecord:
        self._require(principal, CONTENT_WRITE if not shadow else CONTENT_PUBLISH)
        self._tenant(principal)
        if not 1 <= len(events) <= MAX_CONTENT_EVENTS:
            raise ValueError("content backtest event count is invalid")
        if any(item.tenant_id != principal.tenant_id for item in events):
            raise ContentAuthorizationError("content backtest tenant is forbidden")
        with self._lock:
            current = self._current(principal, content_id)
        if shadow and current.status != RuleContentStatus.SHADOW:
            raise ValueError("shadow evaluation requires shadow status")
        if not shadow and current.status not in {
            RuleContentStatus.DRAFT, RuleContentStatus.REJECTED,
            RuleContentStatus.APPROVED, RuleContentStatus.SHADOW,
        }:
            raise ValueError("content status cannot be backtested")
        started = time.perf_counter()
        alerts, errors = self._evaluate(current.definition, events)
        matched = sorted({item.event_id for item in alerts})
        result_payload = {
            "definition_sha256": _definition_digest(current.definition),
            "event_count": len(events), "alert_count": len(alerts),
            "matched_event_ids": matched,
            "alert_types": sorted({item.alert_type for item in alerts}),
            "errors": errors,
            "match_rate": len(matched) / len(events),
        }
        digest = hashlib.sha256(canonical_bytes(result_payload)).hexdigest()
        result = RuleBacktestResult(
            **result_payload,
            result_sha256=digest,
            duration_ms=max(0, round((time.perf_counter() - started) * 1000)),
            completed_at=self._now(),
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                latest = self._current(principal, content_id)
                if latest.revision != current.revision:
                    raise ValueError("content changed during backtest")
                payload = latest.model_dump(mode="python", exclude={
                    "record_sha256", "signature_algorithm", "signature"
                })
                payload.update({
                    "revision": latest.revision + 1,
                    "updated_at": self._now(),
                    "shadow_result" if shadow else "backtest": result,
                })
                record = self._append(
                    principal, payload,
                    "content.shadow.evaluate" if shadow else "content.backtest",
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return record

    def submit(self, principal: ContentPrincipal, content_id: str) -> RuleContentRecord:
        self._require(principal, CONTENT_WRITE)
        return self._status_transition(
            principal, content_id, {RuleContentStatus.DRAFT},
            RuleContentStatus.IN_REVIEW, "content.submit",
            require_validation=True,
        )

    def review(
        self,
        principal: ContentPrincipal,
        content_id: str,
        decision: ReviewDecision,
        comment: str,
    ) -> RuleContentRecord:
        self._require(principal, CONTENT_REVIEW)
        self._tenant(principal)
        if not 3 <= len(comment.strip()) <= 1024:
            raise ValueError("content review comment is invalid")
        with self._lock:
            current = self._current(principal, content_id)
        if current.status != RuleContentStatus.IN_REVIEW:
            raise ValueError("content is not awaiting review")
        if current.author_id == principal.actor_id:
            raise ContentAuthorizationError("content author cannot review their own rule")
        target = (
            RuleContentStatus.APPROVED
            if decision == ReviewDecision.APPROVE
            else RuleContentStatus.REJECTED
        )
        return self._status_transition(
            principal, content_id, {RuleContentStatus.IN_REVIEW}, target,
            "content.review.%s" % decision.value,
            extra={
                "reviewed_at": self._now(), "reviewer_id": principal.actor_id,
                "review_comment": comment.strip(),
            },
        )

    def deploy_shadow(
        self, principal: ContentPrincipal, content_id: str
    ) -> RuleContentRecord:
        self._require(principal, CONTENT_PUBLISH)
        return self._status_transition(
            principal, content_id, {RuleContentStatus.APPROVED},
            RuleContentStatus.SHADOW, "content.shadow.deploy",
            extra={"shadowed_at": self._now()},
        )

    def _status_transition(
        self,
        principal: ContentPrincipal,
        content_id: str,
        allowed: Set[RuleContentStatus],
        target: RuleContentStatus,
        action: str,
        *,
        require_validation: bool = False,
        extra: Optional[Dict[str, Any]] = None,
    ) -> RuleContentRecord:
        self._tenant(principal)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                current = self._current(principal, content_id)
                if current.status not in allowed:
                    raise ValueError("invalid content lifecycle transition")
                if require_validation and (
                    current.validation is None or not current.validation.passed
                    or current.validation.definition_sha256 != _definition_digest(current.definition)
                ):
                    raise ValueError("passing validation for this definition is required")
                payload = current.model_dump(mode="python", exclude={
                    "record_sha256", "signature_algorithm", "signature"
                })
                payload.update({
                    "revision": current.revision + 1,
                    "status": target,
                    "updated_at": self._now(),
                })
                if target == RuleContentStatus.IN_REVIEW:
                    payload["submitted_at"] = self._now()
                if extra:
                    payload.update(extra)
                record = self._append(principal, payload, action)
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return record

    def publish(
        self,
        principal: ContentPrincipal,
        content_id: str,
        *,
        expected_definition_sha256: str,
    ) -> RuleContentRecord:
        self._require(principal, CONTENT_PUBLISH)
        self._tenant(principal)
        with self._lock:
            current = self._current(principal, content_id)
        if current.status != RuleContentStatus.SHADOW or current.shadow_result is None:
            raise ValueError("published content requires completed shadow evaluation")
        if current.shadow_result.errors:
            raise ValueError("shadow evaluation errors block publication")
        digest = _definition_digest(current.definition)
        if expected_definition_sha256 != digest:
            raise ValueError("published content digest acknowledgement is stale")
        self.detection_service.register_rule(
            self.detection_principal, current.definition
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                prior_rows = self._connection.execute(
                    "SELECT * FROM detection_content WHERE tenant_id = ? AND current = 1 AND rule_id = ? AND status = 'published' AND content_id != ?",
                    (principal.tenant_id, current.definition.rule_id, content_id),
                ).fetchall()
                for row in prior_rows:
                    prior = self._row(row)
                    payload = prior.model_dump(mode="python", exclude={
                        "record_sha256", "signature_algorithm", "signature"
                    })
                    payload.update({
                        "revision": prior.revision + 1,
                        "status": RuleContentStatus.RETIRED,
                        "retired_at": self._now(), "updated_at": self._now(),
                    })
                    self._append(principal, payload, "content.retire")
                latest = self._current(principal, content_id)
                if latest.revision != current.revision:
                    raise ValueError("content changed during publication")
                payload = latest.model_dump(mode="python", exclude={
                    "record_sha256", "signature_algorithm", "signature"
                })
                payload.update({
                    "revision": latest.revision + 1,
                    "status": RuleContentStatus.PUBLISHED,
                    "published_at": self._now(), "updated_at": self._now(),
                })
                record = self._append(principal, payload, "content.publish")
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return record

    def rollback(
        self,
        principal: ContentPrincipal,
        target_content_id: str,
        *,
        new_version: str,
        reason: str,
    ) -> RuleContentRecord:
        self._require(principal, CONTENT_PUBLISH)
        self._tenant(principal)
        if not 10 <= len(reason.strip()) <= 1024:
            raise ValueError("rollback reason is invalid")
        history = self.history(principal, target_content_id)
        published = [item for item in history if item.status == RuleContentStatus.PUBLISHED]
        if not published:
            raise ValueError("rollback target was never published")
        target = published[-1]
        current_rules = {
            item.definition.rule_id: item.definition
            for item in self.detection_service.list_rules(self.detection_principal)
        }
        current = current_rules.get(target.definition.rule_id)
        if current is None or _version_key(new_version) <= _version_key(current.version):
            raise ValueError("rollback must use a new increasing rule version")
        definition = target.definition.model_copy(update={"version": new_version})
        # Reject a duplicate content version before mutating the separate live-rule
        # registry. Publication spans two durable stores, so ordering the checks this
        # way avoids a known split-brain failure mode without pretending that SQLite
        # can provide a transaction across both databases.
        with self._lock:
            existing = self._connection.execute(
                "SELECT 1 FROM detection_content WHERE tenant_id = ? AND rule_id = ? AND rule_version = ? LIMIT 1",
                (principal.tenant_id, definition.rule_id, definition.version),
            ).fetchone()
        if existing is not None:
            raise ValueError("rollback content version already exists")
        self.detection_service.register_rule(self.detection_principal, definition)
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                # Keep the transaction-time check to close the race between the
                # preflight query and this writer lock.
                existing = self._connection.execute(
                    "SELECT 1 FROM detection_content WHERE tenant_id = ? AND rule_id = ? AND rule_version = ? LIMIT 1",
                    (principal.tenant_id, definition.rule_id, definition.version),
                ).fetchone()
                if existing is not None:
                    raise ValueError("rollback content version already exists")
                record = self._append(
                    principal,
                    {
                        "content_id": new_id("drc"), "tenant_id": principal.tenant_id,
                        "revision": 1, "status": RuleContentStatus.PUBLISHED,
                        "definition": definition, "author_id": principal.actor_id,
                        "created_at": now, "updated_at": now,
                        "submitted_at": now, "reviewed_at": now,
                        "reviewer_id": target.reviewer_id,
                        "review_comment": "Rollback: %s" % reason.strip(),
                        "shadowed_at": now, "published_at": now,
                        "validation": target.validation,
                        "backtest": target.backtest,
                        "shadow_result": target.shadow_result,
                    },
                    "content.rollback",
                )
                current_published = self._connection.execute(
                    "SELECT * FROM detection_content WHERE tenant_id = ? AND current = 1 AND rule_id = ? AND status = 'published' AND content_id != ?",
                    (principal.tenant_id, definition.rule_id, record.content_id),
                ).fetchall()
                for row in current_published:
                    prior = self._row(row)
                    payload = prior.model_dump(mode="python", exclude={
                        "record_sha256", "signature_algorithm", "signature"
                    })
                    payload.update({
                        "revision": prior.revision + 1,
                        "status": RuleContentStatus.RETIRED,
                        "retired_at": now, "updated_at": now,
                    })
                    self._append(principal, payload, "content.retire.rollback")
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return record

    @staticmethod
    def _pack_unsigned(pack: SignedContentPack) -> Dict[str, Any]:
        return pack.model_dump(
            mode="json", exclude={"pack_sha256", "signature_algorithm", "signature"}
        )

    def export_pack(
        self,
        principal: ContentPrincipal,
        content_ids: Sequence[str],
        *,
        name: str,
        description: str,
        version: str,
    ) -> SignedContentPack:
        self._require(principal, CONTENT_PUBLISH)
        self._tenant(principal)
        if not 1 <= len(content_ids) <= 256 or len(set(content_ids)) != len(content_ids):
            raise ValueError("content pack selection is invalid")
        records = [self.get(principal, item) for item in content_ids]
        if any(item.status != RuleContentStatus.PUBLISHED for item in records):
            raise ValueError("content packs can include only published rules")
        entries = [
            ContentPackEntry(
                definition=item.definition,
                definition_sha256=_definition_digest(item.definition),
            )
            for item in records
        ]
        base = {
            "schema_version": "1.0.0", "pack_id": new_id("dpack"),
            "version": version, "tenant_id": principal.tenant_id,
            "name": name, "description": description, "entries": entries,
            "created_by": principal.actor_id, "created_at": self._now(),
        }
        unsigned = SignedContentPack.model_construct(
            **base, pack_sha256="0" * 64,
            signature_algorithm=self.signer.algorithm, signature="0" * 64,
        )
        payload = self._pack_unsigned(unsigned)
        digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
        signed_payload = dict(payload)
        signed_payload["pack_sha256"] = digest
        pack = SignedContentPack.model_validate({
            **signed_payload,
            "signature_algorithm": self.signer.algorithm,
            "signature": self.signer.sign(signed_payload),
        })
        with self._lock:
            self._connection.execute(
                "INSERT INTO detection_content_packs(tenant_id, pack_id, version, pack_json, pack_sha256, signature, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (principal.tenant_id, pack.pack_id, pack.version, pack.model_dump_json(), pack.pack_sha256, pack.signature, pack.created_at.isoformat()),
            )
            self._audit(principal, "content.pack.export", "%s:%s" % (pack.pack_id, version))
        return pack

    def verify_pack(self, pack: SignedContentPack) -> None:
        payload = self._pack_unsigned(pack)
        digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
        if digest != pack.pack_sha256:
            raise ValueError("content pack digest is invalid")
        signed = dict(payload)
        signed["pack_sha256"] = digest
        if pack.signature_algorithm != self.signer.algorithm or not self.signer.verify(signed, pack.signature):
            raise ValueError("content pack signature is invalid")
        if any(
            item.definition_sha256 != _definition_digest(item.definition)
            for item in pack.entries
        ):
            raise ValueError("content pack rule digest is invalid")

    def import_pack(
        self, principal: ContentPrincipal, pack: SignedContentPack
    ) -> List[RuleContentRecord]:
        self._require(principal, CONTENT_WRITE)
        self._tenant(principal)
        self.verify_pack(pack)
        if pack.tenant_id != principal.tenant_id:
            raise ContentAuthorizationError("cross-tenant content pack is forbidden")
        if any(not entry.definition.enabled for entry in pack.entries):
            raise ValueError("content pack definitions must be enabled")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                for entry in pack.entries:
                    exists = self._connection.execute(
                        "SELECT 1 FROM detection_content WHERE tenant_id = ? AND rule_id = ? AND rule_version = ? LIMIT 1",
                        (principal.tenant_id, entry.definition.rule_id, entry.definition.version),
                    ).fetchone()
                    if exists is not None:
                        raise ValueError("content pack contains an existing rule version")
                records = []
                for entry in pack.entries:
                    now = self._now()
                    records.append(
                        self._append(
                            principal,
                            {
                                "content_id": new_id("drc"),
                                "tenant_id": principal.tenant_id,
                                "revision": 1,
                                "status": RuleContentStatus.DRAFT,
                                "definition": entry.definition,
                                "author_id": principal.actor_id,
                                "created_at": now,
                                "updated_at": now,
                                "source_pack_id": pack.pack_id,
                            },
                            "content.pack.draft",
                        )
                    )
                self._audit(
                    principal,
                    "content.pack.import",
                    "%s:%s" % (pack.pack_id, pack.version),
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return records

    def list_packs(self, principal: ContentPrincipal) -> List[SignedContentPack]:
        self._require(principal, CONTENT_READ)
        self._tenant(principal)
        with self._lock:
            rows = self._connection.execute(
                "SELECT pack_json FROM detection_content_packs WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 200",
                (principal.tenant_id,),
            ).fetchall()
        packs = [SignedContentPack.model_validate_json(row["pack_json"]) for row in rows]
        for pack in packs:
            self.verify_pack(pack)
        return packs

    def health(self, principal: ContentPrincipal) -> ContentHealthSummary:
        self._require(principal, CONTENT_READ)
        self._tenant(principal)
        with self._lock:
            rows = self._connection.execute(
                "SELECT status, COUNT(*) AS total FROM detection_content WHERE tenant_id = ? AND current = 1 GROUP BY status",
                (principal.tenant_id,),
            ).fetchall()
            failures = self._connection.execute(
                "SELECT COUNT(*) AS total FROM detection_content WHERE tenant_id = ? AND current = 1 AND json_extract(content_json, '$.validation.passed') = 0",
                (principal.tenant_id,),
            ).fetchone()["total"]
        counts = {row["status"]: int(row["total"]) for row in rows}
        return ContentHealthSummary(
            tenant_id=principal.tenant_id,
            total_content=sum(counts.values()),
            draft=counts.get("draft", 0), in_review=counts.get("in_review", 0),
            approved=counts.get("approved", 0), shadow=counts.get("shadow", 0),
            published=counts.get("published", 0), rejected=counts.get("rejected", 0),
            retired=counts.get("retired", 0), validation_failures=int(failures or 0),
            rule_health=self.detection_service.health(self.detection_principal),
            calculated_at=self._now(),
        )


__all__ = [
    "CONTENT_ADMIN", "CONTENT_PUBLISH", "CONTENT_READ", "CONTENT_REVIEW",
    "CONTENT_WRITE", "ContentAuthorizationError", "ContentHealthSummary",
    "ContentPackEntry", "ContentPrincipal", "DetectionContentService",
    "ReviewDecision", "RuleBacktestResult", "RuleContentRecord",
    "RuleContentStatus", "RuleTestSuite", "RuleValidationResult",
    "SignedContentPack",
]
