"""Tenant-scoped indexed search and threat-hunting service.

The query language is deliberately smaller than SQL. Every field and operator
is parsed, type checked, and compiled to parameterized statements. Canonical
payloads remain authoritative in :mod:`agentsec.storage`; this index contains
only an allowlisted analyst projection and never protected evidence blobs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from pydantic import Field, field_validator, model_validator

from .contracts import Severity, StrictModel, new_id, utc_now
from .datamodel import (
    ID_FIELDS,
    CanonicalRecord,
    EvidenceRecord,
    RecordType,
    canonical_record_json,
)
from .storage import CanonicalRepository


MAX_QUERY_LENGTH = 4096
MAX_QUERY_TERMS = 128
MAX_QUERY_DEPTH = 16
MAX_PAGE_SIZE = 200
MAX_OFFSET = 100000
MAX_BUCKETS = 100
CURSOR_TTL = timedelta(minutes=15)

READ_PERMISSION = "search:read"
INDEX_PERMISSION = "search:index"
HUNT_WRITE_PERMISSION = "hunt:write"
EVIDENCE_READ_PERMISSION = "evidence:read"


class SearchAuthorizationError(PermissionError):
    """Raised when a tenant principal lacks a required search permission."""


class SearchQueryError(ValueError):
    """Raised for invalid or excessive hunting queries."""


class SearchPrincipal(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=1, max_length=256)
    permissions: Set[str] = Field(default_factory=set, max_length=32)

    @field_validator("permissions")
    @classmethod
    def permissions_are_bounded(cls, value: Set[str]) -> Set[str]:
        if any(not re.fullmatch(r"[a-z]+:[a-z]+", item) for item in value):
            raise ValueError("search permissions must use namespace:operation")
        return value


class SearchRequest(StrictModel):
    query: str = Field(default="*", min_length=1, max_length=MAX_QUERY_LENGTH)
    page_size: int = Field(default=50, ge=1, le=MAX_PAGE_SIZE)
    cursor: Optional[str] = Field(default=None, max_length=4096)
    sort_by: str = Field(default="created_at", min_length=1, max_length=64)
    sort_order: str = Field(default="desc", pattern=r"^(asc|desc)$")


class SearchHit(StrictModel):
    record_type: RecordType
    record_id: str
    created_at: datetime
    severity: Optional[Severity] = None
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    title: Optional[str] = None
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    projection: Dict[str, Any]


class SearchPage(StrictModel):
    query: str
    hits: List[SearchHit]
    total: int = Field(ge=0)
    next_cursor: Optional[str] = None
    elapsed_ms: float = Field(ge=0.0)


class SearchBucket(StrictModel):
    value: str
    count: int = Field(ge=1)


class AggregationResult(StrictModel):
    query: str
    field: str
    buckets: List[SearchBucket]
    elapsed_ms: float = Field(ge=0.0)


class SavedHunt(StrictModel):
    hunt_id: str = Field(min_length=5, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=2048)
    query: str = Field(min_length=1, max_length=MAX_QUERY_LENGTH)
    sort_by: str = Field(default="created_at", min_length=1, max_length=64)
    sort_order: str = Field(default="desc", pattern=r"^(asc|desc)$")
    owner_id: str = Field(min_length=1, max_length=256)
    created_at: datetime
    updated_at: datetime


class EvidencePivot(StrictModel):
    evidence_id: str
    evidence: Dict[str, Any]
    related_records: List[SearchHit]
    protected_content_included: bool = False

    @model_validator(mode="after")
    def raw_evidence_is_never_returned(self) -> "EvidencePivot":
        if self.protected_content_included:
            raise ValueError("search pivots cannot include protected evidence content")
        encoded = json.dumps(self.evidence, sort_keys=True).lower()
        if any(key in encoded for key in ('"ciphertext"', '"key_reference"')):
            raise ValueError("protected evidence fields cannot enter a search pivot")
        return self


class SearchIndexStats(StrictModel):
    tenant_id: str
    indexed_records: int = Field(ge=0)
    indexed_fields: int = Field(ge=0)
    synchronized_at: datetime


@dataclass(frozen=True)
class _Token:
    kind: str
    value: Any


@dataclass(frozen=True)
class _All:
    pass


@dataclass(frozen=True)
class _Comparison:
    field: str
    operator: str
    value: Any


@dataclass(frozen=True)
class _Boolean:
    operator: str
    left: Any
    right: Any


@dataclass(frozen=True)
class _Not:
    child: Any


_TOKEN = re.compile(
    r"\s*(?:(>=|<=|!=|=|>|<|~)|(\()|(\))|"
    r"([A-Za-z_][A-Za-z0-9_]*)|"
    r"(-?(?:\d+(?:\.\d+)?|\.\d+))|"
    r"(\"(?:[^\"\\]|\\.)*\")|(\*))"
)


class _Parser:
    def __init__(self, query: str) -> None:
        if not query or len(query) > MAX_QUERY_LENGTH:
            raise SearchQueryError("query length is invalid")
        self.tokens = self._tokenize(query)
        self.position = 0
        self.terms = 0
        self.depth = 0

    @staticmethod
    def _tokenize(query: str) -> List[_Token]:
        tokens: List[_Token] = []
        position = 0
        while position < len(query):
            match = _TOKEN.match(query, position)
            if match is None:
                raise SearchQueryError("query contains unsupported syntax")
            operator, left, right, identifier, number, quoted, star = match.groups()
            position = match.end()
            if operator:
                tokens.append(_Token("operator", operator))
            elif left:
                tokens.append(_Token("left", left))
            elif right:
                tokens.append(_Token("right", right))
            elif identifier:
                keyword = identifier.upper()
                if keyword in {"AND", "OR", "NOT"}:
                    tokens.append(_Token(keyword.lower(), keyword))
                elif keyword in {"TRUE", "FALSE"}:
                    tokens.append(_Token("value", keyword == "TRUE"))
                else:
                    tokens.append(_Token("identifier", identifier.lower()))
            elif number:
                tokens.append(
                    _Token("value", float(number) if "." in number else int(number))
                )
            elif quoted:
                try:
                    tokens.append(_Token("value", json.loads(quoted)))
                except json.JSONDecodeError as exc:
                    raise SearchQueryError("quoted query value is invalid") from exc
            elif star:
                tokens.append(_Token("star", star))
        if not tokens:
            raise SearchQueryError("query is empty")
        return tokens

    def _peek(self, kind: str) -> bool:
        return self.position < len(self.tokens) and self.tokens[self.position].kind == kind

    def _take(self, kind: str) -> _Token:
        if not self._peek(kind):
            raise SearchQueryError("query syntax is incomplete")
        token = self.tokens[self.position]
        self.position += 1
        return token

    def parse(self) -> Any:
        if len(self.tokens) == 1 and self._peek("star"):
            self.position += 1
            return _All()
        result = self._parse_or()
        if self.position != len(self.tokens):
            raise SearchQueryError("query contains trailing syntax")
        return result

    def _parse_or(self) -> Any:
        value = self._parse_and()
        while self._peek("or"):
            self._take("or")
            value = _Boolean("OR", value, self._parse_and())
        return value

    def _parse_and(self) -> Any:
        value = self._parse_not()
        while self._peek("and"):
            self._take("and")
            value = _Boolean("AND", value, self._parse_not())
        return value

    def _parse_not(self) -> Any:
        if self._peek("not"):
            self._take("not")
            return _Not(self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> Any:
        if self._peek("left"):
            self._take("left")
            self.depth += 1
            if self.depth > MAX_QUERY_DEPTH:
                raise SearchQueryError("query nesting exceeds the safety limit")
            value = self._parse_or()
            self._take("right")
            self.depth -= 1
            return value
        field = self._take("identifier").value
        operator = self._take("operator").value
        value = self._take("value").value
        self.terms += 1
        if self.terms > MAX_QUERY_TERMS:
            raise SearchQueryError("query term count exceeds the safety limit")
        return _Comparison(field, operator, value)


_FIELD_KINDS: Dict[str, str] = {
    "record_type": "string",
    "record_id": "string",
    "created_at": "time",
    "severity": "severity",
    "risk_score": "number",
    "confidence": "number",
    "title": "string",
    "status": "string",
    "alert_type": "string",
    "event_id": "string",
    "detector_id": "string",
    "entity_id": "string",
    "entity_type": "string",
    "name": "string",
    "criticality": "severity",
    "source": "string",
    "source_ref": "string",
    "source_trust": "string",
    "evidence_id": "string",
    "integrity_status": "string",
    "finding_id": "string",
    "finding_type": "string",
    "incident_id": "string",
    "investigation_id": "string",
    "judgment_id": "string",
    "action_id": "string",
    "action": "string",
    "action_type": "string",
    "operation": "string",
    "outcome": "string",
    "owner_ref": "string",
    "policy_version": "string",
    "trace_id": "string",
    "session_id": "string",
    "actor_entity_id": "string",
    "subject_id": "string",
    "subject_type": "string",
    "judge_type": "string",
    "hypothesis": "string",
    "claim": "string",
    "recommended_action": "string",
    "simulated": "boolean",
    "abstained": "boolean",
    "detected_at": "time",
    "opened_at": "time",
    "updated_at": "time",
    "judged_at": "time",
    "requested_at": "time",
    "occurred_at": "time",
}

_DIRECT_FIELDS = {
    "record_type": "d.record_type",
    "record_id": "d.record_id",
    "created_at": "d.created_at",
    "severity": "d.severity_rank",
    "risk_score": "d.risk_score",
    "confidence": "d.confidence",
    "title": "d.title",
}

_SORT_FIELDS = {
    "created_at": "d.created_at",
    "severity": "COALESCE(d.severity_rank, -1)",
    "risk_score": "COALESCE(d.risk_score, -1)",
    "confidence": "COALESCE(d.confidence, -1)",
    "title": "COALESCE(d.title, '') COLLATE NOCASE",
    "record_type": "d.record_type",
    "record_id": "d.record_id",
}

_SEVERITY_RANK = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}

_PROJECTION_FIELDS: Dict[RecordType, Sequence[str]] = {
    RecordType.EVENT: (
        "event_id", "occurred_at", "observed_at", "event_kind", "trace_id",
        "session_id", "actor_entity_id", "target_entity_ids", "operation", "outcome",
        "source_ref", "source_trust", "evidence_ids",
    ),
    RecordType.EVIDENCE: (
        "evidence_id", "evidence_type", "subject_refs", "source", "claim",
        "content_sha256", "integrity_status", "collected_at", "provenance_refs",
        "data_classes",
    ),
    RecordType.ENTITY: (
        "entity_id", "entity_type", "name", "owner_ref", "criticality",
        "external_ref", "first_seen_at", "last_seen_at",
    ),
    RecordType.ALERT: (
        "alert_id", "event_id", "detector_id", "rule_version", "alert_type", "title",
        "severity", "confidence", "status", "reason_codes", "evidence_ids",
        "framework_mappings", "recommended_action", "detected_at",
    ),
    RecordType.FINDING: (
        "finding_id", "finding_type", "alert_ids", "entity_ids", "evidence_ids",
        "severity", "risk_score", "status", "policy_version", "updated_at",
    ),
    RecordType.INCIDENT: (
        "incident_id", "title", "finding_ids", "entity_ids", "severity", "risk_score",
        "status", "owner_ref", "opened_at", "updated_at",
    ),
    RecordType.INVESTIGATION: (
        "investigation_id", "incident_id", "status", "hypothesis", "evidence_ids",
        "conclusion", "assigned_to", "updated_at",
    ),
    RecordType.JUDGMENT: (
        "judgment_id", "subject_type", "subject_id", "judge_type", "action",
        "deterministic_action", "confidence", "reason_codes", "evidence_ids",
        "policy_version", "abstained", "uncertainty", "judged_at",
    ),
    RecordType.ACTION: (
        "action_id", "incident_id", "judgment_id", "action_type", "status", "simulated",
        "approval_ref", "executor_ref", "target_entity_ids", "evidence_ids",
        "requested_at", "completed_at", "result_code",
    ),
}


def _identity(record: CanonicalRecord) -> str:
    return str(getattr(record, ID_FIELDS[record.record_type]))


def _projection(record: CanonicalRecord) -> Dict[str, Any]:
    source = record.model_dump(mode="json")
    allowed = _PROJECTION_FIELDS[record.record_type]
    projected = {
        "record_type": record.record_type.value,
        "record_id": _identity(record),
        "created_at": source["created_at"],
        "labels": sorted(source.get("labels", [])),
    }
    for key in allowed:
        if key in source and source[key] is not None:
            projected[key] = source[key]
    return projected


def _field_values(projection: Dict[str, Any]) -> Dict[str, List[Any]]:
    result: Dict[str, List[Any]] = {}
    for key, raw in projection.items():
        values = raw if isinstance(raw, list) else [raw]
        field = key
        if key.endswith("_ids"):
            field = key[:-1]
        if field not in _FIELD_KINDS:
            continue
        result.setdefault(field, []).extend(value for value in values if value is not None)
    return result


def _normalized_time(value: Any) -> str:
    if not isinstance(value, str):
        raise SearchQueryError("time comparison requires an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SearchQueryError("time comparison requires an ISO-8601 string") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SearchQueryError("time comparison requires a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


def _normalized_value(field: str, value: Any) -> Tuple[str, Any]:
    if field not in _FIELD_KINDS:
        raise SearchQueryError("query field is not searchable: %s" % field)
    kind = _FIELD_KINDS[field]
    if kind == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SearchQueryError("numeric comparison requires a number")
        return kind, float(value)
    if kind == "boolean":
        if not isinstance(value, bool):
            raise SearchQueryError("boolean comparison requires true or false")
        return kind, "true" if value else "false"
    if not isinstance(value, str):
        raise SearchQueryError("text comparison requires a quoted string")
    if len(value) > 1024:
        raise SearchQueryError("query value exceeds the safety limit")
    if kind == "time":
        return kind, _normalized_time(value)
    if kind == "severity":
        if value not in _SEVERITY_RANK:
            raise SearchQueryError("severity value is invalid")
        return kind, _SEVERITY_RANK[value]
    return kind, value


def _like_value(value: str) -> str:
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _compile(node: Any) -> Tuple[str, List[Any]]:
    if isinstance(node, _All):
        return "1 = 1", []
    if isinstance(node, _Boolean):
        left_sql, left_values = _compile(node.left)
        right_sql, right_values = _compile(node.right)
        return "(%s %s %s)" % (left_sql, node.operator, right_sql), left_values + right_values
    if isinstance(node, _Not):
        child_sql, values = _compile(node.child)
        return "(NOT (%s))" % child_sql, values
    if not isinstance(node, _Comparison):
        raise SearchQueryError("query syntax is invalid")
    kind, value = _normalized_value(node.field, node.value)
    if node.operator == "~" and kind not in {"string"}:
        raise SearchQueryError("contains is valid only for text fields")
    if kind in {"string", "boolean"} and node.operator not in {"=", "!=", "~"}:
        raise SearchQueryError("ordered comparisons require numeric, time, or severity fields")
    operator = "LIKE" if node.operator == "~" else node.operator
    if node.operator == "~":
        value = _like_value(value)
    if node.field in _DIRECT_FIELDS:
        column = _DIRECT_FIELDS[node.field]
        if node.field == "severity":
            column = "d.severity_rank"
        suffix = " ESCAPE '\\'" if operator == "LIKE" else ""
        return "%s %s ?%s" % (column, operator, suffix), [value]
    column = "value_number" if kind in {"number", "severity"} else "value_time" if kind == "time" else "value_text"
    suffix = " ESCAPE '\\'" if operator == "LIKE" else ""
    match = (
        "EXISTS (SELECT 1 FROM search_fields sf WHERE sf.tenant_id = d.tenant_id "
        "AND sf.doc_key = d.doc_key AND sf.field = ? AND sf.%s %s ?%s)"
        % (column, operator if operator != "!=" else "=", suffix)
    )
    if operator == "!=":
        exists = (
            "EXISTS (SELECT 1 FROM search_fields sx WHERE sx.tenant_id = d.tenant_id "
            "AND sx.doc_key = d.doc_key AND sx.field = ?)"
        )
        return "(%s AND NOT %s)" % (exists, match), [node.field, node.field, value]
    return match, [node.field, value]


class SearchService:
    """Local reference adapter for safe, indexed canonical threat hunting."""

    def __init__(
        self,
        path: str,
        *,
        cursor_secret: bytes,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if len(cursor_secret) < 32:
            raise ValueError("search cursor secret must contain at least 32 bytes")
        self.path = path
        self.cursor_secret = cursor_secret
        self.clock = clock
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
        self._migrate()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("search clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    def _migrate(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS search_documents (
                tenant_id TEXT NOT NULL,
                doc_key TEXT NOT NULL,
                record_type TEXT NOT NULL,
                record_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                severity TEXT,
                severity_rank INTEGER,
                risk_score REAL,
                confidence REAL,
                title TEXT,
                projection_json TEXT NOT NULL,
                record_sha256 TEXT NOT NULL,
                indexed_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, doc_key)
            );
            CREATE TABLE IF NOT EXISTS search_fields (
                tenant_id TEXT NOT NULL,
                doc_key TEXT NOT NULL,
                field TEXT NOT NULL,
                value_text TEXT,
                value_number REAL,
                value_time TEXT,
                FOREIGN KEY (tenant_id, doc_key)
                    REFERENCES search_documents(tenant_id, doc_key) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS saved_hunts (
                tenant_id TEXT NOT NULL,
                hunt_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                query TEXT NOT NULL,
                sort_by TEXT NOT NULL,
                sort_order TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, hunt_id)
            );
            CREATE TABLE IF NOT EXISTS search_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                action TEXT NOT NULL,
                subject TEXT NOT NULL,
                occurred_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS search_documents_tenant_time
                ON search_documents(tenant_id, created_at DESC, doc_key);
            CREATE INDEX IF NOT EXISTS search_documents_tenant_type
                ON search_documents(tenant_id, record_type, created_at DESC);
            CREATE INDEX IF NOT EXISTS search_documents_tenant_severity
                ON search_documents(tenant_id, severity_rank DESC, created_at DESC);
            CREATE INDEX IF NOT EXISTS search_fields_text
                ON search_fields(tenant_id, field, value_text, doc_key);
            CREATE INDEX IF NOT EXISTS search_fields_number
                ON search_fields(tenant_id, field, value_number, doc_key);
            CREATE INDEX IF NOT EXISTS search_fields_time
                ON search_fields(tenant_id, field, value_time, doc_key);
            """
        )
        self._connection.execute("PRAGMA foreign_keys = ON")

    @staticmethod
    def _require(principal: SearchPrincipal, permission: str) -> None:
        if permission not in principal.permissions:
            raise SearchAuthorizationError("missing permission: %s" % permission)

    @staticmethod
    def validate_query(query: str) -> Any:
        node = _Parser(query.strip()).parse()
        _compile(node)
        return node

    @staticmethod
    def _validate_sort(sort_by: str) -> str:
        try:
            return _SORT_FIELDS[sort_by]
        except KeyError as exc:
            raise SearchQueryError("sort field is not allowed") from exc

    def _audit(self, principal: SearchPrincipal, action: str, subject: str) -> None:
        self._connection.execute(
            "INSERT INTO search_audit(tenant_id, actor_id, action, subject, occurred_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (principal.tenant_id, principal.actor_id, action, subject[:512], self._now().isoformat()),
        )

    def index_record(self, principal: SearchPrincipal, record: CanonicalRecord) -> None:
        self._require(principal, INDEX_PERMISSION)
        if record.tenant_id != principal.tenant_id:
            raise SearchAuthorizationError("cross-tenant indexing is forbidden")
        projection = _projection(record)
        fields = _field_values(projection)
        record_id = _identity(record)
        doc_key = "%s:%s" % (record.record_type.value, record_id)
        digest = hashlib.sha256(canonical_record_json(record)).hexdigest()
        severity = projection.get("severity")
        if severity is None:
            severity = projection.get("criticality")
        title = projection.get("title") or projection.get("name") or projection.get("claim")
        timestamp = self._now().isoformat()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    "INSERT INTO search_documents(tenant_id, doc_key, record_type, record_id, "
                    "created_at, severity, severity_rank, risk_score, confidence, title, "
                    "projection_json, record_sha256, indexed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(tenant_id, doc_key) DO UPDATE SET record_type=excluded.record_type, "
                    "record_id=excluded.record_id, created_at=excluded.created_at, severity=excluded.severity, "
                    "severity_rank=excluded.severity_rank, risk_score=excluded.risk_score, "
                    "confidence=excluded.confidence, title=excluded.title, projection_json=excluded.projection_json, "
                    "record_sha256=excluded.record_sha256, indexed_at=excluded.indexed_at",
                    (
                        principal.tenant_id, doc_key, record.record_type.value, record_id,
                        projection["created_at"], severity, _SEVERITY_RANK.get(severity),
                        projection.get("risk_score"), projection.get("confidence"), title,
                        json.dumps(projection, sort_keys=True, separators=(",", ":")), digest, timestamp,
                    ),
                )
                self._connection.execute(
                    "DELETE FROM search_fields WHERE tenant_id = ? AND doc_key = ?",
                    (principal.tenant_id, doc_key),
                )
                for field, values in fields.items():
                    kind = _FIELD_KINDS[field]
                    for value in values:
                        value_text: Optional[str] = None
                        value_number: Optional[float] = None
                        value_time: Optional[str] = None
                        if kind in {"number", "severity"}:
                            value_number = float(_SEVERITY_RANK[value] if kind == "severity" else value)
                        elif kind == "time":
                            value_time = _normalized_time(str(value))
                        elif kind == "boolean":
                            value_text = "true" if bool(value) else "false"
                        else:
                            value_text = str(value)
                        self._connection.execute(
                            "INSERT INTO search_fields(tenant_id, doc_key, field, value_text, value_number, value_time) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (principal.tenant_id, doc_key, field, value_text, value_number, value_time),
                        )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def synchronize(
        self, principal: SearchPrincipal, repository: CanonicalRepository
    ) -> SearchIndexStats:
        self._require(principal, INDEX_PERMISSION)
        verification = repository.verify(principal.tenant_id)
        if not verification.valid:
            raise ValueError(
                "canonical repository failed verification: %s" % verification.reason
            )
        if repository.active_record_count(principal.tenant_id) > 100000:
            raise ValueError("reference search adapter supports at most 100000 active tenant records")
        records = repository.latest_records(principal.tenant_id, limit=100000)
        seen = set()
        for record in records:
            self.index_record(principal, record)
            seen.add("%s:%s" % (record.record_type.value, _identity(record)))
        with self._lock:
            if seen:
                placeholders = ",".join("?" for _ in seen)
                self._connection.execute(
                    "DELETE FROM search_documents WHERE tenant_id = ? AND doc_key NOT IN (%s)" % placeholders,
                    (principal.tenant_id, *sorted(seen)),
                )
            else:
                self._connection.execute(
                    "DELETE FROM search_documents WHERE tenant_id = ?", (principal.tenant_id,)
                )
            row = self._connection.execute(
                "SELECT COUNT(*) AS documents FROM search_documents WHERE tenant_id = ?",
                (principal.tenant_id,),
            ).fetchone()
            fields = self._connection.execute(
                "SELECT COUNT(*) AS fields FROM search_fields WHERE tenant_id = ?",
                (principal.tenant_id,),
            ).fetchone()
            self._audit(principal, "index.synchronize", "%d records" % len(records))
        return SearchIndexStats(
            tenant_id=principal.tenant_id,
            indexed_records=row["documents"],
            indexed_fields=fields["fields"],
            synchronized_at=self._now(),
        )

    def _encode_cursor(self, principal: SearchPrincipal, payload: Dict[str, Any]) -> str:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = hmac.new(self.cursor_secret, body, hashlib.sha256).digest()
        return "%s.%s" % (
            base64.urlsafe_b64encode(body).decode("ascii").rstrip("="),
            base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
        )

    def _decode_cursor(
        self, principal: SearchPrincipal, request: SearchRequest, query_hash: str
    ) -> int:
        if request.cursor is None:
            return 0
        try:
            encoded_body, encoded_signature = request.cursor.split(".", 1)
            body = base64.urlsafe_b64decode(encoded_body + "=" * (-len(encoded_body) % 4))
            supplied = base64.urlsafe_b64decode(encoded_signature + "=" * (-len(encoded_signature) % 4))
            if (
                base64.urlsafe_b64encode(body).decode("ascii").rstrip("=")
                != encoded_body
                or base64.urlsafe_b64encode(supplied).decode("ascii").rstrip("=")
                != encoded_signature
            ):
                raise SearchQueryError("search cursor encoding is not canonical")
            expected = hmac.new(self.cursor_secret, body, hashlib.sha256).digest()
            if not hmac.compare_digest(supplied, expected):
                raise SearchQueryError("search cursor signature is invalid")
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SearchQueryError("search cursor is invalid") from exc
        if (
            payload.get("v") != 1
            or payload.get("tenant") != principal.tenant_id
            or payload.get("query") != query_hash
            or payload.get("sort_by") != request.sort_by
            or payload.get("sort_order") != request.sort_order
        ):
            raise SearchQueryError("search cursor does not match the request")
        if not isinstance(payload.get("offset"), int) or not 0 <= payload["offset"] <= MAX_OFFSET:
            raise SearchQueryError("search cursor offset is invalid")
        if not isinstance(payload.get("expires"), str) or _normalized_time(payload["expires"]) <= self._now().isoformat():
            raise SearchQueryError("search cursor has expired")
        return payload["offset"]

    @staticmethod
    def _row_hit(row: sqlite3.Row) -> SearchHit:
        return SearchHit(
            record_type=row["record_type"],
            record_id=row["record_id"],
            created_at=row["created_at"],
            severity=row["severity"],
            risk_score=int(row["risk_score"]) if row["risk_score"] is not None else None,
            confidence=row["confidence"],
            title=row["title"],
            record_sha256=row["record_sha256"],
            projection=json.loads(row["projection_json"]),
        )

    def search(self, principal: SearchPrincipal, request: SearchRequest) -> SearchPage:
        self._require(principal, READ_PERMISSION)
        started = self._now()
        query = request.query.strip()
        node = self.validate_query(query)
        where, values = _compile(node)
        sort_column = self._validate_sort(request.sort_by)
        query_hash = hashlib.sha256(query.encode("utf-8")).hexdigest()
        offset = self._decode_cursor(principal, request, query_hash)
        if offset + request.page_size > MAX_OFFSET:
            raise SearchQueryError("search pagination exceeds the safety limit")
        order = "ASC" if request.sort_order == "asc" else "DESC"
        with self._lock:
            total = self._connection.execute(
                "SELECT COUNT(*) AS total FROM search_documents d WHERE d.tenant_id = ? AND (%s)" % where,
                (principal.tenant_id, *values),
            ).fetchone()["total"]
            rows = self._connection.execute(
                "SELECT d.* FROM search_documents d WHERE d.tenant_id = ? AND (%s) "
                "ORDER BY %s %s, d.doc_key %s LIMIT ? OFFSET ?" % (where, sort_column, order, order),
                (principal.tenant_id, *values, request.page_size + 1, offset),
            ).fetchall()
            self._audit(principal, "search.execute", query_hash)
        has_more = len(rows) > request.page_size
        hits = [self._row_hit(row) for row in rows[: request.page_size]]
        next_cursor = None
        if has_more:
            next_cursor = self._encode_cursor(
                principal,
                {
                    "v": 1,
                    "tenant": principal.tenant_id,
                    "query": query_hash,
                    "sort_by": request.sort_by,
                    "sort_order": request.sort_order,
                    "offset": offset + request.page_size,
                    "expires": (self._now() + CURSOR_TTL).isoformat(),
                },
            )
        elapsed = max(0.0, (self._now() - started).total_seconds() * 1000.0)
        return SearchPage(query=query, hits=hits, total=total, next_cursor=next_cursor, elapsed_ms=elapsed)

    def aggregate(
        self,
        principal: SearchPrincipal,
        *,
        query: str,
        field: str,
        limit: int = 20,
    ) -> AggregationResult:
        self._require(principal, READ_PERMISSION)
        if not 1 <= limit <= MAX_BUCKETS:
            raise SearchQueryError("aggregation bucket limit is invalid")
        if field not in _FIELD_KINDS:
            raise SearchQueryError("aggregation field is not searchable")
        started = self._now()
        node = self.validate_query(query.strip())
        where, values = _compile(node)
        if field in _DIRECT_FIELDS:
            column = "d.severity" if field == "severity" else _DIRECT_FIELDS[field]
            sql = (
                "SELECT CAST(%s AS TEXT) AS value, COUNT(*) AS count FROM search_documents d "
                "WHERE d.tenant_id = ? AND (%s) AND %s IS NOT NULL GROUP BY %s "
                "ORDER BY count DESC, value ASC LIMIT ?" % (column, where, column, column)
            )
            parameters: Tuple[Any, ...] = (principal.tenant_id, *values, limit)
        else:
            kind = _FIELD_KINDS[field]
            column = "value_number" if kind in {"number", "severity"} else "value_time" if kind == "time" else "value_text"
            sql = (
                "SELECT CAST(agg.%s AS TEXT) AS value, COUNT(DISTINCT d.doc_key) AS count "
                "FROM search_documents d JOIN search_fields agg ON agg.tenant_id = d.tenant_id "
                "AND agg.doc_key = d.doc_key AND agg.field = ? WHERE d.tenant_id = ? AND (%s) "
                "AND agg.%s IS NOT NULL GROUP BY agg.%s ORDER BY count DESC, value ASC LIMIT ?"
                % (column, where, column, column)
            )
            parameters = (field, principal.tenant_id, *values, limit)
        with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
            self._audit(principal, "search.aggregate", field)
        elapsed = max(0.0, (self._now() - started).total_seconds() * 1000.0)
        return AggregationResult(
            query=query.strip(),
            field=field,
            buckets=[SearchBucket(value=row["value"], count=row["count"]) for row in rows],
            elapsed_ms=elapsed,
        )

    def save_hunt(
        self,
        principal: SearchPrincipal,
        *,
        name: str,
        query: str,
        description: str = "",
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> SavedHunt:
        self._require(principal, HUNT_WRITE_PERMISSION)
        self.validate_query(query.strip())
        self._validate_sort(sort_by)
        if sort_order not in {"asc", "desc"}:
            raise SearchQueryError("saved hunt sort order is invalid")
        now = self._now()
        hunt = SavedHunt(
            hunt_id=new_id("hunt"), tenant_id=principal.tenant_id, name=name,
            description=description, query=query.strip(), sort_by=sort_by,
            sort_order=sort_order, owner_id=principal.actor_id, created_at=now, updated_at=now,
        )
        with self._lock:
            self._connection.execute(
                "INSERT INTO saved_hunts(tenant_id, hunt_id, name, description, query, sort_by, "
                "sort_order, owner_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    hunt.tenant_id, hunt.hunt_id, hunt.name, hunt.description, hunt.query,
                    hunt.sort_by, hunt.sort_order, hunt.owner_id, now.isoformat(), now.isoformat(),
                ),
            )
            self._audit(principal, "hunt.create", hunt.hunt_id)
        return hunt

    @staticmethod
    def _row_hunt(row: sqlite3.Row) -> SavedHunt:
        return SavedHunt(**dict(row))

    def list_hunts(self, principal: SearchPrincipal) -> List[SavedHunt]:
        self._require(principal, READ_PERMISSION)
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM saved_hunts WHERE tenant_id = ? ORDER BY updated_at DESC, hunt_id",
                (principal.tenant_id,),
            ).fetchall()
        return [self._row_hunt(row) for row in rows]

    def get_hunt(self, principal: SearchPrincipal, hunt_id: str) -> SavedHunt:
        self._require(principal, READ_PERMISSION)
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM saved_hunts WHERE tenant_id = ? AND hunt_id = ?",
                (principal.tenant_id, hunt_id),
            ).fetchone()
        if row is None:
            raise KeyError(hunt_id)
        return self._row_hunt(row)

    def update_hunt(
        self,
        principal: SearchPrincipal,
        hunt_id: str,
        *,
        name: str,
        query: str,
        description: str = "",
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> SavedHunt:
        self._require(principal, HUNT_WRITE_PERMISSION)
        existing = self.get_hunt(principal, hunt_id)
        if existing.owner_id != principal.actor_id:
            raise SearchAuthorizationError("only the saved-hunt owner can update it")
        self.validate_query(query.strip())
        self._validate_sort(sort_by)
        if sort_order not in {"asc", "desc"}:
            raise SearchQueryError("saved hunt sort order is invalid")
        now = self._now()
        updated = SavedHunt(
            hunt_id=existing.hunt_id,
            tenant_id=existing.tenant_id,
            name=name,
            description=description,
            query=query.strip(),
            sort_by=sort_by,
            sort_order=sort_order,
            owner_id=existing.owner_id,
            created_at=existing.created_at,
            updated_at=now,
        )
        with self._lock:
            self._connection.execute(
                "UPDATE saved_hunts SET name=?, description=?, query=?, sort_by=?, sort_order=?, "
                "updated_at=? WHERE tenant_id=? AND hunt_id=?",
                (
                    updated.name, updated.description, updated.query, updated.sort_by,
                    updated.sort_order, now.isoformat(), principal.tenant_id, hunt_id,
                ),
            )
            self._audit(principal, "hunt.update", hunt_id)
        return updated

    def delete_hunt(self, principal: SearchPrincipal, hunt_id: str) -> None:
        self._require(principal, HUNT_WRITE_PERMISSION)
        existing = self.get_hunt(principal, hunt_id)
        if existing.owner_id != principal.actor_id:
            raise SearchAuthorizationError("only the saved-hunt owner can delete it")
        with self._lock:
            self._connection.execute(
                "DELETE FROM saved_hunts WHERE tenant_id = ? AND hunt_id = ?",
                (principal.tenant_id, hunt_id),
            )
            self._audit(principal, "hunt.delete", hunt_id)

    def execute_hunt(
        self, principal: SearchPrincipal, hunt_id: str, *, page_size: int = 50
    ) -> SearchPage:
        hunt = self.get_hunt(principal, hunt_id)
        return self.search(
            principal,
            SearchRequest(
                query=hunt.query, page_size=page_size,
                sort_by=hunt.sort_by, sort_order=hunt.sort_order,
            ),
        )

    def evidence_pivot(
        self,
        principal: SearchPrincipal,
        repository: CanonicalRepository,
        evidence_id: str,
    ) -> EvidencePivot:
        self._require(principal, EVIDENCE_READ_PERMISSION)
        self._require(principal, READ_PERMISSION)
        evidence = repository.get(principal.tenant_id, RecordType.EVIDENCE, evidence_id)
        if not isinstance(evidence, EvidenceRecord):
            raise KeyError(evidence_id)
        escaped = json.dumps(evidence_id)
        page = self.search(
            principal,
            SearchRequest(query="evidence_id = %s" % escaped, page_size=MAX_PAGE_SIZE),
        )
        return EvidencePivot(
            evidence_id=evidence_id,
            evidence=_projection(evidence),
            related_records=page.hits,
            protected_content_included=False,
        )


__all__ = [
    "AggregationResult",
    "EVIDENCE_READ_PERMISSION",
    "EvidencePivot",
    "HUNT_WRITE_PERMISSION",
    "INDEX_PERMISSION",
    "READ_PERMISSION",
    "SavedHunt",
    "SearchAuthorizationError",
    "SearchBucket",
    "SearchHit",
    "SearchIndexStats",
    "SearchPage",
    "SearchPrincipal",
    "SearchQueryError",
    "SearchRequest",
    "SearchService",
]
