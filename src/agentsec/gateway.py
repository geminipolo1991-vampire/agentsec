"""Authenticated, tenant-bound, durable AI telemetry ingestion gateway.

This module deliberately stops at the ingestion boundary. It validates workload
identity, prevents request replay, applies quotas and backpressure, normalizes
telemetry through the Module 1 collector, and commits only the safe envelope to
a durable SQLite spool. Downstream evidence retention and indexing belong to
later product modules.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from pydantic import Field, ValidationError

from .contracts import StrictModel, utc_now
from .telemetry import (
    CaptureStatus,
    CollectionMode,
    CollectorConfig,
    TelemetryCollector,
    TelemetryEnvelope,
    TelemetryInput,
)


SIGNATURE_VERSION = "v1"
MAX_CLOCK_SKEW_SECONDS = 300
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{3,128}$")
SIGNATURE_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class GatewayAuthenticationError(ValueError):
    """Authentication failure with a fixed, non-sensitive reason code."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class WorkloadPrincipal(StrictModel):
    credential_id: str = Field(min_length=3, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=256)
    application_ids: Set[str] = Field(default_factory=set, max_length=256)


class WorkloadCredential:
    """Runtime credential whose secret is intentionally absent from repr/models."""

    __slots__ = ("credential_id", "tenant_id", "source_id", "application_ids", "_secret")

    def __init__(
        self,
        *,
        credential_id: str,
        secret: str,
        tenant_id: str,
        source_id: str,
        application_ids: Optional[Iterable[str]] = None,
    ) -> None:
        if KEY_ID_PATTERN.fullmatch(credential_id) is None:
            raise ValueError("credential_id has an invalid format")
        if not 32 <= len(secret) <= 4096:
            raise ValueError("workload secret must contain 32 to 4096 characters")
        if not 1 <= len(tenant_id) <= 128 or not 1 <= len(source_id) <= 256:
            raise ValueError("workload tenant and source must be bounded")
        allowed = set(application_ids or [])
        if len(allowed) > 256 or any(not 1 <= len(item) <= 128 for item in allowed):
            raise ValueError("application allowlist is invalid")
        self.credential_id = credential_id
        self.tenant_id = tenant_id
        self.source_id = source_id
        self.application_ids = allowed
        self._secret = secret.encode("utf-8")

    @property
    def principal(self) -> WorkloadPrincipal:
        return WorkloadPrincipal(
            credential_id=self.credential_id,
            tenant_id=self.tenant_id,
            source_id=self.source_id,
            application_ids=self.application_ids,
        )

    def signature(self, canonical_request: bytes) -> str:
        return hmac.new(self._secret, canonical_request, hashlib.sha256).hexdigest()


def canonical_request(
    *, method: str, path: str, timestamp: str, nonce: str, body: bytes
) -> bytes:
    body_digest = hashlib.sha256(body).hexdigest()
    return ("%s\n%s\n%s\n%s\n%s" % (
        method.upper(),
        path,
        timestamp,
        nonce,
        body_digest,
    )).encode("utf-8")


def sign_workload_request(
    credential: WorkloadCredential,
    *,
    method: str,
    path: str,
    body: bytes,
    timestamp: Optional[int] = None,
    nonce: str,
) -> Dict[str, str]:
    """Build the exact headers used by Python/TypeScript workload SDKs."""

    if NONCE_PATTERN.fullmatch(nonce) is None:
        raise ValueError("nonce has an invalid format")
    timestamp_text = str(int(time.time()) if timestamp is None else timestamp)
    signature = credential.signature(
        canonical_request(
            method=method,
            path=path,
            timestamp=timestamp_text,
            nonce=nonce,
            body=body,
        )
    )
    return {
        "X-AgentSec-Key-Id": credential.credential_id,
        "X-AgentSec-Timestamp": timestamp_text,
        "X-AgentSec-Nonce": nonce,
        "X-AgentSec-Signature": "%s=%s" % (SIGNATURE_VERSION, signature),
    }


class GatewayEventStatus(str, Enum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    PROCESSING = "processing"
    REJECTED = "rejected"
    CONFLICT = "conflict"
    BACKPRESSURE = "backpressure"


class ReservationStatus(str, Enum):
    RESERVED = "reserved"
    DUPLICATE = "duplicate"
    PROCESSING = "processing"
    CONFLICT = "conflict"
    BACKPRESSURE = "backpressure"


class GatewaySourceHealth(StrictModel):
    tenant_id: str
    source_id: str
    status: str
    accepted_events: int = Field(ge=0)
    duplicate_events: int = Field(ge=0)
    rejected_events: int = Field(ge=0)
    rate_limited_requests: int = Field(ge=0)
    backpressured_events: int = Field(ge=0)
    processed_events: int = Field(ge=0)
    dead_letter_events: int = Field(ge=0)
    pending_events: int = Field(ge=0)
    processing_events: int = Field(ge=0)
    last_received_at: Optional[datetime] = None
    last_processed_at: Optional[datetime] = None
    last_error_code: Optional[str] = None


class GatewayReceipt(StrictModel):
    schema_version: str = "1.0.0"
    status: GatewayEventStatus
    event_id: Optional[str] = None
    tenant_id: str
    source_id: str
    queue_id: Optional[int] = None
    reason_codes: List[str] = Field(default_factory=list)
    received_at: datetime = Field(default_factory=utc_now)
    source_health: GatewaySourceHealth


class GatewayBatchResponse(StrictModel):
    schema_version: str = "1.0.0"
    accepted: int = Field(ge=0)
    duplicates: int = Field(ge=0)
    processing: int = Field(ge=0)
    rejected: int = Field(ge=0)
    conflicts: int = Field(ge=0)
    backpressured: int = Field(ge=0)
    receipts: List[GatewayReceipt] = Field(default_factory=list)


class QueueSummary(StrictModel):
    pending: int = Field(ge=0)
    processing: int = Field(ge=0)
    succeeded: int = Field(ge=0)
    dead_letter: int = Field(ge=0)
    reservations: int = Field(ge=0)
    capacity: int = Field(ge=1)


class GatewayQueueItem(StrictModel):
    queue_id: int = Field(ge=1)
    tenant_id: str
    source_id: str
    event_id: str
    attempts: int = Field(ge=1)
    envelope: TelemetryEnvelope


class DurableGatewayStore:
    """SQLite-backed nonce, idempotency, queue, DLQ, and health state."""

    def __init__(
        self,
        path: str,
        *,
        max_queue_depth: int = 10000,
        reservation_ttl_seconds: int = 300,
    ) -> None:
        if max_queue_depth < 1:
            raise ValueError("max_queue_depth must be positive")
        if not 5 <= reservation_ttl_seconds <= 3600:
            raise ValueError("reservation_ttl_seconds must be between 5 and 3600")
        self.path = path
        self.max_queue_depth = max_queue_depth
        self.reservation_ttl_seconds = reservation_ttl_seconds
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

    def _migrate(self) -> None:
        with self._lock:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS gateway_nonces (
                    credential_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (credential_id, nonce)
                );
                CREATE INDEX IF NOT EXISTS gateway_nonces_expiry
                    ON gateway_nonces(expires_at);

                CREATE TABLE IF NOT EXISTS gateway_reservations (
                    tenant_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (tenant_id, event_id)
                );
                CREATE INDEX IF NOT EXISTS gateway_reservations_expiry
                    ON gateway_reservations(expires_at);

                CREATE TABLE IF NOT EXISTS gateway_events (
                    tenant_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, event_id)
                );

                CREATE TABLE IF NOT EXISTS gateway_queue (
                    queue_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('pending', 'processing', 'succeeded', 'dead_letter')
                    ),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    available_at REAL NOT NULL,
                    lease_until REAL,
                    last_error_code TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE (tenant_id, event_id),
                    FOREIGN KEY (tenant_id, event_id)
                        REFERENCES gateway_events(tenant_id, event_id)
                );
                CREATE INDEX IF NOT EXISTS gateway_queue_claim
                    ON gateway_queue(status, available_at, queue_id);

                CREATE TABLE IF NOT EXISTS gateway_source_stats (
                    tenant_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    accepted_events INTEGER NOT NULL DEFAULT 0,
                    duplicate_events INTEGER NOT NULL DEFAULT 0,
                    rejected_events INTEGER NOT NULL DEFAULT 0,
                    rate_limited_requests INTEGER NOT NULL DEFAULT 0,
                    backpressured_events INTEGER NOT NULL DEFAULT 0,
                    processed_events INTEGER NOT NULL DEFAULT 0,
                    dead_letter_events INTEGER NOT NULL DEFAULT 0,
                    last_received_at TEXT,
                    last_processed_at TEXT,
                    last_error_code TEXT,
                    PRIMARY KEY (tenant_id, source_id)
                );
                """
            )

    def register_nonce(
        self, credential_id: str, nonce: str, *, now_epoch: float, ttl_seconds: int
    ) -> bool:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    "DELETE FROM gateway_nonces WHERE expires_at <= ?", (now_epoch,)
                )
                cursor = self._connection.execute(
                    "INSERT OR IGNORE INTO gateway_nonces(credential_id, nonce, expires_at) "
                    "VALUES (?, ?, ?)",
                    (credential_id, nonce, now_epoch + ttl_seconds),
                )
                self._connection.execute("COMMIT")
                return cursor.rowcount == 1
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def _metric(
        self,
        tenant_id: str,
        source_id: str,
        column: str,
        *,
        error_code: Optional[str] = None,
        received: bool = False,
        processed: bool = False,
    ) -> None:
        allowed = {
            "accepted_events",
            "duplicate_events",
            "rejected_events",
            "rate_limited_requests",
            "backpressured_events",
            "processed_events",
            "dead_letter_events",
        }
        if column not in allowed:
            raise ValueError("unsupported source metric")
        now_text = utc_now().isoformat()
        self._connection.execute(
            "INSERT OR IGNORE INTO gateway_source_stats(tenant_id, source_id) VALUES (?, ?)",
            (tenant_id, source_id),
        )
        assignments = ["%s = %s + 1" % (column, column)]
        values: List[object] = []
        if received:
            assignments.append("last_received_at = ?")
            values.append(now_text)
        if processed:
            assignments.append("last_processed_at = ?")
            values.append(now_text)
        if error_code is not None:
            assignments.append("last_error_code = ?")
            values.append(error_code[:128])
        values.extend([tenant_id, source_id])
        self._connection.execute(
            "UPDATE gateway_source_stats SET %s WHERE tenant_id = ? AND source_id = ?"
            % ", ".join(assignments),
            tuple(values),
        )

    def record_metric(
        self,
        principal: WorkloadPrincipal,
        column: str,
        *,
        error_code: Optional[str] = None,
    ) -> None:
        with self._lock:
            self._metric(
                principal.tenant_id,
                principal.source_id,
                column,
                error_code=error_code,
                received=column in {"accepted_events", "rejected_events"},
            )

    def reserve(
        self,
        *,
        tenant_id: str,
        source_id: str,
        event_id: str,
        request_hash: str,
    ) -> ReservationStatus:
        now_epoch = time.time()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    "DELETE FROM gateway_reservations WHERE expires_at <= ?", (now_epoch,)
                )
                existing = self._connection.execute(
                    "SELECT request_hash FROM gateway_events WHERE tenant_id = ? AND event_id = ?",
                    (tenant_id, event_id),
                ).fetchone()
                if existing is not None:
                    result = (
                        ReservationStatus.DUPLICATE
                        if hmac.compare_digest(existing["request_hash"], request_hash)
                        else ReservationStatus.CONFLICT
                    )
                    self._connection.execute("COMMIT")
                    return result
                inflight = self._connection.execute(
                    "SELECT request_hash FROM gateway_reservations "
                    "WHERE tenant_id = ? AND event_id = ?",
                    (tenant_id, event_id),
                ).fetchone()
                if inflight is not None:
                    result = (
                        ReservationStatus.PROCESSING
                        if hmac.compare_digest(inflight["request_hash"], request_hash)
                        else ReservationStatus.CONFLICT
                    )
                    self._connection.execute("COMMIT")
                    return result
                queued = self._connection.execute(
                    "SELECT COUNT(*) AS count FROM gateway_queue "
                    "WHERE status IN ('pending', 'processing')"
                ).fetchone()["count"]
                reserved = self._connection.execute(
                    "SELECT COUNT(*) AS count FROM gateway_reservations"
                ).fetchone()["count"]
                if queued + reserved >= self.max_queue_depth:
                    self._connection.execute("COMMIT")
                    return ReservationStatus.BACKPRESSURE
                self._connection.execute(
                    "INSERT INTO gateway_reservations"
                    "(tenant_id, event_id, source_id, request_hash, expires_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        tenant_id,
                        event_id,
                        source_id,
                        request_hash,
                        now_epoch + self.reservation_ttl_seconds,
                    ),
                )
                self._connection.execute("COMMIT")
                return ReservationStatus.RESERVED
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def cancel_reservation(self, tenant_id: str, event_id: str) -> None:
        with self._lock:
            self._connection.execute(
                "DELETE FROM gateway_reservations WHERE tenant_id = ? AND event_id = ?",
                (tenant_id, event_id),
            )

    def commit(self, envelope: TelemetryEnvelope, request_hash: str) -> int:
        tenant_id = envelope.context.tenant_id
        source_id = envelope.context.source_id
        now = utc_now()
        envelope_json = envelope.model_dump_json()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                reservation = self._connection.execute(
                    "SELECT request_hash FROM gateway_reservations "
                    "WHERE tenant_id = ? AND event_id = ?",
                    (tenant_id, envelope.event_id),
                ).fetchone()
                if reservation is None or not hmac.compare_digest(
                    reservation["request_hash"], request_hash
                ):
                    raise RuntimeError("gateway reservation is missing or mismatched")
                self._connection.execute(
                    "INSERT INTO gateway_events"
                    "(tenant_id, event_id, source_id, request_hash, envelope_json, received_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        tenant_id,
                        envelope.event_id,
                        source_id,
                        request_hash,
                        envelope_json,
                        now.isoformat(),
                    ),
                )
                cursor = self._connection.execute(
                    "INSERT INTO gateway_queue"
                    "(tenant_id, event_id, source_id, status, attempts, available_at, "
                    "created_at, updated_at) VALUES (?, ?, ?, 'pending', 0, ?, ?, ?)",
                    (
                        tenant_id,
                        envelope.event_id,
                        source_id,
                        now.timestamp(),
                        now.isoformat(),
                        now.isoformat(),
                    ),
                )
                self._connection.execute(
                    "DELETE FROM gateway_reservations WHERE tenant_id = ? AND event_id = ?",
                    (tenant_id, envelope.event_id),
                )
                self._metric(
                    tenant_id,
                    source_id,
                    "accepted_events",
                    received=True,
                )
                self._connection.execute("COMMIT")
                return int(cursor.lastrowid)
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def queue_summary(self) -> QueueSummary:
        with self._lock:
            rows = self._connection.execute(
                "SELECT status, COUNT(*) AS count FROM gateway_queue GROUP BY status"
            ).fetchall()
            counts = {row["status"]: int(row["count"]) for row in rows}
            reservations = int(
                self._connection.execute(
                    "SELECT COUNT(*) AS count FROM gateway_reservations WHERE expires_at > ?",
                    (time.time(),),
                ).fetchone()["count"]
            )
        return QueueSummary(
            pending=counts.get("pending", 0),
            processing=counts.get("processing", 0),
            succeeded=counts.get("succeeded", 0),
            dead_letter=counts.get("dead_letter", 0),
            reservations=reservations,
            capacity=self.max_queue_depth,
        )

    def source_health(
        self, *, tenant_id: Optional[str] = None, source_id: Optional[str] = None
    ) -> List[GatewaySourceHealth]:
        query = "SELECT * FROM gateway_source_stats"
        clauses: List[str] = []
        values: List[object] = []
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            values.append(tenant_id)
        if source_id is not None:
            clauses.append("source_id = ?")
            values.append(source_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY tenant_id, source_id"
        with self._lock:
            rows = self._connection.execute(query, tuple(values)).fetchall()
            health: List[GatewaySourceHealth] = []
            for row in rows:
                queue_counts = self._connection.execute(
                    "SELECT status, COUNT(*) AS count FROM gateway_queue "
                    "WHERE tenant_id = ? AND source_id = ? "
                    "AND status IN ('pending', 'processing', 'dead_letter') GROUP BY status",
                    (row["tenant_id"], row["source_id"]),
                ).fetchall()
                counts = {item["status"]: int(item["count"]) for item in queue_counts}
                pending = counts.get("pending", 0)
                processing = counts.get("processing", 0)
                dead_letter = counts.get("dead_letter", 0)
                if dead_letter:
                    status = "degraded"
                elif pending + processing >= max(1, self.max_queue_depth * 8 // 10):
                    status = "degraded"
                else:
                    status = "healthy"
                health.append(
                    GatewaySourceHealth(
                        tenant_id=row["tenant_id"],
                        source_id=row["source_id"],
                        status=status,
                        accepted_events=row["accepted_events"],
                        duplicate_events=row["duplicate_events"],
                        rejected_events=row["rejected_events"],
                        rate_limited_requests=row["rate_limited_requests"],
                        backpressured_events=row["backpressured_events"],
                        processed_events=row["processed_events"],
                        dead_letter_events=dead_letter,
                        pending_events=pending,
                        processing_events=processing,
                        last_received_at=row["last_received_at"],
                        last_processed_at=row["last_processed_at"],
                        last_error_code=row["last_error_code"],
                    )
                )
        return health

    def health_for(self, principal: WorkloadPrincipal) -> GatewaySourceHealth:
        matches = self.source_health(
            tenant_id=principal.tenant_id, source_id=principal.source_id
        )
        if matches:
            return matches[0]
        return GatewaySourceHealth(
            tenant_id=principal.tenant_id,
            source_id=principal.source_id,
            status="healthy",
            accepted_events=0,
            duplicate_events=0,
            rejected_events=0,
            rate_limited_requests=0,
            backpressured_events=0,
            processed_events=0,
            dead_letter_events=0,
            pending_events=0,
            processing_events=0,
        )

    def claim(self, *, limit: int = 1, lease_seconds: int = 30) -> List[GatewayQueueItem]:
        if not 1 <= limit <= 1000 or not 1 <= lease_seconds <= 3600:
            raise ValueError("claim bounds are invalid")
        now_epoch = time.time()
        now_text = utc_now().isoformat()
        claimed: List[GatewayQueueItem] = []
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    "UPDATE gateway_queue SET status = 'pending', lease_until = NULL, "
                    "available_at = ?, updated_at = ? "
                    "WHERE status = 'processing' AND lease_until <= ?",
                    (now_epoch, now_text, now_epoch),
                )
                rows = self._connection.execute(
                    "SELECT q.queue_id, q.tenant_id, q.source_id, q.event_id, "
                    "q.attempts, e.envelope_json FROM gateway_queue q "
                    "JOIN gateway_events e ON e.tenant_id = q.tenant_id "
                    "AND e.event_id = q.event_id "
                    "WHERE q.status = 'pending' AND q.available_at <= ? "
                    "ORDER BY q.queue_id LIMIT ?",
                    (now_epoch, limit),
                ).fetchall()
                for row in rows:
                    attempts = int(row["attempts"]) + 1
                    self._connection.execute(
                        "UPDATE gateway_queue SET status = 'processing', attempts = ?, "
                        "lease_until = ?, updated_at = ? WHERE queue_id = ?",
                        (attempts, now_epoch + lease_seconds, now_text, row["queue_id"]),
                    )
                    claimed.append(
                        GatewayQueueItem(
                            queue_id=row["queue_id"],
                            tenant_id=row["tenant_id"],
                            source_id=row["source_id"],
                            event_id=row["event_id"],
                            attempts=attempts,
                            envelope=TelemetryEnvelope.model_validate_json(row["envelope_json"]),
                        )
                    )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return claimed

    def acknowledge(self, queue_id: int) -> None:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT tenant_id, source_id FROM gateway_queue "
                    "WHERE queue_id = ? AND status = 'processing'",
                    (queue_id,),
                ).fetchone()
                if row is None:
                    raise KeyError(queue_id)
                self._connection.execute(
                    "UPDATE gateway_queue SET status = 'succeeded', lease_until = NULL, "
                    "updated_at = ? WHERE queue_id = ?",
                    (utc_now().isoformat(), queue_id),
                )
                self._metric(
                    row["tenant_id"],
                    row["source_id"],
                    "processed_events",
                    processed=True,
                )
                self._connection.execute(
                    "UPDATE gateway_source_stats SET last_error_code = NULL "
                    "WHERE tenant_id = ? AND source_id = ?",
                    (row["tenant_id"], row["source_id"]),
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def fail(
        self,
        queue_id: int,
        *,
        error_code: str,
        max_attempts: int = 3,
        retry_delay_seconds: int = 1,
    ) -> str:
        if re.fullmatch(r"[a-z0-9_]{1,128}", error_code) is None:
            raise ValueError("error_code must be a fixed machine-readable code")
        if not 1 <= max_attempts <= 100 or not 0 <= retry_delay_seconds <= 86400:
            raise ValueError("retry bounds are invalid")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT tenant_id, source_id, attempts FROM gateway_queue "
                    "WHERE queue_id = ? AND status = 'processing'",
                    (queue_id,),
                ).fetchone()
                if row is None:
                    raise KeyError(queue_id)
                dead = int(row["attempts"]) >= max_attempts
                status = "dead_letter" if dead else "pending"
                self._connection.execute(
                    "UPDATE gateway_queue SET status = ?, lease_until = NULL, "
                    "available_at = ?, last_error_code = ?, updated_at = ? "
                    "WHERE queue_id = ?",
                    (
                        status,
                        time.time() + retry_delay_seconds,
                        error_code,
                        utc_now().isoformat(),
                        queue_id,
                    ),
                )
                if dead:
                    self._metric(
                        row["tenant_id"],
                        row["source_id"],
                        "dead_letter_events",
                        error_code=error_code,
                    )
                else:
                    self._connection.execute(
                        "UPDATE gateway_source_stats SET last_error_code = ? "
                        "WHERE tenant_id = ? AND source_id = ?",
                        (error_code, row["tenant_id"], row["source_id"]),
                    )
                self._connection.execute("COMMIT")
                return status
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def redrive(self, queue_id: int) -> None:
        with self._lock:
            cursor = self._connection.execute(
                "UPDATE gateway_queue SET status = 'pending', attempts = 0, "
                "available_at = ?, lease_until = NULL, last_error_code = NULL, "
                "updated_at = ? WHERE queue_id = ? AND status = 'dead_letter'",
                (time.time(), utc_now().isoformat(), queue_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(queue_id)


class WorkloadAuthenticator:
    def __init__(
        self,
        credentials: Sequence[WorkloadCredential],
        store: DurableGatewayStore,
        *,
        max_clock_skew_seconds: int = MAX_CLOCK_SKEW_SECONDS,
    ) -> None:
        if not 30 <= max_clock_skew_seconds <= 3600:
            raise ValueError("max_clock_skew_seconds must be between 30 and 3600")
        self._credentials = {item.credential_id: item for item in credentials}
        if len(self._credentials) != len(credentials) or not self._credentials:
            raise ValueError("at least one unique workload credential is required")
        self.store = store
        self.max_clock_skew_seconds = max_clock_skew_seconds

    def authenticate(
        self,
        *,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        now_epoch: Optional[float] = None,
    ) -> WorkloadPrincipal:
        key_id = headers.get("X-AgentSec-Key-Id", "")
        timestamp = headers.get("X-AgentSec-Timestamp", "")
        nonce = headers.get("X-AgentSec-Nonce", "")
        supplied = headers.get("X-AgentSec-Signature", "")
        if (
            KEY_ID_PATTERN.fullmatch(key_id) is None
            or not timestamp.isdigit()
            or NONCE_PATTERN.fullmatch(nonce) is None
            or not supplied.startswith(SIGNATURE_VERSION + "=")
            or SIGNATURE_PATTERN.fullmatch(supplied[len(SIGNATURE_VERSION) + 1 :]) is None
        ):
            raise GatewayAuthenticationError("invalid_authentication_headers")
        credential = self._credentials.get(key_id)
        if credential is None:
            raise GatewayAuthenticationError("invalid_workload_credential")
        now = time.time() if now_epoch is None else now_epoch
        if abs(now - int(timestamp)) > self.max_clock_skew_seconds:
            raise GatewayAuthenticationError("request_timestamp_outside_window")
        expected = credential.signature(
            canonical_request(
                method=method,
                path=path,
                timestamp=timestamp,
                nonce=nonce,
                body=body,
            )
        )
        if not hmac.compare_digest(supplied, "%s=%s" % (SIGNATURE_VERSION, expected)):
            raise GatewayAuthenticationError("invalid_workload_signature")
        if not self.store.register_nonce(
            credential.credential_id,
            nonce,
            now_epoch=now,
            ttl_seconds=self.max_clock_skew_seconds * 2,
        ):
            raise GatewayAuthenticationError("request_replay_detected")
        return credential.principal


class TokenBucketRateLimiter:
    """Thread-safe per-credential token bucket for bounded request admission."""

    def __init__(self, *, capacity: int = 1000, refill_per_second: float = 100.0) -> None:
        if capacity < 1 or refill_per_second <= 0:
            raise ValueError("rate limiter settings must be positive")
        self.capacity = float(capacity)
        self.refill_per_second = refill_per_second
        self._lock = threading.Lock()
        self._buckets: Dict[str, Tuple[float, float]] = {}

    def allow(self, key: str, *, cost: int = 1, now: Optional[float] = None) -> Tuple[bool, int]:
        if cost < 1 or cost > self.capacity:
            return False, max(1, int(cost / self.refill_per_second))
        current = time.monotonic() if now is None else now
        with self._lock:
            tokens, previous = self._buckets.get(key, (self.capacity, current))
            tokens = min(self.capacity, tokens + max(0.0, current - previous) * self.refill_per_second)
            if tokens < cost:
                wait = max(1, int((cost - tokens) / self.refill_per_second) + 1)
                self._buckets[key] = (tokens, current)
                return False, wait
            self._buckets[key] = (tokens - cost, current)
            return True, 0


class IngestionGateway:
    def __init__(
        self,
        *,
        store: DurableGatewayStore,
        authenticator: WorkloadAuthenticator,
        collector: Optional[TelemetryCollector] = None,
        rate_limiter: Optional[TokenBucketRateLimiter] = None,
        max_batch_events: int = 1000,
    ) -> None:
        if not 1 <= max_batch_events <= 10000:
            raise ValueError("max_batch_events must be between 1 and 10000")
        self.store = store
        self.authenticator = authenticator
        self.collector = collector or TelemetryCollector()
        self.rate_limiter = rate_limiter or TokenBucketRateLimiter()
        self.max_batch_events = max_batch_events
        self._ingest_lock = threading.RLock()

    def authenticate(
        self, *, method: str, path: str, headers: Mapping[str, str], body: bytes
    ) -> WorkloadPrincipal:
        return self.authenticator.authenticate(
            method=method, path=path, headers=headers, body=body
        )

    def admit(self, principal: WorkloadPrincipal, *, cost: int) -> Tuple[bool, int]:
        allowed, retry_after = self.rate_limiter.allow(principal.credential_id, cost=cost)
        if not allowed:
            self.store.record_metric(principal, "rate_limited_requests", error_code="rate_limited")
        return allowed, retry_after

    @staticmethod
    def _request_hash(event: TelemetryInput) -> str:
        canonical = json.dumps(
            event.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def _identity_error(
        principal: WorkloadPrincipal, event: TelemetryInput
    ) -> Optional[str]:
        if event.context.tenant_id != principal.tenant_id:
            return "tenant_binding_mismatch"
        if event.context.source_id != principal.source_id:
            return "source_binding_mismatch"
        if (
            principal.application_ids
            and event.context.application_id not in principal.application_ids
        ):
            return "application_binding_mismatch"
        return None

    def _receipt(
        self,
        principal: WorkloadPrincipal,
        status: GatewayEventStatus,
        *,
        event_id: Optional[str],
        reason_code: Optional[str] = None,
        queue_id: Optional[int] = None,
    ) -> GatewayReceipt:
        return GatewayReceipt(
            status=status,
            event_id=event_id,
            tenant_id=principal.tenant_id,
            source_id=principal.source_id,
            queue_id=queue_id,
            reason_codes=[reason_code] if reason_code else [],
            source_health=self.store.health_for(principal),
        )

    def ingest_one(
        self, principal: WorkloadPrincipal, payload: Mapping[str, object]
    ) -> GatewayReceipt:
        try:
            event = TelemetryInput.model_validate(payload)
        except (ValidationError, ValueError, TypeError):
            self.store.record_metric(principal, "rejected_events", error_code="invalid_telemetry_input")
            event_id = payload.get("event_id")
            return self._receipt(
                principal,
                GatewayEventStatus.REJECTED,
                event_id=event_id if isinstance(event_id, str) else None,
                reason_code="invalid_telemetry_input",
            )
        identity_error = self._identity_error(principal, event)
        if identity_error:
            self.store.record_metric(principal, "rejected_events", error_code=identity_error)
            return self._receipt(
                principal,
                GatewayEventStatus.REJECTED,
                event_id=event.event_id,
                reason_code=identity_error,
            )
        request_hash = self._request_hash(event)
        with self._ingest_lock:
            reservation = self.store.reserve(
                tenant_id=principal.tenant_id,
                source_id=principal.source_id,
                event_id=event.event_id,
                request_hash=request_hash,
            )
            if reservation == ReservationStatus.DUPLICATE:
                self.store.record_metric(principal, "duplicate_events")
                return self._receipt(
                    principal,
                    GatewayEventStatus.DUPLICATE,
                    event_id=event.event_id,
                    reason_code="duplicate_event_id",
                )
            if reservation == ReservationStatus.PROCESSING:
                return self._receipt(
                    principal,
                    GatewayEventStatus.PROCESSING,
                    event_id=event.event_id,
                    reason_code="event_in_progress",
                )
            if reservation == ReservationStatus.CONFLICT:
                self.store.record_metric(principal, "rejected_events", error_code="event_id_conflict")
                return self._receipt(
                    principal,
                    GatewayEventStatus.CONFLICT,
                    event_id=event.event_id,
                    reason_code="event_id_conflict",
                )
            if reservation == ReservationStatus.BACKPRESSURE:
                self.store.record_metric(
                    principal, "backpressured_events", error_code="queue_capacity_exhausted"
                )
                return self._receipt(
                    principal,
                    GatewayEventStatus.BACKPRESSURE,
                    event_id=event.event_id,
                    reason_code="queue_capacity_exhausted",
                )
            capture = self.collector.capture(event)
            if capture.receipt.status != CaptureStatus.ACCEPTED or capture.event is None:
                self.store.cancel_reservation(principal.tenant_id, event.event_id)
                reason = (
                    capture.receipt.reason_codes[0]
                    if capture.receipt.reason_codes
                    else "telemetry_collection_rejected"
                )
                self.store.record_metric(principal, "rejected_events", error_code=reason)
                return self._receipt(
                    principal,
                    GatewayEventStatus.REJECTED,
                    event_id=event.event_id,
                    reason_code=reason,
                )
            queue_id = self.store.commit(capture.event, request_hash)
            return self._receipt(
                principal,
                GatewayEventStatus.ACCEPTED,
                event_id=event.event_id,
                queue_id=queue_id,
            )

    def ingest_batch(
        self, principal: WorkloadPrincipal, payloads: Sequence[Mapping[str, object]]
    ) -> GatewayBatchResponse:
        if not 1 <= len(payloads) <= self.max_batch_events:
            raise ValueError("events must contain 1 to %d telemetry records" % self.max_batch_events)
        receipts = [self.ingest_one(principal, payload) for payload in payloads]
        return GatewayBatchResponse(
            accepted=sum(item.status == GatewayEventStatus.ACCEPTED for item in receipts),
            duplicates=sum(item.status == GatewayEventStatus.DUPLICATE for item in receipts),
            processing=sum(item.status == GatewayEventStatus.PROCESSING for item in receipts),
            rejected=sum(item.status == GatewayEventStatus.REJECTED for item in receipts),
            conflicts=sum(item.status == GatewayEventStatus.CONFLICT for item in receipts),
            backpressured=sum(item.status == GatewayEventStatus.BACKPRESSURE for item in receipts),
            receipts=receipts,
        )

    def process_once(
        self,
        handler: Callable[[TelemetryEnvelope], None],
        *,
        limit: int = 100,
        max_attempts: int = 3,
    ) -> Tuple[int, int]:
        succeeded = 0
        failed = 0
        for item in self.store.claim(limit=limit):
            try:
                handler(item.envelope)
            except Exception:
                self.store.fail(
                    item.queue_id,
                    error_code="downstream_processing_failed",
                    max_attempts=max_attempts,
                )
                failed += 1
            else:
                self.store.acknowledge(item.queue_id)
                succeeded += 1
        return succeeded, failed


def gateway_from_environment() -> Optional[IngestionGateway]:
    """Build a gateway only when an explicit credential set is configured."""

    raw = os.environ.get("AGENTSEC_WORKLOAD_CREDENTIALS_JSON", "")
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, list) or not parsed:
            raise ValueError("credentials must be a non-empty list")
        credentials = [
            WorkloadCredential(
                credential_id=item["credential_id"],
                secret=item["secret"],
                tenant_id=item["tenant_id"],
                source_id=item["source_id"],
                application_ids=item.get("application_ids", []),
            )
            for item in parsed
            if isinstance(item, dict)
        ]
        if len(credentials) != len(parsed):
            raise ValueError("every credential must be an object")
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("AGENTSEC_WORKLOAD_CREDENTIALS_JSON is invalid") from exc
    database_path = os.environ.get("AGENTSEC_GATEWAY_DB", "agentsec-gateway.db")
    if database_path != ":memory:":
        parent = Path(database_path).expanduser().resolve().parent
        if not parent.is_dir():
            raise ValueError("AGENTSEC_GATEWAY_DB parent directory does not exist")
    try:
        queue_depth = int(os.environ.get("AGENTSEC_GATEWAY_QUEUE_DEPTH", "10000"))
        rate_capacity = int(os.environ.get("AGENTSEC_GATEWAY_RATE_CAPACITY", "1000"))
        rate_refill = float(os.environ.get("AGENTSEC_GATEWAY_RATE_REFILL", "100"))
        mode = CollectionMode(os.environ.get("AGENTSEC_COLLECTION_MODE", "metadata_only"))
    except ValueError as exc:
        raise ValueError("AgentSec gateway numeric or collection-mode configuration is invalid") from exc
    if mode == CollectionMode.ENCRYPTED_RAW:
        raise ValueError("encrypted_raw gateway mode requires an injected ContentProtector")
    store = DurableGatewayStore(database_path, max_queue_depth=queue_depth)
    authenticator = WorkloadAuthenticator(credentials, store)
    return IngestionGateway(
        store=store,
        authenticator=authenticator,
        collector=TelemetryCollector(CollectorConfig(collection_mode=mode)),
        rate_limiter=TokenBucketRateLimiter(
            capacity=rate_capacity, refill_per_second=rate_refill
        ),
    )
