"""Transactional canonical record, evidence, retention, and recovery storage."""

from __future__ import annotations

import hashlib
import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from pydantic import Field, model_validator

from .contracts import StrictModel, new_id, utc_now
from .crypto import PocHmacSigner
from .datamodel import (
    CANONICAL_RECORD_ADAPTER,
    ID_FIELDS,
    ActionRecord,
    AlertRecord,
    CanonicalBundle,
    CanonicalRecord,
    EventRecord,
    EvidenceRecord,
    FindingRecord,
    IncidentRecord,
    InvestigationRecord,
    JudgmentRecord,
    RecordType,
    canonical_record_json,
)


GENESIS_HASH = "0" * 64
IMMUTABLE_RECORD_TYPES = {
    RecordType.EVENT,
    RecordType.EVIDENCE,
    RecordType.ALERT,
    RecordType.JUDGMENT,
    RecordType.ACTION,
}


class RecordCommitReceipt(StrictModel):
    tenant_id: str
    record_type: RecordType
    record_id: str
    revision: int = Field(ge=1)
    ledger_sequence: int = Field(ge=1)
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    previous_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    current_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    duplicate: bool
    committed_at: datetime


class StorageVerification(StrictModel):
    tenant_id: str
    valid: bool
    reason: str
    first_broken_sequence: int = Field(ge=0)
    ledger_entries: int = Field(ge=0)
    active_payloads: int = Field(ge=0)
    expired_payloads: int = Field(ge=0)
    protected_evidence_blobs: int = Field(ge=0)


class ProtectedEvidenceBlob(StrictModel):
    evidence_id: str = Field(min_length=5, max_length=128)
    ciphertext: str = Field(min_length=1, max_length=10_000_000)
    key_reference: str = Field(min_length=1, max_length=512)
    algorithm: str = Field(min_length=1, max_length=128)
    plaintext_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ciphertext_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    protected_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def ciphertext_receipt_matches(self) -> "ProtectedEvidenceBlob":
        expected = hashlib.sha256(self.ciphertext.encode("utf-8")).hexdigest()
        if expected != self.ciphertext_sha256:
            raise ValueError("protected evidence ciphertext digest mismatch")
        if self.protected_at.tzinfo is None or self.protected_at.utcoffset() is None:
            raise ValueError("protected_at must include a timezone")
        return self


class StorageCheckpoint(StrictModel):
    checkpoint_id: str = Field(default_factory=lambda: new_id("scp"))
    tenant_id: str = Field(min_length=1, max_length=128)
    sequence: int = Field(ge=0)
    current_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime = Field(default_factory=utc_now)
    signature_algorithm: str = PocHmacSigner.algorithm
    signature: str = ""

    def unsigned_payload(self) -> Dict[str, object]:
        return self.model_dump(mode="json", exclude={"signature"})


class CheckpointResult(StrictModel):
    valid: bool
    reason: str
    sequence: int = Field(ge=0)


class RetentionPolicy(StrictModel):
    policy_id: str = Field(min_length=1, max_length=128)
    retention_days: Dict[RecordType, int]

    @model_validator(mode="after")
    def complete_and_bounded(self) -> "RetentionPolicy":
        if set(self.retention_days) != set(RecordType):
            raise ValueError("retention policy must cover every canonical record type")
        if any(not 1 <= days <= 36500 for days in self.retention_days.values()):
            raise ValueError("retention days must be between 1 and 36500")
        return self


class RetentionResult(StrictModel):
    policy_id: str
    evaluated_at: datetime
    expired_payloads: int = Field(ge=0)
    expired_blobs: int = Field(ge=0)
    held_payloads: int = Field(ge=0)


class BackupManifest(StrictModel):
    backup_id: str = Field(default_factory=lambda: new_id("bak"))
    backup_path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    byte_length: int = Field(ge=1)
    created_at: datetime = Field(default_factory=utc_now)
    tenant_verifications: List[StorageVerification]


def _record_identity(record: CanonicalRecord) -> str:
    return str(getattr(record, ID_FIELDS[record.record_type]))


def _ledger_hash(
    *,
    tenant_id: str,
    sequence: int,
    record_type: str,
    record_id: str,
    revision: int,
    record_sha256: str,
    previous_hash: str,
) -> str:
    material = "\n".join(
        [
            tenant_id,
            str(sequence),
            record_type,
            record_id,
            str(revision),
            record_sha256,
            previous_hash,
        ]
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


class CanonicalRepository:
    """SQLite system of record with append-only tenant hash chains."""

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

    def _migrate(self) -> None:
        with self._lock:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS canonical_records (
                    tenant_id TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    record_json TEXT,
                    record_sha256 TEXT NOT NULL,
                    payload_state TEXT NOT NULL CHECK (payload_state IN ('active', 'expired')),
                    committed_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, record_type, record_id, revision)
                );
                CREATE TABLE IF NOT EXISTS canonical_heads (
                    tenant_id TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    current_revision INTEGER NOT NULL,
                    current_sha256 TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, record_type, record_id)
                );
                CREATE TABLE IF NOT EXISTS canonical_ledger (
                    tenant_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    record_type TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    current_hash TEXT NOT NULL,
                    committed_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, sequence),
                    FOREIGN KEY (tenant_id, record_type, record_id, revision)
                      REFERENCES canonical_records(tenant_id, record_type, record_id, revision)
                );
                CREATE TABLE IF NOT EXISTS protected_evidence_blobs (
                    tenant_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    ciphertext TEXT,
                    key_reference TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    plaintext_sha256 TEXT NOT NULL,
                    ciphertext_sha256 TEXT NOT NULL,
                    blob_state TEXT NOT NULL CHECK (blob_state IN ('active', 'expired')),
                    protected_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, evidence_id)
                );
                CREATE TABLE IF NOT EXISTS storage_checkpoints (
                    checkpoint_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    current_hash TEXT NOT NULL,
                    checkpoint_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS retention_holds (
                    tenant_id TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    placed_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, record_type, record_id)
                );
                CREATE TABLE IF NOT EXISTS retention_tombstones (
                    tenant_id TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    expired_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, record_type, record_id, revision)
                );
                CREATE INDEX IF NOT EXISTS canonical_record_lookup
                  ON canonical_records(tenant_id, record_type, record_id, revision DESC);
                CREATE INDEX IF NOT EXISTS canonical_record_retention
                  ON canonical_records(record_type, payload_state, committed_at);
                """
            )

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("repository clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    def _commit_in_transaction(
        self, record: CanonicalRecord, committed_at: datetime
    ) -> RecordCommitReceipt:
        record_id = _record_identity(record)
        tenant_id = record.tenant_id
        kind = record.record_type.value
        encoded = canonical_record_json(record)
        digest = hashlib.sha256(encoded).hexdigest()
        head = self._connection.execute(
            "SELECT current_revision, current_sha256 FROM canonical_heads "
            "WHERE tenant_id = ? AND record_type = ? AND record_id = ?",
            (tenant_id, kind, record_id),
        ).fetchone()
        if head is not None and head["current_sha256"] == digest:
            ledger = self._connection.execute(
                "SELECT * FROM canonical_ledger WHERE tenant_id = ? AND record_type = ? "
                "AND record_id = ? AND revision = ?",
                (tenant_id, kind, record_id, head["current_revision"]),
            ).fetchone()
            return RecordCommitReceipt(
                tenant_id=tenant_id,
                record_type=record.record_type,
                record_id=record_id,
                revision=head["current_revision"],
                ledger_sequence=ledger["sequence"],
                record_sha256=digest,
                previous_hash=ledger["previous_hash"],
                current_hash=ledger["current_hash"],
                duplicate=True,
                committed_at=ledger["committed_at"],
            )
        if head is not None and record.record_type in IMMUTABLE_RECORD_TYPES:
            raise ValueError("immutable canonical record ID cannot be reused with new content")
        self._validate_record_references(record)
        revision = 1 if head is None else int(head["current_revision"]) + 1
        ledger_head = self._connection.execute(
            "SELECT sequence, current_hash FROM canonical_ledger "
            "WHERE tenant_id = ? ORDER BY sequence DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        sequence = 1 if ledger_head is None else int(ledger_head["sequence"]) + 1
        previous_hash = GENESIS_HASH if ledger_head is None else ledger_head["current_hash"]
        current_hash = _ledger_hash(
            tenant_id=tenant_id,
            sequence=sequence,
            record_type=kind,
            record_id=record_id,
            revision=revision,
            record_sha256=digest,
            previous_hash=previous_hash,
        )
        timestamp = committed_at.isoformat()
        self._connection.execute(
            "INSERT INTO canonical_records"
            "(tenant_id, record_type, record_id, revision, record_json, record_sha256, "
            "payload_state, committed_at) VALUES (?, ?, ?, ?, ?, ?, 'active', ?)",
            (tenant_id, kind, record_id, revision, encoded.decode("utf-8"), digest, timestamp),
        )
        self._connection.execute(
            "INSERT INTO canonical_heads"
            "(tenant_id, record_type, record_id, current_revision, current_sha256) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT(tenant_id, record_type, record_id) "
            "DO UPDATE SET current_revision = excluded.current_revision, "
            "current_sha256 = excluded.current_sha256",
            (tenant_id, kind, record_id, revision, digest),
        )
        self._connection.execute(
            "INSERT INTO canonical_ledger"
            "(tenant_id, sequence, record_type, record_id, revision, record_sha256, "
            "previous_hash, current_hash, committed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tenant_id,
                sequence,
                kind,
                record_id,
                revision,
                digest,
                previous_hash,
                current_hash,
                timestamp,
            ),
        )
        return RecordCommitReceipt(
            tenant_id=tenant_id,
            record_type=record.record_type,
            record_id=record_id,
            revision=revision,
            ledger_sequence=sequence,
            record_sha256=digest,
            previous_hash=previous_hash,
            current_hash=current_hash,
            duplicate=False,
            committed_at=committed_at,
        )

    def _validate_record_references(self, record: CanonicalRecord) -> None:
        references: List[Tuple[RecordType, str]] = []
        if isinstance(record, EventRecord):
            references.extend(
                (RecordType.ENTITY, item)
                for item in [record.actor_entity_id, *record.target_entity_ids]
            )
            references.extend((RecordType.EVIDENCE, item) for item in record.evidence_ids)
        elif isinstance(record, AlertRecord):
            references.append((RecordType.EVENT, record.event_id))
            references.extend((RecordType.EVIDENCE, item) for item in record.evidence_ids)
        elif isinstance(record, FindingRecord):
            references.extend((RecordType.ALERT, item) for item in record.alert_ids)
            references.extend((RecordType.ENTITY, item) for item in record.entity_ids)
            references.extend((RecordType.EVIDENCE, item) for item in record.evidence_ids)
        elif isinstance(record, IncidentRecord):
            references.extend((RecordType.FINDING, item) for item in record.finding_ids)
            references.extend((RecordType.ENTITY, item) for item in record.entity_ids)
        elif isinstance(record, InvestigationRecord):
            references.append((RecordType.INCIDENT, record.incident_id))
            references.extend((RecordType.EVIDENCE, item) for item in record.evidence_ids)
            for step in record.steps:
                references.extend((RecordType.EVIDENCE, item) for item in step.evidence_ids)
        elif isinstance(record, JudgmentRecord):
            references.append((RecordType(record.subject_type), record.subject_id))
            references.extend((RecordType.EVIDENCE, item) for item in record.evidence_ids)
        elif isinstance(record, ActionRecord):
            references.extend(
                [
                    (RecordType.INCIDENT, record.incident_id),
                    (RecordType.JUDGMENT, record.judgment_id),
                ]
            )
            references.extend((RecordType.ENTITY, item) for item in record.target_entity_ids)
            references.extend((RecordType.EVIDENCE, item) for item in record.evidence_ids)
        for kind, identity in references:
            exists = self._connection.execute(
                "SELECT 1 FROM canonical_heads h JOIN canonical_records r "
                "ON r.tenant_id = h.tenant_id AND r.record_type = h.record_type "
                "AND r.record_id = h.record_id AND r.revision = h.current_revision "
                "WHERE h.tenant_id = ? AND h.record_type = ? AND h.record_id = ? "
                "AND r.payload_state = 'active'",
                (record.tenant_id, kind.value, identity),
            ).fetchone()
            if exists is None:
                raise ValueError(
                    "canonical repository reference is unresolved: %s" % kind.value
                )

    def commit(self, record: CanonicalRecord) -> RecordCommitReceipt:
        committed_at = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                receipt = self._commit_in_transaction(record, committed_at)
                self._connection.execute("COMMIT")
                return receipt
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def commit_bundle(self, bundle: CanonicalBundle) -> List[RecordCommitReceipt]:
        committed_at = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                receipts = [
                    self._commit_in_transaction(record, committed_at)
                    for record in bundle.records
                ]
                self._connection.execute("COMMIT")
                return receipts
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def get(
        self, tenant_id: str, record_type: RecordType, record_id: str
    ) -> CanonicalRecord:
        with self._lock:
            row = self._connection.execute(
                "SELECT r.record_json, r.payload_state FROM canonical_records r "
                "JOIN canonical_heads h ON h.tenant_id = r.tenant_id "
                "AND h.record_type = r.record_type AND h.record_id = r.record_id "
                "AND h.current_revision = r.revision WHERE r.tenant_id = ? "
                "AND r.record_type = ? AND r.record_id = ?",
                (tenant_id, record_type.value, record_id),
            ).fetchone()
        if row is None:
            raise KeyError(record_id)
        if row["payload_state"] != "active" or row["record_json"] is None:
            raise KeyError("record payload expired")
        return CANONICAL_RECORD_ADAPTER.validate_json(row["record_json"])

    def history(
        self, tenant_id: str, record_type: RecordType, record_id: str
    ) -> List[Optional[CanonicalRecord]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT record_json FROM canonical_records WHERE tenant_id = ? "
                "AND record_type = ? AND record_id = ? ORDER BY revision",
                (tenant_id, record_type.value, record_id),
            ).fetchall()
        if not rows:
            raise KeyError(record_id)
        return [
            CANONICAL_RECORD_ADAPTER.validate_json(row["record_json"])
            if row["record_json"] is not None
            else None
            for row in rows
        ]

    def latest_records(
        self,
        tenant_id: str,
        *,
        record_types: Optional[Set[RecordType]] = None,
        limit: int = 10000,
    ) -> List[CanonicalRecord]:
        if not 1 <= limit <= 100000:
            raise ValueError("latest record limit must be between 1 and 100000")
        values: List[object] = [tenant_id]
        type_clause = ""
        if record_types:
            ordered = sorted(item.value for item in record_types)
            type_clause = " AND r.record_type IN (%s)" % ",".join("?" for _ in ordered)
            values.extend(ordered)
        values.append(limit)
        with self._lock:
            rows = self._connection.execute(
                "SELECT r.record_json FROM canonical_records r JOIN canonical_heads h "
                "ON h.tenant_id = r.tenant_id AND h.record_type = r.record_type "
                "AND h.record_id = r.record_id AND h.current_revision = r.revision "
                "WHERE r.tenant_id = ? AND r.payload_state = 'active'"
                + type_clause
                + " ORDER BY r.record_type, r.record_id LIMIT ?",
                tuple(values),
            ).fetchall()
        return [CANONICAL_RECORD_ADAPTER.validate_json(row["record_json"]) for row in rows]

    def active_record_count(self, tenant_id: str) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT COUNT(*) AS count FROM canonical_heads h JOIN canonical_records r "
                "ON h.tenant_id = r.tenant_id AND h.record_type = r.record_type "
                "AND h.record_id = r.record_id AND h.current_revision = r.revision "
                "WHERE h.tenant_id = ? AND r.payload_state = 'active'",
                (tenant_id,),
            ).fetchone()
        return int(row["count"])

    def put_protected_evidence(
        self, tenant_id: str, blob: ProtectedEvidenceBlob
    ) -> None:
        record = self.get(tenant_id, RecordType.EVIDENCE, blob.evidence_id)
        if not isinstance(record, EvidenceRecord):
            raise TypeError("protected evidence requires an EvidenceRecord")
        if record.content_sha256 != blob.plaintext_sha256:
            raise ValueError("protected evidence plaintext receipt does not match record")
        with self._lock:
            existing = self._connection.execute(
                "SELECT ciphertext_sha256 FROM protected_evidence_blobs "
                "WHERE tenant_id = ? AND evidence_id = ?",
                (tenant_id, blob.evidence_id),
            ).fetchone()
            if existing is not None:
                if existing["ciphertext_sha256"] == blob.ciphertext_sha256:
                    return
                raise ValueError("protected evidence is immutable")
            self._connection.execute(
                "INSERT INTO protected_evidence_blobs"
                "(tenant_id, evidence_id, ciphertext, key_reference, algorithm, "
                "plaintext_sha256, ciphertext_sha256, blob_state, protected_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)",
                (
                    tenant_id,
                    blob.evidence_id,
                    blob.ciphertext,
                    blob.key_reference,
                    blob.algorithm,
                    blob.plaintext_sha256,
                    blob.ciphertext_sha256,
                    blob.protected_at.isoformat(),
                ),
            )

    def get_protected_evidence(
        self, tenant_id: str, evidence_id: str
    ) -> ProtectedEvidenceBlob:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM protected_evidence_blobs WHERE tenant_id = ? "
                "AND evidence_id = ? AND blob_state = 'active'",
                (tenant_id, evidence_id),
            ).fetchone()
        if row is None or row["ciphertext"] is None:
            raise KeyError(evidence_id)
        return ProtectedEvidenceBlob(
            evidence_id=evidence_id,
            ciphertext=row["ciphertext"],
            key_reference=row["key_reference"],
            algorithm=row["algorithm"],
            plaintext_sha256=row["plaintext_sha256"],
            ciphertext_sha256=row["ciphertext_sha256"],
            protected_at=row["protected_at"],
        )

    def latest_head(self, tenant_id: str) -> Tuple[int, str]:
        with self._lock:
            row = self._connection.execute(
                "SELECT sequence, current_hash FROM canonical_ledger "
                "WHERE tenant_id = ? ORDER BY sequence DESC LIMIT 1",
                (tenant_id,),
            ).fetchone()
        return (0, GENESIS_HASH) if row is None else (row["sequence"], row["current_hash"])

    def hash_at(self, tenant_id: str, sequence: int) -> str:
        if sequence == 0:
            return GENESIS_HASH
        with self._lock:
            row = self._connection.execute(
                "SELECT current_hash FROM canonical_ledger WHERE tenant_id = ? AND sequence = ?",
                (tenant_id, sequence),
            ).fetchone()
        if row is None:
            raise KeyError(sequence)
        return str(row["current_hash"])

    def verify(self, tenant_id: str) -> StorageVerification:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM canonical_ledger WHERE tenant_id = ? ORDER BY sequence",
                (tenant_id,),
            ).fetchall()
            previous_hash = GENESIS_HASH
            active = 0
            expired = 0
            for expected_sequence, row in enumerate(rows, start=1):
                if row["sequence"] != expected_sequence:
                    return self._verification_failure(
                        tenant_id, "sequence_mismatch", expected_sequence, rows
                    )
                expected_hash = _ledger_hash(
                    tenant_id=tenant_id,
                    sequence=expected_sequence,
                    record_type=row["record_type"],
                    record_id=row["record_id"],
                    revision=row["revision"],
                    record_sha256=row["record_sha256"],
                    previous_hash=previous_hash,
                )
                if row["previous_hash"] != previous_hash:
                    return self._verification_failure(
                        tenant_id, "previous_hash_mismatch", expected_sequence, rows
                    )
                if row["current_hash"] != expected_hash:
                    return self._verification_failure(
                        tenant_id, "current_hash_mismatch", expected_sequence, rows
                    )
                record = self._connection.execute(
                    "SELECT record_json, record_sha256, payload_state FROM canonical_records "
                    "WHERE tenant_id = ? AND record_type = ? AND record_id = ? AND revision = ?",
                    (tenant_id, row["record_type"], row["record_id"], row["revision"]),
                ).fetchone()
                if record is None or record["record_sha256"] != row["record_sha256"]:
                    return self._verification_failure(
                        tenant_id, "record_receipt_mismatch", expected_sequence, rows
                    )
                if record["payload_state"] == "active":
                    active += 1
                    if record["record_json"] is None or hashlib.sha256(
                        record["record_json"].encode("utf-8")
                    ).hexdigest() != record["record_sha256"]:
                        return self._verification_failure(
                            tenant_id, "record_payload_mismatch", expected_sequence, rows
                        )
                else:
                    expired += 1
                    tombstone = self._connection.execute(
                        "SELECT 1 FROM retention_tombstones WHERE tenant_id = ? "
                        "AND record_type = ? AND record_id = ? AND revision = ? "
                        "AND record_sha256 = ?",
                        (
                            tenant_id,
                            row["record_type"],
                            row["record_id"],
                            row["revision"],
                            row["record_sha256"],
                        ),
                    ).fetchone()
                    if record["record_json"] is not None or tombstone is None:
                        return self._verification_failure(
                            tenant_id, "retention_tombstone_mismatch", expected_sequence, rows
                        )
                previous_hash = expected_hash
            blob_rows = self._connection.execute(
                "SELECT * FROM protected_evidence_blobs WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchall()
            active_blobs = 0
            for blob in blob_rows:
                if blob["blob_state"] == "active":
                    active_blobs += 1
                    if blob["ciphertext"] is None or hashlib.sha256(
                        blob["ciphertext"].encode("utf-8")
                    ).hexdigest() != blob["ciphertext_sha256"]:
                        return self._verification_failure(
                            tenant_id, "protected_evidence_mismatch", 0, rows
                        )
                elif blob["ciphertext"] is not None:
                    return self._verification_failure(
                        tenant_id, "expired_evidence_not_erased", 0, rows
                    )
        return StorageVerification(
            tenant_id=tenant_id,
            valid=True,
            reason="ok",
            first_broken_sequence=0,
            ledger_entries=len(rows),
            active_payloads=active,
            expired_payloads=expired,
            protected_evidence_blobs=active_blobs,
        )

    def _verification_failure(
        self, tenant_id: str, reason: str, sequence: int, rows: List[sqlite3.Row]
    ) -> StorageVerification:
        return StorageVerification(
            tenant_id=tenant_id,
            valid=False,
            reason=reason,
            first_broken_sequence=sequence,
            ledger_entries=len(rows),
            active_payloads=0,
            expired_payloads=0,
            protected_evidence_blobs=0,
        )

    def tenants(self) -> List[str]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT DISTINCT tenant_id FROM canonical_ledger ORDER BY tenant_id"
            ).fetchall()
        return [str(row["tenant_id"]) for row in rows]

    def create_checkpoint(
        self, tenant_id: str, signer: PocHmacSigner
    ) -> StorageCheckpoint:
        sequence, current_hash = self.latest_head(tenant_id)
        unsigned = StorageCheckpoint(
            tenant_id=tenant_id,
            sequence=sequence,
            current_hash=current_hash,
            created_at=self._now(),
        )
        checkpoint = unsigned.model_copy(
            update={"signature": signer.sign(unsigned.unsigned_payload())}
        )
        with self._lock:
            self._connection.execute(
                "INSERT INTO storage_checkpoints"
                "(checkpoint_id, tenant_id, sequence, current_hash, checkpoint_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    checkpoint.checkpoint_id,
                    tenant_id,
                    sequence,
                    current_hash,
                    checkpoint.model_dump_json(),
                    checkpoint.created_at.isoformat(),
                ),
            )
        return checkpoint

    def verify_checkpoint(
        self, checkpoint: StorageCheckpoint, signer: PocHmacSigner
    ) -> CheckpointResult:
        if not signer.verify(checkpoint.unsigned_payload(), checkpoint.signature):
            return CheckpointResult(
                valid=False,
                reason="checkpoint_signature_invalid",
                sequence=checkpoint.sequence,
            )
        verification = self.verify(checkpoint.tenant_id)
        if not verification.valid:
            return CheckpointResult(
                valid=False,
                reason="ledger_%s" % verification.reason,
                sequence=verification.first_broken_sequence,
            )
        try:
            ledger_hash = self.hash_at(checkpoint.tenant_id, checkpoint.sequence)
        except KeyError:
            return CheckpointResult(
                valid=False,
                reason="checkpoint_ahead_of_ledger",
                sequence=checkpoint.sequence,
            )
        if ledger_hash != checkpoint.current_hash:
            return CheckpointResult(
                valid=False,
                reason="checkpoint_hash_mismatch",
                sequence=checkpoint.sequence,
            )
        return CheckpointResult(valid=True, reason="ok", sequence=checkpoint.sequence)

    def get_checkpoint(self, checkpoint_id: str) -> StorageCheckpoint:
        with self._lock:
            row = self._connection.execute(
                "SELECT checkpoint_json FROM storage_checkpoints WHERE checkpoint_id = ?",
                (checkpoint_id,),
            ).fetchone()
        if row is None:
            raise KeyError(checkpoint_id)
        return StorageCheckpoint.model_validate_json(row["checkpoint_json"])

    def place_hold(
        self,
        tenant_id: str,
        record_type: RecordType,
        record_id: str,
        *,
        reason: str,
    ) -> None:
        if re.fullmatch(r"[a-z0-9_.:-]{3,128}", reason) is None:
            raise ValueError("retention hold reason must be a fixed machine-readable code")
        self.get(tenant_id, record_type, record_id)
        with self._lock:
            self._connection.execute(
                "INSERT INTO retention_holds"
                "(tenant_id, record_type, record_id, reason, placed_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(tenant_id, record_type, record_id) DO UPDATE SET reason = excluded.reason",
                (tenant_id, record_type.value, record_id, reason, self._now().isoformat()),
            )

    def release_hold(
        self, tenant_id: str, record_type: RecordType, record_id: str
    ) -> None:
        with self._lock:
            cursor = self._connection.execute(
                "DELETE FROM retention_holds WHERE tenant_id = ? AND record_type = ? AND record_id = ?",
                (tenant_id, record_type.value, record_id),
            )
        if cursor.rowcount != 1:
            raise KeyError(record_id)

    def apply_retention(
        self, policy: RetentionPolicy, *, evaluated_at: Optional[datetime] = None
    ) -> RetentionResult:
        now = (evaluated_at or self._now()).astimezone(timezone.utc)
        expired_payloads = 0
        expired_blobs = 0
        held_payloads = 0
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                for record_type, days in policy.retention_days.items():
                    cutoff = (now - timedelta(days=days)).isoformat()
                    rows = self._connection.execute(
                        "SELECT * FROM canonical_records WHERE record_type = ? "
                        "AND payload_state = 'active' AND committed_at < ?",
                        (record_type.value, cutoff),
                    ).fetchall()
                    for row in rows:
                        hold = self._connection.execute(
                            "SELECT 1 FROM retention_holds WHERE tenant_id = ? "
                            "AND record_type = ? AND record_id = ?",
                            (row["tenant_id"], row["record_type"], row["record_id"]),
                        ).fetchone()
                        if hold is not None:
                            held_payloads += 1
                            continue
                        self._connection.execute(
                            "UPDATE canonical_records SET record_json = NULL, payload_state = 'expired' "
                            "WHERE tenant_id = ? AND record_type = ? AND record_id = ? AND revision = ?",
                            (
                                row["tenant_id"],
                                row["record_type"],
                                row["record_id"],
                                row["revision"],
                            ),
                        )
                        self._connection.execute(
                            "INSERT INTO retention_tombstones"
                            "(tenant_id, record_type, record_id, revision, record_sha256, "
                            "policy_id, expired_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (
                                row["tenant_id"],
                                row["record_type"],
                                row["record_id"],
                                row["revision"],
                                row["record_sha256"],
                                policy.policy_id,
                                now.isoformat(),
                            ),
                        )
                        expired_payloads += 1
                        if record_type == RecordType.EVIDENCE:
                            cursor = self._connection.execute(
                                "UPDATE protected_evidence_blobs SET ciphertext = NULL, "
                                "blob_state = 'expired' WHERE tenant_id = ? AND evidence_id = ? "
                                "AND blob_state = 'active'",
                                (row["tenant_id"], row["record_id"]),
                            )
                            expired_blobs += cursor.rowcount
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return RetentionResult(
            policy_id=policy.policy_id,
            evaluated_at=now,
            expired_payloads=expired_payloads,
            expired_blobs=expired_blobs,
            held_payloads=held_payloads,
        )

    def create_backup(self, destination: Path) -> BackupManifest:
        resolved = destination.resolve()
        if resolved.exists():
            raise FileExistsError(str(resolved))
        if not resolved.parent.is_dir():
            raise ValueError("backup destination parent must exist")
        verifications = [self.verify(tenant) for tenant in self.tenants()]
        if any(not item.valid for item in verifications):
            raise RuntimeError("cannot back up an invalid canonical repository")
        backup = sqlite3.connect(str(resolved))
        try:
            with self._lock:
                self._connection.backup(backup)
        finally:
            backup.close()
        payload = resolved.read_bytes()
        return BackupManifest(
            backup_path=str(resolved),
            sha256=hashlib.sha256(payload).hexdigest(),
            byte_length=len(payload),
            created_at=self._now(),
            tenant_verifications=verifications,
        )

    @classmethod
    def restore_backup(
        cls, manifest: BackupManifest, destination: Path
    ) -> "CanonicalRepository":
        source = Path(manifest.backup_path).resolve()
        target = destination.resolve()
        if not source.is_file():
            raise FileNotFoundError(str(source))
        payload = source.read_bytes()
        if len(payload) != manifest.byte_length or hashlib.sha256(payload).hexdigest() != manifest.sha256:
            raise ValueError("backup manifest digest mismatch")
        if target.exists():
            raise FileExistsError(str(target))
        if not target.parent.is_dir():
            raise ValueError("restore destination parent must exist")
        source_connection = sqlite3.connect(str(source))
        target_connection = sqlite3.connect(str(target))
        try:
            source_connection.backup(target_connection)
        finally:
            source_connection.close()
            target_connection.close()
        repository = cls(str(target))
        verifications = [repository.verify(tenant) for tenant in repository.tenants()]
        if any(not item.valid for item in verifications):
            repository.close()
            raise ValueError("restored repository failed integrity verification")
        return repository
