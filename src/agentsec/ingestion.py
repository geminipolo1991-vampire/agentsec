"""Idempotent local ingestion with a deterministic tamper-evident hash chain."""

from __future__ import annotations

import hashlib
import json
from typing import Dict, List

from .contracts import IngestionReceipt, SecurityAlert, StrictModel


GENESIS_HASH = "0" * 64


class LedgerVerification(StrictModel):
    valid: bool
    first_broken_sequence: int = 0
    reason: str = "ok"


def canonical_json(alert: SecurityAlert) -> bytes:
    payload = alert.model_dump(mode="json")
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class InMemoryAlertLedger:
    """PoC ledger; persistence adapters will implement this same behavior."""

    def __init__(self) -> None:
        self._alerts_by_fingerprint: Dict[str, SecurityAlert] = {}
        self._receipts_by_fingerprint: Dict[str, IngestionReceipt] = {}
        self._ordered_alerts: List[SecurityAlert] = []

    def ingest(self, alert: SecurityAlert) -> IngestionReceipt:
        existing = self._receipts_by_fingerprint.get(alert.fingerprint)
        if existing is not None:
            return existing.model_copy(update={"duplicate": True})

        sequence = len(self._ordered_alerts) + 1
        previous_hash = (
            self._receipts_by_fingerprint[self._ordered_alerts[-1].fingerprint].current_hash
            if self._ordered_alerts
            else GENESIS_HASH
        )
        digest = hashlib.sha256(
            canonical_json(alert)
            + previous_hash.encode("ascii")
            + str(sequence).encode("ascii")
        ).hexdigest()
        receipt = IngestionReceipt(
            alert_id=alert.alert_id,
            duplicate=False,
            sequence=sequence,
            previous_hash=previous_hash,
            current_hash=digest,
        )
        self._alerts_by_fingerprint[alert.fingerprint] = alert
        self._receipts_by_fingerprint[alert.fingerprint] = receipt
        self._ordered_alerts.append(alert)
        return receipt

    def verify(self) -> bool:
        return self.verify_detailed().valid

    def verify_detailed(self) -> LedgerVerification:
        previous_hash = GENESIS_HASH
        for sequence, alert in enumerate(self._ordered_alerts, start=1):
            expected = hashlib.sha256(
                canonical_json(alert)
                + previous_hash.encode("ascii")
                + str(sequence).encode("ascii")
            ).hexdigest()
            receipt = self._receipts_by_fingerprint[alert.fingerprint]
            if receipt.sequence != sequence:
                return LedgerVerification(
                    valid=False,
                    first_broken_sequence=sequence,
                    reason="sequence_mismatch",
                )
            if receipt.previous_hash != previous_hash:
                return LedgerVerification(
                    valid=False,
                    first_broken_sequence=sequence,
                    reason="previous_hash_mismatch",
                )
            if receipt.current_hash != expected:
                return LedgerVerification(
                    valid=False,
                    first_broken_sequence=sequence,
                    reason="current_hash_mismatch",
                )
            previous_hash = expected
        if len(self._receipts_by_fingerprint) != len(self._ordered_alerts):
            return LedgerVerification(
                valid=False,
                first_broken_sequence=len(self._ordered_alerts) + 1,
                reason="receipt_count_mismatch",
            )
        return LedgerVerification(valid=True)

    @property
    def count(self) -> int:
        return len(self._ordered_alerts)

    @property
    def latest_sequence(self) -> int:
        return len(self._ordered_alerts)

    @property
    def latest_hash(self) -> str:
        if not self._ordered_alerts:
            return GENESIS_HASH
        return self._receipts_by_fingerprint[
            self._ordered_alerts[-1].fingerprint
        ].current_hash

    def hash_at(self, sequence: int) -> str:
        if sequence == 0:
            return GENESIS_HASH
        if sequence < 0 or sequence > len(self._ordered_alerts):
            raise IndexError(sequence)
        alert = self._ordered_alerts[sequence - 1]
        return self._receipts_by_fingerprint[alert.fingerprint].current_hash
