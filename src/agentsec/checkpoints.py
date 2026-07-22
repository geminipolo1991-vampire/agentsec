"""Signed ledger checkpoints anchored outside the producing ledger object."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List

from pydantic import Field

from .contracts import StrictModel, new_id, utc_now
from .crypto import PocHmacSigner
from .ingestion import InMemoryAlertLedger


class LedgerCheckpoint(StrictModel):
    schema_version: str = "1.0.0"
    checkpoint_id: str = Field(default_factory=lambda: new_id("checkpoint"))
    producer_id: str
    sequence: int = Field(ge=0)
    current_hash: str
    created_at: datetime = Field(default_factory=utc_now)
    signature_algorithm: str = PocHmacSigner.algorithm
    signature: str = ""

    def unsigned_payload(self) -> Dict[str, object]:
        return self.model_dump(mode="json", exclude={"signature"})


class CheckpointVerification(StrictModel):
    valid: bool
    reason: str
    sequence: int = Field(ge=0)


class CheckpointAnchor:
    """Separate PoC anchor; production replaces this with external durable storage."""

    def __init__(self, signer: PocHmacSigner) -> None:
        self.signer = signer
        self._checkpoints: List[LedgerCheckpoint] = []

    def create(self, ledger: InMemoryAlertLedger, producer_id: str) -> LedgerCheckpoint:
        unsigned = LedgerCheckpoint(
            producer_id=producer_id,
            sequence=ledger.latest_sequence,
            current_hash=ledger.latest_hash,
        )
        checkpoint = unsigned.model_copy(
            update={"signature": self.signer.sign(unsigned.unsigned_payload())}
        )
        self._checkpoints.append(checkpoint)
        return checkpoint

    def verify(
        self, checkpoint: LedgerCheckpoint, ledger: InMemoryAlertLedger
    ) -> CheckpointVerification:
        if not self.signer.verify(checkpoint.unsigned_payload(), checkpoint.signature):
            return CheckpointVerification(
                valid=False, reason="checkpoint_signature_invalid", sequence=checkpoint.sequence
            )
        ledger_result = ledger.verify_detailed()
        if not ledger_result.valid:
            return CheckpointVerification(
                valid=False,
                reason="ledger_%s" % ledger_result.reason,
                sequence=ledger_result.first_broken_sequence,
            )
        if checkpoint.sequence > ledger.latest_sequence:
            return CheckpointVerification(
                valid=False, reason="checkpoint_ahead_of_ledger", sequence=checkpoint.sequence
            )
        if ledger.hash_at(checkpoint.sequence) != checkpoint.current_hash:
            return CheckpointVerification(
                valid=False, reason="checkpoint_hash_mismatch", sequence=checkpoint.sequence
            )
        return CheckpointVerification(valid=True, reason="ok", sequence=checkpoint.sequence)

    @property
    def count(self) -> int:
        return len(self._checkpoints)
