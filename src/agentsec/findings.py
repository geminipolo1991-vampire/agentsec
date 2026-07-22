"""Deduplicated finding lifecycle with immutable audit entries."""

from __future__ import annotations

from typing import Dict, Set

from .contracts import (
    Finding,
    FindingAuditEntry,
    FindingStatus,
    SecurityAlert,
    utc_now,
)


ALLOWED_TRANSITIONS: Dict[FindingStatus, Set[FindingStatus]] = {
    FindingStatus.OPEN: {
        FindingStatus.ACKNOWLEDGED,
        FindingStatus.INVESTIGATING,
        FindingStatus.CONTAINED,
        FindingStatus.CLOSED,
    },
    FindingStatus.ACKNOWLEDGED: {
        FindingStatus.INVESTIGATING,
        FindingStatus.CONTAINED,
        FindingStatus.CLOSED,
    },
    FindingStatus.INVESTIGATING: {FindingStatus.CONTAINED, FindingStatus.CLOSED},
    FindingStatus.CONTAINED: {FindingStatus.INVESTIGATING, FindingStatus.CLOSED},
    FindingStatus.CLOSED: set(),
}


class FindingStore:
    def __init__(self) -> None:
        self._by_id: Dict[str, Finding] = {}
        self._id_by_fingerprint: Dict[str, str] = {}

    def create_or_update(self, alert: SecurityAlert, policy_version: str) -> Finding:
        existing_id = self._id_by_fingerprint.get(alert.fingerprint)
        if existing_id is not None:
            existing = self._by_id[existing_id]
            if alert.alert_id in existing.alert_ids:
                return existing
            updated = existing.model_copy(
                update={
                    "alert_ids": existing.alert_ids + [alert.alert_id],
                    "evidence": list(dict.fromkeys(existing.evidence + alert.evidence)),
                    "updated_at": utc_now(),
                }
            )
            self._by_id[existing_id] = updated
            return updated

        finding_id = "fnd_%s" % alert.fingerprint[:32]
        finding = Finding(
            finding_id=finding_id,
            fingerprint=alert.fingerprint,
            tenant_id=alert.tenant_id,
            flow_id=alert.flow_id,
            agent_id=alert.agent_id,
            finding_type=alert.alert_type,
            severity=alert.severity,
            detector_id=alert.detector_id,
            policy_version=policy_version,
            alert_ids=[alert.alert_id],
            evidence=list(alert.evidence),
            audit=[
                FindingAuditEntry(
                    to_status=FindingStatus.OPEN,
                    actor="system://detector",
                    reason="finding created from detector alert",
                )
            ],
        )
        self._by_id[finding_id] = finding
        self._id_by_fingerprint[alert.fingerprint] = finding_id
        return finding

    def transition(
        self,
        finding_id: str,
        to_status: FindingStatus,
        *,
        actor: str,
        reason: str,
    ) -> Finding:
        current = self._by_id[finding_id]
        if current.status == to_status:
            return current
        if to_status not in ALLOWED_TRANSITIONS[current.status]:
            raise ValueError(
                "invalid finding transition %s -> %s"
                % (current.status.value, to_status.value)
            )
        updated = current.model_copy(
            update={
                "status": to_status,
                "audit": current.audit
                + [
                    FindingAuditEntry(
                        from_status=current.status,
                        to_status=to_status,
                        actor=actor,
                        reason=reason,
                    )
                ],
                "updated_at": utc_now(),
            }
        )
        self._by_id[finding_id] = updated
        return updated

    def get(self, finding_id: str) -> Finding:
        return self._by_id[finding_id]

    @property
    def count(self) -> int:
        return len(self._by_id)

