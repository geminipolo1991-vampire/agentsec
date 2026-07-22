"""Allowlist-first model evidence and external SOC export construction."""

from __future__ import annotations

import json
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

from pydantic import Field

from .contracts import PipelineResult, SecurityAlert, StrictModel, TriageAssessment
from .redaction import REDACTED, Redactor


def _resource_class(value: str) -> str:
    if "://" in value:
        return value.split("://", 1)[0]
    return "opaque"


def _destination_class(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"}:
        return "external-network"
    return parsed.scheme or "opaque"


class ModelEvidenceBundle(StrictModel):
    schema_version: str = "1.0.0"
    alert_id: str
    alert_type: str
    severity: str
    confidence: float
    source_trust: str
    operation: str
    resource_class: str
    destination_class: Optional[str]
    reason_codes: List[str]
    evidence_ids: List[str]
    risk_score: int
    priority: str
    redaction_count: int = Field(ge=0)
    untrusted_evidence_is_data: bool = True


class SocFindingExport(StrictModel):
    schema_version: str = "1.0.0"
    finding_id: str
    finding_type: str
    severity: str
    status: str
    tenant_id: str
    agent_id: str
    flow_id: str
    operation: str
    resource_class: str
    destination_class: Optional[str]
    detector_id: str
    policy_version: str
    decision: str
    escalation_level: str
    case_id: Optional[str]
    evidence_pivot_id: str
    ledger_integrity: str


class PrivacyTransformer:
    def __init__(self, canaries: Optional[Set[str]] = None) -> None:
        configured_canaries = canaries or set()
        self.redactor = Redactor(configured_canaries)
        self._canaries = set(configured_canaries)

    def model_evidence(
        self, alert: SecurityAlert, triage: TriageAssessment
    ) -> ModelEvidenceBundle:
        evidence_result = self.redactor.redact(list(alert.evidence))
        bundle = ModelEvidenceBundle(
            alert_id=alert.alert_id,
            alert_type=alert.alert_type,
            severity=alert.severity.value,
            confidence=alert.confidence,
            source_trust=alert.source_trust.value,
            operation=alert.operation,
            resource_class=_resource_class(alert.resource),
            destination_class=_destination_class(alert.destination),
            reason_codes=list(alert.reason_codes),
            evidence_ids=evidence_result.value,
            risk_score=triage.risk_score,
            priority=triage.priority,
            redaction_count=evidence_result.redaction_count,
        )
        self._assert_no_canary(bundle.model_dump(mode="json"))
        return bundle

    def soc_export(self, result: PipelineResult, ledger_valid: bool) -> SocFindingExport:
        export = SocFindingExport(
            finding_id=result.finding.finding_id,
            finding_type=result.finding.finding_type,
            severity=result.finding.severity.value,
            status=result.finding.status.value,
            tenant_id=result.finding.tenant_id,
            agent_id=result.finding.agent_id,
            flow_id=result.finding.flow_id,
            operation=result.alert.operation,
            resource_class=_resource_class(result.alert.resource),
            destination_class=_destination_class(result.alert.destination),
            detector_id=result.finding.detector_id,
            policy_version=result.judgment.policy_version,
            decision=result.judgment.action.value,
            escalation_level=result.escalation.level.value,
            case_id=result.escalation.case_id,
            evidence_pivot_id=result.finding.finding_id,
            ledger_integrity="verified" if ledger_valid else "failed",
        )
        self._assert_no_canary(export.model_dump(mode="json"))
        return export

    def _assert_no_canary(self, value: Dict[str, object]) -> None:
        encoded = json.dumps(value, sort_keys=True)
        for canary in self._canaries:
            if canary in encoded:
                raise ValueError("sensitive canary survived allowlist/redaction")
        if REDACTED in encoded:
            return
