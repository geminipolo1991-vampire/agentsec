"""Privacy-safe, explainable incident details from an authoritative pipeline result."""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional
from urllib.parse import urlparse

from pydantic import Field

from .contracts import PipelineResult, StrictModel
from .workflow import SEVERITY_SCORE


INCIDENT_DETAIL_VERSION = "1.0.0"
TRIAGE_SCORE_VERSION = "triage-2026-07-22.1"
REDACTION_POLICY_VERSION = "incident-detail-2026-07-22.1"


def _reference(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return "ref_sha256:%s" % digest[:24]


def _resource_class(value: str) -> str:
    return value.split("://", 1)[0] if "://" in value else "opaque"


def _destination_class(value: Optional[str]) -> str:
    if value is None:
        return "none"
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"}:
        return "external-network"
    return parsed.scheme or "opaque"


class IncidentEventContext(StrictModel):
    tenant_id: str
    flow_id: str
    agent_id: str
    operation: str
    source_type: str
    source_trust: str
    source_ref: str
    resource_class: str
    resource_ref: str
    destination_class: str
    destination_ref: Optional[str]
    data_classes: List[str]
    authority_operations: List[str]
    indicators: List[str]
    tool_name: Optional[str]
    tool_schema_drift: bool


class IncidentAlertDetail(StrictModel):
    alert_id: str
    event_id: str
    alert_type: str
    title: str
    severity: str
    confidence: float
    detector_id: str
    reason_codes: List[str]
    recommended_action: str
    evidence: List[str]


class IncidentIngestionDetail(StrictModel):
    duplicate: bool
    sequence: int
    previous_hash: str
    current_hash: str
    ingested_at: str


class RiskContribution(StrictModel):
    label: str
    delta: int
    evidence: str


class IncidentTriageDetail(StrictModel):
    risk_score: int
    severity: str
    priority: str
    reasons: List[str]
    assessed_at: str
    score_version: str = TRIAGE_SCORE_VERSION
    score_reproduced: bool = True


class IncidentModelVerdict(StrictModel):
    provider: str
    model_id: str
    action: str
    confidence: float
    reason_codes: List[str]


class IncidentJudgmentDetail(StrictModel):
    action: str
    deterministic_action: str
    reason_codes: List[str]
    ai_mode: str
    policy_version: str
    judged_at: str
    model_verdict: Optional[IncidentModelVerdict]


class IncidentEscalationDetail(StrictModel):
    level: str
    queue: Optional[str]
    case_id: Optional[str]
    reason: str
    escalated_at: str


class IncidentResponseDetail(StrictModel):
    actions: List[str]
    effect_allowed: bool
    simulated: bool
    responder: str
    notes: List[str]
    responded_at: str


class IncidentAuditEntry(StrictModel):
    from_status: Optional[str]
    to_status: str
    actor: str
    reason: str
    at: str


class IncidentFindingDetail(StrictModel):
    finding_id: str
    status: str
    created_at: str
    updated_at: str
    audit: List[IncidentAuditEntry]


class IncidentTimelineStep(StrictModel):
    stage: str
    outcome: str
    at: str
    evidence: Dict[str, str] = Field(default_factory=dict)


class IncidentEnrichmentFact(StrictModel):
    kind: str
    status: str
    value: str
    evidence: str
    source: str
    impact: str


class IncidentValidation(StrictModel):
    status: str = "confirmed_policy_violation"
    authoritative_pipeline_result: bool = True
    deterministic_match: bool = True
    ledger_committed: bool = True
    response_simulated: bool
    basis: List[str]


class IncidentRedaction(StrictModel):
    policy_version: str = REDACTION_POLICY_VERSION
    hashed_reference_count: int = Field(ge=0)
    raw_prompts_included: bool = False
    raw_tool_arguments_included: bool = False


class IncidentDetail(StrictModel):
    schema_version: str = INCIDENT_DETAIL_VERSION
    trace_mode: str = "authoritative"
    detail_availability: str = "complete"
    incident_id: str
    alert_type: str
    event_context: IncidentEventContext
    alert: IncidentAlertDetail
    ingestion: IncidentIngestionDetail
    triage: IncidentTriageDetail
    risk_contributions: List[RiskContribution]
    enrichment: List[IncidentEnrichmentFact]
    judgment: IncidentJudgmentDetail
    escalation: IncidentEscalationDetail
    response: IncidentResponseDetail
    finding: IncidentFindingDetail
    timeline: List[IncidentTimelineStep]
    validation: IncidentValidation
    redaction: IncidentRedaction


def _risk_contributions(result: PipelineResult) -> List[RiskContribution]:
    alert = result.alert
    contributions = [
        RiskContribution(
            label="Base %s severity" % alert.severity.value,
            delta=SEVERITY_SCORE[alert.severity],
            evidence=alert.detector_id,
        )
    ]
    if alert.confidence >= 0.95:
        contributions.append(
            RiskContribution(
                label="High-confidence detection",
                delta=3,
                evidence="confidence %.2f" % alert.confidence,
            )
        )
    if alert.source_trust.value in {"external-untrusted", "suspected-adversarial"}:
        contributions.append(
            RiskContribution(
                label="Untrusted provenance",
                delta=2,
                evidence=alert.source_trust.value,
            )
        )
    raw_score = sum(item.delta for item in contributions)
    if raw_score > 100:
        contributions.append(
            RiskContribution(
                label="Score ceiling",
                delta=100 - raw_score,
                evidence="risk scores are bounded to 100",
            )
        )
    if sum(item.delta for item in contributions) != result.triage.risk_score:
        raise ValueError("triage score cannot be reproduced from recorded contributions")
    return contributions


def _enrichment(result: PipelineResult) -> List[IncidentEnrichmentFact]:
    event = result.event
    untrusted = event.source_trust.value in {
        "external-untrusted",
        "suspected-adversarial",
    }
    authority_match = event.operation in event.authority_operations
    destination_class = _destination_class(event.destination)
    schema_drift = bool(
        event.declared_tool_schema_digest
        and event.observed_tool_schema_digest
        and event.declared_tool_schema_digest != event.observed_tool_schema_digest
    )
    memory_risk = event.source_type == "memory" and "memory_poisoning" in event.indicators
    return [
        IncidentEnrichmentFact(
            kind="Source provenance",
            status="risk" if untrusted else "verified",
            value="%s · %s" % (event.source_type, event.source_trust.value),
            evidence=_reference(event.source_id) or "none",
            source="Normalized AgentEvent provenance metadata",
            impact="Untrusted provenance retained" if untrusted else "Authenticated or internal source",
        ),
        IncidentEnrichmentFact(
            kind="Authority intersection",
            status="verified" if authority_match else "risk",
            value="requested %s · allowed %s"
            % (event.operation, sorted(event.authority_operations)),
            evidence=_reference(event.event_id) or "none",
            source="Effective authority metadata",
            impact="Operation inside effective grant"
            if authority_match
            else "Operation exceeds effective grant",
        ),
        IncidentEnrichmentFact(
            kind="Data classification",
            status="risk" if "secret" in event.data_classes else "verified",
            value="%s · %s"
            % (_resource_class(event.resource), sorted(event.data_classes) or ["unclassified"]),
            evidence=_reference(event.resource) or "none",
            source="Resource and data-class labels",
            impact="Secret-class material present"
            if "secret" in event.data_classes
            else "No secret label observed",
        ),
        IncidentEnrichmentFact(
            kind="Destination analysis",
            status="risk" if destination_class == "external-network" else "verified",
            value=destination_class,
            evidence=_reference(event.destination) or "none",
            source="Destination classifier",
            impact="External network sink"
            if destination_class == "external-network"
            else "No external network sink",
        ),
        IncidentEnrichmentFact(
            kind="Tool contract",
            status="risk" if schema_drift else "verified",
            value=event.tool_name or "no tool declared",
            evidence="schema references match" if not schema_drift else "schema references differ",
            source="ABOM event observation",
            impact="Schema digest drift observed" if schema_drift else "No schema drift observed",
        ),
        IncidentEnrichmentFact(
            kind="Memory persistence",
            status="risk" if memory_risk else "verified",
            value="cross-session" if event.source_type == "memory" else "not memory sourced",
            evidence=", ".join(sorted(event.indicators)) or "no persistence indicators",
            source="Memory and indicator metadata",
            impact="Persisted adversarial influence" if memory_risk else "No memory-poisoning path",
        ),
    ]


def _timeline(result: PipelineResult) -> List[IncidentTimelineStep]:
    allowed_by_stage = {
        "detection": {"detector_id"},
        "ingestion": {"sequence", "hash"},
        "triage": {"risk_score"},
        "judgment": {"policy_version"},
        "escalation": {"case_id"},
        "response": {"actions"},
    }
    steps: List[IncidentTimelineStep] = []
    for entry in result.timeline:
        allowed = allowed_by_stage.get(entry.stage.value, set())
        evidence: Dict[str, str] = {}
        for key, value in entry.evidence.items():
            if key not in allowed:
                continue
            if isinstance(value, list):
                evidence[key] = ", ".join(str(item) for item in value)
            else:
                evidence[key] = str(value)
        steps.append(
            IncidentTimelineStep(
                stage=entry.stage.value,
                outcome=entry.outcome,
                at=entry.at.isoformat(),
                evidence=evidence,
            )
        )
    return steps


def build_incident_detail(result: PipelineResult) -> IncidentDetail:
    """Build an allowlisted explanation from the exact processed alert result."""

    event = result.event
    alert = result.alert
    model = result.judgment.model_verdict
    hashed_references = [event.source_id, event.resource]
    if event.destination:
        hashed_references.append(event.destination)
    hashed_references.extend(alert.evidence)
    return IncidentDetail(
        incident_id=result.finding.finding_id,
        alert_type=alert.alert_type,
        event_context=IncidentEventContext(
            tenant_id=event.tenant_id,
            flow_id=event.flow_id,
            agent_id=event.agent_id,
            operation=event.operation,
            source_type=event.source_type,
            source_trust=event.source_trust.value,
            source_ref=_reference(event.source_id) or "none",
            resource_class=_resource_class(event.resource),
            resource_ref=_reference(event.resource) or "none",
            destination_class=_destination_class(event.destination),
            destination_ref=_reference(event.destination),
            data_classes=sorted(event.data_classes),
            authority_operations=sorted(event.authority_operations),
            indicators=sorted(event.indicators),
            tool_name=event.tool_name,
            tool_schema_drift=bool(
                event.declared_tool_schema_digest
                and event.observed_tool_schema_digest
                and event.declared_tool_schema_digest != event.observed_tool_schema_digest
            ),
        ),
        alert=IncidentAlertDetail(
            alert_id=alert.alert_id,
            event_id=alert.event_id,
            alert_type=alert.alert_type,
            title=alert.title,
            severity=alert.severity.value,
            confidence=alert.confidence,
            detector_id=alert.detector_id,
            reason_codes=list(alert.reason_codes),
            recommended_action=alert.recommended_action.value,
            evidence=[_reference(value) or "none" for value in alert.evidence],
        ),
        ingestion=IncidentIngestionDetail(
            duplicate=result.ingestion.duplicate,
            sequence=result.ingestion.sequence,
            previous_hash=result.ingestion.previous_hash,
            current_hash=result.ingestion.current_hash,
            ingested_at=result.ingestion.ingested_at.isoformat(),
        ),
        triage=IncidentTriageDetail(
            risk_score=result.triage.risk_score,
            severity=result.triage.severity.value,
            priority=result.triage.priority,
            reasons=list(result.triage.reasons),
            assessed_at=result.triage.assessed_at.isoformat(),
        ),
        risk_contributions=_risk_contributions(result),
        enrichment=_enrichment(result),
        judgment=IncidentJudgmentDetail(
            action=result.judgment.action.value,
            deterministic_action=result.judgment.deterministic_action.value,
            reason_codes=list(result.judgment.reason_codes),
            ai_mode=result.judgment.ai_mode.value,
            policy_version=result.judgment.policy_version,
            judged_at=result.judgment.judged_at.isoformat(),
            model_verdict=IncidentModelVerdict(
                provider=model.provider,
                model_id=model.model_id,
                action=model.action.value,
                confidence=model.confidence,
                reason_codes=list(model.reason_codes),
            )
            if model is not None
            else None,
        ),
        escalation=IncidentEscalationDetail(
            level=result.escalation.level.value,
            queue=result.escalation.queue,
            case_id=result.escalation.case_id,
            reason=result.escalation.reason,
            escalated_at=result.escalation.escalated_at.isoformat(),
        ),
        response=IncidentResponseDetail(
            actions=[action.value for action in result.response.actions],
            effect_allowed=result.response.effect_allowed,
            simulated=result.response.simulated,
            responder=result.response.responder,
            notes=list(result.response.notes),
            responded_at=result.response.responded_at.isoformat(),
        ),
        finding=IncidentFindingDetail(
            finding_id=result.finding.finding_id,
            status=result.finding.status.value,
            created_at=result.finding.created_at.isoformat(),
            updated_at=result.finding.updated_at.isoformat(),
            audit=[
                IncidentAuditEntry(
                    from_status=entry.from_status.value if entry.from_status else None,
                    to_status=entry.to_status.value,
                    actor=entry.actor,
                    reason=entry.reason,
                    at=entry.at.isoformat(),
                )
                for entry in result.finding.audit
            ],
        ),
        timeline=_timeline(result),
        validation=IncidentValidation(
            response_simulated=result.response.simulated,
            basis=[
                "Detector rule matched normalized agent-effect metadata",
                "Triage score reproduced from versioned contributions",
                "Final judgment preserved or tightened deterministic enforcement",
                "Alert committed to the hash-chained ledger",
                "Effect disposition recorded before tool completion",
            ],
        ),
        redaction=IncidentRedaction(hashed_reference_count=len(hashed_references)),
    )
