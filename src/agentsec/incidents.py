"""Versioned, privacy-safe incident records and the in-memory POC store."""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Set

from pydantic import Field, model_validator

from .contracts import (
    AiAnalystRun,
    EnrichmentSnapshot,
    Finding,
    FindingStatus,
    PipelineResult,
    RiskContribution,
    StrictModel,
    utc_now,
)
from .redaction import Redactor


INCIDENT_DETAIL_VERSION = "2.0.0"
REDACTION_POLICY_VERSION = "incident-detail-2026-07-23.2"


def _reference(namespace: str, value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return "%s_sha256:%s" % (namespace, digest[:24])


def _resource_class(value: str) -> str:
    return value.split("://", 1)[0] if "://" in value else "opaque"


def _destination_class(value: Optional[str]) -> str:
    if value is None:
        return "none"
    scheme = value.split("://", 1)[0].lower() if "://" in value else "opaque"
    return "external-network" if scheme in {"http", "https"} else scheme


class IncidentTransitionAction(str, Enum):
    ACKNOWLEDGE = "acknowledge"
    START_INVESTIGATION = "start_investigation"
    MARK_CONTAINED = "mark_contained"
    CLOSE = "close"


TRANSITION_STATUS = {
    IncidentTransitionAction.ACKNOWLEDGE: FindingStatus.ACKNOWLEDGED,
    IncidentTransitionAction.START_INVESTIGATION: FindingStatus.INVESTIGATING,
    IncidentTransitionAction.MARK_CONTAINED: FindingStatus.CONTAINED,
    IncidentTransitionAction.CLOSE: FindingStatus.CLOSED,
}


def transition_status(action: IncidentTransitionAction) -> FindingStatus:
    return TRANSITION_STATUS[action]


class IncidentTransitionRequest(StrictModel):
    action: IncidentTransitionAction
    actor: str = Field(
        min_length=3,
        max_length=128,
        pattern=r"^(analyst|system)://[A-Za-z0-9_.@/-]+$",
    )
    reason: str = Field(min_length=3, max_length=256)


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


class IncidentDetectionDetail(StrictModel):
    alert_id: str
    event_id: str
    alert_type: str
    title: str
    severity: str
    confidence: float
    detector_id: str
    rule_version: str
    reason_codes: List[str]
    recommended_action: str
    evidence_refs: List[str]
    detected_at: str


class IncidentIngestionDetail(StrictModel):
    duplicate: bool
    sequence: int
    previous_hash: str
    current_hash: str
    ingested_at: str


class IncidentEnrichmentResult(StrictModel):
    source: str
    status: str
    observed_at: str
    confidence: float = Field(ge=0.0, le=1.0)
    facts: Dict[str, Any]
    evidence_refs: List[str]
    latency_ms: int
    affects_triage: bool
    failure_effect: str
    connector_version: Optional[str] = None
    cache_status: str
    freshness_seconds: Optional[int] = Field(default=None, ge=0)
    expires_at: Optional[str] = None
    policy_decision: str


class IncidentEnrichmentDetail(StrictModel):
    snapshot_id: str
    status: str
    observed_at: str
    completed_sources: int
    total_sources: int
    mandatory_context_complete: bool
    warnings: List[str]
    connector_sources: int = Field(ge=0)
    cache_hits: int = Field(ge=0)
    stale_fallbacks: int = Field(ge=0)
    timed_out_sources: int = Field(ge=0)
    policy_digest: Optional[str] = None
    sources: List[IncidentEnrichmentResult]


class IncidentTriageDetail(StrictModel):
    risk_score: int
    severity: str
    priority: str
    reasons: List[str]
    assessed_at: str
    score_version: str
    contributions: List[RiskContribution]
    sla_minutes: int
    route: str
    missing_context_warnings: List[str]
    behavior_assessment_id: Optional[str] = None
    behavior_anomaly_score: Optional[int] = Field(default=None, ge=0, le=100)
    composite_risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    behavior_drift_state: Optional[str] = None
    narrative: str
    score_reproduced: bool = True


class IncidentModelVerdict(StrictModel):
    label: str
    provider: str
    model_id: str
    action: str
    confidence: float
    reason_codes: List[str]
    evidence_refs: List[str]
    uncertainty: Optional[str]


class IncidentJudgmentDetail(StrictModel):
    detector_recommendation: str
    deterministic_action: str
    model_verdict: Optional[IncidentModelVerdict]
    ai_mode: str
    model_status: str
    model_validation_status: str
    model_calibrated_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    model_human_gate_required: bool
    model_validation_codes: List[str]
    final_action: str
    action: str
    combiner_result: str
    reason_codes: List[str]
    policy_version: str
    judged_at: str


class IncidentEscalationDetail(StrictModel):
    level: str
    queue: Optional[str]
    case_id: Optional[str]
    reason: str
    escalated_at: str


class IncidentResponseDetail(StrictModel):
    actions: List[str]
    effect_allowed: bool
    effect_status: str
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


class IncidentValidation(StrictModel):
    status: str = "confirmed_policy_violation"
    authoritative_pipeline_result: bool = True
    deterministic_match: bool = True
    ledger_committed: bool = True
    ledger_verified: bool
    response_simulated: bool
    basis: List[str]


class IncidentPrivacy(StrictModel):
    redaction_policy_version: str = REDACTION_POLICY_VERSION
    evidence_handling_policy: str = "allowlist-hash-and-mask"
    detail_availability: Literal["complete", "summary_only"]
    redaction_count: int = Field(ge=0)
    hashed_reference_count: int = Field(ge=0)
    raw_prompts_included: Literal[False] = False
    raw_tool_arguments_included: Literal[False] = False
    authorization_headers_included: Literal[False] = False
    ingest_tokens_included: Literal[False] = False
    credentials_included: Literal[False] = False
    full_sensitive_content_included: Literal[False] = False


class IncidentSummary(StrictModel):
    finding_id: str
    event_id: str
    flow_id: str
    alert_type: str
    title: str
    agent_id: str
    severity: str
    priority: str
    status: str
    decision: str
    effect_status: str
    created_at: str
    updated_at: str
    detail_availability: Literal["complete", "summary_only"]


class IncidentDetail(StrictModel):
    schema_version: str = INCIDENT_DETAIL_VERSION
    trace_mode: str
    detail_availability: Literal["complete", "summary_only"]
    incident_id: str
    alert_type: str
    summary: IncidentSummary
    event_context: Optional[IncidentEventContext] = None
    detection: Optional[IncidentDetectionDetail] = None
    alert: Optional[IncidentDetectionDetail] = None
    ingestion: Optional[IncidentIngestionDetail] = None
    enrichment: Optional[IncidentEnrichmentDetail] = None
    triage: Optional[IncidentTriageDetail] = None
    risk_contributions: List[RiskContribution] = Field(default_factory=list)
    judgment: Optional[IncidentJudgmentDetail] = None
    escalation: Optional[IncidentEscalationDetail] = None
    response: Optional[IncidentResponseDetail] = None
    finding: Optional[IncidentFindingDetail] = None
    analyst_run: Optional[AiAnalystRun] = None
    timeline: List[IncidentTimelineStep] = Field(default_factory=list)
    validation: Optional[IncidentValidation] = None
    privacy: IncidentPrivacy
    recorded_at: str

    @model_validator(mode="after")
    def validate_detail_shape(self) -> "IncidentDetail":
        """Prevent partial records from being presented as authoritative details."""

        if self.summary.finding_id != self.incident_id:
            raise ValueError("summary finding ID must match incident ID")
        if self.summary.alert_type != self.alert_type:
            raise ValueError("summary alert type must match incident alert type")
        if self.privacy.detail_availability != self.detail_availability:
            raise ValueError("privacy detail availability must match incident")
        if self.summary.detail_availability != self.detail_availability:
            raise ValueError("summary detail availability must match incident")

        detail_fields = (
            self.event_context,
            self.detection,
            self.alert,
            self.ingestion,
            self.enrichment,
            self.triage,
            self.judgment,
            self.escalation,
            self.response,
            self.finding,
            self.validation,
        )
        if self.detail_availability == "summary_only":
            if any(item is not None for item in detail_fields) or self.analyst_run is not None:
                raise ValueError("summary-only incident cannot contain authoritative detail")
            if self.timeline or self.risk_contributions:
                raise ValueError("summary-only incident cannot contain reconstructed evidence")
            return self

        if any(item is None for item in detail_fields):
            raise ValueError("complete incident requires every pipeline detail section")
        if self.detection != self.alert:
            raise ValueError("detection and compatibility alert views must match")
        expected_stages = [
            "detection",
            "ingestion",
            "enrichment",
            "triage",
            "judgment",
            "escalation",
            "response",
        ]
        if [item.stage for item in self.timeline] != expected_stages:
            raise ValueError("complete incident requires the ordered pipeline timeline")
        if self.triage is not None:
            if self.risk_contributions != self.triage.contributions:
                raise ValueError("top-level and triage risk contributions must match")
            if sum(item.delta for item in self.risk_contributions) != self.triage.risk_score:
                raise ValueError("risk contributions must reproduce the triage score")
        return self

    @classmethod
    def summary_only(cls, summary: IncidentSummary) -> "IncidentDetail":
        return cls(
            trace_mode="historical_summary",
            detail_availability="summary_only",
            incident_id=summary.finding_id,
            alert_type=summary.alert_type,
            summary=summary.model_copy(update={"detail_availability": "summary_only"}),
            privacy=IncidentPrivacy(
                detail_availability="summary_only",
                redaction_count=0,
                hashed_reference_count=0,
            ),
            recorded_at=summary.updated_at,
        )


class IncidentListResponse(StrictModel):
    schema_version: str = INCIDENT_DETAIL_VERSION
    incidents: List[IncidentSummary]
    count: int = Field(ge=0)


def _safe_audit(
    finding: Finding, redactor: Redactor
) -> tuple[IncidentFindingDetail, int]:
    audit: List[IncidentAuditEntry] = []
    redaction_count = 0
    for entry in finding.audit:
        safe_actor = redactor.redact(entry.actor)
        safe_reason = redactor.redact(entry.reason)
        redaction_count += safe_actor.redaction_count + safe_reason.redaction_count
        audit.append(
            IncidentAuditEntry(
                from_status=entry.from_status.value if entry.from_status else None,
                to_status=entry.to_status.value,
                actor=str(safe_actor.value),
                reason=str(safe_reason.value),
                at=entry.at.isoformat(),
            )
        )
    return (
        IncidentFindingDetail(
            finding_id=finding.finding_id,
            status=finding.status.value,
            created_at=finding.created_at.isoformat(),
            updated_at=finding.updated_at.isoformat(),
            audit=audit,
        ),
        redaction_count,
    )


def _safe_enrichment(snapshot: EnrichmentSnapshot) -> IncidentEnrichmentDetail:
    return IncidentEnrichmentDetail(
        snapshot_id=snapshot.snapshot_id,
        status=snapshot.status.value,
        observed_at=snapshot.observed_at.isoformat(),
        completed_sources=snapshot.completed_sources,
        total_sources=snapshot.total_sources,
        mandatory_context_complete=snapshot.mandatory_context_complete,
        warnings=list(snapshot.warnings),
        connector_sources=snapshot.connector_sources,
        cache_hits=snapshot.cache_hits,
        stale_fallbacks=snapshot.stale_fallbacks,
        timed_out_sources=snapshot.timed_out_sources,
        policy_digest=snapshot.policy_digest,
        sources=[
            IncidentEnrichmentResult(
                source=item.source,
                status=item.status.value,
                observed_at=item.observed_at.isoformat(),
                confidence=item.confidence,
                facts=dict(item.facts),
                evidence_refs=list(item.evidence_refs),
                latency_ms=item.latency_ms,
                affects_triage=item.affects_triage,
                failure_effect=item.failure_effect,
                connector_version=item.connector_version,
                cache_status=item.cache_status.value,
                freshness_seconds=item.freshness_seconds,
                expires_at=item.expires_at.isoformat() if item.expires_at else None,
                policy_decision=item.policy_decision,
            )
            for item in snapshot.sources
        ],
    )


def _safe_timeline(result: PipelineResult) -> List[IncidentTimelineStep]:
    allowed_by_stage = {
        "detection": {"detector_id", "rule_version", "matches"},
        "ingestion": {"sequence", "hash"},
        "enrichment": {
            "completed_sources",
            "total_sources",
            "mandatory_context_complete",
            "connector_sources",
            "cache_hits",
            "stale_fallbacks",
            "timed_out_sources",
            "policy_digest",
        },
        "triage": {"risk_score", "score_version", "route"},
        "judgment": {
            "policy_version",
            "deterministic_action",
            "model_status",
            "combiner_result",
            "final_action",
        },
        "escalation": {"case_id", "queue"},
        "response": {"actions", "effect_status"},
    }
    timeline: List[IncidentTimelineStep] = []
    for entry in result.timeline:
        allowed = allowed_by_stage.get(entry.stage.value, set())
        evidence: Dict[str, str] = {}
        for key, value in entry.evidence.items():
            if key not in allowed or value is None:
                continue
            if isinstance(value, list):
                evidence[key] = ", ".join(str(item) for item in value)
            else:
                evidence[key] = str(value)
        timeline.append(
            IncidentTimelineStep(
                stage=entry.stage.value,
                outcome=entry.outcome,
                at=entry.at.isoformat(),
                evidence=evidence,
            )
        )
    return timeline


def build_incident_detail(
    result: PipelineResult, *, redactor: Optional[Redactor] = None
) -> IncidentDetail:
    """Transform only recorded pipeline fields through an explicit allowlist."""

    privacy = redactor or Redactor()
    event = result.event
    alert = result.alert
    model = result.judgment.model_verdict
    raw_references = [event.source_id, event.resource]
    if event.destination:
        raw_references.append(event.destination)
    raw_references.extend(alert.evidence)
    unique_references = list(dict.fromkeys(raw_references))

    detection = IncidentDetectionDetail(
        alert_id=alert.alert_id,
        event_id=alert.event_id,
        alert_type=alert.alert_type,
        title=alert.title,
        severity=alert.severity.value,
        confidence=alert.confidence,
        detector_id=alert.detector_id,
        rule_version=alert.rule_version,
        reason_codes=list(alert.reason_codes),
        recommended_action=alert.recommended_action.value,
        evidence_refs=[
            _reference("evidence", value) or "withheld" for value in alert.evidence
        ],
        detected_at=alert.detected_at.isoformat(),
    )
    finding, audit_redactions = _safe_audit(result.finding, privacy)
    summary = IncidentSummary(
        finding_id=result.finding.finding_id,
        event_id=event.event_id,
        flow_id=event.flow_id,
        alert_type=alert.alert_type,
        title=alert.title,
        agent_id=event.agent_id,
        severity=alert.severity.value,
        priority=result.triage.priority,
        status=result.finding.status.value,
        decision=result.judgment.action.value,
        effect_status=result.response.effect_status.value,
        created_at=result.finding.created_at.isoformat(),
        updated_at=result.finding.updated_at.isoformat(),
        detail_availability="complete",
    )
    incident = IncidentDetail(
        trace_mode="authoritative",
        detail_availability="complete",
        incident_id=result.finding.finding_id,
        alert_type=alert.alert_type,
        summary=summary,
        event_context=IncidentEventContext(
            tenant_id=event.tenant_id,
            flow_id=event.flow_id,
            agent_id=event.agent_id,
            operation=event.operation,
            source_type=event.source_type,
            source_trust=event.source_trust.value,
            source_ref=_reference("source", event.source_id) or "withheld",
            resource_class=_resource_class(event.resource),
            resource_ref=_reference("resource", event.resource) or "withheld",
            destination_class=_destination_class(event.destination),
            destination_ref=_reference("destination", event.destination),
            data_classes=sorted(event.data_classes),
            authority_operations=sorted(event.authority_operations),
            indicators=sorted(event.indicators),
            tool_name=event.tool_name,
            tool_schema_drift=bool(
                event.declared_tool_schema_digest
                and event.observed_tool_schema_digest
                and event.declared_tool_schema_digest
                != event.observed_tool_schema_digest
            ),
        ),
        detection=detection,
        alert=detection,
        ingestion=IncidentIngestionDetail(
            duplicate=result.ingestion.duplicate,
            sequence=result.ingestion.sequence,
            previous_hash=result.ingestion.previous_hash,
            current_hash=result.ingestion.current_hash,
            ingested_at=result.ingestion.ingested_at.isoformat(),
        ),
        enrichment=_safe_enrichment(result.enrichment),
        triage=IncidentTriageDetail(
            risk_score=result.triage.risk_score,
            severity=result.triage.severity.value,
            priority=result.triage.priority,
            reasons=list(result.triage.reasons),
            assessed_at=result.triage.assessed_at.isoformat(),
            score_version=result.triage.score_version,
            contributions=list(result.triage.contributions),
            sla_minutes=result.triage.sla_minutes,
            route=result.triage.route,
            missing_context_warnings=list(result.triage.missing_context_warnings),
            behavior_assessment_id=result.triage.behavior_assessment_id,
            behavior_anomaly_score=result.triage.behavior_anomaly_score,
            composite_risk_score=result.triage.composite_risk_score,
            behavior_drift_state=result.triage.behavior_drift_state,
            narrative=result.triage.narrative,
            score_reproduced=sum(
                item.delta for item in result.triage.contributions
            )
            == result.triage.risk_score,
        ),
        risk_contributions=list(result.triage.contributions),
        judgment=IncidentJudgmentDetail(
            detector_recommendation=alert.recommended_action.value,
            deterministic_action=result.judgment.deterministic_action.value,
            model_verdict=IncidentModelVerdict(
                label="Codex recorded shadow"
                if model.provider == "codex" and result.judgment.ai_mode.value == "shadow"
                else "Structured model recommendation",
                provider=model.provider,
                model_id=model.model_id,
                action=model.action.value,
                confidence=model.confidence,
                reason_codes=list(model.reason_codes),
                evidence_refs=[
                    _reference("model-evidence", item) or "withheld"
                    for item in model.evidence_ids
                ],
                uncertainty=model.uncertainty,
            )
            if model is not None
            else None,
            ai_mode=result.judgment.ai_mode.value,
            model_status=result.judgment.model_status,
            model_validation_status=(
                result.judgment.model_validation.status
                if result.judgment.model_validation is not None
                else "not_requested"
            ),
            model_calibrated_confidence=(
                result.judgment.model_validation.calibrated_confidence
                if result.judgment.model_validation is not None
                else None
            ),
            model_human_gate_required=(
                result.judgment.model_validation.human_gate_required
                if result.judgment.model_validation is not None
                else False
            ),
            model_validation_codes=(
                list(result.judgment.model_validation.reason_codes)
                if result.judgment.model_validation is not None
                else []
            ),
            final_action=result.judgment.action.value,
            action=result.judgment.action.value,
            combiner_result=result.judgment.combiner_result,
            reason_codes=list(result.judgment.reason_codes),
            policy_version=result.judgment.policy_version,
            judged_at=result.judgment.judged_at.isoformat(),
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
            effect_status=result.response.effect_status.value,
            simulated=result.response.simulated,
            responder=result.response.responder,
            notes=list(result.response.notes),
            responded_at=result.response.responded_at.isoformat(),
        ),
        finding=finding,
        analyst_run=result.analyst_run,
        timeline=_safe_timeline(result),
        validation=IncidentValidation(
            response_simulated=result.response.simulated,
            ledger_verified=result.ledger_verified,
            basis=[
                "Detector rule and version are recorded from the matched alert",
                "Ledger receipt is recorded from ingestion",
                "Enrichment source status and failures are explicit",
                "Risk score equals its recorded versioned contributions",
                "Final judgment cannot relax deterministic enforcement",
                "Effect disposition is recorded before completion",
            ],
        ),
        privacy=IncidentPrivacy(
            detail_availability="complete",
            redaction_count=len(unique_references) + audit_redactions,
            hashed_reference_count=len(unique_references),
        ),
        recorded_at=utc_now().isoformat(),
    )
    # Every included field above is allowlisted. Raw event attributes, prompts,
    # tool arguments, headers, tokens, and credential-bearing objects are never
    # copied into this model; free-form audit strings were redacted separately.
    return incident


class IncidentStore:
    """In-memory POC store keyed by finding ID with explicit secondary indexes."""

    def __init__(self, *, canaries: Optional[Set[str]] = None) -> None:
        self._by_finding: Dict[str, IncidentDetail] = {}
        self._indexes: Dict[str, Dict[str, Set[str]]] = {
            name: {}
            for name in (
                "event_id",
                "flow_id",
                "alert_type",
                "agent_id",
                "severity",
                "priority",
                "status",
                "created_at",
            )
        }
        self._redactor = Redactor(canaries or set())

    def _index(self, field: str, value: str, finding_id: str) -> None:
        self._indexes[field].setdefault(value, set()).add(finding_id)

    def _remove_indexes(self, detail: IncidentDetail) -> None:
        summary = detail.summary
        values = {
            "event_id": summary.event_id,
            "flow_id": summary.flow_id,
            "alert_type": summary.alert_type,
            "agent_id": summary.agent_id,
            "severity": summary.severity,
            "priority": summary.priority,
            "status": summary.status,
            "created_at": summary.created_at,
        }
        for field, value in values.items():
            ids = self._indexes[field].get(value)
            if ids is not None:
                ids.discard(summary.finding_id)
                if not ids:
                    del self._indexes[field][value]

    def put(self, detail: IncidentDetail) -> IncidentDetail:
        existing = self._by_finding.get(detail.incident_id)
        if existing is not None:
            self._remove_indexes(existing)
        self._by_finding[detail.incident_id] = detail
        summary = detail.summary
        for field, value in {
            "event_id": summary.event_id,
            "flow_id": summary.flow_id,
            "alert_type": summary.alert_type,
            "agent_id": summary.agent_id,
            "severity": summary.severity,
            "priority": summary.priority,
            "status": summary.status,
            "created_at": summary.created_at,
        }.items():
            self._index(field, value, detail.incident_id)
        return detail

    def record(self, result: PipelineResult) -> IncidentDetail:
        return self.put(build_incident_detail(result, redactor=self._redactor))

    def add_summary(self, summary: IncidentSummary) -> IncidentDetail:
        return self.put(IncidentDetail.summary_only(summary))

    def get(self, finding_id: str) -> IncidentDetail:
        return self._by_finding[finding_id]

    def timeline(self, finding_id: str) -> List[IncidentTimelineStep]:
        return list(self.get(finding_id).timeline)

    def list(self, **filters: str) -> List[IncidentSummary]:
        unknown = set(filters) - set(self._indexes)
        if unknown:
            raise ValueError("unknown incident filter")
        candidate_ids: Optional[Set[str]] = None
        for field, value in filters.items():
            matches = set(self._indexes[field].get(value, set()))
            candidate_ids = matches if candidate_ids is None else candidate_ids & matches
        ids = candidate_ids if candidate_ids is not None else set(self._by_finding)
        summaries = [self._by_finding[item].summary for item in ids]
        return sorted(summaries, key=lambda item: item.updated_at, reverse=True)

    def update_finding(self, finding: Finding) -> IncidentDetail:
        current = self.get(finding.finding_id)
        if current.detail_availability == "summary_only":
            summary = current.summary.model_copy(
                update={
                    "status": finding.status.value,
                    "updated_at": finding.updated_at.isoformat(),
                }
            )
            return self.put(IncidentDetail.summary_only(summary))
        safe_finding, audit_redactions = _safe_audit(finding, self._redactor)
        summary = current.summary.model_copy(
            update={
                "status": finding.status.value,
                "updated_at": finding.updated_at.isoformat(),
            }
        )
        return self.put(
            current.model_copy(
                update={
                    "finding": safe_finding,
                    "summary": summary,
                    "privacy": current.privacy.model_copy(
                        update={
                            "redaction_count": current.privacy.hashed_reference_count
                            + audit_redactions
                        }
                    ),
                    "recorded_at": utc_now().isoformat(),
                }
            )
        )

    @property
    def count(self) -> int:
        return len(self._by_finding)
