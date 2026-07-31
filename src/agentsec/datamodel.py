"""Canonical, versioned AI-security records and compatibility adapters.

The operational PoC contracts predate this normalized data plane. This module
does not silently rename those contracts. It introduces explicit Event,
Evidence, Entity, Alert, Finding, Incident, Investigation, Judgment, and Action
records, then provides audited adapters from the legacy pipeline.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Dict, List, Literal, Mapping, Optional, Set, Union

from pydantic import Field, TypeAdapter, field_validator, model_validator

from .contracts import (
    AgentEvent,
    DecisionAction,
    Finding,
    PipelineResult,
    SecurityAlert,
    Severity,
    StrictModel,
    utc_now,
)
from .telemetry import TelemetryEnvelope


CANONICAL_SCHEMA_VERSION = "1.0.0"
LEGACY_CANONICAL_SCHEMA_VERSION = "0.9.0"
CanonicalScalar = Union[str, int, float, bool]
BoundedReference = Annotated[str, Field(min_length=1, max_length=256)]
BoundedReasonCode = Annotated[str, Field(min_length=1, max_length=128)]


class RecordType(str, Enum):
    EVENT = "event"
    EVIDENCE = "evidence"
    ENTITY = "entity"
    ALERT = "alert"
    FINDING = "finding"
    INCIDENT = "incident"
    INVESTIGATION = "investigation"
    JUDGMENT = "judgment"
    ACTION = "action"


class EntityType(str, Enum):
    APPLICATION = "application"
    AGENT = "agent"
    MODEL = "model"
    TOOL = "tool"
    DATA_STORE = "data_store"
    IDENTITY = "identity"
    RESOURCE = "resource"
    DESTINATION = "destination"


class EvidenceType(str, Enum):
    TELEMETRY = "telemetry"
    DETECTOR = "detector"
    LEDGER = "ledger"
    ENRICHMENT = "enrichment"
    MODEL = "model"
    ANALYST = "analyst"
    RESPONSE = "response"


class IntegrityStatus(str, Enum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    INVALID = "invalid"


class AlertStatus(str, Enum):
    OPEN = "open"
    SUPPRESSED = "suppressed"
    PROMOTED = "promoted"
    CLOSED = "closed"


class FindingStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    CLOSED = "closed"


class IncidentStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class InvestigationStatus(str, Enum):
    PLANNED = "planned"
    RUNNING = "running"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class JudgeType(str, Enum):
    DETERMINISTIC = "deterministic"
    AI_ASSISTED = "ai_assisted"
    HUMAN = "human"
    COMBINED = "combined"


class ActionStatus(str, Enum):
    PROPOSED = "proposed"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"


class CanonicalRecordBase(StrictModel):
    schema_version: Literal["1.0.0"] = CANONICAL_SCHEMA_VERSION
    record_type: RecordType
    tenant_id: str = Field(min_length=1, max_length=128)
    created_at: datetime = Field(default_factory=utc_now)
    labels: Set[str] = Field(default_factory=set, max_length=64)

    @field_validator("created_at")
    @classmethod
    def created_at_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must include a timezone")
        return value

    @field_validator("labels")
    @classmethod
    def labels_are_bounded(cls, value: Set[str]) -> Set[str]:
        if any(not 1 <= len(item) <= 128 for item in value):
            raise ValueError("record labels must contain 1 to 128 characters")
        return value


class EventRecord(CanonicalRecordBase):
    record_type: Literal[RecordType.EVENT] = RecordType.EVENT
    event_id: str = Field(min_length=5, max_length=128)
    occurred_at: datetime
    observed_at: datetime = Field(default_factory=utc_now)
    event_kind: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=1, max_length=128)
    session_id: Optional[str] = Field(default=None, max_length=128)
    actor_entity_id: str = Field(min_length=1, max_length=256)
    target_entity_ids: List[BoundedReference] = Field(default_factory=list, max_length=256)
    operation: Optional[str] = Field(default=None, max_length=128)
    outcome: Optional[str] = Field(default=None, max_length=64)
    source_ref: str = Field(min_length=1, max_length=512)
    source_trust: str = Field(min_length=1, max_length=64)
    evidence_ids: List[BoundedReference] = Field(default_factory=list, max_length=256)
    attributes: Dict[str, CanonicalScalar] = Field(default_factory=dict)

    @field_validator("occurred_at", "observed_at")
    @classmethod
    def event_times_are_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def bounded_attributes(self) -> "EventRecord":
        if len(self.attributes) > 64:
            raise ValueError("event attributes are limited to 64 fields")
        for key, value in self.attributes.items():
            if not key or len(key) > 128:
                raise ValueError("event attribute keys must be bounded")
            if isinstance(value, str) and len(value) > 2048:
                raise ValueError("event attribute values must be bounded")
        return self


class EvidenceRecord(CanonicalRecordBase):
    record_type: Literal[RecordType.EVIDENCE] = RecordType.EVIDENCE
    evidence_id: str = Field(min_length=5, max_length=128)
    evidence_type: EvidenceType
    subject_refs: List[BoundedReference] = Field(min_length=1, max_length=256)
    source: str = Field(min_length=1, max_length=128)
    claim: str = Field(min_length=1, max_length=2048)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    integrity_status: IntegrityStatus
    collected_at: datetime = Field(default_factory=utc_now)
    provenance_refs: List[BoundedReference] = Field(default_factory=list, max_length=256)
    data_classes: Set[str] = Field(default_factory=set, max_length=64)

    @field_validator("collected_at")
    @classmethod
    def collected_at_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("collected_at must include a timezone")
        return value


class EntityRecord(CanonicalRecordBase):
    record_type: Literal[RecordType.ENTITY] = RecordType.ENTITY
    entity_id: str = Field(min_length=3, max_length=256)
    entity_type: EntityType
    name: str = Field(min_length=1, max_length=256)
    owner_ref: Optional[str] = Field(default=None, max_length=256)
    criticality: Severity = Severity.MEDIUM
    external_ref: Optional[str] = Field(default=None, max_length=512)
    first_seen_at: datetime = Field(default_factory=utc_now)
    last_seen_at: datetime = Field(default_factory=utc_now)
    attributes: Dict[str, CanonicalScalar] = Field(default_factory=dict)

    @model_validator(mode="after")
    def entity_times_and_attributes(self) -> "EntityRecord":
        if (
            self.first_seen_at.tzinfo is None
            or self.first_seen_at.utcoffset() is None
            or self.last_seen_at.tzinfo is None
            or self.last_seen_at.utcoffset() is None
        ):
            raise ValueError("entity timestamps must include a timezone")
        if self.last_seen_at < self.first_seen_at:
            raise ValueError("entity last_seen_at cannot precede first_seen_at")
        if len(self.attributes) > 64:
            raise ValueError("entity attributes are limited to 64 fields")
        for key, value in self.attributes.items():
            if not key or len(key) > 128:
                raise ValueError("entity attribute keys must be bounded")
            if isinstance(value, str) and len(value) > 2048:
                raise ValueError("entity attribute values must be bounded")
        return self


class AlertRecord(CanonicalRecordBase):
    record_type: Literal[RecordType.ALERT] = RecordType.ALERT
    alert_id: str = Field(min_length=5, max_length=128)
    event_id: str = Field(min_length=5, max_length=128)
    detector_id: str = Field(min_length=1, max_length=128)
    rule_version: str = Field(min_length=1, max_length=64)
    alert_type: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=512)
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    status: AlertStatus = AlertStatus.OPEN
    reason_codes: List[BoundedReasonCode] = Field(default_factory=list, max_length=128)
    framework_mappings: List[BoundedReference] = Field(default_factory=list, max_length=128)
    evidence_ids: List[BoundedReference] = Field(min_length=1, max_length=256)
    recommended_action: DecisionAction
    detected_at: datetime = Field(default_factory=utc_now)

    @field_validator("detected_at")
    @classmethod
    def detected_at_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("detected_at must include a timezone")
        return value


class FindingRecord(CanonicalRecordBase):
    record_type: Literal[RecordType.FINDING] = RecordType.FINDING
    finding_id: str = Field(min_length=5, max_length=128)
    finding_type: str = Field(min_length=1, max_length=128)
    alert_ids: List[BoundedReference] = Field(min_length=1, max_length=256)
    entity_ids: List[BoundedReference] = Field(min_length=1, max_length=256)
    evidence_ids: List[BoundedReference] = Field(min_length=1, max_length=256)
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    status: FindingStatus = FindingStatus.OPEN
    policy_version: str = Field(min_length=1, max_length=64)
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def finding_time_is_coherent(self) -> "FindingRecord":
        if self.updated_at.tzinfo is None or self.updated_at.utcoffset() is None:
            raise ValueError("finding updated_at must include a timezone")
        if self.updated_at < self.created_at:
            raise ValueError("finding updated_at cannot precede created_at")
        return self


class IncidentRecord(CanonicalRecordBase):
    record_type: Literal[RecordType.INCIDENT] = RecordType.INCIDENT
    incident_id: str = Field(min_length=5, max_length=128)
    title: str = Field(min_length=1, max_length=512)
    finding_ids: List[BoundedReference] = Field(min_length=1, max_length=1024)
    entity_ids: List[BoundedReference] = Field(min_length=1, max_length=1024)
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    status: IncidentStatus = IncidentStatus.OPEN
    owner_ref: Optional[str] = Field(default=None, max_length=256)
    opened_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def incident_times_are_coherent(self) -> "IncidentRecord":
        if (
            self.opened_at.tzinfo is None
            or self.opened_at.utcoffset() is None
            or self.updated_at.tzinfo is None
            or self.updated_at.utcoffset() is None
        ):
            raise ValueError("incident timestamps must include a timezone")
        if self.updated_at < self.opened_at:
            raise ValueError("incident updated_at cannot precede opened_at")
        return self


class InvestigationStep(StrictModel):
    step_id: str = Field(min_length=3, max_length=128)
    description: str = Field(min_length=1, max_length=1024)
    status: str = Field(min_length=1, max_length=64)
    evidence_ids: List[BoundedReference] = Field(default_factory=list, max_length=256)
    performed_by: Optional[str] = Field(default=None, max_length=256)
    performed_at: Optional[datetime] = None

    @model_validator(mode="after")
    def performed_state_is_coherent(self) -> "InvestigationStep":
        if self.performed_at is not None and (
            self.performed_at.tzinfo is None or self.performed_at.utcoffset() is None
        ):
            raise ValueError("investigation step timestamp must include a timezone")
        return self


class InvestigationRecord(CanonicalRecordBase):
    record_type: Literal[RecordType.INVESTIGATION] = RecordType.INVESTIGATION
    investigation_id: str = Field(min_length=5, max_length=128)
    incident_id: str = Field(min_length=5, max_length=128)
    status: InvestigationStatus
    hypothesis: str = Field(min_length=1, max_length=2048)
    steps: List[InvestigationStep] = Field(default_factory=list, max_length=1024)
    evidence_ids: List[BoundedReference] = Field(default_factory=list, max_length=1024)
    conclusion: Optional[str] = Field(default=None, max_length=4096)
    assigned_to: Optional[str] = Field(default=None, max_length=256)
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def investigation_time_is_coherent(self) -> "InvestigationRecord":
        if self.updated_at.tzinfo is None or self.updated_at.utcoffset() is None:
            raise ValueError("investigation updated_at must include a timezone")
        if self.updated_at < self.created_at:
            raise ValueError("investigation updated_at cannot precede created_at")
        return self


class JudgmentRecord(CanonicalRecordBase):
    record_type: Literal[RecordType.JUDGMENT] = RecordType.JUDGMENT
    judgment_id: str = Field(min_length=5, max_length=128)
    subject_type: Literal["alert", "finding", "incident"]
    subject_id: str = Field(min_length=5, max_length=128)
    judge_type: JudgeType
    action: DecisionAction
    deterministic_action: DecisionAction
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: List[BoundedReasonCode] = Field(min_length=1, max_length=128)
    evidence_ids: List[BoundedReference] = Field(min_length=1, max_length=1024)
    policy_version: str = Field(min_length=1, max_length=64)
    abstained: bool = False
    uncertainty: Optional[str] = Field(default=None, max_length=2048)
    judged_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def cannot_weaken_deterministic_action(self) -> "JudgmentRecord":
        rank = {
            DecisionAction.ALLOW: 0,
            DecisionAction.ALLOW_WITH_OBLIGATIONS: 1,
            DecisionAction.REQUIRE_APPROVAL: 2,
            DecisionAction.DENY: 3,
        }
        if rank[self.action] < rank[self.deterministic_action]:
            raise ValueError("canonical judgment cannot weaken deterministic action")
        if self.abstained and not self.uncertainty:
            raise ValueError("abstention requires an uncertainty explanation")
        if self.judged_at.tzinfo is None or self.judged_at.utcoffset() is None:
            raise ValueError("judged_at must include a timezone")
        return self


class ActionRecord(CanonicalRecordBase):
    record_type: Literal[RecordType.ACTION] = RecordType.ACTION
    action_id: str = Field(min_length=5, max_length=128)
    incident_id: str = Field(min_length=5, max_length=128)
    judgment_id: str = Field(min_length=5, max_length=128)
    action_type: str = Field(min_length=1, max_length=128)
    status: ActionStatus
    simulated: bool
    approval_ref: Optional[str] = Field(default=None, max_length=256)
    executor_ref: str = Field(min_length=1, max_length=256)
    target_entity_ids: List[BoundedReference] = Field(default_factory=list, max_length=1024)
    evidence_ids: List[BoundedReference] = Field(default_factory=list, max_length=1024)
    requested_at: datetime = Field(default_factory=utc_now)
    completed_at: Optional[datetime] = None
    result_code: Optional[str] = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def action_lifecycle_is_coherent(self) -> "ActionRecord":
        terminal = {
            ActionStatus.SUCCEEDED,
            ActionStatus.FAILED,
            ActionStatus.ROLLED_BACK,
            ActionStatus.CANCELLED,
        }
        if (self.status in terminal) != (self.completed_at is not None):
            raise ValueError("terminal action status and completed_at must agree")
        if self.requested_at.tzinfo is None or self.requested_at.utcoffset() is None:
            raise ValueError("action requested_at must include a timezone")
        if self.completed_at is not None:
            if self.completed_at.tzinfo is None or self.completed_at.utcoffset() is None:
                raise ValueError("action completed_at must include a timezone")
            if self.completed_at < self.requested_at:
                raise ValueError("action completed_at cannot precede requested_at")
        return self


CanonicalRecord = Annotated[
    Union[
        EventRecord,
        EvidenceRecord,
        EntityRecord,
        AlertRecord,
        FindingRecord,
        IncidentRecord,
        InvestigationRecord,
        JudgmentRecord,
        ActionRecord,
    ],
    Field(discriminator="record_type"),
]
CANONICAL_RECORD_ADAPTER = TypeAdapter(CanonicalRecord)


def canonical_record_json(record: CanonicalRecord) -> bytes:
    return json.dumps(
        record.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


class CanonicalRecordEnvelope(StrictModel):
    envelope_version: Literal["1.0.0"] = "1.0.0"
    record: CanonicalRecord
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    emitted_at: datetime = Field(default_factory=utc_now)
    source_schema_version: str = Field(min_length=1, max_length=32)
    migrations_applied: List[str] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def digest_matches_record(self) -> "CanonicalRecordEnvelope":
        expected = hashlib.sha256(canonical_record_json(self.record)).hexdigest()
        if not hmac_compare(expected, self.record_sha256):
            raise ValueError("canonical record digest mismatch")
        return self

    @classmethod
    def wrap(
        cls,
        record: CanonicalRecord,
        *,
        source_schema_version: str,
        migrations_applied: Optional[List[str]] = None,
    ) -> "CanonicalRecordEnvelope":
        return cls(
            record=record,
            record_sha256=hashlib.sha256(canonical_record_json(record)).hexdigest(),
            source_schema_version=source_schema_version,
            migrations_applied=migrations_applied or [],
        )


def hmac_compare(left: str, right: str) -> bool:
    """Constant-time digest comparison without importing the gateway boundary."""

    import hmac

    return hmac.compare_digest(left, right)


class CanonicalBundle(StrictModel):
    schema_version: Literal["1.0.0"] = CANONICAL_SCHEMA_VERSION
    tenant_id: str = Field(min_length=1, max_length=128)
    records: List[CanonicalRecord] = Field(min_length=1, max_length=10000)

    @model_validator(mode="after")
    def validate_references(self) -> "CanonicalBundle":
        if any(record.tenant_id != self.tenant_id for record in self.records):
            raise ValueError("canonical bundle cannot cross tenants")
        indexes: Dict[RecordType, Set[str]] = {kind: set() for kind in RecordType}
        id_fields = {
            RecordType.EVENT: "event_id",
            RecordType.EVIDENCE: "evidence_id",
            RecordType.ENTITY: "entity_id",
            RecordType.ALERT: "alert_id",
            RecordType.FINDING: "finding_id",
            RecordType.INCIDENT: "incident_id",
            RecordType.INVESTIGATION: "investigation_id",
            RecordType.JUDGMENT: "judgment_id",
            RecordType.ACTION: "action_id",
        }
        all_ids: Set[str] = set()
        for record in self.records:
            identity = getattr(record, id_fields[record.record_type])
            if identity in all_ids:
                raise ValueError("canonical record IDs must be unique within a bundle")
            all_ids.add(identity)
            indexes[record.record_type].add(identity)

        def require(values: List[str], kind: RecordType, label: str) -> None:
            if set(values) - indexes[kind]:
                raise ValueError("%s contains an unresolved %s reference" % (label, kind.value))

        for record in self.records:
            if isinstance(record, EventRecord):
                require([record.actor_entity_id] + record.target_entity_ids, RecordType.ENTITY, "event")
                require(record.evidence_ids, RecordType.EVIDENCE, "event")
            elif isinstance(record, AlertRecord):
                require([record.event_id], RecordType.EVENT, "alert")
                require(record.evidence_ids, RecordType.EVIDENCE, "alert")
            elif isinstance(record, FindingRecord):
                require(record.alert_ids, RecordType.ALERT, "finding")
                require(record.entity_ids, RecordType.ENTITY, "finding")
                require(record.evidence_ids, RecordType.EVIDENCE, "finding")
            elif isinstance(record, IncidentRecord):
                require(record.finding_ids, RecordType.FINDING, "incident")
                require(record.entity_ids, RecordType.ENTITY, "incident")
            elif isinstance(record, InvestigationRecord):
                require([record.incident_id], RecordType.INCIDENT, "investigation")
                require(record.evidence_ids, RecordType.EVIDENCE, "investigation")
                for step in record.steps:
                    require(step.evidence_ids, RecordType.EVIDENCE, "investigation step")
            elif isinstance(record, JudgmentRecord):
                require(
                    [record.subject_id], RecordType(record.subject_type), "judgment"
                )
                require(record.evidence_ids, RecordType.EVIDENCE, "judgment")
            elif isinstance(record, ActionRecord):
                require([record.incident_id], RecordType.INCIDENT, "action")
                require([record.judgment_id], RecordType.JUDGMENT, "action")
                require(record.target_entity_ids, RecordType.ENTITY, "action")
                require(record.evidence_ids, RecordType.EVIDENCE, "action")
        return self


ID_FIELDS = {
    RecordType.EVENT: "event_id",
    RecordType.EVIDENCE: "evidence_id",
    RecordType.ENTITY: "entity_id",
    RecordType.ALERT: "alert_id",
    RecordType.FINDING: "finding_id",
    RecordType.INCIDENT: "incident_id",
    RecordType.INVESTIGATION: "investigation_id",
    RecordType.JUDGMENT: "judgment_id",
    RecordType.ACTION: "action_id",
}


class CanonicalMigrator:
    """Strict one-step migrator for the repository's documented 0.9 beta shape."""

    @staticmethod
    def migrate(payload: Mapping[str, Any]) -> CanonicalRecordEnvelope:
        source_version = payload.get("schema_version")
        if source_version == CANONICAL_SCHEMA_VERSION:
            record = CANONICAL_RECORD_ADAPTER.validate_python(payload)
            return CanonicalRecordEnvelope.wrap(
                record, source_schema_version=CANONICAL_SCHEMA_VERSION
            )
        if source_version != LEGACY_CANONICAL_SCHEMA_VERSION:
            raise ValueError("unsupported canonical schema version")
        try:
            record_type = RecordType(payload["record_type"])
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError("unsupported canonical record type") from exc
        migrated = dict(payload)
        migrated["schema_version"] = CANONICAL_SCHEMA_VERSION
        if "tenant" in migrated:
            migrated["tenant_id"] = migrated.pop("tenant")
        identity_field = ID_FIELDS[record_type]
        if "id" in migrated:
            migrated[identity_field] = migrated.pop("id")
        if "timestamp" in migrated:
            migrated["created_at"] = migrated.pop("timestamp")
        record = CANONICAL_RECORD_ADAPTER.validate_python(migrated)
        return CanonicalRecordEnvelope.wrap(
            record,
            source_schema_version=LEGACY_CANONICAL_SCHEMA_VERSION,
            migrations_applied=["%s:0.9.0->1.0.0" % record_type.value],
        )


def _safe_evidence_id(tenant_id: str, alert_id: str, value: str) -> str:
    digest = hashlib.sha256(
        (tenant_id + "\x00" + alert_id + "\x00" + value).encode("utf-8")
    ).hexdigest()
    return "evd_%s" % digest[:32]


def event_record_from_agent_event(event: AgentEvent) -> EventRecord:
    return EventRecord(
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        created_at=event.occurred_at,
        occurred_at=event.occurred_at,
        observed_at=event.occurred_at,
        event_kind="agent_effect_proposal",
        trace_id=event.flow_id,
        actor_entity_id="entity://agent/%s" % event.agent_id,
        operation=event.operation,
        source_ref=event.source_id,
        source_trust=event.source_trust.value,
        attributes={
            "source_type": event.source_type,
            "is_effectful": event.is_effectful,
            "approval_present": event.approval_present,
        },
    )


def event_record_from_telemetry(event: TelemetryEnvelope) -> EventRecord:
    return EventRecord(
        event_id=event.event_id,
        tenant_id=event.context.tenant_id,
        created_at=event.observed_at,
        occurred_at=event.occurred_at,
        observed_at=event.observed_at,
        event_kind=event.kind.value,
        trace_id=event.context.trace_id,
        session_id=event.context.session_id,
        actor_entity_id="entity://agent/%s" % event.context.agent_id,
        operation=event.operation,
        outcome=("success" if event.success else "failure") if event.success is not None else None,
        source_ref=event.context.source_id,
        source_trust="observed",
        attributes=dict(event.attributes),
    )


def alert_record_from_security_alert(
    alert: SecurityAlert, evidence_ids: List[str]
) -> AlertRecord:
    return AlertRecord(
        alert_id=alert.alert_id,
        tenant_id=alert.tenant_id,
        created_at=alert.detected_at,
        event_id=alert.event_id,
        detector_id=alert.detector_id,
        rule_version=alert.rule_version,
        alert_type=alert.alert_type,
        title=alert.title,
        severity=alert.severity,
        confidence=alert.confidence,
        evidence_ids=evidence_ids,
        reason_codes=alert.reason_codes,
        framework_mappings=alert.framework_mappings,
        recommended_action=alert.recommended_action,
        detected_at=alert.detected_at,
    )


def finding_record_from_finding(
    finding: Finding,
    *,
    entity_ids: List[str],
    evidence_ids: List[str],
    risk_score: int,
) -> FindingRecord:
    return FindingRecord(
        finding_id=finding.finding_id,
        tenant_id=finding.tenant_id,
        created_at=finding.created_at,
        finding_type=finding.finding_type,
        alert_ids=finding.alert_ids,
        entity_ids=entity_ids,
        evidence_ids=evidence_ids,
        severity=finding.severity,
        risk_score=risk_score,
        status=FindingStatus(finding.status.value),
        policy_version=finding.policy_version,
        updated_at=finding.updated_at,
    )


def canonical_bundle_from_pipeline(result: PipelineResult) -> CanonicalBundle:
    """Produce a complete reference-valid canonical projection of one pipeline result."""

    tenant_id = result.event.tenant_id
    entity_id = "entity://agent/%s" % result.event.agent_id
    entity = EntityRecord(
        tenant_id=tenant_id,
        entity_id=entity_id,
        entity_type=EntityType.AGENT,
        name=result.event.agent_id,
        first_seen_at=result.event.occurred_at,
        last_seen_at=result.response.responded_at,
        external_ref=entity_id,
    )
    evidence: List[EvidenceRecord] = []
    evidence_ids: List[str] = []
    for value in result.alert.evidence or result.alert.reason_codes or [result.alert.fingerprint]:
        evidence_id = _safe_evidence_id(tenant_id, result.alert.alert_id, value)
        evidence_ids.append(evidence_id)
        evidence.append(
            EvidenceRecord(
                tenant_id=tenant_id,
                evidence_id=evidence_id,
                evidence_type=EvidenceType.DETECTOR,
                subject_refs=[result.event.event_id, result.alert.alert_id],
                source=result.alert.detector_id,
                claim="Detector evidence supports %s" % result.alert.alert_type,
                content_sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(),
                integrity_status=(
                    IntegrityStatus.VERIFIED
                    if result.ledger_verified
                    else IntegrityStatus.UNVERIFIED
                ),
                collected_at=result.alert.detected_at,
            )
        )
    event = event_record_from_agent_event(result.event)
    alert = alert_record_from_security_alert(result.alert, evidence_ids)
    finding = finding_record_from_finding(
        result.finding,
        entity_ids=[entity_id],
        evidence_ids=evidence_ids,
        risk_score=result.triage.risk_score,
    )
    incident_id = "inc_%s" % result.finding.finding_id.removeprefix("fnd_")
    incident_status = {
        "open": IncidentStatus.OPEN,
        "acknowledged": IncidentStatus.ACKNOWLEDGED,
        "investigating": IncidentStatus.INVESTIGATING,
        "contained": IncidentStatus.CONTAINED,
        "closed": IncidentStatus.CLOSED,
    }[result.finding.status.value]
    incident = IncidentRecord(
        tenant_id=tenant_id,
        incident_id=incident_id,
        title=result.alert.title,
        finding_ids=[result.finding.finding_id],
        entity_ids=[entity_id],
        severity=result.triage.severity,
        risk_score=result.triage.risk_score,
        status=incident_status,
        opened_at=result.finding.created_at,
        updated_at=result.finding.updated_at,
    )
    judgment_id = "jdg_%s" % result.alert.alert_id.removeprefix("alr_")
    judgment = JudgmentRecord(
        tenant_id=tenant_id,
        judgment_id=judgment_id,
        subject_type="alert",
        subject_id=result.alert.alert_id,
        judge_type=(
            JudgeType.COMBINED if result.judgment.model_verdict is not None else JudgeType.DETERMINISTIC
        ),
        action=result.judgment.action,
        deterministic_action=result.judgment.deterministic_action,
        confidence=(
            result.judgment.model_verdict.confidence
            if result.judgment.model_verdict is not None
            else result.alert.confidence
        ),
        reason_codes=result.judgment.reason_codes,
        evidence_ids=evidence_ids,
        policy_version=result.judgment.policy_version,
        judged_at=result.judgment.judged_at,
    )
    action_status = (
        ActionStatus.SUCCEEDED
        if result.response.effect_status.value in {"allowed", "blocked", "held"}
        else ActionStatus.PROPOSED
    )
    action = ActionRecord(
        tenant_id=tenant_id,
        action_id="act_%s" % result.alert.alert_id.removeprefix("alr_"),
        incident_id=incident_id,
        judgment_id=judgment_id,
        action_type="+".join(item.value for item in result.response.actions),
        status=action_status,
        simulated=result.response.simulated,
        executor_ref=result.response.responder,
        target_entity_ids=[entity_id],
        evidence_ids=evidence_ids,
        requested_at=result.judgment.judged_at,
        completed_at=result.response.responded_at,
        result_code=result.response.effect_status.value,
    )
    return CanonicalBundle(
        tenant_id=tenant_id,
        records=[entity, *evidence, event, alert, finding, incident, judgment, action],
    )
