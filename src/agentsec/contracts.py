"""Versioned contracts shared by every security-pipeline component."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


SCHEMA_VERSION = "1.0.0"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return "%s_%s" % (prefix, uuid4().hex)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class TrustClass(str, Enum):
    TRUSTED_CONTROL = "trusted-control"
    AUTHENTICATED_USER = "authenticated-user"
    INTERNAL_DATA = "internal-data"
    EXTERNAL_UNTRUSTED = "external-untrusted"
    SUSPECTED_ADVERSARIAL = "suspected-adversarial"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DecisionAction(str, Enum):
    ALLOW = "allow"
    ALLOW_WITH_OBLIGATIONS = "allow_with_obligations"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class AiMode(str, Enum):
    OFF = "off"
    SHADOW = "shadow"
    ADVISORY = "advisory"
    SEMANTIC_HOLD = "semantic_hold"


class PipelineStage(str, Enum):
    DETECTION = "detection"
    INGESTION = "ingestion"
    TRIAGE = "triage"
    JUDGMENT = "judgment"
    ESCALATION = "escalation"
    RESPONSE = "response"


class EscalationLevel(str, Enum):
    NONE = "none"
    REVIEW_QUEUE = "review_queue"
    SOC_URGENT = "soc_urgent"
    INCIDENT_PAGE = "incident_page"


class ResponseAction(str, Enum):
    RECORD_ONLY = "record_only"
    HOLD_FOR_APPROVAL = "hold_for_approval"
    BLOCK_EFFECT = "block_effect"
    QUARANTINE_SESSION = "quarantine_session"


class FindingStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    CLOSED = "closed"


class AgentEvent(StrictModel):
    """Metadata-only observation of a proposed AI-agent effect."""

    schema_version: str = SCHEMA_VERSION
    event_id: str = Field(default_factory=lambda: new_id("evt"), min_length=5, max_length=128)
    occurred_at: datetime = Field(default_factory=utc_now)
    tenant_id: str = Field(min_length=1, max_length=128)
    flow_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    operation: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=512)
    destination: Optional[str] = Field(default=None, max_length=512)
    source_type: str = Field(min_length=1, max_length=64)
    source_id: str = Field(min_length=1, max_length=256)
    source_trust: TrustClass
    data_classes: Set[str] = Field(default_factory=set)
    authority_operations: Set[str] = Field(default_factory=set)
    indicators: Set[str] = Field(default_factory=set)
    approval_present: bool = False
    is_effectful: bool = True
    tool_name: Optional[str] = Field(default=None, max_length=128)
    declared_tool_schema_digest: Optional[str] = Field(default=None, max_length=128)
    observed_tool_schema_digest: Optional[str] = Field(default=None, max_length=128)
    attributes: Dict[str, str] = Field(default_factory=dict)

    @field_validator("occurred_at")
    @classmethod
    def timestamp_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone")
        return value


class DetectorMatch(StrictModel):
    detector_id: str
    alert_type: str
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: List[str]
    evidence: List[str]
    recommended_action: DecisionAction


class SecurityAlert(StrictModel):
    schema_version: str = SCHEMA_VERSION
    alert_id: str = Field(default_factory=lambda: new_id("alr"))
    fingerprint: str
    event_id: str
    tenant_id: str
    flow_id: str
    agent_id: str
    alert_type: str
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    source_trust: TrustClass
    operation: str
    resource: str
    destination: Optional[str] = None
    detector_id: str
    reason_codes: List[str]
    evidence: List[str]
    recommended_action: DecisionAction
    detected_at: datetime = Field(default_factory=utc_now)


class IngestionReceipt(StrictModel):
    alert_id: str
    duplicate: bool
    sequence: int = Field(ge=1)
    previous_hash: str
    current_hash: str
    ingested_at: datetime = Field(default_factory=utc_now)


class TriageAssessment(StrictModel):
    alert_id: str
    risk_score: int = Field(ge=0, le=100)
    severity: Severity
    priority: str
    reasons: List[str]
    assessed_at: datetime = Field(default_factory=utc_now)


class ModelVerdict(StrictModel):
    provider: str
    model_id: str
    action: DecisionAction
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: List[str]
    reason_codes: List[str]
    uncertainty: Optional[str] = None


class Judgment(StrictModel):
    alert_id: str
    action: DecisionAction
    reason_codes: List[str]
    deterministic_action: DecisionAction
    model_verdict: Optional[ModelVerdict] = None
    ai_mode: AiMode = AiMode.OFF
    policy_version: str
    judged_at: datetime = Field(default_factory=utc_now)


class EscalationRecord(StrictModel):
    alert_id: str
    level: EscalationLevel
    queue: Optional[str] = None
    case_id: Optional[str] = None
    reason: str
    escalated_at: datetime = Field(default_factory=utc_now)


class ResponseRecord(StrictModel):
    alert_id: str
    actions: List[ResponseAction]
    effect_allowed: bool
    simulated: bool = True
    responder: str = "local-safe-response"
    notes: List[str]
    responded_at: datetime = Field(default_factory=utc_now)


class TimelineEntry(StrictModel):
    stage: PipelineStage
    outcome: str
    at: datetime = Field(default_factory=utc_now)
    evidence: Dict[str, Any] = Field(default_factory=dict)


class PipelineResult(StrictModel):
    event: AgentEvent
    alert: SecurityAlert
    ingestion: IngestionReceipt
    triage: TriageAssessment
    judgment: Judgment
    escalation: EscalationRecord
    response: ResponseRecord
    finding: "Finding"
    timeline: List[TimelineEntry]


class EventProcessingResult(StrictModel):
    event: AgentEvent
    alerts: List[PipelineResult]
    overall_action: DecisionAction
    effect_allowed: bool


class FindingAuditEntry(StrictModel):
    from_status: Optional[FindingStatus] = None
    to_status: FindingStatus
    actor: str
    reason: str
    at: datetime = Field(default_factory=utc_now)


class Finding(StrictModel):
    schema_version: str = SCHEMA_VERSION
    finding_id: str
    fingerprint: str
    tenant_id: str
    flow_id: str
    agent_id: str
    finding_type: str
    severity: Severity
    status: FindingStatus = FindingStatus.OPEN
    detector_id: str
    policy_version: str
    alert_ids: List[str]
    evidence: List[str]
    audit: List[FindingAuditEntry]
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
