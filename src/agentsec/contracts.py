"""Versioned contracts shared by every security-pipeline component."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Literal, Optional, Set, Union
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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
    ENRICHMENT = "enrichment"
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


class EnrichmentStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


class EnrichmentCacheStatus(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    MISS = "miss"
    FRESH = "fresh"
    STALE = "stale"


class AnalystRole(str, Enum):
    TRIAGE = "triage"
    INVESTIGATION = "investigation"
    JUDGE = "judge"
    ESCALATION = "escalation"
    RESPONSE_ADVISOR = "response_advisor"


class AnalystRoleStatus(str, Enum):
    COMPLETED = "completed"
    ABSTAINED = "abstained"
    UNAVAILABLE = "unavailable"


class AnalystRunStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    ABSTAINED = "abstained"


class AnalystClaimOperator(str, Enum):
    EQUALS = "equals"
    CONTAINS = "contains"
    EXISTS = "exists"


class ClaimValidationStatus(str, Enum):
    VERIFIED = "verified"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    CONTRADICTED = "contradicted"
    REJECTED = "rejected"


class JudgmentValidationStatus(str, Enum):
    PASSED = "passed"
    HUMAN_REVIEW = "human_review"
    REJECTED = "rejected"


class AnalystDisagreementKind(str, Enum):
    RELAXATION_REJECTED = "relaxation_rejected"
    TIGHTENING_PROPOSED = "tightening_proposed"
    CROSS_ROLE_CONFLICT = "cross_role_conflict"
    ABSTENTION = "abstention"
    ROLE_UNAVAILABLE = "role_unavailable"


class AnalystFeedbackRating(str, Enum):
    HELPFUL = "helpful"
    INCORRECT = "incorrect"
    INCOMPLETE = "incomplete"
    NEEDS_REVIEW = "needs_review"


class EffectStatus(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    HELD = "held"


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
    rule_version: str = "1.0.0"
    alert_type: str
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: List[str]
    evidence: List[str]
    framework_mappings: List[str] = Field(default_factory=list)
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
    rule_version: str = "1.0.0"
    reason_codes: List[str]
    evidence: List[str]
    framework_mappings: List[str] = Field(default_factory=list)
    recommended_action: DecisionAction
    detected_at: datetime = Field(default_factory=utc_now)


class IngestionReceipt(StrictModel):
    alert_id: str
    duplicate: bool
    sequence: int = Field(ge=1)
    previous_hash: str
    current_hash: str
    ingested_at: datetime = Field(default_factory=utc_now)


EnrichmentFactValue = Union[str, bool, int, float, List[str]]


class EnrichmentResult(StrictModel):
    source: str
    status: EnrichmentStatus
    observed_at: datetime = Field(default_factory=utc_now)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    facts: Dict[str, EnrichmentFactValue] = Field(default_factory=dict)
    evidence_refs: List[str] = Field(default_factory=list)
    latency_ms: int = Field(default=0, ge=0)
    affects_triage: bool = False
    failure_effect: str
    connector_version: Optional[str] = Field(default=None, max_length=64)
    cache_status: EnrichmentCacheStatus = EnrichmentCacheStatus.NOT_APPLICABLE
    freshness_seconds: Optional[int] = Field(default=None, ge=0)
    expires_at: Optional[datetime] = None
    policy_decision: str = Field(default="built_in", max_length=64)


class EnrichmentSnapshot(StrictModel):
    snapshot_id: str = Field(default_factory=lambda: new_id("enr"))
    status: EnrichmentStatus
    observed_at: datetime = Field(default_factory=utc_now)
    sources: List[EnrichmentResult]
    completed_sources: int = Field(ge=0)
    total_sources: int = Field(ge=1)
    mandatory_context_complete: bool
    warnings: List[str] = Field(default_factory=list)
    connector_sources: int = Field(default=0, ge=0)
    cache_hits: int = Field(default=0, ge=0)
    stale_fallbacks: int = Field(default=0, ge=0)
    timed_out_sources: int = Field(default=0, ge=0)
    policy_digest: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class RiskContribution(StrictModel):
    category: str
    label: str
    delta: int = Field(ge=-100, le=100)
    evidence_refs: List[str] = Field(min_length=1)
    rationale: str


class TriageAssessment(StrictModel):
    alert_id: str
    risk_score: int = Field(ge=0, le=100)
    severity: Severity
    priority: str
    reasons: List[str]
    score_version: str
    contributions: List[RiskContribution]
    sla_minutes: int = Field(ge=0)
    route: str
    missing_context_warnings: List[str] = Field(default_factory=list)
    behavior_assessment_id: Optional[str] = None
    behavior_anomaly_score: Optional[int] = Field(default=None, ge=0, le=100)
    composite_risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    behavior_drift_state: Optional[str] = None
    narrative: str
    assessed_at: datetime = Field(default_factory=utc_now)


class ModelVerdict(StrictModel):
    provider: str
    model_id: str
    action: DecisionAction
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: List[str]
    reason_codes: List[str]
    uncertainty: Optional[str] = None


class AnalystEvidenceItem(StrictModel):
    evidence_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,31}_sha256:[0-9a-f]{24}$")
    kind: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    source: str = Field(min_length=1, max_length=128)
    observed_at: datetime
    facts: Dict[str, EnrichmentFactValue] = Field(default_factory=dict, max_length=32)

    @field_validator("observed_at")
    @classmethod
    def evidence_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("analyst evidence timestamp must include a timezone")
        return value


class AnalystClaim(StrictModel):
    """A bounded, machine-checkable assertion made by one analyst role."""

    claim_id: str = Field(default_factory=lambda: new_id("acm"), pattern=r"^acm_[0-9a-f]{32}$")
    statement: str = Field(min_length=3, max_length=512)
    subject: str = Field(min_length=1, max_length=128)
    fact_key: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    operator: AnalystClaimOperator
    expected_value: Optional[EnrichmentFactValue] = None
    evidence_ids: List[str] = Field(min_length=1, max_length=16)

    @field_validator("evidence_ids")
    @classmethod
    def valid_evidence_ids(cls, value: List[str]) -> List[str]:
        pattern = re.compile(r"^[a-z][a-z0-9_-]{1,31}_sha256:[0-9a-f]{24}$")
        if any(pattern.fullmatch(item) is None for item in value):
            raise ValueError("analyst claims require governed evidence IDs")
        if len(set(value)) != len(value):
            raise ValueError("analyst claim evidence IDs must be unique")
        return value

    @model_validator(mode="after")
    def valid_operator_value(self) -> "AnalystClaim":
        if self.operator == AnalystClaimOperator.EXISTS:
            if self.expected_value is not None:
                raise ValueError("exists claims cannot include an expected value")
        elif self.expected_value is None:
            raise ValueError("equals and contains claims require an expected value")
        return self


class AnalystAlternative(StrictModel):
    title: str = Field(min_length=3, max_length=128)
    rationale: str = Field(min_length=3, max_length=512)
    recommended_action: Optional[DecisionAction] = None
    evidence_ids: List[str] = Field(default_factory=list, max_length=16)

    @field_validator("evidence_ids")
    @classmethod
    def valid_evidence_ids(cls, value: List[str]) -> List[str]:
        pattern = re.compile(r"^[a-z][a-z0-9_-]{1,31}_sha256:[0-9a-f]{24}$")
        if any(pattern.fullmatch(item) is None for item in value):
            raise ValueError("analyst alternatives require governed evidence IDs")
        return value


class AnalystRoleRequest(StrictModel):
    schema_version: str = "1.0.0"
    run_id: str = Field(pattern=r"^air_[0-9a-f]{32}$")
    role: AnalystRole
    alert_id: str = Field(min_length=5, max_length=128)
    objective: str = Field(min_length=3, max_length=512)
    deterministic_action: DecisionAction
    priority: str = Field(pattern=r"^P[0-3]$")
    evidence: List[AnalystEvidenceItem] = Field(default_factory=list, max_length=64)
    prior_role_summaries: List[str] = Field(default_factory=list, max_length=4)
    max_alternatives: int = Field(default=3, ge=1, le=5)
    requested_at: datetime

    @field_validator("prior_role_summaries")
    @classmethod
    def bounded_prior_summaries(cls, value: List[str]) -> List[str]:
        if any(not item or len(item) > 1024 for item in value):
            raise ValueError("prior role summaries must contain 1 to 1024 characters")
        return value

    @field_validator("requested_at")
    @classmethod
    def request_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("analyst request timestamp must include a timezone")
        return value


class AnalystRoleResult(StrictModel):
    schema_version: str = "1.0.0"
    role: AnalystRole
    status: AnalystRoleStatus
    provider: str = Field(min_length=1, max_length=64)
    model_id: str = Field(min_length=1, max_length=128)
    summary: Optional[str] = Field(default=None, max_length=1024)
    hypothesis: Optional[str] = Field(default=None, max_length=1024)
    recommended_action: Optional[DecisionAction] = None
    escalation_advice: Optional[str] = Field(default=None, max_length=256)
    response_advice: List[str] = Field(default_factory=list, max_length=8)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    evidence_ids: List[str] = Field(default_factory=list, max_length=32)
    claims: List[AnalystClaim] = Field(default_factory=list, max_length=16)
    reason_codes: List[str] = Field(default_factory=list, max_length=32)
    alternatives: List[AnalystAlternative] = Field(default_factory=list, max_length=5)
    uncertainties: List[str] = Field(default_factory=list, max_length=16)
    abstention_reason: Optional[str] = Field(default=None, max_length=512)
    latency_ms: int = Field(default=0, ge=0, le=60000)
    completed_at: datetime = Field(default_factory=utc_now)

    @field_validator("evidence_ids")
    @classmethod
    def valid_evidence_ids(cls, value: List[str]) -> List[str]:
        pattern = re.compile(r"^[a-z][a-z0-9_-]{1,31}_sha256:[0-9a-f]{24}$")
        if any(pattern.fullmatch(item) is None for item in value):
            raise ValueError("analyst roles require governed evidence IDs")
        return value

    @field_validator("reason_codes")
    @classmethod
    def valid_reason_codes(cls, value: List[str]) -> List[str]:
        if any(re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", item) is None for item in value):
            raise ValueError("analyst reason codes must be bounded uppercase identifiers")
        return value

    @field_validator("response_advice", "uncertainties")
    @classmethod
    def bounded_text_lists(cls, value: List[str]) -> List[str]:
        if any(not item or len(item) > 512 for item in value):
            raise ValueError("analyst text list values must contain 1 to 512 characters")
        return value

    @field_validator("completed_at")
    @classmethod
    def completed_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("analyst completion timestamp must include a timezone")
        return value

    @model_validator(mode="after")
    def valid_role_outcome(self) -> "AnalystRoleResult":
        if self.status == AnalystRoleStatus.COMPLETED:
            if not self.summary or self.confidence is None or not self.evidence_ids:
                raise ValueError("completed analyst role requires summary, confidence, and evidence")
            if not self.alternatives:
                raise ValueError("completed analyst role requires at least one alternative")
            if self.abstention_reason is not None:
                raise ValueError("completed analyst role cannot carry an abstention reason")
        else:
            if not self.abstention_reason:
                raise ValueError("non-completed analyst role requires an abstention reason")
            if self.recommended_action is not None:
                raise ValueError("abstained or unavailable role cannot recommend an action")
            if self.claims:
                raise ValueError("abstained or unavailable role cannot make claims")
        return self


class AnalystToolReceipt(StrictModel):
    receipt_id: str = Field(default_factory=lambda: new_id("ait"))
    run_id: str = Field(pattern=r"^air_[0-9a-f]{32}$")
    role: AnalystRole
    tool: Literal["evidence.query"] = "evidence.query"
    requested_kinds: List[str] = Field(default_factory=list, max_length=16)
    returned_evidence_ids: List[str] = Field(default_factory=list, max_length=64)
    result_count: int = Field(ge=0, le=64)
    queried_at: datetime = Field(default_factory=utc_now)
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("requested_kinds")
    @classmethod
    def valid_requested_kinds(cls, value: List[str]) -> List[str]:
        if any(re.fullmatch(r"[a-z][a-z0-9_]{1,63}", item) is None for item in value):
            raise ValueError("analyst evidence kinds must be bounded identifiers")
        return value

    @field_validator("returned_evidence_ids")
    @classmethod
    def valid_returned_evidence_ids(cls, value: List[str]) -> List[str]:
        pattern = re.compile(r"^[a-z][a-z0-9_-]{1,31}_sha256:[0-9a-f]{24}$")
        if any(pattern.fullmatch(item) is None for item in value):
            raise ValueError("analyst tool receipts require governed evidence IDs")
        return value

    @field_validator("queried_at")
    @classmethod
    def query_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("analyst tool timestamp must include a timezone")
        return value

    @model_validator(mode="after")
    def count_matches_evidence(self) -> "AnalystToolReceipt":
        if self.result_count != len(self.returned_evidence_ids):
            raise ValueError("analyst tool result count must match returned evidence")
        return self


class AnalystDisagreement(StrictModel):
    disagreement_id: str = Field(default_factory=lambda: new_id("aid"))
    kind: AnalystDisagreementKind
    left: str = Field(min_length=1, max_length=128)
    right: str = Field(min_length=1, max_length=128)
    left_action: Optional[DecisionAction] = None
    right_action: Optional[DecisionAction] = None
    rationale: str = Field(min_length=3, max_length=512)
    evidence_ids: List[str] = Field(default_factory=list, max_length=16)

    @field_validator("evidence_ids")
    @classmethod
    def valid_evidence_ids(cls, value: List[str]) -> List[str]:
        pattern = re.compile(r"^[a-z][a-z0-9_-]{1,31}_sha256:[0-9a-f]{24}$")
        if any(pattern.fullmatch(item) is None for item in value):
            raise ValueError("analyst disagreements require governed evidence IDs")
        return value


class MandatoryEvidenceCheck(StrictModel):
    role: AnalystRole
    required_kinds: List[str] = Field(min_length=1, max_length=16)
    cited_kinds: List[str] = Field(default_factory=list, max_length=16)
    missing_kinds: List[str] = Field(default_factory=list, max_length=16)
    passed: bool

    @model_validator(mode="after")
    def coherent_evidence_check(self) -> "MandatoryEvidenceCheck":
        if len(set(self.required_kinds)) != len(self.required_kinds):
            raise ValueError("mandatory evidence kinds must be unique")
        if len(set(self.cited_kinds)) != len(self.cited_kinds):
            raise ValueError("cited evidence kinds must be unique")
        expected_missing = [
            item for item in self.required_kinds if item not in self.cited_kinds
        ]
        if self.missing_kinds != expected_missing:
            raise ValueError("missing evidence kinds must be derived from policy")
        if self.passed and self.missing_kinds:
            raise ValueError("a passed evidence check cannot omit a required kind")
        return self


class ClaimValidationResult(StrictModel):
    claim_id: str = Field(pattern=r"^acm_[0-9a-f]{32}$")
    role: AnalystRole
    status: ClaimValidationStatus
    evidence_ids: List[str] = Field(default_factory=list, max_length=16)
    matched_evidence_ids: List[str] = Field(default_factory=list, max_length=16)
    conflicting_evidence_ids: List[str] = Field(default_factory=list, max_length=16)
    independent_sources: int = Field(ge=0, le=16)
    claimed_confidence: float = Field(ge=0.0, le=1.0)
    calibrated_confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: List[str] = Field(default_factory=list, max_length=16)


class JudgmentContradiction(StrictModel):
    left_claim_id: str = Field(pattern=r"^acm_[0-9a-f]{32}$")
    right_claim_id: str = Field(pattern=r"^acm_[0-9a-f]{32}$")
    subject: str = Field(min_length=1, max_length=128)
    fact_key: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    evidence_ids: List[str] = Field(default_factory=list, max_length=16)
    reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")


class JudgmentValidationIssue(StrictModel):
    code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")
    severity: Literal["warning", "error", "critical"]
    role: Optional[AnalystRole] = None
    message: str = Field(min_length=3, max_length=256)
    evidence_ids: List[str] = Field(default_factory=list, max_length=16)


class JudgmentValidationReport(StrictModel):
    schema_version: str = "1.0.0"
    report_id: str = Field(default_factory=lambda: new_id("jvr"), pattern=r"^jvr_[0-9a-f]{32}$")
    policy_version: str = Field(min_length=1, max_length=64)
    status: JudgmentValidationStatus
    deterministic_action: DecisionAction
    machine_action: DecisionAction
    automation_eligible: Literal[False] = False
    human_gate_required: bool
    human_gate_reasons: List[str] = Field(default_factory=list, max_length=32)
    mandatory_evidence: List[MandatoryEvidenceCheck] = Field(min_length=5, max_length=5)
    claim_results: List[ClaimValidationResult] = Field(default_factory=list, max_length=80)
    contradictions: List[JudgmentContradiction] = Field(default_factory=list, max_length=32)
    issues: List[JudgmentValidationIssue] = Field(default_factory=list, max_length=64)
    accepted_claims: int = Field(ge=0)
    rejected_claims: int = Field(ge=0)
    calibrated_confidence: float = Field(ge=0.0, le=1.0)
    validated_at: datetime = Field(default_factory=utc_now)
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def coherent_validation(self) -> "JudgmentValidationReport":
        if self.machine_action != self.deterministic_action:
            raise ValueError("AI validation cannot change the deterministic machine action")
        accepted = sum(
            item.status
            in {ClaimValidationStatus.VERIFIED, ClaimValidationStatus.PARTIAL}
            for item in self.claim_results
        )
        if self.accepted_claims != accepted or self.rejected_claims != len(self.claim_results) - accepted:
            raise ValueError("claim validation counts must match the recorded results")
        if len({item.claim_id for item in self.claim_results}) != len(self.claim_results):
            raise ValueError("claim validation results must use unique claim IDs")
        if [item.role for item in self.mandatory_evidence] != list(AnalystRole):
            raise ValueError("mandatory evidence checks must use the governed role order")
        if self.status != JudgmentValidationStatus.PASSED and not self.human_gate_required:
            raise ValueError("non-passing validation requires a human gate")
        if self.status == JudgmentValidationStatus.PASSED:
            if self.human_gate_required or self.issues or self.contradictions:
                raise ValueError("passing validation cannot contain a human gate or unresolved issue")
            if not all(item.passed for item in self.mandatory_evidence):
                raise ValueError("passing validation requires all mandatory evidence checks")
            if self.rejected_claims:
                raise ValueError("passing validation cannot contain rejected claims")
        if self.validated_at.tzinfo is None or self.validated_at.utcoffset() is None:
            raise ValueError("judgment validation timestamp must include a timezone")
        return self


class AiAnalystRun(StrictModel):
    schema_version: str = "1.0.0"
    run_id: str = Field(default_factory=lambda: new_id("air"), pattern=r"^air_[0-9a-f]{32}$")
    tenant_id: str = Field(min_length=1, max_length=128)
    alert_id: str = Field(min_length=5, max_length=128)
    finding_id: str = Field(min_length=5, max_length=128)
    status: AnalystRunStatus
    provider: str = Field(min_length=1, max_length=64)
    model_id: str = Field(min_length=1, max_length=128)
    recording_id: Optional[str] = Field(default=None, max_length=128)
    policy_version: str = Field(min_length=1, max_length=64)
    deterministic_action: DecisionAction
    advisory_action: DecisionAction
    executive_authority: Literal[False] = False
    human_review_required: bool
    role_results: List[AnalystRoleResult] = Field(min_length=5, max_length=5)
    tool_receipts: List[AnalystToolReceipt] = Field(min_length=5, max_length=5)
    disagreements: List[AnalystDisagreement] = Field(default_factory=list, max_length=32)
    validation: JudgmentValidationReport
    evidence_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    started_at: datetime
    completed_at: datetime
    run_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def coherent_run(self) -> "AiAnalystRun":
        expected = list(AnalystRole)
        if [item.role for item in self.role_results] != expected:
            raise ValueError("analyst roles must use the complete governed order")
        if [item.role for item in self.tool_receipts] != expected:
            raise ValueError("analyst tool receipts must match the governed role order")
        if (
            self.started_at.tzinfo is None
            or self.started_at.utcoffset() is None
            or self.completed_at.tzinfo is None
            or self.completed_at.utcoffset() is None
            or self.completed_at < self.started_at
        ):
            raise ValueError("analyst run timestamps must be aware and ordered")
        if self.validation.deterministic_action != self.deterministic_action:
            raise ValueError("analyst validation must bind the run's deterministic action")
        if self.validation.human_gate_required and not self.human_review_required:
            raise ValueError("validation human gate must be visible on the analyst run")
        return self


class AnalystFeedback(StrictModel):
    schema_version: str = "1.0.0"
    feedback_id: str = Field(default_factory=lambda: new_id("aif"))
    tenant_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(pattern=r"^air_[0-9a-f]{32}$")
    actor_id: str = Field(min_length=3, max_length=256)
    rating: AnalystFeedbackRating
    role: Optional[AnalystRole] = None
    reason: str = Field(min_length=3, max_length=512)
    applied_to_model: Literal[False] = False
    created_at: datetime = Field(default_factory=utc_now)
    feedback_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AnalystHealthSummary(StrictModel):
    schema_version: str = "1.0.0"
    tenant_id: str
    total_runs: int = Field(ge=0)
    completed_runs: int = Field(ge=0)
    partial_runs: int = Field(ge=0)
    abstained_roles: int = Field(ge=0)
    unavailable_roles: int = Field(ge=0)
    disagreements: int = Field(ge=0)
    feedback_records: int = Field(ge=0)
    calculated_at: datetime


class ModelVerdictValidation(StrictModel):
    policy_version: str = Field(min_length=1, max_length=64)
    status: Literal["valid", "human_review", "rejected"]
    cited_evidence_ids: List[str] = Field(default_factory=list, max_length=32)
    unknown_evidence_ids: List[str] = Field(default_factory=list, max_length=32)
    claimed_confidence: float = Field(ge=0.0, le=1.0)
    calibrated_confidence: float = Field(ge=0.0, le=1.0)
    human_gate_required: bool
    eligible_to_tighten: bool
    reason_codes: List[str] = Field(default_factory=list, max_length=16)

    @model_validator(mode="after")
    def coherent_verdict_validation(self) -> "ModelVerdictValidation":
        if self.status != "valid" and self.eligible_to_tighten:
            raise ValueError("non-valid model verdict cannot tighten a judgment")
        if self.status != "valid" and not self.human_gate_required:
            raise ValueError("non-valid model verdict requires a human gate")
        return self


class Judgment(StrictModel):
    alert_id: str
    action: DecisionAction
    reason_codes: List[str]
    deterministic_action: DecisionAction
    model_verdict: Optional[ModelVerdict] = None
    ai_mode: AiMode = AiMode.OFF
    model_status: str = "not_requested"
    model_validation: Optional[ModelVerdictValidation] = None
    combiner_result: str
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
    effect_status: EffectStatus
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
    ledger_verified: bool
    enrichment: EnrichmentSnapshot
    triage: TriageAssessment
    judgment: Judgment
    escalation: EscalationRecord
    response: ResponseRecord
    finding: "Finding"
    timeline: List[TimelineEntry]
    analyst_run: Optional[AiAnalystRun] = None


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
