"""Versioned detection-as-code runtime for normalized AI-agent effect metadata."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import re
import sqlite3
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Set, Tuple, Union

from pydantic import Field, field_validator, model_validator

from .contracts import (
    AgentEvent,
    DecisionAction,
    DetectorMatch,
    SecurityAlert,
    Severity,
    StrictModel,
    TrustClass,
    new_id,
    utc_now,
)


DETECTION_READ = "detection:read"
DETECTION_RUN = "detection:run"
DETECTION_ADMIN = "detection:admin"
MAX_DETECTION_EVENTS = 10000
MAX_RULE_WINDOW_SECONDS = 7 * 24 * 60 * 60


class DetectionAuthorizationError(PermissionError):
    """Raised when a detection principal lacks the requested permission."""


class DetectionEvaluationError(RuntimeError):
    """A bounded rule evaluation failed without stopping other rules."""


class SemanticDetectionUnavailable(DetectionEvaluationError):
    """The configured semantic detector could not produce a usable verdict."""


class DetectionRuleKind(str, Enum):
    EVENT = "event"
    SEQUENCE = "sequence"
    THRESHOLD = "threshold"
    CORRELATION = "correlation"
    SEMANTIC = "semantic"


class DetectionExecutionMode(str, Enum):
    STREAMING = "streaming"
    SCHEDULED = "scheduled"
    BOTH = "both"


class DetectionOperator(str, Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    EQUALS_FIELD = "equals_field"
    NOT_EQUALS_FIELD = "not_equals_field"
    CONTAINS_FIELD = "contains_field"
    NOT_CONTAINS_FIELD = "not_contains_field"


class DetectionEventField(str, Enum):
    EVENT_ID = "event_id"
    FLOW_ID = "flow_id"
    AGENT_ID = "agent_id"
    OPERATION = "operation"
    RESOURCE = "resource"
    DESTINATION = "destination"
    SOURCE_TYPE = "source_type"
    SOURCE_ID = "source_id"
    SOURCE_TRUST = "source_trust"
    DATA_CLASSES = "data_classes"
    AUTHORITY_OPERATIONS = "authority_operations"
    INDICATORS = "indicators"
    APPROVAL_PRESENT = "approval_present"
    IS_EFFECTFUL = "is_effectful"
    TOOL_NAME = "tool_name"
    DECLARED_TOOL_SCHEMA_DIGEST = "declared_tool_schema_digest"
    OBSERVED_TOOL_SCHEMA_DIGEST = "observed_tool_schema_digest"


class DetectionExecutionStatus(str, Enum):
    MATCHED = "matched"
    NO_MATCH = "no_match"
    ERROR = "error"


ConditionValue = Union[str, bool, int, float, List[str]]


class DetectionPrincipal(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=1, max_length=256)
    permissions: Set[str] = Field(default_factory=set, max_length=16)

    @field_validator("permissions")
    @classmethod
    def valid_permissions(cls, value: Set[str]) -> Set[str]:
        if any(re.fullmatch(r"[a-z]+:[a-z]+", item) is None for item in value):
            raise ValueError("detection permissions must use namespace:operation")
        return value


class DetectionCondition(StrictModel):
    field: DetectionEventField
    operator: DetectionOperator
    value: Optional[ConditionValue] = None
    compare_field: Optional[DetectionEventField] = None

    @model_validator(mode="after")
    def coherent_operand(self) -> "DetectionCondition":
        field_operators = {
            DetectionOperator.EQUALS_FIELD,
            DetectionOperator.NOT_EQUALS_FIELD,
            DetectionOperator.CONTAINS_FIELD,
            DetectionOperator.NOT_CONTAINS_FIELD,
        }
        no_operand = {DetectionOperator.EXISTS, DetectionOperator.NOT_EXISTS}
        if self.operator in field_operators:
            if self.compare_field is None or self.value is not None:
                raise ValueError("field comparison requires only compare_field")
        elif self.operator in no_operand:
            if self.value is not None or self.compare_field is not None:
                raise ValueError("existence comparison accepts no operand")
        elif self.value is None or self.compare_field is not None:
            raise ValueError("detection comparison requires only value")
        if self.operator in {DetectionOperator.IN, DetectionOperator.NOT_IN} and not isinstance(self.value, list):
            raise ValueError("membership comparison requires a list")
        if isinstance(self.value, list) and (
            len(self.value) > 128
            or any(not isinstance(item, str) or not 1 <= len(item) <= 512 for item in self.value)
        ):
            raise ValueError("detection condition list is invalid")
        if isinstance(self.value, str) and not 1 <= len(self.value) <= 512:
            raise ValueError("detection condition value is invalid")
        return self


class DetectionPredicate(StrictModel):
    all_conditions: List[DetectionCondition] = Field(default_factory=list, max_length=32)
    any_conditions: List[DetectionCondition] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def has_conditions(self) -> "DetectionPredicate":
        if not self.all_conditions and not self.any_conditions:
            raise ValueError("detection predicate must contain a condition")
        return self


class DetectionRuleDefinition(StrictModel):
    rule_id: str = Field(pattern=r"^DET-[A-Z0-9-]{3,80}$")
    version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    name: str = Field(min_length=3, max_length=256)
    description: str = Field(min_length=3, max_length=1024)
    kind: DetectionRuleKind
    execution_mode: DetectionExecutionMode
    alert_type: str = Field(pattern=r"^[a-z][a-z0-9_]{2,127}$")
    title: str = Field(min_length=3, max_length=512)
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    recommended_action: DecisionAction
    reason_codes: List[str] = Field(min_length=1, max_length=32)
    framework_mappings: List[str] = Field(min_length=1, max_length=32)
    tags: List[str] = Field(default_factory=list, max_length=32)
    evidence_fields: List[DetectionEventField] = Field(
        default_factory=lambda: [DetectionEventField.EVENT_ID], max_length=16
    )
    predicate: Optional[DetectionPredicate] = None
    sequence_steps: List[DetectionPredicate] = Field(default_factory=list, max_length=10)
    correlation_predicates: List[DetectionPredicate] = Field(default_factory=list, max_length=10)
    threshold: Optional[int] = Field(default=None, ge=2, le=10000)
    window_seconds: Optional[int] = Field(
        default=None, ge=1, le=MAX_RULE_WINDOW_SECONDS
    )
    group_by: DetectionEventField = DetectionEventField.FLOW_ID
    semantic_profile: Optional[str] = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$"
    )
    semantic_min_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    enabled: bool = True

    @field_validator("reason_codes")
    @classmethod
    def valid_reason_codes(cls, value: List[str]) -> List[str]:
        if len(set(value)) != len(value) or any(
            re.fullmatch(r"[A-Z][A-Z0-9_]{2,127}", item) is None for item in value
        ):
            raise ValueError("detection reason codes are invalid")
        return value

    @field_validator("framework_mappings", "tags")
    @classmethod
    def bounded_metadata(cls, value: List[str]) -> List[str]:
        if len(set(value)) != len(value) or any(
            not 1 <= len(item) <= 128 or any(ord(character) < 32 for character in item)
            for item in value
        ):
            raise ValueError("detection rule metadata is invalid")
        return value

    @field_validator("evidence_fields")
    @classmethod
    def unique_evidence_fields(
        cls, value: List[DetectionEventField]
    ) -> List[DetectionEventField]:
        if len(set(value)) != len(value):
            raise ValueError("detection evidence fields must be unique")
        return value

    @model_validator(mode="after")
    def coherent_rule_shape(self) -> "DetectionRuleDefinition":
        grouped = {
            DetectionEventField.FLOW_ID,
            DetectionEventField.AGENT_ID,
            DetectionEventField.SOURCE_ID,
            DetectionEventField.TOOL_NAME,
        }
        if self.group_by not in grouped:
            raise ValueError("detection group_by field is invalid")
        if self.kind == DetectionRuleKind.EVENT:
            valid = self.predicate is not None and not any(
                [self.sequence_steps, self.correlation_predicates, self.threshold,
                 self.window_seconds, self.semantic_profile, self.semantic_min_confidence]
            )
        elif self.kind == DetectionRuleKind.SEQUENCE:
            valid = (
                self.predicate is None
                and 2 <= len(self.sequence_steps) <= 10
                and not self.correlation_predicates
                and self.threshold is None
                and self.window_seconds is not None
                and self.semantic_profile is None
                and self.semantic_min_confidence is None
            )
        elif self.kind == DetectionRuleKind.THRESHOLD:
            valid = (
                self.predicate is not None
                and not self.sequence_steps
                and not self.correlation_predicates
                and self.threshold is not None
                and self.window_seconds is not None
                and self.semantic_profile is None
                and self.semantic_min_confidence is None
            )
        elif self.kind == DetectionRuleKind.CORRELATION:
            valid = (
                self.predicate is None
                and not self.sequence_steps
                and 2 <= len(self.correlation_predicates) <= 10
                and self.threshold is None
                and self.window_seconds is not None
                and self.semantic_profile is None
                and self.semantic_min_confidence is None
            )
        else:
            valid = (
                not self.sequence_steps
                and not self.correlation_predicates
                and self.threshold is None
                and self.window_seconds is None
                and self.semantic_profile is not None
                and self.semantic_min_confidence is not None
            )
        if not valid:
            raise ValueError("detection rule fields do not match its kind")
        return self


class DetectionRuleRecord(StrictModel):
    tenant_id: str
    definition: DetectionRuleDefinition
    definition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    superseded_at: Optional[datetime] = None


class SemanticDetectionVerdict(StrictModel):
    provider: str = Field(min_length=1, max_length=64)
    model_id: str = Field(min_length=1, max_length=256)
    matched: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: List[str] = Field(default_factory=list, max_length=16)
    evidence_refs: List[str] = Field(default_factory=list, max_length=16)

    @field_validator("reason_codes")
    @classmethod
    def semantic_reason_codes(cls, value: List[str]) -> List[str]:
        if any(re.fullmatch(r"[A-Z][A-Z0-9_]{2,127}", item) is None for item in value):
            raise ValueError("semantic reason code is invalid")
        return value


class SemanticDetectionProvider(Protocol):
    def analyze(
        self, rule: DetectionRuleDefinition, event: AgentEvent
    ) -> SemanticDetectionVerdict:
        ...


class DetectionExecutionRecord(StrictModel):
    execution_id: str = Field(pattern=r"^dexe_[A-Za-z0-9]+$")
    tenant_id: str
    rule_id: str
    rule_version: str
    mode: DetectionExecutionMode
    status: DetectionExecutionStatus
    evaluated_event_count: int = Field(ge=0, le=MAX_DETECTION_EVENTS)
    matched_event_ids: List[str] = Field(default_factory=list, max_length=256)
    alert_ids: List[str] = Field(default_factory=list, max_length=256)
    error_code: Optional[str] = Field(default=None, max_length=128)
    duration_ms: int = Field(ge=0)
    started_at: datetime
    completed_at: datetime


class DetectionBatchResult(StrictModel):
    tenant_id: str
    mode: DetectionExecutionMode
    alerts: List[SecurityAlert] = Field(default_factory=list, max_length=10000)
    executions: List[DetectionExecutionRecord] = Field(default_factory=list, max_length=512)
    evaluated_event_count: int = Field(ge=0, le=MAX_DETECTION_EVENTS)
    errors: List[str] = Field(default_factory=list, max_length=512)
    started_at: datetime
    completed_at: datetime


class DetectionRuleHealth(StrictModel):
    tenant_id: str
    rule_id: str
    rule_version: str
    evaluation_count: int = Field(ge=0)
    match_count: int = Field(ge=0)
    error_count: int = Field(ge=0)
    last_evaluated_at: Optional[datetime]
    last_error_code: Optional[str]


class DetectionRule(Protocol):
    """Compatibility protocol retained for existing Python detector plug-ins."""

    detector_id: str

    def evaluate(self, event: AgentEvent) -> Iterable[DetectorMatch]:
        ...


class IndirectPromptInjectionRule:
    detector_id = "DET-INDIRECT-INJECTION-001"

    def evaluate(self, event: AgentEvent) -> Iterable[DetectorMatch]:
        untrusted = event.source_trust in {
            TrustClass.EXTERNAL_UNTRUSTED,
            TrustClass.SUSPECTED_ADVERSARIAL,
        }
        if untrusted and "indirect_prompt_injection" in event.indicators:
            yield DetectorMatch(
                detector_id=self.detector_id,
                alert_type="indirect_prompt_injection",
                title="Untrusted content influenced an effectful agent action",
                severity=Severity.HIGH,
                confidence=0.94,
                reason_codes=["UNTRUSTED_INSTRUCTION", "SOURCE_TO_EFFECT_PATH"],
                evidence=[event.source_id, event.event_id],
                framework_mappings=["OWASP-LLM01", "MITRE-ATLAS-AML.T0051"],
                recommended_action=DecisionAction.DENY,
            )


class SecretEgressRule:
    detector_id = "DET-SECRET-EGRESS-001"

    def evaluate(self, event: AgentEvent) -> Iterable[DetectorMatch]:
        is_external_send = event.operation in {"external.send", "external.upload"}
        if is_external_send and "secret" in event.data_classes:
            yield DetectorMatch(
                detector_id=self.detector_id,
                alert_type="secret_egress",
                title="Secret data proposed for external egress",
                severity=Severity.CRITICAL,
                confidence=0.99,
                reason_codes=["SECRET_AT_EXTERNAL_SINK", "EGRESS_POLICY_VIOLATION"],
                evidence=[event.source_id, event.event_id],
                framework_mappings=["OWASP-LLM02", "MITRE-ATLAS-AML.T0057"],
                recommended_action=DecisionAction.DENY,
            )


class AuthorityViolationRule:
    detector_id = "DET-AUTHORITY-001"

    def evaluate(self, event: AgentEvent) -> Iterable[DetectorMatch]:
        if event.is_effectful and event.operation not in event.authority_operations:
            yield DetectorMatch(
                detector_id=self.detector_id,
                alert_type="authority_violation",
                title="Agent requested an operation outside delegated authority",
                severity=Severity.HIGH,
                confidence=1.0,
                reason_codes=["OPERATION_OUTSIDE_EFFECTIVE_GRANT"],
                evidence=[event.event_id, "authority:%s" % sorted(event.authority_operations)],
                framework_mappings=["OWASP-LLM08", "MITRE-ATLAS-AML.T0051"],
                recommended_action=DecisionAction.DENY,
            )


class MemoryPoisoningRule:
    detector_id = "DET-MEMORY-POISONING-001"

    def evaluate(self, event: AgentEvent) -> Iterable[DetectorMatch]:
        if (
            "memory_poisoning" in event.indicators
            and event.source_type == "memory"
            and event.is_effectful
        ):
            yield DetectorMatch(
                detector_id=self.detector_id,
                alert_type="persistent_memory_poisoning",
                title="Persisted untrusted memory influenced a later effect",
                severity=Severity.HIGH,
                confidence=0.96,
                reason_codes=["UNTRUSTED_MEMORY_REUSE", "CROSS_SESSION_INFLUENCE"],
                evidence=[event.source_id, event.event_id],
                framework_mappings=["OWASP-LLM04", "MITRE-ATLAS-AML.T0080"],
                recommended_action=DecisionAction.DENY,
            )


class McpDriftRule:
    detector_id = "DET-MCP-DRIFT-001"

    def evaluate(self, event: AgentEvent) -> Iterable[DetectorMatch]:
        declared = event.declared_tool_schema_digest
        observed = event.observed_tool_schema_digest
        if declared and observed and declared != observed:
            yield DetectorMatch(
                detector_id=self.detector_id,
                alert_type="mcp_schema_drift",
                title="Observed MCP tool schema differs from approved manifest",
                severity=Severity.HIGH,
                confidence=1.0,
                reason_codes=["TOOL_SCHEMA_DIGEST_MISMATCH", "ABOM_DRIFT"],
                evidence=[event.event_id, "declared:%s" % declared, "observed:%s" % observed],
                framework_mappings=["OWASP-LLM03", "MITRE-ATLAS-AML.T0080"],
                recommended_action=DecisionAction.REQUIRE_APPROVAL,
            )


class DestructiveActionRule:
    detector_id = "DET-DESTRUCTIVE-APPROVAL-001"

    def evaluate(self, event: AgentEvent) -> Iterable[DetectorMatch]:
        destructive = event.operation in {"data.delete", "host.isolate", "identity.revoke"}
        if destructive and not event.approval_present:
            yield DetectorMatch(
                detector_id=self.detector_id,
                alert_type="destructive_action_without_approval",
                title="Destructive action lacks exact-action approval",
                severity=Severity.HIGH,
                confidence=1.0,
                reason_codes=["MISSING_REQUIRED_APPROVAL"],
                evidence=[event.event_id],
                framework_mappings=["OWASP-LLM06", "NIST-AI-RMF-MANAGE"],
                recommended_action=DecisionAction.REQUIRE_APPROVAL,
            )


DEFAULT_RULES: List[DetectionRule] = [
    IndirectPromptInjectionRule(),
    SecretEgressRule(),
    AuthorityViolationRule(),
    MemoryPoisoningRule(),
    McpDriftRule(),
    DestructiveActionRule(),
]


def _condition(
    field: DetectionEventField,
    operator: DetectionOperator,
    value: Optional[ConditionValue] = None,
    compare_field: Optional[DetectionEventField] = None,
) -> DetectionCondition:
    return DetectionCondition(
        field=field, operator=operator, value=value, compare_field=compare_field
    )


def _predicate(
    *conditions: DetectionCondition,
    any_conditions: Sequence[DetectionCondition] = (),
) -> DetectionPredicate:
    return DetectionPredicate(
        all_conditions=list(conditions), any_conditions=list(any_conditions)
    )


def _base_definition(**updates: Any) -> DetectionRuleDefinition:
    payload: Dict[str, Any] = {
        "version": "1.0.0",
        "description": "Versioned deterministic AI-security detection content.",
        "kind": DetectionRuleKind.EVENT,
        "execution_mode": DetectionExecutionMode.BOTH,
        "severity": Severity.HIGH,
        "confidence": 1.0,
        "recommended_action": DecisionAction.DENY,
        "reason_codes": ["DETECTION_MATCH"],
        "framework_mappings": ["NIST-AI-RMF-MEASURE"],
        "evidence_fields": [DetectionEventField.EVENT_ID],
    }
    payload.update(updates)
    return DetectionRuleDefinition(**payload)


DEFAULT_RULE_DEFINITIONS: Tuple[DetectionRuleDefinition, ...] = (
    _base_definition(
        rule_id="DET-INDIRECT-INJECTION-001",
        name="Indirect prompt injection into an effect",
        alert_type="indirect_prompt_injection",
        title="Untrusted content influenced an effectful agent action",
        confidence=0.94,
        reason_codes=["UNTRUSTED_INSTRUCTION", "SOURCE_TO_EFFECT_PATH"],
        framework_mappings=["OWASP-LLM01", "MITRE-ATLAS-AML.T0051"],
        evidence_fields=[DetectionEventField.SOURCE_ID, DetectionEventField.EVENT_ID],
        predicate=_predicate(
            _condition(DetectionEventField.INDICATORS, DetectionOperator.CONTAINS, "indirect_prompt_injection"),
            any_conditions=[
                _condition(DetectionEventField.SOURCE_TRUST, DetectionOperator.EQUALS, TrustClass.EXTERNAL_UNTRUSTED.value),
                _condition(DetectionEventField.SOURCE_TRUST, DetectionOperator.EQUALS, TrustClass.SUSPECTED_ADVERSARIAL.value),
            ],
        ),
    ),
    _base_definition(
        rule_id="DET-SECRET-EGRESS-001",
        name="Secret data at an external sink",
        alert_type="secret_egress",
        title="Secret data proposed for external egress",
        severity=Severity.CRITICAL,
        confidence=0.99,
        reason_codes=["SECRET_AT_EXTERNAL_SINK", "EGRESS_POLICY_VIOLATION"],
        framework_mappings=["OWASP-LLM02", "MITRE-ATLAS-AML.T0057"],
        evidence_fields=[DetectionEventField.SOURCE_ID, DetectionEventField.EVENT_ID],
        predicate=_predicate(
            _condition(DetectionEventField.OPERATION, DetectionOperator.IN, ["external.send", "external.upload"]),
            _condition(DetectionEventField.DATA_CLASSES, DetectionOperator.CONTAINS, "secret"),
        ),
    ),
    _base_definition(
        rule_id="DET-AUTHORITY-001",
        name="Operation outside delegated authority",
        alert_type="authority_violation",
        title="Agent requested an operation outside delegated authority",
        reason_codes=["OPERATION_OUTSIDE_EFFECTIVE_GRANT"],
        framework_mappings=["OWASP-LLM08", "MITRE-ATLAS-AML.T0051"],
        predicate=_predicate(
            _condition(DetectionEventField.IS_EFFECTFUL, DetectionOperator.EQUALS, True),
            _condition(
                DetectionEventField.AUTHORITY_OPERATIONS,
                DetectionOperator.NOT_CONTAINS_FIELD,
                compare_field=DetectionEventField.OPERATION,
            ),
        ),
    ),
    _base_definition(
        rule_id="DET-MEMORY-POISONING-001",
        name="Persistent untrusted memory influence",
        alert_type="persistent_memory_poisoning",
        title="Persisted untrusted memory influenced a later effect",
        confidence=0.96,
        reason_codes=["UNTRUSTED_MEMORY_REUSE", "CROSS_SESSION_INFLUENCE"],
        framework_mappings=["OWASP-LLM04", "MITRE-ATLAS-AML.T0080"],
        evidence_fields=[DetectionEventField.SOURCE_ID, DetectionEventField.EVENT_ID],
        predicate=_predicate(
            _condition(DetectionEventField.INDICATORS, DetectionOperator.CONTAINS, "memory_poisoning"),
            _condition(DetectionEventField.SOURCE_TYPE, DetectionOperator.EQUALS, "memory"),
            _condition(DetectionEventField.IS_EFFECTFUL, DetectionOperator.EQUALS, True),
        ),
    ),
    _base_definition(
        rule_id="DET-MCP-DRIFT-001",
        name="MCP tool contract drift",
        alert_type="mcp_schema_drift",
        title="Observed MCP tool schema differs from approved manifest",
        recommended_action=DecisionAction.REQUIRE_APPROVAL,
        reason_codes=["TOOL_SCHEMA_DIGEST_MISMATCH", "ABOM_DRIFT"],
        framework_mappings=["OWASP-LLM03", "MITRE-ATLAS-AML.T0080"],
        evidence_fields=[
            DetectionEventField.EVENT_ID,
            DetectionEventField.DECLARED_TOOL_SCHEMA_DIGEST,
            DetectionEventField.OBSERVED_TOOL_SCHEMA_DIGEST,
        ],
        predicate=_predicate(
            _condition(DetectionEventField.DECLARED_TOOL_SCHEMA_DIGEST, DetectionOperator.EXISTS),
            _condition(DetectionEventField.OBSERVED_TOOL_SCHEMA_DIGEST, DetectionOperator.EXISTS),
            _condition(
                DetectionEventField.DECLARED_TOOL_SCHEMA_DIGEST,
                DetectionOperator.NOT_EQUALS_FIELD,
                compare_field=DetectionEventField.OBSERVED_TOOL_SCHEMA_DIGEST,
            ),
        ),
    ),
    _base_definition(
        rule_id="DET-DESTRUCTIVE-APPROVAL-001",
        name="Destructive operation without approval",
        alert_type="destructive_action_without_approval",
        title="Destructive action lacks exact-action approval",
        recommended_action=DecisionAction.REQUIRE_APPROVAL,
        reason_codes=["MISSING_REQUIRED_APPROVAL"],
        framework_mappings=["OWASP-LLM06", "NIST-AI-RMF-MANAGE"],
        predicate=_predicate(
            _condition(DetectionEventField.OPERATION, DetectionOperator.IN, ["data.delete", "host.isolate", "identity.revoke"]),
            _condition(DetectionEventField.APPROVAL_PRESENT, DetectionOperator.EQUALS, False),
        ),
    ),
    _base_definition(
        rule_id="DET-SEQUENCE-INJECTION-EGRESS-001",
        name="Prompt injection followed by external egress",
        description="Correlates untrusted injection influence with a later external send in one flow.",
        kind=DetectionRuleKind.SEQUENCE,
        alert_type="prompt_injection_egress_sequence",
        title="Untrusted instruction was followed by external egress",
        severity=Severity.CRITICAL,
        confidence=0.98,
        reason_codes=["INJECTION_TO_EGRESS_SEQUENCE"],
        framework_mappings=["OWASP-LLM01", "OWASP-LLM02", "MITRE-ATLAS-AML.T0051"],
        window_seconds=300,
        sequence_steps=[
            _predicate(_condition(DetectionEventField.INDICATORS, DetectionOperator.CONTAINS, "indirect_prompt_injection")),
            _predicate(_condition(DetectionEventField.OPERATION, DetectionOperator.IN, ["external.send", "external.upload"])),
        ],
    ),
    _base_definition(
        rule_id="DET-THRESHOLD-EGRESS-001",
        name="Burst of external agent egress",
        description="Detects repeated external send or upload attempts by one agent.",
        kind=DetectionRuleKind.THRESHOLD,
        alert_type="external_egress_burst",
        title="Agent produced a burst of external egress attempts",
        confidence=0.9,
        reason_codes=["EXTERNAL_EGRESS_THRESHOLD"],
        framework_mappings=["OWASP-LLM02", "NIST-AI-RMF-MEASURE"],
        predicate=_predicate(_condition(DetectionEventField.OPERATION, DetectionOperator.IN, ["external.send", "external.upload"])),
        threshold=3,
        window_seconds=300,
        group_by=DetectionEventField.FLOW_ID,
    ),
    _base_definition(
        rule_id="DET-CORRELATE-MEMORY-EGRESS-001",
        name="Memory poisoning correlated with egress",
        description="Correlates distinct memory-poisoning and external-egress events in one flow.",
        kind=DetectionRuleKind.CORRELATION,
        alert_type="memory_poisoning_egress_correlation",
        title="Memory poisoning correlated with external egress",
        severity=Severity.CRITICAL,
        confidence=0.97,
        reason_codes=["MEMORY_EGRESS_CORRELATION"],
        framework_mappings=["OWASP-LLM04", "OWASP-LLM02", "MITRE-ATLAS-AML.T0080"],
        window_seconds=900,
        correlation_predicates=[
            _predicate(_condition(DetectionEventField.INDICATORS, DetectionOperator.CONTAINS, "memory_poisoning")),
            _predicate(_condition(DetectionEventField.OPERATION, DetectionOperator.IN, ["external.send", "external.upload"])),
        ],
    ),
    _base_definition(
        rule_id="DET-SEMANTIC-SOCIAL-ENGINEERING-001",
        name="Semantic social-engineering review",
        description="Disabled reference rule for provider-governed semantic classification.",
        kind=DetectionRuleKind.SEMANTIC,
        execution_mode=DetectionExecutionMode.STREAMING,
        alert_type="semantic_social_engineering",
        title="Semantic review identified social-engineering intent",
        confidence=0.8,
        reason_codes=["SEMANTIC_SOCIAL_ENGINEERING"],
        framework_mappings=["OWASP-LLM01", "NIST-AI-RMF-MEASURE"],
        predicate=_predicate(_condition(DetectionEventField.SOURCE_TRUST, DetectionOperator.IN, [
            TrustClass.EXTERNAL_UNTRUSTED.value, TrustClass.SUSPECTED_ADVERSARIAL.value
        ])),
        semantic_profile="semantic-social-engineering-v1",
        semantic_min_confidence=0.8,
        enabled=False,
    ),
)


def _normalize(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, set):
        return {_normalize(item) for item in value}
    return value


def _event_value(event: AgentEvent, field: DetectionEventField) -> Any:
    return _normalize(getattr(event, field.value))


def _condition_matches(condition: DetectionCondition, event: AgentEvent) -> bool:
    actual = _event_value(event, condition.field)
    operator = condition.operator
    if operator == DetectionOperator.EXISTS:
        return actual is not None and actual != "" and actual != set()
    if operator == DetectionOperator.NOT_EXISTS:
        return actual is None or actual == "" or actual == set()
    if operator in {
        DetectionOperator.EQUALS_FIELD,
        DetectionOperator.NOT_EQUALS_FIELD,
        DetectionOperator.CONTAINS_FIELD,
        DetectionOperator.NOT_CONTAINS_FIELD,
    }:
        expected = _event_value(event, condition.compare_field)  # type: ignore[arg-type]
        if operator in {DetectionOperator.EQUALS_FIELD, DetectionOperator.NOT_EQUALS_FIELD}:
            result = actual == expected
            return result if operator == DetectionOperator.EQUALS_FIELD else not result
        result = actual is not None and expected in actual
        return result if operator == DetectionOperator.CONTAINS_FIELD else not result
    expected = condition.value
    if operator == DetectionOperator.EQUALS:
        return actual == expected
    if operator == DetectionOperator.NOT_EQUALS:
        return actual != expected
    if operator == DetectionOperator.IN:
        return actual in (expected or [])
    if operator == DetectionOperator.NOT_IN:
        return actual not in (expected or [])
    if operator == DetectionOperator.CONTAINS:
        return actual is not None and expected in actual
    if operator == DetectionOperator.NOT_CONTAINS:
        return actual is None or expected not in actual
    raise DetectionEvaluationError("UNSUPPORTED_DETECTION_OPERATOR")


def _predicate_matches(predicate: DetectionPredicate, event: AgentEvent) -> bool:
    return all(_condition_matches(item, event) for item in predicate.all_conditions) and (
        not predicate.any_conditions
        or any(_condition_matches(item, event) for item in predicate.any_conditions)
    )


def _definition_digest(definition: DetectionRuleDefinition) -> str:
    encoded = json.dumps(
        definition.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _version_key(value: str) -> Tuple[Tuple[int, Any], ...]:
    return tuple(
        (0, int(token)) if token.isdigit() else (1, token.casefold())
        for token in re.findall(r"[0-9]+|[A-Za-z]+", value)
    )


def _group_key(event: AgentEvent, field: DetectionEventField) -> str:
    value = _event_value(event, field)
    return "<none>" if value is None else str(value)


@dataclass(frozen=True)
class _RuleHit:
    anchor: AgentEvent
    events: Tuple[AgentEvent, ...]
    semantic: Optional[SemanticDetectionVerdict] = None


def _sequence_hit(
    events: Sequence[AgentEvent],
    steps: Sequence[DetectionPredicate],
    required_anchor_id: Optional[str] = None,
) -> Optional[_RuleHit]:
    paths: List[Optional[Tuple[AgentEvent, ...]]] = [None] * len(steps)
    for event in sorted(events, key=lambda item: (item.occurred_at, item.event_id)):
        for index in range(len(steps) - 1, -1, -1):
            if not _predicate_matches(steps[index], event):
                continue
            if index == 0:
                paths[0] = (event,)
            elif paths[index - 1] is not None:
                paths[index] = paths[index - 1] + (event,)
    completed = paths[-1]
    if completed is None or (
        required_anchor_id is not None and completed[-1].event_id != required_anchor_id
    ):
        return None
    return _RuleHit(anchor=completed[-1], events=completed)


def _correlation_hit(
    events: Sequence[AgentEvent],
    predicates: Sequence[DetectionPredicate],
    required_anchor_id: Optional[str] = None,
) -> Optional[_RuleHit]:
    ordered = sorted(events, key=lambda item: (item.occurred_at, item.event_id))

    def assign(index: int, used: Set[str], selected: List[AgentEvent]) -> Optional[List[AgentEvent]]:
        if index == len(predicates):
            return selected
        for event in reversed(ordered):
            if event.event_id in used or not _predicate_matches(predicates[index], event):
                continue
            result = assign(index + 1, used | {event.event_id}, selected + [event])
            if result is not None:
                return result
        return None

    selected = assign(0, set(), [])
    if selected is None:
        return None
    anchor = max(selected, key=lambda item: (item.occurred_at, item.event_id))
    if required_anchor_id is not None and anchor.event_id != required_anchor_id:
        return None
    return _RuleHit(anchor=anchor, events=tuple(sorted(selected, key=lambda item: (item.occurred_at, item.event_id))))


class DetectionService:
    """Durable tenant-authorized rule registry and streaming/scheduled runtime."""

    def __init__(
        self,
        path: str,
        *,
        semantic_provider: Optional[SemanticDetectionProvider] = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.path = path
        self.semantic_provider = semantic_provider
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

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("detection clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _require(principal: DetectionPrincipal, permission: str) -> None:
        if permission not in principal.permissions:
            raise DetectionAuthorizationError("missing detection permission: %s" % permission)

    def _migrate(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS detection_rules (
                tenant_id TEXT NOT NULL, rule_id TEXT NOT NULL, version TEXT NOT NULL,
                definition_json TEXT NOT NULL, definition_sha256 TEXT NOT NULL,
                enabled INTEGER NOT NULL, created_at TEXT NOT NULL, superseded_at TEXT,
                PRIMARY KEY (tenant_id, rule_id, version)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS detection_current_rule
                ON detection_rules(tenant_id, rule_id) WHERE superseded_at IS NULL;
            CREATE TABLE IF NOT EXISTS detection_events (
                tenant_id TEXT NOT NULL, event_id TEXT NOT NULL, occurred_at TEXT NOT NULL,
                event_json TEXT NOT NULL, event_sha256 TEXT NOT NULL, recorded_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, event_id)
            );
            CREATE INDEX IF NOT EXISTS detection_event_window
                ON detection_events(tenant_id, occurred_at, event_id);
            CREATE TABLE IF NOT EXISTS detection_executions (
                tenant_id TEXT NOT NULL, execution_id TEXT NOT NULL, rule_id TEXT NOT NULL,
                rule_version TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL,
                evaluated_event_count INTEGER NOT NULL, matched_event_ids_json TEXT NOT NULL,
                alert_ids_json TEXT NOT NULL, error_code TEXT, duration_ms INTEGER NOT NULL,
                started_at TEXT NOT NULL, completed_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, execution_id)
            );
            CREATE INDEX IF NOT EXISTS detection_execution_health
                ON detection_executions(tenant_id, rule_id, rule_version, completed_at);
            CREATE TABLE IF NOT EXISTS detection_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL,
                actor_id TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL,
                occurred_at TEXT NOT NULL
            );
            """
        )

    def _audit(self, principal: DetectionPrincipal, action: str, subject: str) -> None:
        self._connection.execute(
            "INSERT INTO detection_audit(tenant_id, actor_id, action, subject, occurred_at) VALUES (?, ?, ?, ?, ?)",
            (principal.tenant_id, principal.actor_id, action, subject[:512], self._now().isoformat()),
        )

    @staticmethod
    def _rule_row(row: sqlite3.Row) -> DetectionRuleRecord:
        return DetectionRuleRecord(
            tenant_id=row["tenant_id"],
            definition=DetectionRuleDefinition.model_validate_json(row["definition_json"]),
            definition_sha256=row["definition_sha256"],
            created_at=row["created_at"],
            superseded_at=row["superseded_at"],
        )

    def register_rule(
        self, principal: DetectionPrincipal, definition: DetectionRuleDefinition
    ) -> DetectionRuleRecord:
        self._require(principal, DETECTION_ADMIN)
        digest = _definition_digest(definition)
        now = self._now().isoformat()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                same = self._connection.execute(
                    "SELECT * FROM detection_rules WHERE tenant_id = ? AND rule_id = ? AND version = ?",
                    (principal.tenant_id, definition.rule_id, definition.version),
                ).fetchone()
                if same is not None:
                    if same["definition_sha256"] != digest:
                        raise ValueError("detection rule version is immutable")
                    self._connection.execute("COMMIT")
                    return self._rule_row(same)
                current = self._connection.execute(
                    "SELECT * FROM detection_rules WHERE tenant_id = ? AND rule_id = ? AND superseded_at IS NULL",
                    (principal.tenant_id, definition.rule_id),
                ).fetchone()
                if current is not None and _version_key(definition.version) <= _version_key(current["version"]):
                    raise ValueError("detection rule version must increase")
                if current is not None:
                    self._connection.execute(
                        "UPDATE detection_rules SET superseded_at = ? WHERE tenant_id = ? AND rule_id = ? AND superseded_at IS NULL",
                        (now, principal.tenant_id, definition.rule_id),
                    )
                self._connection.execute(
                    "INSERT INTO detection_rules(tenant_id, rule_id, version, definition_json, definition_sha256, enabled, created_at, superseded_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
                    (
                        principal.tenant_id, definition.rule_id, definition.version,
                        definition.model_dump_json(), digest, int(definition.enabled), now,
                    ),
                )
                self._audit(principal, "detection.rule.register", "%s:%s" % (definition.rule_id, definition.version))
                row = self._connection.execute(
                    "SELECT * FROM detection_rules WHERE tenant_id = ? AND rule_id = ? AND version = ?",
                    (principal.tenant_id, definition.rule_id, definition.version),
                ).fetchone()
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return self._rule_row(row)

    def install_defaults(self, principal: DetectionPrincipal) -> List[DetectionRuleRecord]:
        return [self.register_rule(principal, item) for item in DEFAULT_RULE_DEFINITIONS]

    def list_rules(
        self, principal: DetectionPrincipal, *, history: bool = False
    ) -> List[DetectionRuleRecord]:
        self._require(principal, DETECTION_READ)
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM detection_rules WHERE tenant_id = ? "
                + ("" if history else "AND superseded_at IS NULL ")
                + "ORDER BY rule_id, created_at DESC",
                (principal.tenant_id,),
            ).fetchall()
            self._audit(principal, "detection.rule.list", "history" if history else "current")
        records = [self._rule_row(row) for row in rows]
        records.sort(key=lambda item: _version_key(item.definition.version), reverse=True)
        records.sort(key=lambda item: item.definition.rule_id)
        return records

    def _active_rules(
        self,
        principal: DetectionPrincipal,
        mode: DetectionExecutionMode,
        rule_ids: Optional[Sequence[str]] = None,
    ) -> List[DetectionRuleDefinition]:
        selected = set(rule_ids or [])
        if len(selected) > 256 or any(re.fullmatch(r"DET-[A-Z0-9-]{3,80}", item) is None for item in selected):
            raise ValueError("detection rule selection is invalid")
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM detection_rules WHERE tenant_id = ? AND superseded_at IS NULL AND enabled = 1 ORDER BY rule_id",
                (principal.tenant_id,),
            ).fetchall()
        definitions = [self._rule_row(row).definition for row in rows]
        definitions = [
            item for item in definitions
            if item.execution_mode in {mode, DetectionExecutionMode.BOTH}
        ]
        if selected:
            definitions = [item for item in definitions if item.rule_id in selected]
            if {item.rule_id for item in definitions} != selected:
                raise KeyError("unknown, disabled, or incompatible detection rule")
        return definitions

    @staticmethod
    def _safe_event_json(event: AgentEvent) -> str:
        payload = event.model_dump(mode="json", exclude={"attributes"})
        payload["attributes"] = {}
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def capture_event(
        self, principal: DetectionPrincipal, event: AgentEvent
    ) -> bool:
        self._require(principal, DETECTION_RUN)
        if event.tenant_id != principal.tenant_id:
            raise DetectionAuthorizationError("cross-tenant detection event is forbidden")
        encoded = self._safe_event_json(event)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        now = self._now().isoformat()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT event_sha256 FROM detection_events WHERE tenant_id = ? AND event_id = ?",
                    (principal.tenant_id, event.event_id),
                ).fetchone()
                if existing is not None and existing["event_sha256"] != digest:
                    raise ValueError("detection event ID conflicts with stored metadata")
                inserted = existing is None
                if inserted:
                    self._connection.execute(
                        "INSERT INTO detection_events(tenant_id, event_id, occurred_at, event_json, event_sha256, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (principal.tenant_id, event.event_id, event.occurred_at.astimezone(timezone.utc).isoformat(), encoded, digest, now),
                    )
                watermark_row = self._connection.execute(
                    "SELECT MAX(occurred_at) AS watermark FROM detection_events WHERE tenant_id = ?",
                    (principal.tenant_id,),
                ).fetchone()
                watermark = datetime.fromisoformat(watermark_row["watermark"])
                cutoff = (watermark - timedelta(seconds=MAX_RULE_WINDOW_SECONDS)).isoformat()
                self._connection.execute(
                    "DELETE FROM detection_events WHERE tenant_id = ? AND occurred_at < ?",
                    (principal.tenant_id, cutoff),
                )
                self._connection.execute(
                    "DELETE FROM detection_events WHERE tenant_id = ? AND event_id NOT IN "
                    "(SELECT event_id FROM detection_events WHERE tenant_id = ? "
                    "ORDER BY recorded_at DESC, event_id DESC LIMIT ?)",
                    (principal.tenant_id, principal.tenant_id, MAX_DETECTION_EVENTS),
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return inserted

    def _events(
        self,
        tenant_id: str,
        start: datetime,
        end: datetime,
        group_by: Optional[DetectionEventField] = None,
        group_key: Optional[str] = None,
    ) -> List[AgentEvent]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT event_json FROM detection_events WHERE tenant_id = ? AND occurred_at >= ? AND occurred_at <= ? ORDER BY occurred_at, event_id LIMIT ?",
                (tenant_id, start.isoformat(), end.isoformat(), MAX_DETECTION_EVENTS + 1),
            ).fetchall()
        if len(rows) > MAX_DETECTION_EVENTS:
            raise DetectionEvaluationError("DETECTION_WINDOW_LIMIT_EXCEEDED")
        events = [AgentEvent.model_validate_json(row["event_json"]) for row in rows]
        if group_by is not None and group_key is not None:
            events = [item for item in events if _group_key(item, group_by) == group_key]
        return events

    def _semantic_hit(
        self, rule: DetectionRuleDefinition, event: AgentEvent
    ) -> Optional[_RuleHit]:
        if rule.predicate is not None and not _predicate_matches(rule.predicate, event):
            return None
        if self.semantic_provider is None:
            raise SemanticDetectionUnavailable("SEMANTIC_PROVIDER_UNAVAILABLE")
        try:
            verdict = SemanticDetectionVerdict.model_validate(
                self.semantic_provider.analyze(rule, event)
            )
        except Exception as exc:
            raise SemanticDetectionUnavailable("SEMANTIC_PROVIDER_FAILURE") from exc
        allowed_evidence = {event.event_id, event.source_id, event.flow_id, event.agent_id}
        if any(item not in allowed_evidence for item in verdict.evidence_refs):
            raise DetectionEvaluationError("SEMANTIC_UNKNOWN_EVIDENCE")
        if not verdict.matched or verdict.confidence < (rule.semantic_min_confidence or 0.0):
            return None
        return _RuleHit(anchor=event, events=(event,), semantic=verdict)

    def _stream_hits(
        self, principal: DetectionPrincipal, rule: DetectionRuleDefinition, event: AgentEvent
    ) -> Tuple[List[_RuleHit], int]:
        if rule.kind == DetectionRuleKind.EVENT:
            return ([_RuleHit(event, (event,))] if _predicate_matches(rule.predicate, event) else [], 1)  # type: ignore[arg-type]
        if rule.kind == DetectionRuleKind.SEMANTIC:
            hit = self._semantic_hit(rule, event)
            return ([hit] if hit is not None else [], 1)
        start = event.occurred_at.astimezone(timezone.utc) - timedelta(seconds=rule.window_seconds or 1)
        events = self._events(
            principal.tenant_id, start, event.occurred_at.astimezone(timezone.utc),
            rule.group_by, _group_key(event, rule.group_by),
        )
        if rule.kind == DetectionRuleKind.SEQUENCE:
            hit = _sequence_hit(events, rule.sequence_steps, event.event_id)
        elif rule.kind == DetectionRuleKind.THRESHOLD:
            matching = [item for item in events if _predicate_matches(rule.predicate, item)]  # type: ignore[arg-type]
            hit = (
                _RuleHit(event, tuple(matching[-(rule.threshold or 2):]))
                if _predicate_matches(rule.predicate, event) and len(matching) >= (rule.threshold or 2)  # type: ignore[arg-type]
                else None
            )
        else:
            hit = _correlation_hit(events, rule.correlation_predicates, event.event_id)
        return ([hit] if hit is not None else [], len(events))

    def _scheduled_hits(
        self,
        principal: DetectionPrincipal,
        rule: DetectionRuleDefinition,
        as_of: datetime,
    ) -> Tuple[List[_RuleHit], int]:
        start = as_of - timedelta(seconds=rule.window_seconds or MAX_RULE_WINDOW_SECONDS)
        events = self._events(principal.tenant_id, start, as_of)
        if rule.kind in {DetectionRuleKind.EVENT, DetectionRuleKind.SEMANTIC}:
            hits: List[_RuleHit] = []
            for event in events:
                if rule.kind == DetectionRuleKind.EVENT and _predicate_matches(rule.predicate, event):  # type: ignore[arg-type]
                    hits.append(_RuleHit(event, (event,)))
                elif rule.kind == DetectionRuleKind.SEMANTIC:
                    hit = self._semantic_hit(rule, event)
                    if hit is not None:
                        hits.append(hit)
            return hits, len(events)
        groups: Dict[str, List[AgentEvent]] = {}
        for event in events:
            groups.setdefault(_group_key(event, rule.group_by), []).append(event)
        hits = []
        for group_events in groups.values():
            if rule.kind == DetectionRuleKind.SEQUENCE:
                hit = _sequence_hit(group_events, rule.sequence_steps)
            elif rule.kind == DetectionRuleKind.THRESHOLD:
                matching = [item for item in group_events if _predicate_matches(rule.predicate, item)]  # type: ignore[arg-type]
                hit = (
                    _RuleHit(matching[-1], tuple(matching[-(rule.threshold or 2):]))
                    if len(matching) >= (rule.threshold or 2)
                    else None
                )
            else:
                hit = _correlation_hit(group_events, rule.correlation_predicates)
            if hit is not None:
                hits.append(hit)
        return hits, len(events)

    @staticmethod
    def _alert(rule: DetectionRuleDefinition, hit: _RuleHit) -> SecurityAlert:
        event = hit.anchor
        confidence = hit.semantic.confidence if hit.semantic is not None else rule.confidence
        reason_codes = list(rule.reason_codes)
        if hit.semantic is not None:
            reason_codes.extend(item for item in hit.semantic.reason_codes if item not in reason_codes)
        evidence: List[str] = []
        for related in hit.events:
            if related.event_id not in evidence:
                evidence.append(related.event_id)
        for field in rule.evidence_fields:
            value = _event_value(event, field)
            if value is None or value == "" or value == set():
                continue
            encoded = "%s:%s" % (
                field.value,
                ",".join(sorted(str(item) for item in value)) if isinstance(value, set) else value,
            )
            if encoded not in evidence:
                evidence.append(encoded[:512])
        if hit.semantic is not None:
            evidence.extend(item for item in hit.semantic.evidence_refs if item not in evidence)
        fingerprint_material = "|".join(
            [event.tenant_id, event.agent_id, rule.rule_id, rule.version,
             rule.alert_type, event.resource, event.flow_id]
        )
        fingerprint = hashlib.sha256(fingerprint_material.encode("utf-8")).hexdigest()
        return SecurityAlert(
            alert_id="alr_%s" % fingerprint[:32],
            fingerprint=fingerprint,
            event_id=event.event_id,
            tenant_id=event.tenant_id,
            flow_id=event.flow_id,
            agent_id=event.agent_id,
            alert_type=rule.alert_type,
            title=rule.title,
            severity=rule.severity,
            confidence=confidence,
            source_trust=event.source_trust,
            operation=event.operation,
            resource=event.resource,
            destination=event.destination,
            detector_id=rule.rule_id,
            rule_version=rule.version,
            reason_codes=reason_codes,
            evidence=evidence[:256],
            framework_mappings=rule.framework_mappings,
            recommended_action=rule.recommended_action,
            detected_at=event.occurred_at,
        )

    def _record_execution(
        self,
        principal: DetectionPrincipal,
        rule: DetectionRuleDefinition,
        mode: DetectionExecutionMode,
        status: DetectionExecutionStatus,
        evaluated_event_count: int,
        event_ids: Sequence[str],
        alerts: Sequence[SecurityAlert],
        error_code: Optional[str],
        started: datetime,
        started_timer: float,
    ) -> DetectionExecutionRecord:
        completed = self._now()
        record = DetectionExecutionRecord(
            execution_id=new_id("dexe"), tenant_id=principal.tenant_id,
            rule_id=rule.rule_id, rule_version=rule.version, mode=mode, status=status,
            evaluated_event_count=evaluated_event_count,
            matched_event_ids=list(dict.fromkeys(event_ids))[:256],
            alert_ids=[item.alert_id for item in alerts][:256], error_code=error_code,
            duration_ms=max(0, round((time.perf_counter() - started_timer) * 1000)),
            started_at=started, completed_at=completed,
        )
        with self._lock:
            self._connection.execute(
                "INSERT INTO detection_executions(tenant_id, execution_id, rule_id, rule_version, mode, status, evaluated_event_count, matched_event_ids_json, alert_ids_json, error_code, duration_ms, started_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    principal.tenant_id, record.execution_id, rule.rule_id, rule.version,
                    mode.value, status.value, evaluated_event_count,
                    json.dumps(record.matched_event_ids), json.dumps(record.alert_ids),
                    error_code, record.duration_ms, started.isoformat(), completed.isoformat(),
                ),
            )
            self._audit(principal, "detection.execute.%s" % mode.value, record.execution_id)
        return record

    def _run_rules(
        self,
        principal: DetectionPrincipal,
        rules: Sequence[DetectionRuleDefinition],
        mode: DetectionExecutionMode,
        event: Optional[AgentEvent],
        as_of: Optional[datetime],
    ) -> DetectionBatchResult:
        batch_started = self._now()
        alerts: List[SecurityAlert] = []
        executions: List[DetectionExecutionRecord] = []
        errors: List[str] = []
        total_events = 1 if event is not None else 0
        for rule in rules:
            started = self._now()
            timer = time.perf_counter()
            rule_alerts: List[SecurityAlert] = []
            event_count = 0
            error_code = None
            try:
                if mode == DetectionExecutionMode.STREAMING:
                    hits, event_count = self._stream_hits(principal, rule, event)  # type: ignore[arg-type]
                else:
                    hits, event_count = self._scheduled_hits(principal, rule, as_of)  # type: ignore[arg-type]
                rule_alerts = [self._alert(rule, hit) for hit in hits]
                status = DetectionExecutionStatus.MATCHED if rule_alerts else DetectionExecutionStatus.NO_MATCH
                matched_ids = [item.event_id for hit in hits for item in hit.events]
            except DetectionEvaluationError as exc:
                error_code = str(exc)[:128]
                errors.append("%s:%s" % (rule.rule_id, error_code))
                status = DetectionExecutionStatus.ERROR
                matched_ids = []
            executions.append(
                self._record_execution(
                    principal, rule, mode, status, event_count, matched_ids,
                    rule_alerts, error_code, started, timer,
                )
            )
            alerts.extend(rule_alerts)
            total_events = max(total_events, event_count)
        unique_alerts = list({item.fingerprint: item for item in alerts}.values())
        unique_alerts.sort(key=lambda item: (item.detected_at, item.detector_id, item.alert_id))
        return DetectionBatchResult(
            tenant_id=principal.tenant_id, mode=mode, alerts=unique_alerts,
            executions=executions, evaluated_event_count=total_events, errors=errors,
            started_at=batch_started, completed_at=self._now(),
        )

    def stream(
        self,
        principal: DetectionPrincipal,
        event: AgentEvent,
        *,
        rule_ids: Optional[Sequence[str]] = None,
    ) -> DetectionBatchResult:
        self._require(principal, DETECTION_RUN)
        self.capture_event(principal, event)
        rules = self._active_rules(principal, DetectionExecutionMode.STREAMING, rule_ids)
        return self._run_rules(principal, rules, DetectionExecutionMode.STREAMING, event, None)

    def run_scheduled(
        self,
        principal: DetectionPrincipal,
        *,
        as_of: Optional[datetime] = None,
        rule_ids: Optional[Sequence[str]] = None,
    ) -> DetectionBatchResult:
        self._require(principal, DETECTION_RUN)
        effective = as_of or self._now()
        if effective.tzinfo is None or effective.utcoffset() is None:
            raise ValueError("scheduled detection time must include a timezone")
        effective = effective.astimezone(timezone.utc)
        if effective > self._now() + timedelta(minutes=5):
            raise ValueError("scheduled detection time is too far in the future")
        rules = self._active_rules(principal, DetectionExecutionMode.SCHEDULED, rule_ids)
        return self._run_rules(principal, rules, DetectionExecutionMode.SCHEDULED, None, effective)

    def health(self, principal: DetectionPrincipal) -> List[DetectionRuleHealth]:
        self._require(principal, DETECTION_READ)
        rules = self.list_rules(principal)
        result: List[DetectionRuleHealth] = []
        with self._lock:
            for record in rules:
                definition = record.definition
                aggregate = self._connection.execute(
                    "SELECT COUNT(*) AS evaluations, SUM(status = 'matched') AS matches, SUM(status = 'error') AS errors, MAX(completed_at) AS last_at FROM detection_executions WHERE tenant_id = ? AND rule_id = ? AND rule_version = ?",
                    (principal.tenant_id, definition.rule_id, definition.version),
                ).fetchone()
                last_error = self._connection.execute(
                    "SELECT error_code FROM detection_executions WHERE tenant_id = ? AND rule_id = ? AND rule_version = ? AND status = 'error' ORDER BY completed_at DESC LIMIT 1",
                    (principal.tenant_id, definition.rule_id, definition.version),
                ).fetchone()
                result.append(
                    DetectionRuleHealth(
                        tenant_id=principal.tenant_id, rule_id=definition.rule_id,
                        rule_version=definition.version,
                        evaluation_count=int(aggregate["evaluations"] or 0),
                        match_count=int(aggregate["matches"] or 0),
                        error_count=int(aggregate["errors"] or 0),
                        last_evaluated_at=aggregate["last_at"],
                        last_error_code=last_error["error_code"] if last_error else None,
                    )
                )
        return result


class DetectionEngine:
    """Pipeline adapter supporting declarative content and legacy plug-ins."""

    def __init__(
        self,
        rules: Optional[Iterable[Union[DetectionRule, DetectionRuleDefinition]]] = None,
        *,
        semantic_provider: Optional[SemanticDetectionProvider] = None,
        service: Optional[DetectionService] = None,
        principal: Optional[DetectionPrincipal] = None,
    ) -> None:
        if (service is None) != (principal is None):
            raise ValueError("detection service and principal must be configured together")
        selected = list(rules) if rules is not None else list(DEFAULT_RULE_DEFINITIONS)
        self._legacy_rules = [item for item in selected if not isinstance(item, DetectionRuleDefinition)]
        self._definitions = [item for item in selected if isinstance(item, DetectionRuleDefinition)]
        self._semantic_provider = semantic_provider
        self._external_service = service
        self._external_principal = principal
        self._services: Dict[str, Tuple[DetectionService, DetectionPrincipal]] = {}

    def _declarative_service(
        self, tenant_id: str
    ) -> Tuple[DetectionService, DetectionPrincipal]:
        if self._external_service is not None and self._external_principal is not None:
            if tenant_id != self._external_principal.tenant_id:
                raise DetectionAuthorizationError("event tenant does not match detection engine")
            return self._external_service, self._external_principal
        if tenant_id not in self._services:
            service = DetectionService(":memory:", semantic_provider=self._semantic_provider)
            principal = DetectionPrincipal(
                tenant_id=tenant_id, actor_id="system://pipeline-detection",
                permissions={DETECTION_READ, DETECTION_RUN, DETECTION_ADMIN},
            )
            for definition in self._definitions:
                service.register_rule(principal, definition)
            self._services[tenant_id] = (service, principal)
        return self._services[tenant_id]

    @staticmethod
    def _legacy_alert(event: AgentEvent, match: DetectorMatch) -> SecurityAlert:
        fingerprint_material = "|".join(
            [event.tenant_id, event.agent_id, match.detector_id, match.rule_version,
             match.alert_type, event.resource, event.flow_id]
        )
        fingerprint = hashlib.sha256(fingerprint_material.encode("utf-8")).hexdigest()
        return SecurityAlert(
            alert_id="alr_%s" % fingerprint[:32], fingerprint=fingerprint,
            event_id=event.event_id, tenant_id=event.tenant_id, flow_id=event.flow_id,
            agent_id=event.agent_id, alert_type=match.alert_type, title=match.title,
            severity=match.severity, confidence=match.confidence,
            source_trust=event.source_trust, operation=event.operation,
            resource=event.resource, destination=event.destination,
            detector_id=match.detector_id, rule_version=match.rule_version,
            reason_codes=match.reason_codes, evidence=match.evidence,
            framework_mappings=match.framework_mappings,
            recommended_action=match.recommended_action, detected_at=event.occurred_at,
        )

    def detect(self, event: AgentEvent) -> List[SecurityAlert]:
        alerts: List[SecurityAlert] = []
        if self._definitions or self._external_service is not None:
            service, principal = self._declarative_service(event.tenant_id)
            alerts.extend(service.stream(principal, event).alerts)
        for rule in self._legacy_rules:
            for match in rule.evaluate(event):
                alerts.append(self._legacy_alert(event, match))
        return list({item.fingerprint: item for item in alerts}.values())

    def close(self) -> None:
        for service, _principal in self._services.values():
            service.close()
        self._services.clear()


__all__ = [
    "AuthorityViolationRule",
    "DEFAULT_RULES",
    "DEFAULT_RULE_DEFINITIONS",
    "DETECTION_ADMIN",
    "DETECTION_READ",
    "DETECTION_RUN",
    "DestructiveActionRule",
    "DetectionAuthorizationError",
    "DetectionBatchResult",
    "DetectionCondition",
    "DetectionEngine",
    "DetectionEventField",
    "DetectionExecutionMode",
    "DetectionExecutionRecord",
    "DetectionExecutionStatus",
    "DetectionOperator",
    "DetectionPredicate",
    "DetectionPrincipal",
    "DetectionRule",
    "DetectionRuleDefinition",
    "DetectionRuleHealth",
    "DetectionRuleKind",
    "DetectionRuleRecord",
    "DetectionService",
    "IndirectPromptInjectionRule",
    "McpDriftRule",
    "MemoryPoisoningRule",
    "SecretEgressRule",
    "SemanticDetectionProvider",
    "SemanticDetectionUnavailable",
    "SemanticDetectionVerdict",
]
