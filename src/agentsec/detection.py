"""Deterministic detectors operating on normalized agent-effect metadata."""

from __future__ import annotations

import hashlib
from typing import Iterable, List, Protocol

from .contracts import (
    AgentEvent,
    DecisionAction,
    DetectorMatch,
    SecurityAlert,
    Severity,
    TrustClass,
)


class DetectionRule(Protocol):
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
                recommended_action=DecisionAction.DENY,
            )


class MemoryPoisoningRule:
    detector_id = "DET-MEMORY-POISONING-001"

    def evaluate(self, event: AgentEvent) -> Iterable[DetectorMatch]:
        poisoned = "memory_poisoning" in event.indicators
        memory_source = event.source_type == "memory"
        if poisoned and memory_source and event.is_effectful:
            yield DetectorMatch(
                detector_id=self.detector_id,
                alert_type="persistent_memory_poisoning",
                title="Persisted untrusted memory influenced a later effect",
                severity=Severity.HIGH,
                confidence=0.96,
                reason_codes=["UNTRUSTED_MEMORY_REUSE", "CROSS_SESSION_INFLUENCE"],
                evidence=[event.source_id, event.event_id],
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


class DetectionEngine:
    def __init__(self, rules: Iterable[DetectionRule] = DEFAULT_RULES) -> None:
        self._rules = list(rules)

    def detect(self, event: AgentEvent) -> List[SecurityAlert]:
        alerts: List[SecurityAlert] = []
        for rule in self._rules:
            for match in rule.evaluate(event):
                fingerprint_material = "|".join(
                    [event.tenant_id, event.agent_id, match.alert_type, event.resource, event.flow_id]
                )
                fingerprint = hashlib.sha256(fingerprint_material.encode("utf-8")).hexdigest()
                alerts.append(
                    SecurityAlert(
                        alert_id="alr_%s" % fingerprint[:32],
                        fingerprint=fingerprint,
                        event_id=event.event_id,
                        tenant_id=event.tenant_id,
                        flow_id=event.flow_id,
                        agent_id=event.agent_id,
                        alert_type=match.alert_type,
                        title=match.title,
                        severity=match.severity,
                        confidence=match.confidence,
                        source_trust=event.source_trust,
                        operation=event.operation,
                        resource=event.resource,
                        destination=event.destination,
                        detector_id=match.detector_id,
                        reason_codes=match.reason_codes,
                        evidence=match.evidence,
                        recommended_action=match.recommended_action,
                        detected_at=event.occurred_at,
                    )
                )
        return alerts
