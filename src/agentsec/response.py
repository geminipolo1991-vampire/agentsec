"""Governed response playbooks, approvals, execution, verification, and rollback.

This module is deliberately downstream of deterministic authorization.  It can
plan and execute containment against privacy-safe target references, but it can
never authorize or replay the original agent effect.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Protocol, Sequence, Set

from pydantic import Field, field_validator, model_validator

from .contracts import (
    DecisionAction,
    EscalationLevel,
    PipelineResult,
    StrictModel,
    new_id,
    utc_now,
)
from .crypto import canonical_bytes
from .notifications import UrllibNotificationTransport, validate_notification_endpoint
from .privacy import Redactor


RESPONSE_READ = "response:read"
RESPONSE_AUTHOR = "response:author"
RESPONSE_REVIEW = "response:review"
RESPONSE_OPERATE = "response:operate"
RESPONSE_APPROVE = "response:approve"
RESPONSE_EXECUTE = "response:execute"
RESPONSE_ADMIN = "response:admin"

ZERO_SHA256 = "0" * 64
MAX_PLAYBOOK_STEPS = 12
MAX_AUDIT_ENTRIES = 2000
MAX_EXECUTION_PAGE = 200
MAX_PLAYBOOK_PAGE = 200
MAX_ATTEMPTS = 1000
RUNNING_LEASE_SECONDS = 60
APPROVAL_MAX_MINUTES = 60


class ResponseAuthorizationError(PermissionError):
    """The response principal lacks tenant or operation scope."""


class ResponseConflictError(RuntimeError):
    """The requested transition conflicts with durable current state."""


class ResponseIntegrityError(RuntimeError):
    """Durable response evidence failed integrity verification."""


class ResponseExecutionError(RuntimeError):
    """A guarded execution cannot proceed."""


class ResponseOperation(str, Enum):
    SESSION_QUARANTINE = "session.quarantine"
    SESSION_RESTORE = "session.restore"
    AGENT_PAUSE = "agent.pause"
    AGENT_RESUME = "agent.resume"
    IDENTITY_SUSPEND = "identity.suspend"
    IDENTITY_RESTORE = "identity.restore"
    NETWORK_BLOCK = "network.block_destination"
    NETWORK_UNBLOCK = "network.unblock_destination"
    TICKET_ANNOTATE = "ticket.annotate"


class TargetSelector(str, Enum):
    SESSION = "session"
    AGENT = "agent"
    RESOURCE = "resource"
    DESTINATION = "destination"
    CASE = "case"


class PlaybookStatus(str, Enum):
    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    ACTIVE = "active"
    RETIRED = "retired"


class ExecutionMode(str, Enum):
    DRY_RUN = "dry_run"
    LIVE = "live"


class ExecutionStatus(str, Enum):
    DRY_RUN_SUCCEEDED = "dry_run_succeeded"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ROLLBACK_AWAITING_APPROVAL = "rollback_awaiting_approval"
    ROLLBACK_APPROVED = "rollback_approved"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"


class StepStatus(str, Enum):
    DRY_RUN_READY = "dry_run_ready"
    DRY_RUN_NOT_READY = "dry_run_not_ready"
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"


class ApprovalScope(str, Enum):
    EXECUTE = "execute"
    ROLLBACK = "rollback"


class AttemptPhase(str, Enum):
    EXECUTE = "execute"
    VERIFY = "verify"
    ROLLBACK = "rollback"
    VERIFY_ROLLBACK = "verify_rollback"


class ResponsePrincipal(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(
        pattern=r"^(analyst|system|workload)://[A-Za-z0-9_.@/-]+$",
        max_length=256,
    )
    permissions: Set[str] = Field(default_factory=set, max_length=16)

    @field_validator("permissions")
    @classmethod
    def valid_permissions(cls, value: Set[str]) -> Set[str]:
        if any(re.fullmatch(r"response:[a-z]+", item) is None for item in value):
            raise ValueError("response permissions must use response:operation")
        return value


class ResponseConnectorSpec(StrictModel):
    connector_id: str = Field(pattern=r"^connector://[A-Za-z0-9_.@/-]+$")
    name: str = Field(min_length=3, max_length=128)
    endpoint: str = Field(min_length=12, max_length=512)
    allowed_hosts: List[str] = Field(min_length=1, max_length=8)
    credential_env: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    operations: List[ResponseOperation] = Field(min_length=1, max_length=32)
    timeout_seconds: float = Field(default=5.0, ge=0.1, le=30.0)
    enabled: bool = True

    @model_validator(mode="after")
    def coherent_connector(self) -> "ResponseConnectorSpec":
        if len(self.allowed_hosts) != len(set(self.allowed_hosts)):
            raise ValueError("response connector allowed hosts must be unique")
        if len(self.operations) != len(set(self.operations)):
            raise ValueError("response connector operations must be unique")
        validate_notification_endpoint(self.endpoint, self.allowed_hosts)
        return self


class PlaybookTrigger(StrictModel):
    priorities: List[str] = Field(default_factory=list, max_length=4)
    escalation_levels: List[EscalationLevel] = Field(default_factory=list, max_length=4)
    alert_types: List[str] = Field(default_factory=list, max_length=32)
    decisions: List[DecisionAction] = Field(default_factory=list, max_length=4)

    @field_validator("priorities")
    @classmethod
    def valid_priorities(cls, value: List[str]) -> List[str]:
        if any(re.fullmatch(r"P[0-3]", item) is None for item in value):
            raise ValueError("response trigger priorities are invalid")
        if len(value) != len(set(value)):
            raise ValueError("response trigger priorities must be unique")
        return value

    @field_validator("alert_types")
    @classmethod
    def valid_alert_types(cls, value: List[str]) -> List[str]:
        if any(re.fullmatch(r"[a-z][a-z0-9_]{2,63}", item) is None for item in value):
            raise ValueError("response trigger alert types are invalid")
        if len(value) != len(set(value)):
            raise ValueError("response trigger alert types must be unique")
        return value

    @model_validator(mode="after")
    def at_least_one_predicate(self) -> "PlaybookTrigger":
        if not (
            self.priorities
            or self.escalation_levels
            or self.alert_types
            or self.decisions
        ):
            raise ValueError("response trigger requires at least one predicate")
        return self

    def matches(self, item: PipelineResult) -> bool:
        return (
            (not self.priorities or item.triage.priority in self.priorities)
            and (
                not self.escalation_levels
                or item.escalation.level in self.escalation_levels
            )
            and (not self.alert_types or item.alert.alert_type in self.alert_types)
            and (not self.decisions or item.judgment.action in self.decisions)
        )


class PlaybookStepDefinition(StrictModel):
    step_id: str = Field(pattern=r"^step://[A-Za-z0-9_.@/-]+$")
    name: str = Field(min_length=3, max_length=128)
    operation: ResponseOperation
    connector_id: str = Field(pattern=r"^connector://[A-Za-z0-9_.@/-]+$")
    target_selector: TargetSelector
    expected_state: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    rollback_operation: Optional[ResponseOperation] = None
    rollback_expected_state: Optional[str] = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{1,63}$"
    )
    timeout_seconds: float = Field(default=5.0, ge=0.1, le=30.0)
    requires_approval: bool = True

    @model_validator(mode="after")
    def safe_step(self) -> "PlaybookStepDefinition":
        if not self.requires_approval:
            raise ValueError("every live response step requires human approval")
        if (self.rollback_operation is None) != (self.rollback_expected_state is None):
            raise ValueError("rollback operation and expected state must be configured together")
        if self.rollback_operation == self.operation:
            raise ValueError("response rollback must differ from the forward operation")
        return self


class ResponsePlaybookDefinition(StrictModel):
    schema_version: str = "1.0.0"
    playbook_id: str = Field(pattern=r"^playbook://[A-Za-z0-9_.@/-]+$")
    version: int = Field(ge=1, le=1000000)
    name: str = Field(min_length=3, max_length=128)
    description: str = Field(min_length=3, max_length=512)
    priority: int = Field(default=100, ge=0, le=1000)
    trigger: PlaybookTrigger
    steps: List[PlaybookStepDefinition] = Field(
        min_length=1, max_length=MAX_PLAYBOOK_STEPS
    )
    enabled: bool = True
    definition_sha256: str = Field(default=ZERO_SHA256, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def coherent_definition(self) -> "ResponsePlaybookDefinition":
        ids = [item.step_id for item in self.steps]
        if len(ids) != len(set(ids)):
            raise ValueError("response playbook step IDs must be unique")
        expected = digest_payload(
            self.model_dump(mode="json", exclude={"definition_sha256"})
        )
        if self.definition_sha256 not in {ZERO_SHA256, expected}:
            raise ValueError("response playbook definition digest is invalid")
        self.definition_sha256 = expected
        return self


class ResponseAutomationPolicy(StrictModel):
    schema_version: str = "1.0.0"
    policy_version: str = Field(min_length=3, max_length=128)
    connectors: List[ResponseConnectorSpec] = Field(min_length=1, max_length=32)
    playbooks: List[ResponsePlaybookDefinition] = Field(min_length=1, max_length=64)
    policy_sha256: str = Field(default=ZERO_SHA256, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def coherent_policy(self) -> "ResponseAutomationPolicy":
        connector_ids = [item.connector_id for item in self.connectors]
        if len(connector_ids) != len(set(connector_ids)):
            raise ValueError("response connector IDs must be unique")
        playbook_versions = [(item.playbook_id, item.version) for item in self.playbooks]
        if len(playbook_versions) != len(set(playbook_versions)):
            raise ValueError("response playbook versions must be unique")
        connectors = {item.connector_id: item for item in self.connectors}
        for playbook in self.playbooks:
            for step in playbook.steps:
                connector = connectors.get(step.connector_id)
                if connector is None:
                    raise ValueError("response playbook references an unknown connector")
                required = {step.operation}
                if step.rollback_operation is not None:
                    required.add(step.rollback_operation)
                if not required.issubset(set(connector.operations)):
                    raise ValueError("response connector does not allow the playbook operation")
        expected = digest_payload(
            self.model_dump(mode="json", exclude={"policy_sha256"})
        )
        if self.policy_sha256 not in {ZERO_SHA256, expected}:
            raise ValueError("response policy digest is invalid")
        self.policy_sha256 = expected
        return self


class ResponsePlaybookRecord(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    definition: ResponsePlaybookDefinition
    status: PlaybookStatus
    author_id: str = Field(pattern=r"^(analyst|system)://[A-Za-z0-9_.@/-]+$")
    reviewer_id: Optional[str] = Field(
        default=None, pattern=r"^(analyst|system)://[A-Za-z0-9_.@/-]+$"
    )
    review_comment: Optional[str] = Field(default=None, max_length=512)
    revision: int = Field(default=1, ge=1)
    created_at: datetime
    updated_at: datetime
    reviewed_at: Optional[datetime] = None
    activated_at: Optional[datetime] = None
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ResponseStepPlan(StrictModel):
    step_id: str = Field(pattern=r"^step://[A-Za-z0-9_.@/-]+$")
    name: str = Field(min_length=3, max_length=128)
    operation: ResponseOperation
    connector_id: str = Field(pattern=r"^connector://[A-Za-z0-9_.@/-]+$")
    target_ref: str = Field(
        pattern=r"^(?:agent|session|resource|destination)_sha256:[0-9a-f]{24}$|^case_[0-9a-f]{32}$"
    )
    expected_state: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    rollback_operation: Optional[ResponseOperation] = None
    rollback_expected_state: Optional[str] = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{1,63}$"
    )
    timeout_seconds: float = Field(ge=0.1, le=30.0)
    connector_ready: bool
    status: StepStatus
    attempt_count: int = Field(default=0, ge=0, le=MAX_ATTEMPTS)
    last_error_code: Optional[str] = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{2,63}$"
    )
    provider_reference_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    verification_evidence_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    step_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ResponseExecution(StrictModel):
    schema_version: str = "1.0.0"
    execution_id: str = Field(
        default_factory=lambda: new_id("rex"), pattern=r"^rex_[0-9a-f]{32}$"
    )
    tenant_id: str = Field(min_length=1, max_length=128)
    finding_id: str = Field(pattern=r"^fnd_[A-Za-z0-9]+$")
    alert_id: str = Field(pattern=r"^alr_[A-Za-z0-9]+$")
    case_id: Optional[str] = Field(default=None, pattern=r"^case_[0-9a-f]{32}$")
    correlation_incident_id: Optional[str] = Field(
        default=None, pattern=r"^inc_[A-Za-z0-9]+$"
    )
    playbook_id: str = Field(pattern=r"^playbook://[A-Za-z0-9_.@/-]+$")
    playbook_version: int = Field(ge=1)
    playbook_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_version: str = Field(min_length=3, max_length=128)
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    mode: ExecutionMode
    status: ExecutionStatus
    live_eligible: bool
    readiness_warnings: List[str] = Field(default_factory=list, max_length=32)
    requested_by: str = Field(pattern=r"^(analyst|system)://[A-Za-z0-9_.@/-]+$")
    live_requested_by: Optional[str] = Field(
        default=None, pattern=r"^(analyst|system)://[A-Za-z0-9_.@/-]+$"
    )
    rollback_requested_by: Optional[str] = Field(
        default=None, pattern=r"^(analyst|system)://[A-Za-z0-9_.@/-]+$"
    )
    approval_id: Optional[str] = Field(default=None, pattern=r"^rap_[0-9a-f]{32}$")
    rollback_approval_id: Optional[str] = Field(
        default=None, pattern=r"^rap_[0-9a-f]{32}$"
    )
    kill_switch_version: int = Field(ge=1)
    steps: List[ResponseStepPlan] = Field(min_length=1, max_length=MAX_PLAYBOOK_STEPS)
    version: int = Field(default=1, ge=1)
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    audit_count: int = Field(default=0, ge=0, le=MAX_AUDIT_ENTRIES)
    audit_head_sha256: str = Field(default=ZERO_SHA256, pattern=r"^[0-9a-f]{64}$")
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ResponseApproval(StrictModel):
    approval_id: str = Field(
        default_factory=lambda: new_id("rap"), pattern=r"^rap_[0-9a-f]{32}$"
    )
    execution_id: str = Field(pattern=r"^rex_[0-9a-f]{32}$")
    tenant_id: str = Field(min_length=1, max_length=128)
    scope: ApprovalScope
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    approver_id: str = Field(pattern=r"^(analyst|system)://[A-Za-z0-9_.@/-]+$")
    reason: str = Field(min_length=3, max_length=512)
    issued_at: datetime
    expires_at: datetime
    consumed_at: Optional[datetime] = None
    approval_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ResponseAttempt(StrictModel):
    attempt_id: str = Field(
        default_factory=lambda: new_id("rat"), pattern=r"^rat_[0-9a-f]{32}$"
    )
    execution_id: str = Field(pattern=r"^rex_[0-9a-f]{32}$")
    tenant_id: str = Field(min_length=1, max_length=128)
    step_id: str = Field(pattern=r"^step://[A-Za-z0-9_.@/-]+$")
    phase: AttemptPhase
    attempt_number: int = Field(ge=1, le=MAX_ATTEMPTS)
    outcome: str = Field(pattern=r"^(accepted|verified|failed)$")
    error_code: Optional[str] = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{2,63}$"
    )
    latency_ms: int = Field(ge=0, le=120000)
    provider_reference_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    evidence_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    attempted_at: datetime
    attempt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ResponseAuditEntry(StrictModel):
    audit_id: str = Field(
        default_factory=lambda: new_id("rau"), pattern=r"^rau_[0-9a-f]{32}$"
    )
    execution_id: str = Field(pattern=r"^rex_[0-9a-f]{32}$")
    tenant_id: str = Field(min_length=1, max_length=128)
    sequence: int = Field(ge=1, le=MAX_AUDIT_ENTRIES)
    actor_id: str = Field(pattern=r"^(analyst|system)://[A-Za-z0-9_.@/-]+$")
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    status_before: Optional[ExecutionStatus] = None
    status_after: ExecutionStatus
    detail_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    occurred_at: datetime
    previous_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    audit_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ResponseControl(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    kill_switch_active: bool
    version: int = Field(ge=1)
    changed_by: str = Field(pattern=r"^(analyst|system)://[A-Za-z0-9_.@/-]+$")
    reason: str = Field(min_length=3, max_length=512)
    changed_at: datetime
    control_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ResponseConnectorStatus(StrictModel):
    connector_id: str = Field(pattern=r"^connector://[A-Za-z0-9_.@/-]+$")
    name: str
    operations: List[ResponseOperation]
    enabled: bool
    ready: bool


class ResponseExecutionDetail(StrictModel):
    execution: ResponseExecution
    approval: Optional[ResponseApproval] = None
    rollback_approval: Optional[ResponseApproval] = None
    attempts: List[ResponseAttempt] = Field(default_factory=list, max_length=MAX_ATTEMPTS)
    audit: List[ResponseAuditEntry] = Field(
        default_factory=list, max_length=MAX_AUDIT_ENTRIES
    )


class ResponseExecutionPage(StrictModel):
    executions: List[ResponseExecution]
    count: int = Field(ge=0)
    limit: int = Field(ge=1, le=MAX_EXECUTION_PAGE)
    offset: int = Field(ge=0)


class ResponsePlaybookPage(StrictModel):
    playbooks: List[ResponsePlaybookRecord]
    count: int = Field(ge=0)
    limit: int = Field(ge=1, le=MAX_PLAYBOOK_PAGE)
    offset: int = Field(ge=0)


class ResponseHealth(StrictModel):
    tenant_id: str
    total_executions: int = Field(ge=0)
    dry_runs: int = Field(ge=0)
    awaiting_approval: int = Field(ge=0)
    running: int = Field(ge=0)
    succeeded: int = Field(ge=0)
    failed: int = Field(ge=0)
    rollback_pending: int = Field(ge=0)
    rolled_back: int = Field(ge=0)
    verification_failures: int = Field(ge=0)
    active_playbooks: int = Field(ge=0)
    configured_connectors: int = Field(ge=0)
    ready_connectors: int = Field(ge=0)
    kill_switch_active: bool
    kill_switch_version: int = Field(ge=1)
    average_execution_ms: int = Field(ge=0)
    policy_version: str
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: datetime


class ResponseMutationRequest(StrictModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=512)


class ResponseApprovalRequest(ResponseMutationRequest):
    ttl_minutes: int = Field(default=15, ge=1, le=APPROVAL_MAX_MINUTES)


class ResponseKillSwitchRequest(StrictModel):
    active: bool
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=512)


class ResponsePlaybookCreateRequest(StrictModel):
    definition: ResponsePlaybookDefinition


class ResponsePlaybookActionRequest(StrictModel):
    playbook_id: str = Field(pattern=r"^playbook://[A-Za-z0-9_.@/-]+$")
    version: int = Field(ge=1, le=1000000)
    action: str = Field(pattern=r"^(submit|approve|reject|activate|retire)$")
    expected_revision: int = Field(ge=1)
    comment: str = Field(min_length=3, max_length=512)


class ResponseEmptyRequest(StrictModel):
    pass


class ResponseConnectorRequest(StrictModel):
    execution_id: str = Field(pattern=r"^rex_[0-9a-f]{32}$")
    step_id: str = Field(pattern=r"^step://[A-Za-z0-9_.@/-]+$")
    operation: ResponseOperation
    target_ref: str
    expected_state: str
    case_id: Optional[str] = Field(default=None, pattern=r"^case_[0-9a-f]{32}$")
    idempotency_key: str = Field(pattern=r"^response_[0-9a-f]{64}$")
    requested_at: datetime
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ResponseConnectorResult(StrictModel):
    accepted: bool
    provider_reference: Optional[str] = Field(default=None, max_length=512)
    observed_state: Optional[str] = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{1,63}$"
    )
    error_code: Optional[str] = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{2,63}$"
    )

    @model_validator(mode="after")
    def coherent_result(self) -> "ResponseConnectorResult":
        if self.accepted and (self.error_code is not None or self.observed_state is None):
            raise ValueError("accepted response connector result is inconsistent")
        if not self.accepted and self.error_code is None:
            raise ValueError("rejected response connector result requires an error code")
        return self


class ResponseVerificationResult(StrictModel):
    verified: bool
    observed_state: Optional[str] = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{1,63}$"
    )
    evidence_reference: Optional[str] = Field(default=None, max_length=512)
    error_code: Optional[str] = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{2,63}$"
    )

    @model_validator(mode="after")
    def coherent_verification(self) -> "ResponseVerificationResult":
        if self.verified and (self.error_code is not None or self.observed_state is None):
            raise ValueError("verified response result is inconsistent")
        if not self.verified and self.error_code is None:
            raise ValueError("failed response verification requires an error code")
        return self


class ResponseConnector(Protocol):
    def execute(
        self, spec: ResponseConnectorSpec, request: ResponseConnectorRequest
    ) -> ResponseConnectorResult:
        ...

    def verify(
        self, spec: ResponseConnectorSpec, request: ResponseConnectorRequest
    ) -> ResponseVerificationResult:
        ...

    def rollback(
        self, spec: ResponseConnectorSpec, request: ResponseConnectorRequest
    ) -> ResponseConnectorResult:
        ...


class HttpResponseConnector:
    """Provider-neutral response gateway; it never executes shell or file actions."""

    def __init__(
        self,
        *,
        credential: str,
        transport: Optional[UrllibNotificationTransport] = None,
    ) -> None:
        if not credential or len(credential) > 4096:
            raise ValueError("response connector credential is invalid")
        self._credential = credential
        self._transport = transport or UrllibNotificationTransport()

    def _call(
        self,
        phase: str,
        spec: ResponseConnectorSpec,
        request: ResponseConnectorRequest,
    ) -> Mapping[str, Any]:
        if request.operation not in spec.operations:
            raise RuntimeError("response_operation_not_allowed")
        validate_notification_endpoint(spec.endpoint, spec.allowed_hosts)
        return self._transport.post(
            url=spec.endpoint,
            headers={"Authorization": "Bearer " + self._credential},
            payload={
                "schema_version": "1.0.0",
                "phase": phase,
                "request": request.model_dump(mode="json"),
            },
            timeout_seconds=spec.timeout_seconds,
        )

    @staticmethod
    def _result(payload: Mapping[str, Any]) -> ResponseConnectorResult:
        allowed = {"accepted", "provider_reference", "observed_state", "error_code"}
        if set(payload) - allowed:
            raise RuntimeError("response_connector_result_invalid")
        try:
            return ResponseConnectorResult.model_validate(payload)
        except Exception:
            raise RuntimeError("response_connector_result_invalid") from None

    def execute(
        self, spec: ResponseConnectorSpec, request: ResponseConnectorRequest
    ) -> ResponseConnectorResult:
        return self._result(self._call("execute", spec, request))

    def verify(
        self, spec: ResponseConnectorSpec, request: ResponseConnectorRequest
    ) -> ResponseVerificationResult:
        payload = self._call("verify", spec, request)
        allowed = {"verified", "observed_state", "evidence_reference", "error_code"}
        if set(payload) - allowed:
            raise RuntimeError("response_verification_invalid")
        try:
            return ResponseVerificationResult.model_validate(payload)
        except Exception:
            raise RuntimeError("response_verification_invalid") from None

    def rollback(
        self, spec: ResponseConnectorSpec, request: ResponseConnectorRequest
    ) -> ResponseConnectorResult:
        return self._result(self._call("rollback", spec, request))


def digest_payload(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def hash_reference(kind: str, value: str) -> str:
    return "%s_sha256:%s" % (
        kind,
        hashlib.sha256(value.encode("utf-8")).hexdigest()[:24],
    )


def load_response_policy(path: str | Path) -> ResponseAutomationPolicy:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return ResponseAutomationPolicy.model_validate(payload)


class ResponseAutomationService:
    """Durable single-node response control plane and guarded executor."""

    def __init__(
        self,
        database_path: str,
        *,
        policy: ResponseAutomationPolicy,
        connectors: Optional[Mapping[str, ResponseConnector]] = None,
    ) -> None:
        self.policy = policy
        self.connectors = dict(connectors or {})
        configured = {item.connector_id: item for item in policy.connectors if item.enabled}
        if set(self.connectors) - set(configured):
            raise ValueError("response connector is not present in enabled policy")
        self._connector_specs = {item.connector_id: item for item in policy.connectors}
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            database_path, check_same_thread=False, isolation_level=None
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute("PRAGMA synchronous = FULL")
        self._create_schema()
        self._seed_policy()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS response_playbooks (
                tenant_id TEXT NOT NULL,
                playbook_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                status TEXT NOT NULL,
                record_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, playbook_id, version)
            );
            CREATE INDEX IF NOT EXISTS idx_response_playbook_status
              ON response_playbooks(tenant_id, status, playbook_id, version);
            CREATE TABLE IF NOT EXISTS response_executions (
                tenant_id TEXT NOT NULL,
                execution_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                status TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                record_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, execution_id),
                UNIQUE (tenant_id, finding_id)
            );
            CREATE INDEX IF NOT EXISTS idx_response_execution_status
              ON response_executions(tenant_id, status, updated_at);
            CREATE TABLE IF NOT EXISTS response_approvals (
                tenant_id TEXT NOT NULL,
                approval_id TEXT NOT NULL,
                execution_id TEXT NOT NULL,
                scope TEXT NOT NULL,
                record_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, approval_id)
            );
            CREATE TABLE IF NOT EXISTS response_attempts (
                tenant_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                execution_id TEXT NOT NULL,
                step_id TEXT NOT NULL,
                phase TEXT NOT NULL,
                attempted_at TEXT NOT NULL,
                record_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, attempt_id)
            );
            CREATE INDEX IF NOT EXISTS idx_response_attempt_execution
              ON response_attempts(tenant_id, execution_id, attempted_at);
            CREATE TABLE IF NOT EXISTS response_audit (
                tenant_id TEXT NOT NULL,
                execution_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                record_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, execution_id, sequence)
            );
            CREATE TABLE IF NOT EXISTS response_control (
                tenant_id TEXT PRIMARY KEY,
                record_json TEXT NOT NULL
            );
            """
        )

    @staticmethod
    def _dump(model: StrictModel) -> str:
        return json.dumps(model.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _record_digest(model: StrictModel, field: str) -> str:
        return digest_payload(model.model_dump(mode="json", exclude={field}))

    def _require(self, principal: ResponsePrincipal, permission: str) -> None:
        if permission not in principal.permissions and RESPONSE_ADMIN not in principal.permissions:
            raise ResponseAuthorizationError("response permission denied")

    def _ensure_tenant(self, principal: ResponsePrincipal, tenant_id: str) -> None:
        if principal.tenant_id != tenant_id:
            raise ResponseAuthorizationError("response tenant denied")

    def _seed_policy(self) -> None:
        now = utc_now()
        with self._lock:
            tenants = [
                row[0]
                for row in self._connection.execute(
                    "SELECT tenant_id FROM response_control"
                ).fetchall()
            ]
            # The concrete tenant is initialized lazily by ensure_tenant_seed.
            for tenant_id in tenants:
                self._seed_for_tenant(tenant_id, now)

    def _seed_for_tenant(self, tenant_id: str, now: Optional[datetime] = None) -> None:
        moment = now or utc_now()
        existing_control = self._connection.execute(
            "SELECT record_json FROM response_control WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        if existing_control is None:
            unsigned = ResponseControl(
                tenant_id=tenant_id,
                kill_switch_active=False,
                version=1,
                changed_by="system://response-policy-loader",
                reason="Response automation initialized with live execution enabled only after approval.",
                changed_at=moment,
                control_sha256=ZERO_SHA256,
            )
            control = unsigned.model_copy(
                update={"control_sha256": self._record_digest(unsigned, "control_sha256")}
            )
            self._connection.execute(
                "INSERT INTO response_control(tenant_id,record_json) VALUES (?,?)",
                (tenant_id, self._dump(control)),
            )
        for definition in self.policy.playbooks:
            row = self._connection.execute(
                "SELECT record_json FROM response_playbooks WHERE tenant_id=? AND playbook_id=? AND version=?",
                (tenant_id, definition.playbook_id, definition.version),
            ).fetchone()
            if row is not None:
                record = self._verify_playbook(row["record_json"])
                if record.definition.definition_sha256 != definition.definition_sha256:
                    raise ResponseIntegrityError("configured response playbook conflicts with durable version")
                continue
            unsigned = ResponsePlaybookRecord(
                tenant_id=tenant_id,
                definition=definition,
                status=PlaybookStatus.ACTIVE,
                author_id="system://response-policy-author",
                reviewer_id="system://response-policy-reviewer",
                review_comment="Reviewed configuration seed.",
                created_at=moment,
                updated_at=moment,
                reviewed_at=moment,
                activated_at=moment,
                record_sha256=ZERO_SHA256,
            )
            record = unsigned.model_copy(
                update={"record_sha256": self._record_digest(unsigned, "record_sha256")}
            )
            self._connection.execute(
                "INSERT INTO response_playbooks(tenant_id,playbook_id,version,status,record_json) VALUES (?,?,?,?,?)",
                (
                    tenant_id,
                    definition.playbook_id,
                    definition.version,
                    record.status.value,
                    self._dump(record),
                ),
            )

    def _ensure_tenant_seed(self, tenant_id: str) -> None:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._seed_for_tenant(tenant_id)
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def _verify_playbook(self, encoded: str) -> ResponsePlaybookRecord:
        record = ResponsePlaybookRecord.model_validate_json(encoded)
        expected = self._record_digest(record, "record_sha256")
        if record.record_sha256 != expected:
            raise ResponseIntegrityError("response playbook record digest mismatch")
        return record

    def _verify_step(self, step: ResponseStepPlan) -> None:
        if step.step_sha256 != self._record_digest(step, "step_sha256"):
            raise ResponseIntegrityError("response step digest mismatch")

    def _verify_execution_record(self, encoded: str) -> ResponseExecution:
        execution = ResponseExecution.model_validate_json(encoded)
        for step in execution.steps:
            self._verify_step(step)
        if execution.record_sha256 != self._record_digest(execution, "record_sha256"):
            raise ResponseIntegrityError("response execution record digest mismatch")
        return execution

    def _verify_approval(self, encoded: str) -> ResponseApproval:
        record = ResponseApproval.model_validate_json(encoded)
        if record.approval_sha256 != self._record_digest(record, "approval_sha256"):
            raise ResponseIntegrityError("response approval digest mismatch")
        return record

    def _verify_attempt(self, encoded: str) -> ResponseAttempt:
        record = ResponseAttempt.model_validate_json(encoded)
        if record.attempt_sha256 != self._record_digest(record, "attempt_sha256"):
            raise ResponseIntegrityError("response attempt digest mismatch")
        return record

    def _verify_control(self, encoded: str) -> ResponseControl:
        record = ResponseControl.model_validate_json(encoded)
        if record.control_sha256 != self._record_digest(record, "control_sha256"):
            raise ResponseIntegrityError("response control digest mismatch")
        return record

    def _control(self, tenant_id: str) -> ResponseControl:
        row = self._connection.execute(
            "SELECT record_json FROM response_control WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        if row is None:
            raise ResponseIntegrityError("response control is missing")
        return self._verify_control(row["record_json"])

    def _playbook_matches(
        self, tenant_id: str, item: PipelineResult
    ) -> Optional[ResponsePlaybookRecord]:
        rows = self._connection.execute(
            "SELECT record_json FROM response_playbooks WHERE tenant_id=? AND status=? ORDER BY playbook_id, version DESC",
            (tenant_id, PlaybookStatus.ACTIVE.value),
        ).fetchall()
        records = [self._verify_playbook(row["record_json"]) for row in rows]
        records.sort(
            key=lambda record: (
                record.definition.priority,
                -record.definition.version,
                record.definition.playbook_id,
            )
        )
        for record in records:
            if record.definition.enabled and record.definition.trigger.matches(item):
                return record
        return None

    @staticmethod
    def _target(
        selector: TargetSelector, item: PipelineResult, case_id: Optional[str]
    ) -> Optional[str]:
        if selector == TargetSelector.CASE:
            return case_id
        values = {
            TargetSelector.SESSION: ("session", item.event.flow_id),
            TargetSelector.AGENT: ("agent", item.event.agent_id),
            TargetSelector.RESOURCE: ("resource", item.event.resource),
            TargetSelector.DESTINATION: ("destination", item.event.destination),
        }
        kind, value = values[selector]
        return hash_reference(kind, value) if value else None

    def _signed_step(self, **values: Any) -> ResponseStepPlan:
        unsigned = ResponseStepPlan(step_sha256=ZERO_SHA256, **values)
        return unsigned.model_copy(
            update={"step_sha256": self._record_digest(unsigned, "step_sha256")}
        )

    def _signed_execution(self, execution: ResponseExecution, **updates: Any) -> ResponseExecution:
        unsigned = execution.model_copy(update={**updates, "record_sha256": ZERO_SHA256})
        return unsigned.model_copy(
            update={"record_sha256": self._record_digest(unsigned, "record_sha256")}
        )

    def _plan_digest(self, execution: ResponseExecution, scope: ApprovalScope) -> str:
        return digest_payload(
            {
                "execution_id": execution.execution_id,
                "tenant_id": execution.tenant_id,
                "finding_id": execution.finding_id,
                "playbook_id": execution.playbook_id,
                "playbook_version": execution.playbook_version,
                "playbook_sha256": execution.playbook_sha256,
                "policy_sha256": execution.policy_sha256,
                "scope": scope.value,
                "steps": [
                    {
                        "step_id": item.step_id,
                        "operation": (
                            item.rollback_operation.value
                            if scope == ApprovalScope.ROLLBACK and item.rollback_operation
                            else item.operation.value
                        ),
                        "target_ref": item.target_ref,
                        "expected_state": (
                            item.rollback_expected_state
                            if scope == ApprovalScope.ROLLBACK
                            else item.expected_state
                        ),
                        "connector_id": item.connector_id,
                    }
                    for item in execution.steps
                    if scope == ApprovalScope.EXECUTE
                    or item.status == StepStatus.SUCCEEDED
                ],
            }
        )

    def _append_audit(
        self,
        execution: ResponseExecution,
        *,
        actor_id: str,
        action: str,
        status_before: Optional[ExecutionStatus],
        status_after: ExecutionStatus,
        detail: Mapping[str, Any],
        occurred_at: Optional[datetime] = None,
    ) -> ResponseExecution:
        sequence = execution.audit_count + 1
        if sequence > MAX_AUDIT_ENTRIES:
            raise ResponseConflictError("response audit capacity reached")
        moment = occurred_at or utc_now()
        unsigned = ResponseAuditEntry(
            execution_id=execution.execution_id,
            tenant_id=execution.tenant_id,
            sequence=sequence,
            actor_id=actor_id,
            action=action,
            status_before=status_before,
            status_after=status_after,
            detail_sha256=digest_payload(Redactor().redact(dict(detail)).value),
            occurred_at=moment,
            previous_sha256=execution.audit_head_sha256,
            audit_sha256=ZERO_SHA256,
        )
        audit = unsigned.model_copy(
            update={"audit_sha256": self._record_digest(unsigned, "audit_sha256")}
        )
        self._connection.execute(
            "INSERT INTO response_audit(tenant_id,execution_id,sequence,record_json) VALUES (?,?,?,?)",
            (execution.tenant_id, execution.execution_id, sequence, self._dump(audit)),
        )
        return self._signed_execution(
            execution,
            audit_count=sequence,
            audit_head_sha256=audit.audit_sha256,
            updated_at=moment,
        )

    def _save_execution(self, execution: ResponseExecution) -> None:
        self._connection.execute(
            "UPDATE response_executions SET status=?,updated_at=?,record_json=? WHERE tenant_id=? AND execution_id=?",
            (
                execution.status.value,
                execution.updated_at.isoformat(),
                self._dump(execution),
                execution.tenant_id,
                execution.execution_id,
            ),
        )

    def _checkpoint_steps(
        self,
        principal: ResponsePrincipal,
        execution_id: str,
        *,
        expected_status: ExecutionStatus,
        steps: List[ResponseStepPlan],
        action: str,
        detail: Mapping[str, Any],
    ) -> ResponseExecution:
        """Commit each step outcome before another external effect begins."""

        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                current = self._load_execution(principal.tenant_id, execution_id)
                if current.status != expected_status:
                    raise ResponseConflictError("response execution checkpoint lost its claim")
                execution = self._signed_execution(
                    current,
                    steps=steps,
                    version=current.version + 1,
                )
                execution = self._append_audit(
                    execution,
                    actor_id=principal.actor_id,
                    action=action,
                    status_before=expected_status,
                    status_after=expected_status,
                    detail=detail,
                )
                self._save_execution(execution)
                self._connection.execute("COMMIT")
                return execution
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def create_from_pipeline(
        self,
        principal: ResponsePrincipal,
        item: PipelineResult,
        *,
        case_id: Optional[str],
        correlation_incident_id: Optional[str],
    ) -> Optional[ResponseExecution]:
        """Record a dry-run plan; never invokes a connector or changes enforcement."""

        self._require(principal, RESPONSE_OPERATE)
        self._ensure_tenant(principal, item.event.tenant_id)
        self._ensure_tenant_seed(principal.tenant_id)
        if item.judgment.action not in {DecisionAction.DENY, DecisionAction.REQUIRE_APPROVAL}:
            return None
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT record_json FROM response_executions WHERE tenant_id=? AND finding_id=?",
                    (principal.tenant_id, item.finding.finding_id),
                ).fetchone()
                if existing is not None:
                    execution = self._verify_execution_record(existing["record_json"])
                    self._connection.execute("COMMIT")
                    return execution
                playbook = self._playbook_matches(principal.tenant_id, item)
                if playbook is None:
                    self._connection.execute("COMMIT")
                    return None
                control = self._control(principal.tenant_id)
                steps: List[ResponseStepPlan] = []
                warnings: List[str] = []
                for definition in playbook.definition.steps:
                    target = self._target(definition.target_selector, item, case_id)
                    connector_ready = definition.connector_id in self.connectors
                    if target is None:
                        raise ResponseConflictError("response target is unavailable")
                    if not connector_ready:
                        warnings.append("connector_not_ready:%s" % definition.connector_id)
                    steps.append(
                        self._signed_step(
                            step_id=definition.step_id,
                            name=definition.name,
                            operation=definition.operation,
                            connector_id=definition.connector_id,
                            target_ref=target,
                            expected_state=definition.expected_state,
                            rollback_operation=definition.rollback_operation,
                            rollback_expected_state=definition.rollback_expected_state,
                            timeout_seconds=definition.timeout_seconds,
                            connector_ready=connector_ready,
                            status=(
                                StepStatus.DRY_RUN_READY
                                if connector_ready
                                else StepStatus.DRY_RUN_NOT_READY
                            ),
                        )
                    )
                now = utc_now()
                unsigned = ResponseExecution(
                    tenant_id=principal.tenant_id,
                    finding_id=item.finding.finding_id,
                    alert_id=item.alert.alert_id,
                    case_id=case_id,
                    correlation_incident_id=correlation_incident_id,
                    playbook_id=playbook.definition.playbook_id,
                    playbook_version=playbook.definition.version,
                    playbook_sha256=playbook.definition.definition_sha256,
                    policy_version=self.policy.policy_version,
                    policy_sha256=self.policy.policy_sha256,
                    mode=ExecutionMode.DRY_RUN,
                    status=ExecutionStatus.DRY_RUN_SUCCEEDED,
                    live_eligible=not warnings,
                    readiness_warnings=warnings,
                    requested_by=principal.actor_id,
                    kill_switch_version=control.version,
                    steps=steps,
                    created_at=now,
                    updated_at=now,
                    record_sha256=ZERO_SHA256,
                )
                execution = unsigned.model_copy(
                    update={"record_sha256": self._record_digest(unsigned, "record_sha256")}
                )
                self._connection.execute(
                    "INSERT INTO response_executions(tenant_id,execution_id,finding_id,status,updated_at,record_json) VALUES (?,?,?,?,?,?)",
                    (
                        execution.tenant_id,
                        execution.execution_id,
                        execution.finding_id,
                        execution.status.value,
                        execution.updated_at.isoformat(),
                        self._dump(execution),
                    ),
                )
                execution = self._append_audit(
                    execution,
                    actor_id=principal.actor_id,
                    action="dry_run_recorded",
                    status_before=None,
                    status_after=execution.status,
                    detail={"live_eligible": execution.live_eligible, "warnings": warnings},
                )
                self._save_execution(execution)
                self._connection.execute("COMMIT")
                return execution
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def _load_execution(self, tenant_id: str, execution_id: str) -> ResponseExecution:
        row = self._connection.execute(
            "SELECT record_json FROM response_executions WHERE tenant_id=? AND execution_id=?",
            (tenant_id, execution_id),
        ).fetchone()
        if row is None:
            raise KeyError(execution_id)
        execution = self._verify_execution_record(row["record_json"])
        if (
            execution.status in {ExecutionStatus.RUNNING, ExecutionStatus.ROLLING_BACK}
            and (utc_now() - execution.updated_at).total_seconds() > RUNNING_LEASE_SECONDS
        ):
            previous = execution.status
            execution = self._signed_execution(
                execution,
                status=(
                    ExecutionStatus.FAILED
                    if previous == ExecutionStatus.RUNNING
                    else ExecutionStatus.ROLLBACK_FAILED
                ),
                version=execution.version + 1,
                completed_at=utc_now(),
            )
            execution = self._append_audit(
                execution,
                actor_id="system://response-lease-recovery",
                action="executor_lease_expired",
                status_before=previous,
                status_after=execution.status,
                detail={"lease_seconds": RUNNING_LEASE_SECONDS},
            )
            self._save_execution(execution)
        return execution

    def _audit_rows(self, execution: ResponseExecution) -> List[ResponseAuditEntry]:
        rows = self._connection.execute(
            "SELECT record_json FROM response_audit WHERE tenant_id=? AND execution_id=? ORDER BY sequence",
            (execution.tenant_id, execution.execution_id),
        ).fetchall()
        if len(rows) != execution.audit_count:
            raise ResponseIntegrityError("response audit count mismatch")
        previous = ZERO_SHA256
        audits: List[ResponseAuditEntry] = []
        for index, row in enumerate(rows, 1):
            audit = ResponseAuditEntry.model_validate_json(row["record_json"])
            expected = self._record_digest(audit, "audit_sha256")
            if (
                audit.sequence != index
                or audit.previous_sha256 != previous
                or audit.audit_sha256 != expected
            ):
                raise ResponseIntegrityError("response audit chain mismatch")
            audits.append(audit)
            previous = audit.audit_sha256
        if previous != execution.audit_head_sha256:
            raise ResponseIntegrityError("response audit head mismatch")
        return audits

    def _attempt_rows(self, execution: ResponseExecution) -> List[ResponseAttempt]:
        """Verify signed attempt membership against the signed step checkpoints."""

        rows = self._connection.execute(
            "SELECT record_json FROM response_attempts WHERE tenant_id=? AND execution_id=? ORDER BY attempted_at,attempt_id",
            (execution.tenant_id, execution.execution_id),
        ).fetchall()
        attempts = [self._verify_attempt(row["record_json"]) for row in rows]
        step_counts = {step.step_id: 0 for step in execution.steps}
        for attempt in attempts:
            if attempt.step_id not in step_counts:
                raise ResponseIntegrityError("response attempt references an unknown step")
            step_counts[attempt.step_id] += 1
            if attempt.attempt_number != step_counts[attempt.step_id]:
                raise ResponseIntegrityError("response attempt sequence mismatch")
        # An executor records the connector result before checkpointing the
        # signed step. Permit that short in-flight interval only while the
        # durable lease is RUNNING/ROLLING_BACK; terminal records must bind the
        # exact number of attempts for every step, so row deletion is visible.
        if execution.status not in {
            ExecutionStatus.RUNNING,
            ExecutionStatus.ROLLING_BACK,
        }:
            expected = {step.step_id: step.attempt_count for step in execution.steps}
            if step_counts != expected:
                raise ResponseIntegrityError("response attempt count mismatch")
        return attempts

    def _approval_for(
        self, tenant_id: str, execution_id: str, scope: ApprovalScope
    ) -> Optional[ResponseApproval]:
        row = self._connection.execute(
            "SELECT record_json FROM response_approvals WHERE tenant_id=? AND execution_id=? AND scope=? ORDER BY rowid DESC LIMIT 1",
            (tenant_id, execution_id, scope.value),
        ).fetchone()
        return self._verify_approval(row["record_json"]) if row is not None else None

    def get(
        self, principal: ResponsePrincipal, execution_id: str
    ) -> ResponseExecutionDetail:
        self._require(principal, RESPONSE_READ)
        with self._lock:
            execution = self._load_execution(principal.tenant_id, execution_id)
            self._ensure_tenant(principal, execution.tenant_id)
            attempts = self._attempt_rows(execution)
            return ResponseExecutionDetail(
                execution=execution,
                approval=self._approval_for(
                    principal.tenant_id, execution_id, ApprovalScope.EXECUTE
                ),
                rollback_approval=self._approval_for(
                    principal.tenant_id, execution_id, ApprovalScope.ROLLBACK
                ),
                attempts=attempts,
                audit=self._audit_rows(execution),
            )

    def list(
        self, principal: ResponsePrincipal, *, limit: int = 100, offset: int = 0
    ) -> ResponseExecutionPage:
        self._require(principal, RESPONSE_READ)
        if not 1 <= limit <= MAX_EXECUTION_PAGE or offset < 0:
            raise ValueError("response execution page is invalid")
        self._ensure_tenant_seed(principal.tenant_id)
        with self._lock:
            count = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM response_executions WHERE tenant_id=?",
                    (principal.tenant_id,),
                ).fetchone()[0]
            )
            rows = self._connection.execute(
                "SELECT record_json FROM response_executions WHERE tenant_id=? ORDER BY updated_at DESC,execution_id LIMIT ? OFFSET ?",
                (principal.tenant_id, limit, offset),
            ).fetchall()
            executions = [self._verify_execution_record(row["record_json"]) for row in rows]
            for execution in executions:
                self._audit_rows(execution)
                self._attempt_rows(execution)
            return ResponseExecutionPage(
                executions=executions,
                count=count,
                limit=limit,
                offset=offset,
            )

    def request_live(
        self,
        principal: ResponsePrincipal,
        execution_id: str,
        *,
        expected_version: int,
        reason: str,
    ) -> ResponseExecution:
        self._require(principal, RESPONSE_OPERATE)
        reason = str(Redactor().redact({"reason": reason}).value["reason"])
        if not 3 <= len(reason) <= 512:
            raise ValueError("response live request reason is invalid")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                execution = self._load_execution(principal.tenant_id, execution_id)
                if execution.version != expected_version:
                    raise ResponseConflictError("response execution version conflict")
                if execution.status != ExecutionStatus.DRY_RUN_SUCCEEDED:
                    raise ResponseConflictError("response dry run is not current")
                control = self._control(principal.tenant_id)
                if control.kill_switch_active:
                    raise ResponseExecutionError("response kill switch is active")
                missing = [
                    step.connector_id
                    for step in execution.steps
                    if step.connector_id not in self.connectors
                ]
                if missing:
                    raise ResponseExecutionError("response connector is not ready")
                steps = [
                    self._signed_step(
                        **step.model_dump(
                            exclude={
                                "step_sha256",
                                "status",
                                "connector_ready",
                                "last_error_code",
                                "provider_reference_sha256",
                                "verification_evidence_sha256",
                                "started_at",
                                "completed_at",
                                "attempt_count",
                            }
                        ),
                        connector_ready=True,
                        status=StepStatus.PENDING,
                    )
                    for step in execution.steps
                ]
                before = execution.status
                execution = self._signed_execution(
                    execution,
                    mode=ExecutionMode.LIVE,
                    status=ExecutionStatus.AWAITING_APPROVAL,
                    live_eligible=True,
                    readiness_warnings=[],
                    live_requested_by=principal.actor_id,
                    kill_switch_version=control.version,
                    steps=steps,
                    version=execution.version + 1,
                )
                execution = self._append_audit(
                    execution,
                    actor_id=principal.actor_id,
                    action="live_execution_requested",
                    status_before=before,
                    status_after=execution.status,
                    detail={"reason": reason},
                )
                self._save_execution(execution)
                self._connection.execute("COMMIT")
                return execution
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def approve(
        self,
        principal: ResponsePrincipal,
        execution_id: str,
        *,
        scope: ApprovalScope,
        expected_version: int,
        reason: str,
        ttl_minutes: int = 15,
    ) -> ResponseApproval:
        self._require(principal, RESPONSE_APPROVE)
        if not 1 <= ttl_minutes <= APPROVAL_MAX_MINUTES:
            raise ValueError("response approval TTL is invalid")
        redacted = str(Redactor().redact({"reason": reason}).value["reason"])
        if not 3 <= len(redacted) <= 512:
            raise ValueError("response approval reason is invalid")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                execution = self._load_execution(principal.tenant_id, execution_id)
                if execution.version != expected_version:
                    raise ResponseConflictError("response execution version conflict")
                expected_status = (
                    ExecutionStatus.AWAITING_APPROVAL
                    if scope == ApprovalScope.EXECUTE
                    else ExecutionStatus.ROLLBACK_AWAITING_APPROVAL
                )
                if execution.status != expected_status:
                    raise ResponseConflictError("response execution is not awaiting this approval")
                requester = (
                    execution.live_requested_by
                    if scope == ApprovalScope.EXECUTE
                    else execution.rollback_requested_by
                )
                if requester == principal.actor_id:
                    raise ResponseAuthorizationError("response requester cannot approve their own action")
                control = self._control(principal.tenant_id)
                if control.kill_switch_active:
                    raise ResponseExecutionError("response kill switch is active")
                now = utc_now()
                unsigned = ResponseApproval(
                    execution_id=execution.execution_id,
                    tenant_id=execution.tenant_id,
                    scope=scope,
                    plan_sha256=self._plan_digest(execution, scope),
                    approver_id=principal.actor_id,
                    reason=redacted,
                    issued_at=now,
                    expires_at=now + timedelta(minutes=ttl_minutes),
                    approval_sha256=ZERO_SHA256,
                )
                approval = unsigned.model_copy(
                    update={"approval_sha256": self._record_digest(unsigned, "approval_sha256")}
                )
                self._connection.execute(
                    "INSERT INTO response_approvals(tenant_id,approval_id,execution_id,scope,record_json) VALUES (?,?,?,?,?)",
                    (
                        approval.tenant_id,
                        approval.approval_id,
                        approval.execution_id,
                        approval.scope.value,
                        self._dump(approval),
                    ),
                )
                before = execution.status
                status = (
                    ExecutionStatus.APPROVED
                    if scope == ApprovalScope.EXECUTE
                    else ExecutionStatus.ROLLBACK_APPROVED
                )
                updates = {
                    "status": status,
                    "version": execution.version + 1,
                    (
                        "approval_id"
                        if scope == ApprovalScope.EXECUTE
                        else "rollback_approval_id"
                    ): approval.approval_id,
                }
                execution = self._signed_execution(execution, **updates)
                execution = self._append_audit(
                    execution,
                    actor_id=principal.actor_id,
                    action="%s_approved" % scope.value,
                    status_before=before,
                    status_after=status,
                    detail={"approval_id": approval.approval_id, "expires_at": approval.expires_at.isoformat()},
                )
                self._save_execution(execution)
                self._connection.execute("COMMIT")
                return approval
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def _request(
        self,
        execution: ResponseExecution,
        step: ResponseStepPlan,
        *,
        rollback: bool,
    ) -> ResponseConnectorRequest:
        operation = step.rollback_operation if rollback else step.operation
        expected = step.rollback_expected_state if rollback else step.expected_state
        if operation is None or expected is None:
            raise ResponseExecutionError("response rollback is not supported")
        payload = {
            "execution_id": execution.execution_id,
            "step_id": step.step_id,
            "operation": operation,
            "target_ref": step.target_ref,
            "expected_state": expected,
            "case_id": execution.case_id,
            "idempotency_key": "response_" + digest_payload(
                {
                    "execution_id": execution.execution_id,
                    "step_id": step.step_id,
                    "operation": operation.value,
                    "target_ref": step.target_ref,
                }
            ),
            "requested_at": utc_now(),
        }
        return ResponseConnectorRequest(
            **payload, request_sha256=digest_payload(payload)
        )

    def _record_attempt(
        self,
        execution: ResponseExecution,
        step: ResponseStepPlan,
        *,
        phase: AttemptPhase,
        accepted: bool,
        latency_ms: int,
        error_code: Optional[str],
        provider_reference: Optional[str] = None,
        evidence_reference: Optional[str] = None,
    ) -> ResponseAttempt:
        count = int(
            self._connection.execute(
                "SELECT COUNT(*) FROM response_attempts WHERE tenant_id=? AND execution_id=? AND step_id=?",
                (execution.tenant_id, execution.execution_id, step.step_id),
            ).fetchone()[0]
        ) + 1
        unsigned = ResponseAttempt(
            execution_id=execution.execution_id,
            tenant_id=execution.tenant_id,
            step_id=step.step_id,
            phase=phase,
            attempt_number=count,
            outcome=(
                "verified"
                if phase in {AttemptPhase.VERIFY, AttemptPhase.VERIFY_ROLLBACK} and accepted
                else "accepted" if accepted else "failed"
            ),
            error_code=error_code,
            latency_ms=latency_ms,
            provider_reference_sha256=(
                digest_payload(provider_reference) if provider_reference else None
            ),
            evidence_sha256=(
                digest_payload(evidence_reference) if evidence_reference else None
            ),
            attempted_at=utc_now(),
            attempt_sha256=ZERO_SHA256,
        )
        attempt = unsigned.model_copy(
            update={"attempt_sha256": self._record_digest(unsigned, "attempt_sha256")}
        )
        self._connection.execute(
            "INSERT INTO response_attempts(tenant_id,attempt_id,execution_id,step_id,phase,attempted_at,record_json) VALUES (?,?,?,?,?,?,?)",
            (
                attempt.tenant_id,
                attempt.attempt_id,
                attempt.execution_id,
                attempt.step_id,
                attempt.phase.value,
                attempt.attempted_at.isoformat(),
                self._dump(attempt),
            ),
        )
        return attempt

    def _claim(
        self,
        principal: ResponsePrincipal,
        execution_id: str,
        expected: ExecutionStatus,
        claimed: ExecutionStatus,
        approval_scope: ApprovalScope,
    ) -> tuple[ResponseExecution, ResponseApproval]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                execution = self._load_execution(principal.tenant_id, execution_id)
                if execution.status != expected:
                    raise ResponseConflictError("response execution cannot be claimed")
                control = self._control(principal.tenant_id)
                if control.kill_switch_active:
                    raise ResponseExecutionError("response kill switch is active")
                approval = self._approval_for(principal.tenant_id, execution_id, approval_scope)
                if approval is None or approval.consumed_at is not None:
                    raise ResponseExecutionError("response approval is unavailable")
                if approval.approver_id == principal.actor_id:
                    raise ResponseAuthorizationError(
                        "response approver cannot execute the approved action"
                    )
                now = utc_now()
                if not (approval.issued_at <= now < approval.expires_at):
                    raise ResponseExecutionError("response approval expired")
                if approval.plan_sha256 != self._plan_digest(execution, approval_scope):
                    raise ResponseIntegrityError("response approval plan binding mismatch")
                before = execution.status
                execution = self._signed_execution(
                    execution,
                    status=claimed,
                    version=execution.version + 1,
                    started_at=now,
                    completed_at=None,
                )
                execution = self._append_audit(
                    execution,
                    actor_id=principal.actor_id,
                    action="%s_started" % approval_scope.value,
                    status_before=before,
                    status_after=claimed,
                    detail={"approval_id": approval.approval_id},
                )
                self._save_execution(execution)
                consumed = approval.model_copy(
                    update={"consumed_at": now, "approval_sha256": ZERO_SHA256}
                )
                consumed = consumed.model_copy(
                    update={"approval_sha256": self._record_digest(consumed, "approval_sha256")}
                )
                self._connection.execute(
                    "UPDATE response_approvals SET record_json=? WHERE tenant_id=? AND approval_id=?",
                    (self._dump(consumed), consumed.tenant_id, consumed.approval_id),
                )
                self._connection.execute("COMMIT")
                return execution, consumed
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _safe_error(error: Exception, fallback: str) -> str:
        value = str(error)
        return value if re.fullmatch(r"[a-z][a-z0-9_]{2,63}", value) else fallback

    def execute(
        self, principal: ResponsePrincipal, execution_id: str
    ) -> ResponseExecution:
        self._require(principal, RESPONSE_EXECUTE)
        execution, _approval = self._claim(
            principal,
            execution_id,
            ExecutionStatus.APPROVED,
            ExecutionStatus.RUNNING,
            ApprovalScope.EXECUTE,
        )
        failed = False
        steps: List[ResponseStepPlan] = []
        initial_steps = list(execution.steps)
        for index, original in enumerate(initial_steps):
            if failed:
                steps.append(original)
                continue
            if self._control(principal.tenant_id).kill_switch_active:
                failed = True
                steps.append(
                    self._signed_step(
                        **original.model_dump(exclude={"step_sha256", "status", "last_error_code"}),
                        status=StepStatus.FAILED,
                        last_error_code="response_kill_switch_active",
                    )
                )
                execution = self._checkpoint_steps(
                    principal,
                    execution_id,
                    expected_status=ExecutionStatus.RUNNING,
                    steps=steps + initial_steps[index + 1 :],
                    action="step_blocked",
                    detail={"step_id": original.step_id, "error_code": "response_kill_switch_active"},
                )
                continue
            spec = self._connector_specs[original.connector_id]
            connector = self.connectors.get(original.connector_id)
            if connector is None:
                failed = True
                steps.append(
                    self._signed_step(
                        **original.model_dump(exclude={"step_sha256", "status", "last_error_code"}),
                        status=StepStatus.FAILED,
                        last_error_code="response_connector_not_ready",
                    )
                )
                execution = self._checkpoint_steps(
                    principal,
                    execution_id,
                    expected_status=ExecutionStatus.RUNNING,
                    steps=steps + initial_steps[index + 1 :],
                    action="step_failed",
                    detail={"step_id": original.step_id, "error_code": "response_connector_not_ready"},
                )
                continue
            request = self._request(execution, original, rollback=False)
            started = time.monotonic()
            try:
                result = connector.execute(spec, request)
                latency = min(120000, int((time.monotonic() - started) * 1000))
                with self._lock:
                    self._record_attempt(
                        execution,
                        original,
                        phase=AttemptPhase.EXECUTE,
                        accepted=result.accepted,
                        latency_ms=latency,
                        error_code=result.error_code,
                        provider_reference=result.provider_reference,
                    )
                if not result.accepted:
                    failed = True
                    error_code = result.error_code or "response_connector_rejected"
                    steps.append(
                        self._signed_step(
                            **original.model_dump(exclude={"step_sha256", "status", "attempt_count", "last_error_code", "provider_reference_sha256", "started_at", "completed_at"}),
                            status=StepStatus.FAILED,
                            attempt_count=original.attempt_count + 1,
                            last_error_code=error_code,
                            provider_reference_sha256=(digest_payload(result.provider_reference) if result.provider_reference else None),
                            started_at=utc_now(),
                            completed_at=utc_now(),
                        )
                    )
                    execution = self._checkpoint_steps(
                        principal,
                        execution_id,
                        expected_status=ExecutionStatus.RUNNING,
                        steps=steps + initial_steps[index + 1 :],
                        action="step_failed",
                        detail={"step_id": original.step_id, "error_code": error_code},
                    )
                    continue
                verify_started = time.monotonic()
                verification = connector.verify(spec, request)
                verify_latency = min(120000, int((time.monotonic() - verify_started) * 1000))
                verified = verification.verified and verification.observed_state == original.expected_state
                error_code = None if verified else (verification.error_code or "response_state_mismatch")
                with self._lock:
                    self._record_attempt(
                        execution,
                        original,
                        phase=AttemptPhase.VERIFY,
                        accepted=verified,
                        latency_ms=verify_latency,
                        error_code=error_code,
                        evidence_reference=verification.evidence_reference,
                    )
                failed = not verified
                steps.append(
                    self._signed_step(
                        **original.model_dump(exclude={"step_sha256", "status", "attempt_count", "last_error_code", "provider_reference_sha256", "verification_evidence_sha256", "started_at", "completed_at"}),
                        status=StepStatus.SUCCEEDED if verified else StepStatus.FAILED,
                        attempt_count=original.attempt_count + 2,
                        last_error_code=error_code,
                        provider_reference_sha256=(digest_payload(result.provider_reference) if result.provider_reference else None),
                        verification_evidence_sha256=(digest_payload(verification.evidence_reference) if verification.evidence_reference else None),
                        started_at=utc_now(),
                        completed_at=utc_now(),
                    )
                )
                execution = self._checkpoint_steps(
                    principal,
                    execution_id,
                    expected_status=ExecutionStatus.RUNNING,
                    steps=steps + initial_steps[index + 1 :],
                    action="step_verified" if verified else "step_failed",
                    detail={"step_id": original.step_id, "verified": verified, "error_code": error_code},
                )
            except Exception as exc:
                failed = True
                code = self._safe_error(exc, "response_connector_failure")
                with self._lock:
                    self._record_attempt(
                        execution,
                        original,
                        phase=AttemptPhase.EXECUTE,
                        accepted=False,
                        latency_ms=min(120000, int((time.monotonic() - started) * 1000)),
                        error_code=code,
                    )
                steps.append(
                    self._signed_step(
                        **original.model_dump(exclude={"step_sha256", "status", "attempt_count", "last_error_code", "started_at", "completed_at"}),
                        status=StepStatus.FAILED,
                        attempt_count=original.attempt_count + 1,
                        last_error_code=code,
                        started_at=utc_now(),
                        completed_at=utc_now(),
                    )
                )
                execution = self._checkpoint_steps(
                    principal,
                    execution_id,
                    expected_status=ExecutionStatus.RUNNING,
                    steps=steps + initial_steps[index + 1 :],
                    action="step_failed",
                    detail={"step_id": original.step_id, "error_code": code},
                )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                current = self._load_execution(principal.tenant_id, execution_id)
                if current.status != ExecutionStatus.RUNNING:
                    raise ResponseConflictError("response execution claim was lost")
                status = ExecutionStatus.FAILED if failed else ExecutionStatus.SUCCEEDED
                execution = self._signed_execution(
                    current,
                    status=status,
                    steps=steps,
                    version=current.version + 1,
                    completed_at=utc_now(),
                )
                execution = self._append_audit(
                    execution,
                    actor_id=principal.actor_id,
                    action="execution_completed" if not failed else "execution_failed",
                    status_before=ExecutionStatus.RUNNING,
                    status_after=status,
                    detail={"successful_steps": sum(item.status == StepStatus.SUCCEEDED for item in steps)},
                )
                self._save_execution(execution)
                self._connection.execute("COMMIT")
                return execution
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def request_rollback(
        self,
        principal: ResponsePrincipal,
        execution_id: str,
        *,
        expected_version: int,
        reason: str,
    ) -> ResponseExecution:
        self._require(principal, RESPONSE_OPERATE)
        redacted = str(Redactor().redact({"reason": reason}).value["reason"])
        if not 3 <= len(redacted) <= 512:
            raise ValueError("response rollback reason is invalid")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                execution = self._load_execution(principal.tenant_id, execution_id)
                if execution.version != expected_version:
                    raise ResponseConflictError("response execution version conflict")
                if execution.status not in {ExecutionStatus.SUCCEEDED, ExecutionStatus.FAILED}:
                    raise ResponseConflictError("response execution cannot be rolled back")
                completed = [step for step in execution.steps if step.status == StepStatus.SUCCEEDED]
                if not completed or any(step.rollback_operation is None for step in completed):
                    raise ResponseExecutionError("response rollback is not fully supported")
                before = execution.status
                execution = self._signed_execution(
                    execution,
                    status=ExecutionStatus.ROLLBACK_AWAITING_APPROVAL,
                    rollback_requested_by=principal.actor_id,
                    version=execution.version + 1,
                )
                execution = self._append_audit(
                    execution,
                    actor_id=principal.actor_id,
                    action="rollback_requested",
                    status_before=before,
                    status_after=execution.status,
                    detail={"reason": redacted},
                )
                self._save_execution(execution)
                self._connection.execute("COMMIT")
                return execution
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def rollback(
        self, principal: ResponsePrincipal, execution_id: str
    ) -> ResponseExecution:
        self._require(principal, RESPONSE_EXECUTE)
        execution, _approval = self._claim(
            principal,
            execution_id,
            ExecutionStatus.ROLLBACK_APPROVED,
            ExecutionStatus.ROLLING_BACK,
            ApprovalScope.ROLLBACK,
        )
        failed = False
        by_id = {step.step_id: step for step in execution.steps}
        rollback_order = list(reversed(execution.steps))
        for original in rollback_order:
            if original.status != StepStatus.SUCCEEDED:
                continue
            if self._control(principal.tenant_id).kill_switch_active:
                failed = True
                by_id[original.step_id] = self._signed_step(
                    **original.model_dump(exclude={"step_sha256", "status", "last_error_code"}),
                    status=StepStatus.ROLLBACK_FAILED,
                    last_error_code="response_kill_switch_active",
                )
                execution = self._checkpoint_steps(
                    principal,
                    execution_id,
                    expected_status=ExecutionStatus.ROLLING_BACK,
                    steps=[by_id[item.step_id] for item in execution.steps],
                    action="rollback_step_blocked",
                    detail={
                        "step_id": original.step_id,
                        "error_code": "response_kill_switch_active",
                    },
                )
                break
            connector = self.connectors.get(original.connector_id)
            spec = self._connector_specs[original.connector_id]
            if connector is None:
                failed = True
                by_id[original.step_id] = self._signed_step(
                    **original.model_dump(exclude={"step_sha256", "status", "last_error_code"}),
                    status=StepStatus.ROLLBACK_FAILED,
                    last_error_code="response_connector_not_ready",
                )
                execution = self._checkpoint_steps(
                    principal,
                    execution_id,
                    expected_status=ExecutionStatus.ROLLING_BACK,
                    steps=[by_id[item.step_id] for item in execution.steps],
                    action="rollback_step_failed",
                    detail={
                        "step_id": original.step_id,
                        "error_code": "response_connector_not_ready",
                    },
                )
                break
            request = self._request(execution, original, rollback=True)
            started = time.monotonic()
            try:
                result = connector.rollback(spec, request)
                latency = min(120000, int((time.monotonic() - started) * 1000))
                with self._lock:
                    self._record_attempt(
                        execution,
                        original,
                        phase=AttemptPhase.ROLLBACK,
                        accepted=result.accepted,
                        latency_ms=latency,
                        error_code=result.error_code,
                        provider_reference=result.provider_reference,
                    )
                if not result.accepted:
                    raise RuntimeError(result.error_code or "response_rollback_rejected")
                verification = connector.verify(spec, request)
                verified = verification.verified and verification.observed_state == original.rollback_expected_state
                error_code = None if verified else (verification.error_code or "response_rollback_state_mismatch")
                with self._lock:
                    self._record_attempt(
                        execution,
                        original,
                        phase=AttemptPhase.VERIFY_ROLLBACK,
                        accepted=verified,
                        latency_ms=0,
                        error_code=error_code,
                        evidence_reference=verification.evidence_reference,
                    )
                if not verified:
                    raise RuntimeError(error_code)
                by_id[original.step_id] = self._signed_step(
                    **original.model_dump(exclude={"step_sha256", "status", "attempt_count", "last_error_code", "completed_at"}),
                    status=StepStatus.ROLLED_BACK,
                    attempt_count=original.attempt_count + 2,
                    last_error_code=None,
                    completed_at=utc_now(),
                )
                execution = self._checkpoint_steps(
                    principal,
                    execution_id,
                    expected_status=ExecutionStatus.ROLLING_BACK,
                    steps=[by_id[item.step_id] for item in execution.steps],
                    action="rollback_step_verified",
                    detail={"step_id": original.step_id, "verified": True},
                )
            except Exception as exc:
                failed = True
                code = self._safe_error(exc, "response_rollback_failure")
                by_id[original.step_id] = self._signed_step(
                    **original.model_dump(exclude={"step_sha256", "status", "last_error_code", "completed_at"}),
                    status=StepStatus.ROLLBACK_FAILED,
                    last_error_code=code,
                    completed_at=utc_now(),
                )
                execution = self._checkpoint_steps(
                    principal,
                    execution_id,
                    expected_status=ExecutionStatus.ROLLING_BACK,
                    steps=[by_id[item.step_id] for item in execution.steps],
                    action="rollback_step_failed",
                    detail={"step_id": original.step_id, "error_code": code},
                )
                break
        steps = [by_id[item.step_id] for item in execution.steps]
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                current = self._load_execution(principal.tenant_id, execution_id)
                status = ExecutionStatus.ROLLBACK_FAILED if failed else ExecutionStatus.ROLLED_BACK
                execution = self._signed_execution(
                    current,
                    status=status,
                    steps=steps,
                    version=current.version + 1,
                    completed_at=utc_now(),
                )
                execution = self._append_audit(
                    execution,
                    actor_id=principal.actor_id,
                    action="rollback_failed" if failed else "rollback_completed",
                    status_before=ExecutionStatus.ROLLING_BACK,
                    status_after=status,
                    detail={"rolled_back_steps": sum(item.status == StepStatus.ROLLED_BACK for item in steps)},
                )
                self._save_execution(execution)
                self._connection.execute("COMMIT")
                return execution
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def set_kill_switch(
        self,
        principal: ResponsePrincipal,
        *,
        active: bool,
        expected_version: int,
        reason: str,
    ) -> ResponseControl:
        self._require(principal, RESPONSE_ADMIN)
        redacted = str(Redactor().redact({"reason": reason}).value["reason"])
        if not 3 <= len(redacted) <= 512:
            raise ValueError("response kill-switch reason is invalid")
        self._ensure_tenant_seed(principal.tenant_id)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                current = self._control(principal.tenant_id)
                if current.version != expected_version:
                    raise ResponseConflictError("response control version conflict")
                if current.kill_switch_active == active:
                    raise ResponseConflictError("response kill switch already has that state")
                unsigned = current.model_copy(
                    update={
                        "kill_switch_active": active,
                        "version": current.version + 1,
                        "changed_by": principal.actor_id,
                        "reason": redacted,
                        "changed_at": utc_now(),
                        "control_sha256": ZERO_SHA256,
                    }
                )
                control = unsigned.model_copy(
                    update={"control_sha256": self._record_digest(unsigned, "control_sha256")}
                )
                self._connection.execute(
                    "UPDATE response_control SET record_json=? WHERE tenant_id=?",
                    (self._dump(control), principal.tenant_id),
                )
                self._connection.execute("COMMIT")
                return control
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def control(self, principal: ResponsePrincipal) -> ResponseControl:
        self._require(principal, RESPONSE_READ)
        self._ensure_tenant_seed(principal.tenant_id)
        with self._lock:
            return self._control(principal.tenant_id)

    def connectors_status(self, principal: ResponsePrincipal) -> List[ResponseConnectorStatus]:
        self._require(principal, RESPONSE_READ)
        return [
            ResponseConnectorStatus(
                connector_id=item.connector_id,
                name=item.name,
                operations=item.operations,
                enabled=item.enabled,
                ready=item.connector_id in self.connectors,
            )
            for item in self.policy.connectors
        ]

    def list_playbooks(
        self, principal: ResponsePrincipal, *, limit: int = 100, offset: int = 0
    ) -> ResponsePlaybookPage:
        self._require(principal, RESPONSE_READ)
        if not 1 <= limit <= MAX_PLAYBOOK_PAGE or offset < 0:
            raise ValueError("response playbook page is invalid")
        self._ensure_tenant_seed(principal.tenant_id)
        with self._lock:
            count = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM response_playbooks WHERE tenant_id=?",
                    (principal.tenant_id,),
                ).fetchone()[0]
            )
            rows = self._connection.execute(
                "SELECT record_json FROM response_playbooks WHERE tenant_id=? ORDER BY playbook_id,version DESC LIMIT ? OFFSET ?",
                (principal.tenant_id, limit, offset),
            ).fetchall()
            return ResponsePlaybookPage(
                playbooks=[self._verify_playbook(row["record_json"]) for row in rows],
                count=count,
                limit=limit,
                offset=offset,
            )

    def create_playbook_draft(
        self,
        principal: ResponsePrincipal,
        definition: ResponsePlaybookDefinition,
    ) -> ResponsePlaybookRecord:
        self._require(principal, RESPONSE_AUTHOR)
        self._ensure_tenant_seed(principal.tenant_id)
        transformed = Redactor().redact(definition.model_dump(mode="json"))
        definition_payload = dict(transformed.value)
        definition_payload["definition_sha256"] = ZERO_SHA256
        definition = ResponsePlaybookDefinition.model_validate(definition_payload)
        for step in definition.steps:
            spec = self._connector_specs.get(step.connector_id)
            if spec is None or step.operation not in spec.operations:
                raise ValueError("response draft references an unavailable operation")
        now = utc_now()
        unsigned = ResponsePlaybookRecord(
            tenant_id=principal.tenant_id,
            definition=definition,
            status=PlaybookStatus.DRAFT,
            author_id=principal.actor_id,
            created_at=now,
            updated_at=now,
            record_sha256=ZERO_SHA256,
        )
        record = unsigned.model_copy(
            update={"record_sha256": self._record_digest(unsigned, "record_sha256")}
        )
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO response_playbooks(tenant_id,playbook_id,version,status,record_json) VALUES (?,?,?,?,?)",
                    (
                        record.tenant_id,
                        definition.playbook_id,
                        definition.version,
                        record.status.value,
                        self._dump(record),
                    ),
                )
            except sqlite3.IntegrityError:
                raise ResponseConflictError("response playbook version already exists") from None
        return record

    def playbook_action(
        self,
        principal: ResponsePrincipal,
        playbook_id: str,
        version: int,
        *,
        action: str,
        expected_revision: int,
        comment: str,
    ) -> ResponsePlaybookRecord:
        if action == "submit":
            self._require(principal, RESPONSE_AUTHOR)
        elif action in {"approve", "reject"}:
            self._require(principal, RESPONSE_REVIEW)
        elif action in {"activate", "retire"}:
            self._require(principal, RESPONSE_ADMIN)
        else:
            raise ValueError("response playbook action is invalid")
        redacted = str(Redactor().redact({"comment": comment}).value["comment"])
        if not 3 <= len(redacted) <= 512:
            raise ValueError("response playbook comment is invalid")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT record_json FROM response_playbooks WHERE tenant_id=? AND playbook_id=? AND version=?",
                    (principal.tenant_id, playbook_id, version),
                ).fetchone()
                if row is None:
                    raise KeyError(playbook_id)
                record = self._verify_playbook(row["record_json"])
                if record.revision != expected_revision:
                    raise ResponseConflictError("response playbook revision conflict")
                transitions = {
                    "submit": (PlaybookStatus.DRAFT, PlaybookStatus.IN_REVIEW),
                    "approve": (PlaybookStatus.IN_REVIEW, PlaybookStatus.APPROVED),
                    "reject": (PlaybookStatus.IN_REVIEW, PlaybookStatus.REJECTED),
                    "activate": (PlaybookStatus.APPROVED, PlaybookStatus.ACTIVE),
                    "retire": (PlaybookStatus.ACTIVE, PlaybookStatus.RETIRED),
                }
                before, after = transitions[action]
                if record.status != before:
                    raise ResponseConflictError("response playbook transition is invalid")
                if action == "submit" and record.author_id != principal.actor_id and RESPONSE_ADMIN not in principal.permissions:
                    raise ResponseAuthorizationError("only the response author can submit")
                if action in {"approve", "reject"} and record.author_id == principal.actor_id:
                    raise ResponseAuthorizationError("response author cannot review their playbook")
                now = utc_now()
                updates: Dict[str, Any] = {
                    "status": after,
                    "revision": record.revision + 1,
                    "updated_at": now,
                    "record_sha256": ZERO_SHA256,
                }
                if action in {"approve", "reject"}:
                    updates.update(
                        reviewer_id=principal.actor_id,
                        review_comment=redacted,
                        reviewed_at=now,
                    )
                if action == "activate":
                    if record.reviewer_id is None or record.reviewer_id == principal.actor_id:
                        raise ResponseAuthorizationError("response activation requires independent review")
                    updates["activated_at"] = now
                    active_rows = self._connection.execute(
                        "SELECT version,record_json FROM response_playbooks WHERE tenant_id=? AND playbook_id=? AND status=?",
                        (principal.tenant_id, playbook_id, PlaybookStatus.ACTIVE.value),
                    ).fetchall()
                    for active_row in active_rows:
                        active_record = self._verify_playbook(active_row["record_json"])
                        retired_unsigned = active_record.model_copy(
                            update={
                                "status": PlaybookStatus.RETIRED,
                                "revision": active_record.revision + 1,
                                "updated_at": now,
                                "record_sha256": ZERO_SHA256,
                            }
                        )
                        retired = retired_unsigned.model_copy(
                            update={"record_sha256": self._record_digest(retired_unsigned, "record_sha256")}
                        )
                        self._connection.execute(
                            "UPDATE response_playbooks SET status=?,record_json=? WHERE tenant_id=? AND playbook_id=? AND version=?",
                            (
                                PlaybookStatus.RETIRED.value,
                                self._dump(retired),
                                principal.tenant_id,
                                playbook_id,
                                active_row["version"],
                            ),
                        )
                unsigned = record.model_copy(update=updates)
                updated = unsigned.model_copy(
                    update={"record_sha256": self._record_digest(unsigned, "record_sha256")}
                )
                self._connection.execute(
                    "UPDATE response_playbooks SET status=?,record_json=? WHERE tenant_id=? AND playbook_id=? AND version=?",
                    (
                        updated.status.value,
                        self._dump(updated),
                        principal.tenant_id,
                        playbook_id,
                        version,
                    ),
                )
                self._connection.execute("COMMIT")
                return updated
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def health(self, principal: ResponsePrincipal) -> ResponseHealth:
        self._require(principal, RESPONSE_READ)
        self._ensure_tenant_seed(principal.tenant_id)
        control = self._control(principal.tenant_id)
        # Health is an exact tenant-wide control-plane view, not a page summary.
        # Verify every signed record before using it so a forged or truncated row
        # cannot silently skew readiness and failure metrics.
        executions = [
            self._verify_execution_record(row["record_json"])
            for row in self._connection.execute(
                "SELECT record_json FROM response_executions WHERE tenant_id=?",
                (principal.tenant_id,),
            ).fetchall()
        ]
        for execution in executions:
            self._audit_rows(execution)
        attempts = [
            attempt
            for execution in executions
            for attempt in self._attempt_rows(execution)
        ]
        status_count = lambda *values: sum(item.status in values for item in executions)
        durations = [
            int((item.completed_at - item.started_at).total_seconds() * 1000)
            for item in executions
            if item.started_at is not None and item.completed_at is not None
        ]
        active_playbooks = int(
            self._connection.execute(
                "SELECT COUNT(*) FROM response_playbooks WHERE tenant_id=? AND status=?",
                (principal.tenant_id, PlaybookStatus.ACTIVE.value),
            ).fetchone()[0]
        )
        return ResponseHealth(
            tenant_id=principal.tenant_id,
            total_executions=len(executions),
            dry_runs=status_count(ExecutionStatus.DRY_RUN_SUCCEEDED),
            awaiting_approval=status_count(
                ExecutionStatus.AWAITING_APPROVAL, ExecutionStatus.APPROVED
            ),
            running=status_count(ExecutionStatus.RUNNING, ExecutionStatus.ROLLING_BACK),
            succeeded=status_count(ExecutionStatus.SUCCEEDED),
            failed=status_count(ExecutionStatus.FAILED, ExecutionStatus.ROLLBACK_FAILED),
            rollback_pending=status_count(
                ExecutionStatus.ROLLBACK_AWAITING_APPROVAL,
                ExecutionStatus.ROLLBACK_APPROVED,
            ),
            rolled_back=status_count(ExecutionStatus.ROLLED_BACK),
            verification_failures=sum(
                item.phase in {AttemptPhase.VERIFY, AttemptPhase.VERIFY_ROLLBACK}
                and item.outcome == "failed"
                for item in attempts
            ),
            active_playbooks=active_playbooks,
            configured_connectors=len(self.policy.connectors),
            ready_connectors=len(self.connectors),
            kill_switch_active=control.kill_switch_active,
            kill_switch_version=control.version,
            average_execution_ms=(sum(durations) // len(durations) if durations else 0),
            policy_version=self.policy.policy_version,
            policy_sha256=self.policy.policy_sha256,
            observed_at=utc_now(),
        )


def response_service_from_environment(
    database_path: str,
    policy_path: str,
    *,
    tenant_id: str,
    environment: Optional[Mapping[str, str]] = None,
) -> tuple[ResponseAutomationService, ResponsePrincipal]:
    values = environment if environment is not None else os.environ
    policy = load_response_policy(policy_path)
    connectors: Dict[str, ResponseConnector] = {}
    for spec in policy.connectors:
        credential = values.get(spec.credential_env, "")
        if spec.enabled and credential:
            connectors[spec.connector_id] = HttpResponseConnector(credential=credential)
    principal = ResponsePrincipal(
        tenant_id=tenant_id,
        actor_id="system://local-response-service",
        permissions={
            RESPONSE_READ,
            RESPONSE_OPERATE,
        },
    )
    return ResponseAutomationService(
        database_path, policy=policy, connectors=connectors
    ), principal


__all__ = [
    "APPROVAL_MAX_MINUTES",
    "ApprovalScope",
    "AttemptPhase",
    "ExecutionMode",
    "ExecutionStatus",
    "HttpResponseConnector",
    "PlaybookStatus",
    "PlaybookStepDefinition",
    "PlaybookTrigger",
    "RESPONSE_ADMIN",
    "RESPONSE_APPROVE",
    "RESPONSE_AUTHOR",
    "RESPONSE_EXECUTE",
    "RESPONSE_OPERATE",
    "RESPONSE_READ",
    "RESPONSE_REVIEW",
    "ResponseApproval",
    "ResponseApprovalRequest",
    "ResponseAttempt",
    "ResponseAuditEntry",
    "ResponseAutomationPolicy",
    "ResponseAutomationService",
    "ResponseAuthorizationError",
    "ResponseConflictError",
    "ResponseConnector",
    "ResponseConnectorRequest",
    "ResponseConnectorResult",
    "ResponseConnectorSpec",
    "ResponseConnectorStatus",
    "ResponseControl",
    "ResponseExecution",
    "ResponseExecutionDetail",
    "ResponseExecutionError",
    "ResponseExecutionPage",
    "ResponseEmptyRequest",
    "ResponseHealth",
    "ResponseIntegrityError",
    "ResponseKillSwitchRequest",
    "ResponseMutationRequest",
    "ResponseOperation",
    "ResponsePlaybookDefinition",
    "ResponsePlaybookActionRequest",
    "ResponsePlaybookCreateRequest",
    "ResponsePlaybookPage",
    "ResponsePlaybookRecord",
    "ResponsePrincipal",
    "ResponseStepPlan",
    "ResponseVerificationResult",
    "StepStatus",
    "TargetSelector",
    "hash_reference",
    "load_response_policy",
    "response_service_from_environment",
]
