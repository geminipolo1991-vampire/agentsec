"""Durable, policy-routed escalation notification outbox and delivery audit."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import ipaddress
import json
import os
import re
import socket
import sqlite3
import string
import threading
import time
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Mapping, Optional, Protocol, Sequence, Set
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import Field, field_validator, model_validator

from .contracts import (
    EscalationLevel,
    StrictModel,
    new_id,
    utc_now,
)
from .crypto import canonical_bytes
from .redaction import Redactor

if TYPE_CHECKING:
    from .contracts import PipelineResult


NOTIFICATION_READ = "notification:read"
NOTIFICATION_ROUTE = "notification:route"
NOTIFICATION_DELIVER = "notification:deliver"
NOTIFICATION_ACK = "notification:acknowledge"
NOTIFICATION_ADMIN = "notification:admin"
NOTIFICATION_POLICY_VERSION = "notification-policy-2026-07-24.1"
MAX_NOTIFICATION_PAGE = 200
MAX_DELIVERY_BATCH = 100
MAX_DESTINATIONS = 32
MAX_ROUTES = 32
MAX_TEMPLATES = 64
MAX_SCHEDULES = 32
MAX_AUDIT_ENTRIES = 2000
MAX_HTTP_RESPONSE_BYTES = 65536
MAX_REDRIVES = 5
IN_FLIGHT_LEASE_SECONDS = 60
ZERO_SHA256 = "0" * 64


class NotificationAuthorizationError(PermissionError):
    """Raised when a notification principal lacks tenant or operation scope."""


class NotificationConflictError(RuntimeError):
    """Raised for stale lifecycle state or conflicting durable identities."""


class NotificationRoutingError(RuntimeError):
    """Raised when an escalation has no complete governed route."""


class NotificationChannel(str, Enum):
    ON_CALL = "on_call"
    TICKET = "ticket"
    EMAIL = "email"
    MESSAGING = "messaging"


class DeliveryStatus(str, Enum):
    PENDING = "pending"
    IN_FLIGHT = "in_flight"
    RETRY_SCHEDULED = "retry_scheduled"
    ACK_PENDING = "ack_pending"
    DELIVERED = "delivered"
    ACKNOWLEDGED = "acknowledged"
    DEAD_LETTER = "dead_letter"


class DeliveryState(str, Enum):
    PENDING = "pending"
    PARTIAL = "partial"
    DELIVERED = "delivered"
    DEAD_LETTER = "dead_letter"


class AcknowledgmentState(str, Enum):
    PENDING = "pending"
    ACKNOWLEDGED = "acknowledged"
    BREACHED = "breached"


class AttemptOutcome(str, Enum):
    DELIVERED = "delivered"
    ACK_PENDING = "ack_pending"
    RETRY_SCHEDULED = "retry_scheduled"
    DEAD_LETTER = "dead_letter"


class NotificationPrincipal(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(
        pattern=r"^(analyst|system|workload)://[A-Za-z0-9_.@/-]+$",
        max_length=256,
    )
    permissions: Set[str] = Field(default_factory=set, max_length=16)

    @field_validator("permissions")
    @classmethod
    def valid_permissions(cls, value: Set[str]) -> Set[str]:
        if any(re.fullmatch(r"notification:[a-z]+", item) is None for item in value):
            raise ValueError("notification permissions must use notification:operation")
        return value


def validate_notification_endpoint(endpoint: str, allowed_hosts: Sequence[str]) -> str:
    parsed = urlsplit(endpoint)
    host = (parsed.hostname or "").lower()
    normalized_hosts = {item.lower() for item in allowed_hosts}
    if parsed.scheme != "https" or not host:
        raise ValueError("notification endpoint must use HTTPS")
    if host not in normalized_hosts:
        raise ValueError("notification endpoint host is not allowlisted")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("notification endpoint contains prohibited URL components")
    if parsed.port not in {None, 443}:
        raise ValueError("notification endpoint must use port 443")
    if not parsed.path.startswith("/") or "//" in parsed.path:
        raise ValueError("notification endpoint path is invalid")
    if host == "localhost" or host.endswith(".local"):
        raise ValueError("notification endpoint cannot use a local host")
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global:
        raise ValueError("notification endpoint cannot use a non-public address")
    return endpoint


class NotificationDestination(StrictModel):
    destination_id: str = Field(pattern=r"^destination://[A-Za-z0-9_.@/-]+$")
    name: str = Field(min_length=3, max_length=128)
    channel: NotificationChannel
    endpoint: str = Field(min_length=12, max_length=512)
    allowed_hosts: List[str] = Field(min_length=1, max_length=16)
    credential_env: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    provider_ack_required: bool = False
    enabled: bool = True

    @model_validator(mode="after")
    def safe_endpoint(self) -> "NotificationDestination":
        if len(set(self.allowed_hosts)) != len(self.allowed_hosts):
            raise ValueError("notification allowed hosts must be unique")
        validate_notification_endpoint(self.endpoint, self.allowed_hosts)
        return self


class OnCallSchedule(StrictModel):
    schedule_id: str = Field(pattern=r"^schedule://[A-Za-z0-9_.@/-]+$")
    name: str = Field(min_length=3, max_length=128)
    timezone_name: str = Field(min_length=1, max_length=64)
    starts_at: datetime
    rotation_minutes: int = Field(ge=15, le=10080)
    member_ids: List[str] = Field(min_length=1, max_length=100)
    version: int = Field(ge=1)

    @field_validator("member_ids")
    @classmethod
    def valid_members(cls, value: List[str]) -> List[str]:
        if len(set(value)) != len(value) or any(
            re.fullmatch(r"^analyst://[A-Za-z0-9_.@/-]+$", item) is None
            for item in value
        ):
            raise ValueError("on-call members must be unique analyst identities")
        return value

    @model_validator(mode="after")
    def valid_schedule(self) -> "OnCallSchedule":
        if self.starts_at.tzinfo is None or self.starts_at.utcoffset() is None:
            raise ValueError("on-call schedule start must include a timezone")
        try:
            ZoneInfo(self.timezone_name)
        except ZoneInfoNotFoundError:
            raise ValueError("on-call schedule timezone is unknown") from None
        return self


TEMPLATE_FIELDS = {
    "notification_id",
    "finding_id",
    "alert_type",
    "severity",
    "priority",
    "decision",
    "escalation_level",
    "queue",
    "case_id",
    "correlation_incident_id",
    "on_call_actor",
}


def _template_fields(value: str) -> Set[str]:
    fields: Set[str] = set()
    try:
        parsed = string.Formatter().parse(value)
        for _, field_name, format_spec, conversion in parsed:
            if field_name is None:
                continue
            if not field_name or format_spec or conversion or "." in field_name or "[" in field_name:
                raise ValueError("notification template uses an unsafe expression")
            fields.add(field_name)
    except ValueError:
        raise ValueError("notification template syntax is invalid") from None
    if not fields.issubset(TEMPLATE_FIELDS):
        raise ValueError("notification template uses an unknown field")
    return fields


class NotificationTemplate(StrictModel):
    template_id: str = Field(pattern=r"^template://[A-Za-z0-9_.@/-]+$")
    name: str = Field(min_length=3, max_length=128)
    channel: NotificationChannel
    subject_template: str = Field(min_length=3, max_length=256)
    body_template: str = Field(min_length=3, max_length=1024)
    version: int = Field(ge=1)

    @model_validator(mode="after")
    def bounded_fields(self) -> "NotificationTemplate":
        _template_fields(self.subject_template)
        _template_fields(self.body_template)
        return self


class NotificationRoute(StrictModel):
    route_id: str = Field(pattern=r"^route://[A-Za-z0-9_.@/-]+$")
    name: str = Field(min_length=3, max_length=128)
    priorities: List[str] = Field(min_length=1, max_length=4)
    escalation_levels: List[EscalationLevel] = Field(min_length=1, max_length=3)
    alert_types: List[str] = Field(default_factory=list, max_length=32)
    destination_templates: Dict[str, str] = Field(min_length=1, max_length=16)
    on_call_schedule_id: str = Field(pattern=r"^schedule://[A-Za-z0-9_.@/-]+$")
    acknowledgment_minutes: int = Field(ge=1, le=1440)
    max_attempts: int = Field(ge=1, le=20)
    retry_base_seconds: int = Field(ge=1, le=3600)
    enabled: bool = True

    @field_validator("priorities")
    @classmethod
    def valid_priorities(cls, value: List[str]) -> List[str]:
        if len(set(value)) != len(value) or not set(value).issubset(
            {"P0", "P1", "P2", "P3"}
        ):
            raise ValueError("notification route priority is invalid")
        return value

    @field_validator("alert_types")
    @classmethod
    def valid_alert_types(cls, value: List[str]) -> List[str]:
        if len(set(value)) != len(value) or any(
            re.fullmatch(r"^[a-z][a-z0-9_]{2,63}$", item) is None
            for item in value
        ):
            raise ValueError("notification route alert type is invalid")
        return value

    @field_validator("escalation_levels")
    @classmethod
    def unique_levels(
        cls, value: List[EscalationLevel]
    ) -> List[EscalationLevel]:
        if len(set(value)) != len(value):
            raise ValueError("notification escalation levels must be unique")
        return value

    @model_validator(mode="after")
    def excludes_none(self) -> "NotificationRoute":
        if EscalationLevel.NONE in self.escalation_levels:
            raise ValueError("non-escalated results cannot have a notification route")
        return self


class NotificationPolicy(StrictModel):
    schema_version: str = "1.0.0"
    policy_version: str = Field(min_length=3, max_length=128)
    destinations: List[NotificationDestination] = Field(min_length=1, max_length=MAX_DESTINATIONS)
    schedules: List[OnCallSchedule] = Field(min_length=1, max_length=MAX_SCHEDULES)
    templates: List[NotificationTemplate] = Field(min_length=1, max_length=MAX_TEMPLATES)
    routes: List[NotificationRoute] = Field(min_length=1, max_length=MAX_ROUTES)
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def coherent_references(self) -> "NotificationPolicy":
        for collection, label, attr in (
            (self.destinations, "destination", "destination_id"),
            (self.schedules, "schedule", "schedule_id"),
            (self.templates, "template", "template_id"),
            (self.routes, "route", "route_id"),
        ):
            values = [getattr(item, attr) for item in collection]
            if len(values) != len(set(values)):
                raise ValueError("notification %s IDs must be unique" % label)
        destinations = {item.destination_id: item for item in self.destinations}
        templates = {item.template_id: item for item in self.templates}
        schedules = {item.schedule_id for item in self.schedules}
        for route in self.routes:
            if route.on_call_schedule_id not in schedules:
                raise ValueError("notification route references an unknown schedule")
            for destination_id, template_id in route.destination_templates.items():
                destination = destinations.get(destination_id)
                template = templates.get(template_id)
                if destination is None or template is None:
                    raise ValueError("notification route has an unknown destination/template")
                if destination.channel != template.channel:
                    raise ValueError("notification destination/template channels differ")
        return self


class NotificationMessage(StrictModel):
    notification_id: str = Field(pattern=r"^ntf_[0-9a-f]{32}$")
    tenant_id: str = Field(min_length=1, max_length=128)
    channel: NotificationChannel
    recipient: str = Field(pattern=r"^analyst://[A-Za-z0-9_.@/-]+$")
    subject: str = Field(min_length=3, max_length=256)
    body: str = Field(min_length=3, max_length=1024)
    idempotency_key: str = Field(pattern=r"^notify_[0-9a-f]{64}$")
    message_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class NotificationRecord(StrictModel):
    schema_version: str = "1.0.0"
    notification_id: str = Field(default_factory=lambda: new_id("ntf"), pattern=r"^ntf_[0-9a-f]{32}$")
    tenant_id: str = Field(min_length=1, max_length=128)
    finding_id: str = Field(pattern=r"^fnd_[A-Za-z0-9]+$")
    alert_id: str = Field(pattern=r"^alr_[A-Za-z0-9]+$")
    alert_type: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    priority: str = Field(pattern=r"^P[0-3]$")
    decision: str = Field(pattern=r"^(deny|require_approval|allow_with_obligations|allow)$")
    escalation_level: EscalationLevel
    queue: str = Field(min_length=1, max_length=128)
    case_id: Optional[str] = Field(default=None, pattern=r"^case_[0-9a-f]{32}$")
    correlation_incident_id: Optional[str] = Field(default=None, pattern=r"^inc_[A-Za-z0-9]+$")
    route_id: str = Field(pattern=r"^route://[A-Za-z0-9_.@/-]+$")
    policy_version: str = Field(min_length=3, max_length=128)
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    on_call_actor: str = Field(pattern=r"^analyst://[A-Za-z0-9_.@/-]+$")
    schedule_id: str = Field(pattern=r"^schedule://[A-Za-z0-9_.@/-]+$")
    schedule_version: int = Field(ge=1)
    delivery_state: DeliveryState = DeliveryState.PENDING
    acknowledgment_state: AcknowledgmentState = AcknowledgmentState.PENDING
    acknowledgment_due_at: datetime
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = Field(
        default=None, pattern=r"^(analyst|system)://[A-Za-z0-9_.@/-]+$"
    )
    acknowledgment_note: Optional[str] = Field(default=None, max_length=512)
    version: int = Field(default=1, ge=1)
    created_at: datetime
    updated_at: datetime
    audit_count: int = Field(default=0, ge=0, le=MAX_AUDIT_ENTRIES)
    audit_head_sha256: str = Field(default=ZERO_SHA256, pattern=r"^[0-9a-f]{64}$")
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def coherent_state(self) -> "NotificationRecord":
        timestamps = [self.created_at, self.updated_at, self.acknowledgment_due_at]
        if self.acknowledged_at is not None:
            timestamps.append(self.acknowledged_at)
        if any(item.tzinfo is None or item.utcoffset() is None for item in timestamps):
            raise ValueError("notification timestamps must include a timezone")
        if self.updated_at < self.created_at or self.acknowledgment_due_at < self.created_at:
            raise ValueError("notification timestamps are not ordered")
        acknowledged = self.acknowledgment_state == AcknowledgmentState.ACKNOWLEDGED
        if acknowledged != (self.acknowledged_at is not None):
            raise ValueError("notification acknowledgment state is inconsistent")
        if acknowledged != (self.acknowledged_by is not None):
            raise ValueError("notification acknowledgment actor is inconsistent")
        if self.audit_count == 0 and self.audit_head_sha256 != ZERO_SHA256:
            raise ValueError("empty notification audit must use zero hash")
        if self.audit_count > 0 and self.audit_head_sha256 == ZERO_SHA256:
            raise ValueError("notification audit head is required")
        return self


class NotificationDelivery(StrictModel):
    delivery_id: str = Field(default_factory=lambda: new_id("ndv"), pattern=r"^ndv_[0-9a-f]{32}$")
    notification_id: str = Field(pattern=r"^ntf_[0-9a-f]{32}$")
    tenant_id: str = Field(min_length=1, max_length=128)
    destination_id: str = Field(pattern=r"^destination://[A-Za-z0-9_.@/-]+$")
    channel: NotificationChannel
    template_id: str = Field(pattern=r"^template://[A-Za-z0-9_.@/-]+$")
    template_version: int = Field(ge=1)
    recipient: str = Field(pattern=r"^analyst://[A-Za-z0-9_.@/-]+$")
    subject: str = Field(min_length=3, max_length=256)
    body: str = Field(min_length=3, max_length=1024)
    idempotency_key: str = Field(pattern=r"^notify_[0-9a-f]{64}$")
    message_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: DeliveryStatus = DeliveryStatus.PENDING
    provider_ack_required: bool
    attempts: int = Field(default=0, ge=0, le=1000)
    redrive_count: int = Field(default=0, ge=0, le=MAX_REDRIVES)
    max_attempts: int = Field(ge=1, le=20)
    retry_base_seconds: int = Field(ge=1, le=3600)
    next_attempt_at: datetime
    accepted_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    provider_reference_sha256: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    provider_receipt_sha256: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    last_error_code: Optional[str] = Field(default=None, pattern=r"^[a-z][a-z0-9_]{2,63}$")
    created_at: datetime
    updated_at: datetime
    delivery_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def coherent_delivery(self) -> "NotificationDelivery":
        timestamps = [self.next_attempt_at, self.created_at, self.updated_at]
        timestamps.extend(item for item in (self.accepted_at, self.acknowledged_at) if item is not None)
        if any(item.tzinfo is None or item.utcoffset() is None for item in timestamps):
            raise ValueError("notification delivery timestamps must include a timezone")
        if self.status in {DeliveryStatus.DELIVERED, DeliveryStatus.ACK_PENDING, DeliveryStatus.ACKNOWLEDGED} and self.accepted_at is None:
            raise ValueError("accepted delivery requires accepted_at")
        if self.status == DeliveryStatus.ACKNOWLEDGED and self.acknowledged_at is None:
            raise ValueError("acknowledged delivery requires acknowledged_at")
        if self.status == DeliveryStatus.ACK_PENDING and not self.provider_ack_required:
            raise ValueError("ack-pending delivery must require provider acknowledgment")
        return self


class NotificationAttempt(StrictModel):
    attempt_id: str = Field(default_factory=lambda: new_id("nat"), pattern=r"^nat_[0-9a-f]{32}$")
    delivery_id: str = Field(pattern=r"^ndv_[0-9a-f]{32}$")
    notification_id: str = Field(pattern=r"^ntf_[0-9a-f]{32}$")
    tenant_id: str = Field(min_length=1, max_length=128)
    attempt_number: int = Field(ge=1, le=1000)
    redrive_count: int = Field(ge=0, le=MAX_REDRIVES)
    outcome: AttemptOutcome
    error_code: Optional[str] = Field(default=None, pattern=r"^[a-z][a-z0-9_]{2,63}$")
    provider_receipt_sha256: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    latency_ms: int = Field(ge=0, le=120000)
    attempted_at: datetime
    attempt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("attempted_at")
    @classmethod
    def aware_attempted_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("notification attempt time must include a timezone")
        return value


class NotificationAuditEntry(StrictModel):
    audit_id: str = Field(default_factory=lambda: new_id("nau"), pattern=r"^nau_[0-9a-f]{32}$")
    notification_id: str = Field(pattern=r"^ntf_[0-9a-f]{32}$")
    tenant_id: str = Field(min_length=1, max_length=128)
    sequence: int = Field(ge=1, le=MAX_AUDIT_ENTRIES)
    actor_id: str = Field(pattern=r"^(analyst|system|workload)://[A-Za-z0-9_.@/-]+$")
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    delivery_state_before: Optional[DeliveryState] = None
    delivery_state_after: DeliveryState
    detail_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    occurred_at: datetime
    previous_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    audit_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("occurred_at")
    @classmethod
    def aware_occurred_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("notification audit time must include a timezone")
        return value


class NotificationDetail(StrictModel):
    notification: NotificationRecord
    deliveries: List[NotificationDelivery] = Field(default_factory=list, max_length=MAX_DESTINATIONS)
    attempts: List[NotificationAttempt] = Field(default_factory=list, max_length=1000)
    audit: List[NotificationAuditEntry] = Field(default_factory=list, max_length=MAX_AUDIT_ENTRIES)


class NotificationPage(StrictModel):
    notifications: List[NotificationRecord]
    count: int = Field(ge=0)
    limit: int = Field(ge=1, le=MAX_NOTIFICATION_PAGE)
    offset: int = Field(ge=0)


class NotificationHealth(StrictModel):
    tenant_id: str
    total: int = Field(ge=0)
    pending_deliveries: int = Field(ge=0)
    retry_scheduled: int = Field(ge=0)
    provider_ack_pending: int = Field(ge=0)
    dead_letters: int = Field(ge=0)
    human_ack_breaches: int = Field(ge=0)
    configured_destinations: int = Field(ge=0)
    ready_destinations: int = Field(ge=0)
    oldest_pending_seconds: Optional[int] = Field(default=None, ge=0)
    policy_version: str
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: datetime


class NotificationDestinationStatus(StrictModel):
    destination_id: str = Field(pattern=r"^destination://[A-Za-z0-9_.@/-]+$")
    name: str = Field(min_length=3, max_length=128)
    channel: NotificationChannel
    provider_ack_required: bool
    enabled: bool
    ready: bool


class NotificationDestinationPage(StrictModel):
    destinations: List[NotificationDestinationStatus] = Field(max_length=MAX_DESTINATIONS)
    count: int = Field(ge=0, le=MAX_DESTINATIONS)


class DeliveryBatchResult(StrictModel):
    claimed: int = Field(ge=0, le=MAX_DELIVERY_BATCH)
    delivered: int = Field(ge=0)
    ack_pending: int = Field(ge=0)
    retry_scheduled: int = Field(ge=0)
    dead_lettered: int = Field(ge=0)
    processed_at: datetime


class NotificationAcknowledgeRequest(StrictModel):
    expected_version: int = Field(ge=1)
    note: str = Field(min_length=3, max_length=512)


class ProviderAcknowledgeRequest(StrictModel):
    provider_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class NotificationProcessRequest(StrictModel):
    limit: int = Field(default=20, ge=1, le=MAX_DELIVERY_BATCH)


class NotificationRedriveRequest(StrictModel):
    reason: str = Field(min_length=3, max_length=512)


class ConnectorResult(StrictModel):
    accepted: bool
    acknowledged: bool = False
    provider_reference: Optional[str] = Field(default=None, max_length=512)
    provider_receipt: Optional[str] = Field(default=None, max_length=2048)
    error_code: Optional[str] = Field(default=None, pattern=r"^[a-z][a-z0-9_]{2,63}$")

    @model_validator(mode="after")
    def coherent_result(self) -> "ConnectorResult":
        if self.acknowledged and not self.accepted:
            raise ValueError("connector cannot acknowledge a rejected delivery")
        if self.accepted and self.error_code is not None:
            raise ValueError("accepted connector result cannot contain an error")
        if not self.accepted and self.error_code is None:
            raise ValueError("rejected connector result requires a safe error code")
        return self


class NotificationConnector(Protocol):
    def send(
        self,
        destination: NotificationDestination,
        message: NotificationMessage,
    ) -> ConnectorResult:
        ...


class NotificationHttpTransport(Protocol):
    def post(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        ...


def _require_public_resolution(host: str) -> None:
    try:
        results = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise RuntimeError("notification_dns_unavailable") from None
    addresses = {item[4][0] for item in results}
    if not addresses or any(not ipaddress.ip_address(item).is_global for item in addresses):
        raise RuntimeError("notification_endpoint_not_public")


class _NoNotificationRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class UrllibNotificationTransport:
    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoNotificationRedirect())

    def post(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        host = urlsplit(url).hostname
        if not host:
            raise RuntimeError("notification_endpoint_invalid")
        _require_public_resolution(host)
        request = urllib.request.Request(
            url,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers=dict(headers),
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=timeout_seconds) as response:
                content_type = response.headers.get_content_type()
                raw = response.read(MAX_HTTP_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise RuntimeError("notification_http_%d" % exc.code) from None
        except (urllib.error.URLError, socket.timeout, TimeoutError):
            raise RuntimeError("notification_transport_unavailable") from None
        if content_type != "application/json" or len(raw) > MAX_HTTP_RESPONSE_BYTES:
            raise RuntimeError("notification_response_invalid")
        try:
            payload_result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError("notification_response_invalid") from None
        if not isinstance(payload_result, dict):
            raise RuntimeError("notification_response_invalid")
        return payload_result


class HttpNotificationConnector:
    """Provider-neutral HTTPS adapter for ticket, email, and messaging gateways."""

    def __init__(
        self,
        *,
        credential: str,
        transport: Optional[NotificationHttpTransport] = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        if len(credential) < 16:
            raise ValueError("notification connector credential is too short")
        if not 0.1 <= timeout_seconds <= 30.0:
            raise ValueError("notification connector timeout is invalid")
        self._credential = credential
        self.transport = transport or UrllibNotificationTransport()
        self.timeout_seconds = timeout_seconds

    def send(
        self,
        destination: NotificationDestination,
        message: NotificationMessage,
    ) -> ConnectorResult:
        validate_notification_endpoint(destination.endpoint, destination.allowed_hosts)
        try:
            response = self.transport.post(
                url=destination.endpoint,
                headers={
                    "Authorization": "Bearer %s" % self._credential,
                    "Content-Type": "application/json",
                    "Idempotency-Key": message.idempotency_key,
                },
                payload=message.model_dump(mode="json"),
                timeout_seconds=self.timeout_seconds,
            )
        except RuntimeError as exc:
            code = str(exc)
            if re.fullmatch(r"[a-z][a-z0-9_]{2,63}", code) is None:
                code = "notification_connector_failed"
            return ConnectorResult(accepted=False, error_code=code)
        allowed = {"accepted", "acknowledged", "reference", "receipt"}
        if set(response) - allowed:
            return ConnectorResult(accepted=False, error_code="notification_response_invalid")
        accepted = response.get("accepted") is True
        acknowledged = response.get("acknowledged") is True
        reference = response.get("reference")
        receipt = response.get("receipt")
        if reference is not None and not isinstance(reference, str):
            return ConnectorResult(accepted=False, error_code="notification_response_invalid")
        if receipt is not None and not isinstance(receipt, str):
            return ConnectorResult(accepted=False, error_code="notification_response_invalid")
        if not accepted:
            return ConnectorResult(accepted=False, error_code="notification_provider_rejected")
        return ConnectorResult(
            accepted=True,
            acknowledged=acknowledged,
            provider_reference=reference,
            provider_receipt=receipt,
        )


class _ChannelNotificationConnector(HttpNotificationConnector):
    channel: NotificationChannel

    def send(
        self,
        destination: NotificationDestination,
        message: NotificationMessage,
    ) -> ConnectorResult:
        if destination.channel != self.channel or message.channel != self.channel:
            return ConnectorResult(
                accepted=False, error_code="notification_channel_mismatch"
            )
        return super().send(destination, message)


class OnCallNotificationConnector(_ChannelNotificationConnector):
    channel = NotificationChannel.ON_CALL


class TicketNotificationConnector(_ChannelNotificationConnector):
    channel = NotificationChannel.TICKET


class EmailNotificationConnector(_ChannelNotificationConnector):
    channel = NotificationChannel.EMAIL


class MessagingNotificationConnector(_ChannelNotificationConnector):
    channel = NotificationChannel.MESSAGING


def _digest(model: StrictModel, field: str) -> str:
    return hashlib.sha256(
        canonical_bytes(model.model_dump(mode="json", exclude={field}))
    ).hexdigest()


def sign_notification_policy(policy: NotificationPolicy) -> NotificationPolicy:
    unsigned = policy.model_copy(update={"policy_sha256": ZERO_SHA256})
    return unsigned.model_copy(update={"policy_sha256": _digest(unsigned, "policy_sha256")})


def load_notification_policy(path: str) -> NotificationPolicy:
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict):
        raise ValueError("notification policy must be an object")
    supplied = raw.get("policy_sha256", ZERO_SHA256)
    raw["policy_sha256"] = ZERO_SHA256
    unsigned = NotificationPolicy.model_validate(raw)
    signed = sign_notification_policy(unsigned)
    if supplied not in {ZERO_SHA256, signed.policy_sha256}:
        raise ValueError("notification policy digest is invalid")
    return signed


class NotificationService:
    """Durable outbox with governed routing, retries, DLQ, and dual acknowledgments."""

    def __init__(
        self,
        path: str,
        *,
        policy: NotificationPolicy,
        connectors: Mapping[str, NotificationConnector],
        clock: Callable[[], datetime] = utc_now,
        redactor: Optional[Redactor] = None,
    ) -> None:
        expected_policy = sign_notification_policy(policy)
        if policy.policy_sha256 not in {ZERO_SHA256, expected_policy.policy_sha256}:
            raise ValueError("notification policy integrity verification failed")
        self.policy = expected_policy
        self.path = path
        self.connectors = dict(connectors)
        self.clock = clock
        self.redactor = redactor or Redactor()
        destination_ids = {item.destination_id for item in self.policy.destinations if item.enabled}
        if not set(self.connectors).issubset(destination_ids):
            raise ValueError("notification connector references an unknown destination")
        self._destinations = {item.destination_id: item for item in self.policy.destinations}
        self._templates = {item.template_id: item for item in self.policy.templates}
        self._schedules = {item.schedule_id: item for item in self.policy.schedules}
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS notifications (
                tenant_id TEXT NOT NULL, notification_id TEXT NOT NULL,
                finding_id TEXT NOT NULL, delivery_state TEXT NOT NULL,
                acknowledgment_state TEXT NOT NULL, acknowledgment_due_at TEXT NOT NULL,
                updated_at TEXT NOT NULL, version INTEGER NOT NULL,
                item_json TEXT NOT NULL, item_sha256 TEXT NOT NULL,
                PRIMARY KEY (tenant_id, notification_id),
                UNIQUE (tenant_id, finding_id)
            );
            CREATE INDEX IF NOT EXISTS notification_listing
                ON notifications(tenant_id, updated_at DESC, notification_id);
            CREATE INDEX IF NOT EXISTS notification_ack_due
                ON notifications(tenant_id, acknowledgment_state, acknowledgment_due_at);
            CREATE TABLE IF NOT EXISTS notification_deliveries (
                tenant_id TEXT NOT NULL, delivery_id TEXT NOT NULL,
                notification_id TEXT NOT NULL, destination_id TEXT NOT NULL,
                status TEXT NOT NULL, next_attempt_at TEXT NOT NULL,
                updated_at TEXT NOT NULL, item_json TEXT NOT NULL,
                item_sha256 TEXT NOT NULL,
                PRIMARY KEY (tenant_id, delivery_id),
                UNIQUE (tenant_id, notification_id, destination_id),
                FOREIGN KEY (tenant_id, notification_id)
                    REFERENCES notifications(tenant_id, notification_id)
            );
            CREATE INDEX IF NOT EXISTS notification_delivery_due
                ON notification_deliveries(tenant_id, status, next_attempt_at);
            CREATE TABLE IF NOT EXISTS notification_attempts (
                tenant_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
                notification_id TEXT NOT NULL, delivery_id TEXT NOT NULL,
                attempted_at TEXT NOT NULL, item_json TEXT NOT NULL,
                item_sha256 TEXT NOT NULL,
                PRIMARY KEY (tenant_id, attempt_id),
                FOREIGN KEY (tenant_id, notification_id)
                    REFERENCES notifications(tenant_id, notification_id),
                FOREIGN KEY (tenant_id, delivery_id)
                    REFERENCES notification_deliveries(tenant_id, delivery_id)
            );
            CREATE TABLE IF NOT EXISTS notification_audit (
                tenant_id TEXT NOT NULL, audit_id TEXT NOT NULL,
                notification_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                occurred_at TEXT NOT NULL, item_json TEXT NOT NULL,
                item_sha256 TEXT NOT NULL,
                PRIMARY KEY (tenant_id, audit_id),
                UNIQUE (tenant_id, notification_id, sequence),
                FOREIGN KEY (tenant_id, notification_id)
                    REFERENCES notifications(tenant_id, notification_id)
            );
            """
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("notification clock must include a timezone")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _require(principal: NotificationPrincipal, permission: str) -> None:
        if permission not in principal.permissions:
            raise NotificationAuthorizationError(
                "missing notification permission: %s" % permission
            )

    @staticmethod
    def _signed(model: StrictModel, field: str) -> StrictModel:
        return model.model_copy(update={field: _digest(model, field)})

    @staticmethod
    def _verify(model: StrictModel, field: str) -> None:
        if _digest(model, field) != getattr(model, field):
            raise ValueError("notification record integrity verification failed")

    def _route(self, result: PipelineResult) -> NotificationRoute:
        for route in self.policy.routes:
            if not route.enabled:
                continue
            if result.triage.priority not in route.priorities:
                continue
            if result.escalation.level not in route.escalation_levels:
                continue
            if route.alert_types and result.alert.alert_type not in route.alert_types:
                continue
            return route
        raise NotificationRoutingError("no governed notification route matched escalation")

    def _on_call(self, schedule: OnCallSchedule, now: datetime) -> str:
        start = schedule.starts_at.astimezone(timezone.utc)
        elapsed = max(0, int((now - start).total_seconds()))
        slot = elapsed // (schedule.rotation_minutes * 60)
        return schedule.member_ids[slot % len(schedule.member_ids)]

    def _render(
        self,
        record: NotificationRecord,
        destination: NotificationDestination,
        template: NotificationTemplate,
    ) -> NotificationMessage:
        values = {
            "notification_id": record.notification_id,
            "finding_id": record.finding_id,
            "alert_type": record.alert_type,
            "severity": record.severity,
            "priority": record.priority,
            "decision": record.decision,
            "escalation_level": record.escalation_level.value,
            "queue": record.queue,
            "case_id": record.case_id or "not_available",
            "correlation_incident_id": record.correlation_incident_id or "not_available",
            "on_call_actor": record.on_call_actor,
        }
        subject = template.subject_template.format_map(values)
        body = template.body_template.format_map(values)
        safe = self.redactor.redact({"subject": subject, "body": body}).value
        key_material = "%s\0%s" % (record.notification_id, destination.destination_id)
        idempotency_key = "notify_" + hashlib.sha256(key_material.encode("utf-8")).hexdigest()
        unsigned = NotificationMessage(
            notification_id=record.notification_id,
            tenant_id=record.tenant_id,
            channel=destination.channel,
            recipient=record.on_call_actor,
            subject=str(safe["subject"]),
            body=str(safe["body"]),
            idempotency_key=idempotency_key,
            message_sha256=ZERO_SHA256,
        )
        signed = self._signed(unsigned, "message_sha256")
        assert isinstance(signed, NotificationMessage)
        return signed

    def _audit_entry(
        self,
        principal: NotificationPrincipal,
        record: NotificationRecord,
        *,
        action: str,
        delivery_state_after: DeliveryState,
        details: Mapping[str, Any],
    ) -> NotificationAuditEntry:
        if record.audit_count >= MAX_AUDIT_ENTRIES:
            raise NotificationConflictError("notification audit capacity reached")
        detail_sha256 = hashlib.sha256(canonical_bytes(dict(details))).hexdigest()
        unsigned = NotificationAuditEntry(
            notification_id=record.notification_id,
            tenant_id=record.tenant_id,
            sequence=record.audit_count + 1,
            actor_id=principal.actor_id,
            action=action,
            delivery_state_before=(record.delivery_state if record.audit_count else None),
            delivery_state_after=delivery_state_after,
            detail_sha256=detail_sha256,
            occurred_at=self._now(),
            previous_sha256=record.audit_head_sha256,
            audit_sha256=ZERO_SHA256,
        )
        signed = self._signed(unsigned, "audit_sha256")
        assert isinstance(signed, NotificationAuditEntry)
        return signed

    def _persist_audit(self, entry: NotificationAuditEntry) -> None:
        self._connection.execute(
            "INSERT INTO notification_audit VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                entry.tenant_id,
                entry.audit_id,
                entry.notification_id,
                entry.sequence,
                entry.occurred_at.isoformat(),
                entry.model_dump_json(),
                entry.audit_sha256,
            ),
        )

    def _persist_record(self, record: NotificationRecord, *, insert: bool = False) -> None:
        if insert:
            self._connection.execute(
                "INSERT INTO notifications VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.tenant_id,
                    record.notification_id,
                    record.finding_id,
                    record.delivery_state.value,
                    record.acknowledgment_state.value,
                    record.acknowledgment_due_at.isoformat(),
                    record.updated_at.isoformat(),
                    record.version,
                    record.model_dump_json(),
                    record.record_sha256,
                ),
            )
        else:
            self._connection.execute(
                "UPDATE notifications SET delivery_state=?, acknowledgment_state=?, acknowledgment_due_at=?, updated_at=?, version=?, item_json=?, item_sha256=? WHERE tenant_id=? AND notification_id=?",
                (
                    record.delivery_state.value,
                    record.acknowledgment_state.value,
                    record.acknowledgment_due_at.isoformat(),
                    record.updated_at.isoformat(),
                    record.version,
                    record.model_dump_json(),
                    record.record_sha256,
                    record.tenant_id,
                    record.notification_id,
                ),
            )

    def _verify_audit(self, record: NotificationRecord) -> None:
        rows = self._connection.execute(
            "SELECT item_json FROM notification_audit WHERE tenant_id=? AND notification_id=? ORDER BY sequence",
            (record.tenant_id, record.notification_id),
        ).fetchall()
        previous = ZERO_SHA256
        for sequence, row in enumerate(rows, 1):
            entry = NotificationAuditEntry.model_validate_json(row["item_json"])
            self._verify(entry, "audit_sha256")
            if entry.sequence != sequence or entry.previous_sha256 != previous:
                raise ValueError("notification audit chain integrity verification failed")
            previous = entry.audit_sha256
        if len(rows) != record.audit_count or previous != record.audit_head_sha256:
            raise ValueError("notification record does not bind its complete audit trail")

    def _load(self, principal: NotificationPrincipal, notification_id: str) -> NotificationRecord:
        row = self._connection.execute(
            "SELECT item_json FROM notifications WHERE tenant_id=? AND notification_id=?",
            (principal.tenant_id, notification_id),
        ).fetchone()
        if row is None:
            raise KeyError(notification_id)
        record = NotificationRecord.model_validate_json(row["item_json"])
        self._verify(record, "record_sha256")
        self._verify_audit(record)
        if (
            record.acknowledgment_state == AcknowledgmentState.PENDING
            and self._now() > record.acknowledgment_due_at
        ):
            derived = record.model_copy(
                update={
                    "acknowledgment_state": AcknowledgmentState.BREACHED,
                    "record_sha256": ZERO_SHA256,
                }
            )
            signed = self._signed(derived, "record_sha256")
            assert isinstance(signed, NotificationRecord)
            return signed
        return record

    def _load_delivery(
        self, principal: NotificationPrincipal, delivery_id: str
    ) -> NotificationDelivery:
        row = self._connection.execute(
            "SELECT item_json FROM notification_deliveries WHERE tenant_id=? AND delivery_id=?",
            (principal.tenant_id, delivery_id),
        ).fetchone()
        if row is None:
            raise KeyError(delivery_id)
        delivery = NotificationDelivery.model_validate_json(row["item_json"])
        self._verify(delivery, "delivery_sha256")
        return delivery

    def _persist_delivery(self, delivery: NotificationDelivery, *, insert: bool = False) -> None:
        if insert:
            self._connection.execute(
                "INSERT INTO notification_deliveries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    delivery.tenant_id,
                    delivery.delivery_id,
                    delivery.notification_id,
                    delivery.destination_id,
                    delivery.status.value,
                    delivery.next_attempt_at.isoformat(),
                    delivery.updated_at.isoformat(),
                    delivery.model_dump_json(),
                    delivery.delivery_sha256,
                ),
            )
        else:
            self._connection.execute(
                "UPDATE notification_deliveries SET status=?, next_attempt_at=?, updated_at=?, item_json=?, item_sha256=? WHERE tenant_id=? AND delivery_id=?",
                (
                    delivery.status.value,
                    delivery.next_attempt_at.isoformat(),
                    delivery.updated_at.isoformat(),
                    delivery.model_dump_json(),
                    delivery.delivery_sha256,
                    delivery.tenant_id,
                    delivery.delivery_id,
                ),
            )

    def enqueue_from_pipeline(
        self,
        principal: NotificationPrincipal,
        result: PipelineResult,
        *,
        case_id: Optional[str] = None,
        correlation_incident_id: Optional[str] = None,
    ) -> Optional[NotificationRecord]:
        self._require(principal, NOTIFICATION_ROUTE)
        if result.event.tenant_id != principal.tenant_id:
            raise NotificationAuthorizationError("pipeline and notification tenants differ")
        if result.escalation.level == EscalationLevel.NONE:
            return None
        route = self._route(result)
        schedule = self._schedules[route.on_call_schedule_id]
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT notification_id FROM notifications WHERE tenant_id=? AND finding_id=?",
                    (principal.tenant_id, result.finding.finding_id),
                ).fetchone()
                if existing is not None:
                    record = self._load(principal, existing["notification_id"])
                    self._connection.execute("COMMIT")
                    return record
                unsigned = NotificationRecord(
                    tenant_id=principal.tenant_id,
                    finding_id=result.finding.finding_id,
                    alert_id=result.alert.alert_id,
                    alert_type=result.alert.alert_type,
                    severity=result.alert.severity.value,
                    priority=result.triage.priority,
                    decision=result.judgment.action.value,
                    escalation_level=result.escalation.level,
                    queue=result.escalation.queue or result.triage.route,
                    case_id=case_id,
                    correlation_incident_id=correlation_incident_id,
                    route_id=route.route_id,
                    policy_version=self.policy.policy_version,
                    policy_sha256=self.policy.policy_sha256,
                    on_call_actor=self._on_call(schedule, now),
                    schedule_id=schedule.schedule_id,
                    schedule_version=schedule.version,
                    acknowledgment_due_at=now + timedelta(minutes=route.acknowledgment_minutes),
                    created_at=now,
                    updated_at=now,
                    record_sha256=ZERO_SHA256,
                )
                audit = self._audit_entry(
                    principal,
                    unsigned,
                    action="notification_queued",
                    delivery_state_after=DeliveryState.PENDING,
                    details={"route_id": route.route_id, "destinations": sorted(route.destination_templates)},
                )
                record_unsigned = unsigned.model_copy(
                    update={
                        "audit_count": 1,
                        "audit_head_sha256": audit.audit_sha256,
                        "record_sha256": ZERO_SHA256,
                    }
                )
                record = self._signed(record_unsigned, "record_sha256")
                assert isinstance(record, NotificationRecord)
                self._persist_record(record, insert=True)
                self._persist_audit(audit)
                for destination_id, template_id in route.destination_templates.items():
                    destination = self._destinations[destination_id]
                    if not destination.enabled:
                        raise NotificationRoutingError("notification route uses a disabled destination")
                    template = self._templates[template_id]
                    message = self._render(record, destination, template)
                    delivery_unsigned = NotificationDelivery(
                        notification_id=record.notification_id,
                        tenant_id=record.tenant_id,
                        destination_id=destination.destination_id,
                        channel=destination.channel,
                        template_id=template.template_id,
                        template_version=template.version,
                        recipient=message.recipient,
                        subject=message.subject,
                        body=message.body,
                        idempotency_key=message.idempotency_key,
                        message_sha256=message.message_sha256,
                        provider_ack_required=destination.provider_ack_required,
                        max_attempts=route.max_attempts,
                        retry_base_seconds=route.retry_base_seconds,
                        next_attempt_at=now,
                        created_at=now,
                        updated_at=now,
                        delivery_sha256=ZERO_SHA256,
                    )
                    delivery = self._signed(delivery_unsigned, "delivery_sha256")
                    assert isinstance(delivery, NotificationDelivery)
                    self._persist_delivery(delivery, insert=True)
                self._connection.execute("COMMIT")
                return record
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def list(
        self,
        principal: NotificationPrincipal,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> NotificationPage:
        self._require(principal, NOTIFICATION_READ)
        if not 1 <= limit <= MAX_NOTIFICATION_PAGE or offset < 0:
            raise ValueError("notification pagination is invalid")
        with self._lock:
            rows = self._connection.execute(
                "SELECT item_json FROM notifications WHERE tenant_id=? ORDER BY updated_at DESC, notification_id LIMIT ? OFFSET ?",
                (principal.tenant_id, limit, offset),
            ).fetchall()
            count = self._connection.execute(
                "SELECT COUNT(*) AS total FROM notifications WHERE tenant_id=?",
                (principal.tenant_id,),
            ).fetchone()["total"]
        records: List[NotificationRecord] = []
        for row in rows:
            record = NotificationRecord.model_validate_json(row["item_json"])
            self._verify(record, "record_sha256")
            self._verify_audit(record)
            records.append(self._load(principal, record.notification_id))
        return NotificationPage(
            notifications=records, count=int(count), limit=limit, offset=offset
        )

    def get(self, principal: NotificationPrincipal, notification_id: str) -> NotificationDetail:
        self._require(principal, NOTIFICATION_READ)
        with self._lock:
            record = self._load(principal, notification_id)
            delivery_rows = self._connection.execute(
                "SELECT item_json FROM notification_deliveries WHERE tenant_id=? AND notification_id=? ORDER BY destination_id",
                (principal.tenant_id, notification_id),
            ).fetchall()
            attempt_rows = self._connection.execute(
                "SELECT item_json FROM notification_attempts WHERE tenant_id=? AND notification_id=? ORDER BY attempted_at, rowid",
                (principal.tenant_id, notification_id),
            ).fetchall()
            audit_rows = self._connection.execute(
                "SELECT item_json FROM notification_audit WHERE tenant_id=? AND notification_id=? ORDER BY sequence",
                (principal.tenant_id, notification_id),
            ).fetchall()
        deliveries = [NotificationDelivery.model_validate_json(row["item_json"]) for row in delivery_rows]
        attempts = [NotificationAttempt.model_validate_json(row["item_json"]) for row in attempt_rows]
        audit = [NotificationAuditEntry.model_validate_json(row["item_json"]) for row in audit_rows]
        for item in deliveries:
            self._verify(item, "delivery_sha256")
        for item in attempts:
            self._verify(item, "attempt_sha256")
        for item in audit:
            self._verify(item, "audit_sha256")
        return NotificationDetail(notification=record, deliveries=deliveries, attempts=attempts, audit=audit)

    def _aggregate_delivery_state(self, principal: NotificationPrincipal, notification_id: str) -> DeliveryState:
        rows = self._connection.execute(
            "SELECT status FROM notification_deliveries WHERE tenant_id=? AND notification_id=?",
            (principal.tenant_id, notification_id),
        ).fetchall()
        statuses = {DeliveryStatus(row["status"]) for row in rows}
        delivered = {DeliveryStatus.DELIVERED, DeliveryStatus.ACK_PENDING, DeliveryStatus.ACKNOWLEDGED}
        if statuses and statuses.issubset(delivered):
            return DeliveryState.DELIVERED
        if statuses and statuses == {DeliveryStatus.DEAD_LETTER}:
            return DeliveryState.DEAD_LETTER
        if statuses & delivered or DeliveryStatus.DEAD_LETTER in statuses:
            return DeliveryState.PARTIAL
        return DeliveryState.PENDING

    def _update_record_for_delivery(
        self,
        principal: NotificationPrincipal,
        record: NotificationRecord,
        *,
        action: str,
        details: Mapping[str, Any],
    ) -> NotificationRecord:
        state = self._aggregate_delivery_state(principal, record.notification_id)
        audit = self._audit_entry(
            principal,
            record,
            action=action,
            delivery_state_after=state,
            details=details,
        )
        unsigned = record.model_copy(
            update={
                "delivery_state": state,
                "version": record.version + 1,
                "updated_at": self._now(),
                "audit_count": audit.sequence,
                "audit_head_sha256": audit.audit_sha256,
                "record_sha256": ZERO_SHA256,
            }
        )
        updated = self._signed(unsigned, "record_sha256")
        assert isinstance(updated, NotificationRecord)
        self._persist_audit(audit)
        self._persist_record(updated)
        return updated

    def process_due(
        self,
        principal: NotificationPrincipal,
        *,
        limit: int = 20,
    ) -> DeliveryBatchResult:
        self._require(principal, NOTIFICATION_DELIVER)
        if not 1 <= limit <= MAX_DELIVERY_BATCH:
            raise ValueError("notification delivery limit is invalid")
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._recover_expired_claims(principal, now)
                rows = self._connection.execute(
                    "SELECT delivery_id FROM notification_deliveries WHERE tenant_id=? AND status IN ('pending','retry_scheduled') AND next_attempt_at<=? ORDER BY next_attempt_at, delivery_id LIMIT ?",
                    (principal.tenant_id, now.isoformat(), limit),
                ).fetchall()
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        counters = {"delivered": 0, "ack_pending": 0, "retry_scheduled": 0, "dead_lettered": 0}
        for row in rows:
            outcome = self._process_one(principal, row["delivery_id"])
            counters[outcome] += 1
        return DeliveryBatchResult(
            claimed=len(rows),
            delivered=counters["delivered"],
            ack_pending=counters["ack_pending"],
            retry_scheduled=counters["retry_scheduled"],
            dead_lettered=counters["dead_lettered"],
            processed_at=self._now(),
        )

    def _recover_expired_claims(
        self, principal: NotificationPrincipal, now: datetime
    ) -> None:
        cutoff = now - timedelta(seconds=IN_FLIGHT_LEASE_SECONDS)
        rows = self._connection.execute(
            "SELECT item_json FROM notification_deliveries WHERE tenant_id=? AND status='in_flight' AND updated_at<=?",
            (principal.tenant_id, cutoff.isoformat()),
        ).fetchall()
        for row in rows:
            current = NotificationDelivery.model_validate_json(row["item_json"])
            self._verify(current, "delivery_sha256")
            unsigned = current.model_copy(
                update={
                    "status": DeliveryStatus.RETRY_SCHEDULED,
                    "next_attempt_at": now,
                    "last_error_code": "notification_worker_lease_expired",
                    "updated_at": now,
                    "delivery_sha256": ZERO_SHA256,
                }
            )
            delivery = self._signed(unsigned, "delivery_sha256")
            assert isinstance(delivery, NotificationDelivery)
            self._persist_delivery(delivery)
            record = self._load(principal, delivery.notification_id)
            self._update_record_for_delivery(
                principal,
                record,
                action="delivery_lease_recovered",
                details={"delivery_id": delivery.delivery_id},
            )

    def _process_one(self, principal: NotificationPrincipal, delivery_id: str) -> str:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                delivery = self._load_delivery(principal, delivery_id)
                if delivery.status not in {DeliveryStatus.PENDING, DeliveryStatus.RETRY_SCHEDULED}:
                    self._connection.execute("COMMIT")
                    return "retry_scheduled"
                if delivery.next_attempt_at > self._now():
                    self._connection.execute("COMMIT")
                    return "retry_scheduled"
                claimed_unsigned = delivery.model_copy(
                    update={"status": DeliveryStatus.IN_FLIGHT, "updated_at": self._now(), "delivery_sha256": ZERO_SHA256}
                )
                claimed = self._signed(claimed_unsigned, "delivery_sha256")
                assert isinstance(claimed, NotificationDelivery)
                self._persist_delivery(claimed)
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

        destination = self._destinations[claimed.destination_id]
        connector = self.connectors.get(claimed.destination_id)
        started = time.monotonic()
        if connector is None:
            result = ConnectorResult(accepted=False, error_code="notification_connector_unavailable")
        else:
            message = NotificationMessage(
                notification_id=claimed.notification_id,
                tenant_id=claimed.tenant_id,
                channel=claimed.channel,
                recipient=claimed.recipient,
                subject=claimed.subject,
                body=claimed.body,
                idempotency_key=claimed.idempotency_key,
                message_sha256=claimed.message_sha256,
            )
            self._verify(message, "message_sha256")
            try:
                result = connector.send(destination, message)
            except Exception:
                result = ConnectorResult(accepted=False, error_code="notification_connector_failed")
        latency_ms = min(120000, max(0, int((time.monotonic() - started) * 1000)))
        return self._complete_attempt(principal, claimed, result, latency_ms)

    def _complete_attempt(
        self,
        principal: NotificationPrincipal,
        claimed: NotificationDelivery,
        result: ConnectorResult,
        latency_ms: int,
    ) -> str:
        now = self._now()
        provider_reference_sha256 = (
            hashlib.sha256(result.provider_reference.encode("utf-8")).hexdigest()
            if result.provider_reference
            else None
        )
        provider_receipt_sha256 = (
            hashlib.sha256(result.provider_receipt.encode("utf-8")).hexdigest()
            if result.provider_receipt
            else None
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                current = self._load_delivery(principal, claimed.delivery_id)
                if current.status != DeliveryStatus.IN_FLIGHT or current.delivery_sha256 != claimed.delivery_sha256:
                    raise NotificationConflictError("notification delivery claim is stale")
                attempts = current.attempts + 1
                if result.accepted:
                    if current.provider_ack_required and not result.acknowledged:
                        status = DeliveryStatus.ACK_PENDING
                        outcome = AttemptOutcome.ACK_PENDING
                        counter = "ack_pending"
                    elif current.provider_ack_required:
                        status = DeliveryStatus.ACKNOWLEDGED
                        outcome = AttemptOutcome.DELIVERED
                        counter = "delivered"
                    else:
                        status = DeliveryStatus.DELIVERED
                        outcome = AttemptOutcome.DELIVERED
                        counter = "delivered"
                    next_attempt_at = now
                    error_code = None
                    accepted_at = now
                    acknowledged_at = now if status == DeliveryStatus.ACKNOWLEDGED else None
                elif attempts >= current.max_attempts:
                    status = DeliveryStatus.DEAD_LETTER
                    outcome = AttemptOutcome.DEAD_LETTER
                    counter = "dead_lettered"
                    next_attempt_at = now
                    error_code = result.error_code or "notification_connector_failed"
                    accepted_at = current.accepted_at
                    acknowledged_at = current.acknowledged_at
                else:
                    status = DeliveryStatus.RETRY_SCHEDULED
                    outcome = AttemptOutcome.RETRY_SCHEDULED
                    counter = "retry_scheduled"
                    delay = min(86400, current.retry_base_seconds * (2 ** (attempts - 1)))
                    next_attempt_at = now + timedelta(seconds=delay)
                    error_code = result.error_code or "notification_connector_failed"
                    accepted_at = current.accepted_at
                    acknowledged_at = current.acknowledged_at
                unsigned = current.model_copy(
                    update={
                        "status": status,
                        "attempts": attempts,
                        "next_attempt_at": next_attempt_at,
                        "accepted_at": accepted_at,
                        "acknowledged_at": acknowledged_at,
                        "provider_reference_sha256": provider_reference_sha256,
                        "provider_receipt_sha256": provider_receipt_sha256,
                        "last_error_code": error_code,
                        "updated_at": now,
                        "delivery_sha256": ZERO_SHA256,
                    }
                )
                delivery = self._signed(unsigned, "delivery_sha256")
                assert isinstance(delivery, NotificationDelivery)
                self._persist_delivery(delivery)
                attempt_unsigned = NotificationAttempt(
                    delivery_id=delivery.delivery_id,
                    notification_id=delivery.notification_id,
                    tenant_id=delivery.tenant_id,
                    attempt_number=attempts,
                    redrive_count=delivery.redrive_count,
                    outcome=outcome,
                    error_code=error_code,
                    provider_receipt_sha256=provider_receipt_sha256,
                    latency_ms=latency_ms,
                    attempted_at=now,
                    attempt_sha256=ZERO_SHA256,
                )
                attempt = self._signed(attempt_unsigned, "attempt_sha256")
                assert isinstance(attempt, NotificationAttempt)
                self._connection.execute(
                    "INSERT INTO notification_attempts VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        attempt.tenant_id,
                        attempt.attempt_id,
                        attempt.notification_id,
                        attempt.delivery_id,
                        attempt.attempted_at.isoformat(),
                        attempt.model_dump_json(),
                        attempt.attempt_sha256,
                    ),
                )
                record = self._load(principal, delivery.notification_id)
                self._update_record_for_delivery(
                    principal,
                    record,
                    action="delivery_%s" % outcome.value,
                    details={"delivery_id": delivery.delivery_id, "attempt": attempts, "outcome": outcome.value},
                )
                self._connection.execute("COMMIT")
                return counter
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def acknowledge_provider_delivery(
        self,
        principal: NotificationPrincipal,
        delivery_id: str,
        *,
        provider_receipt_sha256: str,
    ) -> NotificationDelivery:
        self._require(principal, NOTIFICATION_DELIVER)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                current = self._load_delivery(principal, delivery_id)
                if current.status == DeliveryStatus.ACKNOWLEDGED:
                    if current.provider_receipt_sha256 == provider_receipt_sha256:
                        self._connection.execute("COMMIT")
                        return current
                    raise NotificationConflictError("provider acknowledgment conflicts")
                if current.status != DeliveryStatus.ACK_PENDING:
                    raise NotificationConflictError("delivery is not awaiting provider acknowledgment")
                now = self._now()
                unsigned = current.model_copy(
                    update={
                        "status": DeliveryStatus.ACKNOWLEDGED,
                        "acknowledged_at": now,
                        "provider_receipt_sha256": provider_receipt_sha256,
                        "updated_at": now,
                        "delivery_sha256": ZERO_SHA256,
                    }
                )
                delivery = self._signed(unsigned, "delivery_sha256")
                assert isinstance(delivery, NotificationDelivery)
                self._persist_delivery(delivery)
                record = self._load(principal, delivery.notification_id)
                self._update_record_for_delivery(
                    principal,
                    record,
                    action="provider_acknowledged",
                    details={"delivery_id": delivery.delivery_id, "receipt_sha256": provider_receipt_sha256},
                )
                self._connection.execute("COMMIT")
                return delivery
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def acknowledge(
        self,
        principal: NotificationPrincipal,
        notification_id: str,
        *,
        expected_version: int,
        note: str,
    ) -> NotificationRecord:
        self._require(principal, NOTIFICATION_ACK)
        safe_note = str(self.redactor.redact(note).value)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                current = self._load(principal, notification_id)
                if current.acknowledged_at is not None:
                    if current.acknowledged_by == principal.actor_id and current.acknowledgment_note == safe_note:
                        self._connection.execute("COMMIT")
                        return current
                    raise NotificationConflictError("notification is already acknowledged")
                if current.version != expected_version:
                    raise NotificationConflictError("notification version conflict")
                if principal.actor_id != current.on_call_actor and NOTIFICATION_ADMIN not in principal.permissions:
                    raise NotificationAuthorizationError("only the routed on-call analyst may acknowledge")
                statuses = self._connection.execute(
                    "SELECT status FROM notification_deliveries WHERE tenant_id=? AND notification_id=?",
                    (principal.tenant_id, notification_id),
                ).fetchall()
                if not any(
                    DeliveryStatus(row["status"])
                    in {DeliveryStatus.DELIVERED, DeliveryStatus.ACK_PENDING, DeliveryStatus.ACKNOWLEDGED}
                    for row in statuses
                ):
                    raise NotificationConflictError("notification has not reached any destination")
                now = self._now()
                audit = self._audit_entry(
                    principal,
                    current,
                    action="escalation_acknowledged",
                    delivery_state_after=current.delivery_state,
                    details={"note_sha256": hashlib.sha256(safe_note.encode("utf-8")).hexdigest()},
                )
                unsigned = current.model_copy(
                    update={
                        "acknowledgment_state": AcknowledgmentState.ACKNOWLEDGED,
                        "acknowledged_at": now,
                        "acknowledged_by": principal.actor_id,
                        "acknowledgment_note": safe_note,
                        "version": current.version + 1,
                        "updated_at": now,
                        "audit_count": audit.sequence,
                        "audit_head_sha256": audit.audit_sha256,
                        "record_sha256": ZERO_SHA256,
                    }
                )
                record = self._signed(unsigned, "record_sha256")
                assert isinstance(record, NotificationRecord)
                self._persist_audit(audit)
                self._persist_record(record)
                self._connection.execute("COMMIT")
                return record
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def redrive(
        self,
        principal: NotificationPrincipal,
        delivery_id: str,
        *,
        reason: str,
    ) -> NotificationDelivery:
        self._require(principal, NOTIFICATION_ADMIN)
        safe_reason = str(self.redactor.redact(reason).value)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                current = self._load_delivery(principal, delivery_id)
                if current.status != DeliveryStatus.DEAD_LETTER:
                    raise NotificationConflictError("only dead-letter delivery can be redriven")
                if current.redrive_count >= MAX_REDRIVES:
                    raise NotificationConflictError("notification redrive capacity reached")
                now = self._now()
                unsigned = current.model_copy(
                    update={
                        "status": DeliveryStatus.RETRY_SCHEDULED,
                        "attempts": 0,
                        "redrive_count": current.redrive_count + 1,
                        "next_attempt_at": now,
                        "last_error_code": None,
                        "updated_at": now,
                        "delivery_sha256": ZERO_SHA256,
                    }
                )
                delivery = self._signed(unsigned, "delivery_sha256")
                assert isinstance(delivery, NotificationDelivery)
                self._persist_delivery(delivery)
                record = self._load(principal, delivery.notification_id)
                self._update_record_for_delivery(
                    principal,
                    record,
                    action="delivery_redriven",
                    details={
                        "delivery_id": delivery.delivery_id,
                        "redrive_count": delivery.redrive_count,
                        "reason_sha256": hashlib.sha256(safe_reason.encode("utf-8")).hexdigest(),
                    },
                )
                self._connection.execute("COMMIT")
                return delivery
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def health(self, principal: NotificationPrincipal) -> NotificationHealth:
        self._require(principal, NOTIFICATION_READ)
        now = self._now()
        with self._lock:
            notification_rows = self._connection.execute(
                "SELECT item_json FROM notifications WHERE tenant_id=?",
                (principal.tenant_id,),
            ).fetchall()
            delivery_rows = self._connection.execute(
                "SELECT item_json FROM notification_deliveries WHERE tenant_id=?",
                (principal.tenant_id,),
            ).fetchall()
        notifications = [NotificationRecord.model_validate_json(row["item_json"]) for row in notification_rows]
        deliveries = [NotificationDelivery.model_validate_json(row["item_json"]) for row in delivery_rows]
        for item in notifications:
            self._verify(item, "record_sha256")
            self._verify_audit(item)
        for item in deliveries:
            self._verify(item, "delivery_sha256")
        pending = [
            item for item in deliveries
            if item.status in {DeliveryStatus.PENDING, DeliveryStatus.IN_FLIGHT, DeliveryStatus.RETRY_SCHEDULED}
        ]
        oldest = min((item.created_at for item in pending), default=None)
        configured = [item for item in self.policy.destinations if item.enabled]
        return NotificationHealth(
            tenant_id=principal.tenant_id,
            total=len(notifications),
            pending_deliveries=sum(item.status in {DeliveryStatus.PENDING, DeliveryStatus.IN_FLIGHT} for item in deliveries),
            retry_scheduled=sum(item.status == DeliveryStatus.RETRY_SCHEDULED for item in deliveries),
            provider_ack_pending=sum(item.status == DeliveryStatus.ACK_PENDING for item in deliveries),
            dead_letters=sum(item.status == DeliveryStatus.DEAD_LETTER for item in deliveries),
            human_ack_breaches=sum(
                item.acknowledged_at is None and now > item.acknowledgment_due_at
                for item in notifications
            ),
            configured_destinations=len(configured),
            ready_destinations=sum(item.destination_id in self.connectors for item in configured),
            oldest_pending_seconds=(max(0, int((now - oldest).total_seconds())) if oldest else None),
            policy_version=self.policy.policy_version,
            policy_sha256=self.policy.policy_sha256,
            observed_at=now,
        )

    def destinations(
        self, principal: NotificationPrincipal
    ) -> NotificationDestinationPage:
        self._require(principal, NOTIFICATION_READ)
        destinations = [
            NotificationDestinationStatus(
                destination_id=item.destination_id,
                name=item.name,
                channel=item.channel,
                provider_ack_required=item.provider_ack_required,
                enabled=item.enabled,
                ready=item.destination_id in self.connectors,
            )
            for item in self.policy.destinations
        ]
        return NotificationDestinationPage(
            destinations=destinations, count=len(destinations)
        )


def notification_service_from_environment(
    database_path: str,
    policy_path: str,
    *,
    tenant_id: str,
    environment: Optional[Mapping[str, str]] = None,
) -> tuple[NotificationService, NotificationPrincipal]:
    """Build the local service without placing connector secrets in policy state."""

    values = environment if environment is not None else os.environ
    policy = load_notification_policy(policy_path)
    connector_types = {
        NotificationChannel.ON_CALL: OnCallNotificationConnector,
        NotificationChannel.TICKET: TicketNotificationConnector,
        NotificationChannel.EMAIL: EmailNotificationConnector,
        NotificationChannel.MESSAGING: MessagingNotificationConnector,
    }
    connectors: Dict[str, NotificationConnector] = {}
    for destination in policy.destinations:
        if not destination.enabled:
            continue
        credential = values.get(destination.credential_env, "")
        if credential:
            connectors[destination.destination_id] = connector_types[
                destination.channel
            ](
                credential=credential
            )
    principal = NotificationPrincipal(
        tenant_id=tenant_id,
        actor_id="system://local-notification-service",
        permissions={
            NOTIFICATION_READ,
            NOTIFICATION_ROUTE,
            NOTIFICATION_DELIVER,
            NOTIFICATION_ACK,
            NOTIFICATION_ADMIN,
        },
    )
    return (
        NotificationService(
            database_path,
            policy=policy,
            connectors=connectors,
        ),
        principal,
    )


__all__ = [
    "AcknowledgmentState",
    "ConnectorResult",
    "DeliveryBatchResult",
    "DeliveryState",
    "DeliveryStatus",
    "EmailNotificationConnector",
    "HttpNotificationConnector",
    "MessagingNotificationConnector",
    "NOTIFICATION_ACK",
    "NOTIFICATION_ADMIN",
    "NOTIFICATION_DELIVER",
    "NOTIFICATION_READ",
    "NOTIFICATION_ROUTE",
    "NotificationAcknowledgeRequest",
    "NotificationAttempt",
    "NotificationAuditEntry",
    "NotificationAuthorizationError",
    "NotificationChannel",
    "NotificationConflictError",
    "NotificationDelivery",
    "NotificationDestination",
    "NotificationDestinationPage",
    "NotificationDestinationStatus",
    "NotificationDetail",
    "NotificationHealth",
    "NotificationMessage",
    "NotificationPage",
    "NotificationPolicy",
    "NotificationPrincipal",
    "NotificationProcessRequest",
    "NotificationRecord",
    "NotificationRedriveRequest",
    "NotificationRoute",
    "NotificationRoutingError",
    "NotificationService",
    "NotificationTemplate",
    "OnCallNotificationConnector",
    "OnCallSchedule",
    "ProviderAcknowledgeRequest",
    "TicketNotificationConnector",
    "load_notification_policy",
    "notification_service_from_environment",
    "sign_notification_policy",
    "validate_notification_endpoint",
]
