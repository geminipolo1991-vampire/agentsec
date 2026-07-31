"""Versioned external event stream and governed SIEM delivery plane.

The module deliberately exports a newly constructed allowlist record.  It never
serializes a prompt, model response, tool arguments/results, protected evidence,
provider response body, endpoint credential, or arbitrary canonical record.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import sqlite3
import ssl
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Protocol, Sequence, Set, Tuple
from urllib.parse import urlencode, urlsplit

from pydantic import Field, field_validator, model_validator

from .contracts import PipelineResult, StrictModel, utc_now
from .privacy import PrivacyTransformer, SocFindingExport


INTEGRATION_READ = "integration:read"
INTEGRATION_ENQUEUE = "integration:enqueue"
INTEGRATION_DELIVER = "integration:deliver"
INTEGRATION_REDRIVE = "integration:redrive"
INTEGRATION_ADMIN = "integration:admin"

EXTERNAL_CAPABILITIES = "external:capabilities"
EXTERNAL_EVENTS_READ = "external:events:read"
EXTERNAL_SEARCH = "external:search"
EXTERNAL_ENTITIES_READ = "external:entities:read"
EXTERNAL_RULES_READ = "external:rules:read"
EXTERNAL_FINDINGS_READ = "external:findings:read"
EXTERNAL_INCIDENTS_READ = "external:incidents:read"
EXTERNAL_INTEGRATIONS_READ = "external:integrations:read"
EXTERNAL_INTEGRATIONS_OPERATE = "external:integrations:operate"
EXTERNAL_API_SCOPES = {
    EXTERNAL_CAPABILITIES,
    EXTERNAL_EVENTS_READ,
    EXTERNAL_SEARCH,
    EXTERNAL_ENTITIES_READ,
    EXTERNAL_RULES_READ,
    EXTERNAL_FINDINGS_READ,
    EXTERNAL_INCIDENTS_READ,
    EXTERNAL_INTEGRATIONS_READ,
    EXTERNAL_INTEGRATIONS_OPERATE,
}

MAX_DESTINATIONS = 32
MAX_EVENT_PAGE = 200
MAX_DELIVERY_PAGE = 200
MAX_PROCESS_BATCH = 100
MAX_RESPONSE_BYTES = 64 * 1024
MAX_CONFIG_BYTES = 512 * 1024
ZERO_SHA256 = "0" * 64


def _canonical_json(value: Any) -> str:
    if isinstance(value, StrictModel):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(value: Any) -> str:
    if not isinstance(value, str):
        value = _canonical_json(value)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _stable_id(prefix: str, *parts: str) -> str:
    return "%s_%s" % (prefix, _sha256("\x1f".join(parts))[:32])


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("integration timestamp must include a timezone")
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _aware(value).isoformat().replace("+00:00", "Z")


class IntegrationKind(str, Enum):
    SPLUNK_HEC = "splunk_hec"
    ELASTIC_BULK = "elastic_bulk"
    SIGNED_WEBHOOK = "signed_webhook"
    SYSLOG_TLS = "syslog_tls"
    CEF_TLS = "cef_tls"
    OTLP_HTTP_JSON = "otlp_http_json"


class IntegrationDeliveryState(str, Enum):
    QUEUED = "queued"
    RETRY = "retry"
    ACK_PENDING = "ack_pending"
    DELIVERED = "delivered"
    DEAD_LETTER = "dead_letter"


class IntegrationAuthorizationError(PermissionError):
    pass


class IntegrationConflictError(RuntimeError):
    pass


class IntegrationPrincipal(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(
        pattern=r"^(system|workload|analyst)://[A-Za-z0-9_.@/-]+$",
        max_length=256,
    )
    permissions: Set[str] = Field(default_factory=set, max_length=16)

    @field_validator("permissions")
    @classmethod
    def valid_permissions(cls, value: Set[str]) -> Set[str]:
        if any(re.fullmatch(r"integration:[a-z]+", item) is None for item in value):
            raise ValueError("integration permissions must use integration:operation")
        return value


class ExternalApiAuthenticationError(PermissionError):
    pass


class ExternalApiAuthorizationError(PermissionError):
    pass


class ExternalApiClientSpec(StrictModel):
    client_id: str = Field(pattern=r"^client://[A-Za-z0-9_.@/-]+$", max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    token_env: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    scopes: Set[str] = Field(min_length=1, max_length=16)
    enabled: bool = True

    @field_validator("scopes")
    @classmethod
    def valid_scopes(cls, value: Set[str]) -> Set[str]:
        unknown = value - EXTERNAL_API_SCOPES
        if unknown:
            raise ValueError("external API client contains an unknown scope")
        return value


class ExternalApiAccessPolicy(StrictModel):
    schema_version: str = "1.0.0"
    policy_version: str = Field(min_length=3, max_length=128)
    clients: List[ExternalApiClientSpec] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def unique_clients(self) -> "ExternalApiAccessPolicy":
        identifiers = [item.client_id for item in self.clients]
        token_variables = [item.token_env for item in self.clients]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("external API client IDs must be unique")
        if len(token_variables) != len(set(token_variables)):
            raise ValueError("external API token variables must be unique")
        return self


class ExternalApiPrincipal(StrictModel):
    client_id: str = Field(pattern=r"^client://[A-Za-z0-9_.@/-]+$", max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    scopes: Set[str] = Field(min_length=1, max_length=16)


class ExternalApiAuthenticator:
    """Runtime-only bearer authentication with explicit tenant and scopes."""

    def __init__(
        self,
        policy: ExternalApiAccessPolicy,
        *,
        environment: Optional[Mapping[str, str]] = None,
    ) -> None:
        self.policy = policy
        source = environment if environment is not None else os.environ
        self._credentials: List[Tuple[ExternalApiClientSpec, str]] = []
        for client in policy.clients:
            token = source.get(client.token_env, "")
            if client.enabled and token:
                if not 32 <= len(token.encode("utf-8")) <= 4096:
                    raise ValueError("external API token must contain 32 to 4096 bytes")
                self._credentials.append((client, token))

    def authenticate(self, supplied_header: str) -> ExternalApiPrincipal:
        supplied = supplied_header.removeprefix("Bearer ")
        valid_shape = supplied_header.startswith("Bearer ") and bool(supplied)
        matched: Optional[ExternalApiClientSpec] = None
        # Compare every configured credential so client position is not revealed.
        for client, credential in self._credentials:
            if hmac.compare_digest(supplied, credential):
                matched = client
        if not valid_shape or matched is None:
            raise ExternalApiAuthenticationError("external API authentication failed")
        return ExternalApiPrincipal(
            client_id=matched.client_id,
            tenant_id=matched.tenant_id,
            scopes=matched.scopes,
        )

    @staticmethod
    def authorize(principal: ExternalApiPrincipal, scope: str) -> None:
        if scope not in principal.scopes:
            raise ExternalApiAuthorizationError("external API scope denied")

    @classmethod
    def from_config(
        cls,
        path: str,
        *,
        environment: Optional[Mapping[str, str]] = None,
    ) -> "ExternalApiAuthenticator":
        file_path = Path(path)
        raw = file_path.read_bytes()
        if not raw or len(raw) > MAX_CONFIG_BYTES:
            raise ValueError("external API access policy size is invalid")
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("external API access policy is invalid JSON") from None
        return cls(
            ExternalApiAccessPolicy.model_validate(decoded),
            environment=environment,
        )


def validate_integration_endpoint(
    kind: IntegrationKind, endpoint: str, allowed_hosts: Sequence[str]
) -> str:
    parsed = urlsplit(endpoint)
    host = (parsed.hostname or "").lower()
    normalized_hosts = {item.lower() for item in allowed_hosts}
    expected_scheme = "tls" if kind in {IntegrationKind.SYSLOG_TLS, IntegrationKind.CEF_TLS} else "https"
    if parsed.scheme != expected_scheme or not host:
        raise ValueError("integration endpoint uses an invalid transport")
    if host not in normalized_hosts:
        raise ValueError("integration endpoint host is not allowlisted")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("integration endpoint contains prohibited URL components")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("integration endpoint port is invalid")
    if host == "localhost" or host.endswith(".local"):
        raise ValueError("integration endpoint cannot use a local host")
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global:
        raise ValueError("integration endpoint cannot use a non-public address")
    path = parsed.path.rstrip("/")
    if kind == IntegrationKind.SPLUNK_HEC and path != "/services/collector/event":
        raise ValueError("Splunk endpoint path must be /services/collector/event")
    if kind == IntegrationKind.ELASTIC_BULK and not path.endswith("/_bulk"):
        raise ValueError("Elastic endpoint path must end in /_bulk")
    if kind == IntegrationKind.OTLP_HTTP_JSON and path != "/v1/logs":
        raise ValueError("OTLP log endpoint path must be /v1/logs")
    if kind == IntegrationKind.SIGNED_WEBHOOK and (not path or "//" in path):
        raise ValueError("webhook endpoint path is invalid")
    if kind in {IntegrationKind.SYSLOG_TLS, IntegrationKind.CEF_TLS}:
        if path or parsed.query or parsed.fragment or parsed.port is None:
            raise ValueError("TLS log endpoint must contain a host and explicit port only")
    return endpoint


class IntegrationDestinationSpec(StrictModel):
    destination_id: str = Field(pattern=r"^integration://[A-Za-z0-9_.@/-]+$")
    name: str = Field(min_length=3, max_length=128)
    kind: IntegrationKind
    endpoint: str = Field(min_length=10, max_length=512)
    allowed_hosts: List[str] = Field(min_length=1, max_length=16)
    credential_env: Optional[str] = Field(
        default=None, pattern=r"^[A-Z][A-Z0-9_]{2,127}$"
    )
    index: Optional[str] = Field(
        default=None, pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$"
    )
    sourcetype: str = Field(default="agentsec:finding", min_length=3, max_length=128)
    indexer_ack: bool = False
    enabled: bool = True
    max_attempts: int = Field(default=5, ge=1, le=20)
    retry_base_seconds: int = Field(default=10, ge=1, le=3600)

    @model_validator(mode="after")
    def coherent_destination(self) -> "IntegrationDestinationSpec":
        if len(set(item.lower() for item in self.allowed_hosts)) != len(self.allowed_hosts):
            raise ValueError("integration allowed hosts must be unique")
        validate_integration_endpoint(self.kind, self.endpoint, self.allowed_hosts)
        if self.kind in {IntegrationKind.SPLUNK_HEC, IntegrationKind.ELASTIC_BULK} and not self.index:
            raise ValueError("Splunk and Elastic destinations require an index")
        if self.kind != IntegrationKind.SPLUNK_HEC and self.indexer_ack:
            raise ValueError("indexer acknowledgment is Splunk-only")
        if self.kind in {
            IntegrationKind.SPLUNK_HEC,
            IntegrationKind.ELASTIC_BULK,
            IntegrationKind.SIGNED_WEBHOOK,
        } and self.credential_env is None:
            raise ValueError("destination requires an environment-backed credential")
        return self


class IntegrationPolicy(StrictModel):
    schema_version: str = "1.0.0"
    policy_version: str = Field(min_length=3, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    destinations: List[IntegrationDestinationSpec] = Field(
        min_length=1, max_length=MAX_DESTINATIONS
    )

    @model_validator(mode="after")
    def unique_destinations(self) -> "IntegrationPolicy":
        identifiers = [item.destination_id for item in self.destinations]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("integration destination IDs must be unique")
        return self


class ExternalSecurityEvent(StrictModel):
    schema_version: str = "1.0.0"
    event_id: str = Field(pattern=r"^xevt_[0-9a-f]{32}$")
    event_type: str = Field(default="finding", pattern=r"^(finding|incident|alert|audit)$")
    tenant_id: str = Field(min_length=1, max_length=128)
    finding_id: str = Field(pattern=r"^fnd_[A-Za-z0-9]+$")
    finding_type: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    status: str = Field(min_length=1, max_length=64)
    agent_id: str = Field(min_length=1, max_length=128)
    flow_id: str = Field(min_length=1, max_length=128)
    operation: str = Field(min_length=1, max_length=128)
    resource_class: str = Field(min_length=1, max_length=64)
    destination_class: Optional[str] = Field(default=None, max_length=64)
    detector_id: str = Field(min_length=1, max_length=128)
    policy_version: str = Field(min_length=1, max_length=128)
    decision: str = Field(min_length=1, max_length=64)
    escalation_level: str = Field(min_length=1, max_length=64)
    case_id: Optional[str] = Field(default=None, max_length=128)
    evidence_pivot_id: str = Field(min_length=1, max_length=128)
    ledger_integrity: str = Field(pattern=r"^(verified|failed)$")
    observed_at: datetime
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def valid_record(self) -> "ExternalSecurityEvent":
        _aware(self.observed_at)
        body = self.model_dump(mode="json", exclude={"record_sha256"})
        if not hmac.compare_digest(self.record_sha256, _sha256(body)):
            raise ValueError("external event digest is invalid")
        return self

    @classmethod
    def from_pipeline(
        cls, result: PipelineResult, *, ledger_valid: bool
    ) -> "ExternalSecurityEvent":
        export = PrivacyTransformer().soc_export(result, ledger_valid=ledger_valid)
        return cls.from_soc_export(export, observed_at=result.alert.detected_at)

    @classmethod
    def from_soc_export(
        cls, export: SocFindingExport, *, observed_at: Optional[datetime] = None
    ) -> "ExternalSecurityEvent":
        payload: Dict[str, Any] = {
            "schema_version": "1.0.0",
            "event_id": _stable_id("xevt", export.tenant_id, export.finding_id),
            "event_type": "finding",
            **export.model_dump(mode="json", exclude={"schema_version"}),
            "observed_at": _iso(observed_at or utc_now()),
        }
        payload["record_sha256"] = _sha256(payload)
        return cls.model_validate(payload)


class ExternalEventPage(StrictModel):
    schema_version: str = "1.0.0"
    events: List[ExternalSecurityEvent] = Field(max_length=MAX_EVENT_PAGE)
    next_cursor: Optional[str] = Field(default=None, max_length=4096)
    count: int = Field(ge=0, le=MAX_EVENT_PAGE)


class IntegrationDestinationStatus(StrictModel):
    destination_id: str
    name: str
    kind: IntegrationKind
    enabled: bool
    ready: bool
    credential_required: bool
    credential_configured: bool
    indexer_ack: bool
    queued: int = Field(ge=0)
    ack_pending: int = Field(ge=0)
    delivered: int = Field(ge=0)
    dead_letter: int = Field(ge=0)
    last_error_code: Optional[str] = None


class IntegrationAttempt(StrictModel):
    attempt_id: str = Field(pattern=r"^iat_[0-9a-f]{32}$")
    delivery_id: str = Field(pattern=r"^idl_[0-9a-f]{32}$")
    sequence: int = Field(ge=1)
    operation: str = Field(pattern=r"^(send|ack_poll)$")
    accepted: bool
    acknowledged: bool
    error_code: Optional[str] = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{2,63}$"
    )
    provider_reference_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    provider_receipt_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    attempted_at: datetime


class IntegrationDelivery(StrictModel):
    schema_version: str = "1.0.0"
    delivery_id: str = Field(pattern=r"^idl_[0-9a-f]{32}$")
    tenant_id: str = Field(min_length=1, max_length=128)
    event_id: str = Field(pattern=r"^xevt_[0-9a-f]{32}$")
    destination_id: str = Field(pattern=r"^integration://[A-Za-z0-9_.@/-]+$")
    kind: IntegrationKind
    state: IntegrationDeliveryState
    attempts: int = Field(ge=0, le=1000)
    redrive_count: int = Field(ge=0, le=10)
    max_attempts: int = Field(ge=1, le=20)
    next_attempt_at: datetime
    accepted_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    provider_reference_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    provider_receipt_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    last_error_code: Optional[str] = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{2,63}$"
    )
    created_at: datetime
    updated_at: datetime
    delivery_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def coherent_delivery(self) -> "IntegrationDelivery":
        for item in (
            self.next_attempt_at,
            self.created_at,
            self.updated_at,
            self.accepted_at,
            self.acknowledged_at,
        ):
            if item is not None:
                _aware(item)
        if self.state in {
            IntegrationDeliveryState.ACK_PENDING,
            IntegrationDeliveryState.DELIVERED,
        } and self.accepted_at is None:
            raise ValueError("accepted integration delivery requires accepted_at")
        if self.state == IntegrationDeliveryState.DELIVERED and self.acknowledged_at is None:
            raise ValueError("delivered integration record requires acknowledgment")
        body = self.model_dump(mode="json", exclude={"delivery_sha256"})
        if not hmac.compare_digest(self.delivery_sha256, _sha256(body)):
            raise ValueError("integration delivery digest is invalid")
        return self


class IntegrationDeliveryDetail(StrictModel):
    delivery: IntegrationDelivery
    event: ExternalSecurityEvent
    attempts: List[IntegrationAttempt] = Field(max_length=1000)


class IntegrationDeliveryPage(StrictModel):
    schema_version: str = "1.0.0"
    deliveries: List[IntegrationDelivery] = Field(max_length=MAX_DELIVERY_PAGE)
    count: int = Field(ge=0, le=MAX_DELIVERY_PAGE)
    total: int = Field(ge=0)


class IntegrationHealth(StrictModel):
    schema_version: str = "1.0.0"
    status: str = Field(pattern=r"^(healthy|degraded|not_ready)$")
    policy_version: str
    events: int = Field(ge=0)
    queued: int = Field(ge=0)
    retrying: int = Field(ge=0)
    ack_pending: int = Field(ge=0)
    delivered: int = Field(ge=0)
    dead_letter: int = Field(ge=0)
    pipeline_enqueue_error: Optional[str] = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{2,63}$"
    )
    destinations: List[IntegrationDestinationStatus] = Field(
        max_length=MAX_DESTINATIONS
    )
    calculated_at: datetime = Field(default_factory=utc_now)


class IntegrationAuditEntry(StrictModel):
    sequence: int = Field(ge=1)
    tenant_id: str
    actor_id: str
    action: str = Field(pattern=r"^integration\.[a-z_]+$")
    object_id: str = Field(min_length=1, max_length=256)
    occurred_at: datetime
    previous_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    entry_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ExternalApiCapability(StrictModel):
    resource: str = Field(pattern=r"^[a-z][a-z_]+$")
    methods: List[str] = Field(min_length=1, max_length=8)
    paths: List[str] = Field(min_length=1, max_length=16)
    contract_version: str = Field(pattern=r"^\d+\.\d+\.\d+$")


class ExternalApiCapabilities(StrictModel):
    schema_version: str = "1.0.0"
    api_version: str = "v1"
    authentication: List[str] = Field(
        default_factory=lambda: ["bearer", "workload_hmac_v1"]
    )
    capabilities: List[ExternalApiCapability]
    export_formats: List[IntegrationKind]
    raw_content_exported: bool = False


class IntegrationProcessRequest(StrictModel):
    limit: int = Field(default=25, ge=1, le=MAX_PROCESS_BATCH)


class IntegrationRedriveRequest(StrictModel):
    reason: str = Field(min_length=3, max_length=512)


class IntegrationProcessResult(StrictModel):
    schema_version: str = "1.0.0"
    processed: int = Field(ge=0, le=MAX_PROCESS_BATCH)
    delivered: int = Field(ge=0, le=MAX_PROCESS_BATCH)
    ack_pending: int = Field(ge=0, le=MAX_PROCESS_BATCH)
    retried: int = Field(ge=0, le=MAX_PROCESS_BATCH)
    dead_lettered: int = Field(ge=0, le=MAX_PROCESS_BATCH)


class IntegrationTransportResponse(StrictModel):
    status_code: int = Field(ge=100, le=599)
    body: Dict[str, Any] = Field(default_factory=dict, max_length=128)
    receipt: Optional[str] = Field(default=None, max_length=4096)


class IntegrationTransport(Protocol):
    def post(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> IntegrationTransportResponse:
        ...

    def send_line(
        self,
        *,
        endpoint: str,
        message: str,
        timeout_seconds: float,
    ) -> IntegrationTransportResponse:
        ...


def _require_public_resolution(host: str, port: int) -> None:
    try:
        results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise RuntimeError("integration_dns_unavailable") from None
    addresses = {item[4][0] for item in results}
    if not addresses or any(not ipaddress.ip_address(item).is_global for item in addresses):
        raise RuntimeError("integration_endpoint_not_public")


class _NoIntegrationRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class UrllibIntegrationTransport:
    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoIntegrationRedirect())

    def post(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> IntegrationTransportResponse:
        parsed = urlsplit(url)
        host = parsed.hostname
        if not host:
            raise RuntimeError("integration_endpoint_invalid")
        _require_public_resolution(host, parsed.port or 443)
        request = urllib.request.Request(
            url, data=body, headers=dict(headers), method="POST"
        )
        try:
            with self._opener.open(request, timeout=timeout_seconds) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                status = int(response.status)
        except urllib.error.HTTPError as exc:
            raise RuntimeError("integration_http_%d" % exc.code) from None
        except (urllib.error.URLError, socket.timeout, TimeoutError):
            raise RuntimeError("integration_transport_unavailable") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise RuntimeError("integration_response_too_large")
        payload: Dict[str, Any] = {}
        if raw:
            try:
                decoded = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise RuntimeError("integration_response_invalid") from None
            if not isinstance(decoded, dict):
                raise RuntimeError("integration_response_invalid")
            payload = decoded
        return IntegrationTransportResponse(
            status_code=status,
            body=payload,
            receipt=_sha256(raw.decode("utf-8", errors="replace")),
        )

    def send_line(
        self,
        *,
        endpoint: str,
        message: str,
        timeout_seconds: float,
    ) -> IntegrationTransportResponse:
        parsed = urlsplit(endpoint)
        host = parsed.hostname
        port = parsed.port
        if not host or port is None:
            raise RuntimeError("integration_endpoint_invalid")
        _require_public_resolution(host, port)
        encoded = message.encode("utf-8")
        framed = str(len(encoded)).encode("ascii") + b" " + encoded
        try:
            with socket.create_connection((host, port), timeout=timeout_seconds) as raw_socket:
                with ssl.create_default_context().wrap_socket(
                    raw_socket, server_hostname=host
                ) as tls_socket:
                    tls_socket.sendall(framed)
        except (OSError, socket.timeout, ssl.SSLError):
            raise RuntimeError("integration_transport_unavailable") from None
        return IntegrationTransportResponse(
            status_code=200, receipt=_sha256(message)
        )


def _severity_number(severity: str) -> int:
    return {"info": 9, "low": 10, "medium": 13, "high": 17, "critical": 21}[severity]


def render_splunk_event(
    event: ExternalSecurityEvent, destination: IntegrationDestinationSpec
) -> bytes:
    payload = {
        "time": _aware(event.observed_at).timestamp(),
        "event": event.model_dump(mode="json"),
        "sourcetype": destination.sourcetype,
        "source": "agentsec",
        "index": destination.index,
        "fields": {"event_id": event.event_id, "tenant_id": event.tenant_id},
    }
    return _canonical_json(payload).encode("utf-8")


def render_elastic_bulk(
    event: ExternalSecurityEvent, destination: IntegrationDestinationSpec
) -> bytes:
    action = {"create": {"_index": destination.index, "_id": event.event_id}}
    return ("%s\n%s\n" % (_canonical_json(action), _canonical_json(event))).encode("utf-8")


def render_webhook(event: ExternalSecurityEvent) -> bytes:
    return _canonical_json(
        {
            "schema_version": "1.0.0",
            "event_type": "agentsec.finding.v1",
            "event": event.model_dump(mode="json"),
        }
    ).encode("utf-8")


def render_otlp_logs(event: ExternalSecurityEvent) -> bytes:
    timestamp_ns = str(int(_aware(event.observed_at).timestamp() * 1_000_000_000))
    attributes = [
        {"key": "agentsec.%s" % key, "value": {"stringValue": str(value)}}
        for key, value in sorted(
            {
                "event_id": event.event_id,
                "finding_id": event.finding_id,
                "finding_type": event.finding_type,
                "tenant_id": event.tenant_id,
                "decision": event.decision,
                "ledger_integrity": event.ledger_integrity,
            }.items()
        )
    ]
    payload = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "service.name",
                            "value": {"stringValue": "agentsec"},
                        }
                    ]
                },
                "scopeLogs": [
                    {
                        "scope": {"name": "agentsec.external", "version": "1.0.0"},
                        "logRecords": [
                            {
                                "timeUnixNano": timestamp_ns,
                                "observedTimeUnixNano": timestamp_ns,
                                "severityNumber": _severity_number(event.severity),
                                "severityText": event.severity.upper(),
                                "eventName": "agentsec.finding",
                                "body": {"stringValue": event.finding_type},
                                "attributes": attributes,
                            }
                        ],
                    }
                ],
            }
        ]
    }
    return _canonical_json(payload).encode("utf-8")


def _syslog_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def render_rfc5424(event: ExternalSecurityEvent) -> str:
    syslog_severity = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}[
        event.severity
    ]
    priority = 16 * 8 + syslog_severity
    structured = (
        '[agentsec@32473 eventId="%s" findingId="%s" tenantId="%s" '
        'decision="%s" integrity="%s"]'
        % tuple(
            _syslog_escape(item)
            for item in (
                event.event_id,
                event.finding_id,
                event.tenant_id,
                event.decision,
                event.ledger_integrity,
            )
        )
    )
    message = "%s severity=%s" % (event.finding_type, event.severity)
    # RFC 5424 requires HOSTNAME, APP-NAME, PROCID, and MSGID before the
    # STRUCTURED-DATA element. Use stable non-identifying names and NILVALUE
    # for process/message identity.
    return "<%d>1 %s agentsec agentsec - - %s %s" % (
        priority,
        _iso(event.observed_at),
        structured,
        message,
    )


def _cef_header_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _cef_extension_escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def render_cef(event: ExternalSecurityEvent) -> str:
    severity = {"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}[
        event.severity
    ]
    header = "CEF:0|OpenAI-Labs|AgentSec|1.0|%s|%s|%d|" % (
        _cef_header_escape(event.finding_type),
        _cef_header_escape(event.finding_type.replace("_", " ").title()),
        severity,
    )
    extension = {
        "externalId": event.event_id,
        "deviceCustomString1": event.finding_id,
        "deviceCustomString1Label": "Finding ID",
        "deviceCustomString2": event.tenant_id,
        "deviceCustomString2Label": "Tenant ID",
        "deviceCustomString3": event.decision,
        "deviceCustomString3Label": "Decision",
        "deviceCustomString4": event.ledger_integrity,
        "deviceCustomString4Label": "Ledger Integrity",
    }
    return header + " ".join(
        "%s=%s" % (key, _cef_extension_escape(value))
        for key, value in extension.items()
    )


class ConnectorOutcome(StrictModel):
    accepted: bool
    acknowledged: bool
    provider_reference: Optional[str] = Field(default=None, max_length=256)
    provider_receipt_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    error_code: Optional[str] = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{2,63}$"
    )


class GovernedIntegrationConnector:
    def __init__(
        self,
        transport: Optional[IntegrationTransport] = None,
        *,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not 0.1 <= timeout_seconds <= 30.0:
            raise ValueError("integration connector timeout is invalid")
        self.transport = transport or UrllibIntegrationTransport()
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _error(code: str) -> ConnectorOutcome:
        if re.fullmatch(r"[a-z][a-z0-9_]{2,63}", code) is None:
            code = "integration_connector_failed"
        return ConnectorOutcome(accepted=False, acknowledged=False, error_code=code)

    def send(
        self,
        destination: IntegrationDestinationSpec,
        event: ExternalSecurityEvent,
        *,
        delivery_id: str,
        credential: Optional[str],
    ) -> ConnectorOutcome:
        validate_integration_endpoint(
            destination.kind, destination.endpoint, destination.allowed_hosts
        )
        if destination.credential_env is not None and not credential:
            return self._error("integration_credential_unavailable")
        if (
            destination.kind == IntegrationKind.SIGNED_WEBHOOK
            and len(str(credential).encode("utf-8")) < 32
        ):
            return self._error("integration_credential_invalid")
        try:
            if destination.kind == IntegrationKind.SPLUNK_HEC:
                response = self.transport.post(
                    url=destination.endpoint,
                    headers={
                        "Authorization": "Splunk %s" % credential,
                        "Content-Type": "application/json",
                        "X-Splunk-Request-Channel": delivery_id,
                    },
                    body=render_splunk_event(event, destination),
                    timeout_seconds=self.timeout_seconds,
                )
                if response.status_code // 100 != 2 or response.body.get("code") not in {0, "0"}:
                    return self._error("splunk_event_rejected")
                if destination.indexer_ack:
                    ack_id = response.body.get("ackId")
                    if not isinstance(ack_id, int) or ack_id < 0:
                        return self._error("splunk_ack_id_missing")
                    return ConnectorOutcome(
                        accepted=True,
                        acknowledged=False,
                        provider_reference=str(ack_id),
                        provider_receipt_sha256=response.receipt,
                    )
                return ConnectorOutcome(
                    accepted=True,
                    acknowledged=True,
                    provider_receipt_sha256=response.receipt,
                )
            if destination.kind == IntegrationKind.ELASTIC_BULK:
                response = self.transport.post(
                    url=destination.endpoint,
                    headers={
                        "Authorization": "ApiKey %s" % credential,
                        "Content-Type": "application/x-ndjson",
                        "X-Opaque-Id": delivery_id,
                    },
                    body=render_elastic_bulk(event, destination),
                    timeout_seconds=self.timeout_seconds,
                )
                items = response.body.get("items")
                statuses = []
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict) and isinstance(item.get("create"), dict):
                            statuses.append(item["create"].get("status"))
                if (
                    response.status_code // 100 != 2
                    or response.body.get("errors") is not False
                    or statuses != [201]
                ):
                    return self._error("elastic_bulk_rejected")
                return ConnectorOutcome(
                    accepted=True,
                    acknowledged=True,
                    provider_receipt_sha256=response.receipt,
                )
            if destination.kind == IntegrationKind.SIGNED_WEBHOOK:
                body = render_webhook(event)
                timestamp = str(int(utc_now().timestamp()))
                signature = hmac.new(
                    str(credential).encode("utf-8"),
                    timestamp.encode("ascii") + b"." + body,
                    hashlib.sha256,
                ).hexdigest()
                response = self.transport.post(
                    url=destination.endpoint,
                    headers={
                        "Content-Type": "application/json",
                        "Idempotency-Key": delivery_id,
                        "X-AgentSec-Timestamp": timestamp,
                        "X-AgentSec-Content-SHA256": hashlib.sha256(body).hexdigest(),
                        "X-AgentSec-Signature": "v1=%s" % signature,
                    },
                    body=body,
                    timeout_seconds=self.timeout_seconds,
                )
                if response.status_code // 100 != 2:
                    return self._error("webhook_rejected")
                return ConnectorOutcome(
                    accepted=True,
                    acknowledged=True,
                    provider_receipt_sha256=response.receipt,
                )
            if destination.kind == IntegrationKind.OTLP_HTTP_JSON:
                headers = {"Content-Type": "application/json"}
                if credential:
                    headers["Authorization"] = "Bearer %s" % credential
                response = self.transport.post(
                    url=destination.endpoint,
                    headers=headers,
                    body=render_otlp_logs(event),
                    timeout_seconds=self.timeout_seconds,
                )
                partial = response.body.get("partialSuccess", {})
                rejected = partial.get("rejectedLogRecords", 0) if isinstance(partial, dict) else 0
                if response.status_code // 100 != 2 or str(rejected) not in {"0", "None"}:
                    return self._error("otlp_logs_rejected")
                return ConnectorOutcome(
                    accepted=True,
                    acknowledged=True,
                    provider_receipt_sha256=response.receipt,
                )
            message = (
                render_cef(event)
                if destination.kind == IntegrationKind.CEF_TLS
                else render_rfc5424(event)
            )
            response = self.transport.send_line(
                endpoint=destination.endpoint,
                message=message,
                timeout_seconds=self.timeout_seconds,
            )
            if response.status_code // 100 != 2:
                return self._error("tls_log_rejected")
            return ConnectorOutcome(
                accepted=True,
                acknowledged=True,
                provider_receipt_sha256=response.receipt,
            )
        except RuntimeError as exc:
            return self._error(str(exc))

    def poll_ack(
        self,
        destination: IntegrationDestinationSpec,
        *,
        delivery_id: str,
        provider_reference: str,
        credential: Optional[str],
    ) -> ConnectorOutcome:
        if destination.kind != IntegrationKind.SPLUNK_HEC or not destination.indexer_ack:
            return self._error("integration_ack_not_supported")
        if not credential or not provider_reference.isdigit():
            return self._error("integration_ack_state_invalid")
        ack_url = destination.endpoint.rsplit("/", 1)[0] + "/ack"
        try:
            response = self.transport.post(
                url=ack_url,
                headers={
                    "Authorization": "Splunk %s" % credential,
                    "Content-Type": "application/json",
                    "X-Splunk-Request-Channel": delivery_id,
                },
                body=_canonical_json({"acks": [int(provider_reference)]}).encode("utf-8"),
                timeout_seconds=self.timeout_seconds,
            )
        except RuntimeError as exc:
            return self._error(str(exc))
        acks = response.body.get("acks")
        acknowledged = isinstance(acks, dict) and acks.get(provider_reference) is True
        if response.status_code // 100 != 2:
            return self._error("splunk_ack_rejected")
        return ConnectorOutcome(
            accepted=True,
            acknowledged=acknowledged,
            provider_reference=provider_reference,
            provider_receipt_sha256=response.receipt,
            error_code=None if acknowledged else "splunk_ack_pending",
        )


class IntegrationService:
    """Tenant-bound durable event stream, outbox, receipts, and audit ledger."""

    def __init__(
        self,
        database_path: str,
        *,
        cursor_secret: bytes,
        policy: IntegrationPolicy,
        connector: Optional[GovernedIntegrationConnector] = None,
        environment: Optional[Mapping[str, str]] = None,
    ) -> None:
        if len(cursor_secret) < 32:
            raise ValueError("integration cursor secret must contain at least 32 bytes")
        self.policy = policy
        self._cursor_secret = bytes(cursor_secret)
        self.connector = connector or GovernedIntegrationConnector()
        self._environment = environment if environment is not None else os.environ
        self._destinations = {item.destination_id: item for item in policy.destinations}
        self.pipeline_enqueue_error: Optional[str] = None
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            database_path, check_same_thread=False, isolation_level=None
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._create_schema()

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS integration_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                tenant_id TEXT NOT NULL,
                record_sha256 TEXT NOT NULL,
                event_json TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_integration_events_tenant_sequence
                ON integration_events(tenant_id, sequence);

            CREATE TABLE IF NOT EXISTS integration_deliveries (
                delivery_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                destination_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                state TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                redrive_count INTEGER NOT NULL,
                max_attempts INTEGER NOT NULL,
                next_attempt_at TEXT NOT NULL,
                accepted_at TEXT,
                acknowledged_at TEXT,
                provider_reference TEXT,
                provider_reference_sha256 TEXT,
                provider_receipt_sha256 TEXT,
                last_error_code TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                delivery_sha256 TEXT NOT NULL,
                UNIQUE(tenant_id, event_id, destination_id),
                FOREIGN KEY(event_id) REFERENCES integration_events(event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_integration_delivery_due
                ON integration_deliveries(tenant_id, state, next_attempt_at);
            CREATE INDEX IF NOT EXISTS idx_integration_delivery_destination
                ON integration_deliveries(tenant_id, destination_id, state);

            CREATE TABLE IF NOT EXISTS integration_attempts (
                attempt_id TEXT PRIMARY KEY,
                delivery_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                operation TEXT NOT NULL,
                accepted INTEGER NOT NULL,
                acknowledged INTEGER NOT NULL,
                error_code TEXT,
                provider_reference_sha256 TEXT,
                provider_receipt_sha256 TEXT,
                attempted_at TEXT NOT NULL,
                UNIQUE(delivery_id, sequence),
                FOREIGN KEY(delivery_id) REFERENCES integration_deliveries(delivery_id)
            );

            CREATE TABLE IF NOT EXISTS integration_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                action TEXT NOT NULL,
                object_id TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                previous_sha256 TEXT NOT NULL,
                entry_sha256 TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_integration_audit_tenant_sequence
                ON integration_audit(tenant_id, sequence);
            """
        )

    @staticmethod
    def _authorize(principal: IntegrationPrincipal, permission: str) -> None:
        if permission not in principal.permissions and INTEGRATION_ADMIN not in principal.permissions:
            raise IntegrationAuthorizationError("integration permission denied")

    def _tenant(self, principal: IntegrationPrincipal) -> None:
        if principal.tenant_id != self.policy.tenant_id:
            raise IntegrationAuthorizationError("integration tenant denied")

    def _audit(
        self,
        principal: IntegrationPrincipal,
        action: str,
        object_id: str,
        *,
        occurred_at: Optional[datetime] = None,
    ) -> None:
        previous_row = self._connection.execute(
            "SELECT entry_sha256 FROM integration_audit WHERE tenant_id = ? "
            "ORDER BY sequence DESC LIMIT 1",
            (principal.tenant_id,),
        ).fetchone()
        previous = str(previous_row["entry_sha256"]) if previous_row else ZERO_SHA256
        timestamp = _iso(occurred_at or utc_now())
        cursor = self._connection.execute(
            "INSERT INTO integration_audit "
            "(tenant_id, actor_id, action, object_id, occurred_at, previous_sha256, entry_sha256) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                principal.tenant_id,
                principal.actor_id,
                action,
                object_id,
                timestamp,
                previous,
                ZERO_SHA256,
            ),
        )
        sequence = int(cursor.lastrowid)
        body = {
            "sequence": sequence,
            "tenant_id": principal.tenant_id,
            "actor_id": principal.actor_id,
            "action": action,
            "object_id": object_id,
            "occurred_at": timestamp,
            "previous_sha256": previous,
        }
        self._connection.execute(
            "UPDATE integration_audit SET entry_sha256 = ? WHERE sequence = ?",
            (_sha256(body), sequence),
        )

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> ExternalSecurityEvent:
        payload = json.loads(str(row["event_json"]))
        if not isinstance(payload, dict):
            raise ValueError("integration event storage is invalid")
        event = ExternalSecurityEvent.model_validate(payload)
        if not hmac.compare_digest(event.record_sha256, str(row["record_sha256"])):
            raise ValueError("integration event storage digest is invalid")
        return event

    @staticmethod
    def _delivery_payload(values: Mapping[str, Any]) -> Dict[str, Any]:
        payload = {
            "schema_version": "1.0.0",
            "delivery_id": values["delivery_id"],
            "tenant_id": values["tenant_id"],
            "event_id": values["event_id"],
            "destination_id": values["destination_id"],
            "kind": values["kind"],
            "state": values["state"],
            "attempts": int(values["attempts"]),
            "redrive_count": int(values["redrive_count"]),
            "max_attempts": int(values["max_attempts"]),
            "next_attempt_at": values["next_attempt_at"],
            "accepted_at": values.get("accepted_at"),
            "acknowledged_at": values.get("acknowledged_at"),
            "provider_reference_sha256": values.get("provider_reference_sha256"),
            "provider_receipt_sha256": values.get("provider_receipt_sha256"),
            "last_error_code": values.get("last_error_code"),
            "created_at": values["created_at"],
            "updated_at": values["updated_at"],
        }
        payload["delivery_sha256"] = _sha256(payload)
        return payload

    @classmethod
    def _row_to_delivery(cls, row: sqlite3.Row) -> IntegrationDelivery:
        values = {key: row[key] for key in row.keys()}
        payload = cls._delivery_payload(values)
        if not hmac.compare_digest(payload["delivery_sha256"], str(row["delivery_sha256"])):
            raise ValueError("integration delivery storage digest is invalid")
        return IntegrationDelivery.model_validate(payload)

    @staticmethod
    def _row_to_attempt(row: sqlite3.Row) -> IntegrationAttempt:
        return IntegrationAttempt.model_validate(
            {
                "attempt_id": row["attempt_id"],
                "delivery_id": row["delivery_id"],
                "sequence": row["sequence"],
                "operation": row["operation"],
                "accepted": bool(row["accepted"]),
                "acknowledged": bool(row["acknowledged"]),
                "error_code": row["error_code"],
                "provider_reference_sha256": row["provider_reference_sha256"],
                "provider_receipt_sha256": row["provider_receipt_sha256"],
                "attempted_at": row["attempted_at"],
            }
        )

    def _write_delivery(self, values: Mapping[str, Any]) -> IntegrationDelivery:
        payload = self._delivery_payload(values)
        self._connection.execute(
            """
            UPDATE integration_deliveries SET
                state = ?, attempts = ?, redrive_count = ?, next_attempt_at = ?,
                accepted_at = ?, acknowledged_at = ?, provider_reference = ?,
                provider_reference_sha256 = ?, provider_receipt_sha256 = ?,
                last_error_code = ?, updated_at = ?, delivery_sha256 = ?
            WHERE delivery_id = ?
            """,
            (
                payload["state"],
                payload["attempts"],
                payload["redrive_count"],
                payload["next_attempt_at"],
                payload["accepted_at"],
                payload["acknowledged_at"],
                values.get("provider_reference"),
                payload["provider_reference_sha256"],
                payload["provider_receipt_sha256"],
                payload["last_error_code"],
                payload["updated_at"],
                payload["delivery_sha256"],
                payload["delivery_id"],
            ),
        )
        return IntegrationDelivery.model_validate(payload)

    def enqueue(
        self, principal: IntegrationPrincipal, event: ExternalSecurityEvent
    ) -> List[IntegrationDelivery]:
        self._authorize(principal, INTEGRATION_ENQUEUE)
        self._tenant(principal)
        if event.tenant_id != principal.tenant_id:
            raise IntegrationAuthorizationError("external event tenant denied")
        now = utc_now()
        created: List[IntegrationDelivery] = []
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT record_sha256 FROM integration_events WHERE event_id = ?",
                    (event.event_id,),
                ).fetchone()
                if existing is not None and not hmac.compare_digest(
                    str(existing["record_sha256"]), event.record_sha256
                ):
                    raise IntegrationConflictError("external event ID conflicts with prior content")
                if existing is None:
                    self._connection.execute(
                        "INSERT INTO integration_events "
                        "(event_id, tenant_id, record_sha256, event_json, observed_at, created_at) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            event.event_id,
                            event.tenant_id,
                            event.record_sha256,
                            _canonical_json(event),
                            _iso(event.observed_at),
                            _iso(now),
                        ),
                    )
                    self._audit(principal, "integration.event_enqueued", event.event_id, occurred_at=now)
                for destination in self.policy.destinations:
                    if not destination.enabled:
                        continue
                    delivery_id = _stable_id(
                        "idl", event.tenant_id, event.event_id, destination.destination_id
                    )
                    timestamp = _iso(now)
                    values: Dict[str, Any] = {
                        "delivery_id": delivery_id,
                        "tenant_id": event.tenant_id,
                        "event_id": event.event_id,
                        "destination_id": destination.destination_id,
                        "kind": destination.kind.value,
                        "state": IntegrationDeliveryState.QUEUED.value,
                        "attempts": 0,
                        "redrive_count": 0,
                        "max_attempts": destination.max_attempts,
                        "next_attempt_at": timestamp,
                        "accepted_at": None,
                        "acknowledged_at": None,
                        "provider_reference_sha256": None,
                        "provider_receipt_sha256": None,
                        "last_error_code": None,
                        "created_at": timestamp,
                        "updated_at": timestamp,
                    }
                    payload = self._delivery_payload(values)
                    cursor = self._connection.execute(
                        """
                        INSERT OR IGNORE INTO integration_deliveries
                        (delivery_id, tenant_id, event_id, destination_id, kind, state,
                         attempts, redrive_count, max_attempts, next_attempt_at,
                         accepted_at, acknowledged_at, provider_reference,
                         provider_reference_sha256, provider_receipt_sha256,
                         last_error_code, created_at, updated_at, delivery_sha256)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            delivery_id,
                            event.tenant_id,
                            event.event_id,
                            destination.destination_id,
                            destination.kind.value,
                            IntegrationDeliveryState.QUEUED.value,
                            0,
                            0,
                            destination.max_attempts,
                            timestamp,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            timestamp,
                            timestamp,
                            payload["delivery_sha256"],
                        ),
                    )
                    if cursor.rowcount:
                        delivery = IntegrationDelivery.model_validate(payload)
                        created.append(delivery)
                        self._audit(
                            principal,
                            "integration.delivery_created",
                            delivery_id,
                            occurred_at=now,
                        )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        self.pipeline_enqueue_error = None
        return created

    def enqueue_pipeline_result(
        self,
        principal: IntegrationPrincipal,
        result: PipelineResult,
        *,
        ledger_valid: bool,
    ) -> List[IntegrationDelivery]:
        return self.enqueue(
            principal,
            ExternalSecurityEvent.from_pipeline(result, ledger_valid=ledger_valid),
        )

    def capabilities(self, principal: IntegrationPrincipal) -> ExternalApiCapabilities:
        self._authorize(principal, INTEGRATION_READ)
        self._tenant(principal)
        return ExternalApiCapabilities(
            capabilities=[
                ExternalApiCapability(
                    resource="ingestion",
                    methods=["POST"],
                    paths=["/v1/telemetry", "/v1/telemetry/batch"],
                    contract_version="1.0.0",
                ),
                ExternalApiCapability(
                    resource="event_stream",
                    methods=["GET"],
                    paths=["/api/v1/events", "/api/v1/events/stream"],
                    contract_version="1.0.0",
                ),
                ExternalApiCapability(
                    resource="search",
                    methods=["POST"],
                    paths=["/api/v1/search"],
                    contract_version="1.0.0",
                ),
                ExternalApiCapability(
                    resource="entities",
                    methods=["GET"],
                    paths=["/api/v1/entities", "/api/v1/entities/{entity_id}"],
                    contract_version="1.0.0",
                ),
                ExternalApiCapability(
                    resource="rules",
                    methods=["GET"],
                    paths=["/api/v1/rules"],
                    contract_version="1.0.0",
                ),
                ExternalApiCapability(
                    resource="findings",
                    methods=["GET"],
                    paths=["/api/v1/findings", "/api/v1/findings/{finding_id}"],
                    contract_version="2.0.0",
                ),
                ExternalApiCapability(
                    resource="incidents",
                    methods=["GET"],
                    paths=[
                        "/api/v1/incidents",
                        "/api/v1/incidents/{incident_id}",
                    ],
                    contract_version="1.0.0",
                ),
                ExternalApiCapability(
                    resource="integrations",
                    methods=["GET", "POST"],
                    paths=[
                        "/api/v1/integrations",
                        "/api/v1/integrations/deliveries",
                        "/api/v1/integrations/process",
                    ],
                    contract_version="1.0.0",
                ),
            ],
            export_formats=list(IntegrationKind),
        )

    def _encode_cursor(self, principal: IntegrationPrincipal, sequence: int, event_types: List[str]) -> str:
        payload = _canonical_json(
            {
                "tenant_id": principal.tenant_id,
                "sequence": sequence,
                "event_types": event_types,
                "expires_at": int((utc_now() + timedelta(minutes=15)).timestamp()),
            }
        ).encode("utf-8")
        encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        signature = hmac.new(self._cursor_secret, payload, hashlib.sha256).hexdigest()
        return "%s.%s" % (encoded, signature)

    def _decode_cursor(
        self, principal: IntegrationPrincipal, cursor: str, event_types: List[str]
    ) -> int:
        if len(cursor) > 4096 or cursor.count(".") != 1:
            raise ValueError("external event cursor is invalid")
        encoded, supplied = cursor.split(".", 1)
        try:
            payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            decoded = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("external event cursor is invalid") from None
        expected = hmac.new(self._cursor_secret, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(supplied, expected) or not isinstance(decoded, dict):
            raise ValueError("external event cursor is invalid")
        if (
            decoded.get("tenant_id") != principal.tenant_id
            or decoded.get("event_types") != event_types
            or not isinstance(decoded.get("sequence"), int)
            or not isinstance(decoded.get("expires_at"), int)
            or decoded["expires_at"] < int(utc_now().timestamp())
        ):
            raise ValueError("external event cursor is invalid")
        return int(decoded["sequence"])

    def stream_events(
        self,
        principal: IntegrationPrincipal,
        *,
        limit: int = 100,
        cursor: Optional[str] = None,
        event_types: Optional[Sequence[str]] = None,
    ) -> ExternalEventPage:
        self._authorize(principal, INTEGRATION_READ)
        self._tenant(principal)
        if not 1 <= limit <= MAX_EVENT_PAGE:
            raise ValueError("external event limit is invalid")
        normalized = sorted(set(event_types or []))
        if any(item not in {"finding", "incident", "alert", "audit"} for item in normalized):
            raise ValueError("external event type filter is invalid")
        after = self._decode_cursor(principal, cursor, normalized) if cursor else 0
        sql = (
            "SELECT * FROM integration_events WHERE tenant_id = ? AND sequence > ?"
        )
        parameters: List[Any] = [principal.tenant_id, after]
        if normalized:
            placeholders = ",".join("?" for _ in normalized)
            sql += " AND json_extract(event_json, '$.event_type') IN (%s)" % placeholders
            parameters.extend(normalized)
        sql += " ORDER BY sequence ASC LIMIT ?"
        parameters.append(limit + 1)
        with self._lock:
            rows = self._connection.execute(sql, tuple(parameters)).fetchall()
        has_more = len(rows) > limit
        selected = rows[:limit]
        events = [self._row_to_event(row) for row in selected]
        next_cursor = None
        if has_more and selected:
            next_cursor = self._encode_cursor(
                principal, int(selected[-1]["sequence"]), normalized
            )
        return ExternalEventPage(events=events, next_cursor=next_cursor, count=len(events))

    def destinations(
        self, principal: IntegrationPrincipal
    ) -> List[IntegrationDestinationStatus]:
        self._authorize(principal, INTEGRATION_READ)
        self._tenant(principal)
        results: List[IntegrationDestinationStatus] = []
        with self._lock:
            for destination in self.policy.destinations:
                rows = self._connection.execute(
                    "SELECT state, COUNT(*) AS count FROM integration_deliveries "
                    "WHERE tenant_id = ? AND destination_id = ? GROUP BY state",
                    (principal.tenant_id, destination.destination_id),
                ).fetchall()
                counts = {str(row["state"]): int(row["count"]) for row in rows}
                error = self._connection.execute(
                    "SELECT last_error_code FROM integration_deliveries "
                    "WHERE tenant_id = ? AND destination_id = ? AND last_error_code IS NOT NULL "
                    "ORDER BY updated_at DESC LIMIT 1",
                    (principal.tenant_id, destination.destination_id),
                ).fetchone()
                credential_required = destination.credential_env is not None
                credential_configured = (
                    bool(self._environment.get(destination.credential_env, ""))
                    if destination.credential_env
                    else True
                )
                results.append(
                    IntegrationDestinationStatus(
                        destination_id=destination.destination_id,
                        name=destination.name,
                        kind=destination.kind,
                        enabled=destination.enabled,
                        ready=destination.enabled and credential_configured,
                        credential_required=credential_required,
                        credential_configured=credential_configured,
                        indexer_ack=destination.indexer_ack,
                        queued=counts.get(IntegrationDeliveryState.QUEUED.value, 0),
                        ack_pending=counts.get(IntegrationDeliveryState.ACK_PENDING.value, 0),
                        delivered=counts.get(IntegrationDeliveryState.DELIVERED.value, 0),
                        dead_letter=counts.get(IntegrationDeliveryState.DEAD_LETTER.value, 0),
                        last_error_code=str(error["last_error_code"]) if error else None,
                    )
                )
        return results

    def list_deliveries(
        self,
        principal: IntegrationPrincipal,
        *,
        state: Optional[IntegrationDeliveryState] = None,
        destination_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> IntegrationDeliveryPage:
        self._authorize(principal, INTEGRATION_READ)
        self._tenant(principal)
        if not 1 <= limit <= MAX_DELIVERY_PAGE or not 0 <= offset <= 1_000_000:
            raise ValueError("integration delivery page is invalid")
        if destination_id is not None and destination_id not in self._destinations:
            raise ValueError("integration destination filter is invalid")
        clauses = ["tenant_id = ?"]
        values: List[Any] = [principal.tenant_id]
        if state is not None:
            clauses.append("state = ?")
            values.append(state.value)
        if destination_id is not None:
            clauses.append("destination_id = ?")
            values.append(destination_id)
        where = " AND ".join(clauses)
        with self._lock:
            total = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM integration_deliveries WHERE " + where,
                    tuple(values),
                ).fetchone()[0]
            )
            rows = self._connection.execute(
                "SELECT * FROM integration_deliveries WHERE "
                + where
                + " ORDER BY created_at DESC, delivery_id ASC LIMIT ? OFFSET ?",
                tuple(values + [limit, offset]),
            ).fetchall()
        deliveries = [self._row_to_delivery(row) for row in rows]
        return IntegrationDeliveryPage(
            deliveries=deliveries, count=len(deliveries), total=total
        )

    def get_delivery(
        self, principal: IntegrationPrincipal, delivery_id: str
    ) -> IntegrationDeliveryDetail:
        self._authorize(principal, INTEGRATION_READ)
        self._tenant(principal)
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM integration_deliveries WHERE delivery_id = ? AND tenant_id = ?",
                (delivery_id, principal.tenant_id),
            ).fetchone()
            if row is None:
                raise KeyError(delivery_id)
            event_row = self._connection.execute(
                "SELECT * FROM integration_events WHERE event_id = ? AND tenant_id = ?",
                (row["event_id"], principal.tenant_id),
            ).fetchone()
            if event_row is None:
                raise ValueError("integration delivery event is missing")
            attempt_rows = self._connection.execute(
                "SELECT * FROM integration_attempts WHERE delivery_id = ? ORDER BY sequence",
                (delivery_id,),
            ).fetchall()
        return IntegrationDeliveryDetail(
            delivery=self._row_to_delivery(row),
            event=self._row_to_event(event_row),
            attempts=self._validated_attempts(row, attempt_rows),
        )

    @staticmethod
    def _validated_attempts(
        delivery_row: sqlite3.Row, attempt_rows: Sequence[sqlite3.Row]
    ) -> List[IntegrationAttempt]:
        attempts = [IntegrationService._row_to_attempt(item) for item in attempt_rows]
        expected_count = int(delivery_row["attempts"])
        if len(attempts) != expected_count or [item.sequence for item in attempts] != list(
            range(1, expected_count + 1)
        ):
            raise ValueError("integration attempt membership is invalid")
        return attempts

    def process_due(
        self, principal: IntegrationPrincipal, *, limit: int = 25
    ) -> IntegrationProcessResult:
        self._authorize(principal, INTEGRATION_DELIVER)
        self._tenant(principal)
        if not 1 <= limit <= MAX_PROCESS_BATCH:
            raise ValueError("integration process limit is invalid")
        counters = {
            "processed": 0,
            "delivered": 0,
            "ack_pending": 0,
            "retried": 0,
            "dead_lettered": 0,
        }
        with self._lock:
            due = self._connection.execute(
                "SELECT * FROM integration_deliveries WHERE tenant_id = ? "
                "AND state IN (?, ?, ?) AND next_attempt_at <= ? "
                "ORDER BY next_attempt_at, created_at, delivery_id LIMIT ?",
                (
                    principal.tenant_id,
                    IntegrationDeliveryState.QUEUED.value,
                    IntegrationDeliveryState.RETRY.value,
                    IntegrationDeliveryState.ACK_PENDING.value,
                    _iso(utc_now()),
                    limit,
                ),
            ).fetchall()
            for row in due:
                self._connection.execute("BEGIN IMMEDIATE")
                try:
                    values = {key: row[key] for key in row.keys()}
                    destination = self._destinations.get(str(row["destination_id"]))
                    if destination is None or not destination.enabled:
                        outcome = ConnectorOutcome(
                            accepted=False,
                            acknowledged=False,
                            error_code="integration_destination_unavailable",
                        )
                    else:
                        event_row = self._connection.execute(
                            "SELECT * FROM integration_events WHERE event_id = ? AND tenant_id = ?",
                            (row["event_id"], principal.tenant_id),
                        ).fetchone()
                        if event_row is None:
                            raise ValueError("integration delivery event is missing")
                        credential = (
                            self._environment.get(destination.credential_env)
                            if destination.credential_env
                            else None
                        )
                        if row["state"] == IntegrationDeliveryState.ACK_PENDING.value:
                            outcome = self.connector.poll_ack(
                                destination,
                                delivery_id=str(row["delivery_id"]),
                                provider_reference=str(row["provider_reference"] or ""),
                                credential=credential,
                            )
                        else:
                            outcome = self.connector.send(
                                destination,
                                self._row_to_event(event_row),
                                delivery_id=str(row["delivery_id"]),
                                credential=credential,
                            )
                    now = utc_now()
                    attempts = int(row["attempts"]) + 1
                    operation = (
                        "ack_poll"
                        if row["state"] == IntegrationDeliveryState.ACK_PENDING.value
                        else "send"
                    )
                    provider_reference = outcome.provider_reference or row["provider_reference"]
                    reference_sha = _sha256(provider_reference) if provider_reference else None
                    accepted_at = row["accepted_at"]
                    if outcome.accepted and accepted_at is None:
                        accepted_at = _iso(now)
                    acknowledged_at = row["acknowledged_at"]
                    if outcome.acknowledged:
                        acknowledged_at = _iso(now)
                        state = IntegrationDeliveryState.DELIVERED
                        counters["delivered"] += 1
                    elif attempts >= int(row["max_attempts"]):
                        state = IntegrationDeliveryState.DEAD_LETTER
                        counters["dead_lettered"] += 1
                    elif outcome.accepted and provider_reference:
                        state = IntegrationDeliveryState.ACK_PENDING
                        counters["ack_pending"] += 1
                    else:
                        state = IntegrationDeliveryState.RETRY
                        counters["retried"] += 1
                    delay = destination.retry_base_seconds if destination else 10
                    if state == IntegrationDeliveryState.RETRY:
                        delay = min(delay * (2 ** max(0, attempts - 1)), 3600)
                    values.update(
                        {
                            "state": state.value,
                            "attempts": attempts,
                            "next_attempt_at": _iso(now + timedelta(seconds=delay)),
                            "accepted_at": accepted_at,
                            "acknowledged_at": acknowledged_at,
                            "provider_reference": provider_reference,
                            "provider_reference_sha256": reference_sha,
                            "provider_receipt_sha256": outcome.provider_receipt_sha256,
                            "last_error_code": outcome.error_code,
                            "updated_at": _iso(now),
                        }
                    )
                    self._write_delivery(values)
                    self._connection.execute(
                        "INSERT INTO integration_attempts "
                        "(attempt_id, delivery_id, sequence, operation, accepted, acknowledged, "
                        "error_code, provider_reference_sha256, provider_receipt_sha256, attempted_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            _stable_id("iat", str(row["delivery_id"]), str(attempts)),
                            row["delivery_id"],
                            attempts,
                            operation,
                            1 if outcome.accepted else 0,
                            1 if outcome.acknowledged else 0,
                            outcome.error_code,
                            reference_sha,
                            outcome.provider_receipt_sha256,
                            _iso(now),
                        ),
                    )
                    self._audit(
                        principal,
                        "integration.delivery_%s" % state.value,
                        str(row["delivery_id"]),
                        occurred_at=now,
                    )
                    self._connection.execute("COMMIT")
                    counters["processed"] += 1
                except Exception:
                    self._connection.execute("ROLLBACK")
                    raise
        return IntegrationProcessResult(**counters)

    def redrive(
        self,
        principal: IntegrationPrincipal,
        delivery_id: str,
        *,
        reason: str,
    ) -> IntegrationDelivery:
        self._authorize(principal, INTEGRATION_REDRIVE)
        self._tenant(principal)
        request = IntegrationRedriveRequest(reason=reason)
        del request
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT * FROM integration_deliveries WHERE delivery_id = ? AND tenant_id = ?",
                    (delivery_id, principal.tenant_id),
                ).fetchone()
                if row is None:
                    raise KeyError(delivery_id)
                if row["state"] != IntegrationDeliveryState.DEAD_LETTER.value:
                    raise IntegrationConflictError("only dead-letter deliveries can be redriven")
                redrive_count = int(row["redrive_count"]) + 1
                if redrive_count > 10:
                    raise IntegrationConflictError("integration redrive limit exceeded")
                now = utc_now()
                values = {key: row[key] for key in row.keys()}
                values.update(
                    {
                        "state": IntegrationDeliveryState.QUEUED.value,
                        "attempts": int(row["attempts"]),
                        "redrive_count": redrive_count,
                        "max_attempts": min(
                            20,
                            int(row["attempts"])
                            + self._destinations[str(row["destination_id"])].max_attempts,
                        ),
                        "next_attempt_at": _iso(now),
                        "accepted_at": None,
                        "acknowledged_at": None,
                        "provider_reference": None,
                        "provider_reference_sha256": None,
                        "provider_receipt_sha256": None,
                        "last_error_code": None,
                        "updated_at": _iso(now),
                    }
                )
                delivery = self._write_delivery(values)
                self._audit(
                    principal,
                    "integration.delivery_redriven",
                    delivery_id,
                    occurred_at=now,
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return delivery

    def health(self, principal: IntegrationPrincipal) -> IntegrationHealth:
        self._authorize(principal, INTEGRATION_READ)
        self._tenant(principal)
        statuses = self.destinations(principal)
        with self._lock:
            event_count = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM integration_events WHERE tenant_id = ?",
                    (principal.tenant_id,),
                ).fetchone()[0]
            )
            rows = self._connection.execute(
                "SELECT state, COUNT(*) AS count FROM integration_deliveries "
                "WHERE tenant_id = ? GROUP BY state",
                (principal.tenant_id,),
            ).fetchall()
        counts = {str(row["state"]): int(row["count"]) for row in rows}
        not_ready = any(item.enabled and not item.ready for item in statuses)
        degraded = bool(counts.get(IntegrationDeliveryState.DEAD_LETTER.value, 0)) or bool(
            self.pipeline_enqueue_error
        )
        status = "not_ready" if not_ready else "degraded" if degraded else "healthy"
        return IntegrationHealth(
            status=status,
            policy_version=self.policy.policy_version,
            events=event_count,
            queued=counts.get(IntegrationDeliveryState.QUEUED.value, 0),
            retrying=counts.get(IntegrationDeliveryState.RETRY.value, 0),
            ack_pending=counts.get(IntegrationDeliveryState.ACK_PENDING.value, 0),
            delivered=counts.get(IntegrationDeliveryState.DELIVERED.value, 0),
            dead_letter=counts.get(IntegrationDeliveryState.DEAD_LETTER.value, 0),
            pipeline_enqueue_error=self.pipeline_enqueue_error,
            destinations=statuses,
        )

    def audit(
        self, principal: IntegrationPrincipal, *, limit: int = 200
    ) -> List[IntegrationAuditEntry]:
        self._authorize(principal, INTEGRATION_READ)
        self._tenant(principal)
        if not 1 <= limit <= 1000:
            raise ValueError("integration audit limit is invalid")
        with self._lock:
            all_rows = self._connection.execute(
                "SELECT * FROM integration_audit WHERE tenant_id = ? ORDER BY sequence",
                (principal.tenant_id,),
            ).fetchall()
        previous = ZERO_SHA256
        entries: List[IntegrationAuditEntry] = []
        for row in all_rows:
            body = {
                "sequence": int(row["sequence"]),
                "tenant_id": row["tenant_id"],
                "actor_id": row["actor_id"],
                "action": row["action"],
                "object_id": row["object_id"],
                "occurred_at": row["occurred_at"],
                "previous_sha256": row["previous_sha256"],
            }
            if row["previous_sha256"] != previous or not hmac.compare_digest(
                str(row["entry_sha256"]), _sha256(body)
            ):
                raise ValueError("integration audit ledger is invalid")
            entry = IntegrationAuditEntry.model_validate(
                {**body, "entry_sha256": row["entry_sha256"]}
            )
            entries.append(entry)
            previous = entry.entry_sha256
        return entries[-limit:]

    def close(self) -> None:
        with self._lock:
            self._connection.close()


def integration_service_from_config(
    database_path: str,
    config_path: str,
    *,
    cursor_secret: str,
    connector: Optional[GovernedIntegrationConnector] = None,
    environment: Optional[Mapping[str, str]] = None,
) -> Tuple[IntegrationService, IntegrationPrincipal]:
    if len(cursor_secret.encode("utf-8")) < 32:
        raise ValueError("integration cursor secret must contain at least 32 bytes")
    path = Path(config_path)
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("integration configuration size is invalid")
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("integration configuration is invalid JSON") from None
    policy = IntegrationPolicy.model_validate(decoded)
    service = IntegrationService(
        database_path,
        cursor_secret=cursor_secret.encode("utf-8"),
        policy=policy,
        connector=connector,
        environment=environment,
    )
    principal = IntegrationPrincipal(
        tenant_id=policy.tenant_id,
        actor_id="system://local-integration-service",
        permissions={
            INTEGRATION_READ,
            INTEGRATION_ENQUEUE,
            INTEGRATION_DELIVER,
            INTEGRATION_REDRIVE,
            INTEGRATION_ADMIN,
        },
    )
    return service, principal


class ExternalApiTransport(Protocol):
    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        payload: Optional[Mapping[str, Any]],
        timeout_seconds: float,
    ) -> Dict[str, Any]:
        ...


class UrllibExternalApiTransport:
    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoIntegrationRedirect())

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        payload: Optional[Mapping[str, Any]],
        timeout_seconds: float,
    ) -> Dict[str, Any]:
        body = None if payload is None else _canonical_json(payload).encode("utf-8")
        request = urllib.request.Request(
            url, data=body, headers=dict(headers), method=method
        )
        try:
            with self._opener.open(request, timeout=timeout_seconds) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise RuntimeError("AgentSec external API returned HTTP %d" % exc.code) from None
        except (urllib.error.URLError, socket.timeout, TimeoutError):
            raise RuntimeError("AgentSec external API unavailable") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise RuntimeError("AgentSec external API response is too large")
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError("AgentSec external API returned invalid JSON") from None
        if not isinstance(decoded, dict):
            raise RuntimeError("AgentSec external API response must be an object")
        return decoded


def _validate_api_endpoint(value: str, allow_loopback_http: bool) -> str:
    parsed = urlsplit(value)
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    if parsed.scheme != "https" and not (
        allow_loopback_http and loopback and parsed.scheme == "http"
    ):
        raise ValueError("external API endpoint must use HTTPS or explicit loopback HTTP")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("external API endpoint contains prohibited URL components")
    return value.rstrip("/")


class AgentSecExternalApiClient:
    """Small fixed-route Python consumer SDK; the bearer remains header-only."""

    def __init__(
        self,
        *,
        endpoint: str,
        token: str,
        transport: Optional[ExternalApiTransport] = None,
        allow_loopback_http: bool = False,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.endpoint = _validate_api_endpoint(endpoint, allow_loopback_http)
        if not 32 <= len(token.encode("utf-8")) <= 4096:
            raise ValueError("external API token is invalid")
        if not 0.1 <= timeout_seconds <= 30.0:
            raise ValueError("external API timeout is invalid")
        self._token = token
        self.transport = transport or UrllibExternalApiTransport()
        self.timeout_seconds = timeout_seconds

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: Optional[Mapping[str, str]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        suffix = "?" + urlencode(query) if query else ""
        headers = {"Authorization": "Bearer %s" % self._token}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        return self.transport.request(
            method=method,
            url=self.endpoint + path + suffix,
            headers=headers,
            payload=payload,
            timeout_seconds=self.timeout_seconds,
        )

    def capabilities(self) -> Dict[str, Any]:
        return self._request("GET", "/api/v1/capabilities")

    def stream_events(
        self,
        *,
        limit: int = 100,
        cursor: Optional[str] = None,
        event_types: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        if not 1 <= limit <= MAX_EVENT_PAGE:
            raise ValueError("external event limit is invalid")
        if cursor is not None and (not cursor or len(cursor) > 4096):
            raise ValueError("external event cursor is invalid")
        allowed_event_types = {"finding", "incident", "alert", "audit"}
        if event_types is not None and (
            not event_types
            or len(event_types) > len(allowed_event_types)
            or any(item not in allowed_event_types for item in event_types)
        ):
            raise ValueError("external event types are invalid")
        query = {"limit": str(limit)}
        if cursor:
            query["cursor"] = cursor
        if event_types:
            query["event_types"] = ",".join(event_types)
        return self._request("GET", "/api/v1/events/stream", query=query)

    def search(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        return self._request("POST", "/api/v1/search", payload=request)

    def list_entities(self, *, limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        if not 1 <= limit <= 200 or not 0 <= offset <= 1_000_000:
            raise ValueError("external entity page is invalid")
        return self._request(
            "GET",
            "/api/v1/entities",
            query={"limit": str(limit), "offset": str(offset)},
        )

    def list_rules(self) -> Dict[str, Any]:
        return self._request("GET", "/api/v1/rules")

    def list_findings(self, *, limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        if not 1 <= limit <= 200 or not 0 <= offset <= 1_000_000:
            raise ValueError("external finding page is invalid")
        return self._request(
            "GET",
            "/api/v1/findings",
            query={"limit": str(limit), "offset": str(offset)},
        )

    def list_incidents(self, *, limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        if not 1 <= limit <= 200 or not 0 <= offset <= 1_000_000:
            raise ValueError("external incident page is invalid")
        return self._request(
            "GET",
            "/api/v1/incidents",
            query={"limit": str(limit), "offset": str(offset)},
        )

    def get_entity(self, entity_id: str) -> Dict[str, Any]:
        if re.fullmatch(r"cmp_[A-Za-z0-9]+", entity_id) is None:
            raise ValueError("external entity ID is invalid")
        return self._request("GET", "/api/v1/entities/%s" % entity_id)

    def get_finding(self, finding_id: str) -> Dict[str, Any]:
        if re.fullmatch(r"fnd_[A-Za-z0-9]+", finding_id) is None:
            raise ValueError("external finding ID is invalid")
        return self._request("GET", "/api/v1/findings/%s" % finding_id)

    def get_incident(self, incident_id: str) -> Dict[str, Any]:
        if re.fullmatch(r"inc_[A-Za-z0-9]+", incident_id) is None:
            raise ValueError("external incident ID is invalid")
        return self._request("GET", "/api/v1/incidents/%s" % incident_id)

    def integrations(self) -> Dict[str, Any]:
        return self._request("GET", "/api/v1/integrations")

    def deliveries(
        self,
        *,
        state: Optional[IntegrationDeliveryState] = None,
        destination_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        if not 1 <= limit <= MAX_DELIVERY_PAGE or not 0 <= offset <= 1_000_000:
            raise ValueError("external delivery page is invalid")
        query = {"limit": str(limit), "offset": str(offset)}
        if state is not None:
            query["state"] = state.value
        if destination_id is not None:
            if re.fullmatch(r"integration://[A-Za-z0-9_.@/-]+", destination_id) is None:
                raise ValueError("external destination ID is invalid")
            query["destination_id"] = destination_id
        return self._request(
            "GET", "/api/v1/integrations/deliveries", query=query
        )

    def process_integrations(self, *, limit: int = 25) -> Dict[str, Any]:
        request = IntegrationProcessRequest(limit=limit)
        return self._request(
            "POST",
            "/api/v1/integrations/process",
            payload=request.model_dump(mode="json"),
        )

    def redrive_delivery(self, delivery_id: str, *, reason: str) -> Dict[str, Any]:
        if re.fullmatch(r"idl_[0-9a-f]{32}", delivery_id) is None:
            raise ValueError("external delivery ID is invalid")
        request = IntegrationRedriveRequest(reason=reason)
        return self._request(
            "POST",
            "/api/v1/integrations/deliveries/%s/redrive" % delivery_id,
            payload=request.model_dump(mode="json"),
        )
