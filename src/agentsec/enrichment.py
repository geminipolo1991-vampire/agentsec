"""Governed, concurrent, fail-explicit context enrichment."""

from __future__ import annotations

import asyncio
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import ssl
import threading
from time import monotonic, perf_counter
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
)
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from pydantic import Field, field_validator, model_validator

from .abom import AbomRegistry
from .authority import AuthorityGrant, AuthorityService
from .contracts import (
    AgentEvent,
    EnrichmentCacheStatus,
    EnrichmentFactValue,
    EnrichmentResult,
    EnrichmentSnapshot,
    EnrichmentStatus,
    StrictModel,
    utc_now,
)
from .crypto import canonical_bytes
from .graph import CausalPath
from .provenance import ProvenanceStore

if TYPE_CHECKING:
    from .observation import ObservationReconciler, SdkEffectReport
    from .synthetic import EffectObservation


FAILURE_EFFECT = "Missing context cannot relax deterministic enforcement"
ENRICHMENT_READ = "enrichment:read"
ENRICHMENT_EXECUTE = "enrichment:execute"
ENRICHMENT_ADMIN = "enrichment:admin"
MAX_CONNECTORS = 32
MAX_CONNECTOR_FACTS = 64
MAX_EVIDENCE_REFS = 32
MAX_HTTP_RESPONSE_BYTES = 1024 * 1024
MAX_CONNECTOR_PAYLOAD_BYTES = 64 * 1024
SAFE_INPUT_FIELDS = {
    "event_ref", "flow_ref", "agent_ref", "source_ref", "resource_ref",
    "destination_ref", "tool_ref", "operation", "resource_class",
    "destination_class", "source_type", "source_trust", "data_classes",
    "environment", "authority_operations",
}
STATUS_CONFIDENCE = {
    EnrichmentStatus.COMPLETE: 1.0,
    EnrichmentStatus.PARTIAL: 0.7,
    EnrichmentStatus.UNAVAILABLE: 0.0,
    EnrichmentStatus.FAILED: 0.0,
}


class EnrichmentAuthorizationError(PermissionError):
    """Raised when an enrichment principal exceeds its tenant or policy."""


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"


class ConnectorOutcome(str, Enum):
    SUCCESS = "success"
    CACHE_FRESH = "cache_fresh"
    CACHE_STALE = "cache_stale"
    POLICY_DENIED = "policy_denied"
    CIRCUIT_OPEN = "circuit_open"
    TIMEOUT = "timeout"
    FAILED = "failed"


class EnrichmentPrincipal(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=3, max_length=256)
    permissions: Set[str] = Field(default_factory=set, max_length=8)
    allowed_connectors: Set[str] = Field(default_factory=set, max_length=MAX_CONNECTORS)
    allowed_input_fields: Set[str] = Field(default_factory=set, max_length=len(SAFE_INPUT_FIELDS))

    @field_validator("permissions")
    @classmethod
    def valid_permissions(cls, value: Set[str]) -> Set[str]:
        if any(re.fullmatch(r"enrichment:[a-z]+", item) is None for item in value):
            raise ValueError("enrichment permissions must use enrichment:operation")
        return value

    @field_validator("allowed_connectors")
    @classmethod
    def valid_connectors(cls, value: Set[str]) -> Set[str]:
        if any(re.fullmatch(r"[a-z][a-z0-9_.-]{2,63}", item) is None for item in value):
            raise ValueError("allowed connector name is invalid")
        return value

    @field_validator("allowed_input_fields")
    @classmethod
    def valid_fields(cls, value: Set[str]) -> Set[str]:
        if not value.issubset(SAFE_INPUT_FIELDS):
            raise ValueError("connector input field is not in the metadata allowlist")
        return value


class EnrichmentConnectorSpec(StrictModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,63}$")
    version: str = Field(min_length=1, max_length=64)
    description: str = Field(min_length=3, max_length=512)
    required_fields: Set[str] = Field(default_factory=set, max_length=len(SAFE_INPUT_FIELDS))
    allowed_fact_keys: Set[str] = Field(min_length=1, max_length=MAX_CONNECTOR_FACTS)
    timeout_ms: int = Field(default=1000, ge=10, le=10000)
    cache_ttl_seconds: int = Field(default=300, ge=0, le=86400)
    max_stale_seconds: int = Field(default=3600, ge=0, le=604800)
    mandatory: bool = False

    @field_validator("required_fields")
    @classmethod
    def valid_required_fields(cls, value: Set[str]) -> Set[str]:
        if not value.issubset(SAFE_INPUT_FIELDS):
            raise ValueError("required connector input is not metadata-safe")
        return value

    @field_validator("allowed_fact_keys")
    @classmethod
    def valid_fact_keys(cls, value: Set[str]) -> Set[str]:
        if any(re.fullmatch(r"[a-z][a-z0-9_]{1,63}", item) is None for item in value):
            raise ValueError("connector fact key is invalid")
        return value

    @model_validator(mode="after")
    def valid_stale_window(self) -> "EnrichmentConnectorSpec":
        if self.max_stale_seconds < self.cache_ttl_seconds:
            raise ValueError("max stale window must include the fresh cache TTL")
        return self


class EnrichmentConnectorRequest(StrictModel):
    schema_version: str = "1.0.0"
    tenant_id: str = Field(min_length=1, max_length=128)
    connector: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,63}$")
    connector_version: str = Field(min_length=1, max_length=64)
    fields: Dict[str, EnrichmentFactValue] = Field(default_factory=dict, max_length=len(SAFE_INPUT_FIELDS))
    requested_at: datetime
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def bounded_request(self) -> "EnrichmentConnectorRequest":
        if len(canonical_bytes(self.fields)) > 64 * 1024:
            raise ValueError("connector request fields exceed the metadata size limit")
        return self


class EnrichmentConnectorPayload(StrictModel):
    schema_version: str = "1.0.0"
    source: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,63}$")
    status: EnrichmentStatus
    facts: Dict[str, EnrichmentFactValue] = Field(default_factory=dict, max_length=MAX_CONNECTOR_FACTS)
    evidence_refs: List[str] = Field(default_factory=list, max_length=MAX_EVIDENCE_REFS)
    affects_triage: bool = False
    observed_at: datetime = Field(default_factory=utc_now)

    @field_validator("status")
    @classmethod
    def valid_status(cls, value: EnrichmentStatus) -> EnrichmentStatus:
        if value == EnrichmentStatus.FAILED:
            raise ValueError("connectors must raise on failure")
        return value

    @field_validator("evidence_refs")
    @classmethod
    def safe_evidence_refs(cls, value: List[str]) -> List[str]:
        pattern = re.compile(r"^[a-z][a-z0-9_-]{1,31}_sha256:[0-9a-f]{24}$")
        if any(pattern.fullmatch(item) is None for item in value):
            raise ValueError("connector evidence references must be hashed references")
        return value

    @field_validator("observed_at")
    @classmethod
    def aware_observation(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("connector observation timestamp must include a timezone")
        return value

    @model_validator(mode="after")
    def bounded_payload(self) -> "EnrichmentConnectorPayload":
        if len(canonical_bytes(self.facts)) > 64 * 1024:
            raise ValueError("connector facts exceed the metadata size limit")
        return self


class EnrichmentConnectorHealth(StrictModel):
    tenant_id: str
    connector: str
    connector_version: str
    circuit_state: CircuitState
    circuit_open_until: Optional[datetime] = None
    successes: int = Field(ge=0)
    failures: int = Field(ge=0)
    timeouts: int = Field(ge=0)
    cache_hits: int = Field(ge=0)
    stale_fallbacks: int = Field(ge=0)
    consecutive_failures: int = Field(ge=0)
    cache_entries: int = Field(ge=0)
    last_outcome: Optional[ConnectorOutcome] = None
    last_latency_ms: Optional[int] = Field(default=None, ge=0)
    last_called_at: Optional[datetime] = None


class EnrichmentHealthSummary(StrictModel):
    schema_version: str = "1.0.0"
    tenant_id: str
    connector_count: int = Field(ge=0)
    healthy_connectors: int = Field(ge=0)
    open_circuits: int = Field(ge=0)
    cache_entries: int = Field(ge=0)
    connectors: List[EnrichmentConnectorHealth] = Field(default_factory=list)
    calculated_at: datetime


class HttpEnrichmentConnectorConfig(StrictModel):
    connector: EnrichmentConnectorSpec
    endpoint: str = Field(min_length=9, max_length=2048)
    bearer_token_env: Optional[str] = Field(
        default=None, pattern=r"^[A-Z][A-Z0-9_]{2,127}$"
    )


class EnrichmentRuntimeConfig(StrictModel):
    schema_version: str = "1.0.0"
    allowed_input_fields: Set[str] = Field(
        default_factory=set, max_length=len(SAFE_INPUT_FIELDS)
    )
    connectors: List[HttpEnrichmentConnectorConfig] = Field(
        default_factory=list, max_length=MAX_CONNECTORS
    )
    max_workers: int = Field(default=8, ge=1, le=32)
    circuit_failure_threshold: int = Field(default=3, ge=1, le=20)
    circuit_cooldown_seconds: int = Field(default=60, ge=1, le=3600)

    @field_validator("allowed_input_fields")
    @classmethod
    def valid_runtime_fields(cls, value: Set[str]) -> Set[str]:
        if not value.issubset(SAFE_INPUT_FIELDS):
            raise ValueError("runtime connector input field is not metadata-safe")
        return value

    @model_validator(mode="after")
    def unique_connectors(self) -> "EnrichmentRuntimeConfig":
        names = [item.connector.name for item in self.connectors]
        if len(names) != len(set(names)):
            raise ValueError("runtime connector names must be unique")
        return self


class EnrichmentConnector(Protocol):
    spec: EnrichmentConnectorSpec

    def enrich(self, request: EnrichmentConnectorRequest) -> EnrichmentConnectorPayload:
        """Return a bounded metadata-only enrichment payload."""


class CallableEnrichmentConnector:
    """Small connector SDK adapter for inventory, reputation, and CMDB clients."""

    def __init__(
        self,
        spec: EnrichmentConnectorSpec,
        callback: Callable[[EnrichmentConnectorRequest], EnrichmentConnectorPayload],
    ) -> None:
        self.spec = spec
        self._callback = callback

    def enrich(self, request: EnrichmentConnectorRequest) -> EnrichmentConnectorPayload:
        return self._callback(request)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class HttpJsonEnrichmentConnector:
    """HTTPS JSON connector with exact endpoint, bounded response, and no redirects."""

    def __init__(
        self,
        spec: EnrichmentConnectorSpec,
        *,
        endpoint: str,
        bearer_token: Optional[str] = None,
        transport: Optional[Callable[[str, bytes, Mapping[str, str], float], bytes]] = None,
    ) -> None:
        parsed = urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("connector endpoint must be an exact credential-free HTTPS URL")
        self.spec = spec
        self.endpoint = endpoint
        self._bearer_token = bearer_token
        self._transport = transport or self._default_transport

    @staticmethod
    def _default_transport(endpoint: str, body: bytes, headers: Mapping[str, str], timeout: float) -> bytes:
        request = Request(endpoint, data=body, headers=dict(headers), method="POST")
        opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), _NoRedirect())
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                raise RuntimeError("connector returned a non-success status")
            payload = response.read(MAX_HTTP_RESPONSE_BYTES + 1)
        if len(payload) > MAX_HTTP_RESPONSE_BYTES:
            raise RuntimeError("connector response exceeds the size limit")
        return payload

    def enrich(self, request: EnrichmentConnectorRequest) -> EnrichmentConnectorPayload:
        body = request.model_dump_json(exclude_none=True).encode("utf-8")
        if len(body) > MAX_CONNECTOR_PAYLOAD_BYTES:
            raise RuntimeError("connector request exceeds the semantic size limit")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._bearer_token:
            headers["Authorization"] = "Bearer %s" % self._bearer_token
        raw = self._transport(self.endpoint, body, headers, self.spec.timeout_ms / 1000)
        if len(raw) > MAX_HTTP_RESPONSE_BYTES:
            raise RuntimeError("connector response exceeds the size limit")
        return EnrichmentConnectorPayload.model_validate_json(raw)


@dataclass(frozen=True)
class _CacheCandidate:
    payload: EnrichmentConnectorPayload
    expires_at: datetime
    stale_until: datetime
    freshness_seconds: int


def evidence_ref(namespace: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return "%s_sha256:%s" % (namespace, digest[:24])


def resource_class(value: str) -> str:
    return value.split("://", 1)[0] if "://" in value else "opaque"


def destination_class(value: Optional[str]) -> str:
    if value is None:
        return "none"
    scheme = value.split("://", 1)[0].lower() if "://" in value else "opaque"
    return "external-network" if scheme in {"http", "https"} else scheme


@dataclass
class EnrichmentContext:
    """Trusted subsystem outputs supplied by the gateway, never by the browser."""

    authority_grant: Optional[AuthorityGrant] = None
    provenance_ids: Sequence[str] = field(default_factory=tuple)
    sdk_reports: Sequence["SdkEffectReport"] = field(default_factory=tuple)
    gateway_observations: Sequence["EffectObservation"] = field(default_factory=tuple)
    causal_path: Optional[CausalPath] = None
    agent_owner: Optional[str] = None
    approved_model_profile: Optional[str] = None
    observed_model_profile: Optional[str] = None
    asset_criticality: Optional[str] = None
    forced_failures: Set[str] = field(default_factory=set)


class EnrichmentEngine:
    """Runs built-ins plus governed live connectors without making them gates."""

    source_order = (
        "provenance",
        "effective_authority",
        "data_classification",
        "destination_classification",
        "abom_tool_drift",
        "agent_model_profile",
        "independent_observations",
        "causal_path",
        "repeat_frequency",
    )

    def __init__(
        self,
        *,
        abom_registry: Optional[AbomRegistry] = None,
        provenance_store: Optional[ProvenanceStore] = None,
        authority_service: Optional[AuthorityService] = None,
        observation_reconciler: Optional[Any] = None,
        connectors: Sequence[EnrichmentConnector] = (),
        principal: Optional[EnrichmentPrincipal] = None,
        database_path: str = ":memory:",
        max_workers: int = 8,
        circuit_failure_threshold: int = 3,
        circuit_cooldown_seconds: int = 60,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if connectors and principal is None:
            raise ValueError("live enrichment connectors require an execution principal")
        if not 1 <= max_workers <= 32:
            raise ValueError("enrichment max workers must be between 1 and 32")
        if not 1 <= circuit_failure_threshold <= 20:
            raise ValueError("circuit failure threshold must be between 1 and 20")
        if not 1 <= circuit_cooldown_seconds <= 3600:
            raise ValueError("circuit cooldown must be between 1 and 3600 seconds")
        self.abom_registry = abom_registry
        self.provenance_store = provenance_store
        self.authority_service = authority_service
        if observation_reconciler is None:
            from .observation import ObservationReconciler

            observation_reconciler = ObservationReconciler()
        self.observation_reconciler = observation_reconciler
        self.principal = principal
        self.database_path = database_path
        self.clock = clock
        self.circuit_failure_threshold = circuit_failure_threshold
        self.circuit_cooldown_seconds = circuit_cooldown_seconds
        self._connectors: Dict[str, EnrichmentConnector] = {}
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            database_path, check_same_thread=False, isolation_level=None
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if database_path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
        self._migrate()
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="agentsec-enrichment"
        )
        for connector in connectors:
            self._register(connector)

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
        with self._lock:
            self._connection.close()

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("enrichment clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _require(principal: EnrichmentPrincipal, permission: str) -> None:
        if permission not in principal.permissions:
            raise EnrichmentAuthorizationError(
                "missing enrichment permission: %s" % permission
            )

    def _migrate(self) -> None:
        with self._lock:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS enrichment_cache (
                    tenant_id TEXT NOT NULL,
                    connector TEXT NOT NULL,
                    cache_key TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    stale_until TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, connector, cache_key)
                );
                CREATE INDEX IF NOT EXISTS enrichment_cache_expiry
                    ON enrichment_cache(tenant_id, connector, stale_until);
                CREATE TABLE IF NOT EXISTS enrichment_connector_state (
                    tenant_id TEXT NOT NULL,
                    connector TEXT NOT NULL,
                    connector_version TEXT NOT NULL,
                    successes INTEGER NOT NULL DEFAULT 0,
                    failures INTEGER NOT NULL DEFAULT 0,
                    timeouts INTEGER NOT NULL DEFAULT 0,
                    cache_hits INTEGER NOT NULL DEFAULT 0,
                    stale_fallbacks INTEGER NOT NULL DEFAULT 0,
                    consecutive_failures INTEGER NOT NULL DEFAULT 0,
                    circuit_open_until TEXT,
                    last_outcome TEXT,
                    last_latency_ms INTEGER,
                    last_called_at TEXT,
                    PRIMARY KEY (tenant_id, connector)
                );
                """
            )

    def _register(self, connector: EnrichmentConnector) -> None:
        spec = EnrichmentConnectorSpec.model_validate(connector.spec)
        if spec.name in self.source_order:
            raise ValueError("connector name collides with a built-in enrichment source")
        if spec.name in self._connectors:
            raise ValueError("duplicate enrichment connector")
        if len(self._connectors) >= MAX_CONNECTORS:
            raise ValueError("too many enrichment connectors")
        self._connectors[spec.name] = connector

    def register_connector(
        self, principal: EnrichmentPrincipal, connector: EnrichmentConnector
    ) -> None:
        self._require(principal, ENRICHMENT_ADMIN)
        if self.principal is None or principal.tenant_id != self.principal.tenant_id:
            raise EnrichmentAuthorizationError("cross-tenant connector registration is forbidden")
        self._register(connector)

    def collect(
        self,
        event: AgentEvent,
        *,
        repeat_count: int,
        duplicate: bool = False,
        context: Optional[EnrichmentContext] = None,
    ) -> EnrichmentSnapshot:
        supplied = context or EnrichmentContext()
        sources: List[EnrichmentResult] = []
        for name in self.source_order:
            started = perf_counter()
            try:
                if name in supplied.forced_failures:
                    raise RuntimeError("forced enrichment outage")
                if name == "repeat_frequency":
                    result = self._repeat_frequency(
                        event, repeat_count, duplicate, supplied
                    )
                else:
                    result = getattr(self, "_%s" % name)(
                        event, repeat_count, supplied
                    )
                result = result.model_copy(
                    update={
                        "latency_ms": max(
                            0, round((perf_counter() - started) * 1000)
                        ),
                        "confidence": STATUS_CONFIDENCE[result.status],
                    }
                )
            except Exception:
                result = EnrichmentResult(
                    source=name,
                    status=EnrichmentStatus.FAILED,
                    facts={},
                    evidence_refs=[evidence_ref("event", event.event_id)],
                    latency_ms=max(0, round((perf_counter() - started) * 1000)),
                    affects_triage=True,
                    failure_effect=FAILURE_EFFECT,
                )
            sources.append(result)

        connector_counts = {
            "cache_hits": 0,
            "stale_fallbacks": 0,
            "timed_out_sources": 0,
        }
        if self._connectors:
            if self.principal is None:
                raise RuntimeError("enrichment execution principal is unavailable")
            self._require(self.principal, ENRICHMENT_EXECUTE)
            if event.tenant_id != self.principal.tenant_id:
                raise EnrichmentAuthorizationError(
                    "cross-tenant enrichment execution is forbidden"
                )
            live_sources, connector_counts = self._collect_connectors(event)
            sources.extend(live_sources)

        completed = sum(item.status == EnrichmentStatus.COMPLETE for item in sources)
        mandatory = {
            "provenance",
            "effective_authority",
            "data_classification",
            "destination_classification",
        }
        mandatory.update(
            connector.spec.name
            for connector in self._connectors.values()
            if connector.spec.mandatory
        )
        mandatory_complete = all(
            item.status not in {EnrichmentStatus.UNAVAILABLE, EnrichmentStatus.FAILED}
            for item in sources
            if item.source in mandatory
        )
        warnings = [
            "%s:%s" % (item.source, item.status.value)
            for item in sources
            if item.status != EnrichmentStatus.COMPLETE
        ]
        if all(item.status == EnrichmentStatus.FAILED for item in sources):
            overall = EnrichmentStatus.FAILED
        elif warnings:
            overall = EnrichmentStatus.PARTIAL
        else:
            overall = EnrichmentStatus.COMPLETE
        return EnrichmentSnapshot(
            status=overall,
            sources=sources,
            completed_sources=completed,
            total_sources=len(sources),
            mandatory_context_complete=mandatory_complete,
            warnings=warnings,
            connector_sources=len(self._connectors),
            cache_hits=connector_counts["cache_hits"],
            stale_fallbacks=connector_counts["stale_fallbacks"],
            timed_out_sources=connector_counts["timed_out_sources"],
            policy_digest=self._policy_digest(),
        )

    async def collect_async(
        self,
        event: AgentEvent,
        *,
        repeat_count: int,
        duplicate: bool = False,
        context: Optional[EnrichmentContext] = None,
    ) -> EnrichmentSnapshot:
        """Awaitable facade; live connector calls still use the bounded worker pool."""

        return await asyncio.to_thread(
            self.collect,
            event,
            repeat_count=repeat_count,
            duplicate=duplicate,
            context=context,
        )

    def _policy_digest(self) -> Optional[str]:
        if self.principal is None or not self._connectors:
            return None
        payload = {
            "tenant_id": self.principal.tenant_id,
            "allowed_connectors": sorted(self.principal.allowed_connectors),
            "allowed_input_fields": sorted(self.principal.allowed_input_fields),
            "connectors": [
                connector.spec.model_dump(mode="json")
                for connector in sorted(
                    self._connectors.values(), key=lambda item: item.spec.name
                )
            ],
        }
        return hashlib.sha256(canonical_bytes(payload)).hexdigest()

    def _provenance(
        self, event: AgentEvent, _repeat: int, context: EnrichmentContext
    ) -> EnrichmentResult:
        facts = {
            "source_type": event.source_type,
            "trust_class": event.source_trust.value,
            "cross_session_memory": event.source_type == "memory",
        }
        refs = [evidence_ref("source", event.source_id)]
        status = EnrichmentStatus.PARTIAL
        if self.provenance_store is not None and context.provenance_ids:
            records = [self.provenance_store.get(item) for item in context.provenance_ids]
            facts.update(
                {
                    "lineage_depth": len(records),
                    "lineage_trust_classes": sorted(
                        {record.trust_class.value for record in records}
                    ),
                }
            )
            refs.extend(evidence_ref("provenance", item) for item in context.provenance_ids)
            status = EnrichmentStatus.COMPLETE
        else:
            facts["lineage_depth"] = 1
        risky = event.source_trust.value in {
            "external-untrusted",
            "suspected-adversarial",
            "unknown",
        }
        return EnrichmentResult(
            source="provenance",
            status=status,
            facts=facts,
            evidence_refs=refs,
            affects_triage=risky or event.source_type == "memory",
            failure_effect=FAILURE_EFFECT,
        )

    def _effective_authority(
        self, event: AgentEvent, _repeat: int, context: EnrichmentContext
    ) -> EnrichmentResult:
        operation_allowed = event.operation in event.authority_operations
        facts = {
            "requested_operation": event.operation,
            "granted_operations": sorted(event.authority_operations),
            "operation_allowed": operation_allowed,
            "requested_resource_class": resource_class(event.resource),
        }
        refs = [evidence_ref("event", event.event_id)]
        status = EnrichmentStatus.PARTIAL
        if self.authority_service is not None and context.authority_grant is not None:
            full_scope_allowed = self.authority_service.authorize(
                context.authority_grant, event, consume=False
            )
            facts["full_scope_allowed"] = full_scope_allowed
            refs.append(evidence_ref("grant", context.authority_grant.grant_id))
            status = EnrichmentStatus.COMPLETE
        else:
            facts["full_scope_allowed"] = "unavailable"
        return EnrichmentResult(
            source="effective_authority",
            status=status,
            facts=facts,
            evidence_refs=refs,
            affects_triage=not operation_allowed,
            failure_effect=FAILURE_EFFECT,
        )

    def _data_classification(
        self, event: AgentEvent, _repeat: int, _context: EnrichmentContext
    ) -> EnrichmentResult:
        classifications = sorted(event.data_classes) or ["unclassified"]
        sensitive = bool({"secret", "restricted", "credential"} & event.data_classes)
        return EnrichmentResult(
            source="data_classification",
            status=EnrichmentStatus.COMPLETE,
            facts={
                "resource_class": resource_class(event.resource),
                "data_classes": classifications,
                "sensitive": sensitive,
            },
            evidence_refs=[evidence_ref("resource", event.resource)],
            affects_triage=sensitive,
            failure_effect=FAILURE_EFFECT,
        )

    def _destination_classification(
        self, event: AgentEvent, _repeat: int, _context: EnrichmentContext
    ) -> EnrichmentResult:
        classification = destination_class(event.destination)
        external = classification == "external-network"
        refs = [evidence_ref("destination", event.destination)] if event.destination else []
        return EnrichmentResult(
            source="destination_classification",
            status=EnrichmentStatus.COMPLETE,
            facts={"destination_class": classification, "external": external},
            evidence_refs=refs or [evidence_ref("event", event.event_id)],
            affects_triage=external,
            failure_effect=FAILURE_EFFECT,
        )

    def _abom_tool_drift(
        self, event: AgentEvent, _repeat: int, _context: EnrichmentContext
    ) -> EnrichmentResult:
        refs = [evidence_ref("event", event.event_id)]
        if self.abom_registry is not None:
            diff = self.abom_registry.observe(event)
            facts = {
                "tool_name": event.tool_name or "none",
                "drifted": diff.drifted,
                "unknown_agent": diff.unknown_agent,
                "changed_tool_schemas": sorted(diff.changed_tool_schemas),
                "new_operations": sorted(diff.new_operations),
                "new_destinations": sorted(
                    evidence_ref("destination", item) for item in diff.new_destinations
                ),
            }
            if diff.manifest_id:
                refs.append(evidence_ref("manifest", diff.manifest_id))
            status = EnrichmentStatus.COMPLETE
            drifted = diff.drifted
        elif event.tool_name is None:
            facts = {"tool_name": "none", "drifted": False, "comparison": "not_applicable"}
            status = EnrichmentStatus.COMPLETE
            drifted = False
        elif event.declared_tool_schema_digest and event.observed_tool_schema_digest:
            drifted = event.declared_tool_schema_digest != event.observed_tool_schema_digest
            facts = {
                "tool_name": event.tool_name,
                "drifted": drifted,
                "comparison": "event_digest_only",
                "declared_schema_ref": evidence_ref(
                    "schema", event.declared_tool_schema_digest
                ),
                "observed_schema_ref": evidence_ref(
                    "schema", event.observed_tool_schema_digest
                ),
            }
            status = EnrichmentStatus.PARTIAL
        else:
            facts = {"tool_name": event.tool_name, "drifted": "unknown"}
            status = EnrichmentStatus.UNAVAILABLE
            drifted = False
        return EnrichmentResult(
            source="abom_tool_drift",
            status=status,
            facts=facts,
            evidence_refs=refs,
            affects_triage=drifted,
            failure_effect=FAILURE_EFFECT,
        )

    def _agent_model_profile(
        self, event: AgentEvent, _repeat: int, context: EnrichmentContext
    ) -> EnrichmentResult:
        supplied = [
            context.agent_owner,
            context.approved_model_profile,
            context.observed_model_profile,
            context.asset_criticality,
        ]
        if not any(supplied):
            return EnrichmentResult(
                source="agent_model_profile",
                status=EnrichmentStatus.UNAVAILABLE,
                facts={"agent_id": event.agent_id, "profile_status": "not_supplied"},
                evidence_refs=[evidence_ref("agent", event.agent_id)],
                affects_triage=False,
                failure_effect=FAILURE_EFFECT,
            )
        mismatch = bool(
            context.approved_model_profile
            and context.observed_model_profile
            and context.approved_model_profile != context.observed_model_profile
        )
        facts = {
            "agent_id": event.agent_id,
            "owner_ref": evidence_ref("owner", context.agent_owner)
            if context.agent_owner
            else "unavailable",
            "approved_model_profile": context.approved_model_profile or "unavailable",
            "observed_model_profile": context.observed_model_profile or "unavailable",
            "model_profile_mismatch": mismatch,
            "asset_criticality": context.asset_criticality or "unknown",
        }
        return EnrichmentResult(
            source="agent_model_profile",
            status=EnrichmentStatus.COMPLETE if all(supplied) else EnrichmentStatus.PARTIAL,
            facts=facts,
            evidence_refs=[evidence_ref("agent", event.agent_id)],
            affects_triage=mismatch or context.asset_criticality in {"high", "critical"},
            failure_effect=FAILURE_EFFECT,
        )

    def _independent_observations(
        self, event: AgentEvent, _repeat: int, context: EnrichmentContext
    ) -> EnrichmentResult:
        if not context.sdk_reports and not context.gateway_observations:
            return EnrichmentResult(
                source="independent_observations",
                status=EnrichmentStatus.UNAVAILABLE,
                facts={"reconciliation": "not_supplied"},
                evidence_refs=[evidence_ref("event", event.event_id)],
                affects_triage=False,
                failure_effect=FAILURE_EFFECT,
            )
        findings = self.observation_reconciler.reconcile(
            event.event_id,
            list(context.sdk_reports),
            list(context.gateway_observations),
        )
        return EnrichmentResult(
            source="independent_observations",
            status=EnrichmentStatus.COMPLETE,
            facts={
                "sdk_phases": sorted({item.phase for item in context.sdk_reports}),
                "gateway_phases": sorted(
                    {item.phase for item in context.gateway_observations}
                ),
                "integrity_findings": sorted(
                    {item.finding_type for item in findings}
                ),
            },
            evidence_refs=[evidence_ref("event", event.event_id)],
            affects_triage=bool(findings),
            failure_effect=FAILURE_EFFECT,
        )

    def _causal_path(
        self, event: AgentEvent, _repeat: int, context: EnrichmentContext
    ) -> EnrichmentResult:
        if context.causal_path is not None:
            facts = {
                "node_count": len(context.causal_path.node_ids),
                "edge_count": len(context.causal_path.edge_ids),
                "path_scope": "recorded",
                "path_refs": [
                    evidence_ref("node", item) for item in context.causal_path.node_ids
                ],
            }
            status = EnrichmentStatus.COMPLETE
            refs = [evidence_ref("edge", item) for item in context.causal_path.edge_ids]
        else:
            path = [
                evidence_ref("source", event.source_id),
                evidence_ref("agent", event.agent_id),
            ]
            if event.tool_name:
                path.append(evidence_ref("tool", event.tool_name))
            if event.destination:
                path.append(evidence_ref("destination", event.destination))
            facts = {"node_count": len(path), "path_refs": path, "path_scope": "event_only"}
            status = EnrichmentStatus.PARTIAL
            refs = [evidence_ref("event", event.event_id)]
        return EnrichmentResult(
            source="causal_path",
            status=status,
            facts=facts,
            evidence_refs=refs or [evidence_ref("event", event.event_id)],
            affects_triage=False,
            failure_effect=FAILURE_EFFECT,
        )

    def _repeat_frequency(
        self,
        event: AgentEvent,
        repeat_count: int,
        duplicate: bool,
        _context: EnrichmentContext,
    ) -> EnrichmentResult:
        return EnrichmentResult(
            source="repeat_frequency",
            status=EnrichmentStatus.COMPLETE,
            facts={
                "flow_event_count": repeat_count,
                "duplicate_fingerprint": duplicate,
                "repeated": repeat_count > 1,
            },
            evidence_refs=[evidence_ref("flow", event.flow_id)],
            affects_triage=repeat_count > 1,
            failure_effect=FAILURE_EFFECT,
        )

    def _event_fields(self, event: AgentEvent) -> Dict[str, EnrichmentFactValue]:
        values: Dict[str, EnrichmentFactValue] = {
            "event_ref": evidence_ref("event", event.event_id),
            "flow_ref": evidence_ref("flow", event.flow_id),
            "agent_ref": evidence_ref("agent", event.agent_id),
            "source_ref": evidence_ref("source", event.source_id),
            "resource_ref": evidence_ref("resource", event.resource),
            "operation": event.operation,
            "resource_class": resource_class(event.resource),
            "destination_class": destination_class(event.destination),
            "source_type": event.source_type,
            "source_trust": event.source_trust.value,
            "data_classes": sorted(event.data_classes),
            "authority_operations": sorted(event.authority_operations),
            "environment": event.attributes.get("environment", "unknown"),
        }
        if event.destination:
            values["destination_ref"] = evidence_ref("destination", event.destination)
        if event.tool_name:
            values["tool_ref"] = evidence_ref("tool", event.tool_name)
        return values

    def _request_for(
        self, event: AgentEvent, spec: EnrichmentConnectorSpec
    ) -> EnrichmentConnectorRequest:
        assert self.principal is not None
        available = self._event_fields(event)
        fields = {
            name: available[name]
            for name in sorted(self.principal.allowed_input_fields)
            if name in available
        }
        missing = spec.required_fields - set(fields)
        if missing:
            raise EnrichmentAuthorizationError(
                "connector required fields are denied or unavailable"
            )
        digest_payload = {
            "tenant_id": event.tenant_id,
            "connector": spec.name,
            "connector_version": spec.version,
            "fields": fields,
        }
        request = EnrichmentConnectorRequest(
            tenant_id=event.tenant_id,
            connector=spec.name,
            connector_version=spec.version,
            fields=fields,
            requested_at=self._now(),
            input_sha256=hashlib.sha256(canonical_bytes(digest_payload)).hexdigest(),
        )
        if len(request.model_dump_json().encode("utf-8")) > MAX_CONNECTOR_PAYLOAD_BYTES:
            raise ValueError("connector request exceeds the semantic size limit")
        return request

    @staticmethod
    def _parse_time(value: Optional[str]) -> Optional[datetime]:
        if value is None:
            return None
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("stored enrichment timestamp is not timezone-aware")
        return parsed.astimezone(timezone.utc)

    def _cache_candidate(
        self, request: EnrichmentConnectorRequest, now: datetime
    ) -> Optional[_CacheCandidate]:
        with self._lock:
            row = self._connection.execute(
                "SELECT payload_json, expires_at, stale_until FROM enrichment_cache "
                "WHERE tenant_id = ? AND connector = ? AND cache_key = ?",
                (request.tenant_id, request.connector, request.input_sha256),
            ).fetchone()
        if row is None:
            return None
        try:
            payload = EnrichmentConnectorPayload.model_validate_json(row["payload_json"])
            expires_at = self._parse_time(row["expires_at"])
            stale_until = self._parse_time(row["stale_until"])
            assert expires_at is not None and stale_until is not None
            if now > stale_until:
                with self._lock:
                    self._connection.execute(
                        "DELETE FROM enrichment_cache WHERE tenant_id = ? AND connector = ? AND cache_key = ?",
                        (request.tenant_id, request.connector, request.input_sha256),
                    )
                return None
            observed = payload.observed_at.astimezone(timezone.utc)
            freshness = max(0, int((now - observed).total_seconds()))
            return _CacheCandidate(payload, expires_at, stale_until, freshness)
        except Exception:
            with self._lock:
                self._connection.execute(
                    "DELETE FROM enrichment_cache WHERE tenant_id = ? AND connector = ? AND cache_key = ?",
                    (request.tenant_id, request.connector, request.input_sha256),
                )
            return None

    def _cache_payload(
        self,
        request: EnrichmentConnectorRequest,
        spec: EnrichmentConnectorSpec,
        payload: EnrichmentConnectorPayload,
        now: datetime,
    ) -> None:
        expires = now + timedelta(seconds=spec.cache_ttl_seconds)
        stale_until = now + timedelta(seconds=spec.max_stale_seconds)
        with self._lock:
            self._connection.execute(
                "INSERT INTO enrichment_cache(tenant_id, connector, cache_key, payload_json, observed_at, expires_at, stale_until) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(tenant_id, connector, cache_key) DO UPDATE SET "
                "payload_json = excluded.payload_json, observed_at = excluded.observed_at, "
                "expires_at = excluded.expires_at, stale_until = excluded.stale_until",
                (
                    request.tenant_id,
                    spec.name,
                    request.input_sha256,
                    payload.model_dump_json(),
                    payload.observed_at.astimezone(timezone.utc).isoformat(),
                    expires.isoformat(),
                    stale_until.isoformat(),
                ),
            )

    def _state_row(self, tenant_id: str, connector: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._connection.execute(
                "SELECT * FROM enrichment_connector_state WHERE tenant_id = ? AND connector = ?",
                (tenant_id, connector),
            ).fetchone()

    def _circuit_open(
        self, tenant_id: str, connector: str, now: datetime
    ) -> Tuple[bool, Optional[datetime]]:
        row = self._state_row(tenant_id, connector)
        open_until = self._parse_time(row["circuit_open_until"]) if row else None
        return bool(open_until and now < open_until), open_until

    def _record_outcome(
        self,
        tenant_id: str,
        spec: EnrichmentConnectorSpec,
        outcome: ConnectorOutcome,
        *,
        latency_ms: Optional[int] = None,
        failed: bool = False,
        timed_out: bool = False,
        cache_hit: bool = False,
        stale_fallback: bool = False,
    ) -> None:
        now = self._now()
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM enrichment_connector_state WHERE tenant_id = ? AND connector = ?",
                (tenant_id, spec.name),
            ).fetchone()
            successes = int(row["successes"]) if row else 0
            failures = int(row["failures"]) if row else 0
            timeouts = int(row["timeouts"]) if row else 0
            cache_hits = int(row["cache_hits"]) if row else 0
            stale = int(row["stale_fallbacks"]) if row else 0
            consecutive = int(row["consecutive_failures"]) if row else 0
            open_until = row["circuit_open_until"] if row else None
            if outcome == ConnectorOutcome.SUCCESS:
                successes += 1
                consecutive = 0
                open_until = None
            elif failed:
                failures += 1
                timeouts += int(timed_out)
                consecutive += 1
                if consecutive >= self.circuit_failure_threshold:
                    open_until = (
                        now + timedelta(seconds=self.circuit_cooldown_seconds)
                    ).isoformat()
            cache_hits += int(cache_hit)
            stale += int(stale_fallback)
            self._connection.execute(
                "INSERT INTO enrichment_connector_state(tenant_id, connector, connector_version, successes, failures, timeouts, cache_hits, stale_fallbacks, consecutive_failures, circuit_open_until, last_outcome, last_latency_ms, last_called_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(tenant_id, connector) DO UPDATE SET connector_version = excluded.connector_version, "
                "successes = excluded.successes, failures = excluded.failures, timeouts = excluded.timeouts, "
                "cache_hits = excluded.cache_hits, stale_fallbacks = excluded.stale_fallbacks, "
                "consecutive_failures = excluded.consecutive_failures, circuit_open_until = excluded.circuit_open_until, "
                "last_outcome = excluded.last_outcome, last_latency_ms = excluded.last_latency_ms, "
                "last_called_at = excluded.last_called_at",
                (
                    tenant_id, spec.name, spec.version, successes, failures,
                    timeouts, cache_hits, stale, consecutive, open_until,
                    outcome.value, latency_ms, now.isoformat(),
                ),
            )

    @staticmethod
    def _validate_payload(
        spec: EnrichmentConnectorSpec, payload: EnrichmentConnectorPayload
    ) -> EnrichmentConnectorPayload:
        if payload.source != spec.name:
            raise ValueError("connector payload source does not match registration")
        if set(payload.facts) - spec.allowed_fact_keys:
            raise ValueError("connector returned a fact outside its output allowlist")
        if payload.observed_at.tzinfo is None or payload.observed_at.utcoffset() is None:
            raise ValueError("connector observation timestamp must be timezone-aware")
        if len(payload.model_dump_json().encode("utf-8")) > MAX_CONNECTOR_PAYLOAD_BYTES:
            raise ValueError("connector payload exceeds the semantic size limit")
        return payload

    @staticmethod
    def _from_payload(
        spec: EnrichmentConnectorSpec,
        payload: EnrichmentConnectorPayload,
        *,
        latency_ms: int,
        cache_status: EnrichmentCacheStatus,
        freshness_seconds: int,
        expires_at: Optional[datetime],
        policy_decision: str,
        force_partial: bool = False,
    ) -> EnrichmentResult:
        status = payload.status
        if force_partial and status == EnrichmentStatus.COMPLETE:
            status = EnrichmentStatus.PARTIAL
        return EnrichmentResult(
            source=spec.name,
            status=status,
            observed_at=payload.observed_at,
            confidence=STATUS_CONFIDENCE[status],
            facts=payload.facts,
            evidence_refs=payload.evidence_refs,
            latency_ms=max(0, latency_ms),
            affects_triage=payload.affects_triage,
            failure_effect=FAILURE_EFFECT,
            connector_version=spec.version,
            cache_status=cache_status,
            freshness_seconds=max(0, freshness_seconds),
            expires_at=expires_at,
            policy_decision=policy_decision,
        )

    @staticmethod
    def _connector_failure(
        event: AgentEvent,
        spec: EnrichmentConnectorSpec,
        *,
        status: EnrichmentStatus,
        latency_ms: int,
        decision: str,
    ) -> EnrichmentResult:
        return EnrichmentResult(
            source=spec.name,
            status=status,
            facts={},
            evidence_refs=[evidence_ref("event", event.event_id)],
            latency_ms=max(0, latency_ms),
            affects_triage=spec.mandatory,
            failure_effect=FAILURE_EFFECT,
            connector_version=spec.version,
            cache_status=EnrichmentCacheStatus.MISS,
            policy_decision=decision,
        )

    def _stale_result(
        self,
        spec: EnrichmentConnectorSpec,
        candidate: _CacheCandidate,
        *,
        latency_ms: int,
        decision: str,
    ) -> EnrichmentResult:
        return self._from_payload(
            spec,
            candidate.payload,
            latency_ms=latency_ms,
            cache_status=EnrichmentCacheStatus.STALE,
            freshness_seconds=candidate.freshness_seconds,
            expires_at=candidate.expires_at,
            policy_decision=decision,
            force_partial=True,
        )

    def _collect_connectors(
        self, event: AgentEvent
    ) -> Tuple[List[EnrichmentResult], Dict[str, int]]:
        assert self.principal is not None
        counts = {"cache_hits": 0, "stale_fallbacks": 0, "timed_out_sources": 0}
        completed: Dict[str, EnrichmentResult] = {}
        pending: List[
            Tuple[
                EnrichmentConnectorSpec,
                EnrichmentConnectorRequest,
                Future[EnrichmentConnectorPayload],
                Optional[_CacheCandidate],
                float,
                float,
            ]
        ] = []
        now = self._now()
        for connector in sorted(self._connectors.values(), key=lambda item: item.spec.name):
            spec = connector.spec
            if spec.name not in self.principal.allowed_connectors:
                completed[spec.name] = self._connector_failure(
                    event, spec, status=EnrichmentStatus.UNAVAILABLE,
                    latency_ms=0, decision=ConnectorOutcome.POLICY_DENIED.value,
                )
                self._record_outcome(
                    event.tenant_id, spec, ConnectorOutcome.POLICY_DENIED
                )
                continue
            try:
                request = self._request_for(event, spec)
            except EnrichmentAuthorizationError:
                completed[spec.name] = self._connector_failure(
                    event, spec, status=EnrichmentStatus.UNAVAILABLE,
                    latency_ms=0, decision=ConnectorOutcome.POLICY_DENIED.value,
                )
                self._record_outcome(
                    event.tenant_id, spec, ConnectorOutcome.POLICY_DENIED
                )
                continue
            candidate = self._cache_candidate(request, now)
            if candidate is not None and now <= candidate.expires_at:
                completed[spec.name] = self._from_payload(
                    spec, candidate.payload, latency_ms=0,
                    cache_status=EnrichmentCacheStatus.FRESH,
                    freshness_seconds=candidate.freshness_seconds,
                    expires_at=candidate.expires_at,
                    policy_decision=ConnectorOutcome.CACHE_FRESH.value,
                )
                counts["cache_hits"] += 1
                self._record_outcome(
                    event.tenant_id, spec, ConnectorOutcome.CACHE_FRESH,
                    latency_ms=0, cache_hit=True,
                )
                continue
            circuit_open, _ = self._circuit_open(event.tenant_id, spec.name, now)
            if circuit_open:
                if candidate is not None:
                    completed[spec.name] = self._stale_result(
                        spec, candidate, latency_ms=0,
                        decision="circuit_open_stale_fallback",
                    )
                    counts["cache_hits"] += 1
                    counts["stale_fallbacks"] += 1
                    self._record_outcome(
                        event.tenant_id, spec, ConnectorOutcome.CACHE_STALE,
                        latency_ms=0, cache_hit=True, stale_fallback=True,
                    )
                else:
                    completed[spec.name] = self._connector_failure(
                        event, spec, status=EnrichmentStatus.UNAVAILABLE,
                        latency_ms=0, decision=ConnectorOutcome.CIRCUIT_OPEN.value,
                    )
                    self._record_outcome(
                        event.tenant_id, spec, ConnectorOutcome.CIRCUIT_OPEN,
                        latency_ms=0,
                    )
                continue
            started = monotonic()
            future = self._executor.submit(connector.enrich, request)
            pending.append(
                (spec, request, future, candidate, started, started + spec.timeout_ms / 1000)
            )

        for spec, request, future, candidate, started, deadline in pending:
            remaining = max(0.0, deadline - monotonic())
            try:
                payload = future.result(timeout=remaining)
                payload = self._validate_payload(spec, payload)
                latency_ms = max(0, round((monotonic() - started) * 1000))
                if payload.status in {EnrichmentStatus.COMPLETE, EnrichmentStatus.PARTIAL}:
                    self._cache_payload(request, spec, payload, self._now())
                freshness = max(
                    0,
                    int((self._now() - payload.observed_at.astimezone(timezone.utc)).total_seconds()),
                )
                completed[spec.name] = self._from_payload(
                    spec, payload, latency_ms=latency_ms,
                    cache_status=EnrichmentCacheStatus.MISS,
                    freshness_seconds=freshness,
                    expires_at=(
                        self._now() + timedelta(seconds=spec.cache_ttl_seconds)
                        if payload.status in {EnrichmentStatus.COMPLETE, EnrichmentStatus.PARTIAL}
                        else None
                    ),
                    policy_decision=ConnectorOutcome.SUCCESS.value,
                )
                self._record_outcome(
                    event.tenant_id, spec, ConnectorOutcome.SUCCESS,
                    latency_ms=latency_ms,
                )
            except FutureTimeout:
                future.cancel()
                latency_ms = max(0, round((monotonic() - started) * 1000))
                counts["timed_out_sources"] += 1
                if candidate is not None:
                    completed[spec.name] = self._stale_result(
                        spec, candidate, latency_ms=latency_ms,
                        decision="timeout_stale_fallback",
                    )
                    counts["cache_hits"] += 1
                    counts["stale_fallbacks"] += 1
                else:
                    completed[spec.name] = self._connector_failure(
                        event, spec, status=EnrichmentStatus.FAILED,
                        latency_ms=latency_ms, decision=ConnectorOutcome.TIMEOUT.value,
                    )
                self._record_outcome(
                    event.tenant_id, spec, ConnectorOutcome.TIMEOUT,
                    latency_ms=latency_ms, failed=True, timed_out=True,
                    cache_hit=candidate is not None,
                    stale_fallback=candidate is not None,
                )
            except Exception:
                latency_ms = max(0, round((monotonic() - started) * 1000))
                if candidate is not None:
                    completed[spec.name] = self._stale_result(
                        spec, candidate, latency_ms=latency_ms,
                        decision="failure_stale_fallback",
                    )
                    counts["cache_hits"] += 1
                    counts["stale_fallbacks"] += 1
                else:
                    completed[spec.name] = self._connector_failure(
                        event, spec, status=EnrichmentStatus.FAILED,
                        latency_ms=latency_ms, decision=ConnectorOutcome.FAILED.value,
                    )
                self._record_outcome(
                    event.tenant_id, spec, ConnectorOutcome.FAILED,
                    latency_ms=latency_ms, failed=True,
                    cache_hit=candidate is not None,
                    stale_fallback=candidate is not None,
                )
        return [completed[name] for name in sorted(completed)], counts

    def health(self, principal: EnrichmentPrincipal) -> EnrichmentHealthSummary:
        self._require(principal, ENRICHMENT_READ)
        if self.principal is None or principal.tenant_id != self.principal.tenant_id:
            raise EnrichmentAuthorizationError("cross-tenant enrichment health is forbidden")
        now = self._now()
        connectors: List[EnrichmentConnectorHealth] = []
        for connector in sorted(self._connectors.values(), key=lambda item: item.spec.name):
            spec = connector.spec
            row = self._state_row(principal.tenant_id, spec.name)
            with self._lock:
                cache_entries = int(
                    self._connection.execute(
                        "SELECT COUNT(*) FROM enrichment_cache WHERE tenant_id = ? AND connector = ? AND stale_until >= ?",
                        (principal.tenant_id, spec.name, now.isoformat()),
                    ).fetchone()[0]
                )
            open_until = self._parse_time(row["circuit_open_until"]) if row else None
            is_open = bool(open_until and now < open_until)
            connectors.append(
                EnrichmentConnectorHealth(
                    tenant_id=principal.tenant_id,
                    connector=spec.name,
                    connector_version=spec.version,
                    circuit_state=CircuitState.OPEN if is_open else CircuitState.CLOSED,
                    circuit_open_until=open_until if is_open else None,
                    successes=int(row["successes"]) if row else 0,
                    failures=int(row["failures"]) if row else 0,
                    timeouts=int(row["timeouts"]) if row else 0,
                    cache_hits=int(row["cache_hits"]) if row else 0,
                    stale_fallbacks=int(row["stale_fallbacks"]) if row else 0,
                    consecutive_failures=int(row["consecutive_failures"]) if row else 0,
                    cache_entries=cache_entries,
                    last_outcome=ConnectorOutcome(row["last_outcome"])
                    if row and row["last_outcome"] else None,
                    last_latency_ms=int(row["last_latency_ms"])
                    if row and row["last_latency_ms"] is not None else None,
                    last_called_at=self._parse_time(row["last_called_at"]) if row else None,
                )
            )
        return EnrichmentHealthSummary(
            tenant_id=principal.tenant_id,
            connector_count=len(connectors),
            healthy_connectors=sum(
                item.circuit_state == CircuitState.CLOSED for item in connectors
            ),
            open_circuits=sum(
                item.circuit_state == CircuitState.OPEN for item in connectors
            ),
            cache_entries=sum(item.cache_entries for item in connectors),
            connectors=connectors,
            calculated_at=now,
        )


def enrichment_engine_from_config(
    config_path: str,
    *,
    database_path: str,
    tenant_id: str,
    actor_id: str = "system://local-enrichment-engine",
    environ: Optional[Mapping[str, str]] = None,
) -> Tuple[EnrichmentEngine, EnrichmentPrincipal]:
    """Build governed HTTPS connectors from a bounded, secret-free JSON file."""

    path = Path(config_path)
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("enrichment runtime config exceeds the size limit")
    config = EnrichmentRuntimeConfig.model_validate_json(
        path.read_text(encoding="utf-8")
    )
    environment = environ if environ is not None else os.environ
    names = {item.connector.name for item in config.connectors}
    principal = EnrichmentPrincipal(
        tenant_id=tenant_id,
        actor_id=actor_id,
        permissions={ENRICHMENT_READ, ENRICHMENT_EXECUTE, ENRICHMENT_ADMIN},
        allowed_connectors=names,
        allowed_input_fields=config.allowed_input_fields,
    )
    connectors: List[EnrichmentConnector] = []
    for item in config.connectors:
        token = None
        if item.bearer_token_env is not None:
            token = environment.get(item.bearer_token_env, "")
            if not token:
                raise ValueError(
                    "configured enrichment connector token environment variable is missing"
                )
        connectors.append(
            HttpJsonEnrichmentConnector(
                item.connector,
                endpoint=item.endpoint,
                bearer_token=token,
            )
        )
    return (
        EnrichmentEngine(
            connectors=connectors,
            principal=principal,
            database_path=database_path,
            max_workers=config.max_workers,
            circuit_failure_threshold=config.circuit_failure_threshold,
            circuit_cooldown_seconds=config.circuit_cooldown_seconds,
        ),
        principal,
    )


def enrichment_engine_from_config(
    config_path: str,
    *,
    database_path: str,
    tenant_id: str,
    actor_id: str = "system://local-enrichment-engine",
    environ: Optional[Mapping[str, str]] = None,
) -> Tuple[EnrichmentEngine, EnrichmentPrincipal]:
    """Build governed HTTPS connectors; configuration references, but never stores, secrets."""

    path = Path(config_path)
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("enrichment connector configuration exceeds the size limit")
    config = EnrichmentRuntimeConfig.model_validate_json(path.read_text(encoding="utf-8"))
    environment = environ if environ is not None else os.environ
    connectors: List[EnrichmentConnector] = []
    for item in config.connectors:
        token: Optional[str] = None
        if item.bearer_token_env is not None:
            token = environment.get(item.bearer_token_env)
            if not token:
                raise ValueError("configured enrichment connector secret is unavailable")
        connectors.append(
            HttpJsonEnrichmentConnector(
                item.connector,
                endpoint=item.endpoint,
                bearer_token=token,
            )
        )
    principal = EnrichmentPrincipal(
        tenant_id=tenant_id,
        actor_id=actor_id,
        permissions={ENRICHMENT_READ, ENRICHMENT_EXECUTE, ENRICHMENT_ADMIN},
        allowed_connectors={item.connector.name for item in config.connectors},
        allowed_input_fields=config.allowed_input_fields,
    )
    return (
        EnrichmentEngine(
            connectors=connectors,
            principal=principal,
            database_path=database_path,
            max_workers=config.max_workers,
            circuit_failure_threshold=config.circuit_failure_threshold,
            circuit_cooldown_seconds=config.circuit_cooldown_seconds,
        ),
        principal,
    )
