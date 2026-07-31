"""Durable, fail-closed model gateway and AI governance controls.

The gateway never stores provider credentials or raw model inputs/outputs.  It
binds every call to an immutable prompt, exact model route, active secret
fingerprint, passed qualification, privacy policy, budget reservation, and
sanitized call receipt.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
from time import perf_counter
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Sequence, Set, Tuple

from pydantic import Field, field_validator, model_validator

from .analyst import AnalystRoleReasoner
from .contracts import (
    AiMode,
    AnalystRoleRequest,
    AnalystRoleResult,
    ModelVerdict,
    SecurityAlert,
    StrictModel,
    TriageAssessment,
    new_id,
    utc_now,
)
from .crypto import canonical_bytes
from .providers import (
    ANALYST_RESULT_SCHEMA,
    AnthropicAnalystRoleReasoner,
    AnthropicMessagesReasoner,
    JsonTransport,
    OpenAIAnalystRoleReasoner,
    OpenAIResponsesReasoner,
    ProviderCallRecord,
    VERDICT_SCHEMA,
    validate_provider_endpoint,
)
from .reasoning import ModelUnavailableError, SecurityReasoner


MODEL_GATEWAY_READ = "model_gateway:read"
MODEL_GATEWAY_INVOKE = "model_gateway:invoke"
MODEL_GATEWAY_WRITE = "model_gateway:write"
MODEL_GATEWAY_QUALIFY = "model_gateway:qualify"
MODEL_GATEWAY_ACTIVATE = "model_gateway:activate"
MODEL_GATEWAY_SECRET = "model_gateway:secret"
MODEL_GATEWAY_ADMIN = "model_gateway:admin"
MODEL_GATEWAY_POLICY_VERSION = "model-gateway-2026-07-24.1"
MAX_GATEWAY_PAGE = 200


def workload_output_schema_sha256(workload: str) -> str:
    """Return the canonical output-contract digest for a gateway workload."""

    schemas = {
        "security_verdict": VERDICT_SCHEMA,
        "analyst_role": ANALYST_RESULT_SCHEMA,
    }
    try:
        schema = schemas[workload]
    except KeyError as exc:
        raise ValueError("unsupported model gateway workload") from exc
    return hashlib.sha256(canonical_bytes(schema)).hexdigest()


class ModelGatewayAuthorizationError(PermissionError):
    """Raised when a model-gateway principal lacks a required permission."""


class ModelGatewayUnavailable(ModelUnavailableError):
    """Fail-closed, provider-neutral gateway denial or outage."""


class ProviderKind(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class RouteStage(str, Enum):
    CANDIDATE = "candidate"
    SHADOW = "shadow"
    ACTIVE = "active"
    RETIRED = "retired"


class SecretStage(str, Enum):
    ACTIVE = "active"
    RETIRED = "retired"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class GatewayCallStatus(str, Enum):
    RESERVED = "reserved"
    COMPLETED = "completed"
    FAILED = "failed"
    DENIED = "denied"


class ModelGatewayPrincipal(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=3, max_length=256)
    permissions: Set[str] = Field(default_factory=set, max_length=16)

    @field_validator("permissions")
    @classmethod
    def valid_permissions(cls, value: Set[str]) -> Set[str]:
        if any(re.fullmatch(r"model_gateway:[a-z]+", item) is None for item in value):
            raise ValueError("model gateway permissions must use model_gateway:operation")
        return value


class PromptVersion(StrictModel):
    prompt_id: str = Field(pattern=r"^prm_[A-Za-z0-9_.-]+$")
    version: int = Field(ge=1)
    tenant_id: str
    workload: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    system_instructions: str = Field(min_length=20, max_length=16000)
    output_schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    author_id: str
    created_at: datetime
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("system_instructions")
    @classmethod
    def governed_prompt_invariants(cls, value: str) -> str:
        normalized = value.casefold()
        if any(
            required not in normalized
            for required in ("read-only", "evidence", "instructions", "cannot")
        ):
            raise ValueError(
                "model prompts must preserve read-only evidence and non-executive instructions"
            )
        return value


class SecretVersionMetadata(StrictModel):
    secret_id: str = Field(pattern=r"^sec_[A-Za-z0-9_.-]+$")
    version: int = Field(ge=1)
    tenant_id: str
    environment_variable: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    value_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stage: SecretStage
    created_by: str
    created_at: datetime
    retired_at: Optional[datetime] = None


class ModelRouteRevision(StrictModel):
    route_id: str = Field(pattern=r"^mrt_[A-Za-z0-9_.-]+$")
    revision: int = Field(ge=1)
    tenant_id: str
    provider: ProviderKind
    exact_model_id: str = Field(min_length=1, max_length=256)
    endpoint: str = Field(min_length=8, max_length=512)
    secret_id: str
    secret_version: int = Field(ge=1)
    prompt_id: str
    prompt_version: int = Field(ge=1)
    workload: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    allowed_modes: Set[AiMode] = Field(min_length=1, max_length=3)
    allowed_data_classes: Set[DataClassification] = Field(min_length=1, max_length=4)
    region: str = Field(min_length=2, max_length=64)
    priority: int = Field(default=100, ge=0, le=10000)
    fallback_route_id: Optional[str] = None
    max_requests_per_minute: int = Field(default=60, ge=1, le=100000)
    max_tokens_per_day: int = Field(default=100000, ge=1, le=1_000_000_000)
    max_concurrency: int = Field(default=4, ge=1, le=1000)
    max_output_tokens: int = Field(default=512, ge=32, le=100000)
    timeout_seconds: float = Field(default=30.0, ge=1.0, le=300.0)
    stage: RouteStage = RouteStage.CANDIDATE
    created_by: str
    created_at: datetime
    activated_at: Optional[datetime] = None
    retired_at: Optional[datetime] = None
    route_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def route_is_consistent(self) -> "ModelRouteRevision":
        if self.fallback_route_id == self.route_id:
            raise ValueError("route cannot fall back to itself")
        if self.workload == "security_verdict" and AiMode.OFF in self.allowed_modes:
            raise ValueError("AI-off mode cannot invoke a model route")
        expected = (
            ("api.openai.com", "/v1/responses")
            if self.provider == ProviderKind.OPENAI
            else ("api.anthropic.com", "/v1/messages")
        )
        validate_provider_endpoint(self.endpoint, {expected[0]}, expected[1])
        return self


class QualificationMetrics(StrictModel):
    fixture_count: int = Field(ge=1, le=1000000)
    schema_valid_rate: float = Field(ge=0.0, le=1.0)
    citation_valid_rate: float = Field(ge=0.0, le=1.0)
    forbidden_effect_rate: float = Field(ge=0.0, le=1.0)
    privacy_canary_leak_rate: float = Field(ge=0.0, le=1.0)
    fallback_test_passed: bool
    deterministic_relaxation_rate: float = Field(ge=0.0, le=1.0)

    @property
    def passed(self) -> bool:
        return (
            self.fixture_count >= 5
            and self.schema_valid_rate == 1.0
            and self.citation_valid_rate == 1.0
            and self.forbidden_effect_rate == 0.0
            and self.privacy_canary_leak_rate == 0.0
            and self.fallback_test_passed
            and self.deterministic_relaxation_rate == 0.0
        )


class ModelQualification(StrictModel):
    qualification_id: str = Field(pattern=r"^mql_[0-9a-f]{32}$")
    tenant_id: str
    route_id: str
    route_revision: int = Field(ge=1)
    route_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_model_id: str
    test_suite_version: str = Field(min_length=1, max_length=128)
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    metrics: QualificationMetrics
    passed: bool
    executed_by: str
    reviewed_by: str
    qualified_at: datetime
    valid_until: datetime

    @model_validator(mode="after")
    def qualification_is_independent(self) -> "ModelQualification":
        if self.executed_by == self.reviewed_by:
            raise ValueError("qualification requires a distinct reviewer")
        if self.passed != self.metrics.passed:
            raise ValueError("qualification result does not match metrics")
        if self.valid_until <= self.qualified_at:
            raise ValueError("qualification validity must end after qualification")
        return self


class ModelCallReceipt(StrictModel):
    call_id: str = Field(pattern=r"^mgc_[0-9a-f]{32}$")
    tenant_id: str
    route_id: str
    route_revision: int = Field(ge=1)
    provider: ProviderKind
    exact_model_id: str
    prompt_id: str
    prompt_version: int = Field(ge=1)
    workload: str
    mode: AiMode
    data_classes: Set[DataClassification]
    status: GatewayCallStatus
    reserved_tokens: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    latency_ms: int = Field(ge=0)
    provider_request_id: Optional[str] = None
    output_sha256: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    error_code: Optional[str] = Field(default=None, pattern=r"^[a-z0-9_]{3,64}$")
    created_at: datetime
    completed_at: Optional[datetime] = None


class ProviderHealth(StrictModel):
    tenant_id: str
    route_id: str
    route_revision: int
    provider: ProviderKind
    stage: RouteStage
    circuit_state: str = Field(pattern=r"^(closed|open)$")
    consecutive_failures: int = Field(ge=0)
    successful_calls: int = Field(ge=0)
    failed_calls: int = Field(ge=0)
    last_latency_ms: Optional[int] = Field(default=None, ge=0)
    last_error_code: Optional[str] = None
    circuit_open_until: Optional[datetime] = None
    qualification_id: Optional[str] = None
    secret_ready: bool
    budget_requests_last_minute: int = Field(ge=0)
    budget_tokens_today: int = Field(ge=0)
    in_flight: int = Field(ge=0)
    calculated_at: datetime


class ModelGatewayHealthSummary(StrictModel):
    schema_version: str = "1.0.0"
    tenant_id: str
    policy_version: str = MODEL_GATEWAY_POLICY_VERSION
    prompts: int = Field(ge=0)
    routes: int = Field(ge=0)
    active_routes: int = Field(ge=0)
    qualified_routes: int = Field(ge=0)
    open_circuits: int = Field(ge=0)
    providers: List[ProviderHealth]
    calculated_at: datetime


class ModelGatewayAuditEntry(StrictModel):
    sequence: int = Field(ge=1)
    tenant_id: str
    actor_id: str
    action: str
    subject: str
    details_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    occurred_at: datetime


class PromptConfiguration(StrictModel):
    prompt_id: str
    version: int = 1
    workload: str
    system_instructions: str
    output_schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SecretConfiguration(StrictModel):
    secret_id: str
    version: int = 1
    environment_variable: str


class RouteConfiguration(StrictModel):
    route_id: str
    revision: int = 1
    provider: ProviderKind
    exact_model_id: str
    endpoint: str
    secret_id: str
    secret_version: int = 1
    prompt_id: str
    prompt_version: int = 1
    workload: str
    allowed_modes: Set[AiMode]
    allowed_data_classes: Set[DataClassification]
    region: str
    priority: int = 100
    fallback_route_id: Optional[str] = None
    max_requests_per_minute: int = 60
    max_tokens_per_day: int = 100000
    max_concurrency: int = 4
    max_output_tokens: int = 512
    timeout_seconds: float = 30.0


class ModelGatewayConfiguration(StrictModel):
    schema_version: str = "1.0.0"
    prompts: List[PromptConfiguration]
    secrets: List[SecretConfiguration]
    routes: List[RouteConfiguration]

    @model_validator(mode="after")
    def unique_config(self) -> "ModelGatewayConfiguration":
        identities = [(item.prompt_id, item.version) for item in self.prompts]
        if len(identities) != len(set(identities)):
            raise ValueError("prompt versions must be unique")
        route_ids = [(item.route_id, item.revision) for item in self.routes]
        if len(route_ids) != len(set(route_ids)):
            raise ValueError("route revisions must be unique")
        secret_ids = [(item.secret_id, item.version) for item in self.secrets]
        if len(secret_ids) != len(set(secret_ids)):
            raise ValueError("secret versions must be unique")
        return self


class SecurityReasonerFactory(Protocol):
    def __call__(
        self, route: ModelRouteRevision, prompt: PromptVersion, secret: str
    ) -> SecurityReasoner:
        ...


class AnalystReasonerFactory(Protocol):
    def __call__(
        self, route: ModelRouteRevision, prompt: PromptVersion, secret: str
    ) -> AnalystRoleReasoner:
        ...


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _route_digest(value: Any) -> str:
    """Bind immutable route configuration while permitting lifecycle transitions."""

    if isinstance(value, ModelRouteRevision):
        payload = value.model_dump(mode="json")
    else:
        payload = dict(value)
    for field in ("stage", "activated_at", "retired_at", "route_sha256"):
        payload.pop(field, None)
    # Pydantic serializes sets as JSON arrays, but parsing that JSON can produce
    # a different iteration order in the reconstructed set.  Sort the two set
    # fields explicitly so a persisted route always verifies across processes
    # and hash seeds while changes to set membership remain detectable.
    for field in ("allowed_modes", "allowed_data_classes"):
        payload[field] = sorted(payload[field])
    return _digest(payload)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("model gateway clock must be timezone-aware")
    return value.astimezone(timezone.utc)


class ModelGatewayService:
    """Tenant-scoped registry, router, budget enforcer, and call ledger."""

    def __init__(
        self,
        path: str,
        *,
        environment: Optional[Mapping[str, str]] = None,
        clock: Callable[[], datetime] = utc_now,
        security_factories: Optional[Mapping[ProviderKind, SecurityReasonerFactory]] = None,
        analyst_factories: Optional[Mapping[ProviderKind, AnalystReasonerFactory]] = None,
        failure_threshold: int = 3,
        circuit_seconds: int = 60,
    ) -> None:
        if failure_threshold < 1 or circuit_seconds < 1:
            raise ValueError("circuit policy must be positive")
        self.path = path
        self.environment = environment if environment is not None else os.environ
        self.clock = clock
        self.failure_threshold = failure_threshold
        self.circuit_seconds = circuit_seconds
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
        self._security_factories = dict(security_factories or {})
        self._analyst_factories = dict(analyst_factories or {})
        self._migrate()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _now(self) -> datetime:
        return _utc(self.clock())

    @staticmethod
    def _require(principal: ModelGatewayPrincipal, permission: str) -> None:
        if permission not in principal.permissions:
            raise ModelGatewayAuthorizationError(
                "missing model gateway permission: %s" % permission
            )

    def _migrate(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS model_prompts (
                tenant_id TEXT NOT NULL, prompt_id TEXT NOT NULL, version INTEGER NOT NULL,
                prompt_json TEXT NOT NULL, prompt_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, prompt_id, version)
            );
            CREATE TABLE IF NOT EXISTS model_secrets (
                tenant_id TEXT NOT NULL, secret_id TEXT NOT NULL, version INTEGER NOT NULL,
                secret_json TEXT NOT NULL, stage TEXT NOT NULL, created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, secret_id, version)
            );
            CREATE TABLE IF NOT EXISTS model_routes (
                tenant_id TEXT NOT NULL, route_id TEXT NOT NULL, revision INTEGER NOT NULL,
                route_json TEXT NOT NULL, stage TEXT NOT NULL, route_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, route_id, revision)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS model_routes_active
                ON model_routes(tenant_id, route_id) WHERE stage = 'active';
            CREATE TABLE IF NOT EXISTS model_qualifications (
                tenant_id TEXT NOT NULL, qualification_id TEXT NOT NULL,
                route_id TEXT NOT NULL, route_revision INTEGER NOT NULL,
                qualification_json TEXT NOT NULL, passed INTEGER NOT NULL,
                qualified_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, qualification_id)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS model_qualification_binding
                ON model_qualifications(tenant_id, route_id, route_revision);
            CREATE TABLE IF NOT EXISTS model_calls (
                tenant_id TEXT NOT NULL, call_id TEXT NOT NULL, route_id TEXT NOT NULL,
                route_revision INTEGER NOT NULL, status TEXT NOT NULL,
                reserved_tokens INTEGER NOT NULL, total_tokens INTEGER NOT NULL,
                created_at TEXT NOT NULL, completed_at TEXT, call_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, call_id)
            );
            CREATE INDEX IF NOT EXISTS model_calls_budget
                ON model_calls(tenant_id, route_id, route_revision, created_at);
            CREATE TABLE IF NOT EXISTS model_provider_health (
                tenant_id TEXT NOT NULL, route_id TEXT NOT NULL, revision INTEGER NOT NULL,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                successful_calls INTEGER NOT NULL DEFAULT 0,
                failed_calls INTEGER NOT NULL DEFAULT 0,
                last_latency_ms INTEGER, last_error_code TEXT, circuit_open_until TEXT,
                PRIMARY KEY (tenant_id, route_id, revision)
            );
            CREATE TABLE IF NOT EXISTS model_route_history (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL,
                route_id TEXT NOT NULL, revision INTEGER NOT NULL,
                action TEXT NOT NULL, actor_id TEXT NOT NULL, occurred_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS model_gateway_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL,
                actor_id TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL,
                details_sha256 TEXT NOT NULL, occurred_at TEXT NOT NULL
            );
            """
        )

    def _audit(
        self, principal: ModelGatewayPrincipal, action: str, subject: str, details: Any
    ) -> None:
        self._connection.execute(
            "INSERT INTO model_gateway_audit(tenant_id, actor_id, action, subject, details_sha256, occurred_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                principal.tenant_id,
                principal.actor_id,
                action,
                subject[:512],
                _digest(details),
                self._now().isoformat(),
            ),
        )

    def register_prompt(
        self,
        principal: ModelGatewayPrincipal,
        *,
        prompt_id: str,
        version: int,
        workload: str,
        system_instructions: str,
        output_schema_sha256: str,
    ) -> PromptVersion:
        self._require(principal, MODEL_GATEWAY_WRITE)
        expected_schema_sha256 = workload_output_schema_sha256(workload)
        if output_schema_sha256 != expected_schema_sha256:
            raise ValueError("prompt output schema digest does not match the workload contract")
        now = self._now()
        unsigned = {
            "prompt_id": prompt_id,
            "version": version,
            "tenant_id": principal.tenant_id,
            "workload": workload,
            "system_instructions": system_instructions,
            "output_schema_sha256": output_schema_sha256,
            "author_id": principal.actor_id,
            "created_at": now,
        }
        prompt_unsigned = PromptVersion.model_validate(
            {**unsigned, "prompt_sha256": "0" * 64}
        )
        prompt = prompt_unsigned.model_copy(
            update={
                "prompt_sha256": _digest(
                    prompt_unsigned.model_dump(
                        mode="json", exclude={"prompt_sha256"}
                    )
                )
            }
        )
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO model_prompts VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        principal.tenant_id, prompt.prompt_id, prompt.version,
                        prompt.model_dump_json(), prompt.prompt_sha256, now.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError:
                current = self.get_prompt(principal, prompt_id, version)
                if (
                    current.workload != workload
                    or current.system_instructions != system_instructions
                    or current.output_schema_sha256 != output_schema_sha256
                ):
                    raise ValueError("prompt version is immutable") from None
                return current
            self._audit(principal, "prompt.register", "%s:%d" % (prompt_id, version), unsigned)
        return prompt

    def get_prompt(
        self, principal: ModelGatewayPrincipal, prompt_id: str, version: int
    ) -> PromptVersion:
        self._require(principal, MODEL_GATEWAY_READ)
        row = self._connection.execute(
            "SELECT prompt_json FROM model_prompts WHERE tenant_id = ? AND prompt_id = ? AND version = ?",
            (principal.tenant_id, prompt_id, version),
        ).fetchone()
        if row is None:
            raise KeyError(prompt_id)
        prompt = PromptVersion.model_validate_json(row["prompt_json"])
        raw = prompt.model_dump(mode="json", exclude={"prompt_sha256"})
        if _digest(raw) != prompt.prompt_sha256:
            raise ValueError("prompt digest verification failed")
        return prompt

    def list_prompts(self, principal: ModelGatewayPrincipal) -> List[PromptVersion]:
        self._require(principal, MODEL_GATEWAY_READ)
        rows = self._connection.execute(
            "SELECT prompt_json FROM model_prompts WHERE tenant_id = ? ORDER BY prompt_id, version DESC",
            (principal.tenant_id,),
        ).fetchall()
        return [PromptVersion.model_validate_json(row["prompt_json"]) for row in rows]

    def register_secret(
        self,
        principal: ModelGatewayPrincipal,
        *,
        secret_id: str,
        version: int,
        environment_variable: str,
    ) -> SecretVersionMetadata:
        self._require(principal, MODEL_GATEWAY_SECRET)
        secret_value = self.environment.get(environment_variable, "")
        if len(secret_value) < 8:
            raise ValueError("secret environment variable is missing or too short")
        now = self._now()
        metadata = SecretVersionMetadata(
            secret_id=secret_id,
            version=version,
            tenant_id=principal.tenant_id,
            environment_variable=environment_variable,
            value_sha256=hashlib.sha256(secret_value.encode("utf-8")).hexdigest(),
            stage=SecretStage.ACTIVE,
            created_by=principal.actor_id,
            created_at=now,
        )
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO model_secrets VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        principal.tenant_id, secret_id, version,
                        metadata.model_dump_json(), metadata.stage.value, now.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError:
                current = self.get_secret_metadata(principal, secret_id, version)
                if (
                    current.environment_variable != environment_variable
                    or current.value_sha256 != metadata.value_sha256
                    or current.stage != SecretStage.ACTIVE
                ):
                    raise ValueError("secret version metadata is immutable") from None
                return current
            self._audit(
                principal, "secret.register", "%s:%d" % (secret_id, version),
                metadata.model_dump(mode="json", exclude={"value_sha256"}),
            )
        return metadata

    def get_secret_metadata(
        self, principal: ModelGatewayPrincipal, secret_id: str, version: int
    ) -> SecretVersionMetadata:
        if not ({MODEL_GATEWAY_READ, MODEL_GATEWAY_SECRET} & principal.permissions):
            self._require(principal, MODEL_GATEWAY_READ)
        row = self._connection.execute(
            "SELECT secret_json FROM model_secrets WHERE tenant_id = ? AND secret_id = ? AND version = ?",
            (principal.tenant_id, secret_id, version),
        ).fetchone()
        if row is None:
            raise KeyError(secret_id)
        return SecretVersionMetadata.model_validate_json(row["secret_json"])

    def list_secrets(self, principal: ModelGatewayPrincipal) -> List[SecretVersionMetadata]:
        self._require(principal, MODEL_GATEWAY_READ)
        rows = self._connection.execute(
            "SELECT secret_json FROM model_secrets WHERE tenant_id = ? ORDER BY secret_id, version DESC",
            (principal.tenant_id,),
        ).fetchall()
        return [SecretVersionMetadata.model_validate_json(row["secret_json"]) for row in rows]

    def _resolve_secret(self, principal: ModelGatewayPrincipal, route: ModelRouteRevision) -> str:
        metadata = self.get_secret_metadata(principal, route.secret_id, route.secret_version)
        if metadata.stage != SecretStage.ACTIVE:
            raise ModelGatewayUnavailable("model route secret is retired")
        value = self.environment.get(metadata.environment_variable, "")
        if not value or hashlib.sha256(value.encode("utf-8")).hexdigest() != metadata.value_sha256:
            raise ModelGatewayUnavailable("model route secret fingerprint mismatch")
        return value

    def retire_secret(
        self, principal: ModelGatewayPrincipal, secret_id: str, version: int
    ) -> SecretVersionMetadata:
        self._require(principal, MODEL_GATEWAY_SECRET)
        current = self.get_secret_metadata(principal, secret_id, version)
        if current.stage == SecretStage.RETIRED:
            return current
        active_use = self._connection.execute(
            "SELECT COUNT(*) AS n FROM model_routes WHERE tenant_id = ? AND stage = 'active' AND json_extract(route_json, '$.secret_id') = ? AND json_extract(route_json, '$.secret_version') = ?",
            (principal.tenant_id, secret_id, version),
        ).fetchone()["n"]
        if active_use:
            raise ValueError("cannot retire a secret used by an active route")
        updated = current.model_copy(
            update={"stage": SecretStage.RETIRED, "retired_at": self._now()}
        )
        with self._lock:
            self._connection.execute(
                "UPDATE model_secrets SET secret_json = ?, stage = ? WHERE tenant_id = ? AND secret_id = ? AND version = ?",
                (updated.model_dump_json(), updated.stage.value, principal.tenant_id, secret_id, version),
            )
            self._audit(principal, "secret.retire", "%s:%d" % (secret_id, version), {})
        return updated

    def register_route(
        self, principal: ModelGatewayPrincipal, configuration: RouteConfiguration
    ) -> ModelRouteRevision:
        self._require(principal, MODEL_GATEWAY_WRITE)
        prompt = self.get_prompt(
            principal, configuration.prompt_id, configuration.prompt_version
        )
        if prompt.workload != configuration.workload:
            raise ValueError("route and prompt workloads must match")
        secret = self.get_secret_metadata(
            principal, configuration.secret_id, configuration.secret_version
        )
        if secret.stage != SecretStage.ACTIVE:
            raise ValueError("route secret must be active")
        now = self._now()
        unsigned = {
            **configuration.model_dump(mode="json"),
            "tenant_id": principal.tenant_id,
            "stage": RouteStage.CANDIDATE,
            "created_by": principal.actor_id,
            "created_at": now,
            "activated_at": None,
            "retired_at": None,
        }
        route_unsigned = ModelRouteRevision.model_validate(
            {**unsigned, "route_sha256": "0" * 64}
        )
        route = route_unsigned.model_copy(
            update={"route_sha256": _route_digest(route_unsigned)}
        )
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO model_routes VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        principal.tenant_id, route.route_id, route.revision,
                        route.model_dump_json(), route.stage.value, route.route_sha256,
                        now.isoformat(),
                    ),
                )
                self._connection.execute(
                    "INSERT OR IGNORE INTO model_provider_health(tenant_id, route_id, revision) VALUES (?, ?, ?)",
                    (principal.tenant_id, route.route_id, route.revision),
                )
            except sqlite3.IntegrityError:
                current = self.get_route(principal, route.route_id, route.revision)
                current_configuration = RouteConfiguration.model_validate(
                    current.model_dump(
                        exclude={
                            "tenant_id", "stage", "created_by", "created_at",
                            "activated_at", "retired_at", "route_sha256",
                        }
                    )
                )
                if current_configuration != configuration:
                    raise ValueError("route revision is immutable") from None
                return current
            self._audit(principal, "route.register", "%s:%d" % (route.route_id, route.revision), unsigned)
        return route

    def get_route(
        self, principal: ModelGatewayPrincipal, route_id: str, revision: int
    ) -> ModelRouteRevision:
        self._require(principal, MODEL_GATEWAY_READ)
        row = self._connection.execute(
            "SELECT route_json FROM model_routes WHERE tenant_id = ? AND route_id = ? AND revision = ?",
            (principal.tenant_id, route_id, revision),
        ).fetchone()
        if row is None:
            raise KeyError(route_id)
        route = ModelRouteRevision.model_validate_json(row["route_json"])
        if _route_digest(route) != route.route_sha256:
            raise ValueError("model route digest verification failed")
        return route

    def list_routes(self, principal: ModelGatewayPrincipal) -> List[ModelRouteRevision]:
        self._require(principal, MODEL_GATEWAY_READ)
        rows = self._connection.execute(
            "SELECT route_json FROM model_routes WHERE tenant_id = ? ORDER BY route_id, revision DESC",
            (principal.tenant_id,),
        ).fetchall()
        routes = [ModelRouteRevision.model_validate_json(row["route_json"]) for row in rows]
        if any(_route_digest(route) != route.route_sha256 for route in routes):
            raise ValueError("model route digest verification failed")
        return routes

    def qualify(
        self,
        principal: ModelGatewayPrincipal,
        *,
        route_id: str,
        revision: int,
        test_suite_version: str,
        evidence_sha256: str,
        metrics: QualificationMetrics,
        reviewed_by: str,
        valid_for_hours: int = 168,
    ) -> ModelQualification:
        self._require(principal, MODEL_GATEWAY_QUALIFY)
        if not 1 <= valid_for_hours <= 720:
            raise ValueError("qualification validity must be between 1 and 720 hours")
        route = self.get_route(principal, route_id, revision)
        prompt = self.get_prompt(principal, route.prompt_id, route.prompt_version)
        qualified_at = self._now()
        qualification = ModelQualification(
            qualification_id=new_id("mql"),
            tenant_id=principal.tenant_id,
            route_id=route_id,
            route_revision=revision,
            route_sha256=route.route_sha256,
            prompt_sha256=prompt.prompt_sha256,
            exact_model_id=route.exact_model_id,
            test_suite_version=test_suite_version,
            evidence_sha256=evidence_sha256,
            metrics=metrics,
            passed=metrics.passed,
            executed_by=principal.actor_id,
            reviewed_by=reviewed_by,
            qualified_at=qualified_at,
            valid_until=qualified_at + timedelta(hours=valid_for_hours),
        )
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO model_qualifications VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        principal.tenant_id, qualification.qualification_id,
                        route_id, revision, qualification.model_dump_json(),
                        int(qualification.passed), qualification.qualified_at.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError:
                raise ValueError("route revision already has a qualification") from None
            self._audit(
                principal, "route.qualify", "%s:%d" % (route_id, revision),
                qualification.model_dump(mode="json"),
            )
        return qualification

    def _qualification(
        self, principal: ModelGatewayPrincipal, route: ModelRouteRevision
    ) -> Optional[ModelQualification]:
        row = self._connection.execute(
            "SELECT qualification_json FROM model_qualifications WHERE tenant_id = ? AND route_id = ? AND route_revision = ?",
            (principal.tenant_id, route.route_id, route.revision),
        ).fetchone()
        if row is None:
            return None
        item = ModelQualification.model_validate_json(row["qualification_json"])
        prompt = self.get_prompt(principal, route.prompt_id, route.prompt_version)
        if (
            item.route_sha256 != route.route_sha256
            or item.prompt_sha256 != prompt.prompt_sha256
            or item.exact_model_id != route.exact_model_id
            or item.valid_until <= self._now()
        ):
            return None
        return item

    def list_qualifications(
        self, principal: ModelGatewayPrincipal
    ) -> List[ModelQualification]:
        self._require(principal, MODEL_GATEWAY_READ)
        rows = self._connection.execute(
            "SELECT qualification_json FROM model_qualifications WHERE tenant_id = ? ORDER BY qualified_at DESC",
            (principal.tenant_id,),
        ).fetchall()
        return [ModelQualification.model_validate_json(row["qualification_json"]) for row in rows]

    def _set_route_stage(
        self,
        principal: ModelGatewayPrincipal,
        route: ModelRouteRevision,
        stage: RouteStage,
        *,
        action: str,
    ) -> ModelRouteRevision:
        now = self._now()
        updated = route.model_copy(
            update={
                "stage": stage,
                "activated_at": now if stage == RouteStage.ACTIVE else route.activated_at,
                "retired_at": now if stage == RouteStage.RETIRED else route.retired_at,
            }
        )
        self._connection.execute(
            "UPDATE model_routes SET route_json = ?, stage = ? WHERE tenant_id = ? AND route_id = ? AND revision = ?",
            (
                updated.model_dump_json(), stage.value, principal.tenant_id,
                route.route_id, route.revision,
            ),
        )
        self._connection.execute(
            "INSERT INTO model_route_history(tenant_id, route_id, revision, action, actor_id, occurred_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                principal.tenant_id, route.route_id, route.revision, action,
                principal.actor_id, now.isoformat(),
            ),
        )
        return updated

    def promote_shadow(
        self, principal: ModelGatewayPrincipal, route_id: str, revision: int
    ) -> ModelRouteRevision:
        self._require(principal, MODEL_GATEWAY_ACTIVATE)
        route = self.get_route(principal, route_id, revision)
        qualification = self._qualification(principal, route)
        if qualification is None or not qualification.passed:
            raise ValueError("route requires a passed exact qualification")
        with self._lock:
            updated = self._set_route_stage(
                principal, route, RouteStage.SHADOW, action="promote_shadow"
            )
            self._audit(principal, "route.shadow", "%s:%d" % (route_id, revision), {})
        return updated

    def activate(
        self, principal: ModelGatewayPrincipal, route_id: str, revision: int
    ) -> ModelRouteRevision:
        self._require(principal, MODEL_GATEWAY_ACTIVATE)
        route = self.get_route(principal, route_id, revision)
        if route.stage != RouteStage.SHADOW:
            raise ValueError("route must pass through shadow before activation")
        qualification = self._qualification(principal, route)
        if qualification is None or not qualification.passed:
            raise ValueError("route requires a passed exact qualification")
        if qualification.reviewed_by == principal.actor_id:
            raise ValueError("activation requires an actor distinct from the qualification reviewer")
        self._resolve_secret(principal, route)
        with self._lock:
            current_rows = self._connection.execute(
                "SELECT route_json FROM model_routes WHERE tenant_id = ? AND stage = 'active'",
                (principal.tenant_id,),
            ).fetchall()
            # SQLite JSON may not be compiled everywhere; filter decoded rows.
            for row in current_rows:
                current = ModelRouteRevision.model_validate_json(row["route_json"])
                if current.workload == route.workload and current.route_id == route.route_id:
                    self._set_route_stage(
                        principal, current, RouteStage.RETIRED, action="superseded"
                    )
            updated = self._set_route_stage(
                principal, route, RouteStage.ACTIVE, action="activate"
            )
            self._audit(principal, "route.activate", "%s:%d" % (route_id, revision), {})
        return updated

    def rollback(
        self, principal: ModelGatewayPrincipal, route_id: str
    ) -> ModelRouteRevision:
        self._require(principal, MODEL_GATEWAY_ACTIVATE)
        routes = [item for item in self.list_routes(principal) if item.route_id == route_id]
        current = next((item for item in routes if item.stage == RouteStage.ACTIVE), None)
        if current is None:
            raise ValueError("route has no active revision")
        candidates = []
        for item in routes:
            qualification = self._qualification(principal, item)
            if (
                item.revision < current.revision
                and item.stage == RouteStage.RETIRED
                and qualification is not None
                and qualification.passed
            ):
                candidates.append(item)
        if not candidates:
            raise ValueError("route has no previously qualified revision")
        target = max(candidates, key=lambda item: item.revision)
        self._resolve_secret(principal, target)
        with self._lock:
            self._set_route_stage(
                principal, current, RouteStage.RETIRED, action="rollback_from"
            )
            restored = self._set_route_stage(
                principal, target, RouteStage.ACTIVE, action="rollback_to"
            )
            self._audit(
                principal, "route.rollback", route_id,
                {"from_revision": current.revision, "to_revision": target.revision},
            )
        return restored

    def _route_candidates(
        self,
        principal: ModelGatewayPrincipal,
        *,
        workload: str,
        mode: AiMode,
        data_classes: Set[DataClassification],
    ) -> List[ModelRouteRevision]:
        routes = [
            item for item in self.list_routes(principal)
            if item.stage == RouteStage.ACTIVE
            and item.workload == workload
            and mode in item.allowed_modes
            and data_classes.issubset(item.allowed_data_classes)
            and (qualification := self._qualification(principal, item)) is not None
            and qualification.passed
        ]
        return sorted(routes, key=lambda item: (item.priority, item.route_id, -item.revision))

    def _health_row(self, route: ModelRouteRevision) -> sqlite3.Row:
        row = self._connection.execute(
            "SELECT * FROM model_provider_health WHERE tenant_id = ? AND route_id = ? AND revision = ?",
            (route.tenant_id, route.route_id, route.revision),
        ).fetchone()
        if row is None:
            raise ValueError("provider health row is missing")
        return row

    def _circuit_open(self, route: ModelRouteRevision) -> bool:
        value = self._health_row(route)["circuit_open_until"]
        return bool(value and datetime.fromisoformat(value) > self._now())

    @staticmethod
    def _token_estimate(payload: Any) -> int:
        return max(1, (len(canonical_bytes(payload)) + 3) // 4)

    def _reserve(
        self,
        principal: ModelGatewayPrincipal,
        route: ModelRouteRevision,
        *,
        mode: AiMode,
        data_classes: Set[DataClassification],
        payload: Any,
    ) -> ModelCallReceipt:
        now = self._now()
        minute = (now - timedelta(minutes=1)).isoformat()
        day = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        reserved_tokens = self._token_estimate(payload) + route.max_output_tokens
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                request_count = self._connection.execute(
                    "SELECT COUNT(*) AS n FROM model_calls WHERE tenant_id = ? AND route_id = ? AND route_revision = ? AND created_at >= ?",
                    (principal.tenant_id, route.route_id, route.revision, minute),
                ).fetchone()["n"]
                token_count = self._connection.execute(
                    "SELECT COALESCE(SUM(CASE WHEN status = 'reserved' THEN reserved_tokens ELSE total_tokens END), 0) AS n FROM model_calls WHERE tenant_id = ? AND route_id = ? AND route_revision = ? AND created_at >= ?",
                    (principal.tenant_id, route.route_id, route.revision, day),
                ).fetchone()["n"]
                in_flight = self._connection.execute(
                    "SELECT COUNT(*) AS n FROM model_calls WHERE tenant_id = ? AND route_id = ? AND route_revision = ? AND status = 'reserved' AND created_at >= ?",
                    (
                        principal.tenant_id, route.route_id, route.revision,
                        (now - timedelta(seconds=route.timeout_seconds * 2)).isoformat(),
                    ),
                ).fetchone()["n"]
                if request_count >= route.max_requests_per_minute:
                    raise ModelGatewayUnavailable("model gateway request budget exhausted")
                if token_count + reserved_tokens > route.max_tokens_per_day:
                    raise ModelGatewayUnavailable("model gateway token budget exhausted")
                if in_flight >= route.max_concurrency:
                    raise ModelGatewayUnavailable("model gateway concurrency exhausted")
                receipt = ModelCallReceipt(
                    call_id=new_id("mgc"), tenant_id=principal.tenant_id,
                    route_id=route.route_id, route_revision=route.revision,
                    provider=route.provider, exact_model_id=route.exact_model_id,
                    prompt_id=route.prompt_id, prompt_version=route.prompt_version,
                    workload=route.workload, mode=mode, data_classes=data_classes,
                    status=GatewayCallStatus.RESERVED, reserved_tokens=reserved_tokens,
                    input_tokens=0, output_tokens=0, total_tokens=0, latency_ms=0,
                    created_at=now,
                )
                self._connection.execute(
                    "INSERT INTO model_calls VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        principal.tenant_id, receipt.call_id, route.route_id,
                        route.revision, receipt.status.value, receipt.reserved_tokens,
                        0, now.isoformat(), None, receipt.model_dump_json(),
                    ),
                )
                self._connection.execute("COMMIT")
                return receipt
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _usage(call: Optional[ProviderCallRecord]) -> Tuple[int, int, int]:
        if call is None:
            return 0, 0, 0
        raw = call.usage
        input_tokens = int(raw.get("input_tokens", 0))
        output_tokens = int(raw.get("output_tokens", 0))
        total = int(raw.get("total_tokens", input_tokens + output_tokens))
        return input_tokens, output_tokens, total

    def _complete_call(
        self,
        receipt: ModelCallReceipt,
        *,
        provider_call: Optional[ProviderCallRecord],
        latency_ms: int,
    ) -> ModelCallReceipt:
        input_tokens, output_tokens, total = self._usage(provider_call)
        charged_total = total if total > 0 else receipt.reserved_tokens
        completed = receipt.model_copy(
            update={
                "status": GatewayCallStatus.COMPLETED,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": charged_total,
                "latency_ms": latency_ms,
                "provider_request_id": provider_call.request_id if provider_call else None,
                "output_sha256": provider_call.output_digest if provider_call else None,
                "completed_at": self._now(),
            }
        )
        with self._lock:
            self._connection.execute(
                "UPDATE model_calls SET status = ?, total_tokens = ?, completed_at = ?, call_json = ? WHERE tenant_id = ? AND call_id = ?",
                (
                    completed.status.value, charged_total, completed.completed_at.isoformat(),
                    completed.model_dump_json(), completed.tenant_id, completed.call_id,
                ),
            )
            self._connection.execute(
                "UPDATE model_provider_health SET consecutive_failures = 0, successful_calls = successful_calls + 1, last_latency_ms = ?, last_error_code = NULL, circuit_open_until = NULL WHERE tenant_id = ? AND route_id = ? AND revision = ?",
                (latency_ms, completed.tenant_id, completed.route_id, completed.route_revision),
            )
        return completed

    def _fail_call(
        self,
        receipt: ModelCallReceipt,
        route: ModelRouteRevision,
        *,
        error_code: str,
        latency_ms: int,
    ) -> ModelCallReceipt:
        completed_at = self._now()
        failed = receipt.model_copy(
            update={
                "status": GatewayCallStatus.FAILED,
                "total_tokens": receipt.reserved_tokens,
                "latency_ms": latency_ms,
                "error_code": error_code,
                "completed_at": completed_at,
            }
        )
        with self._lock:
            row = self._health_row(route)
            failures = int(row["consecutive_failures"]) + 1
            circuit = (
                (completed_at + timedelta(seconds=self.circuit_seconds)).isoformat()
                if failures >= self.failure_threshold else None
            )
            self._connection.execute(
                "UPDATE model_calls SET status = ?, total_tokens = ?, completed_at = ?, call_json = ? WHERE tenant_id = ? AND call_id = ?",
                (
                    failed.status.value, failed.total_tokens, completed_at.isoformat(), failed.model_dump_json(),
                    failed.tenant_id, failed.call_id,
                ),
            )
            self._connection.execute(
                "UPDATE model_provider_health SET consecutive_failures = ?, failed_calls = failed_calls + 1, last_latency_ms = ?, last_error_code = ?, circuit_open_until = ? WHERE tenant_id = ? AND route_id = ? AND revision = ?",
                (
                    failures, latency_ms, error_code, circuit, failed.tenant_id,
                    failed.route_id, failed.route_revision,
                ),
            )
        return failed

    def _default_security_factory(
        self, route: ModelRouteRevision, prompt: PromptVersion, secret: str
    ) -> SecurityReasoner:
        common = {
            "api_key": secret,
            "model_id": route.exact_model_id,
            "endpoint": route.endpoint,
            "timeout_seconds": route.timeout_seconds,
            "system_prompt": prompt.system_instructions,
            "max_output_tokens": route.max_output_tokens,
        }
        if route.provider == ProviderKind.OPENAI:
            return OpenAIResponsesReasoner(**common)
        if route.provider == ProviderKind.ANTHROPIC:
            return AnthropicMessagesReasoner(**common)
        raise ModelGatewayUnavailable("unsupported model provider")

    def _default_analyst_factory(
        self, route: ModelRouteRevision, prompt: PromptVersion, secret: str
    ) -> AnalystRoleReasoner:
        common = {
            "api_key": secret,
            "model_id": route.exact_model_id,
            "endpoint": route.endpoint,
            "timeout_seconds": route.timeout_seconds,
            "system_prompt": prompt.system_instructions,
            "max_output_tokens": route.max_output_tokens,
        }
        if route.provider == ProviderKind.OPENAI:
            return OpenAIAnalystRoleReasoner(**common)
        if route.provider == ProviderKind.ANTHROPIC:
            return AnthropicAnalystRoleReasoner(**common)
        raise ModelGatewayUnavailable("unsupported model provider")

    def _ordered_with_fallbacks(
        self,
        principal: ModelGatewayPrincipal,
        routes: Sequence[ModelRouteRevision],
    ) -> List[ModelRouteRevision]:
        indexed = {item.route_id: item for item in routes}
        ordered: List[ModelRouteRevision] = []
        visited: Set[str] = set()
        for initial in routes:
            current: Optional[ModelRouteRevision] = initial
            chain: Set[str] = set()
            while current is not None:
                if current.route_id in chain:
                    raise ValueError("model route fallback cycle detected")
                chain.add(current.route_id)
                if current.route_id not in visited:
                    ordered.append(current)
                    visited.add(current.route_id)
                current = indexed.get(current.fallback_route_id or "")
        return ordered

    @staticmethod
    def _error_code(exc: Exception) -> str:
        message = str(exc).casefold()
        if "refus" in message:
            return "provider_refusal"
        if "schema" in message or "json" in message:
            return "provider_invalid_output"
        if "evidence" in message or "citation" in message:
            return "provider_invalid_citation"
        if "timeout" in message or "transport" in message or "http" in message:
            return "provider_unavailable"
        return "provider_failure"

    def analyze_security(
        self,
        principal: ModelGatewayPrincipal,
        alert: SecurityAlert,
        triage: TriageAssessment,
        *,
        mode: AiMode,
        data_classes: Set[DataClassification],
    ) -> ModelVerdict:
        self._require(principal, MODEL_GATEWAY_INVOKE)
        routes = self._route_candidates(
            principal, workload="security_verdict", mode=mode, data_classes=data_classes
        )
        errors: List[str] = []
        for route in self._ordered_with_fallbacks(principal, routes):
            if self._circuit_open(route):
                errors.append("circuit_open")
                continue
            prompt = self.get_prompt(principal, route.prompt_id, route.prompt_version)
            try:
                secret = self._resolve_secret(principal, route)
                receipt = self._reserve(
                    principal, route, mode=mode, data_classes=data_classes,
                    payload={"alert": alert.model_dump(mode="json"), "triage": triage.model_dump(mode="json")},
                )
            except ModelGatewayUnavailable as exc:
                errors.append(self._error_code(exc))
                continue
            started = perf_counter()
            try:
                factory = self._security_factories.get(route.provider)
                reasoner = (
                    factory(route, prompt, secret)
                    if factory is not None
                    else self._default_security_factory(route, prompt, secret)
                )
                result = reasoner.analyze(alert, triage)
                self._complete_call(
                    receipt, provider_call=getattr(reasoner, "last_call", None),
                    latency_ms=max(0, int((perf_counter() - started) * 1000)),
                )
                return result
            except Exception as exc:
                code = self._error_code(exc)
                self._fail_call(
                    receipt, route, error_code=code,
                    latency_ms=max(0, int((perf_counter() - started) * 1000)),
                )
                errors.append(code)
        raise ModelGatewayUnavailable(
            "no governed model route completed (%s)" % ",".join(errors or ["no_route"])
        )

    def analyze_role(
        self,
        principal: ModelGatewayPrincipal,
        request: AnalystRoleRequest,
        *,
        mode: AiMode,
        data_classes: Set[DataClassification],
    ) -> AnalystRoleResult:
        self._require(principal, MODEL_GATEWAY_INVOKE)
        routes = self._route_candidates(
            principal, workload="analyst_role", mode=mode, data_classes=data_classes
        )
        errors: List[str] = []
        for route in self._ordered_with_fallbacks(principal, routes):
            if self._circuit_open(route):
                errors.append("circuit_open")
                continue
            prompt = self.get_prompt(principal, route.prompt_id, route.prompt_version)
            try:
                secret = self._resolve_secret(principal, route)
                receipt = self._reserve(
                    principal, route, mode=mode, data_classes=data_classes,
                    payload=request.model_dump(mode="json"),
                )
            except ModelGatewayUnavailable as exc:
                errors.append(self._error_code(exc))
                continue
            started = perf_counter()
            try:
                factory = self._analyst_factories.get(route.provider)
                reasoner = (
                    factory(route, prompt, secret)
                    if factory is not None
                    else self._default_analyst_factory(route, prompt, secret)
                )
                result = reasoner.analyze_role(request)
                self._complete_call(
                    receipt, provider_call=getattr(reasoner, "last_call", None),
                    latency_ms=max(0, int((perf_counter() - started) * 1000)),
                )
                return result
            except Exception as exc:
                code = self._error_code(exc)
                self._fail_call(
                    receipt, route, error_code=code,
                    latency_ms=max(0, int((perf_counter() - started) * 1000)),
                )
                errors.append(code)
        raise ModelGatewayUnavailable(
            "no governed analyst route completed (%s)" % ",".join(errors or ["no_route"])
        )

    def list_calls(
        self, principal: ModelGatewayPrincipal, *, limit: int = 100, offset: int = 0
    ) -> List[ModelCallReceipt]:
        self._require(principal, MODEL_GATEWAY_READ)
        if not 1 <= limit <= MAX_GATEWAY_PAGE or offset < 0:
            raise ValueError("invalid model call page")
        rows = self._connection.execute(
            "SELECT call_json FROM model_calls WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (principal.tenant_id, limit, offset),
        ).fetchall()
        return [ModelCallReceipt.model_validate_json(row["call_json"]) for row in rows]

    def audit(
        self, principal: ModelGatewayPrincipal, *, limit: int = 100
    ) -> List[ModelGatewayAuditEntry]:
        self._require(principal, MODEL_GATEWAY_ADMIN)
        if not 1 <= limit <= MAX_GATEWAY_PAGE:
            raise ValueError("invalid audit limit")
        rows = self._connection.execute(
            "SELECT * FROM model_gateway_audit WHERE tenant_id = ? ORDER BY sequence DESC LIMIT ?",
            (principal.tenant_id, limit),
        ).fetchall()
        return [
            ModelGatewayAuditEntry(
                sequence=row["sequence"], tenant_id=row["tenant_id"],
                actor_id=row["actor_id"], action=row["action"], subject=row["subject"],
                details_sha256=row["details_sha256"],
                occurred_at=datetime.fromisoformat(row["occurred_at"]),
            )
            for row in rows
        ]

    def health(self, principal: ModelGatewayPrincipal) -> ModelGatewayHealthSummary:
        self._require(principal, MODEL_GATEWAY_READ)
        now = self._now()
        minute = (now - timedelta(minutes=1)).isoformat()
        day = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        providers: List[ProviderHealth] = []
        qualified = 0
        for route in self.list_routes(principal):
            qualification = self._qualification(principal, route)
            if qualification is not None and qualification.passed:
                qualified += 1
            row = self._health_row(route)
            request_count = self._connection.execute(
                "SELECT COUNT(*) AS n FROM model_calls WHERE tenant_id = ? AND route_id = ? AND route_revision = ? AND created_at >= ?",
                (principal.tenant_id, route.route_id, route.revision, minute),
            ).fetchone()["n"]
            token_count = self._connection.execute(
                "SELECT COALESCE(SUM(total_tokens), 0) AS n FROM model_calls WHERE tenant_id = ? AND route_id = ? AND route_revision = ? AND created_at >= ?",
                (principal.tenant_id, route.route_id, route.revision, day),
            ).fetchone()["n"]
            in_flight = self._connection.execute(
                "SELECT COUNT(*) AS n FROM model_calls WHERE tenant_id = ? AND route_id = ? AND route_revision = ? AND status = 'reserved'",
                (principal.tenant_id, route.route_id, route.revision),
            ).fetchone()["n"]
            circuit_until = (
                datetime.fromisoformat(row["circuit_open_until"])
                if row["circuit_open_until"] else None
            )
            secret_ready = False
            try:
                self._resolve_secret(principal, route)
                secret_ready = True
            except (KeyError, ModelGatewayUnavailable):
                pass
            providers.append(
                ProviderHealth(
                    tenant_id=principal.tenant_id, route_id=route.route_id,
                    route_revision=route.revision, provider=route.provider,
                    stage=route.stage,
                    circuit_state="open" if circuit_until and circuit_until > now else "closed",
                    consecutive_failures=row["consecutive_failures"],
                    successful_calls=row["successful_calls"], failed_calls=row["failed_calls"],
                    last_latency_ms=row["last_latency_ms"],
                    last_error_code=row["last_error_code"], circuit_open_until=circuit_until,
                    qualification_id=qualification.qualification_id if qualification else None,
                    secret_ready=secret_ready,
                    budget_requests_last_minute=request_count,
                    budget_tokens_today=token_count, in_flight=in_flight,
                    calculated_at=now,
                )
            )
        prompts = self._connection.execute(
            "SELECT COUNT(*) AS n FROM model_prompts WHERE tenant_id = ?",
            (principal.tenant_id,),
        ).fetchone()["n"]
        routes = len(providers)
        return ModelGatewayHealthSummary(
            tenant_id=principal.tenant_id, prompts=prompts, routes=routes,
            active_routes=sum(item.stage == RouteStage.ACTIVE for item in providers),
            qualified_routes=qualified,
            open_circuits=sum(item.circuit_state == "open" for item in providers),
            providers=providers, calculated_at=now,
        )

    def bootstrap(
        self, principal: ModelGatewayPrincipal, configuration: ModelGatewayConfiguration
    ) -> None:
        for prompt in configuration.prompts:
            self.register_prompt(principal, **prompt.model_dump())
        for secret in configuration.secrets:
            self.register_secret(principal, **secret.model_dump())
        for route in configuration.routes:
            self.register_route(principal, route)


class GovernedSecurityReasoner(SecurityReasoner):
    """SecurityPipeline adapter that delegates only through governed routes."""

    def __init__(
        self,
        gateway: ModelGatewayService,
        principal: ModelGatewayPrincipal,
        *,
        mode: AiMode,
        data_classification: DataClassification = DataClassification.INTERNAL,
    ) -> None:
        self.gateway = gateway
        self.principal = principal
        self.mode = mode
        self.data_classification = data_classification

    def analyze(self, alert: SecurityAlert, triage: TriageAssessment) -> ModelVerdict:
        inferred = {self.data_classification}
        if alert.alert_type == "secret_egress" or any(
            any(marker in item.casefold() for marker in ("secret", "credential", "pii", "restricted"))
            for item in alert.reason_codes
        ):
            inferred.add(DataClassification.RESTRICTED)
        return self.gateway.analyze_security(
            self.principal, alert, triage, mode=self.mode, data_classes=inferred
        )


class GovernedAnalystRoleReasoner:
    """Five-role analyst adapter backed by the governed model gateway."""

    provider = "model_gateway"
    model_id = "governed-route"
    recording_id: Optional[str] = None

    def __init__(
        self,
        gateway: ModelGatewayService,
        principal: ModelGatewayPrincipal,
        *,
        mode: AiMode,
        data_classification: DataClassification = DataClassification.INTERNAL,
    ) -> None:
        self.gateway = gateway
        self.principal = principal
        self.mode = mode
        self.data_classification = data_classification

    def analyze_role(self, request: AnalystRoleRequest) -> AnalystRoleResult:
        return self.gateway.analyze_role(
            self.principal, request, mode=self.mode,
            data_classes={self.data_classification},
        )

    def accepts_identity(self, provider: str, model_id: str) -> bool:
        """Accept only an exact identity on an active qualified analyst route."""

        try:
            provider_kind = ProviderKind(provider)
        except ValueError:
            return False
        for route in self.gateway.list_routes(self.principal):
            if (
                route.stage == RouteStage.ACTIVE
                and route.workload == "analyst_role"
                and route.provider == provider_kind
                and route.exact_model_id == model_id
                and (qualification := self.gateway._qualification(self.principal, route))
                is not None
                and qualification.passed
            ):
                return True
        return False


def model_gateway_from_config(
    database_path: str,
    config_path: str,
    *,
    tenant_id: str,
    environment: Optional[Mapping[str, str]] = None,
) -> Tuple[ModelGatewayService, ModelGatewayPrincipal]:
    """Build and idempotently seed candidate-only governance definitions."""

    path = Path(config_path)
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("model gateway configuration exceeds the size limit")
    configuration = ModelGatewayConfiguration.model_validate_json(
        path.read_text(encoding="utf-8")
    )
    principal = ModelGatewayPrincipal(
        tenant_id=tenant_id,
        actor_id="system://local-model-gateway",
        permissions={
            MODEL_GATEWAY_READ, MODEL_GATEWAY_INVOKE, MODEL_GATEWAY_WRITE,
            MODEL_GATEWAY_QUALIFY, MODEL_GATEWAY_ACTIVATE, MODEL_GATEWAY_SECRET,
            MODEL_GATEWAY_ADMIN,
        },
    )
    service = ModelGatewayService(database_path, environment=environment)
    try:
        service.bootstrap(principal, configuration)
    except Exception:
        service.close()
        raise
    return service, principal
