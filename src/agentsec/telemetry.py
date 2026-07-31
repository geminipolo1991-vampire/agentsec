"""Provider-neutral AI runtime telemetry collection and privacy boundary.

The collector input is deliberately ephemeral.  A successful capture produces a
``TelemetryEnvelope`` that contains only bounded metadata and protected content
evidence.  Raw prompts, model output, tool arguments, and tool results are never
copied into the envelope by accident.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
import urllib.request
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Protocol, Set, Tuple, Union
from urllib.parse import urlsplit

from pydantic import Field, ValidationError, field_validator, model_validator

from .contracts import AgentEvent, StrictModel, TrustClass, new_id, utc_now
from .redaction import Redactor


TELEMETRY_SCHEMA_VERSION = "1.0.0"
TelemetryScalar = Union[str, int, float, bool]
DEFAULT_ALLOWED_ATTRIBUTES = {
    "api_operation",
    "provider_status",
    "provider_request_id",
    "finish_reason",
    "otel_span_name",
    "framework_name",
    "framework_event",
    "mcp_jsonrpc_method",
}


class TelemetryEventKind(str, Enum):
    MODEL_REQUEST = "model_request"
    MODEL_RESPONSE = "model_response"
    MODEL_CALL = "model_call"
    TOOL_CALL_REQUEST = "tool_call_request"
    TOOL_CALL_RESULT = "tool_call_result"
    AGENT_MESSAGE = "agent_message"
    RAG_RETRIEVAL = "rag_retrieval"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    GUARDRAIL_DECISION = "guardrail_decision"
    ERROR = "error"
    HEARTBEAT = "heartbeat"


class CollectionMode(str, Enum):
    METADATA_ONLY = "metadata_only"
    REDACTED = "redacted"
    ENCRYPTED_RAW = "encrypted_raw"


class CaptureStatus(str, Enum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"


class TelemetryContext(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    application_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=256)
    source_type: str = Field(min_length=1, max_length=64)
    collector_id: str = Field(min_length=1, max_length=128)
    environment: str = Field(default="unknown", min_length=1, max_length=64)
    provider: Optional[str] = Field(default=None, max_length=64)
    model_id: Optional[str] = Field(default=None, max_length=256)


def _validate_json_value(value: Any, *, depth: int = 0, count: Optional[List[int]] = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    if count[0] > 4096:
        raise ValueError("content contains too many values")
    if depth > 20:
        raise ValueError("content nesting exceeds 20 levels")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise ValueError("content contains a non-finite number")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, depth=depth + 1, count=count)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128:
                raise ValueError("content object keys must be bounded strings")
            _validate_json_value(item, depth=depth + 1, count=count)
        return
    raise TypeError("telemetry content must be JSON-compatible")


class TelemetryInput(StrictModel):
    """Ephemeral SDK/adapter input.  Do not persist or export this model."""

    schema_version: str = TELEMETRY_SCHEMA_VERSION
    event_id: str = Field(default_factory=lambda: new_id("tel"), min_length=5, max_length=128)
    occurred_at: datetime = Field(default_factory=utc_now)
    context: TelemetryContext
    kind: TelemetryEventKind
    span_id: Optional[str] = Field(default=None, max_length=128)
    parent_span_id: Optional[str] = Field(default=None, max_length=128)
    sequence: Optional[int] = Field(default=None, ge=1)
    operation: Optional[str] = Field(default=None, max_length=128)
    resource: Optional[str] = Field(default=None, max_length=512)
    destination: Optional[str] = Field(default=None, max_length=512)
    tool_name: Optional[str] = Field(default=None, max_length=128)
    data_classes: Set[str] = Field(default_factory=set, max_length=64)
    indicators: Set[str] = Field(default_factory=set, max_length=64)
    attributes: Dict[str, TelemetryScalar] = Field(default_factory=dict)
    content: Dict[str, Any] = Field(default_factory=dict)
    duration_ms: Optional[int] = Field(default=None, ge=0)
    input_tokens: Optional[int] = Field(default=None, ge=0)
    output_tokens: Optional[int] = Field(default=None, ge=0)
    success: Optional[bool] = None
    error_code: Optional[str] = Field(default=None, max_length=128)

    @field_validator("occurred_at")
    @classmethod
    def timestamp_must_be_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone")
        return value

    @model_validator(mode="after")
    def bounded_maps(self) -> "TelemetryInput":
        if len(self.attributes) > 64:
            raise ValueError("at most 64 telemetry attributes are allowed")
        for key, value in self.attributes.items():
            if not key or len(key) > 128:
                raise ValueError("attribute keys must contain 1 to 128 characters")
            if isinstance(value, str) and len(value) > 2048:
                raise ValueError("attribute string values are limited to 2048 characters")
        if len(self.content) > 16:
            raise ValueError("at most 16 content fields are allowed")
        for field_name, value in self.content.items():
            if not field_name or len(field_name) > 128:
                raise ValueError("content field names must contain 1 to 128 characters")
            _validate_json_value(value)
        return self


class ProtectedContent(StrictModel):
    ciphertext: str = Field(min_length=1, max_length=2_000_000)
    key_reference: str = Field(min_length=1, max_length=512)
    algorithm: str = Field(min_length=1, max_length=64)


class ContentProtector(Protocol):
    def protect(
        self, payload: bytes, *, field_name: str, context: TelemetryContext
    ) -> ProtectedContent:
        ...


class ContentEvidence(StrictModel):
    field_name: str = Field(min_length=1, max_length=128)
    collection_mode: CollectionMode
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    byte_length: int = Field(ge=0)
    data_classes: Set[str] = Field(default_factory=set)
    redaction_count: int = Field(default=0, ge=0)
    redacted_preview: Optional[str] = Field(default=None, max_length=8192)
    ciphertext: Optional[str] = Field(default=None, max_length=2_000_000)
    key_reference: Optional[str] = Field(default=None, max_length=512)
    protection_algorithm: Optional[str] = Field(default=None, max_length=64)
    omitted_reason: Optional[str] = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def mode_shape_is_safe(self) -> "ContentEvidence":
        protected_fields = [self.ciphertext, self.key_reference, self.protection_algorithm]
        if self.omitted_reason:
            if self.redacted_preview is not None or any(item is not None for item in protected_fields):
                raise ValueError("omitted content cannot include a preview or protected payload")
            return self
        if self.collection_mode == CollectionMode.METADATA_ONLY:
            if self.redacted_preview is not None or any(item is not None for item in protected_fields):
                raise ValueError("metadata-only content can contain only digest and size")
        elif self.collection_mode == CollectionMode.REDACTED:
            if self.redacted_preview is None or any(item is not None for item in protected_fields):
                raise ValueError("redacted content requires only a redacted preview")
        elif self.collection_mode == CollectionMode.ENCRYPTED_RAW:
            if self.redacted_preview is not None or any(item is None for item in protected_fields):
                raise ValueError("encrypted content requires ciphertext, key reference, and algorithm")
        return self


class TelemetryEnvelope(StrictModel):
    """Safe normalized result of collection; suitable for downstream ingestion."""

    schema_version: str = TELEMETRY_SCHEMA_VERSION
    event_id: str
    occurred_at: datetime
    observed_at: datetime = Field(default_factory=utc_now)
    context: TelemetryContext
    kind: TelemetryEventKind
    span_id: Optional[str] = None
    parent_span_id: Optional[str] = None
    sequence: Optional[int] = None
    operation: Optional[str] = None
    resource: Optional[str] = None
    destination: Optional[str] = None
    tool_name: Optional[str] = None
    data_classes: Set[str] = Field(default_factory=set)
    indicators: Set[str] = Field(default_factory=set)
    attributes: Dict[str, TelemetryScalar] = Field(default_factory=dict)
    content_evidence: List[ContentEvidence] = Field(default_factory=list)
    collection_mode: CollectionMode
    duration_ms: Optional[int] = None
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    success: Optional[bool] = None
    error_code: Optional[str] = None


class CaptureReceipt(StrictModel):
    status: CaptureStatus
    event_id: Optional[str] = None
    source_key: str
    reason_codes: List[str] = Field(default_factory=list)
    observed_at: datetime = Field(default_factory=utc_now)


class TelemetrySourceHealth(StrictModel):
    source_key: str
    status: str
    accepted_events: int = Field(ge=0)
    duplicate_events: int = Field(ge=0)
    rejected_events: int = Field(ge=0)
    late_events: int = Field(ge=0)
    out_of_order_events: int = Field(ge=0)
    observed_sequence_gaps: int = Field(ge=0)
    omitted_content_fields: int = Field(ge=0)
    redaction_count: int = Field(ge=0)
    last_sequence: Optional[int] = None
    last_occurred_at: Optional[datetime] = None
    last_observed_at: Optional[datetime] = None
    last_error_code: Optional[str] = None


class TelemetryCapture(StrictModel):
    receipt: CaptureReceipt
    event: Optional[TelemetryEnvelope] = None
    source_health: TelemetrySourceHealth


class TelemetryBatchResult(StrictModel):
    accepted: int = Field(ge=0)
    duplicates: int = Field(ge=0)
    rejected: int = Field(ge=0)
    events: List[TelemetryEnvelope] = Field(default_factory=list)
    receipts: List[CaptureReceipt] = Field(default_factory=list)
    source_health: List[TelemetrySourceHealth] = Field(default_factory=list)


class CollectorConfig(StrictModel):
    collection_mode: CollectionMode = CollectionMode.METADATA_ONLY
    allowed_attribute_keys: Set[str] = Field(
        default_factory=lambda: set(DEFAULT_ALLOWED_ATTRIBUTES)
    )
    reject_unknown_attributes: bool = True
    late_after_seconds: int = Field(default=300, ge=0, le=86400)
    max_content_bytes: int = Field(default=262_144, ge=0, le=10_000_000)
    max_redacted_preview_bytes: int = Field(default=8192, ge=128, le=65536)
    max_batch_events: int = Field(default=1000, ge=1, le=10000)
    max_jsonl_bytes: int = Field(default=25_000_000, ge=1024, le=500_000_000)
    max_jsonl_line_bytes: int = Field(default=1_000_000, ge=128, le=10_000_000)


class _MutableHealth:
    def __init__(self) -> None:
        self.accepted_events = 0
        self.duplicate_events = 0
        self.rejected_events = 0
        self.late_events = 0
        self.out_of_order_events = 0
        self.observed_sequence_gaps = 0
        self.omitted_content_fields = 0
        self.redaction_count = 0
        self.last_sequence: Optional[int] = None
        self.last_occurred_at: Optional[datetime] = None
        self.last_observed_at: Optional[datetime] = None
        self.last_error_code: Optional[str] = None


class TelemetryHealthRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sources: Dict[str, _MutableHealth] = {}

    def _state(self, source_key: str) -> _MutableHealth:
        return self._sources.setdefault(source_key, _MutableHealth())

    @staticmethod
    def _snapshot(source_key: str, state: _MutableHealth) -> TelemetrySourceHealth:
        degraded = any(
            [
                state.rejected_events,
                state.late_events,
                state.out_of_order_events,
                state.observed_sequence_gaps,
                state.omitted_content_fields,
            ]
        )
        return TelemetrySourceHealth(
            source_key=source_key,
            status="degraded" if degraded else "healthy",
            accepted_events=state.accepted_events,
            duplicate_events=state.duplicate_events,
            rejected_events=state.rejected_events,
            late_events=state.late_events,
            out_of_order_events=state.out_of_order_events,
            observed_sequence_gaps=state.observed_sequence_gaps,
            omitted_content_fields=state.omitted_content_fields,
            redaction_count=state.redaction_count,
            last_sequence=state.last_sequence,
            last_occurred_at=state.last_occurred_at,
            last_observed_at=state.last_observed_at,
            last_error_code=state.last_error_code,
        )

    def accepted(
        self,
        source_key: str,
        event: TelemetryEnvelope,
        *,
        late: bool,
        omitted: int,
        redactions: int,
    ) -> TelemetrySourceHealth:
        with self._lock:
            state = self._state(source_key)
            state.accepted_events += 1
            state.late_events += int(late)
            state.omitted_content_fields += omitted
            state.redaction_count += redactions
            if event.sequence is not None:
                if state.last_sequence is not None:
                    if event.sequence <= state.last_sequence:
                        state.out_of_order_events += 1
                    elif event.sequence > state.last_sequence + 1:
                        state.observed_sequence_gaps += event.sequence - state.last_sequence - 1
                if state.last_sequence is None or event.sequence > state.last_sequence:
                    state.last_sequence = event.sequence
            state.last_occurred_at = event.occurred_at
            state.last_observed_at = event.observed_at
            state.last_error_code = None
            return self._snapshot(source_key, state)

    def duplicate(self, source_key: str) -> TelemetrySourceHealth:
        with self._lock:
            state = self._state(source_key)
            state.duplicate_events += 1
            state.last_observed_at = utc_now()
            return self._snapshot(source_key, state)

    def rejected(self, source_key: str, error_code: str) -> TelemetrySourceHealth:
        with self._lock:
            state = self._state(source_key)
            state.rejected_events += 1
            state.last_observed_at = utc_now()
            state.last_error_code = error_code
            return self._snapshot(source_key, state)

    def get(self, source_key: str) -> TelemetrySourceHealth:
        with self._lock:
            return self._snapshot(source_key, self._state(source_key))

    def all(self) -> List[TelemetrySourceHealth]:
        with self._lock:
            return [
                self._snapshot(key, self._sources[key]) for key in sorted(self._sources)
            ]


def _canonical_content(value: Any) -> bytes:
    _validate_json_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class TelemetryCollector:
    """Captures strict runtime telemetry and emits only safe envelopes."""

    def __init__(
        self,
        config: Optional[CollectorConfig] = None,
        *,
        redactor: Optional[Redactor] = None,
        protector: Optional[ContentProtector] = None,
        health: Optional[TelemetryHealthRegistry] = None,
    ) -> None:
        self.config = config or CollectorConfig()
        if self.config.collection_mode == CollectionMode.ENCRYPTED_RAW and protector is None:
            raise ValueError("encrypted_raw collection requires a ContentProtector")
        self.redactor = redactor or Redactor()
        self.protector = protector
        self.health = health or TelemetryHealthRegistry()
        self._seen_lock = threading.Lock()
        self._seen_event_ids: Set[Tuple[str, str]] = set()

    @staticmethod
    def source_key(context: TelemetryContext) -> str:
        return "%s/%s" % (context.collector_id, context.source_id)

    @staticmethod
    def _source_key_from_payload(payload: Mapping[str, object]) -> str:
        context = payload.get("context")
        if isinstance(context, Mapping):
            collector = context.get("collector_id")
            source = context.get("source_id")
            if isinstance(collector, str) and isinstance(source, str):
                return "%s/%s" % (collector[:128], source[:256])
        return "unknown/unknown"

    def _reject(
        self,
        source_key: str,
        reason_code: str,
        *,
        event_id: Optional[str] = None,
    ) -> TelemetryCapture:
        source_health = self.health.rejected(source_key, reason_code)
        return TelemetryCapture(
            receipt=CaptureReceipt(
                status=CaptureStatus.REJECTED,
                event_id=event_id,
                source_key=source_key,
                reason_codes=[reason_code],
            ),
            source_health=source_health,
        )

    def _content_evidence(self, item: TelemetryInput) -> List[ContentEvidence]:
        evidence: List[ContentEvidence] = []
        for field_name in sorted(item.content):
            payload = _canonical_content(item.content[field_name])
            digest = hashlib.sha256(payload).hexdigest()
            common: Dict[str, Any] = {
                "field_name": field_name,
                "collection_mode": self.config.collection_mode,
                "sha256": digest,
                "byte_length": len(payload),
                "data_classes": item.data_classes,
            }
            if len(payload) > self.config.max_content_bytes:
                evidence.append(ContentEvidence(**common, omitted_reason="content_size_limit"))
                continue
            if self.config.collection_mode == CollectionMode.METADATA_ONLY:
                evidence.append(ContentEvidence(**common))
                continue
            if self.config.collection_mode == CollectionMode.REDACTED:
                redacted = self.redactor.redact(item.content[field_name])
                encoded = json.dumps(
                    redacted.value,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
                if len(encoded) > self.config.max_redacted_preview_bytes:
                    evidence.append(
                        ContentEvidence(**common, omitted_reason="redacted_preview_size_limit")
                    )
                else:
                    evidence.append(
                        ContentEvidence(
                            **common,
                            redacted_preview=encoded.decode("utf-8"),
                            redaction_count=redacted.redaction_count,
                        )
                    )
                continue
            if self.protector is None:  # defensive; constructor already rejects this state
                raise RuntimeError("content protector is unavailable")
            protected = self.protector.protect(
                payload, field_name=field_name, context=item.context
            )
            evidence.append(
                ContentEvidence(
                    **common,
                    ciphertext=protected.ciphertext,
                    key_reference=protected.key_reference,
                    protection_algorithm=protected.algorithm,
                )
            )
        return evidence

    def capture(self, payload: Union[TelemetryInput, Mapping[str, object]]) -> TelemetryCapture:
        if isinstance(payload, TelemetryInput):
            item = payload
        else:
            source_key = self._source_key_from_payload(payload)
            try:
                item = TelemetryInput.model_validate(payload)
            except (ValidationError, ValueError, TypeError):
                event_id = payload.get("event_id")
                return self._reject(
                    source_key,
                    "invalid_telemetry_input",
                    event_id=event_id if isinstance(event_id, str) else None,
                )

        source_key = self.source_key(item.context)
        unknown_attributes = set(item.attributes) - self.config.allowed_attribute_keys
        if unknown_attributes and self.config.reject_unknown_attributes:
            return self._reject(source_key, "unknown_telemetry_attributes", event_id=item.event_id)

        event_key = (item.context.tenant_id, item.event_id)
        with self._seen_lock:
            if event_key in self._seen_event_ids:
                source_health = self.health.duplicate(source_key)
                return TelemetryCapture(
                    receipt=CaptureReceipt(
                        status=CaptureStatus.DUPLICATE,
                        event_id=item.event_id,
                        source_key=source_key,
                        reason_codes=["duplicate_event_id"],
                    ),
                    source_health=source_health,
                )
            # Reserve before performing content work so two concurrent captures
            # cannot both accept the same event ID. Failed work releases it.
            self._seen_event_ids.add(event_key)

        try:
            redacted_attributes = self.redactor.redact(item.attributes)
            content_evidence = self._content_evidence(item)
        except (TypeError, ValueError, RuntimeError):
            with self._seen_lock:
                self._seen_event_ids.discard(event_key)
            return self._reject(source_key, "content_protection_failed", event_id=item.event_id)

        observed_at = utc_now()
        envelope = TelemetryEnvelope(
            event_id=item.event_id,
            occurred_at=item.occurred_at,
            observed_at=observed_at,
            context=item.context,
            kind=item.kind,
            span_id=item.span_id,
            parent_span_id=item.parent_span_id,
            sequence=item.sequence,
            operation=item.operation,
            resource=item.resource,
            destination=item.destination,
            tool_name=item.tool_name,
            data_classes=item.data_classes,
            indicators=item.indicators,
            attributes=redacted_attributes.value,
            content_evidence=content_evidence,
            collection_mode=self.config.collection_mode,
            duration_ms=item.duration_ms,
            input_tokens=item.input_tokens,
            output_tokens=item.output_tokens,
            success=item.success,
            error_code=item.error_code,
        )
        age_seconds = max(0.0, (observed_at - item.occurred_at.astimezone(timezone.utc)).total_seconds())
        omitted = sum(entry.omitted_reason is not None for entry in content_evidence)
        content_redactions = sum(entry.redaction_count for entry in content_evidence)
        source_health = self.health.accepted(
            source_key,
            envelope,
            late=age_seconds > self.config.late_after_seconds,
            omitted=omitted,
            redactions=redacted_attributes.redaction_count + content_redactions,
        )
        return TelemetryCapture(
            receipt=CaptureReceipt(
                status=CaptureStatus.ACCEPTED,
                event_id=item.event_id,
                source_key=source_key,
            ),
            event=envelope,
            source_health=source_health,
        )

    def capture_batch(
        self, payloads: Iterable[Union[TelemetryInput, Mapping[str, object]]]
    ) -> TelemetryBatchResult:
        captures: List[TelemetryCapture] = []
        for index, payload in enumerate(payloads):
            if index >= self.config.max_batch_events:
                captures.append(self._reject("batch/batch", "batch_event_limit_exceeded"))
                break
            captures.append(self.capture(payload))
        return self._batch(captures)

    def capture_stream(
        self, payloads: Iterable[Union[TelemetryInput, Mapping[str, object]]]
    ) -> Iterator[TelemetryCapture]:
        for payload in payloads:
            yield self.capture(payload)

    def _batch(self, captures: List[TelemetryCapture]) -> TelemetryBatchResult:
        return TelemetryBatchResult(
            accepted=sum(item.receipt.status == CaptureStatus.ACCEPTED for item in captures),
            duplicates=sum(item.receipt.status == CaptureStatus.DUPLICATE for item in captures),
            rejected=sum(item.receipt.status == CaptureStatus.REJECTED for item in captures),
            events=[item.event for item in captures if item.event is not None],
            receipts=[item.receipt for item in captures],
            source_health=self.health.all(),
        )


class JsonlTelemetryReplayer:
    """Bounded JSONL replay for fixtures, historical logs, and collector recovery."""

    def __init__(self, collector: TelemetryCollector) -> None:
        self.collector = collector

    def replay(self, path: Path) -> TelemetryBatchResult:
        if not path.is_file():
            raise ValueError("telemetry replay path must be a file")
        if path.stat().st_size > self.collector.config.max_jsonl_bytes:
            raise ValueError("telemetry replay file exceeds configured size")
        captures: List[TelemetryCapture] = []
        with path.open("rb") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                if line_number > self.collector.config.max_batch_events:
                    captures.append(
                        self.collector._reject("replay/replay", "replay_event_limit_exceeded")
                    )
                    break
                if len(raw_line) > self.collector.config.max_jsonl_line_bytes:
                    captures.append(
                        self.collector._reject("replay/replay", "replay_line_size_exceeded")
                    )
                    continue
                try:
                    payload = json.loads(raw_line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    captures.append(
                        self.collector._reject("replay/replay", "invalid_jsonl_record")
                    )
                    continue
                if not isinstance(payload, dict):
                    captures.append(
                        self.collector._reject("replay/replay", "invalid_jsonl_record")
                    )
                    continue
                captures.append(self.collector.capture(payload))
        return self.collector._batch(captures)


def _usage_value(payload: Mapping[str, object], *names: str) -> Optional[int]:
    for name in names:
        value = payload.get(name)
        if isinstance(value, int) and value >= 0:
            return value
    return None


class OpenAIResponsesTelemetryAdapter:
    """Maps one OpenAI Responses call into request/response telemetry events."""

    @staticmethod
    def normalize(
        context: TelemetryContext,
        request: Mapping[str, object],
        response: Mapping[str, object],
        *,
        occurred_at: Optional[datetime] = None,
        sequence_start: Optional[int] = None,
    ) -> List[TelemetryInput]:
        model = str(response.get("model") or request.get("model") or context.model_id or "unknown")
        adapted_context = context.model_copy(update={"provider": "openai", "model_id": model})
        request_event = TelemetryInput(
            occurred_at=occurred_at or utc_now(),
            context=adapted_context,
            kind=TelemetryEventKind.MODEL_REQUEST,
            sequence=sequence_start,
            operation="model.generate",
            resource="model://openai/%s" % model,
            attributes={"api_operation": "responses.create"},
            content={"input": request.get("input")},
        )
        usage = response.get("usage")
        usage_map = usage if isinstance(usage, Mapping) else {}
        response_event = TelemetryInput(
            context=adapted_context,
            kind=TelemetryEventKind.MODEL_RESPONSE,
            parent_span_id=request_event.event_id,
            sequence=sequence_start + 1 if sequence_start is not None else None,
            operation="model.generate",
            resource="model://openai/%s" % model,
            attributes={
                "api_operation": "responses.create",
                "provider_status": str(response.get("status", "unknown")),
                "provider_request_id": str(response.get("id", "unknown")),
            },
            content={"output": response.get("output")},
            input_tokens=_usage_value(usage_map, "input_tokens"),
            output_tokens=_usage_value(usage_map, "output_tokens"),
            success=response.get("status") == "completed" and not response.get("error"),
            error_code="provider_error" if response.get("error") else None,
        )
        return [request_event, response_event]


class AnthropicMessagesTelemetryAdapter:
    """Maps one Anthropic Messages call into request/response telemetry events."""

    @staticmethod
    def normalize(
        context: TelemetryContext,
        request: Mapping[str, object],
        response: Mapping[str, object],
        *,
        occurred_at: Optional[datetime] = None,
        sequence_start: Optional[int] = None,
    ) -> List[TelemetryInput]:
        model = str(response.get("model") or request.get("model") or context.model_id or "unknown")
        adapted_context = context.model_copy(update={"provider": "anthropic", "model_id": model})
        content: Dict[str, object] = {"messages": request.get("messages")}
        if "system" in request:
            content["system"] = request.get("system")
        request_event = TelemetryInput(
            occurred_at=occurred_at or utc_now(),
            context=adapted_context,
            kind=TelemetryEventKind.MODEL_REQUEST,
            sequence=sequence_start,
            operation="model.generate",
            resource="model://anthropic/%s" % model,
            attributes={"api_operation": "messages.create"},
            content=content,
        )
        usage = response.get("usage")
        usage_map = usage if isinstance(usage, Mapping) else {}
        stop_reason = response.get("stop_reason")
        response_event = TelemetryInput(
            context=adapted_context,
            kind=TelemetryEventKind.MODEL_RESPONSE,
            parent_span_id=request_event.event_id,
            sequence=sequence_start + 1 if sequence_start is not None else None,
            operation="model.generate",
            resource="model://anthropic/%s" % model,
            attributes={
                "api_operation": "messages.create",
                "provider_status": "completed" if stop_reason in {"end_turn", "stop_sequence"} else "incomplete",
                "provider_request_id": str(response.get("id", "unknown")),
                "finish_reason": str(stop_reason or "unknown"),
            },
            content={"output": response.get("content")},
            input_tokens=_usage_value(usage_map, "input_tokens"),
            output_tokens=_usage_value(usage_map, "output_tokens"),
            success=stop_reason in {"end_turn", "stop_sequence"},
            error_code=None if stop_reason in {"end_turn", "stop_sequence"} else "incomplete_response",
        )
        return [request_event, response_event]


class ToolCallTelemetryAdapter:
    """Maps a tool request and result without placing either raw value in metadata."""

    @staticmethod
    def normalize(
        context: TelemetryContext,
        *,
        tool_name: str,
        operation: str,
        resource: str,
        arguments: Any,
        result: Any,
        destination: Optional[str] = None,
        success: bool = True,
        sequence_start: Optional[int] = None,
        data_classes: Optional[Set[str]] = None,
        indicators: Optional[Set[str]] = None,
    ) -> List[TelemetryInput]:
        request_event = TelemetryInput(
            context=context,
            kind=TelemetryEventKind.TOOL_CALL_REQUEST,
            sequence=sequence_start,
            operation=operation,
            resource=resource,
            destination=destination,
            tool_name=tool_name,
            data_classes=data_classes or set(),
            indicators=indicators or set(),
            content={"tool_arguments": arguments},
        )
        result_event = TelemetryInput(
            context=context,
            kind=TelemetryEventKind.TOOL_CALL_RESULT,
            parent_span_id=request_event.event_id,
            sequence=sequence_start + 1 if sequence_start is not None else None,
            operation=operation,
            resource=resource,
            destination=destination,
            tool_name=tool_name,
            data_classes=data_classes or set(),
            indicators=indicators or set(),
            content={"tool_result": result},
            success=success,
            error_code=None if success else "tool_error",
        )
        return [request_event, result_event]


class LangChainCallbackTelemetryAdapter:
    """Dependency-free mapping for LangChain callback handler inputs.

    Applications call this adapter from ``on_llm_start``/``on_llm_end`` (or the
    corresponding chat callbacks). The SDK does not import LangChain and thus
    cannot inherit its dependency or release lifecycle.
    """

    @staticmethod
    def normalize(
        context: TelemetryContext,
        *,
        run_id: str,
        parent_run_id: Optional[str],
        provider: str,
        model_id: str,
        prompts: Any,
        generations: Any,
        sequence_start: Optional[int] = None,
        error_code: Optional[str] = None,
    ) -> List[TelemetryInput]:
        adapted = context.model_copy(update={"provider": provider, "model_id": model_id})
        run_key = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:32]
        request = TelemetryInput(
            event_id="tel_lc_req_%s" % run_key,
            context=adapted,
            kind=TelemetryEventKind.MODEL_REQUEST,
            span_id=run_id,
            parent_span_id=parent_run_id,
            sequence=sequence_start,
            operation="model.generate",
            resource="model://%s/%s" % (provider, model_id),
            attributes={"framework_name": "langchain", "framework_event": "llm_start"},
            content={"input": prompts},
        )
        response = TelemetryInput(
            event_id="tel_lc_res_%s" % run_key,
            context=adapted,
            kind=TelemetryEventKind.MODEL_RESPONSE,
            span_id=run_id,
            parent_span_id=request.event_id,
            sequence=sequence_start + 1 if sequence_start is not None else None,
            operation="model.generate",
            resource="model://%s/%s" % (provider, model_id),
            attributes={"framework_name": "langchain", "framework_event": "llm_end"},
            content={"output": generations},
            success=error_code is None,
            error_code=error_code,
        )
        return [request, response]


class McpJsonRpcTelemetryAdapter:
    """Map one MCP ``tools/call`` JSON-RPC exchange into tool telemetry."""

    @staticmethod
    def normalize(
        context: TelemetryContext,
        request: Mapping[str, object],
        response: Mapping[str, object],
        *,
        operation: str,
        resource: str,
        destination: Optional[str] = None,
        sequence_start: Optional[int] = None,
        data_classes: Optional[Set[str]] = None,
        indicators: Optional[Set[str]] = None,
    ) -> List[TelemetryInput]:
        if request.get("jsonrpc") != "2.0" or request.get("method") != "tools/call":
            raise ValueError("MCP telemetry requires a JSON-RPC 2.0 tools/call request")
        params = request.get("params")
        if not isinstance(params, Mapping):
            raise ValueError("MCP tools/call params must be an object")
        tool_name = params.get("name")
        if not isinstance(tool_name, str) or not tool_name:
            raise ValueError("MCP tools/call requires a tool name")
        arguments = params.get("arguments", {})
        success = "error" not in response
        result = response.get("result") if success else response.get("error")
        events = ToolCallTelemetryAdapter.normalize(
            context,
            tool_name=tool_name,
            operation=operation,
            resource=resource,
            destination=destination,
            arguments=arguments,
            result=result,
            success=success,
            sequence_start=sequence_start,
            data_classes=data_classes,
            indicators=indicators,
        )
        return [
            event.model_copy(
                update={
                    "attributes": {
                        **event.attributes,
                        "mcp_jsonrpc_method": "tools/call",
                    }
                }
            )
            for event in events
        ]


class OpenTelemetrySpanAdapter:
    """Maps an allowlisted subset of OpenTelemetry GenAI span fields."""

    @staticmethod
    def normalize(context: TelemetryContext, span: Mapping[str, object]) -> TelemetryInput:
        attributes = span.get("attributes")
        source = attributes if isinstance(attributes, Mapping) else {}
        operation = str(source.get("gen_ai.operation.name", span.get("name", "model.call")))
        provider = source.get("gen_ai.provider.name")
        model = source.get("gen_ai.request.model")
        adapted_context = context.model_copy(
            update={
                "provider": str(provider) if provider is not None else context.provider,
                "model_id": str(model) if model is not None else context.model_id,
            }
        )
        content: Dict[str, object] = {}
        if "gen_ai.input.messages" in source:
            content["input"] = source["gen_ai.input.messages"]
        if "gen_ai.output.messages" in source:
            content["output"] = source["gen_ai.output.messages"]
        occurred_at = span.get("start_time") or utc_now()
        return TelemetryInput(
            event_id=str(span.get("event_id") or new_id("tel")),
            occurred_at=occurred_at,
            context=adapted_context,
            kind=TelemetryEventKind.MODEL_CALL,
            span_id=str(span.get("span_id")) if span.get("span_id") is not None else None,
            parent_span_id=(
                str(span.get("parent_span_id")) if span.get("parent_span_id") is not None else None
            ),
            sequence=source.get("agentsec.sequence") if isinstance(source.get("agentsec.sequence"), int) else None,
            operation=operation,
            resource=(
                "model://%s/%s"
                % (adapted_context.provider or "unknown", adapted_context.model_id or "unknown")
            ),
            attributes={
                "otel_span_name": str(span.get("name", "unknown")),
                "provider_status": str(source.get("error.type", "ok")),
            },
            content=content,
            input_tokens=(
                source.get("gen_ai.usage.input_tokens")
                if isinstance(source.get("gen_ai.usage.input_tokens"), int)
                else None
            ),
            output_tokens=(
                source.get("gen_ai.usage.output_tokens")
                if isinstance(source.get("gen_ai.usage.output_tokens"), int)
                else None
            ),
            success="error.type" not in source,
            error_code=str(source["error.type"]) if "error.type" in source else None,
        )


def agent_event_from_telemetry(
    envelope: TelemetryEnvelope,
    *,
    source_trust: TrustClass,
    authority_operations: Set[str],
    approval_present: bool = False,
    declared_tool_schema_digest: Optional[str] = None,
    observed_tool_schema_digest: Optional[str] = None,
) -> AgentEvent:
    """Bridge a protected tool proposal into the existing enforcement pipeline.

    Collection metadata is observation, not authorization.  Consequently trust,
    effective authority, approval, and manifest digests must come from a trusted
    gateway/controller and are never inferred from SDK attributes.
    """

    if envelope.kind != TelemetryEventKind.TOOL_CALL_REQUEST:
        raise ValueError("only tool_call_request telemetry can propose an effect")
    if not envelope.operation or not envelope.resource or not envelope.tool_name:
        raise ValueError("tool telemetry requires operation, resource, and tool name")
    safe_attributes = {
        "telemetry_schema_version": envelope.schema_version,
        "telemetry_collector_id": envelope.context.collector_id,
        "telemetry_application_id": envelope.context.application_id,
        "telemetry_session_id": envelope.context.session_id,
        "telemetry_content_evidence_count": str(len(envelope.content_evidence)),
    }
    return AgentEvent(
        event_id=envelope.event_id,
        occurred_at=envelope.occurred_at,
        tenant_id=envelope.context.tenant_id,
        flow_id=envelope.context.trace_id,
        agent_id=envelope.context.agent_id,
        operation=envelope.operation,
        resource=envelope.resource,
        destination=envelope.destination,
        source_type=envelope.context.source_type,
        source_id=envelope.context.source_id,
        source_trust=source_trust,
        data_classes=envelope.data_classes,
        authority_operations=authority_operations,
        indicators=envelope.indicators,
        approval_present=approval_present,
        is_effectful=True,
        tool_name=envelope.tool_name,
        declared_tool_schema_digest=declared_tool_schema_digest,
        observed_tool_schema_digest=observed_tool_schema_digest,
        attributes=safe_attributes,
    )


class TelemetryDeliveryTransport(Protocol):
    def send(self, event: TelemetryInput) -> Dict[str, object]:
        ...

    def send_batch(self, events: List[TelemetryInput]) -> Dict[str, object]:
        ...


class TelemetryHttpClient(Protocol):
    def post(
        self,
        *,
        url: str,
        headers: Dict[str, str],
        payload: Dict[str, object],
        timeout_seconds: float,
    ) -> Dict[str, object]:
        ...


class UrllibTelemetryHttpClient:
    def post(
        self,
        *,
        url: str,
        headers: Dict[str, str],
        payload: Dict[str, object],
        timeout_seconds: float,
    ) -> Dict[str, object]:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = response.read(1_000_001)
        if len(body) > 1_000_000:
            raise RuntimeError("telemetry response exceeds size limit")
        decoded = json.loads(body.decode("utf-8"))
        if not isinstance(decoded, dict):
            raise RuntimeError("telemetry response must be a JSON object")
        return decoded


def validate_telemetry_endpoint(endpoint: str, *, allow_loopback_http: bool = False) -> str:
    parsed = urlsplit(endpoint)
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    if parsed.scheme != "https" and not (allow_loopback_http and loopback and parsed.scheme == "http"):
        raise ValueError("telemetry endpoint must use HTTPS or explicit loopback HTTP")
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("telemetry endpoint cannot contain credentials, query, or fragment")
    path = parsed.path.rstrip("/")
    if path:
        raise ValueError("telemetry endpoint must be an origin without a path")
    port = ":%s" % parsed.port if parsed.port is not None else ""
    host = "[%s]" % parsed.hostname if ":" in parsed.hostname else parsed.hostname
    return "%s://%s%s" % (parsed.scheme, host, port)


class HttpTelemetryDeliveryTransport:
    """Legacy bearer transport for compatible proxies; prefer signed delivery."""

    def __init__(
        self,
        *,
        endpoint: str,
        token: str,
        allow_loopback_http: bool = False,
        timeout_seconds: float = 5.0,
        http_client: Optional[TelemetryHttpClient] = None,
    ) -> None:
        if not token or len(token) > 4096:
            raise ValueError("telemetry token must contain 1 to 4096 characters")
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValueError("telemetry timeout must be between 0 and 60 seconds")
        self.endpoint = validate_telemetry_endpoint(
            endpoint, allow_loopback_http=allow_loopback_http
        )
        self._token = token
        self.timeout_seconds = timeout_seconds
        self.http_client = http_client or UrllibTelemetryHttpClient()

    def _post(self, path: str, payload: Dict[str, object]) -> Dict[str, object]:
        return self.http_client.post(
            url=self.endpoint + path,
            headers={
                "Authorization": "Bearer %s" % self._token,
                "Content-Type": "application/json",
            },
            payload=payload,
            timeout_seconds=self.timeout_seconds,
        )

    def send(self, event: TelemetryInput) -> Dict[str, object]:
        return self._post("/v1/telemetry", event.model_dump(mode="json"))

    def send_batch(self, events: List[TelemetryInput]) -> Dict[str, object]:
        return self._post(
            "/v1/telemetry/batch",
            {"events": [event.model_dump(mode="json") for event in events]},
        )


class SignedHttpTelemetryDeliveryTransport:
    """Replay-resistant workload transport for the AgentSec ingestion gateway."""

    def __init__(
        self,
        *,
        endpoint: str,
        credential_id: str,
        secret: str,
        allow_loopback_http: bool = False,
        timeout_seconds: float = 5.0,
        http_client: Optional[TelemetryHttpClient] = None,
    ) -> None:
        if not 3 <= len(credential_id) <= 128 or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
            for character in credential_id
        ):
            raise ValueError("telemetry credential_id has an invalid format")
        if not 32 <= len(secret) <= 4096:
            raise ValueError("telemetry workload secret must contain 32 to 4096 characters")
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValueError("telemetry timeout must be between 0 and 60 seconds")
        self.endpoint = validate_telemetry_endpoint(
            endpoint, allow_loopback_http=allow_loopback_http
        )
        self.credential_id = credential_id
        self._secret = secret.encode("utf-8")
        self.timeout_seconds = timeout_seconds
        self.http_client = http_client or UrllibTelemetryHttpClient()

    def _post(self, path: str, payload: Dict[str, object]) -> Dict[str, object]:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(24)
        body_digest = hashlib.sha256(body).hexdigest()
        canonical = ("POST\n%s\n%s\n%s\n%s" % (
            path,
            timestamp,
            nonce,
            body_digest,
        )).encode("utf-8")
        signature = hmac.new(self._secret, canonical, hashlib.sha256).hexdigest()
        return self.http_client.post(
            url=self.endpoint + path,
            headers={
                "Content-Type": "application/json",
                "X-AgentSec-Key-Id": self.credential_id,
                "X-AgentSec-Timestamp": timestamp,
                "X-AgentSec-Nonce": nonce,
                "X-AgentSec-Signature": "v1=%s" % signature,
            },
            payload=payload,
            timeout_seconds=self.timeout_seconds,
        )

    def send(self, event: TelemetryInput) -> Dict[str, object]:
        return self._post("/v1/telemetry", event.model_dump(mode="json"))

    def send_batch(self, events: List[TelemetryInput]) -> Dict[str, object]:
        return self._post(
            "/v1/telemetry/batch",
            {"events": [event.model_dump(mode="json") for event in events]},
        )


class AgentSecTelemetryClient:
    """Small Python SDK client; content transmission is opt-in."""

    def __init__(
        self, transport: TelemetryDeliveryTransport, *, include_content: bool = False
    ) -> None:
        self.transport = transport
        self.include_content = include_content

    def _project(self, event: TelemetryInput) -> TelemetryInput:
        if self.include_content:
            return event
        return event.model_copy(update={"content": {}})

    def emit(self, event: TelemetryInput) -> Dict[str, object]:
        return self.transport.send(self._project(event))

    def emit_batch(self, events: List[TelemetryInput]) -> Dict[str, object]:
        if not 1 <= len(events) <= 1000:
            raise ValueError("events must contain 1 to 1000 telemetry records")
        return self.transport.send_batch([self._project(event) for event in events])
