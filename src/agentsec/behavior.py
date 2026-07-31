"""Durable metadata-only behavioral baselines, anomalies, drift, and risk."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import math
import re
import sqlite3
import threading
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from pydantic import Field, field_validator, model_validator

from .contracts import (
    AgentEvent,
    DecisionAction,
    SecurityAlert,
    Severity,
    StrictModel,
    new_id,
    utc_now,
)
from .crypto import canonical_bytes
from .enrichment import destination_class, evidence_ref, resource_class


BEHAVIOR_READ = "behavior:read"
BEHAVIOR_ANALYZE = "behavior:analyze"
BEHAVIOR_ADMIN = "behavior:admin"
DEFAULT_CONFIG_ID = "BHV-DEFAULT"
MAX_BEHAVIOR_PAGE = 200


class BehaviorAuthorizationError(PermissionError):
    """Raised when a behavior principal lacks a required permission."""


class BehaviorEntityType(str, Enum):
    AGENT = "agent"
    SOURCE = "source"
    TOOL = "tool"
    DESTINATION = "destination"


class BaselineState(str, Enum):
    LEARNING = "learning"
    ACTIVE = "active"


class DriftState(str, Enum):
    INSUFFICIENT_DATA = "insufficient_data"
    STABLE = "stable"
    WARNING = "warning"
    CRITICAL = "critical"


class LearningStatus(str, Enum):
    PENDING = "pending"
    LEARNED = "learned"
    REJECTED = "rejected"


class BehaviorPrincipal(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=3, max_length=256)
    permissions: Set[str] = Field(default_factory=set, max_length=8)

    @field_validator("permissions")
    @classmethod
    def valid_permissions(cls, value: Set[str]) -> Set[str]:
        if any(re.fullmatch(r"[a-z]+:[a-z]+", item) is None for item in value):
            raise ValueError("behavior permissions must use namespace:operation")
        return value


class BehaviorFeatureVector(StrictModel):
    event_id: str
    occurred_at: datetime
    operation: str = Field(min_length=1, max_length=128)
    resource_class: str = Field(min_length=1, max_length=64)
    destination_class: str = Field(min_length=1, max_length=64)
    source_trust: str = Field(min_length=1, max_length=64)
    hour_bucket: int = Field(ge=0, le=23)
    effectful: bool
    approval_present: bool
    sensitive_data: bool
    authority_gap: bool
    schema_drift: bool
    feature_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class BehaviorRiskFactor(StrictModel):
    factor: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    entity_ref: str = Field(min_length=8, max_length=128)
    observed: str = Field(min_length=1, max_length=256)
    expected: str = Field(min_length=1, max_length=512)
    probability: float = Field(ge=0.0, le=1.0)
    contribution: int = Field(ge=0, le=100)
    evidence_refs: List[str] = Field(min_length=1, max_length=16)
    rationale: str = Field(min_length=3, max_length=512)


class EntityBehaviorScore(StrictModel):
    entity_ref: str
    entity_type: BehaviorEntityType
    baseline_revision: int = Field(ge=0)
    observation_count: int = Field(ge=0)
    baseline_state: BaselineState
    anomaly_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    factors: List[BehaviorRiskFactor] = Field(default_factory=list, max_length=32)
    evaluated_at: datetime


class BehaviorEventAssessment(StrictModel):
    schema_version: str = "1.0.0"
    assessment_id: str = Field(pattern=r"^bhas_[A-Za-z0-9]+$")
    tenant_id: str
    event_id: str
    feature_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    config_id: str
    config_version: str
    entity_scores: List[EntityBehaviorScore] = Field(min_length=2, max_length=4)
    anomaly_score: int = Field(ge=0, le=100)
    composite_risk_score: int = Field(ge=0, le=100)
    is_anomaly: bool
    cold_start: bool
    drift_state: DriftState
    factors: List[BehaviorRiskFactor] = Field(default_factory=list, max_length=64)
    learning_status: LearningStatus = LearningStatus.PENDING
    learning_reason: Optional[str] = Field(default=None, max_length=512)
    evaluated_at: datetime

    @model_validator(mode="after")
    def coherent_assessment(self) -> "BehaviorEventAssessment":
        if self.is_anomaly and self.cold_start:
            raise ValueError("cold-start behavior cannot be classified as anomalous")
        if self.anomaly_score != max(item.anomaly_score for item in self.entity_scores):
            raise ValueError("event anomaly score must equal the maximum entity score")
        return self


class BehaviorBaseline(StrictModel):
    schema_version: str = "1.0.0"
    tenant_id: str
    entity_ref: str
    entity_type: BehaviorEntityType
    revision: int = Field(ge=1)
    state: BaselineState
    observation_count: int = Field(ge=1)
    operation_counts: Dict[str, int]
    destination_counts: Dict[str, int]
    source_trust_counts: Dict[str, int]
    hour_counts: Dict[str, int]
    authority_gap_count: int = Field(ge=0)
    sensitive_data_count: int = Field(ge=0)
    schema_drift_count: int = Field(ge=0)
    effectful_count: int = Field(ge=0)
    first_observed_at: datetime
    last_observed_at: datetime
    config_version: str
    baseline_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "operation_counts", "destination_counts", "source_trust_counts", "hour_counts"
    )
    @classmethod
    def bounded_counts(cls, value: Dict[str, int]) -> Dict[str, int]:
        if len(value) > 512 or any(
            not 1 <= len(key) <= 256 or count < 0 for key, count in value.items()
        ):
            raise ValueError("behavior baseline counts are invalid")
        return value


class BehaviorTuningInput(StrictModel):
    config_id: str = Field(default=DEFAULT_CONFIG_ID, pattern=r"^BHV-[A-Z0-9-]{3,64}$")
    version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    minimum_observations: int = Field(default=5, ge=5, le=1000)
    maximum_observations: int = Field(default=100000, ge=100, le=1000000)
    rare_probability: float = Field(default=0.1, ge=0.01, le=0.4)
    anomaly_threshold: int = Field(default=55, ge=30, le=95)
    operation_weight: int = Field(default=25, ge=0, le=50)
    destination_weight: int = Field(default=15, ge=0, le=40)
    source_trust_weight: int = Field(default=15, ge=0, le=40)
    time_weight: int = Field(default=10, ge=0, le=30)
    authority_weight: int = Field(default=15, ge=0, le=40)
    sensitive_weight: int = Field(default=10, ge=0, le=30)
    schema_drift_weight: int = Field(default=10, ge=0, le=30)
    drift_window_size: int = Field(default=50, ge=10, le=500)
    drift_warning_rate: float = Field(default=0.25, ge=0.05, le=0.8)
    drift_critical_rate: float = Field(default=0.5, ge=0.1, le=0.95)
    retention_days: int = Field(default=30, ge=1, le=365)

    @model_validator(mode="after")
    def coherent_tuning(self) -> "BehaviorTuningInput":
        weights = (
            self.operation_weight + self.destination_weight
            + self.source_trust_weight + self.time_weight
            + self.authority_weight + self.sensitive_weight
            + self.schema_drift_weight
        )
        if weights != 100:
            raise ValueError("behavior anomaly weights must total 100")
        if self.drift_warning_rate >= self.drift_critical_rate:
            raise ValueError("behavior drift warning must be below critical")
        if self.maximum_observations < self.minimum_observations * 4:
            raise ValueError("behavior maximum observations is too small")
        return self


class BehaviorTuningConfig(BehaviorTuningInput):
    tenant_id: str
    active: bool = True
    created_by: str
    reason: str = Field(min_length=10, max_length=1024)
    created_at: datetime
    config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class BehaviorDriftSummary(StrictModel):
    tenant_id: str
    entity_ref: Optional[str] = None
    window_size: int = Field(ge=0)
    anomaly_count: int = Field(ge=0)
    anomaly_rate: float = Field(ge=0.0, le=1.0)
    average_score: float = Field(ge=0.0, le=100.0)
    drift_score: int = Field(ge=0, le=100)
    state: DriftState
    reasons: List[str]
    config_version: str
    calculated_at: datetime


class BehaviorHealthSummary(StrictModel):
    tenant_id: str
    total_baselines: int = Field(ge=0)
    learning_baselines: int = Field(ge=0)
    active_baselines: int = Field(ge=0)
    total_assessments: int = Field(ge=0)
    anomalies: int = Field(ge=0)
    learned: int = Field(ge=0)
    rejected_learning: int = Field(ge=0)
    drift: BehaviorDriftSummary
    active_config: BehaviorTuningConfig
    calculated_at: datetime


def _version_key(value: str) -> Tuple[Tuple[int, Any], ...]:
    return tuple(
        (0, int(token)) if token.isdigit() else (1, token.casefold())
        for token in re.findall(r"[0-9]+|[A-Za-z]+", value)
    )


def _digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _safe_entity_ref(kind: BehaviorEntityType, value: str) -> str:
    return "%s_sha256:%s" % (
        kind.value,
        hashlib.sha256(value.encode("utf-8")).hexdigest()[:32],
    )


def _feature_vector(event: AgentEvent) -> BehaviorFeatureVector:
    unsigned = {
        "event_id": event.event_id,
        "occurred_at": event.occurred_at.astimezone(timezone.utc).isoformat(),
        "operation": event.operation,
        "resource_class": resource_class(event.resource),
        "destination_class": destination_class(event.destination),
        "source_trust": event.source_trust.value,
        "hour_bucket": event.occurred_at.astimezone(timezone.utc).hour,
        "effectful": event.is_effectful,
        "approval_present": event.approval_present,
        "sensitive_data": bool(
            {"secret", "restricted", "credential"} & event.data_classes
        ),
        "authority_gap": event.operation not in event.authority_operations,
        "schema_drift": bool(
            event.declared_tool_schema_digest
            and event.observed_tool_schema_digest
            and event.declared_tool_schema_digest != event.observed_tool_schema_digest
        ),
    }
    return BehaviorFeatureVector(**unsigned, feature_sha256=_digest(unsigned))


def _entities(event: AgentEvent, feature: BehaviorFeatureVector) -> List[Tuple[str, BehaviorEntityType]]:
    values = [
        (_safe_entity_ref(BehaviorEntityType.AGENT, event.agent_id), BehaviorEntityType.AGENT),
        (_safe_entity_ref(BehaviorEntityType.SOURCE, event.source_id), BehaviorEntityType.SOURCE),
    ]
    if event.tool_name:
        values.append(
            (_safe_entity_ref(BehaviorEntityType.TOOL, event.tool_name), BehaviorEntityType.TOOL)
        )
    if feature.destination_class != "none":
        values.append(
            (
                _safe_entity_ref(
                    BehaviorEntityType.DESTINATION, feature.destination_class
                ),
                BehaviorEntityType.DESTINATION,
            )
        )
    return values


class BehavioralRiskService:
    """Tenant-scoped event profiling with evaluate-before-learn semantics."""

    def __init__(self, path: str, *, clock: Callable[[], datetime] = utc_now) -> None:
        self.path = path
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
            raise ValueError("behavior clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _require(principal: BehaviorPrincipal, permission: str) -> None:
        if permission not in principal.permissions:
            raise BehaviorAuthorizationError("missing behavior permission: %s" % permission)

    def _migrate(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS behavior_configs (
                tenant_id TEXT NOT NULL, config_id TEXT NOT NULL, version TEXT NOT NULL,
                config_json TEXT NOT NULL, config_sha256 TEXT NOT NULL,
                active INTEGER NOT NULL, created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, config_id, version)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS behavior_config_active
                ON behavior_configs(tenant_id, config_id) WHERE active = 1;
            CREATE TABLE IF NOT EXISTS behavior_baselines (
                tenant_id TEXT NOT NULL, entity_ref TEXT NOT NULL, entity_type TEXT NOT NULL,
                baseline_json TEXT NOT NULL, revision INTEGER NOT NULL,
                observation_count INTEGER NOT NULL, state TEXT NOT NULL,
                last_observed_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, entity_ref)
            );
            CREATE INDEX IF NOT EXISTS behavior_baseline_state
                ON behavior_baselines(tenant_id, state, last_observed_at DESC);
            CREATE TABLE IF NOT EXISTS behavior_assessments (
                tenant_id TEXT NOT NULL, assessment_id TEXT NOT NULL, event_id TEXT NOT NULL,
                feature_sha256 TEXT NOT NULL, assessment_json TEXT NOT NULL,
                anomaly_score INTEGER NOT NULL, composite_risk_score INTEGER NOT NULL,
                is_anomaly INTEGER NOT NULL, learning_status TEXT NOT NULL,
                evaluated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, assessment_id),
                UNIQUE (tenant_id, event_id)
            );
            CREATE INDEX IF NOT EXISTS behavior_assessment_time
                ON behavior_assessments(tenant_id, is_anomaly, evaluated_at DESC);
            CREATE TABLE IF NOT EXISTS behavior_entity_scores (
                tenant_id TEXT NOT NULL, assessment_id TEXT NOT NULL, entity_ref TEXT NOT NULL,
                anomaly_score INTEGER NOT NULL, is_anomaly INTEGER NOT NULL,
                evaluated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, assessment_id, entity_ref)
            );
            CREATE INDEX IF NOT EXISTS behavior_entity_score_time
                ON behavior_entity_scores(tenant_id, entity_ref, evaluated_at DESC);
            CREATE TABLE IF NOT EXISTS behavior_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL,
                actor_id TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL,
                occurred_at TEXT NOT NULL
            );
            """
        )

    def _audit(self, principal: BehaviorPrincipal, action: str, subject: str) -> None:
        self._connection.execute(
            "INSERT INTO behavior_audit(tenant_id, actor_id, action, subject, occurred_at) VALUES (?, ?, ?, ?, ?)",
            (principal.tenant_id, principal.actor_id, action, subject[:512], self._now().isoformat()),
        )

    def install_default(self, principal: BehaviorPrincipal) -> BehaviorTuningConfig:
        self._require(principal, BEHAVIOR_ADMIN)
        try:
            return self.active_config(principal)
        except KeyError:
            return self.register_config(
                principal,
                BehaviorTuningInput(version="1.0.0"),
                reason="Install the bounded default behavioral risk policy.",
            )

    def register_config(
        self,
        principal: BehaviorPrincipal,
        tuning: BehaviorTuningInput,
        *,
        reason: str,
    ) -> BehaviorTuningConfig:
        self._require(principal, BEHAVIOR_ADMIN)
        if not 10 <= len(reason.strip()) <= 1024:
            raise ValueError("behavior tuning reason is invalid")
        with self._lock:
            row = self._connection.execute(
                "SELECT config_json FROM behavior_configs WHERE tenant_id = ? AND config_id = ? AND active = 1",
                (principal.tenant_id, tuning.config_id),
            ).fetchone()
            if row is not None:
                current = BehaviorTuningConfig.model_validate_json(row["config_json"])
                if _version_key(tuning.version) <= _version_key(current.version):
                    raise ValueError("behavior tuning version must increase")
            base = {
                **tuning.model_dump(mode="json"),
                "tenant_id": principal.tenant_id,
                "active": True,
                "created_by": principal.actor_id,
                "reason": reason.strip(),
                "created_at": self._now().isoformat(),
            }
            candidate = BehaviorTuningConfig.model_validate(
                {**base, "config_sha256": "0" * 64}
            )
            unsigned = candidate.model_dump(
                mode="json", exclude={"config_sha256"}
            )
            config = BehaviorTuningConfig(
                **unsigned, config_sha256=_digest(unsigned)
            )
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    "UPDATE behavior_configs SET active = 0 WHERE tenant_id = ? AND config_id = ? AND active = 1",
                    (principal.tenant_id, tuning.config_id),
                )
                self._connection.execute(
                    "INSERT INTO behavior_configs(tenant_id, config_id, version, config_json, config_sha256, active, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)",
                    (
                        principal.tenant_id, config.config_id, config.version,
                        config.model_dump_json(), config.config_sha256,
                        config.created_at.isoformat(),
                    ),
                )
                self._audit(principal, "behavior.config.activate", "%s:%s" % (config.config_id, config.version))
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return config

    @staticmethod
    def _verify_config(config: BehaviorTuningConfig) -> None:
        payload = config.model_dump(mode="json", exclude={"config_sha256"})
        if _digest(payload) != config.config_sha256:
            raise ValueError("behavior tuning config digest is invalid")

    def active_config(self, principal: BehaviorPrincipal) -> BehaviorTuningConfig:
        self._require(principal, BEHAVIOR_READ)
        with self._lock:
            row = self._connection.execute(
                "SELECT config_json FROM behavior_configs WHERE tenant_id = ? AND config_id = ? AND active = 1",
                (principal.tenant_id, DEFAULT_CONFIG_ID),
            ).fetchone()
        if row is None:
            raise KeyError(DEFAULT_CONFIG_ID)
        config = BehaviorTuningConfig.model_validate_json(row["config_json"])
        self._verify_config(config)
        return config

    def config_history(self, principal: BehaviorPrincipal) -> List[BehaviorTuningConfig]:
        self._require(principal, BEHAVIOR_READ)
        with self._lock:
            rows = self._connection.execute(
                "SELECT config_json FROM behavior_configs WHERE tenant_id = ? AND config_id = ? ORDER BY created_at DESC LIMIT 100",
                (principal.tenant_id, DEFAULT_CONFIG_ID),
            ).fetchall()
        result = [BehaviorTuningConfig.model_validate_json(row["config_json"]) for row in rows]
        for item in result:
            self._verify_config(item)
        return result

    @staticmethod
    def _verify_baseline(baseline: BehaviorBaseline) -> None:
        payload = baseline.model_dump(mode="json", exclude={"baseline_sha256"})
        if _digest(payload) != baseline.baseline_sha256:
            raise ValueError("behavior baseline digest is invalid")

    def _baseline(self, tenant_id: str, entity_ref: str) -> Optional[BehaviorBaseline]:
        row = self._connection.execute(
            "SELECT baseline_json FROM behavior_baselines WHERE tenant_id = ? AND entity_ref = ?",
            (tenant_id, entity_ref),
        ).fetchone()
        if row is None:
            return None
        baseline = BehaviorBaseline.model_validate_json(row["baseline_json"])
        self._verify_baseline(baseline)
        return baseline

    @staticmethod
    def _probability(counts: Mapping[str, int], observed: str, total: int) -> float:
        return (counts.get(observed, 0) + 1.0) / (total + len(counts) + 1.0)

    def _score_entity(
        self,
        entity_ref: str,
        entity_type: BehaviorEntityType,
        baseline: Optional[BehaviorBaseline],
        feature: BehaviorFeatureVector,
        config: BehaviorTuningConfig,
    ) -> EntityBehaviorScore:
        now = self._now()
        if baseline is None or baseline.observation_count < config.minimum_observations:
            return EntityBehaviorScore(
                entity_ref=entity_ref,
                entity_type=entity_type,
                baseline_revision=baseline.revision if baseline else 0,
                observation_count=baseline.observation_count if baseline else 0,
                baseline_state=BaselineState.LEARNING,
                anomaly_score=0,
                confidence=min(
                    0.99,
                    (baseline.observation_count if baseline else 0)
                    / config.minimum_observations,
                ),
                factors=[],
                evaluated_at=now,
            )

        factors: List[BehaviorRiskFactor] = []
        refs = [evidence_ref("event", feature.event_id), entity_ref]

        def categorical(
            factor: str,
            observed: str,
            counts: Mapping[str, int],
            weight: int,
            rationale: str,
        ) -> None:
            probability = self._probability(counts, observed, baseline.observation_count)
            unseen = counts.get(observed, 0) == 0
            if not unseen and probability >= config.rare_probability:
                return
            scale = (
                1.0
                if unseen
                else min(
                    1.0,
                    max(
                        0.25,
                        (config.rare_probability - probability)
                        / config.rare_probability,
                    ),
                )
            )
            contribution = max(1, round(weight * scale))
            expected = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:3]
            factors.append(
                BehaviorRiskFactor(
                    factor=factor,
                    entity_ref=entity_ref,
                    observed=observed,
                    expected=", ".join("%s=%d" % item for item in expected) or "no learned value",
                    probability=probability,
                    contribution=contribution,
                    evidence_refs=refs,
                    rationale=rationale,
                )
            )

        categorical(
            "rare_operation", feature.operation, baseline.operation_counts,
            config.operation_weight,
            "The operation is rare for this entity's accepted-event baseline.",
        )
        categorical(
            "rare_destination", feature.destination_class, baseline.destination_counts,
            config.destination_weight,
            "The destination class is rare for this entity.",
        )
        categorical(
            "rare_source_trust", feature.source_trust, baseline.source_trust_counts,
            config.source_trust_weight,
            "The source-trust label differs from established behavior.",
        )
        categorical(
            "rare_time", str(feature.hour_bucket), baseline.hour_counts,
            config.time_weight,
            "The UTC hour is rare for this entity's accepted activity.",
        )

        def rare_boolean(
            factor: str,
            observed: bool,
            count: int,
            weight: int,
            rationale: str,
        ) -> None:
            if not observed:
                return
            probability = (count + 1.0) / (baseline.observation_count + 2.0)
            if count > 0 and probability >= config.rare_probability:
                return
            factors.append(
                BehaviorRiskFactor(
                    factor=factor,
                    entity_ref=entity_ref,
                    observed="true",
                    expected="learned rate %.4f" % (count / baseline.observation_count),
                    probability=probability,
                    contribution=weight,
                    evidence_refs=refs,
                    rationale=rationale,
                )
            )

        rare_boolean(
            "rare_authority_gap", feature.authority_gap, baseline.authority_gap_count,
            config.authority_weight,
            "The requested operation exceeds the event's granted authority and is rare.",
        )
        rare_boolean(
            "rare_sensitive_data", feature.sensitive_data, baseline.sensitive_data_count,
            config.sensitive_weight,
            "Sensitive-data involvement is rare for this entity.",
        )
        rare_boolean(
            "rare_schema_drift", feature.schema_drift, baseline.schema_drift_count,
            config.schema_drift_weight,
            "Tool schema drift is rare for this entity.",
        )
        return EntityBehaviorScore(
            entity_ref=entity_ref,
            entity_type=entity_type,
            baseline_revision=baseline.revision,
            observation_count=baseline.observation_count,
            baseline_state=BaselineState.ACTIVE,
            anomaly_score=min(100, sum(item.contribution for item in factors)),
            confidence=min(
                1.0,
                baseline.observation_count / (config.minimum_observations * 4.0),
            ),
            factors=factors,
            evaluated_at=now,
        )

    def _drift_from_rows(
        self,
        principal: BehaviorPrincipal,
        rows: Sequence[sqlite3.Row],
        config: BehaviorTuningConfig,
        *,
        entity_ref: Optional[str],
    ) -> BehaviorDriftSummary:
        count = len(rows)
        anomalies = sum(int(row["is_anomaly"]) for row in rows)
        rate = anomalies / count if count else 0.0
        average = (
            sum(int(row["anomaly_score"]) for row in rows) / count if count else 0.0
        )
        if count < config.minimum_observations:
            state = DriftState.INSUFFICIENT_DATA
            reasons = ["Fewer than the configured minimum observations exist in the drift window."]
        elif rate >= config.drift_critical_rate:
            state = DriftState.CRITICAL
            reasons = ["Recent anomaly rate met or exceeded the critical drift threshold."]
        elif rate >= config.drift_warning_rate:
            state = DriftState.WARNING
            reasons = ["Recent anomaly rate met or exceeded the warning drift threshold."]
        else:
            state = DriftState.STABLE
            reasons = ["Recent anomaly rate remains below configured drift thresholds."]
        return BehaviorDriftSummary(
            tenant_id=principal.tenant_id,
            entity_ref=entity_ref,
            window_size=count,
            anomaly_count=anomalies,
            anomaly_rate=rate,
            average_score=round(average, 4),
            drift_score=min(100, round(rate * 100)),
            state=state,
            reasons=reasons,
            config_version=config.version,
            calculated_at=self._now(),
        )

    def drift(
        self, principal: BehaviorPrincipal, *, entity_ref: Optional[str] = None
    ) -> BehaviorDriftSummary:
        self._require(principal, BEHAVIOR_READ)
        if entity_ref is not None and re.fullmatch(
            r"(?:agent|source|tool|destination)_sha256:[0-9a-f]{32}", entity_ref
        ) is None:
            raise ValueError("behavior entity reference is invalid")
        config = self.active_config(principal)
        with self._lock:
            if entity_ref is None:
                rows = self._connection.execute(
                    "SELECT anomaly_score, is_anomaly FROM behavior_assessments WHERE tenant_id = ? ORDER BY evaluated_at DESC LIMIT ?",
                    (principal.tenant_id, config.drift_window_size),
                ).fetchall()
            else:
                rows = self._connection.execute(
                    "SELECT anomaly_score, is_anomaly FROM behavior_entity_scores WHERE tenant_id = ? AND entity_ref = ? ORDER BY evaluated_at DESC LIMIT ?",
                    (principal.tenant_id, entity_ref, config.drift_window_size),
                ).fetchall()
        return self._drift_from_rows(
            principal, rows, config, entity_ref=entity_ref
        )

    def analyze(
        self, principal: BehaviorPrincipal, event: AgentEvent
    ) -> BehaviorEventAssessment:
        self._require(principal, BEHAVIOR_ANALYZE)
        if event.tenant_id != principal.tenant_id:
            raise BehaviorAuthorizationError("cross-tenant behavior event is forbidden")
        feature = _feature_vector(event)
        config = self.active_config(principal)
        with self._lock:
            existing = self._connection.execute(
                "SELECT feature_sha256, assessment_json FROM behavior_assessments WHERE tenant_id = ? AND event_id = ?",
                (principal.tenant_id, event.event_id),
            ).fetchone()
            if existing is not None:
                if existing["feature_sha256"] != feature.feature_sha256:
                    raise ValueError("behavior event ID conflicts with prior features")
                return BehaviorEventAssessment.model_validate_json(existing["assessment_json"])
            scores = [
                self._score_entity(
                    entity_ref,
                    entity_type,
                    self._baseline(principal.tenant_id, entity_ref),
                    feature,
                    config,
                )
                for entity_ref, entity_type in _entities(event, feature)
            ]
            anomaly_score = max(item.anomaly_score for item in scores)
            cold_start = all(item.baseline_state == BaselineState.LEARNING for item in scores)
            contextual = 0
            if feature.source_trust in {"external-untrusted", "suspected-adversarial", "unknown"}:
                contextual += 15
            if feature.authority_gap:
                contextual += 15
            if feature.sensitive_data:
                contextual += 10
            if feature.schema_drift:
                contextual += 10
            if feature.effectful and feature.destination_class == "external-network":
                contextual += 5
            composite = min(100, round(anomaly_score * 0.75) + contextual)
            is_anomaly = not cold_start and composite >= config.anomaly_threshold
            factors = []
            seen = set()
            for score in sorted(scores, key=lambda item: -item.anomaly_score):
                for factor in score.factors:
                    key = (factor.factor, factor.entity_ref)
                    if key not in seen:
                        factors.append(factor)
                        seen.add(key)
            prior_rows = self._connection.execute(
                "SELECT anomaly_score, is_anomaly FROM behavior_assessments WHERE tenant_id = ? ORDER BY evaluated_at DESC LIMIT ?",
                (principal.tenant_id, max(0, config.drift_window_size - 1)),
            ).fetchall()
            synthetic_rows = list(prior_rows) + [
                {"anomaly_score": anomaly_score, "is_anomaly": int(is_anomaly)}  # type: ignore[list-item]
            ]
            drift = self._drift_from_rows(
                principal, synthetic_rows[-config.drift_window_size:], config,
                entity_ref=None,
            )
            assessment = BehaviorEventAssessment(
                assessment_id=new_id("bhas"),
                tenant_id=principal.tenant_id,
                event_id=event.event_id,
                feature_sha256=feature.feature_sha256,
                config_id=config.config_id,
                config_version=config.version,
                entity_scores=scores,
                anomaly_score=anomaly_score,
                composite_risk_score=composite,
                is_anomaly=is_anomaly,
                cold_start=cold_start,
                drift_state=drift.state,
                factors=factors,
                evaluated_at=self._now(),
            )
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    "INSERT INTO behavior_assessments(tenant_id, assessment_id, event_id, feature_sha256, assessment_json, anomaly_score, composite_risk_score, is_anomaly, learning_status, evaluated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        principal.tenant_id, assessment.assessment_id, event.event_id,
                        feature.feature_sha256, assessment.model_dump_json(),
                        assessment.anomaly_score, assessment.composite_risk_score,
                        int(assessment.is_anomaly), assessment.learning_status.value,
                        assessment.evaluated_at.isoformat(),
                    ),
                )
                for score in assessment.entity_scores:
                    self._connection.execute(
                        "INSERT INTO behavior_entity_scores(tenant_id, assessment_id, entity_ref, anomaly_score, is_anomaly, evaluated_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            principal.tenant_id, assessment.assessment_id,
                            score.entity_ref, score.anomaly_score,
                            int(score.anomaly_score >= config.anomaly_threshold),
                            assessment.evaluated_at.isoformat(),
                        ),
                    )
                self._audit(principal, "behavior.analyze", assessment.assessment_id)
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        self._prune(principal, config)
        return assessment

    @staticmethod
    def _increment(counts: Dict[str, int], key: str) -> Dict[str, int]:
        updated = dict(counts)
        updated[key] = updated.get(key, 0) + 1
        return updated

    @staticmethod
    def _decay(counts: Dict[str, int]) -> Dict[str, int]:
        return {
            key: decayed
            for key, value in counts.items()
            if (decayed := math.floor(value * 0.9)) > 0
        }

    def learn(
        self,
        principal: BehaviorPrincipal,
        event: AgentEvent,
        assessment: BehaviorEventAssessment,
        *,
        eligible: bool,
        reason: str,
    ) -> BehaviorEventAssessment:
        self._require(principal, BEHAVIOR_ANALYZE)
        if event.tenant_id != principal.tenant_id or assessment.tenant_id != principal.tenant_id:
            raise BehaviorAuthorizationError("cross-tenant behavior learning is forbidden")
        if assessment.event_id != event.event_id or assessment.feature_sha256 != _feature_vector(event).feature_sha256:
            raise ValueError("behavior learning event does not match assessment")
        if not 3 <= len(reason.strip()) <= 512:
            raise ValueError("behavior learning reason is invalid")
        config = self.active_config(principal)
        target_status = LearningStatus.LEARNED if eligible else LearningStatus.REJECTED
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT assessment_json, learning_status FROM behavior_assessments WHERE tenant_id = ? AND assessment_id = ?",
                    (principal.tenant_id, assessment.assessment_id),
                ).fetchone()
                if row is None:
                    raise KeyError(assessment.assessment_id)
                if row["learning_status"] != LearningStatus.PENDING.value:
                    stored = BehaviorEventAssessment.model_validate_json(row["assessment_json"])
                    if stored.learning_status != target_status:
                        raise ValueError("behavior learning decision is already final")
                    self._connection.execute("ROLLBACK")
                    return stored
                updated_assessment = assessment.model_copy(
                    update={
                        "learning_status": target_status,
                        "learning_reason": reason.strip(),
                    }
                )
                if eligible:
                    feature = _feature_vector(event)
                    for entity_ref, entity_type in _entities(event, feature):
                        baseline = self._baseline(principal.tenant_id, entity_ref)
                        if baseline is None:
                            count = 1
                            payload = {
                                "tenant_id": principal.tenant_id,
                                "entity_ref": entity_ref,
                                "entity_type": entity_type,
                                "revision": 1,
                                "state": BaselineState.LEARNING,
                                "observation_count": count,
                                "operation_counts": {feature.operation: 1},
                                "destination_counts": {feature.destination_class: 1},
                                "source_trust_counts": {feature.source_trust: 1},
                                "hour_counts": {str(feature.hour_bucket): 1},
                                "authority_gap_count": int(feature.authority_gap),
                                "sensitive_data_count": int(feature.sensitive_data),
                                "schema_drift_count": int(feature.schema_drift),
                                "effectful_count": int(feature.effectful),
                                "first_observed_at": feature.occurred_at,
                                "last_observed_at": feature.occurred_at,
                                "config_version": config.version,
                            }
                        else:
                            decay = baseline.observation_count >= config.maximum_observations
                            operation_counts = self._decay(baseline.operation_counts) if decay else baseline.operation_counts
                            destination_counts = self._decay(baseline.destination_counts) if decay else baseline.destination_counts
                            source_trust_counts = self._decay(baseline.source_trust_counts) if decay else baseline.source_trust_counts
                            hour_counts = self._decay(baseline.hour_counts) if decay else baseline.hour_counts
                            base_count = sum(operation_counts.values())
                            count = min(config.maximum_observations, base_count + 1)
                            scale = 0.9 if decay else 1.0
                            payload = baseline.model_dump(
                                mode="python", exclude={"baseline_sha256"}
                            )
                            payload.update(
                                {
                                    "revision": baseline.revision + 1,
                                    "state": BaselineState.ACTIVE
                                    if count >= config.minimum_observations
                                    else BaselineState.LEARNING,
                                    "observation_count": count,
                                    "operation_counts": self._increment(operation_counts, feature.operation),
                                    "destination_counts": self._increment(destination_counts, feature.destination_class),
                                    "source_trust_counts": self._increment(source_trust_counts, feature.source_trust),
                                    "hour_counts": self._increment(hour_counts, str(feature.hour_bucket)),
                                    "authority_gap_count": math.floor(baseline.authority_gap_count * scale) + int(feature.authority_gap),
                                    "sensitive_data_count": math.floor(baseline.sensitive_data_count * scale) + int(feature.sensitive_data),
                                    "schema_drift_count": math.floor(baseline.schema_drift_count * scale) + int(feature.schema_drift),
                                    "effectful_count": math.floor(baseline.effectful_count * scale) + int(feature.effectful),
                                    "first_observed_at": min(
                                        baseline.first_observed_at,
                                        feature.occurred_at,
                                    ),
                                    "last_observed_at": max(
                                        baseline.last_observed_at,
                                        feature.occurred_at,
                                    ),
                                    "config_version": config.version,
                                }
                            )
                        unsigned = BehaviorBaseline.model_construct(
                            **payload, baseline_sha256="0" * 64
                        ).model_dump(mode="json", exclude={"baseline_sha256"})
                        baseline_record = BehaviorBaseline(
                            **unsigned, baseline_sha256=_digest(unsigned)
                        )
                        self._connection.execute(
                            "INSERT INTO behavior_baselines(tenant_id, entity_ref, entity_type, baseline_json, revision, observation_count, state, last_observed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(tenant_id, entity_ref) DO UPDATE SET entity_type=excluded.entity_type, baseline_json=excluded.baseline_json, revision=excluded.revision, observation_count=excluded.observation_count, state=excluded.state, last_observed_at=excluded.last_observed_at",
                            (
                                principal.tenant_id, entity_ref, entity_type.value,
                                baseline_record.model_dump_json(), baseline_record.revision,
                                baseline_record.observation_count, baseline_record.state.value,
                                baseline_record.last_observed_at.isoformat(),
                            ),
                        )
                self._connection.execute(
                    "UPDATE behavior_assessments SET assessment_json = ?, learning_status = ? WHERE tenant_id = ? AND assessment_id = ?",
                    (
                        updated_assessment.model_dump_json(), target_status.value,
                        principal.tenant_id, assessment.assessment_id,
                    ),
                )
                self._audit(
                    principal,
                    "behavior.learn" if eligible else "behavior.learn.reject",
                    "%s:%s" % (assessment.assessment_id, reason.strip()),
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return updated_assessment

    def _prune(self, principal: BehaviorPrincipal, config: BehaviorTuningConfig) -> None:
        cutoff = self._now() - timedelta(days=config.retention_days)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                old = self._connection.execute(
                    "SELECT assessment_id FROM behavior_assessments WHERE tenant_id = ? AND evaluated_at < ? LIMIT 1000",
                    (principal.tenant_id, cutoff.isoformat()),
                ).fetchall()
                ids = [row["assessment_id"] for row in old]
                for assessment_id in ids:
                    self._connection.execute(
                        "DELETE FROM behavior_entity_scores WHERE tenant_id = ? AND assessment_id = ?",
                        (principal.tenant_id, assessment_id),
                    )
                    self._connection.execute(
                        "DELETE FROM behavior_assessments WHERE tenant_id = ? AND assessment_id = ?",
                        (principal.tenant_id, assessment_id),
                    )
                if ids:
                    self._audit(principal, "behavior.retention", "removed:%d" % len(ids))
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def get_assessment(
        self, principal: BehaviorPrincipal, assessment_id: str
    ) -> BehaviorEventAssessment:
        self._require(principal, BEHAVIOR_READ)
        if re.fullmatch(r"bhas_[A-Za-z0-9]+", assessment_id) is None:
            raise ValueError("behavior assessment ID is invalid")
        with self._lock:
            row = self._connection.execute(
                "SELECT assessment_json FROM behavior_assessments WHERE tenant_id = ? AND assessment_id = ?",
                (principal.tenant_id, assessment_id),
            ).fetchone()
        if row is None:
            raise KeyError(assessment_id)
        return BehaviorEventAssessment.model_validate_json(row["assessment_json"])

    def list_assessments(
        self,
        principal: BehaviorPrincipal,
        *,
        anomalies_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> List[BehaviorEventAssessment]:
        self._require(principal, BEHAVIOR_READ)
        if not 1 <= limit <= MAX_BEHAVIOR_PAGE or not 0 <= offset <= 100000:
            raise ValueError("behavior assessment pagination is invalid")
        clause = " AND is_anomaly = 1" if anomalies_only else ""
        with self._lock:
            rows = self._connection.execute(
                "SELECT assessment_json FROM behavior_assessments WHERE tenant_id = ?"
                + clause + " ORDER BY evaluated_at DESC, assessment_id LIMIT ? OFFSET ?",
                (principal.tenant_id, limit, offset),
            ).fetchall()
        return [BehaviorEventAssessment.model_validate_json(row["assessment_json"]) for row in rows]

    def list_baselines(
        self,
        principal: BehaviorPrincipal,
        *,
        state: Optional[BaselineState] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[BehaviorBaseline]:
        self._require(principal, BEHAVIOR_READ)
        if not 1 <= limit <= MAX_BEHAVIOR_PAGE or not 0 <= offset <= 100000:
            raise ValueError("behavior baseline pagination is invalid")
        clause = " AND state = ?" if state is not None else ""
        values: List[Any] = [principal.tenant_id]
        if state is not None:
            values.append(state.value)
        values.extend([limit, offset])
        with self._lock:
            rows = self._connection.execute(
                "SELECT baseline_json FROM behavior_baselines WHERE tenant_id = ?"
                + clause + " ORDER BY last_observed_at DESC, entity_ref LIMIT ? OFFSET ?",
                values,
            ).fetchall()
        result = [BehaviorBaseline.model_validate_json(row["baseline_json"]) for row in rows]
        for item in result:
            self._verify_baseline(item)
        return result

    def health(self, principal: BehaviorPrincipal) -> BehaviorHealthSummary:
        self._require(principal, BEHAVIOR_READ)
        config = self.active_config(principal)
        with self._lock:
            baseline = self._connection.execute(
                "SELECT COUNT(*) AS total, SUM(CASE WHEN state = 'learning' THEN 1 ELSE 0 END) AS learning, SUM(CASE WHEN state = 'active' THEN 1 ELSE 0 END) AS active FROM behavior_baselines WHERE tenant_id = ?",
                (principal.tenant_id,),
            ).fetchone()
            assessment = self._connection.execute(
                "SELECT COUNT(*) AS total, SUM(is_anomaly) AS anomalies, SUM(CASE WHEN learning_status = 'learned' THEN 1 ELSE 0 END) AS learned, SUM(CASE WHEN learning_status = 'rejected' THEN 1 ELSE 0 END) AS rejected FROM behavior_assessments WHERE tenant_id = ?",
                (principal.tenant_id,),
            ).fetchone()
        return BehaviorHealthSummary(
            tenant_id=principal.tenant_id,
            total_baselines=int(baseline["total"] or 0),
            learning_baselines=int(baseline["learning"] or 0),
            active_baselines=int(baseline["active"] or 0),
            total_assessments=int(assessment["total"] or 0),
            anomalies=int(assessment["anomalies"] or 0),
            learned=int(assessment["learned"] or 0),
            rejected_learning=int(assessment["rejected"] or 0),
            drift=self.drift(principal),
            active_config=config,
            calculated_at=self._now(),
        )

    def alert_for(
        self, assessment: BehaviorEventAssessment, event: AgentEvent
    ) -> Optional[SecurityAlert]:
        if not assessment.is_anomaly:
            return None
        severity = (
            Severity.CRITICAL if assessment.composite_risk_score >= 90
            else Severity.HIGH if assessment.composite_risk_score >= 70
            else Severity.MEDIUM
        )
        recommended = (
            DecisionAction.DENY
            if assessment.composite_risk_score >= 90
            else DecisionAction.REQUIRE_APPROVAL
        )
        fingerprint = _digest(
            {
                "tenant_id": event.tenant_id,
                "event_id": event.event_id,
                "assessment_id": assessment.assessment_id,
                "config_version": assessment.config_version,
            }
        )
        factor_codes = [item.factor.upper() for item in assessment.factors[:8]]
        return SecurityAlert(
            fingerprint=fingerprint,
            event_id=event.event_id,
            tenant_id=event.tenant_id,
            flow_id=event.flow_id,
            agent_id=event.agent_id,
            alert_type="behavioral_anomaly",
            title="AI-agent behavior deviated from its accepted baseline",
            severity=severity,
            confidence=max(item.confidence for item in assessment.entity_scores),
            source_trust=event.source_trust,
            operation=event.operation,
            resource=event.resource,
            destination=event.destination,
            detector_id="BHV-COMPOSITE-RISK-001",
            rule_version=assessment.config_version,
            reason_codes=["BEHAVIORAL_ANOMALY", *factor_codes],
            evidence=[assessment.assessment_id, *[item.entity_ref for item in assessment.entity_scores]],
            framework_mappings=["MITRE-ATLAS-AML.T0051", "NIST-AI-RMF-MEASURE"],
            recommended_action=recommended,
        )
