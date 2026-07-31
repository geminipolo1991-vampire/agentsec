"""Durable explainable finding correlation and first-class incident lifecycle."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import re
import sqlite3
import threading
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from pydantic import Field, field_validator, model_validator

from .contracts import PipelineResult, StrictModel, new_id, utc_now
from .crypto import canonical_bytes


CORRELATION_READ = "correlation:read"
CORRELATION_WRITE = "correlation:write"
CORRELATION_ADMIN = "correlation:admin"
MAX_INCIDENT_FINDINGS = 500
MAX_CORRELATION_PAGE = 200
CORRELATION_WINDOW = timedelta(hours=4)
REOPEN_WINDOW = timedelta(days=7)
ATTACH_THRESHOLD = 60


class CorrelationAuthorizationError(PermissionError):
    """Raised when a correlation principal lacks a required permission."""


class CorrelationIncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    CLOSED = "closed"
    MERGED = "merged"


class CorrelationOutcome(str, Enum):
    CREATED = "created"
    ATTACHED = "attached"
    REOPENED = "reopened"
    SUPPRESSED = "suppressed"


class AttackStage(str, Enum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DISCOVERY = "discovery"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"


STAGE_BY_ALERT = {
    "indirect_prompt_injection": AttackStage.INITIAL_ACCESS,
    "authority_violation": AttackStage.PRIVILEGE_ESCALATION,
    "destructive_action_without_approval": AttackStage.IMPACT,
    "persistent_memory_poisoning": AttackStage.PERSISTENCE,
    "mcp_schema_drift": AttackStage.DISCOVERY,
    "secret_egress": AttackStage.EXFILTRATION,
    "behavioral_anomaly": AttackStage.ANOMALOUS_BEHAVIOR,
}


class CorrelationPrincipal(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=3, max_length=256)
    permissions: Set[str] = Field(default_factory=set, max_length=8)

    @field_validator("permissions")
    @classmethod
    def valid_permissions(cls, value: Set[str]) -> Set[str]:
        if any(re.fullmatch(r"[a-z]+:[a-z]+", item) is None for item in value):
            raise ValueError("correlation permissions must use namespace:operation")
        return value


class CorrelationSignal(StrictModel):
    tenant_id: str
    finding_id: str = Field(pattern=r"^fnd_[A-Za-z0-9]+$")
    alert_id: str
    event_id: str
    flow_ref: str = Field(pattern=r"^flow_sha256:[0-9a-f]{32}$")
    agent_ref: str = Field(pattern=r"^agent_sha256:[0-9a-f]{32}$")
    entity_refs: List[str] = Field(min_length=2, max_length=8)
    alert_type: str
    title: str
    severity: str
    risk_score: int = Field(ge=0, le=100)
    priority: str
    decision: str
    attack_stage: AttackStage
    evidence_refs: List[str] = Field(default_factory=list, max_length=32)
    occurred_at: datetime


class IncidentFindingLink(StrictModel):
    finding_id: str
    alert_id: str
    event_id: str
    alert_type: str
    title: str
    severity: str
    risk_score: int = Field(ge=0, le=100)
    priority: str
    decision: str
    attack_stage: AttackStage
    flow_ref: str
    agent_ref: str
    entity_refs: List[str]
    evidence_refs: List[str]
    correlation_reasons: List[str]
    correlation_score: int = Field(ge=0, le=100)
    sequence_order: int = Field(ge=1)
    occurred_at: datetime
    linked_at: datetime


class AttackSequenceStep(StrictModel):
    order: int = Field(ge=1)
    stage: AttackStage
    finding_id: str
    event_id: str
    occurred_at: datetime
    evidence_refs: List[str]


class CorrelationAuditEntry(StrictModel):
    action: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,63}$")
    actor_id: str
    reason: str = Field(min_length=3, max_length=512)
    at: datetime


class CorrelatedIncident(StrictModel):
    schema_version: str = "1.0.0"
    incident_id: str = Field(pattern=r"^inc_[A-Za-z0-9]+$")
    tenant_id: str
    title: str
    status: CorrelationIncidentStatus
    severity: str
    priority: str
    risk_score: int = Field(ge=0, le=100)
    finding_count: int = Field(ge=1, le=MAX_INCIDENT_FINDINGS)
    finding_links: List[IncidentFindingLink] = Field(min_length=1, max_length=MAX_INCIDENT_FINDINGS)
    attack_sequence: List[AttackSequenceStep] = Field(min_length=1, max_length=MAX_INCIDENT_FINDINGS)
    entity_refs: List[str] = Field(min_length=2, max_length=2048)
    evidence_refs: List[str] = Field(default_factory=list, max_length=2048)
    correlation_policy_version: str = "correlation-2026-07-24.1"
    reopened_count: int = Field(default=0, ge=0)
    parent_incident_id: Optional[str] = None
    superseded_by: Optional[str] = None
    revision: int = Field(ge=1)
    audit: List[CorrelationAuditEntry] = Field(min_length=1, max_length=2048)
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None
    incident_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def coherent_incident(self) -> "CorrelatedIncident":
        if self.finding_count != len(self.finding_links):
            raise ValueError("incident finding count must match links")
        ordered = sorted(self.finding_links, key=lambda item: (item.occurred_at, item.finding_id))
        if [item.finding_id for item in ordered] != [item.finding_id for item in self.finding_links]:
            raise ValueError("incident links must be ordered by event time")
        if [item.sequence_order for item in self.finding_links] != list(range(1, len(self.finding_links) + 1)):
            raise ValueError("incident sequence order must be contiguous")
        if self.status == CorrelationIncidentStatus.MERGED and not self.superseded_by:
            raise ValueError("merged incident requires a superseding incident")
        return self


class CorrelationCandidate(StrictModel):
    incident_id: str
    score: int = Field(ge=0, le=100)
    reasons: List[str]


class CorrelationDecision(StrictModel):
    schema_version: str = "1.0.0"
    decision_id: str = Field(pattern=r"^cord_[A-Za-z0-9]+$")
    tenant_id: str
    finding_id: str
    outcome: CorrelationOutcome
    incident_id: Optional[str]
    suppression_id: Optional[str]
    candidates: List[CorrelationCandidate] = Field(default_factory=list, max_length=20)
    selected_score: int = Field(ge=0, le=100)
    reasons: List[str]
    policy_version: str = "correlation-2026-07-24.1"
    decided_at: datetime
    decision_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SuppressionRule(StrictModel):
    schema_version: str = "1.0.0"
    suppression_id: str = Field(pattern=r"^sup_[A-Za-z0-9]+$")
    tenant_id: str
    alert_type: str = Field(min_length=3, max_length=128)
    agent_ref: Optional[str] = Field(default=None, pattern=r"^agent_sha256:[0-9a-f]{32}$")
    reason: str = Field(min_length=10, max_length=512)
    created_by: str
    created_at: datetime
    expires_at: datetime
    active: bool = True
    revoked_by: Optional[str] = None
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = Field(default=None, max_length=512)
    suppression_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CorrelationHealth(StrictModel):
    tenant_id: str
    total_incidents: int = Field(ge=0)
    open_incidents: int = Field(ge=0)
    closed_incidents: int = Field(ge=0)
    merged_incidents: int = Field(ge=0)
    total_findings: int = Field(ge=0)
    multi_finding_incidents: int = Field(ge=0)
    suppressed_findings: int = Field(ge=0)
    active_suppressions: int = Field(ge=0)
    calculated_at: datetime


class CorrelationSplitResult(StrictModel):
    source: CorrelatedIncident
    child: CorrelatedIncident


def _digest(payload: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _ref(namespace: str, value: str) -> str:
    return "%s_sha256:%s" % (namespace, hashlib.sha256(value.encode()).hexdigest()[:32])


def signal_from_result(result: PipelineResult) -> CorrelationSignal:
    event = result.event
    values = [
        _ref("agent", event.agent_id),
        _ref("source", event.source_id),
        _ref("resource", event.resource),
    ]
    if event.tool_name:
        values.append(_ref("tool", event.tool_name))
    if event.destination:
        values.append(_ref("destination", event.destination))
    return CorrelationSignal(
        tenant_id=event.tenant_id,
        finding_id=result.finding.finding_id,
        alert_id=result.alert.alert_id,
        event_id=event.event_id,
        flow_ref=_ref("flow", event.flow_id),
        agent_ref=_ref("agent", event.agent_id),
        entity_refs=list(dict.fromkeys(values)),
        alert_type=result.alert.alert_type,
        title=result.alert.title,
        severity=result.alert.severity.value,
        risk_score=result.triage.risk_score,
        priority=result.triage.priority,
        decision=result.judgment.action.value,
        attack_stage=STAGE_BY_ALERT.get(result.alert.alert_type, AttackStage.EXECUTION),
        evidence_refs=[_ref("evidence", value) for value in result.alert.evidence[:32]],
        occurred_at=event.occurred_at,
    )


class IncidentCorrelationService:
    """SQLite-backed correlation with explainable grouping and governed surgery."""

    def __init__(self, path: str, *, clock: Callable[[], datetime] = utc_now) -> None:
        self.path = path
        self.clock = clock
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS correlated_incidents (
              tenant_id TEXT NOT NULL, incident_id TEXT NOT NULL, incident_json TEXT NOT NULL,
              incident_sha256 TEXT NOT NULL, status TEXT NOT NULL, risk_score INTEGER NOT NULL,
              finding_count INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              PRIMARY KEY (tenant_id, incident_id));
            CREATE INDEX IF NOT EXISTS correlated_incident_status ON correlated_incidents(tenant_id, status, updated_at DESC);
            CREATE TABLE IF NOT EXISTS incident_finding_links (
              tenant_id TEXT NOT NULL, finding_id TEXT NOT NULL, incident_id TEXT NOT NULL,
              link_json TEXT NOT NULL, occurred_at TEXT NOT NULL,
              PRIMARY KEY (tenant_id, finding_id));
            CREATE INDEX IF NOT EXISTS incident_link_incident ON incident_finding_links(tenant_id, incident_id, occurred_at);
            CREATE TABLE IF NOT EXISTS correlation_decisions (
              tenant_id TEXT NOT NULL, decision_id TEXT NOT NULL, finding_id TEXT NOT NULL,
              decision_json TEXT NOT NULL, decided_at TEXT NOT NULL,
              PRIMARY KEY (tenant_id, decision_id), UNIQUE (tenant_id, finding_id));
            CREATE TABLE IF NOT EXISTS correlation_suppressions (
              tenant_id TEXT NOT NULL, suppression_id TEXT NOT NULL, suppression_json TEXT NOT NULL,
              active INTEGER NOT NULL, expires_at TEXT NOT NULL,
              PRIMARY KEY (tenant_id, suppression_id));
            CREATE INDEX IF NOT EXISTS correlation_suppression_active ON correlation_suppressions(tenant_id, active, expires_at);
            """
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("correlation clock must be timezone aware")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _require(principal: CorrelationPrincipal, permission: str) -> None:
        if permission not in principal.permissions:
            raise CorrelationAuthorizationError("missing correlation permission: %s" % permission)

    @staticmethod
    def _sign_incident(unsigned: Mapping[str, object]) -> CorrelatedIncident:
        return CorrelatedIncident(**unsigned, incident_sha256=_digest(unsigned))

    @staticmethod
    def _verify_incident(incident: CorrelatedIncident) -> None:
        unsigned = incident.model_dump(mode="json", exclude={"incident_sha256"})
        if _digest(unsigned) != incident.incident_sha256:
            raise ValueError("correlated incident digest is invalid")

    @staticmethod
    def _sign_decision(unsigned: Mapping[str, object]) -> CorrelationDecision:
        return CorrelationDecision(**unsigned, decision_sha256=_digest(unsigned))

    @staticmethod
    def _verify_decision(decision: CorrelationDecision) -> None:
        unsigned = decision.model_dump(mode="json", exclude={"decision_sha256"})
        if _digest(unsigned) != decision.decision_sha256:
            raise ValueError("correlation decision digest is invalid")

    @staticmethod
    def _sign_suppression(unsigned: Mapping[str, object]) -> SuppressionRule:
        return SuppressionRule(**unsigned, suppression_sha256=_digest(unsigned))

    @staticmethod
    def _verify_suppression(rule: SuppressionRule) -> None:
        unsigned = rule.model_dump(mode="json", exclude={"suppression_sha256"})
        if _digest(unsigned) != rule.suppression_sha256:
            raise ValueError("correlation suppression digest is invalid")

    def _load_incident(self, tenant_id: str, incident_id: str) -> CorrelatedIncident:
        row = self._connection.execute(
            "SELECT incident_json FROM correlated_incidents WHERE tenant_id = ? AND incident_id = ?",
            (tenant_id, incident_id),
        ).fetchone()
        if row is None:
            raise KeyError(incident_id)
        incident = CorrelatedIncident.model_validate_json(row["incident_json"])
        self._verify_incident(incident)
        return incident

    def _store_incident(self, incident: CorrelatedIncident) -> None:
        self._connection.execute(
            "INSERT INTO correlated_incidents(tenant_id, incident_id, incident_json, incident_sha256, status, risk_score, finding_count, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(tenant_id, incident_id) DO UPDATE SET incident_json=excluded.incident_json, incident_sha256=excluded.incident_sha256, status=excluded.status, risk_score=excluded.risk_score, finding_count=excluded.finding_count, updated_at=excluded.updated_at",
            (incident.tenant_id, incident.incident_id, incident.model_dump_json(), incident.incident_sha256, incident.status.value, incident.risk_score, incident.finding_count, incident.created_at.isoformat(), incident.updated_at.isoformat()),
        )

    @staticmethod
    def _rollup(links: Sequence[IncidentFindingLink]) -> Tuple[int, str, str]:
        stages = {item.attack_stage for item in links}
        score = min(100, max(item.risk_score for item in links) + min(20, 5 * (len(links) - 1)) + (10 if len(stages) >= 3 else 0))
        severity = "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 40 else "low"
        priority = "P0" if score >= 90 else "P1" if score >= 70 else "P2" if score >= 40 else "P3"
        return score, severity, priority

    def _build_incident(
        self,
        *,
        incident_id: str,
        tenant_id: str,
        links: Sequence[IncidentFindingLink],
        status: CorrelationIncidentStatus,
        revision: int,
        audit: Sequence[CorrelationAuditEntry],
        created_at: datetime,
        reopened_count: int = 0,
        parent_incident_id: Optional[str] = None,
        superseded_by: Optional[str] = None,
        closed_at: Optional[datetime] = None,
    ) -> CorrelatedIncident:
        ordered = [item.model_copy(update={"sequence_order": index}) for index, item in enumerate(sorted(links, key=lambda item: (item.occurred_at, item.finding_id)), 1)]
        risk, severity, priority = self._rollup(ordered)
        types = list(dict.fromkeys(item.alert_type for item in ordered))
        unsigned = {
            "incident_id": incident_id,
            "tenant_id": tenant_id,
            "title": "Correlated AI-agent activity: " + ", ".join(types[:3]),
            "status": status,
            "severity": severity,
            "priority": priority,
            "risk_score": risk,
            "finding_count": len(ordered),
            "finding_links": ordered,
            "attack_sequence": [AttackSequenceStep(order=item.sequence_order, stage=item.attack_stage, finding_id=item.finding_id, event_id=item.event_id, occurred_at=item.occurred_at, evidence_refs=item.evidence_refs) for item in ordered],
            "entity_refs": sorted({ref for item in ordered for ref in item.entity_refs}),
            "evidence_refs": list(dict.fromkeys(ref for item in ordered for ref in item.evidence_refs))[:2048],
            "reopened_count": reopened_count,
            "parent_incident_id": parent_incident_id,
            "superseded_by": superseded_by,
            "revision": revision,
            "audit": list(audit),
            "created_at": created_at,
            "updated_at": self._now(),
            "closed_at": closed_at,
        }
        return self._sign_incident(CorrelatedIncident.model_construct(**unsigned, incident_sha256="0" * 64).model_dump(mode="json", exclude={"incident_sha256"}))

    @staticmethod
    def _candidate(signal: CorrelationSignal, incident: CorrelatedIncident) -> CorrelationCandidate:
        reasons: List[str] = []
        score = 0
        if any(link.flow_ref == signal.flow_ref for link in incident.finding_links):
            score += 70
            reasons.append("same_flow")
        if signal.agent_ref in incident.entity_refs:
            score += 20
            reasons.append("same_agent")
        overlap = set(signal.entity_refs) & set(incident.entity_refs)
        if overlap:
            delta = min(30, len(overlap) * 10)
            score += delta
            reasons.append("shared_entities:%d" % len(overlap))
        if any(link.alert_type == signal.alert_type for link in incident.finding_links):
            score += 5
            reasons.append("same_alert_family")
        if signal.attack_stage not in {link.attack_stage for link in incident.finding_links}:
            score += 10
            reasons.append("sequence_extension")
        return CorrelationCandidate(incident_id=incident.incident_id, score=min(100, score), reasons=reasons)

    def _active_suppression(self, signal: CorrelationSignal) -> Optional[SuppressionRule]:
        rows = self._connection.execute(
            "SELECT suppression_json FROM correlation_suppressions WHERE tenant_id = ? AND active = 1 AND expires_at > ? ORDER BY expires_at",
            (signal.tenant_id, self._now().isoformat()),
        ).fetchall()
        for row in rows:
            rule = SuppressionRule.model_validate_json(row["suppression_json"])
            self._verify_suppression(rule)
            if rule.alert_type == signal.alert_type and (rule.agent_ref is None or rule.agent_ref == signal.agent_ref):
                return rule
        return None

    def correlate(self, principal: CorrelationPrincipal, result: PipelineResult) -> CorrelationDecision:
        self._require(principal, CORRELATION_WRITE)
        signal = signal_from_result(result)
        if signal.tenant_id != principal.tenant_id:
            raise CorrelationAuthorizationError("cross-tenant correlation is forbidden")
        with self._lock:
            existing = self._connection.execute(
                "SELECT decision_json FROM correlation_decisions WHERE tenant_id = ? AND finding_id = ?",
                (principal.tenant_id, signal.finding_id),
            ).fetchone()
            if existing is not None:
                decision = CorrelationDecision.model_validate_json(existing["decision_json"])
                self._verify_decision(decision)
                return decision
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                suppression = self._active_suppression(signal)
                now = self._now()
                candidates: List[CorrelationCandidate] = []
                incident_id: Optional[str] = None
                outcome = CorrelationOutcome.SUPPRESSED if suppression else CorrelationOutcome.CREATED
                reasons = ["active_suppression"] if suppression else ["no_candidate_met_threshold"]
                if suppression is None:
                    rows = self._connection.execute(
                        "SELECT incident_json FROM correlated_incidents WHERE tenant_id = ? AND status != 'merged' AND updated_at >= ? ORDER BY updated_at DESC LIMIT 200",
                        (principal.tenant_id, (now - REOPEN_WINDOW).isoformat()),
                    ).fetchall()
                    loaded = [CorrelatedIncident.model_validate_json(row["incident_json"]) for row in rows]
                    for incident in loaded:
                        self._verify_incident(incident)
                        if (
                            incident.status != CorrelationIncidentStatus.CLOSED
                            and incident.updated_at < now - CORRELATION_WINDOW
                        ):
                            continue
                        candidate = self._candidate(signal, incident)
                        if candidate.score:
                            candidates.append(candidate)
                    candidates.sort(key=lambda item: (-item.score, item.incident_id))
                    selected = candidates[0] if candidates and candidates[0].score >= ATTACH_THRESHOLD else None
                    if selected is None:
                        incident_id = new_id("inc")
                        link = IncidentFindingLink(**signal.model_dump(exclude={"tenant_id"}), correlation_reasons=["new_incident"], correlation_score=0, sequence_order=1, linked_at=now)
                        incident = self._build_incident(incident_id=incident_id, tenant_id=principal.tenant_id, links=[link], status=CorrelationIncidentStatus.OPEN, revision=1, audit=[CorrelationAuditEntry(action="incident.created", actor_id=principal.actor_id, reason="No existing incident met the correlation threshold.", at=now)], created_at=now)
                        self._store_incident(incident)
                    else:
                        incident = self._load_incident(principal.tenant_id, selected.incident_id)
                        if incident.finding_count >= MAX_INCIDENT_FINDINGS:
                            raise ValueError("correlated incident finding limit reached")
                        outcome = CorrelationOutcome.REOPENED if incident.status == CorrelationIncidentStatus.CLOSED else CorrelationOutcome.ATTACHED
                        reasons = selected.reasons
                        incident_id = incident.incident_id
                        link = IncidentFindingLink(**signal.model_dump(exclude={"tenant_id"}), correlation_reasons=selected.reasons, correlation_score=selected.score, sequence_order=incident.finding_count + 1, linked_at=now)
                        incident = self._build_incident(incident_id=incident.incident_id, tenant_id=incident.tenant_id, links=[*incident.finding_links, link], status=CorrelationIncidentStatus.OPEN if outcome == CorrelationOutcome.REOPENED else incident.status, revision=incident.revision + 1, audit=[*incident.audit, CorrelationAuditEntry(action="incident.reopened" if outcome == CorrelationOutcome.REOPENED else "finding.attached", actor_id=principal.actor_id, reason="Correlation score %d: %s" % (selected.score, ", ".join(selected.reasons)), at=now)], created_at=incident.created_at, reopened_count=incident.reopened_count + int(outcome == CorrelationOutcome.REOPENED), parent_incident_id=incident.parent_incident_id, closed_at=None if outcome == CorrelationOutcome.REOPENED else incident.closed_at)
                        self._store_incident(incident)
                    self._connection.execute(
                        "INSERT INTO incident_finding_links(tenant_id, finding_id, incident_id, link_json, occurred_at) VALUES (?, ?, ?, ?, ?)",
                        (principal.tenant_id, signal.finding_id, incident_id, link.model_dump_json(), signal.occurred_at.isoformat()),
                    )
                unsigned = {
                    "decision_id": new_id("cord"), "tenant_id": principal.tenant_id,
                    "finding_id": signal.finding_id, "outcome": outcome,
                    "incident_id": incident_id,
                    "suppression_id": suppression.suppression_id if suppression else None,
                    "candidates": candidates[:20],
                    "selected_score": (
                        candidates[0].score
                        if outcome in {CorrelationOutcome.ATTACHED, CorrelationOutcome.REOPENED}
                        and candidates
                        else 0
                    ),
                    "reasons": reasons, "decided_at": now,
                }
                decision = self._sign_decision(CorrelationDecision.model_construct(**unsigned, decision_sha256="0" * 64).model_dump(mode="json", exclude={"decision_sha256"}))
                self._connection.execute(
                    "INSERT INTO correlation_decisions(tenant_id, decision_id, finding_id, decision_json, decided_at) VALUES (?, ?, ?, ?, ?)",
                    (principal.tenant_id, decision.decision_id, signal.finding_id, decision.model_dump_json(), now.isoformat()),
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return decision

    def get(self, principal: CorrelationPrincipal, incident_id: str) -> CorrelatedIncident:
        self._require(principal, CORRELATION_READ)
        if re.fullmatch(r"inc_[A-Za-z0-9]+", incident_id) is None:
            raise ValueError("correlated incident ID is invalid")
        with self._lock:
            return self._load_incident(principal.tenant_id, incident_id)

    def list_incidents(self, principal: CorrelationPrincipal, *, status: Optional[CorrelationIncidentStatus] = None, limit: int = 100, offset: int = 0) -> List[CorrelatedIncident]:
        self._require(principal, CORRELATION_READ)
        if not 1 <= limit <= MAX_CORRELATION_PAGE or not 0 <= offset <= 100000:
            raise ValueError("correlated incident pagination is invalid")
        clause = " AND status = ?" if status else ""
        values: List[object] = [principal.tenant_id]
        if status:
            values.append(status.value)
        values.extend([limit, offset])
        with self._lock:
            rows = self._connection.execute("SELECT incident_json FROM correlated_incidents WHERE tenant_id = ?" + clause + " ORDER BY risk_score DESC, updated_at DESC LIMIT ? OFFSET ?", values).fetchall()
        incidents = [CorrelatedIncident.model_validate_json(row["incident_json"]) for row in rows]
        for incident in incidents:
            self._verify_incident(incident)
        return incidents

    def list_decisions(self, principal: CorrelationPrincipal, *, limit: int = 100) -> List[CorrelationDecision]:
        self._require(principal, CORRELATION_READ)
        if not 1 <= limit <= MAX_CORRELATION_PAGE:
            raise ValueError("correlation decision page is invalid")
        with self._lock:
            rows = self._connection.execute("SELECT decision_json FROM correlation_decisions WHERE tenant_id = ? ORDER BY decided_at DESC LIMIT ?", (principal.tenant_id, limit)).fetchall()
        decisions = [CorrelationDecision.model_validate_json(row["decision_json"]) for row in rows]
        for decision in decisions:
            self._verify_decision(decision)
        return decisions

    def transition(self, principal: CorrelationPrincipal, incident_id: str, status: CorrelationIncidentStatus, *, reason: str) -> CorrelatedIncident:
        self._require(principal, CORRELATION_WRITE)
        if status == CorrelationIncidentStatus.MERGED or not 3 <= len(reason.strip()) <= 512:
            raise ValueError("correlated incident transition is invalid")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                current = self._load_incident(principal.tenant_id, incident_id)
                allowed = {
                    CorrelationIncidentStatus.OPEN: {CorrelationIncidentStatus.INVESTIGATING, CorrelationIncidentStatus.CONTAINED, CorrelationIncidentStatus.CLOSED},
                    CorrelationIncidentStatus.INVESTIGATING: {CorrelationIncidentStatus.CONTAINED, CorrelationIncidentStatus.CLOSED},
                    CorrelationIncidentStatus.CONTAINED: {CorrelationIncidentStatus.INVESTIGATING, CorrelationIncidentStatus.CLOSED},
                    CorrelationIncidentStatus.CLOSED: {CorrelationIncidentStatus.OPEN},
                    CorrelationIncidentStatus.MERGED: set(),
                }
                if status == current.status:
                    self._connection.execute("ROLLBACK")
                    return current
                if status not in allowed[current.status]:
                    raise ValueError("invalid correlated incident transition")
                now = self._now()
                updated = self._build_incident(incident_id=current.incident_id, tenant_id=current.tenant_id, links=current.finding_links, status=status, revision=current.revision + 1, audit=[*current.audit, CorrelationAuditEntry(action="incident.%s" % status.value, actor_id=principal.actor_id, reason=reason.strip(), at=now)], created_at=current.created_at, reopened_count=current.reopened_count + int(current.status == CorrelationIncidentStatus.CLOSED and status == CorrelationIncidentStatus.OPEN), parent_incident_id=current.parent_incident_id, closed_at=now if status == CorrelationIncidentStatus.CLOSED else None)
                self._store_incident(updated)
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return updated

    def create_suppression(self, principal: CorrelationPrincipal, *, alert_type: str, reason: str, expires_at: datetime, agent_ref: Optional[str] = None) -> SuppressionRule:
        self._require(principal, CORRELATION_ADMIN)
        now = self._now()
        if expires_at.tzinfo is None or not now < expires_at.astimezone(timezone.utc) <= now + timedelta(days=90):
            raise ValueError("suppression expiry must be within 90 days")
        unsigned = {"suppression_id": new_id("sup"), "tenant_id": principal.tenant_id, "alert_type": alert_type, "agent_ref": agent_ref, "reason": reason.strip(), "created_by": principal.actor_id, "created_at": now, "expires_at": expires_at.astimezone(timezone.utc), "active": True}
        rule = self._sign_suppression(SuppressionRule.model_construct(**unsigned, suppression_sha256="0" * 64).model_dump(mode="json", exclude={"suppression_sha256"}))
        with self._lock:
            self._connection.execute("INSERT INTO correlation_suppressions(tenant_id, suppression_id, suppression_json, active, expires_at) VALUES (?, ?, ?, 1, ?)", (principal.tenant_id, rule.suppression_id, rule.model_dump_json(), rule.expires_at.isoformat()))
        return rule

    def revoke_suppression(self, principal: CorrelationPrincipal, suppression_id: str, *, reason: str) -> SuppressionRule:
        self._require(principal, CORRELATION_ADMIN)
        if not 3 <= len(reason.strip()) <= 512:
            raise ValueError("suppression revocation reason is invalid")
        with self._lock:
            row = self._connection.execute("SELECT suppression_json FROM correlation_suppressions WHERE tenant_id = ? AND suppression_id = ?", (principal.tenant_id, suppression_id)).fetchone()
            if row is None:
                raise KeyError(suppression_id)
            current = SuppressionRule.model_validate_json(row["suppression_json"])
            self._verify_suppression(current)
            if not current.active:
                return current
            unsigned = current.model_dump(mode="json", exclude={"suppression_sha256"})
            unsigned.update({"active": False, "revoked_by": principal.actor_id, "revoked_at": self._now(), "revocation_reason": reason.strip()})
            updated = self._sign_suppression(unsigned)
            self._connection.execute("UPDATE correlation_suppressions SET suppression_json = ?, active = 0 WHERE tenant_id = ? AND suppression_id = ?", (updated.model_dump_json(), principal.tenant_id, suppression_id))
        return updated

    def list_suppressions(self, principal: CorrelationPrincipal) -> List[SuppressionRule]:
        self._require(principal, CORRELATION_READ)
        with self._lock:
            rows = self._connection.execute("SELECT suppression_json FROM correlation_suppressions WHERE tenant_id = ? ORDER BY expires_at DESC LIMIT 200", (principal.tenant_id,)).fetchall()
        result = [SuppressionRule.model_validate_json(row["suppression_json"]) for row in rows]
        for item in result:
            self._verify_suppression(item)
        return result

    def merge(self, principal: CorrelationPrincipal, incident_ids: Sequence[str], *, reason: str) -> CorrelatedIncident:
        self._require(principal, CORRELATION_ADMIN)
        unique = list(dict.fromkeys(incident_ids))
        if not 2 <= len(unique) <= 20 or not 10 <= len(reason.strip()) <= 512:
            raise ValueError("incident merge request is invalid")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                incidents = [self._load_incident(principal.tenant_id, item) for item in unique]
                if any(item.status == CorrelationIncidentStatus.MERGED for item in incidents):
                    raise ValueError("merged incidents cannot be merged again")
                target = min(incidents, key=lambda item: (item.created_at, item.incident_id))
                links = {link.finding_id: link for incident in incidents for link in incident.finding_links}
                if len(links) > MAX_INCIDENT_FINDINGS:
                    raise ValueError("merged incident finding limit reached")
                now = self._now()
                merged = self._build_incident(incident_id=target.incident_id, tenant_id=target.tenant_id, links=list(links.values()), status=CorrelationIncidentStatus.OPEN, revision=target.revision + 1, audit=[*target.audit, CorrelationAuditEntry(action="incident.merge.accept", actor_id=principal.actor_id, reason=reason.strip(), at=now)], created_at=target.created_at, reopened_count=target.reopened_count)
                self._store_incident(merged)
                self._connection.execute("UPDATE incident_finding_links SET incident_id = ? WHERE tenant_id = ? AND incident_id IN (%s)" % ",".join("?" for _ in unique), [target.incident_id, principal.tenant_id, *unique])
                for source in incidents:
                    if source.incident_id == target.incident_id:
                        continue
                    superseded = self._build_incident(incident_id=source.incident_id, tenant_id=source.tenant_id, links=source.finding_links, status=CorrelationIncidentStatus.MERGED, revision=source.revision + 1, audit=[*source.audit, CorrelationAuditEntry(action="incident.merged", actor_id=principal.actor_id, reason=reason.strip(), at=now)], created_at=source.created_at, reopened_count=source.reopened_count, parent_incident_id=source.parent_incident_id, superseded_by=target.incident_id, closed_at=now)
                    self._store_incident(superseded)
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return merged

    def split(self, principal: CorrelationPrincipal, incident_id: str, finding_ids: Sequence[str], *, reason: str) -> Tuple[CorrelatedIncident, CorrelatedIncident]:
        self._require(principal, CORRELATION_ADMIN)
        selected_ids = set(finding_ids)
        if not selected_ids or not 10 <= len(reason.strip()) <= 512:
            raise ValueError("incident split request is invalid")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                source = self._load_incident(principal.tenant_id, incident_id)
                selected = [item for item in source.finding_links if item.finding_id in selected_ids]
                retained = [item for item in source.finding_links if item.finding_id not in selected_ids]
                if len(selected) != len(selected_ids) or not retained:
                    raise ValueError("incident split must select a proper finding subset")
                now = self._now()
                child_id = new_id("inc")
                child = self._build_incident(incident_id=child_id, tenant_id=source.tenant_id, links=selected, status=CorrelationIncidentStatus.OPEN, revision=1, audit=[CorrelationAuditEntry(action="incident.split.created", actor_id=principal.actor_id, reason=reason.strip(), at=now)], created_at=now, parent_incident_id=source.incident_id)
                updated = self._build_incident(incident_id=source.incident_id, tenant_id=source.tenant_id, links=retained, status=source.status, revision=source.revision + 1, audit=[*source.audit, CorrelationAuditEntry(action="incident.split.source", actor_id=principal.actor_id, reason=reason.strip(), at=now)], created_at=source.created_at, reopened_count=source.reopened_count, parent_incident_id=source.parent_incident_id, closed_at=source.closed_at)
                self._store_incident(updated)
                self._store_incident(child)
                self._connection.execute("UPDATE incident_finding_links SET incident_id = ? WHERE tenant_id = ? AND finding_id IN (%s)" % ",".join("?" for _ in selected_ids), [child_id, principal.tenant_id, *sorted(selected_ids)])
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return updated, child

    def health(self, principal: CorrelationPrincipal) -> CorrelationHealth:
        self._require(principal, CORRELATION_READ)
        with self._lock:
            row = self._connection.execute("SELECT COUNT(*) total, SUM(status='open') open_count, SUM(status='closed') closed_count, SUM(status='merged') merged_count, SUM(status != 'merged' AND finding_count > 1) multi FROM correlated_incidents WHERE tenant_id = ?", (principal.tenant_id,)).fetchone()
            findings = self._connection.execute("SELECT COUNT(*) count FROM incident_finding_links WHERE tenant_id = ?", (principal.tenant_id,)).fetchone()
            suppressed = self._connection.execute("SELECT COUNT(*) count FROM correlation_decisions WHERE tenant_id = ? AND json_extract(decision_json, '$.outcome') = 'suppressed'", (principal.tenant_id,)).fetchone()
            suppressions = self._connection.execute("SELECT COUNT(*) count FROM correlation_suppressions WHERE tenant_id = ? AND active = 1 AND expires_at > ?", (principal.tenant_id, self._now().isoformat())).fetchone()
        return CorrelationHealth(tenant_id=principal.tenant_id, total_incidents=int(row["total"] or 0), open_incidents=int(row["open_count"] or 0), closed_incidents=int(row["closed_count"] or 0), merged_incidents=int(row["merged_count"] or 0), total_findings=int(findings["count"] or 0), multi_finding_incidents=int(row["multi"] or 0), suppressed_findings=int(suppressed["count"] or 0), active_suppressions=int(suppressions["count"] or 0), calculated_at=self._now())
