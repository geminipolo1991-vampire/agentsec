"""Bounded, evidence-cited, non-executive AI security analyst orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import sqlite3
import threading
from time import perf_counter
from typing import Any, Callable, Dict, List, Optional, Protocol, Sequence, Set, Tuple

from pydantic import Field, field_validator, model_validator

from .contracts import (
    AiAnalystRun,
    AnalystAlternative,
    AnalystClaim,
    AnalystClaimOperator,
    AnalystDisagreement,
    AnalystDisagreementKind,
    AnalystEvidenceItem,
    AnalystFeedback,
    AnalystFeedbackRating,
    AnalystHealthSummary,
    AnalystRole,
    AnalystRoleRequest,
    AnalystRoleResult,
    AnalystRoleStatus,
    AnalystRunStatus,
    AnalystToolReceipt,
    DecisionAction,
    EnrichmentFactValue,
    ModelVerdict,
    PipelineResult,
    StrictModel,
    new_id,
    utc_now,
)
from .crypto import canonical_bytes
from .enrichment import evidence_ref
from .judgment import EvidenceJudgmentValidator
from .redaction import Redactor


ANALYST_READ = "analyst:read"
ANALYST_RUN = "analyst:run"
ANALYST_FEEDBACK = "analyst:feedback"
ANALYST_ADMIN = "analyst:admin"
ANALYST_POLICY_VERSION = "ai-analyst-2026-07-24.1"
MAX_ANALYST_PAGE = 200
MAX_EVIDENCE_ITEMS = 64

ACTION_RANK = {
    DecisionAction.ALLOW: 0,
    DecisionAction.ALLOW_WITH_OBLIGATIONS: 1,
    DecisionAction.REQUIRE_APPROVAL: 2,
    DecisionAction.DENY: 3,
}

ROLE_OBJECTIVES = {
    AnalystRole.TRIAGE: "Assess urgency, confidence, missing context, and routing from recorded evidence.",
    AnalystRole.INVESTIGATION: "Form and challenge a bounded security hypothesis using recorded evidence.",
    AnalystRole.JUDGE: "Recommend a non-executive action while preserving deterministic authority.",
    AnalystRole.ESCALATION: "Advise human escalation level, queue, and review urgency.",
    AnalystRole.RESPONSE_ADVISOR: "Propose safe reversible response options; do not execute any action.",
}

SAFE_ENRICHMENT_FACTS = {
    "trust_class", "cross_session_memory", "lineage_depth",
    "lineage_trust_classes", "requested_operation", "granted_operations",
    "operation_allowed", "requested_resource_class", "full_scope_allowed",
    "resource_class", "data_classes", "sensitive", "destination_class",
    "external", "drifted", "unknown_agent", "changed_tool_schemas",
    "new_operations", "model_profile_mismatch", "asset_criticality",
    "sdk_phases", "gateway_phases", "integrity_findings", "node_count",
    "edge_count", "path_scope", "flow_event_count", "duplicate_fingerprint",
    "repeated",
}


class AnalystAuthorizationError(PermissionError):
    """Raised when a principal exceeds analyst tenant or role permissions."""


class AnalystPrincipal(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=3, max_length=256)
    permissions: Set[str] = Field(default_factory=set, max_length=8)

    @field_validator("permissions")
    @classmethod
    def valid_permissions(cls, value: Set[str]) -> Set[str]:
        if any(re.fullmatch(r"analyst:[a-z]+", item) is None for item in value):
            raise ValueError("analyst permissions must use analyst:operation")
        return value


class AnalystRoleReasoner(Protocol):
    provider: str
    model_id: str
    recording_id: Optional[str]

    def analyze_role(self, request: AnalystRoleRequest) -> AnalystRoleResult:
        """Return one read-only structured role report."""


class RecordedRoleTemplate(StrictModel):
    summary: str = Field(min_length=10, max_length=1024)
    hypothesis: Optional[str] = Field(default=None, max_length=1024)
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: List[str] = Field(min_length=1, max_length=8)
    uncertainties: List[str] = Field(default_factory=list, max_length=8)
    escalation_advice: Optional[str] = Field(default=None, max_length=256)
    response_advice: List[str] = Field(default_factory=list, max_length=8)
    alternative_title: str = Field(
        default="Preserve deterministic control", min_length=3, max_length=128
    )
    alternative_rationale: str = Field(
        default="Keep the deterministic action while a human reviews the cited evidence.",
        min_length=3,
        max_length=512,
    )


class RecordedAnalystConfiguration(StrictModel):
    schema_version: str = "1.0.0"
    provider: str = "codex"
    model_id: str = Field(min_length=1, max_length=128)
    recording_id: str = Field(min_length=3, max_length=128)
    roles: Dict[str, RecordedRoleTemplate]

    @model_validator(mode="after")
    def complete_roles(self) -> "RecordedAnalystConfiguration":
        if set(self.roles) != {item.value for item in AnalystRole}:
            raise ValueError("recorded analyst configuration must define all five roles")
        return self


class RecordedCodexAnalystReasoner:
    """Replays Codex-authored role playbooks without claiming a live API call."""

    def __init__(self, configuration: RecordedAnalystConfiguration) -> None:
        self.provider = configuration.provider
        self.model_id = configuration.model_id
        self.recording_id: Optional[str] = configuration.recording_id
        self._configuration = configuration

    @classmethod
    def from_path(cls, path: Path) -> "RecordedCodexAnalystReasoner":
        if path.stat().st_size > 1024 * 1024:
            raise ValueError("recorded analyst configuration exceeds the size limit")
        return cls(
            RecordedAnalystConfiguration.model_validate_json(
                path.read_text(encoding="utf-8")
            )
        )

    def analyze_role(self, request: AnalystRoleRequest) -> AnalystRoleResult:
        template = self._configuration.roles[request.role.value]
        diverse = []
        seen_kinds = set()
        for item in request.evidence:
            if item.kind not in seen_kinds:
                diverse.append(item.evidence_id)
                seen_kinds.add(item.kind)
        citations = list(dict.fromkeys(
            diverse + [item.evidence_id for item in request.evidence]
        ))[:8]
        if not citations:
            return AnalystRoleResult(
                role=request.role,
                status=AnalystRoleStatus.ABSTAINED,
                provider=self.provider,
                model_id=self.model_id,
                abstention_reason="No governed evidence was available for this role.",
                uncertainties=["Evidence bundle was empty."],
            )
        action = (
            request.deterministic_action
            if request.role == AnalystRole.JUDGE
            else None
        )
        alternatives = [
            AnalystAlternative(
                title=template.alternative_title,
                rationale=template.alternative_rationale,
                recommended_action=request.deterministic_action,
                evidence_ids=citations[:4],
            ),
            AnalystAlternative(
                title="Request additional human evidence review",
                rationale="Collect independent context before changing policy or containment scope.",
                recommended_action=DecisionAction.REQUIRE_APPROVAL,
                evidence_ids=citations[:4],
            ),
        ][: request.max_alternatives]
        claim_item = next((item for item in request.evidence if item.facts), None)
        claims = []
        if claim_item is not None:
            preferred_keys = (
                "alert_type", "risk_score", "final_action", "level",
                "effect_status", "status", "confidence",
            )
            fact_key = next(
                (key for key in preferred_keys if key in claim_item.facts),
                next(iter(claim_item.facts)),
            )
            claims.append(
                AnalystClaim(
                    statement="The recorded %s fact matches the cited evidence." % fact_key,
                    subject=request.alert_id,
                    fact_key=fact_key,
                    operator=AnalystClaimOperator.EQUALS,
                    expected_value=claim_item.facts[fact_key],
                    evidence_ids=[claim_item.evidence_id],
                )
            )
        return AnalystRoleResult(
            role=request.role,
            status=AnalystRoleStatus.COMPLETED,
            provider=self.provider,
            model_id=self.model_id,
            summary=template.summary.format(
                priority=request.priority,
                deterministic_action=request.deterministic_action.value,
            ),
            hypothesis=(
                template.hypothesis.format(priority=request.priority)
                if template.hypothesis
                else None
            ),
            recommended_action=action,
            escalation_advice=template.escalation_advice,
            response_advice=template.response_advice,
            confidence=template.confidence,
            evidence_ids=citations,
            claims=claims,
            reason_codes=template.reason_codes,
            alternatives=alternatives,
            uncertainties=template.uncertainties,
        )


class BoundedAnalystEvidenceTool:
    """Creates a privacy-safe evidence manifest and a receipt for every role query."""

    version = "analyst-evidence-2026-07-24.1"

    @staticmethod
    def _item(
        namespace: str,
        identity: str,
        *,
        kind: str,
        source: str,
        observed_at: datetime,
        facts: Dict[str, EnrichmentFactValue],
    ) -> AnalystEvidenceItem:
        return AnalystEvidenceItem(
            evidence_id=evidence_ref(namespace, identity),
            kind=kind,
            source=source,
            observed_at=observed_at,
            facts=facts,
        )

    def manifest(
        self,
        result: PipelineResult,
    ) -> List[AnalystEvidenceItem]:
        alert = result.alert
        enrichment = result.enrichment
        triage = result.triage
        items = [
            self._item(
                "analyst-alert",
                alert.alert_id,
                kind="detector",
                source=alert.detector_id,
                observed_at=alert.detected_at,
                facts={
                    "alert_type": alert.alert_type,
                    "severity": alert.severity.value,
                    "confidence": alert.confidence,
                    "operation": alert.operation,
                    "recommended_action": alert.recommended_action.value,
                    "reason_codes": list(alert.reason_codes),
                },
            ),
            self._item(
                "analyst-triage",
                triage.alert_id,
                kind="triage",
                source=triage.score_version,
                observed_at=triage.assessed_at,
                facts={
                    "risk_score": triage.risk_score,
                    "priority": triage.priority,
                    "route": triage.route,
                    "sla_minutes": triage.sla_minutes,
                    "missing_context_warnings": list(triage.missing_context_warnings),
                },
            ),
        ]
        for index, raw in enumerate(alert.evidence[:16], start=1):
            items.append(
                self._item(
                    "detector-evidence",
                    raw,
                    kind="detector_evidence",
                    source=alert.detector_id,
                    observed_at=alert.detected_at,
                    facts={"ordinal": index, "alert_type": alert.alert_type},
                )
            )
        for source in enrichment.sources[:32]:
            safe_facts: Dict[str, EnrichmentFactValue] = {
                "status": source.status.value,
                "confidence": source.confidence,
                "affects_triage": source.affects_triage,
                "cache_status": source.cache_status.value,
                "policy_decision": source.policy_decision,
            }
            safe_facts.update(
                {
                    key: value
                    for key, value in source.facts.items()
                    if key in SAFE_ENRICHMENT_FACTS
                }
            )
            items.append(
                self._item(
                    "enrichment-evidence",
                    "%s:%s" % (enrichment.snapshot_id, source.source),
                    kind="enrichment",
                    source=source.source,
                    observed_at=source.observed_at,
                    facts=safe_facts,
                )
            )
        for index, contribution in enumerate(triage.contributions[:24], start=1):
            items.append(
                self._item(
                    "triage-contribution",
                    "%s:%s:%d" % (triage.alert_id, contribution.category, index),
                    kind="risk_contribution",
                    source=triage.score_version,
                    observed_at=triage.assessed_at,
                    facts={
                        "category": contribution.category,
                        "label": contribution.label,
                        "delta": contribution.delta,
                        "rationale": contribution.rationale,
                    },
                )
            )
        items.extend(
            [
                self._item(
                    "analyst-ingestion",
                    "%s:%d" % (alert.alert_id, result.ingestion.sequence),
                    kind="ingestion",
                    source="evidence-ledger",
                    observed_at=result.ingestion.ingested_at,
                    facts={
                        "sequence": result.ingestion.sequence,
                        "duplicate": result.ingestion.duplicate,
                        "ledger_verified": result.ledger_verified,
                    },
                ),
                self._item(
                    "analyst-judgment",
                    "%s:%s" % (alert.alert_id, result.judgment.policy_version),
                    kind="judgment",
                    source=result.judgment.policy_version,
                    observed_at=result.judgment.judged_at,
                    facts={
                        "deterministic_action": result.judgment.deterministic_action.value,
                        "final_action": result.judgment.action.value,
                        "model_status": result.judgment.model_status,
                        "combiner_result": result.judgment.combiner_result,
                    },
                ),
                self._item(
                    "analyst-escalation",
                    "%s:%s" % (alert.alert_id, result.escalation.level.value),
                    kind="escalation",
                    source="deterministic-escalator",
                    observed_at=result.escalation.escalated_at,
                    facts={
                        "level": result.escalation.level.value,
                        "queue": result.escalation.queue or "none",
                        "case_created": bool(result.escalation.case_id),
                    },
                ),
                self._item(
                    "analyst-response",
                    "%s:%s" % (alert.alert_id, result.response.effect_status.value),
                    kind="response",
                    source=result.response.responder,
                    observed_at=result.response.responded_at,
                    facts={
                        "actions": [item.value for item in result.response.actions],
                        "effect_status": result.response.effect_status.value,
                        "effect_allowed": result.response.effect_allowed,
                        "simulated": result.response.simulated,
                    },
                ),
            ]
        )
        deduplicated = {item.evidence_id: item for item in items}
        return list(deduplicated.values())[:MAX_EVIDENCE_ITEMS]

    def query(
        self,
        *,
        run_id: str,
        role: AnalystRole,
        manifest: Sequence[AnalystEvidenceItem],
    ) -> Tuple[List[AnalystEvidenceItem], AnalystToolReceipt]:
        requested = {
            AnalystRole.TRIAGE: {"detector", "ingestion", "triage", "risk_contribution", "enrichment"},
            AnalystRole.INVESTIGATION: {"detector", "detector_evidence", "ingestion", "triage", "risk_contribution", "enrichment", "judgment", "escalation", "response"},
            AnalystRole.JUDGE: {"detector", "detector_evidence", "triage", "risk_contribution", "enrichment", "judgment"},
            AnalystRole.ESCALATION: {"detector", "triage", "risk_contribution", "judgment", "escalation"},
            AnalystRole.RESPONSE_ADVISOR: {"detector", "triage", "risk_contribution", "enrichment", "judgment", "escalation", "response"},
        }[role]
        returned = [item for item in manifest if item.kind in requested][:MAX_EVIDENCE_ITEMS]
        receipt_id = new_id("ait")
        queried_at = utc_now()
        payload = {
            "receipt_id": receipt_id,
            "run_id": run_id,
            "role": role.value,
            "tool": "evidence.query",
            "requested_kinds": sorted(requested),
            "returned_evidence_ids": [item.evidence_id for item in returned],
            "result_count": len(returned),
            "queried_at": queried_at,
        }
        unsigned = AnalystToolReceipt(**payload, receipt_sha256="0" * 64)
        digest_payload = unsigned.model_dump(mode="json", exclude={"receipt_sha256"})
        receipt = unsigned.model_copy(
            update={
                "receipt_sha256": hashlib.sha256(
                    canonical_bytes(digest_payload)
                ).hexdigest()
            }
        )
        return returned, receipt


class AiAnalystService:
    """Durable five-role orchestration with evidence receipts and inert feedback."""

    def __init__(
        self,
        path: str,
        *,
        reasoner: AnalystRoleReasoner,
        evidence_tool: Optional[BoundedAnalystEvidenceTool] = None,
        role_timeout_seconds: float = 5.0,
        clock: Callable[[], datetime] = utc_now,
        redactor: Optional[Redactor] = None,
        judgment_validator: Optional[EvidenceJudgmentValidator] = None,
    ) -> None:
        if not 0.01 <= role_timeout_seconds <= 30.0:
            raise ValueError("analyst role timeout must be between 0.01 and 30 seconds")
        self.path = path
        self.reasoner = reasoner
        self.evidence_tool = evidence_tool or BoundedAnalystEvidenceTool()
        self.role_timeout_seconds = role_timeout_seconds
        self.clock = clock
        self.redactor = redactor or Redactor()
        self.judgment_validator = judgment_validator or EvidenceJudgmentValidator()
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="agentsec-analyst")
        self._connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS analyst_runs (
                tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, alert_id TEXT NOT NULL,
                finding_id TEXT NOT NULL, status TEXT NOT NULL, run_json TEXT NOT NULL,
                run_sha256 TEXT NOT NULL, completed_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, run_id), UNIQUE (tenant_id, alert_id)
            );
            CREATE INDEX IF NOT EXISTS analyst_run_time
                ON analyst_runs(tenant_id, completed_at DESC, run_id);
            CREATE TABLE IF NOT EXISTS analyst_feedback (
                tenant_id TEXT NOT NULL, feedback_id TEXT NOT NULL, run_id TEXT NOT NULL,
                feedback_json TEXT NOT NULL, feedback_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL, PRIMARY KEY (tenant_id, feedback_id),
                FOREIGN KEY (tenant_id, run_id) REFERENCES analyst_runs(tenant_id, run_id)
            );
            CREATE INDEX IF NOT EXISTS analyst_feedback_run
                ON analyst_feedback(tenant_id, run_id, created_at);
            """
        )

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
        with self._lock:
            self._connection.close()

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("analyst clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _require(principal: AnalystPrincipal, permission: str) -> None:
        if permission not in principal.permissions:
            raise AnalystAuthorizationError("missing analyst permission: %s" % permission)

    @staticmethod
    def _run_digest(run: AiAnalystRun) -> str:
        payload = run.model_dump(mode="json", exclude={"run_sha256"})
        return hashlib.sha256(canonical_bytes(payload)).hexdigest()

    @staticmethod
    def _feedback_digest(feedback: AnalystFeedback) -> str:
        payload = feedback.model_dump(mode="json", exclude={"feedback_sha256"})
        return hashlib.sha256(canonical_bytes(payload)).hexdigest()

    def _verify_run(self, run: AiAnalystRun) -> None:
        self.judgment_validator.verify(run.validation)
        if self._run_digest(run) != run.run_sha256:
            raise ValueError("analyst run integrity verification failed")
        self.judgment_validator.verify(run.validation)

    def _verify_feedback(self, feedback: AnalystFeedback) -> None:
        if self._feedback_digest(feedback) != feedback.feedback_sha256:
            raise ValueError("analyst feedback integrity verification failed")

    @staticmethod
    def _unavailable(role: AnalystRole, provider: str, model_id: str, latency_ms: int) -> AnalystRoleResult:
        return AnalystRoleResult(
            role=role,
            status=AnalystRoleStatus.UNAVAILABLE,
            provider=provider,
            model_id=model_id,
            abstention_reason="Role analysis was unavailable within its governed bound.",
            uncertainties=["No model conclusion was accepted for this role."],
            latency_ms=latency_ms,
        )

    def _validate_result(
        self,
        request: AnalystRoleRequest,
        result: AnalystRoleResult,
    ) -> AnalystRoleResult:
        if result.role != request.role:
            raise ValueError("analyst result role does not match request")
        identity_validator = getattr(self.reasoner, "accepts_identity", None)
        identity_valid = (
            bool(identity_validator(result.provider, result.model_id))
            if callable(identity_validator)
            else result.provider == self.reasoner.provider
            and result.model_id == self.reasoner.model_id
        )
        if not identity_valid:
            raise ValueError("analyst result provider identity does not match the configured reasoner")
        allowed = {item.evidence_id for item in request.evidence}
        cited = set(result.evidence_ids)
        cited.update(
            evidence_id
            for alternative in result.alternatives
            for evidence_id in alternative.evidence_ids
        )
        cited.update(
            evidence_id
            for claim in result.claims
            for evidence_id in claim.evidence_ids
        )
        if cited - allowed:
            raise ValueError("analyst role cited evidence outside its tool result")
        return result

    def _redact_result(self, result: AnalystRoleResult) -> AnalystRoleResult:
        """Redact provider-authored prose before it can enter durable/UI records."""
        prose = {
            "summary": result.summary,
            "hypothesis": result.hypothesis,
            "escalation_advice": result.escalation_advice,
            "response_advice": result.response_advice,
            "uncertainties": result.uncertainties,
            "abstention_reason": result.abstention_reason,
            "alternatives": [
                {
                    "title": item.title,
                    "rationale": item.rationale,
                    "recommended_action": item.recommended_action,
                    "evidence_ids": item.evidence_ids,
                }
                for item in result.alternatives
            ],
            "claims": [item.model_dump(mode="python") for item in result.claims],
        }
        safe = self.redactor.redact(prose).value
        return AnalystRoleResult.model_validate(
            {**result.model_dump(mode="python"), **safe}
        )

    def _execute_role(self, request: AnalystRoleRequest) -> AnalystRoleResult:
        started = perf_counter()
        future = self._executor.submit(self.reasoner.analyze_role, request)
        try:
            result = future.result(timeout=self.role_timeout_seconds)
            result = self._validate_result(request, result)
            result = self._redact_result(result)
            latency = max(0, round((perf_counter() - started) * 1000))
            return result.model_copy(update={"latency_ms": latency, "completed_at": self._now()})
        except Exception:
            future.cancel()
            latency = max(0, round((perf_counter() - started) * 1000))
            return self._unavailable(
                request.role, self.reasoner.provider, self.reasoner.model_id, latency
            )

    @staticmethod
    def _disagreements(
        deterministic: DecisionAction, results: Sequence[AnalystRoleResult]
    ) -> List[AnalystDisagreement]:
        disagreements: List[AnalystDisagreement] = []
        judge = next(item for item in results if item.role == AnalystRole.JUDGE)
        if judge.status != AnalystRoleStatus.COMPLETED:
            kind = (
                AnalystDisagreementKind.ABSTENTION
                if judge.status == AnalystRoleStatus.ABSTAINED
                else AnalystDisagreementKind.ROLE_UNAVAILABLE
            )
            disagreements.append(
                AnalystDisagreement(
                    kind=kind,
                    left="deterministic_policy",
                    right="ai_judge",
                    left_action=deterministic,
                    rationale="The AI judge produced no accepted action recommendation.",
                    evidence_ids=judge.evidence_ids[:16],
                )
            )
        elif judge.recommended_action is not None and judge.recommended_action != deterministic:
            kind = (
                AnalystDisagreementKind.TIGHTENING_PROPOSED
                if ACTION_RANK[judge.recommended_action] > ACTION_RANK[deterministic]
                else AnalystDisagreementKind.RELAXATION_REJECTED
            )
            disagreements.append(
                AnalystDisagreement(
                    kind=kind,
                    left="deterministic_policy",
                    right="ai_judge",
                    left_action=deterministic,
                    right_action=judge.recommended_action,
                    rationale="The recorded AI judge action differs from deterministic policy.",
                    evidence_ids=judge.evidence_ids[:16],
                )
            )
        actions = {
            item.recommended_action
            for item in results
            if item.status == AnalystRoleStatus.COMPLETED
            and item.recommended_action is not None
        }
        if len(actions) > 1:
            disagreements.append(
                AnalystDisagreement(
                    kind=AnalystDisagreementKind.CROSS_ROLE_CONFLICT,
                    left="ai_roles",
                    right="ai_roles",
                    rationale="Completed analyst roles proposed different advisory actions.",
                    evidence_ids=list(dict.fromkeys(
                        evidence for item in results for evidence in item.evidence_ids
                    ))[:16],
                )
            )
        for item in results:
            if item.role == AnalystRole.JUDGE or item.status == AnalystRoleStatus.COMPLETED:
                continue
            disagreements.append(
                AnalystDisagreement(
                    kind=(
                        AnalystDisagreementKind.ABSTENTION
                        if item.status == AnalystRoleStatus.ABSTAINED
                        else AnalystDisagreementKind.ROLE_UNAVAILABLE
                    ),
                    left="governed_role_sequence",
                    right=item.role.value,
                    rationale="A governed analyst role did not produce a completed report.",
                    evidence_ids=item.evidence_ids[:16],
                )
            )
        return disagreements

    def analyze(
        self,
        principal: AnalystPrincipal,
        result: PipelineResult,
    ) -> AiAnalystRun:
        self._require(principal, ANALYST_RUN)
        if result.event.tenant_id != principal.tenant_id:
            raise AnalystAuthorizationError("cross-tenant analyst execution is forbidden")
        alert = result.alert
        finding_id = result.finding.finding_id
        triage = result.triage
        deterministic_action = result.judgment.action
        with self._lock:
            existing = self._connection.execute(
                "SELECT run_json FROM analyst_runs WHERE tenant_id = ? AND alert_id = ?",
                (principal.tenant_id, alert.alert_id),
            ).fetchone()
            if existing is not None:
                run = AiAnalystRun.model_validate_json(existing["run_json"])
                self._verify_run(run)
                return run

            started_at = self._now()
            run_id = new_id("air")
            manifest = self.evidence_tool.manifest(result)
            manifest_payload = [item.model_dump(mode="json") for item in manifest]
            manifest_sha = hashlib.sha256(canonical_bytes(manifest_payload)).hexdigest()
            results: List[AnalystRoleResult] = []
            receipts: List[AnalystToolReceipt] = []
            prior: List[str] = []
            for role in AnalystRole:
                evidence, receipt = self.evidence_tool.query(
                    run_id=run_id, role=role, manifest=manifest
                )
                receipts.append(receipt)
                request = AnalystRoleRequest(
                    run_id=run_id,
                    role=role,
                    alert_id=alert.alert_id,
                    objective=ROLE_OBJECTIVES[role],
                    deterministic_action=deterministic_action,
                    priority=triage.priority,
                    evidence=evidence,
                    prior_role_summaries=prior[-4:],
                    requested_at=self._now(),
                )
                result = self._execute_role(request)
                results.append(result)
                if result.status == AnalystRoleStatus.COMPLETED and result.summary:
                    prior.append(result.summary)
            disagreements = self._disagreements(deterministic_action, results)
            judge = next(item for item in results if item.role == AnalystRole.JUDGE)
            judge_advisory = (
                judge.recommended_action
                if judge.status == AnalystRoleStatus.COMPLETED
                and judge.recommended_action is not None
                else deterministic_action
            )
            advisory = max(
                (deterministic_action, judge_advisory),
                key=lambda action: ACTION_RANK[action],
            )
            completed = sum(item.status == AnalystRoleStatus.COMPLETED for item in results)
            abstained = sum(item.status == AnalystRoleStatus.ABSTAINED for item in results)
            status = (
                AnalystRunStatus.COMPLETED
                if completed == len(AnalystRole)
                else AnalystRunStatus.ABSTAINED
                if abstained == len(AnalystRole)
                else AnalystRunStatus.PARTIAL
            )
            validation = self.judgment_validator.validate(
                manifest=manifest,
                role_results=results,
                deterministic_action=deterministic_action,
                priority=triage.priority,
            )
            run_fields: Dict[str, Any] = {
                "run_id": run_id,
                "tenant_id": principal.tenant_id,
                "alert_id": alert.alert_id,
                "finding_id": finding_id,
                "status": status,
                "provider": self.reasoner.provider,
                "model_id": self.reasoner.model_id,
                "recording_id": getattr(self.reasoner, "recording_id", None),
                "policy_version": ANALYST_POLICY_VERSION,
                "deterministic_action": deterministic_action,
                "advisory_action": advisory,
                "human_review_required": (
                    bool(disagreements)
                    or triage.priority in {"P0", "P1"}
                    or validation.human_gate_required
                ),
                "role_results": results,
                "tool_receipts": receipts,
                "disagreements": disagreements,
                "validation": validation,
                "evidence_manifest_sha256": manifest_sha,
                "started_at": started_at,
                "completed_at": self._now(),
            }
            digest_payload = AiAnalystRun(
                **run_fields,
                run_sha256="0" * 64,
            ).model_dump(mode="json", exclude={"run_sha256"})
            run = AiAnalystRun(
                **run_fields,
                run_sha256=hashlib.sha256(canonical_bytes(digest_payload)).hexdigest(),
            )
            self._connection.execute(
                "INSERT INTO analyst_runs(tenant_id, run_id, alert_id, finding_id, status, run_json, run_sha256, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    principal.tenant_id, run.run_id, run.alert_id, run.finding_id,
                    run.status.value, run.model_dump_json(), run.run_sha256,
                    run.completed_at.isoformat(),
                ),
            )
            return run

    def get(self, principal: AnalystPrincipal, run_id: str) -> AiAnalystRun:
        self._require(principal, ANALYST_READ)
        with self._lock:
            row = self._connection.execute(
                "SELECT run_json FROM analyst_runs WHERE tenant_id = ? AND run_id = ?",
                (principal.tenant_id, run_id),
            ).fetchone()
        if row is None:
            raise KeyError(run_id)
        run = AiAnalystRun.model_validate_json(row["run_json"])
        self._verify_run(run)
        return run

    def get_run(self, principal: AnalystPrincipal, run_id: str) -> AiAnalystRun:
        return self.get(principal, run_id)

    def get_for_finding(
        self, principal: AnalystPrincipal, finding_id: str
    ) -> AiAnalystRun:
        self._require(principal, ANALYST_READ)
        with self._lock:
            row = self._connection.execute(
                "SELECT run_json FROM analyst_runs WHERE tenant_id = ? AND finding_id = ? ORDER BY completed_at DESC LIMIT 1",
                (principal.tenant_id, finding_id),
            ).fetchone()
        if row is None:
            raise KeyError(finding_id)
        run = AiAnalystRun.model_validate_json(row["run_json"])
        self._verify_run(run)
        return run

    def list_runs(
        self, principal: AnalystPrincipal, *, limit: int = 100, offset: int = 0
    ) -> List[AiAnalystRun]:
        self._require(principal, ANALYST_READ)
        if not 1 <= limit <= MAX_ANALYST_PAGE or not 0 <= offset <= 100000:
            raise ValueError("analyst run pagination is invalid")
        with self._lock:
            rows = self._connection.execute(
                "SELECT run_json FROM analyst_runs WHERE tenant_id = ? ORDER BY completed_at DESC, run_id LIMIT ? OFFSET ?",
                (principal.tenant_id, limit, offset),
            ).fetchall()
        result = [AiAnalystRun.model_validate_json(row["run_json"]) for row in rows]
        for run in result:
            self._verify_run(run)
        return result

    def record_feedback(
        self,
        principal: AnalystPrincipal,
        run_id: str,
        *,
        rating: AnalystFeedbackRating,
        reason: str,
        role: Optional[AnalystRole] = None,
    ) -> AnalystFeedback:
        self._require(principal, ANALYST_FEEDBACK)
        self.get(
            principal.model_copy(update={"permissions": set(principal.permissions) | {ANALYST_READ}}),
            run_id,
        )
        fields = {
            "tenant_id": principal.tenant_id,
            "run_id": run_id,
            "actor_id": principal.actor_id,
            "rating": rating,
            "role": role,
            "reason": str(self.redactor.redact(reason).value),
            "created_at": self._now(),
        }
        unsigned = AnalystFeedback(**fields, feedback_sha256="0" * 64)
        feedback = unsigned.model_copy(
            update={"feedback_sha256": self._feedback_digest(unsigned)}
        )
        with self._lock:
            self._connection.execute(
                "INSERT INTO analyst_feedback(tenant_id, feedback_id, run_id, feedback_json, feedback_sha256, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    principal.tenant_id, feedback.feedback_id, run_id,
                    feedback.model_dump_json(), feedback.feedback_sha256,
                    feedback.created_at.isoformat(),
                ),
            )
        return feedback

    def add_feedback(
        self,
        principal: AnalystPrincipal,
        run_id: str,
        *,
        rating: AnalystFeedbackRating,
        reason: str,
        role: Optional[AnalystRole] = None,
    ) -> AnalystFeedback:
        return self.record_feedback(
            principal, run_id, rating=rating, reason=reason, role=role
        )

    def list_feedback(
        self, principal: AnalystPrincipal, *, run_id: Optional[str] = None
    ) -> List[AnalystFeedback]:
        self._require(principal, ANALYST_READ)
        clause = " AND run_id = ?" if run_id else ""
        values: List[Any] = [principal.tenant_id]
        if run_id:
            values.append(run_id)
        with self._lock:
            rows = self._connection.execute(
                "SELECT feedback_json FROM analyst_feedback WHERE tenant_id = ?"
                + clause + " ORDER BY created_at DESC, feedback_id LIMIT 200",
                values,
            ).fetchall()
        feedback = [
            AnalystFeedback.model_validate_json(row["feedback_json"]) for row in rows
        ]
        for item in feedback:
            self._verify_feedback(item)
        return feedback

    def health(self, principal: AnalystPrincipal) -> AnalystHealthSummary:
        self._require(principal, ANALYST_READ)
        with self._lock:
            run_rows = self._connection.execute(
                "SELECT run_json FROM analyst_runs WHERE tenant_id = ?",
                (principal.tenant_id,),
            ).fetchall()
            feedback_row = self._connection.execute(
                "SELECT COUNT(*) AS total FROM analyst_feedback WHERE tenant_id = ?",
                (principal.tenant_id,),
            ).fetchone()
        runs = [AiAnalystRun.model_validate_json(row["run_json"]) for row in run_rows]
        for run in runs:
            self._verify_run(run)
        roles = [result for run in runs for result in run.role_results]
        return AnalystHealthSummary(
            tenant_id=principal.tenant_id,
            total_runs=len(runs),
            completed_runs=sum(run.status == AnalystRunStatus.COMPLETED for run in runs),
            partial_runs=sum(run.status == AnalystRunStatus.PARTIAL for run in runs),
            abstained_roles=sum(item.status == AnalystRoleStatus.ABSTAINED for item in roles),
            unavailable_roles=sum(item.status == AnalystRoleStatus.UNAVAILABLE for item in roles),
            disagreements=sum(len(run.disagreements) for run in runs),
            feedback_records=int(feedback_row["total"]),
            calculated_at=self._now(),
        )

    @staticmethod
    def model_verdict(run: AiAnalystRun) -> Optional[ModelVerdict]:
        judge = next(item for item in run.role_results if item.role == AnalystRole.JUDGE)
        if (
            judge.status != AnalystRoleStatus.COMPLETED
            or judge.recommended_action is None
            or judge.confidence is None
        ):
            return None
        return ModelVerdict(
            provider=run.provider,
            model_id=run.model_id,
            action=judge.recommended_action,
            confidence=judge.confidence,
            evidence_ids=judge.evidence_ids,
            reason_codes=list(dict.fromkeys(["AI_ANALYST_JUDGE", *judge.reason_codes])),
            uncertainty="; ".join(judge.uncertainties) or None,
        )


def analyst_service_from_recording(
    database_path: str,
    recording_path: str,
    *,
    tenant_id: str,
) -> Tuple[AiAnalystService, AnalystPrincipal]:
    reasoner = RecordedCodexAnalystReasoner.from_path(Path(recording_path))
    principal = AnalystPrincipal(
        tenant_id=tenant_id,
        actor_id="system://local-ai-analyst",
        permissions={ANALYST_READ, ANALYST_RUN, ANALYST_FEEDBACK, ANALYST_ADMIN},
    )
    return AiAnalystService(database_path, reasoner=reasoner), principal


__all__ = [
    "ANALYST_ADMIN", "ANALYST_FEEDBACK", "ANALYST_READ", "ANALYST_RUN",
    "ANALYST_POLICY_VERSION", "AiAnalystService", "AnalystAuthorizationError",
    "AnalystPrincipal", "AnalystRoleReasoner", "BoundedAnalystEvidenceTool",
    "RecordedAnalystConfiguration", "RecordedCodexAnalystReasoner",
    "analyst_service_from_recording",
]
