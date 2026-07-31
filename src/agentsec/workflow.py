"""Triage, judgment, escalation, and safe response components."""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional

from .contracts import (
    AiMode,
    DecisionAction,
    EffectStatus,
    EnrichmentResult,
    EnrichmentSnapshot,
    EnrichmentStatus,
    EscalationLevel,
    EscalationRecord,
    Judgment,
    ModelVerdict,
    ResponseAction,
    ResponseRecord,
    RiskContribution,
    SecurityAlert,
    Severity,
    TriageAssessment,
    new_id,
)
from .enrichment import evidence_ref
from .judgment import EvidenceJudgmentValidator

if TYPE_CHECKING:
    from .behavior import BehaviorEventAssessment


SEVERITY_SCORE: Dict[Severity, int] = {
    Severity.INFO: 10,
    Severity.LOW: 25,
    Severity.MEDIUM: 50,
    Severity.HIGH: 75,
    Severity.CRITICAL: 95,
}

TRIAGE_SCORE_VERSION = "triage-2026-07-24.3"

ACTION_RANK: Dict[DecisionAction, int] = {
    DecisionAction.ALLOW: 0,
    DecisionAction.ALLOW_WITH_OBLIGATIONS: 1,
    DecisionAction.REQUIRE_APPROVAL: 2,
    DecisionAction.DENY: 3,
}


class Triager:
    @staticmethod
    def _source(enrichment: EnrichmentSnapshot, name: str):
        return next(item for item in enrichment.sources if item.source == name)

    def assess(
        self,
        alert: SecurityAlert,
        enrichment: Optional[EnrichmentSnapshot] = None,
        *,
        behavior: Optional["BehaviorEventAssessment"] = None,
        behavior_unavailable: bool = False,
    ) -> TriageAssessment:
        if enrichment is None:
            enrichment = self._compatibility_snapshot(alert)
        contributions: List[RiskContribution] = []

        def add(category: str, label: str, delta: int, refs: List[str], rationale: str) -> None:
            contributions.append(
                RiskContribution(
                    category=category,
                    label=label,
                    delta=delta,
                    evidence_refs=refs or [evidence_ref("alert", alert.alert_id)],
                    rationale=rationale,
                )
            )

        add(
            "base_severity",
            "Base %s severity" % alert.severity.value,
            SEVERITY_SCORE[alert.severity],
            [evidence_ref("detector", alert.detector_id)],
            "The detector's versioned base severity establishes the initial score.",
        )
        if alert.confidence >= 0.95:
            add(
                "detector_confidence",
                "High-confidence detector",
                3,
                [evidence_ref("alert", alert.alert_id)],
                "Detector confidence met or exceeded 0.95.",
            )

        provenance = self._source(enrichment, "provenance")
        if provenance.facts.get("trust_class") in {
            "external-untrusted",
            "suspected-adversarial",
            "unknown",
        }:
            add(
                "source_trust",
                "Untrusted or unknown provenance",
                2,
                provenance.evidence_refs,
                "Conservative provenance labels survive agent and memory transforms.",
            )
        if provenance.facts.get("cross_session_memory"):
            add(
                "persistent_influence",
                "Persistent or cross-session influence",
                5,
                provenance.evidence_refs,
                "The action was influenced by persisted memory context.",
            )

        data = self._source(enrichment, "data_classification")
        if data.facts.get("sensitive") is True:
            add(
                "sensitive_data_exposure",
                "Sensitive data exposure",
                10,
                data.evidence_refs,
                "Sensitive-class material is involved in the proposed effect.",
            )

        destination = self._source(enrichment, "destination_classification")
        if destination.facts.get("external") is True:
            add(
                "external_destination",
                "External destination",
                5,
                destination.evidence_refs,
                "The effect targets an external network destination.",
            )

        authority = self._source(enrichment, "effective_authority")
        if authority.facts.get("operation_allowed") is False or authority.facts.get(
            "full_scope_allowed"
        ) is False:
            add(
                "authority_scope_difference",
                "Requested authority exceeds effective grant",
                10,
                authority.evidence_refs,
                "Requested operation or scope is not contained by the effective grant.",
            )

        if alert.operation in {"data.delete", "host.isolate", "identity.revoke"}:
            add(
                "destructive_operation",
                "Destructive operation",
                8,
                [evidence_ref("event", alert.event_id)],
                "The requested operation has destructive or containment impact.",
            )

        abom = self._source(enrichment, "abom_tool_drift")
        if abom.facts.get("drifted") is True:
            add(
                "tool_drift",
                "Approved and observed tool contract differ",
                8,
                abom.evidence_refs,
                "ABOM or event-level schema comparison recorded tool drift.",
            )

        profile = self._source(enrichment, "agent_model_profile")
        if profile.facts.get("model_profile_mismatch") is True:
            add(
                "model_profile_drift",
                "Observed model profile differs from approval",
                5,
                profile.evidence_refs,
                "The observed model profile did not match the approved profile.",
            )
        if profile.facts.get("asset_criticality") in {"high", "critical"}:
            add(
                "asset_criticality",
                "High-criticality asset",
                5,
                profile.evidence_refs,
                "The affected asset is classified high or critical.",
            )

        repeats = self._source(enrichment, "repeat_frequency")
        if repeats.facts.get("repeated") is True:
            add(
                "repeat_frequency",
                "Repeated event in the same flow",
                5,
                repeats.evidence_refs,
                "Repeated alert activity raises urgency without changing authorization.",
            )

        observations = self._source(enrichment, "independent_observations")
        if observations.facts.get("integrity_findings"):
            add(
                "observation_difference",
                "SDK and gateway observations disagree",
                10,
                observations.evidence_refs,
                "Independent effect observations produced integrity findings.",
            )

        if behavior is not None and behavior.is_anomaly:
            behavior_delta = min(
                20, max(5, round(behavior.composite_risk_score * 0.2))
            )
            refs = [
                evidence_ref("behavior-assessment", behavior.assessment_id),
                *[
                    reference
                    for factor in behavior.factors[:8]
                    for reference in factor.evidence_refs[:2]
                ],
            ]
            add(
                "behavioral_anomaly",
                "Behavior deviates from accepted entity baselines",
                behavior_delta,
                list(dict.fromkeys(refs))[:16],
                "The pre-update behavioral assessment recorded an explainable anomaly and composite risk.",
            )
        elif behavior_unavailable:
            add(
                "behavioral_context_unavailable",
                "Behavioral analytics unavailable",
                5,
                [evidence_ref("alert", alert.alert_id)],
                "Missing behavioral context raises risk and cannot suppress deterministic enforcement.",
            )

        missing = [
            item
            for item in enrichment.sources
            if item.source
            in {
                "provenance",
                "effective_authority",
                "data_classification",
                "destination_classification",
            }
            and item.status in {EnrichmentStatus.UNAVAILABLE, EnrichmentStatus.FAILED}
        ]
        if missing:
            add(
                "missing_mandatory_context",
                "Mandatory context unavailable",
                5,
                [reference for item in missing for reference in item.evidence_refs],
                "Missing mandatory evidence increases risk and can never relax enforcement.",
            )

        raw_score = sum(item.delta for item in contributions)
        if raw_score > 100:
            add(
                "score_ceiling",
                "Bound score to 100",
                100 - raw_score,
                [evidence_ref("policy", TRIAGE_SCORE_VERSION)],
                "The versioned scoring policy caps risk at 100.",
            )
        score = sum(item.delta for item in contributions)
        if score >= 90:
            priority = "P0"
        elif score >= 70:
            priority = "P1"
        elif score >= 40:
            priority = "P2"
        else:
            priority = "P3"
        route_by_priority = {
            "P0": (15, "soc-critical"),
            "P1": (60, "soc-urgent"),
            "P2": (240, "soc-review"),
            "P3": (1440, "security-observation"),
        }
        sla_minutes, route = route_by_priority[priority]
        reasons = [item.category.upper() for item in contributions]
        warnings = list(enrichment.warnings)
        if behavior_unavailable:
            warnings.append("behavioral_analytics:unavailable")
        return TriageAssessment(
            alert_id=alert.alert_id,
            risk_score=score,
            severity=alert.severity,
            priority=priority,
            reasons=reasons,
            score_version=TRIAGE_SCORE_VERSION,
            contributions=contributions,
            sla_minutes=sla_minutes,
            route=route,
            missing_context_warnings=warnings,
            behavior_assessment_id=behavior.assessment_id if behavior else None,
            behavior_anomaly_score=behavior.anomaly_score if behavior else None,
            composite_risk_score=behavior.composite_risk_score if behavior else None,
            behavior_drift_state=behavior.drift_state.value if behavior else None,
            narrative=(
                "Risk %d/100 routes to %s as %s; %d recorded contributions were applied%s."
                % (
                    score,
                    route,
                    priority,
                    len(contributions),
                    (
                        "; behavioral composite %d/100"
                        % behavior.composite_risk_score
                        if behavior is not None
                        else ""
                    ),
                )
            ),
        )

    @staticmethod
    def _compatibility_snapshot(alert: SecurityAlert) -> EnrichmentSnapshot:
        """Support direct reasoner-adapter tests; the real pipeline never uses this path."""

        ref = [evidence_ref("alert", alert.alert_id)]
        facts = {
            "provenance": {"trust_class": alert.source_trust.value, "cross_session_memory": False},
            "effective_authority": {
                "operation_allowed": "unavailable",
                "full_scope_allowed": "unavailable",
            },
            "data_classification": {
                "sensitive": alert.alert_type == "secret_egress"
            },
            "destination_classification": {
                "external": bool(alert.destination)
            },
            "abom_tool_drift": {"drifted": alert.alert_type == "mcp_schema_drift"},
            "agent_model_profile": {"asset_criticality": "unknown"},
            "independent_observations": {"integrity_findings": []},
            "causal_path": {"path_scope": "alert_only"},
            "repeat_frequency": {"repeated": False},
        }
        sources = [
            EnrichmentResult(
                source=name,
                status=EnrichmentStatus.PARTIAL,
                confidence=0.7,
                facts=value,
                evidence_refs=ref,
                affects_triage=False,
                failure_effect="Compatibility-only context cannot relax enforcement",
            )
            for name, value in facts.items()
        ]
        return EnrichmentSnapshot(
            status=EnrichmentStatus.PARTIAL,
            sources=sources,
            completed_sources=0,
            total_sources=len(sources),
            mandatory_context_complete=False,
            warnings=["compatibility_snapshot:partial"],
        )


class Judge:
    """Combines decisions without ever weakening deterministic enforcement."""

    policy_version = "policy-2026-07-22.1"

    def __init__(self, evidence_validator: Optional[EvidenceJudgmentValidator] = None) -> None:
        self.evidence_validator = evidence_validator or EvidenceJudgmentValidator()

    def decide(
        self,
        alert: SecurityAlert,
        triage: TriageAssessment,
        model_verdict: Optional[ModelVerdict] = None,
        ai_mode: AiMode = AiMode.OFF,
        model_status: str = "not_requested",
    ) -> Judgment:
        deterministic = alert.recommended_action
        final = deterministic
        reason_codes = list(alert.reason_codes)
        combiner_result = "deterministic_only"
        model_validation = None

        if triage.severity == Severity.CRITICAL:
            final = DecisionAction.DENY
            reason_codes.append("CRITICAL_RISK_FAIL_CLOSED")

        if model_verdict is not None:
            model_validation = self.evidence_validator.validate_model_verdict(
                alert=alert,
                triage=triage,
                verdict=model_verdict,
            )
            reason_codes.extend(model_validation.reason_codes)
            reason_codes.extend(model_verdict.reason_codes)
            if (
                ai_mode == AiMode.SEMANTIC_HOLD
                and ACTION_RANK[model_verdict.action] > ACTION_RANK[final]
                and model_validation.eligible_to_tighten
            ):
                final = model_verdict.action
                reason_codes.append("MODEL_TIGHTENED_DECISION")
                combiner_result = "model_tightened"
            elif (
                ai_mode == AiMode.SEMANTIC_HOLD
                and ACTION_RANK[model_verdict.action] > ACTION_RANK[final]
            ):
                reason_codes.append("MODEL_TIGHTENING_HELD_FOR_HUMAN")
                combiner_result = "model_tightening_human_gate"
            elif ACTION_RANK[model_verdict.action] < ACTION_RANK[final]:
                reason_codes.append("MODEL_RELAXATION_REJECTED")
                combiner_result = "model_relaxation_rejected"
            elif ai_mode == AiMode.SHADOW:
                reason_codes.append("MODEL_SHADOW_ONLY")
                combiner_result = "shadow_recorded"
            elif ai_mode == AiMode.ADVISORY:
                reason_codes.append("MODEL_ADVISORY_ONLY")
                combiner_result = "advisory_recorded"
            else:
                combiner_result = "same_action"

        return Judgment(
            alert_id=alert.alert_id,
            action=final,
            reason_codes=list(dict.fromkeys(reason_codes)),
            deterministic_action=deterministic,
            model_verdict=model_verdict,
            ai_mode=ai_mode,
            model_status=model_status,
            model_validation=model_validation,
            combiner_result=combiner_result,
            policy_version=self.policy_version,
        )


class Escalator:
    def escalate(self, alert: SecurityAlert, triage: TriageAssessment, judgment: Judgment) -> EscalationRecord:
        if triage.priority == "P0" and judgment.action == DecisionAction.DENY:
            return EscalationRecord(
                alert_id=alert.alert_id,
                level=EscalationLevel.INCIDENT_PAGE,
                queue="soc-critical",
                case_id=new_id("case"),
                reason="Critical forbidden effect was blocked",
            )
        if judgment.action == DecisionAction.DENY:
            return EscalationRecord(
                alert_id=alert.alert_id,
                level=EscalationLevel.SOC_URGENT,
                queue="soc-urgent",
                case_id=new_id("case"),
                reason="High-risk forbidden effect was blocked",
            )
        if judgment.action == DecisionAction.REQUIRE_APPROVAL:
            return EscalationRecord(
                alert_id=alert.alert_id,
                level=EscalationLevel.REVIEW_QUEUE,
                queue="security-approval",
                case_id=new_id("case"),
                reason="Exact action requires human approval",
            )
        return EscalationRecord(
            alert_id=alert.alert_id,
            level=EscalationLevel.NONE,
            reason="No escalation required",
        )


class SafeResponder:
    """Records simulated containment; it has no real tool or network adapters."""

    def respond(
        self, alert: SecurityAlert, judgment: Judgment, escalation: EscalationRecord
    ) -> ResponseRecord:
        if judgment.action == DecisionAction.DENY:
            actions = [ResponseAction.BLOCK_EFFECT]
            notes = ["Proposed effect was denied before execution"]
            if escalation.level == EscalationLevel.INCIDENT_PAGE:
                actions.append(ResponseAction.QUARANTINE_SESSION)
                notes.append("Session quarantine recorded for critical incident")
            return ResponseRecord(
                alert_id=alert.alert_id,
                actions=actions,
                effect_allowed=False,
                effect_status=EffectStatus.BLOCKED,
                notes=notes,
            )
        if judgment.action == DecisionAction.REQUIRE_APPROVAL:
            return ResponseRecord(
                alert_id=alert.alert_id,
                actions=[ResponseAction.HOLD_FOR_APPROVAL],
                effect_allowed=False,
                effect_status=EffectStatus.HELD,
                notes=["Effect held until an exact-action approval is verified"],
            )
        return ResponseRecord(
            alert_id=alert.alert_id,
            actions=[ResponseAction.RECORD_ONLY],
            effect_allowed=True,
            effect_status=EffectStatus.ALLOWED,
            notes=["Effect may proceed under the deterministic decision"],
        )
