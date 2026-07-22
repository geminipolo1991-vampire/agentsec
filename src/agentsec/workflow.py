"""Triage, judgment, escalation, and safe response components."""

from __future__ import annotations

from typing import Dict, List, Optional

from .contracts import (
    AiMode,
    DecisionAction,
    EscalationLevel,
    EscalationRecord,
    Judgment,
    ModelVerdict,
    ResponseAction,
    ResponseRecord,
    SecurityAlert,
    Severity,
    TriageAssessment,
    new_id,
)


SEVERITY_SCORE: Dict[Severity, int] = {
    Severity.INFO: 10,
    Severity.LOW: 25,
    Severity.MEDIUM: 50,
    Severity.HIGH: 75,
    Severity.CRITICAL: 95,
}

ACTION_RANK: Dict[DecisionAction, int] = {
    DecisionAction.ALLOW: 0,
    DecisionAction.ALLOW_WITH_OBLIGATIONS: 1,
    DecisionAction.REQUIRE_APPROVAL: 2,
    DecisionAction.DENY: 3,
}


class Triager:
    def assess(self, alert: SecurityAlert) -> TriageAssessment:
        score = SEVERITY_SCORE[alert.severity]
        reasons: List[str] = ["BASE_SEVERITY_%s" % alert.severity.value.upper()]
        if alert.confidence >= 0.95:
            score += 3
            reasons.append("HIGH_CONFIDENCE_DETECTION")
        if alert.source_trust.value in {"external-untrusted", "suspected-adversarial"}:
            score += 2
            reasons.append("UNTRUSTED_PROVENANCE")
        score = min(score, 100)
        if score >= 90:
            priority = "P0"
        elif score >= 70:
            priority = "P1"
        elif score >= 40:
            priority = "P2"
        else:
            priority = "P3"
        return TriageAssessment(
            alert_id=alert.alert_id,
            risk_score=score,
            severity=alert.severity,
            priority=priority,
            reasons=reasons,
        )


class Judge:
    """Combines decisions without ever weakening deterministic enforcement."""

    policy_version = "policy-2026-07-22.1"

    def decide(
        self,
        alert: SecurityAlert,
        triage: TriageAssessment,
        model_verdict: Optional[ModelVerdict] = None,
        ai_mode: AiMode = AiMode.OFF,
    ) -> Judgment:
        deterministic = alert.recommended_action
        final = deterministic
        reason_codes = list(alert.reason_codes)

        if triage.severity == Severity.CRITICAL:
            final = DecisionAction.DENY
            reason_codes.append("CRITICAL_RISK_FAIL_CLOSED")

        if model_verdict is not None:
            reason_codes.extend(model_verdict.reason_codes)
            if (
                ai_mode == AiMode.SEMANTIC_HOLD
                and ACTION_RANK[model_verdict.action] > ACTION_RANK[final]
            ):
                final = model_verdict.action
                reason_codes.append("MODEL_TIGHTENED_DECISION")
            elif ACTION_RANK[model_verdict.action] < ACTION_RANK[final]:
                reason_codes.append("MODEL_RELAXATION_REJECTED")
            elif ai_mode == AiMode.SHADOW:
                reason_codes.append("MODEL_SHADOW_ONLY")
            elif ai_mode == AiMode.ADVISORY:
                reason_codes.append("MODEL_ADVISORY_ONLY")

        return Judgment(
            alert_id=alert.alert_id,
            action=final,
            reason_codes=list(dict.fromkeys(reason_codes)),
            deterministic_action=deterministic,
            model_verdict=model_verdict,
            ai_mode=ai_mode,
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
                notes=notes,
            )
        if judgment.action == DecisionAction.REQUIRE_APPROVAL:
            return ResponseRecord(
                alert_id=alert.alert_id,
                actions=[ResponseAction.HOLD_FOR_APPROVAL],
                effect_allowed=False,
                notes=["Effect held until an exact-action approval is verified"],
            )
        return ResponseRecord(
            alert_id=alert.alert_id,
            actions=[ResponseAction.RECORD_ONLY],
            effect_allowed=True,
            notes=["Effect may proceed under the deterministic decision"],
        )
