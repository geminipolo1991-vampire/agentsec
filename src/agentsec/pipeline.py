"""Orchestration of the complete security-alert lifecycle."""

from __future__ import annotations

from typing import List, Optional

from .contracts import (
    AgentEvent,
    AiMode,
    DecisionAction,
    EventProcessingResult,
    PipelineResult,
    PipelineStage,
    TimelineEntry,
)
from .detection import DetectionEngine
from .ingestion import InMemoryAlertLedger
from .findings import FindingStore
from .reasoning import ModelUnavailableError, SecurityReasoner
from .workflow import Escalator, Judge, SafeResponder, Triager
from .workflow import ACTION_RANK
from .contracts import FindingStatus, ResponseAction


class SecurityPipeline:
    def __init__(
        self,
        detector: Optional[DetectionEngine] = None,
        ledger: Optional[InMemoryAlertLedger] = None,
        reasoner: Optional[SecurityReasoner] = None,
        findings: Optional[FindingStore] = None,
        ai_mode: AiMode = AiMode.OFF,
    ) -> None:
        self.detector = detector or DetectionEngine()
        self.ledger = ledger or InMemoryAlertLedger()
        self.reasoner = reasoner
        self.findings = findings or FindingStore()
        self.ai_mode = ai_mode
        self.triager = Triager()
        self.judge = Judge()
        self.escalator = Escalator()
        self.responder = SafeResponder()

    def process(self, event: AgentEvent) -> EventProcessingResult:
        processed: List[PipelineResult] = []
        for alert in self.detector.detect(event):
            timeline = [
                TimelineEntry(
                    stage=PipelineStage.DETECTION,
                    outcome="alert_created",
                    evidence={"detector_id": alert.detector_id},
                )
            ]
            ingestion = self.ledger.ingest(alert)
            timeline.append(
                TimelineEntry(
                    stage=PipelineStage.INGESTION,
                    outcome="deduplicated" if ingestion.duplicate else "committed",
                    evidence={"sequence": ingestion.sequence, "hash": ingestion.current_hash},
                )
            )
            triage = self.triager.assess(alert)
            timeline.append(
                TimelineEntry(
                    stage=PipelineStage.TRIAGE,
                    outcome=triage.priority,
                    evidence={"risk_score": triage.risk_score},
                )
            )

            model_verdict = None
            if self.reasoner is not None and self.ai_mode != AiMode.OFF:
                try:
                    model_verdict = self.reasoner.analyze(alert, triage)
                except ModelUnavailableError:
                    timeline.append(
                        TimelineEntry(
                            stage=PipelineStage.JUDGMENT,
                            outcome="model_unavailable_deterministic_fallback",
                        )
                    )

            judgment = self.judge.decide(
                alert, triage, model_verdict, ai_mode=self.ai_mode
            )
            timeline.append(
                TimelineEntry(
                    stage=PipelineStage.JUDGMENT,
                    outcome=judgment.action.value,
                    evidence={"policy_version": judgment.policy_version},
                )
            )
            escalation = self.escalator.escalate(alert, triage, judgment)
            timeline.append(
                TimelineEntry(
                    stage=PipelineStage.ESCALATION,
                    outcome=escalation.level.value,
                    evidence={"case_id": escalation.case_id},
                )
            )
            response = self.responder.respond(alert, judgment, escalation)
            finding = self.findings.create_or_update(alert, judgment.policy_version)
            if ResponseAction.BLOCK_EFFECT in response.actions:
                finding = self.findings.transition(
                    finding.finding_id,
                    FindingStatus.CONTAINED,
                    actor="system://safe-responder",
                    reason="forbidden effect blocked before execution",
                )
            timeline.append(
                TimelineEntry(
                    stage=PipelineStage.RESPONSE,
                    outcome="effect_allowed" if response.effect_allowed else "effect_prevented",
                    evidence={"actions": [action.value for action in response.actions]},
                )
            )
            processed.append(
                PipelineResult(
                    event=event,
                    alert=alert,
                    ingestion=ingestion,
                    triage=triage,
                    judgment=judgment,
                    escalation=escalation,
                    response=response,
                    finding=finding,
                    timeline=timeline,
                )
            )

        overall_action = max(
            (item.judgment.action for item in processed),
            key=lambda action: ACTION_RANK[action],
            default=DecisionAction.ALLOW,
        )
        combined: List[PipelineResult] = []
        for item in processed:
            if ACTION_RANK[overall_action] <= ACTION_RANK[item.judgment.action]:
                combined.append(item)
                continue

            judgment = item.judgment.model_copy(
                update={
                    "action": overall_action,
                    "reason_codes": item.judgment.reason_codes
                    + ["EVENT_MOST_RESTRICTIVE_COMBINATION"],
                }
            )
            escalation = self.escalator.escalate(item.alert, item.triage, judgment)
            response = self.responder.respond(item.alert, judgment, escalation)
            finding = item.finding
            if ResponseAction.BLOCK_EFFECT in response.actions:
                finding = self.findings.transition(
                    finding.finding_id,
                    FindingStatus.CONTAINED,
                    actor="system://safe-responder",
                    reason="event-level restrictive decision blocked effect",
                )
            timeline = list(item.timeline[:3])
            timeline.extend(
                [
                    TimelineEntry(
                        stage=PipelineStage.JUDGMENT,
                        outcome=judgment.action.value,
                        evidence={"policy_version": judgment.policy_version},
                    ),
                    TimelineEntry(
                        stage=PipelineStage.ESCALATION,
                        outcome=escalation.level.value,
                        evidence={"case_id": escalation.case_id},
                    ),
                    TimelineEntry(
                        stage=PipelineStage.RESPONSE,
                        outcome="effect_allowed"
                        if response.effect_allowed
                        else "effect_prevented",
                        evidence={"actions": [action.value for action in response.actions]},
                    ),
                ]
            )
            combined.append(
                item.model_copy(
                    update={
                        "judgment": judgment,
                        "escalation": escalation,
                        "response": response,
                        "finding": finding,
                        "timeline": timeline,
                    }
                )
            )

        return EventProcessingResult(
            event=event,
            alerts=combined,
            overall_action=overall_action,
            effect_allowed=overall_action
            in {DecisionAction.ALLOW, DecisionAction.ALLOW_WITH_OBLIGATIONS},
        )
