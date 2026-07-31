"""Orchestration of the complete, evidence-backed security-alert lifecycle."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .contracts import (
    AgentEvent,
    AiMode,
    DecisionAction,
    EventProcessingResult,
    FindingStatus,
    Judgment,
    PipelineResult,
    PipelineStage,
    ResponseAction,
    SecurityAlert,
    TimelineEntry,
)
from .detection import DetectionEngine
from .enrichment import EnrichmentContext, EnrichmentEngine
from .findings import FindingStore
from .graph import CausalGraph
from .incidents import (
    IncidentDetail,
    IncidentStore,
    IncidentTransitionAction,
    transition_status,
)
from .ingestion import InMemoryAlertLedger
from .reasoning import ModelUnavailableError, SecurityReasoner
from .redaction import Redactor
from .workflow import ACTION_RANK, Escalator, Judge, SafeResponder, Triager
from .behavior import (
    BehaviorEventAssessment,
    BehaviorPrincipal,
    BehavioralRiskService,
)
from .correlation import CorrelationPrincipal, IncidentCorrelationService
from .analyst import AiAnalystService, AnalystPrincipal
from .cases import CasePrincipal, CaseService
from .notifications import NotificationPrincipal, NotificationService
from .response import ResponseAutomationService, ResponsePrincipal


class SecurityPipeline:
    def __init__(
        self,
        detector: Optional[DetectionEngine] = None,
        ledger: Optional[InMemoryAlertLedger] = None,
        reasoner: Optional[SecurityReasoner] = None,
        findings: Optional[FindingStore] = None,
        incidents: Optional[IncidentStore] = None,
        enricher: Optional[EnrichmentEngine] = None,
        causal_graph: Optional[CausalGraph] = None,
        behavior_service: Optional[BehavioralRiskService] = None,
        behavior_principal: Optional[BehaviorPrincipal] = None,
        correlation_service: Optional[IncidentCorrelationService] = None,
        correlation_principal: Optional[CorrelationPrincipal] = None,
        analyst_service: Optional[AiAnalystService] = None,
        analyst_principal: Optional[AnalystPrincipal] = None,
        case_service: Optional[CaseService] = None,
        case_principal: Optional[CasePrincipal] = None,
        notification_service: Optional[NotificationService] = None,
        notification_principal: Optional[NotificationPrincipal] = None,
        response_service: Optional[ResponseAutomationService] = None,
        response_principal: Optional[ResponsePrincipal] = None,
        ai_mode: AiMode = AiMode.OFF,
    ) -> None:
        if (behavior_service is None) != (behavior_principal is None):
            raise ValueError("behavior service and principal must be configured together")
        if (correlation_service is None) != (correlation_principal is None):
            raise ValueError("correlation service and principal must be configured together")
        if (analyst_service is None) != (analyst_principal is None):
            raise ValueError("analyst service and principal must be configured together")
        if (case_service is None) != (case_principal is None):
            raise ValueError("case service and principal must be configured together")
        if (notification_service is None) != (notification_principal is None):
            raise ValueError(
                "notification service and principal must be configured together"
            )
        if (response_service is None) != (response_principal is None):
            raise ValueError(
                "response service and principal must be configured together"
            )
        if analyst_service is not None and reasoner is not None:
            raise ValueError("configure either the AI analyst engine or the legacy reasoner")
        self.detector = detector or DetectionEngine()
        self.ledger = ledger or InMemoryAlertLedger()
        self.reasoner = reasoner
        self.findings = findings or FindingStore()
        self.incidents = incidents or IncidentStore()
        self.enricher = enricher or EnrichmentEngine()
        self.causal_graph = causal_graph or CausalGraph()
        self.behavior_service = behavior_service
        self.behavior_principal = behavior_principal
        self.last_behavior_error: Optional[str] = None
        self.correlation_service = correlation_service
        self.correlation_principal = correlation_principal
        self.last_correlation_error: Optional[str] = None
        self.analyst_service = analyst_service
        self.analyst_principal = analyst_principal
        self.last_analyst_error: Optional[str] = None
        self.case_service = case_service
        self.case_principal = case_principal
        self.last_case_error: Optional[str] = None
        self.notification_service = notification_service
        self.notification_principal = notification_principal
        self.last_notification_error: Optional[str] = None
        self.response_service = response_service
        self.response_principal = response_principal
        self.last_response_automation_error: Optional[str] = None
        self.ai_mode = ai_mode
        self.triager = Triager()
        self.judge = Judge()
        self.escalator = Escalator()
        self.responder = SafeResponder()
        self._repeat_counts: Dict[Tuple[str, str], int] = {}

    def process(
        self, event: AgentEvent, *, enrichment_context: Optional[EnrichmentContext] = None
    ) -> EventProcessingResult:
        behavior: Optional[BehaviorEventAssessment] = None
        behavior_unavailable = False
        if self.behavior_service is not None and self.behavior_principal is not None:
            try:
                behavior = self.behavior_service.analyze(self.behavior_principal, event)
                self.last_behavior_error = None
            except Exception:
                # Behavioral analytics can tighten triage or authorization, but
                # its outage cannot suppress deterministic detection.
                behavior_unavailable = True
                self.last_behavior_error = "behavior_analysis_unavailable"
        detected = list(self.detector.detect(event))
        if behavior is not None and self.behavior_service is not None:
            behavior_alert = self.behavior_service.alert_for(behavior, event)
            if behavior_alert is not None:
                detected.append(behavior_alert)
        prepared: List[Tuple[SecurityAlert, object, object, object, Judgment, List[TimelineEntry]]] = []
        for alert in detected:
            timeline = [
                TimelineEntry(
                    stage=PipelineStage.DETECTION,
                    outcome="alert_created",
                    evidence={
                        "detector_id": alert.detector_id,
                        "rule_version": alert.rule_version,
                        "matches": 1,
                    },
                )
            ]
            ingestion = self.ledger.ingest(alert)
            timeline.append(
                TimelineEntry(
                    stage=PipelineStage.INGESTION,
                    outcome="deduplicated" if ingestion.duplicate else "committed",
                    evidence={
                        "sequence": ingestion.sequence,
                        "hash": ingestion.current_hash,
                        "duplicate": ingestion.duplicate,
                    },
                )
            )

            repeat_key = (event.flow_id, alert.alert_type)
            repeat_count = self._repeat_counts.get(repeat_key, 0) + 1
            self._repeat_counts[repeat_key] = repeat_count
            enrichment = self.enricher.collect(
                event,
                repeat_count=repeat_count,
                duplicate=ingestion.duplicate,
                context=enrichment_context,
            )
            timeline.append(
                TimelineEntry(
                    stage=PipelineStage.ENRICHMENT,
                    outcome=enrichment.status.value,
                    evidence={
                        "completed_sources": enrichment.completed_sources,
                        "total_sources": enrichment.total_sources,
                        "status": enrichment.status.value,
                        "connector_sources": enrichment.connector_sources,
                        "cache_hits": enrichment.cache_hits,
                        "stale_fallbacks": enrichment.stale_fallbacks,
                        "timed_out_sources": enrichment.timed_out_sources,
                        "policy_digest": enrichment.policy_digest or "built_in",
                    },
                )
            )
            triage = self.triager.assess(
                alert,
                enrichment,
                behavior=behavior,
                behavior_unavailable=behavior_unavailable,
            )
            timeline.append(
                TimelineEntry(
                    stage=PipelineStage.TRIAGE,
                    outcome=triage.priority,
                    evidence={
                        "risk_score": triage.risk_score,
                        "priority": triage.priority,
                        "route": triage.route,
                    },
                )
            )

            model_verdict = None
            model_status = "not_requested"
            if self.reasoner is not None and self.ai_mode != AiMode.OFF:
                try:
                    model_verdict = self.reasoner.analyze(alert, triage)
                    model_status = (
                        "codex_recorded_shadow"
                        if model_verdict.provider == "codex" and self.ai_mode == AiMode.SHADOW
                        else "available"
                    )
                except ModelUnavailableError:
                    model_status = "unavailable"

            judgment = self.judge.decide(
                alert,
                triage,
                model_verdict,
                ai_mode=self.ai_mode,
                model_status=model_status,
            )
            prepared.append((alert, ingestion, enrichment, triage, judgment, timeline))

        overall_action = max(
            (item[4].action for item in prepared),
            key=lambda action: ACTION_RANK[action],
            default=DecisionAction.ALLOW,
        )
        processed: List[PipelineResult] = []
        for alert, ingestion, enrichment, triage, judgment, timeline in prepared:
            if ACTION_RANK[overall_action] > ACTION_RANK[judgment.action]:
                judgment = judgment.model_copy(
                    update={
                        "action": overall_action,
                        "reason_codes": list(
                            dict.fromkeys(
                                judgment.reason_codes
                                + ["EVENT_MOST_RESTRICTIVE_COMBINATION"]
                            )
                        ),
                        "combiner_result": "event_most_restrictive",
                    }
                )
            timeline.append(
                TimelineEntry(
                    stage=PipelineStage.JUDGMENT,
                    outcome=(
                        "model_unavailable_deterministic_fallback"
                        if judgment.model_status == "unavailable"
                        else judgment.action.value
                    ),
                    evidence={
                        "policy_version": judgment.policy_version,
                        "combiner_result": judgment.combiner_result,
                        "model_status": judgment.model_status,
                        "final_action": judgment.action.value,
                    },
                )
            )
            escalation = self.escalator.escalate(alert, triage, judgment)
            timeline.append(
                TimelineEntry(
                    stage=PipelineStage.ESCALATION,
                    outcome=escalation.level.value,
                    evidence={
                        "case_id": escalation.case_id,
                        "queue": escalation.queue,
                        "level": escalation.level.value,
                    },
                )
            )
            response = self.responder.respond(alert, judgment, escalation)
            finding = self.findings.create_or_update(alert, judgment.policy_version)
            if (
                ResponseAction.BLOCK_EFFECT in response.actions
                and finding.status not in {FindingStatus.CONTAINED, FindingStatus.CLOSED}
            ):
                finding = self.findings.transition(
                    finding.finding_id,
                    FindingStatus.CONTAINED,
                    actor="system://safe-responder",
                    reason="forbidden effect blocked before execution",
                )
            timeline.append(
                TimelineEntry(
                    stage=PipelineStage.RESPONSE,
                    outcome=response.effect_status.value,
                    evidence={
                        "actions": [action.value for action in response.actions],
                        "effect_status": response.effect_status.value,
                    },
                )
            )
            item = PipelineResult(
                event=event,
                alert=alert,
                ingestion=ingestion,
                ledger_verified=self.ledger.verify(),
                enrichment=enrichment,
                triage=triage,
                judgment=judgment,
                escalation=escalation,
                response=response,
                finding=finding,
                timeline=timeline,
            )
            if (
                self.analyst_service is not None
                and self.analyst_principal is not None
                and self.ai_mode != AiMode.OFF
            ):
                try:
                    analyst_run = self.analyst_service.analyze(
                        self.analyst_principal, item
                    )
                    item = item.model_copy(update={"analyst_run": analyst_run})
                    self.last_analyst_error = None
                except Exception:
                    # AI analyst output is advisory and post-response. Its outage
                    # cannot change the action or erase deterministic evidence.
                    self.last_analyst_error = "ai_analyst_unavailable"
            processed.append(item)
            self.incidents.record(item)
            correlation_incident_id: Optional[str] = None
            if self.correlation_service is not None and self.correlation_principal is not None:
                try:
                    correlation = self.correlation_service.correlate(
                        self.correlation_principal, item
                    )
                    correlation_incident_id = correlation.incident_id
                    self.last_correlation_error = None
                except Exception:
                    # Post-response correlation cannot change or suppress the
                    # authorization result; a sanitized health error remains visible.
                    self.last_correlation_error = "incident_correlation_unavailable"
            if self.case_service is not None and self.case_principal is not None:
                try:
                    case = self.case_service.create_from_pipeline(
                        self.case_principal,
                        item,
                        correlation_incident_id=correlation_incident_id,
                    )
                    case_id = case.case_id
                    self.last_case_error = None
                except Exception:
                    # Case collaboration is post-response. A case-store outage
                    # cannot alter authorization or erase authoritative findings.
                    self.last_case_error = "case_management_unavailable"
                    case_id = item.escalation.case_id
            else:
                case_id = item.escalation.case_id
            if (
                self.notification_service is not None
                and self.notification_principal is not None
            ):
                try:
                    self.notification_service.enqueue_from_pipeline(
                        self.notification_principal,
                        item,
                        case_id=case_id,
                        correlation_incident_id=correlation_incident_id,
                    )
                    self.last_notification_error = None
                except Exception:
                    # Notification routing is a durable post-response outbox.
                    # Its outage cannot change the already-enforced decision.
                    self.last_notification_error = "notification_routing_unavailable"
            if self.response_service is not None and self.response_principal is not None:
                try:
                    self.response_service.create_from_pipeline(
                        self.response_principal,
                        item,
                        case_id=case_id,
                        correlation_incident_id=correlation_incident_id,
                    )
                    self.last_response_automation_error = None
                except Exception:
                    # Response automation records an inert dry-run plan only.
                    # It is downstream of enforcement and cannot authorize or
                    # execute the original effect when its store is unavailable.
                    self.last_response_automation_error = (
                        "response_automation_unavailable"
                    )

        result = EventProcessingResult(
            event=event,
            alerts=processed,
            overall_action=overall_action,
            effect_allowed=overall_action
            in {DecisionAction.ALLOW, DecisionAction.ALLOW_WITH_OBLIGATIONS},
        )
        self.causal_graph.ingest(result)
        if (
            behavior is not None
            and self.behavior_service is not None
            and self.behavior_principal is not None
        ):
            eligible = not processed and result.effect_allowed
            try:
                self.behavior_service.learn(
                    self.behavior_principal,
                    event,
                    behavior,
                    eligible=eligible,
                    reason=(
                        "Allowed event completed with no security alert."
                        if eligible
                        else "Security alert or restrictive outcome excluded the event from learning."
                    ),
                )
            except Exception:
                self.last_behavior_error = "behavior_learning_unavailable"
        return result

    def incident(self, finding_id: str) -> IncidentDetail:
        return self.incidents.get(finding_id)

    def transition_incident(
        self,
        finding_id: str,
        action: IncidentTransitionAction,
        *,
        actor: str,
        reason: str,
    ) -> IncidentDetail:
        transformed = Redactor().redact(
            {"actor": actor, "reason": reason}
        ).value
        updated = self.findings.transition(
            finding_id,
            transition_status(action),
            actor=str(transformed["actor"]),
            reason=str(transformed["reason"]),
        )
        return self.incidents.update_finding(updated)
