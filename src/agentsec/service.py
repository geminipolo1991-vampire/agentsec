"""Authenticated authorization, incident, and AI telemetry HTTP service."""

from __future__ import annotations

import hmac
import json
import os
import re
import threading
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple, Type
from urllib.parse import parse_qs, urlsplit
from pathlib import Path

from pydantic import Field, ValidationError

from .contracts import (
    AgentEvent,
    AnalystFeedbackRating,
    AnalystRole,
    Severity,
    StrictModel,
)
from .datamodel import canonical_bundle_from_pipeline
from .gateway import (
    GatewayAuthenticationError,
    GatewayEventStatus,
    GatewayReceipt,
    IngestionGateway,
    gateway_from_environment,
)
from .incidents import (
    IncidentDetail,
    IncidentListResponse,
    IncidentTimelineStep,
    IncidentTransitionRequest,
)
from .pipeline import SecurityPipeline
from .runtime import build_pipeline_from_environment
from .search import (
    EVIDENCE_READ_PERMISSION,
    HUNT_WRITE_PERMISSION,
    INDEX_PERMISSION,
    READ_PERMISSION,
    SearchAuthorizationError,
    SearchPrincipal,
    SearchQueryError,
    SearchRequest,
    SearchService,
)
from .storage import CanonicalRepository
from .inventory import (
    INVENTORY_ADMIN,
    INVENTORY_DISCOVER,
    INVENTORY_READ,
    INVENTORY_WRITE,
    ComponentKind,
    ComponentStatus,
    InventoryAuthorizationError,
    InventoryObservation,
    InventoryPrincipal,
    InventoryService,
)
from .model_registry import ModelRegistry
from .graph import (
    GRAPH_ANALYZE,
    GRAPH_READ,
    GRAPH_WRITE,
    GraphAuthorizationError,
    GraphPrincipal,
    SecurityGraphService,
)
from .posture import (
    POSTURE_ADMIN,
    POSTURE_READ,
    POSTURE_SCAN,
    PostureAuthorizationError,
    PostureFindingStatus,
    PosturePrincipal,
    PostureService,
)
from .detection import (
    DETECTION_ADMIN,
    DETECTION_READ,
    DETECTION_RUN,
    DetectionAuthorizationError,
    DetectionEngine,
    DetectionPrincipal,
    DetectionRuleDefinition,
    DetectionService,
)
from .content import (
    CONTENT_ADMIN,
    CONTENT_PUBLISH,
    CONTENT_READ,
    CONTENT_REVIEW,
    CONTENT_WRITE,
    ContentAuthorizationError,
    ContentPrincipal,
    DetectionContentService,
    ReviewDecision,
    RuleContentStatus,
    RuleTestSuite,
    SignedContentPack,
)
from .crypto import PocHmacSigner
from .behavior import (
    BEHAVIOR_ADMIN,
    BEHAVIOR_ANALYZE,
    BEHAVIOR_READ,
    BaselineState,
    BehaviorAuthorizationError,
    BehaviorPrincipal,
    BehaviorTuningInput,
    BehavioralRiskService,
)
from .correlation import (
    CORRELATION_ADMIN,
    CORRELATION_READ,
    CORRELATION_WRITE,
    CorrelationAuthorizationError,
    CorrelationIncidentStatus,
    CorrelationPrincipal,
    CorrelationSplitResult,
    IncidentCorrelationService,
)
from .enrichment import (
    EnrichmentAuthorizationError,
    EnrichmentPrincipal,
    enrichment_engine_from_config,
)
from .analyst import (
    AiAnalystService,
    AnalystAuthorizationError,
    AnalystPrincipal,
    analyst_service_from_recording,
)
from .model_gateway import (
    MODEL_GATEWAY_ACTIVATE,
    MODEL_GATEWAY_ADMIN,
    MODEL_GATEWAY_INVOKE,
    MODEL_GATEWAY_QUALIFY,
    MODEL_GATEWAY_READ,
    MODEL_GATEWAY_SECRET,
    MODEL_GATEWAY_WRITE,
    GovernedAnalystRoleReasoner,
    GovernedSecurityReasoner,
    ModelGatewayAuthorizationError,
    ModelGatewayPrincipal,
    ModelGatewayService,
    QualificationMetrics,
    RouteConfiguration,
    model_gateway_from_config,
)
from .cases import (
    CASE_ADMIN,
    CASE_ASSIGN,
    CASE_ATTACH,
    CASE_COMMENT,
    CASE_READ,
    CASE_REVIEW,
    CASE_TASK,
    CASE_WRITE,
    AttachmentScanStatus,
    CaseAssignmentRequest,
    CaseAttachmentRequest,
    CaseAttachmentScanRequest,
    CaseAuthorizationError,
    CaseCommentRequest,
    CaseConflictError,
    CaseLifecycleRequest,
    CasePrincipal,
    CaseRelationshipRequest,
    CaseReviewRequest,
    CaseService,
    CaseStatus,
    CaseTaskCreateRequest,
    CaseTaskTransitionRequest,
    CaseTeamCreateRequest,
    case_service_from_environment,
)
from .notifications import (
    NOTIFICATION_ACK,
    NOTIFICATION_ADMIN,
    NOTIFICATION_DELIVER,
    NOTIFICATION_READ,
    NOTIFICATION_ROUTE,
    NotificationAcknowledgeRequest,
    NotificationAuthorizationError,
    NotificationConflictError,
    NotificationPrincipal,
    NotificationProcessRequest,
    NotificationRedriveRequest,
    NotificationService,
    ProviderAcknowledgeRequest,
    notification_service_from_environment,
)
from .response import (
    ApprovalScope,
    RESPONSE_ADMIN,
    RESPONSE_APPROVE,
    RESPONSE_AUTHOR,
    RESPONSE_EXECUTE,
    RESPONSE_OPERATE,
    RESPONSE_READ,
    RESPONSE_REVIEW,
    ResponseApprovalRequest,
    ResponseAutomationService,
    ResponseAuthorizationError,
    ResponseConflictError,
    ResponseEmptyRequest,
    ResponseExecutionError,
    ResponseKillSwitchRequest,
    ResponseMutationRequest,
    ResponsePlaybookActionRequest,
    ResponsePlaybookCreateRequest,
    ResponsePrincipal,
    response_service_from_environment,
)
from .integrations import (
    EXTERNAL_CAPABILITIES,
    EXTERNAL_ENTITIES_READ,
    EXTERNAL_EVENTS_READ,
    EXTERNAL_FINDINGS_READ,
    EXTERNAL_INCIDENTS_READ,
    EXTERNAL_INTEGRATIONS_OPERATE,
    EXTERNAL_INTEGRATIONS_READ,
    EXTERNAL_RULES_READ,
    EXTERNAL_SEARCH,
    INTEGRATION_ADMIN,
    INTEGRATION_DELIVER,
    INTEGRATION_ENQUEUE,
    INTEGRATION_READ,
    INTEGRATION_REDRIVE,
    ExternalApiAuthenticationError,
    ExternalApiAuthenticator,
    ExternalApiAuthorizationError,
    ExternalApiPrincipal,
    IntegrationAuthorizationError,
    IntegrationConflictError,
    IntegrationDeliveryState,
    IntegrationPrincipal,
    IntegrationProcessRequest,
    IntegrationRedriveRequest,
    IntegrationService,
    integration_service_from_config,
)
from .simulation import (
    SimulationAuthorizationError,
    SimulationConflictError,
    SimulationImportRequest,
    SimulationMutationRequest,
    SimulationPrincipal,
    SimulationReplayRequest,
    SimulationRunRequest,
    SimulationScenarioSource,
    SimulationService,
    SimulationVariant,
    simulation_service_from_environment,
)
from .continuous_evaluation import (
    EVALUATION_ADMIN,
    EVALUATION_FEEDBACK,
    EVALUATION_READ,
    EVALUATION_REVIEW,
    EVALUATION_RUN,
    CandidateKind,
    ContinuousEvaluationService,
    EvaluationAuthorizationError,
    EvaluationBaselineApprovalRequest,
    EvaluationConflictError,
    EvaluationFeedbackPromotionRequest,
    EvaluationFeedbackProposalRequest,
    EvaluationFeedbackReviewRequest,
    EvaluationFeedbackState,
    EvaluationGateState,
    EvaluationPrincipal,
    EvaluationRunRequest,
    evaluation_service_from_environment,
)
from .administration import (
    AdministrationAuthorizationError,
    AdministrationConflictError,
    AdministrationPrincipal,
    AdministrationService,
    administration_service_from_environment,
)


MAX_REQUEST_BYTES = 1024 * 1024


def health_payload() -> Dict[str, str]:
    return {"status": "ok", "service": "agentsec-authorization"}


def bearer_is_valid(supplied_header: str, bearer_token: str) -> bool:
    return hmac.compare_digest(supplied_header, "Bearer %s" % bearer_token)


class AuthorizationAlertSummary(StrictModel):
    alert_id: str
    finding_id: str
    alert_type: str
    severity: str
    decision: str
    escalation: str


class AuthorizationResponse(StrictModel):
    schema_version: str = "2.0.0"
    event_id: str
    overall_action: str
    effect_allowed: bool
    alerts: List[AuthorizationAlertSummary] = Field(default_factory=list)
    incidents: List[IncidentDetail] = Field(default_factory=list)
    ledger_verified: bool


class AuthorizationApplication:
    """Serializes access to the in-memory PoC stores and returns an allowlist view."""

    def __init__(
        self,
        pipeline: Optional[SecurityPipeline] = None,
        *,
        canonical_repository: Optional[CanonicalRepository] = None,
        search_service: Optional[SearchService] = None,
        search_principal: Optional[SearchPrincipal] = None,
        inventory_service: Optional[InventoryService] = None,
        inventory_principal: Optional[InventoryPrincipal] = None,
        inventory_application_id: str = "authorization-service",
        graph_service: Optional[SecurityGraphService] = None,
        graph_principal: Optional[GraphPrincipal] = None,
        posture_service: Optional[PostureService] = None,
        posture_principal: Optional[PosturePrincipal] = None,
        detection_service: Optional[DetectionService] = None,
        detection_principal: Optional[DetectionPrincipal] = None,
        content_service: Optional[DetectionContentService] = None,
        content_principal: Optional[ContentPrincipal] = None,
        behavior_service: Optional[BehavioralRiskService] = None,
        behavior_principal: Optional[BehaviorPrincipal] = None,
        correlation_service: Optional[IncidentCorrelationService] = None,
        correlation_principal: Optional[CorrelationPrincipal] = None,
        enrichment_principal: Optional[EnrichmentPrincipal] = None,
        analyst_service: Optional[AiAnalystService] = None,
        analyst_principal: Optional[AnalystPrincipal] = None,
        model_gateway_service: Optional[ModelGatewayService] = None,
        model_gateway_principal: Optional[ModelGatewayPrincipal] = None,
        case_service: Optional[CaseService] = None,
        case_principal: Optional[CasePrincipal] = None,
        notification_service: Optional[NotificationService] = None,
        notification_principal: Optional[NotificationPrincipal] = None,
        response_service: Optional[ResponseAutomationService] = None,
        response_principal: Optional[ResponsePrincipal] = None,
        integration_service: Optional[IntegrationService] = None,
        integration_principal: Optional[IntegrationPrincipal] = None,
        simulation_service: Optional[SimulationService] = None,
        simulation_principal: Optional[SimulationPrincipal] = None,
        evaluation_service: Optional[ContinuousEvaluationService] = None,
        evaluation_principal: Optional[EvaluationPrincipal] = None,
        administration_service: Optional[AdministrationService] = None,
        administration_principal: Optional[AdministrationPrincipal] = None,
    ) -> None:
        configured = [
            canonical_repository is not None,
            search_service is not None,
            search_principal is not None,
        ]
        if any(configured) and not all(configured):
            raise ValueError(
                "canonical repository, search service, and search principal must be configured together"
            )
        if (inventory_service is None) != (inventory_principal is None):
            raise ValueError(
                "inventory service and inventory principal must be configured together"
            )
        if (graph_service is None) != (graph_principal is None):
            raise ValueError("graph service and graph principal must be configured together")
        if (posture_service is None) != (posture_principal is None):
            raise ValueError("posture service and posture principal must be configured together")
        if (detection_service is None) != (detection_principal is None):
            raise ValueError("detection service and detection principal must be configured together")
        if (content_service is None) != (content_principal is None):
            raise ValueError("content service and content principal must be configured together")
        if (behavior_service is None) != (behavior_principal is None):
            raise ValueError("behavior service and behavior principal must be configured together")
        if (correlation_service is None) != (correlation_principal is None):
            raise ValueError("correlation service and principal must be configured together")
        if enrichment_principal is not None and (
            pipeline is None or pipeline.enricher.principal is None
        ):
            raise ValueError("enrichment principal requires a configured enrichment engine")
        if (
            enrichment_principal is not None
            and pipeline is not None
            and pipeline.enricher.principal is not None
            and enrichment_principal.tenant_id != pipeline.enricher.principal.tenant_id
        ):
            raise ValueError("enrichment engine and application tenants must match")
        if (analyst_service is None) != (analyst_principal is None):
            raise ValueError("analyst service and principal must be configured together")
        if (model_gateway_service is None) != (model_gateway_principal is None):
            raise ValueError("model gateway service and principal must be configured together")
        if (case_service is None) != (case_principal is None):
            raise ValueError("case service and principal must be configured together")
        if (notification_service is None) != (notification_principal is None):
            raise ValueError(
                "notification service and principal must be configured together"
            )
        if (response_service is None) != (response_principal is None):
            raise ValueError("response service and principal must be configured together")
        if (integration_service is None) != (integration_principal is None):
            raise ValueError("integration service and principal must be configured together")
        if (simulation_service is None) != (simulation_principal is None):
            raise ValueError("simulation service and principal must be configured together")
        if (evaluation_service is None) != (evaluation_principal is None):
            raise ValueError("evaluation service and principal must be configured together")
        if (administration_service is None) != (administration_principal is None):
            raise ValueError("administration service and principal must be configured together")
        if content_service is not None and detection_service is None:
            raise ValueError("content service requires the detection service")
        if posture_service is not None and inventory_service is None:
            raise ValueError("posture service requires the inventory service")
        if not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", inventory_application_id):
            raise ValueError("inventory application ID is invalid")
        configured_tenants = {
            principal.tenant_id
            for principal in (
                search_principal, inventory_principal, graph_principal,
                posture_principal, detection_principal,
                content_principal,
                behavior_principal,
                correlation_principal,
                enrichment_principal,
                analyst_principal,
                model_gateway_principal,
                case_principal,
                notification_principal,
                response_principal,
                integration_principal,
                simulation_principal,
                evaluation_principal,
                administration_principal,
            )
            if principal is not None
        }
        if len(configured_tenants) > 1:
            raise ValueError(
                "configured product-store tenants must match"
            )
        self.product_tenant_id = (
            next(iter(configured_tenants)) if configured_tenants else None
        )
        self.pipeline = pipeline or SecurityPipeline()
        self.canonical_repository = canonical_repository
        self.search_service = search_service
        self.search_principal = search_principal
        self.inventory_service = inventory_service
        self.inventory_principal = inventory_principal
        self.inventory_application_id = inventory_application_id
        self.graph_service = graph_service
        self.graph_principal = graph_principal
        self.posture_service = posture_service
        self.posture_principal = posture_principal
        self.detection_service = detection_service
        self.detection_principal = detection_principal
        self.content_service = content_service
        self.content_principal = content_principal
        self.behavior_service = behavior_service
        self.behavior_principal = behavior_principal
        self.correlation_service = correlation_service
        self.correlation_principal = correlation_principal
        self.enrichment_principal = enrichment_principal
        self.analyst_service = analyst_service
        self.analyst_principal = analyst_principal
        self.model_gateway_service = model_gateway_service
        self.model_gateway_principal = model_gateway_principal
        self.case_service = case_service
        self.case_principal = case_principal
        self.notification_service = notification_service
        self.notification_principal = notification_principal
        self.response_service = response_service
        self.response_principal = response_principal
        self.integration_service = integration_service
        self.integration_principal = integration_principal
        self.simulation_service = simulation_service
        self.simulation_principal = simulation_principal
        self.evaluation_service = evaluation_service
        self.evaluation_principal = evaluation_principal
        self.administration_service = administration_service
        self.administration_principal = administration_principal
        if detection_service is not None and detection_principal is not None:
            self.pipeline.detector = DetectionEngine(
                service=detection_service, principal=detection_principal
            )
        if behavior_service is not None and behavior_principal is not None:
            self.pipeline.behavior_service = behavior_service
            self.pipeline.behavior_principal = behavior_principal
        if correlation_service is not None and correlation_principal is not None:
            self.pipeline.correlation_service = correlation_service
            self.pipeline.correlation_principal = correlation_principal
        if analyst_service is not None and analyst_principal is not None:
            self.pipeline.analyst_service = analyst_service
            self.pipeline.analyst_principal = analyst_principal
        if case_service is not None and case_principal is not None:
            self.pipeline.case_service = case_service
            self.pipeline.case_principal = case_principal
        if notification_service is not None and notification_principal is not None:
            self.pipeline.notification_service = notification_service
            self.pipeline.notification_principal = notification_principal
        if response_service is not None and response_principal is not None:
            self.pipeline.response_service = response_service
            self.pipeline.response_principal = response_principal
        self._lock = threading.Lock()

    def authorize(self, payload: Dict[str, Any]) -> AuthorizationResponse:
        event = AgentEvent.model_validate(payload)
        if self.search_principal is not None and event.tenant_id != self.search_principal.tenant_id:
            raise SearchAuthorizationError(
                "authorization event is outside the configured search tenant"
            )
        if self.inventory_principal is not None and event.tenant_id != self.inventory_principal.tenant_id:
            raise InventoryAuthorizationError(
                "authorization event is outside the configured inventory tenant"
            )
        if self.graph_principal is not None and event.tenant_id != self.graph_principal.tenant_id:
            raise GraphAuthorizationError(
                "authorization event is outside the configured graph tenant"
            )
        if self.detection_principal is not None and event.tenant_id != self.detection_principal.tenant_id:
            raise DetectionAuthorizationError(
                "authorization event is outside the configured detection tenant"
            )
        if self.content_principal is not None and event.tenant_id != self.content_principal.tenant_id:
            raise ContentAuthorizationError(
                "authorization event is outside the configured content tenant"
            )
        if self.behavior_principal is not None and event.tenant_id != self.behavior_principal.tenant_id:
            raise BehaviorAuthorizationError(
                "authorization event is outside the configured behavior tenant"
            )
        if self.correlation_principal is not None and event.tenant_id != self.correlation_principal.tenant_id:
            raise CorrelationAuthorizationError(
                "authorization event is outside the configured correlation tenant"
            )
        if self.enrichment_principal is not None and event.tenant_id != self.enrichment_principal.tenant_id:
            raise EnrichmentAuthorizationError(
                "authorization event is outside the configured enrichment tenant"
            )
        if self.analyst_principal is not None and event.tenant_id != self.analyst_principal.tenant_id:
            raise AnalystAuthorizationError(
                "authorization event is outside the configured analyst tenant"
            )
        if (
            self.model_gateway_principal is not None
            and event.tenant_id != self.model_gateway_principal.tenant_id
        ):
            raise ModelGatewayAuthorizationError(
                "authorization event is outside the configured model gateway tenant"
            )
        if self.case_principal is not None and event.tenant_id != self.case_principal.tenant_id:
            raise CaseAuthorizationError(
                "authorization event is outside the configured case tenant"
            )
        if (
            self.notification_principal is not None
            and event.tenant_id != self.notification_principal.tenant_id
        ):
            raise NotificationAuthorizationError(
                "authorization event is outside the configured notification tenant"
            )
        if (
            self.response_principal is not None
            and event.tenant_id != self.response_principal.tenant_id
        ):
            raise ResponseAuthorizationError(
                "authorization event is outside the configured response tenant"
            )
        if (
            self.integration_principal is not None
            and event.tenant_id != self.integration_principal.tenant_id
        ):
            raise IntegrationAuthorizationError(
                "authorization event is outside the configured integration tenant"
            )
        if (
            self.integration_principal is not None
            and event.tenant_id != self.integration_principal.tenant_id
        ):
            raise IntegrationAuthorizationError(
                "authorization event is outside the configured integration tenant"
            )
        with self._lock:
            result = self.pipeline.process(event)
            ledger_verified = self.pipeline.ledger.verify()
            incidents = [
                self.pipeline.incidents.get(item.finding.finding_id)
                for item in result.alerts
            ]
            if self.search_principal is not None:
                assert self.canonical_repository is not None
                assert self.search_service is not None
                for item in result.alerts:
                    bundle = canonical_bundle_from_pipeline(item)
                    self.canonical_repository.commit_bundle(bundle)
                    for record in bundle.records:
                        self.search_service.index_record(self.search_principal, record)
            if self.inventory_principal is not None:
                assert self.inventory_service is not None
                discovery = self.inventory_service.observe_agent_event(
                    self.inventory_principal,
                    event,
                    application_id=self.inventory_application_id,
                )
                if self.graph_principal is not None:
                    assert self.graph_service is not None
                    components = [
                        self.inventory_service.get_component(
                            self.inventory_principal, component_id
                        )
                        for component_id in discovery.component_ids
                    ]
                    component_ids = set(discovery.component_ids)
                    relationships = [
                        relationship
                        for relationship in self.inventory_service.all_relationships(
                            self.inventory_principal
                        )
                        if relationship.source_component_id in component_ids
                        and relationship.target_component_id in component_ids
                    ]
                    self.graph_service.ingest_inventory(
                        self.graph_principal, components, relationships
                    )
            if self.graph_principal is not None:
                assert self.graph_service is not None
                self.graph_service.ingest_processing_result(self.graph_principal, result)
            if self.integration_principal is not None:
                assert self.integration_service is not None
                try:
                    for item in result.alerts:
                        self.integration_service.enqueue_pipeline_result(
                            self.integration_principal,
                            item,
                            ledger_valid=ledger_verified,
                        )
                except Exception:
                    # External export is downstream of enforcement. A broken
                    # outbox is visible in health but can never relax or replace
                    # the authorization result.
                    self.integration_service.pipeline_enqueue_error = (
                        "integration_enqueue_failed"
                    )
        return AuthorizationResponse(
            event_id=event.event_id,
            overall_action=result.overall_action.value,
            effect_allowed=result.effect_allowed,
            alerts=[
                AuthorizationAlertSummary(
                    alert_id=item.alert.alert_id,
                    finding_id=item.finding.finding_id,
                    alert_type=item.alert.alert_type,
                    severity=item.alert.severity.value,
                    decision=item.judgment.action.value,
                    escalation=item.escalation.level.value,
                )
                for item in result.alerts
            ],
            incidents=incidents,
            ledger_verified=ledger_verified,
        )

    def list_incidents(self, filters: Dict[str, str]) -> IncidentListResponse:
        with self._lock:
            summaries = self.pipeline.incidents.list(**filters)
        return IncidentListResponse(incidents=summaries, count=len(summaries))

    def get_incident(self, finding_id: str) -> IncidentDetail:
        with self._lock:
            return self.pipeline.incidents.get(finding_id)

    def get_timeline(self, finding_id: str) -> List[IncidentTimelineStep]:
        with self._lock:
            return self.pipeline.incidents.timeline(finding_id)

    def transition_incident(
        self, finding_id: str, payload: Dict[str, Any]
    ) -> IncidentDetail:
        request = IncidentTransitionRequest.model_validate(payload)
        with self._lock:
            return self.pipeline.transition_incident(
                finding_id,
                request.action,
                actor=request.actor,
                reason=request.reason,
            )

    def _case_components(self) -> Tuple[CaseService, CasePrincipal]:
        if self.case_service is None or self.case_principal is None:
            raise RuntimeError("case_not_configured")
        return self.case_service, self.case_principal

    def list_cases(self, filters: Dict[str, str]) -> Any:
        if set(filters) - {"status", "priority", "assigned_to", "team_id", "limit", "offset"}:
            raise ValueError("unknown case filter")
        service, principal = self._case_components()
        return service.list(
            principal,
            status=CaseStatus(filters["status"]) if "status" in filters else None,
            priority=filters.get("priority"),
            assigned_to=filters.get("assigned_to"),
            team_id=filters.get("team_id"),
            limit=int(filters.get("limit", "100")),
            offset=int(filters.get("offset", "0")),
        )

    def get_case(self, case_id: str) -> Any:
        service, principal = self._case_components()
        return service.get(principal, case_id)

    def case_health(self) -> Any:
        service, principal = self._case_components()
        return service.health(principal)

    def case_teams(self) -> List[Any]:
        service, principal = self._case_components()
        return service.list_teams(principal)

    def case_team_create(self, payload: Dict[str, Any]) -> Any:
        request = CaseTeamCreateRequest.model_validate(payload)
        service, principal = self._case_components()
        return service.create_team(
            principal,
            team_id=request.team_id,
            name=request.name,
            description=request.description,
            member_ids=request.member_ids,
        )

    def case_assign(self, case_id: str, payload: Dict[str, Any]) -> Any:
        request = CaseAssignmentRequest.model_validate(payload)
        service, principal = self._case_components()
        return service.assign(
            principal,
            case_id,
            expected_version=request.expected_version,
            assigned_to=request.assigned_to,
            team_id=request.team_id,
        )

    def case_comment(self, case_id: str, payload: Dict[str, Any]) -> Any:
        request = CaseCommentRequest.model_validate(payload)
        service, principal = self._case_components()
        return service.add_comment(
            principal,
            case_id,
            expected_version=request.expected_version,
            body=request.body,
        )

    def case_task(self, case_id: str, payload: Dict[str, Any]) -> Any:
        request = CaseTaskCreateRequest.model_validate(payload)
        service, principal = self._case_components()
        return service.create_task(
            principal,
            case_id,
            expected_version=request.expected_version,
            title=request.title,
            description=request.description,
            assigned_to=request.assigned_to,
            due_at=request.due_at,
        )

    def case_task_transition(
        self, case_id: str, task_id: str, payload: Dict[str, Any]
    ) -> Any:
        request = CaseTaskTransitionRequest.model_validate(payload)
        service, principal = self._case_components()
        return service.transition_task(
            principal,
            case_id,
            task_id,
            expected_version=request.expected_version,
            status=request.status,
        )

    def case_attachment(self, case_id: str, payload: Dict[str, Any]) -> Any:
        request = CaseAttachmentRequest.model_validate(payload)
        service, principal = self._case_components()
        return service.add_attachment(
            principal,
            case_id,
            expected_version=request.expected_version,
            display_name=request.display_name,
            media_type=request.media_type,
            size_bytes=request.size_bytes,
            content_sha256=request.content_sha256,
            evidence_ref=request.evidence_ref,
        )

    def case_attachment_scan(
        self, case_id: str, attachment_id: str, payload: Dict[str, Any]
    ) -> Any:
        request = CaseAttachmentScanRequest.model_validate(payload)
        service, principal = self._case_components()
        return service.record_attachment_scan(
            principal,
            case_id,
            attachment_id,
            expected_version=request.expected_version,
            status=AttachmentScanStatus(request.status),
            scanner_ref=request.scanner_ref,
        )

    def case_relationship(self, case_id: str, payload: Dict[str, Any]) -> Any:
        request = CaseRelationshipRequest.model_validate(payload)
        service, principal = self._case_components()
        return service.add_relationship(
            principal,
            case_id,
            expected_version=request.expected_version,
            kind=request.kind,
            target_type=request.target_type,
            target_id=request.target_id,
            reason=request.reason,
        )

    def case_acknowledge(self, case_id: str, payload: Dict[str, Any]) -> Any:
        request = CaseLifecycleRequest.model_validate(payload)
        service, principal = self._case_components()
        return service.acknowledge(
            principal, case_id, expected_version=request.expected_version
        )

    def case_start(self, case_id: str, payload: Dict[str, Any]) -> Any:
        request = CaseLifecycleRequest.model_validate(payload)
        service, principal = self._case_components()
        return service.start_investigation(
            principal, case_id, expected_version=request.expected_version
        )

    def case_request_review(self, case_id: str, payload: Dict[str, Any]) -> Any:
        request = CaseLifecycleRequest.model_validate(payload)
        service, principal = self._case_components()
        principal = principal.model_copy(
            update={"actor_id": "system://local-case-requester"}
        )
        return service.request_review(
            principal, case_id, expected_version=request.expected_version
        )

    def case_review(self, case_id: str, payload: Dict[str, Any]) -> Any:
        request = CaseReviewRequest.model_validate(payload)
        service, principal = self._case_components()
        principal = principal.model_copy(
            update={"actor_id": "system://local-case-reviewer"}
        )
        return service.review(
            principal,
            case_id,
            expected_version=request.expected_version,
            decision=request.decision,
            comment=request.comment,
        )

    def case_close(self, case_id: str, payload: Dict[str, Any]) -> Any:
        request = CaseLifecycleRequest.model_validate(payload)
        service, principal = self._case_components()
        return service.close_case(
            principal, case_id, expected_version=request.expected_version
        )

    def _notification_components(
        self,
    ) -> Tuple[NotificationService, NotificationPrincipal]:
        if self.notification_service is None or self.notification_principal is None:
            raise RuntimeError("notification_not_configured")
        return self.notification_service, self.notification_principal

    def list_notifications(self, filters: Dict[str, str]) -> Any:
        if set(filters) - {"limit", "offset"}:
            raise ValueError("unknown notification filter")
        service, principal = self._notification_components()
        return service.list(
            principal,
            limit=int(filters.get("limit", "100")),
            offset=int(filters.get("offset", "0")),
        )

    def get_notification(self, notification_id: str) -> Any:
        service, principal = self._notification_components()
        return service.get(principal, notification_id)

    def notification_health(self) -> Any:
        service, principal = self._notification_components()
        return service.health(principal)

    def notification_destinations(self) -> Any:
        service, principal = self._notification_components()
        return service.destinations(principal)

    def notification_process(self, payload: Dict[str, Any]) -> Any:
        request = NotificationProcessRequest.model_validate(payload)
        service, principal = self._notification_components()
        return service.process_due(principal, limit=request.limit)

    def notification_acknowledge(
        self, notification_id: str, payload: Dict[str, Any]
    ) -> Any:
        request = NotificationAcknowledgeRequest.model_validate(payload)
        service, principal = self._notification_components()
        current = service.get(principal, notification_id).notification
        on_call = principal.model_copy(update={"actor_id": current.on_call_actor})
        return service.acknowledge(
            on_call,
            notification_id,
            expected_version=request.expected_version,
            note=request.note,
        )

    def notification_provider_acknowledge(
        self, delivery_id: str, payload: Dict[str, Any]
    ) -> Any:
        request = ProviderAcknowledgeRequest.model_validate(payload)
        service, principal = self._notification_components()
        return service.acknowledge_provider_delivery(
            principal,
            delivery_id,
            provider_receipt_sha256=request.provider_receipt_sha256,
        )

    def notification_redrive(
        self, delivery_id: str, payload: Dict[str, Any]
    ) -> Any:
        request = NotificationRedriveRequest.model_validate(payload)
        service, principal = self._notification_components()
        return service.redrive(principal, delivery_id, reason=request.reason)

    def _response_components(
        self,
    ) -> Tuple[ResponseAutomationService, ResponsePrincipal]:
        if self.response_service is None or self.response_principal is None:
            raise RuntimeError("response_not_configured")
        return self.response_service, self.response_principal

    @staticmethod
    def _response_actor(
        principal: ResponsePrincipal,
        actor_id: str,
        permissions: Set[str],
    ) -> ResponsePrincipal:
        """Create a fixed, least-privilege service-side response identity.

        The HTTP caller never supplies an actor or permission.  Each endpoint
        maps to one narrowly scoped identity so request, approval, execution,
        review, and publication remain independently attributable.
        """

        return ResponsePrincipal(
            tenant_id=principal.tenant_id,
            actor_id=actor_id,
            permissions={RESPONSE_READ, *permissions},
        )

    def response_executions(self, filters: Dict[str, str]) -> Any:
        if set(filters) - {"limit", "offset"}:
            raise ValueError("unknown response execution filter")
        service, principal = self._response_components()
        return service.list(
            principal,
            limit=int(filters.get("limit", "100")),
            offset=int(filters.get("offset", "0")),
        )

    def response_execution(self, execution_id: str) -> Any:
        service, principal = self._response_components()
        return service.get(principal, execution_id)

    def response_health(self) -> Any:
        service, principal = self._response_components()
        return service.health(principal)

    def response_connectors(self) -> List[Any]:
        service, principal = self._response_components()
        return service.connectors_status(principal)

    def response_control(self) -> Any:
        service, principal = self._response_components()
        return service.control(principal)

    def response_playbooks(self, filters: Dict[str, str]) -> Any:
        if set(filters) - {"limit", "offset"}:
            raise ValueError("unknown response playbook filter")
        service, principal = self._response_components()
        return service.list_playbooks(
            principal,
            limit=int(filters.get("limit", "100")),
            offset=int(filters.get("offset", "0")),
        )

    def response_request_live(self, execution_id: str, payload: Dict[str, Any]) -> Any:
        request = ResponseMutationRequest.model_validate(payload)
        service, principal = self._response_components()
        operator = self._response_actor(
            principal,
            "analyst://local-response-operator",
            {RESPONSE_OPERATE},
        )
        return service.request_live(
            operator,
            execution_id,
            expected_version=request.expected_version,
            reason=request.reason,
        )

    def response_approve(
        self, execution_id: str, payload: Dict[str, Any], *, rollback: bool = False
    ) -> Any:
        request = ResponseApprovalRequest.model_validate(payload)
        service, principal = self._response_components()
        actor = (
            "analyst://local-response-rollback-approver"
            if rollback
            else "analyst://local-response-approver"
        )
        approver = self._response_actor(principal, actor, {RESPONSE_APPROVE})
        return service.approve(
            approver,
            execution_id,
            scope=ApprovalScope.ROLLBACK if rollback else ApprovalScope.EXECUTE,
            expected_version=request.expected_version,
            reason=request.reason,
            ttl_minutes=request.ttl_minutes,
        )

    def response_execute(
        self, execution_id: str, payload: Dict[str, Any], *, rollback: bool = False
    ) -> Any:
        ResponseEmptyRequest.model_validate(payload)
        service, principal = self._response_components()
        executor = self._response_actor(
            principal,
            "system://local-response-executor",
            {RESPONSE_EXECUTE},
        )
        return (
            service.rollback(executor, execution_id)
            if rollback
            else service.execute(executor, execution_id)
        )

    def response_request_rollback(
        self, execution_id: str, payload: Dict[str, Any]
    ) -> Any:
        request = ResponseMutationRequest.model_validate(payload)
        service, principal = self._response_components()
        operator = self._response_actor(
            principal,
            "analyst://local-response-operator",
            {RESPONSE_OPERATE},
        )
        return service.request_rollback(
            operator,
            execution_id,
            expected_version=request.expected_version,
            reason=request.reason,
        )

    def response_set_kill_switch(self, payload: Dict[str, Any]) -> Any:
        request = ResponseKillSwitchRequest.model_validate(payload)
        service, principal = self._response_components()
        administrator = self._response_actor(
            principal,
            "system://local-response-administrator",
            {RESPONSE_ADMIN},
        )
        return service.set_kill_switch(
            administrator,
            active=request.active,
            expected_version=request.expected_version,
            reason=request.reason,
        )

    def response_create_playbook(self, payload: Dict[str, Any]) -> Any:
        request = ResponsePlaybookCreateRequest.model_validate(payload)
        service, principal = self._response_components()
        author = self._response_actor(
            principal,
            "analyst://local-response-author",
            {RESPONSE_AUTHOR},
        )
        return service.create_playbook_draft(author, request.definition)

    def response_playbook_action(self, payload: Dict[str, Any]) -> Any:
        request = ResponsePlaybookActionRequest.model_validate(payload)
        service, principal = self._response_components()
        actor = {
            "submit": "analyst://local-response-author",
            "approve": "analyst://local-response-reviewer",
            "reject": "analyst://local-response-reviewer",
            "activate": "system://local-response-publisher",
            "retire": "system://local-response-publisher",
        }[request.action]
        permission = (
            RESPONSE_AUTHOR
            if request.action == "submit"
            else RESPONSE_REVIEW
            if request.action in {"approve", "reject"}
            else RESPONSE_ADMIN
        )
        scoped = self._response_actor(principal, actor, {permission})
        return service.playbook_action(
            scoped,
            request.playbook_id,
            request.version,
            action=request.action,
            expected_revision=request.expected_revision,
            comment=request.comment,
        )

    def assert_external_tenant(self, principal: ExternalApiPrincipal) -> None:
        if (
            self.product_tenant_id is not None
            and principal.tenant_id != self.product_tenant_id
        ):
            raise ExternalApiAuthorizationError("external API tenant denied")

    def _integration_components(
        self,
    ) -> Tuple[IntegrationService, IntegrationPrincipal]:
        if self.integration_service is None or self.integration_principal is None:
            raise RuntimeError("integration_not_configured")
        return self.integration_service, self.integration_principal

    def public_capabilities(self, principal: ExternalApiPrincipal) -> Any:
        self.assert_external_tenant(principal)
        service, integration_principal = self._integration_components()
        return service.capabilities(integration_principal)

    def public_events(
        self, principal: ExternalApiPrincipal, filters: Dict[str, str]
    ) -> Any:
        self.assert_external_tenant(principal)
        if set(filters) - {"limit", "cursor", "event_types"}:
            raise ValueError("unknown external event filter")
        service, integration_principal = self._integration_components()
        event_types = filters.get("event_types")
        return service.stream_events(
            integration_principal,
            limit=int(filters.get("limit", "100")),
            cursor=filters.get("cursor"),
            event_types=event_types.split(",") if event_types else None,
        )

    def public_integrations(
        self, principal: ExternalApiPrincipal
    ) -> Dict[str, Any]:
        self.assert_external_tenant(principal)
        service, integration_principal = self._integration_components()
        return {
            "schema_version": "1.0.0",
            "health": service.health(integration_principal).model_dump(mode="json"),
            "destinations": [
                item.model_dump(mode="json")
                for item in service.destinations(integration_principal)
            ],
        }

    def public_deliveries(
        self, principal: ExternalApiPrincipal, filters: Dict[str, str]
    ) -> Any:
        self.assert_external_tenant(principal)
        if set(filters) - {"state", "destination_id", "limit", "offset"}:
            raise ValueError("unknown integration delivery filter")
        service, integration_principal = self._integration_components()
        return service.list_deliveries(
            integration_principal,
            state=(
                IntegrationDeliveryState(filters["state"])
                if "state" in filters
                else None
            ),
            destination_id=filters.get("destination_id"),
            limit=int(filters.get("limit", "100")),
            offset=int(filters.get("offset", "0")),
        )

    def public_delivery(
        self, principal: ExternalApiPrincipal, delivery_id: str
    ) -> Any:
        self.assert_external_tenant(principal)
        service, integration_principal = self._integration_components()
        return service.get_delivery(integration_principal, delivery_id)

    def public_integration_process(
        self, principal: ExternalApiPrincipal, payload: Dict[str, Any]
    ) -> Any:
        self.assert_external_tenant(principal)
        request = IntegrationProcessRequest.model_validate(payload)
        service, integration_principal = self._integration_components()
        return service.process_due(integration_principal, limit=request.limit)

    def public_integration_redrive(
        self,
        principal: ExternalApiPrincipal,
        delivery_id: str,
        payload: Dict[str, Any],
    ) -> Any:
        self.assert_external_tenant(principal)
        request = IntegrationRedriveRequest.model_validate(payload)
        service, integration_principal = self._integration_components()
        return service.redrive(
            integration_principal, delivery_id, reason=request.reason
        )

    def public_findings(
        self, principal: ExternalApiPrincipal, filters: Dict[str, str]
    ) -> Dict[str, Any]:
        self.assert_external_tenant(principal)
        page_fields = {"limit", "offset"}
        incident_fields = {
            "event_id", "flow_id", "alert_type", "agent_id", "severity",
            "priority", "status", "created_at",
        }
        if set(filters) - page_fields - incident_fields:
            raise ValueError("unknown finding filter")
        incident_filters = {
            key: value for key, value in filters.items() if key in incident_fields
        }
        limit = int(filters.get("limit", "100"))
        offset = int(filters.get("offset", "0"))
        if not 1 <= limit <= 200 or not 0 <= offset <= 1_000_000:
            raise ValueError("finding page is invalid")
        summaries = self.pipeline.incidents.list(**incident_filters)
        tenant_summaries = []
        for summary in summaries:
            detail = self.pipeline.incidents.get(summary.finding_id)
            if (
                detail.event_context is not None
                and detail.event_context.tenant_id == principal.tenant_id
            ):
                tenant_summaries.append(summary)
        selected = tenant_summaries[offset : offset + limit]
        return {
            "schema_version": "2.0.0",
            "findings": [item.model_dump(mode="json") for item in selected],
            "count": len(selected),
            "total": len(tenant_summaries),
        }

    def public_finding(
        self, principal: ExternalApiPrincipal, finding_id: str
    ) -> Any:
        self.assert_external_tenant(principal)
        detail = self.get_incident(finding_id)
        if (
            detail.event_context is None
            or detail.event_context.tenant_id != principal.tenant_id
        ):
            raise KeyError(finding_id)
        return detail

    def _search_components(
        self,
    ) -> Tuple[SearchService, SearchPrincipal, CanonicalRepository]:
        if (
            self.search_service is None
            or self.search_principal is None
            or self.canonical_repository is None
        ):
            raise RuntimeError("search_not_configured")
        return self.search_service, self.search_principal, self.canonical_repository

    def search(self, payload: Dict[str, Any]) -> Any:
        service, principal, _ = self._search_components()
        return service.search(principal, SearchRequest.model_validate(payload))

    def aggregate(self, payload: Dict[str, Any]) -> Any:
        if set(payload) - {"query", "field", "limit"}:
            raise ValueError("unknown aggregation field")
        service, principal, _ = self._search_components()
        return service.aggregate(
            principal,
            query=str(payload.get("query", "*")),
            field=str(payload.get("field", "record_type")),
            limit=int(payload.get("limit", 20)),
        )

    def list_hunts(self) -> List[Any]:
        service, principal, _ = self._search_components()
        return service.list_hunts(principal)

    def save_hunt(self, payload: Dict[str, Any]) -> Any:
        if set(payload) - {"name", "description", "query", "sort_by", "sort_order"}:
            raise ValueError("unknown saved-hunt field")
        service, principal, _ = self._search_components()
        return service.save_hunt(
            principal,
            name=str(payload["name"]),
            description=str(payload.get("description", "")),
            query=str(payload["query"]),
            sort_by=str(payload.get("sort_by", "created_at")),
            sort_order=str(payload.get("sort_order", "desc")),
        )

    def execute_hunt(self, hunt_id: str, payload: Dict[str, Any]) -> Any:
        if set(payload) - {"page_size"}:
            raise ValueError("unknown saved-hunt execution field")
        service, principal, _ = self._search_components()
        return service.execute_hunt(
            principal, hunt_id, page_size=int(payload.get("page_size", 50))
        )

    def update_hunt(self, hunt_id: str, payload: Dict[str, Any]) -> Any:
        if set(payload) - {"name", "description", "query", "sort_by", "sort_order"}:
            raise ValueError("unknown saved-hunt field")
        service, principal, _ = self._search_components()
        current = service.get_hunt(principal, hunt_id)
        return service.update_hunt(
            principal,
            hunt_id,
            name=str(payload.get("name", current.name)),
            description=str(payload.get("description", current.description)),
            query=str(payload.get("query", current.query)),
            sort_by=str(payload.get("sort_by", current.sort_by)),
            sort_order=str(payload.get("sort_order", current.sort_order)),
        )

    def delete_hunt(self, hunt_id: str) -> None:
        service, principal, _ = self._search_components()
        service.delete_hunt(principal, hunt_id)

    def evidence_pivot(self, evidence_id: str) -> Any:
        service, principal, repository = self._search_components()
        return service.evidence_pivot(principal, repository, evidence_id)

    def _inventory_components(self) -> Tuple[InventoryService, InventoryPrincipal]:
        if self.inventory_service is None or self.inventory_principal is None:
            raise RuntimeError("inventory_not_configured")
        return self.inventory_service, self.inventory_principal

    def inventory_list(self, filters: Dict[str, str]) -> Any:
        allowed = {
            "kind", "status", "owner_ref", "application_id", "minimum_risk", "limit", "offset"
        }
        if set(filters) - allowed:
            raise ValueError("unknown inventory filter")
        service, principal = self._inventory_components()
        return service.list_components(
            principal,
            kind=ComponentKind(filters["kind"]) if "kind" in filters else None,
            status=ComponentStatus(filters["status"]) if "status" in filters else None,
            owner_ref=filters.get("owner_ref"),
            application_id=filters.get("application_id"),
            minimum_risk=int(filters.get("minimum_risk", "0")),
            limit=int(filters.get("limit", "100")),
            offset=int(filters.get("offset", "0")),
        )

    def inventory_summary(self) -> Any:
        service, principal = self._inventory_components()
        return service.summary(principal)

    def inventory_detail(self, component_id: str) -> Any:
        service, principal = self._inventory_components()
        return service.detail(principal, component_id)

    def inventory_discover(self, payload: Dict[str, Any]) -> Any:
        service, principal = self._inventory_components()
        return service.discover(principal, InventoryObservation.model_validate(payload))

    def inventory_governance(self, component_id: str, payload: Dict[str, Any]) -> Any:
        if set(payload) != {"owner_ref", "criticality", "status"}:
            raise ValueError("inventory governance fields must be exact")
        service, principal = self._inventory_components()
        return service.set_governance(
            principal,
            component_id,
            owner_ref=payload["owner_ref"],
            criticality=Severity(str(payload["criticality"])),
            status=ComponentStatus(str(payload["status"])),
        )

    def _graph_components(self) -> Tuple[SecurityGraphService, GraphPrincipal]:
        if self.graph_service is None or self.graph_principal is None:
            raise RuntimeError("graph_not_configured")
        return self.graph_service, self.graph_principal

    @staticmethod
    def _graph_time(value: Any) -> Optional[datetime]:
        if value in {None, ""}:
            return None
        if not isinstance(value, str) or len(value) > 64:
            raise ValueError("graph time is invalid")
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("graph time must include a timezone")
        return parsed

    def graph_snapshot(self, filters: Dict[str, str]) -> Any:
        if set(filters) - {"as_of"}:
            raise ValueError("unknown graph filter")
        service, principal = self._graph_components()
        return service.snapshot(principal, as_of=self._graph_time(filters.get("as_of")))

    def graph_summary(self, filters: Dict[str, str]) -> Any:
        if set(filters) - {"as_of"}:
            raise ValueError("unknown graph filter")
        service, principal = self._graph_components()
        return service.summary(principal, as_of=self._graph_time(filters.get("as_of")))

    def graph_reachability(self, payload: Dict[str, Any]) -> Any:
        if set(payload) - {"origin_node_id", "direction", "max_depth", "max_nodes", "as_of"}:
            raise ValueError("unknown graph reachability field")
        if "origin_node_id" not in payload:
            raise ValueError("origin_node_id is required")
        service, principal = self._graph_components()
        return service.reachability(
            principal,
            str(payload["origin_node_id"]),
            direction=str(payload.get("direction", "outbound")),
            max_depth=int(payload.get("max_depth", 8)),
            max_nodes=int(payload.get("max_nodes", 5000)),
            as_of=self._graph_time(payload.get("as_of")),
        )

    def graph_blast_radius(self, payload: Dict[str, Any]) -> Any:
        if set(payload) - {"origin_node_id", "max_depth", "as_of"}:
            raise ValueError("unknown graph blast-radius field")
        if "origin_node_id" not in payload:
            raise ValueError("origin_node_id is required")
        service, principal = self._graph_components()
        return service.blast_radius(
            principal,
            str(payload["origin_node_id"]),
            max_depth=int(payload.get("max_depth", 8)),
            as_of=self._graph_time(payload.get("as_of")),
        )

    def graph_attack_paths(self, payload: Dict[str, Any]) -> Any:
        allowed = {
            "source_node_id", "target_node_id", "max_paths", "max_depth", "max_states", "as_of"
        }
        if set(payload) - allowed:
            raise ValueError("unknown graph attack-path field")
        if not {"source_node_id", "target_node_id"}.issubset(payload):
            raise ValueError("graph attack-path endpoints are required")
        service, principal = self._graph_components()
        return service.attack_paths(
            principal,
            str(payload["source_node_id"]),
            str(payload["target_node_id"]),
            max_paths=int(payload.get("max_paths", 5)),
            max_depth=int(payload.get("max_depth", 12)),
            max_states=int(payload.get("max_states", 20000)),
            as_of=self._graph_time(payload.get("as_of")),
        )

    def _posture_components(self) -> Tuple[PostureService, PosturePrincipal]:
        if self.posture_service is None or self.posture_principal is None:
            raise RuntimeError("posture_not_configured")
        return self.posture_service, self.posture_principal

    def _inventory_snapshot(self) -> List[Any]:
        inventory, principal = self._inventory_components()
        components: List[Any] = []
        offset = 0
        while True:
            page = inventory.list_components(principal, limit=200, offset=offset)
            components.extend(page.components)
            offset += len(page.components)
            if offset >= page.total:
                return components

    def posture_summary(self) -> Any:
        service, principal = self._posture_components()
        return service.summary(principal)

    def posture_checks(self, filters: Dict[str, str]) -> List[Any]:
        if set(filters) - {"history"}:
            raise ValueError("unknown posture check filter")
        history = filters.get("history", "false")
        if history not in {"true", "false"}:
            raise ValueError("posture check history filter is invalid")
        service, principal = self._posture_components()
        return service.list_checks(principal, history=history == "true")

    def posture_findings(self, filters: Dict[str, str]) -> Any:
        allowed = {"status", "severity", "check_id", "component_id", "limit", "offset"}
        if set(filters) - allowed:
            raise ValueError("unknown posture finding filter")
        service, principal = self._posture_components()
        return service.list_findings(
            principal,
            status=PostureFindingStatus(filters["status"]) if "status" in filters else None,
            severity=Severity(filters["severity"]) if "severity" in filters else None,
            check_id=filters.get("check_id"), component_id=filters.get("component_id"),
            limit=int(filters.get("limit", "100")), offset=int(filters.get("offset", "0")),
        )

    def posture_detail(self, finding_id: str) -> Any:
        service, principal = self._posture_components()
        return service.detail(principal, finding_id)

    def posture_trends(self, filters: Dict[str, str]) -> Any:
        if set(filters) - {"limit"}:
            raise ValueError("unknown posture trend filter")
        service, principal = self._posture_components()
        return service.trends(principal, limit=int(filters.get("limit", "30")))

    def posture_scan(self, payload: Dict[str, Any]) -> Any:
        if set(payload) - {"check_ids"}:
            raise ValueError("unknown posture scan field")
        check_ids = payload.get("check_ids")
        if check_ids is not None and (
            not isinstance(check_ids, list) or any(not isinstance(item, str) for item in check_ids)
        ):
            raise ValueError("posture check IDs must be a list of strings")
        service, principal = self._posture_components()
        return service.scan(principal, self._inventory_snapshot(), check_ids=check_ids)

    def posture_exception(self, finding_id: str, payload: Dict[str, Any]) -> Any:
        if set(payload) != {"reason", "owner_ref", "approved_by", "expires_at"}:
            raise ValueError("posture exception fields must be exact")
        service, principal = self._posture_components()
        expires_at = self._graph_time(payload["expires_at"])
        if expires_at is None:
            raise ValueError("posture exception expiry is required")
        return service.create_exception(
            principal, finding_id, reason=str(payload["reason"]),
            owner_ref=str(payload["owner_ref"]), approved_by=str(payload["approved_by"]),
            expires_at=expires_at,
        )

    def posture_revoke_exception(self, exception_id: str, payload: Dict[str, Any]) -> Any:
        if set(payload) != {"reason"}:
            raise ValueError("posture exception revocation fields must be exact")
        service, principal = self._posture_components()
        return service.revoke_exception(principal, exception_id, reason=str(payload["reason"]))

    def _detection_components(self) -> Tuple[DetectionService, DetectionPrincipal]:
        if self.detection_service is None or self.detection_principal is None:
            raise RuntimeError("detection_not_configured")
        return self.detection_service, self.detection_principal

    def detection_rules(self) -> List[Any]:
        service, principal = self._detection_components()
        return service.list_rules(principal)

    def detection_health(self) -> List[Any]:
        service, principal = self._detection_components()
        return service.health(principal)

    def detection_scheduled(self, payload: Dict[str, Any]) -> Any:
        if set(payload) - {"as_of", "rule_ids"}:
            raise ValueError("unknown scheduled detection field")
        rule_ids = payload.get("rule_ids")
        if rule_ids is not None and (
            not isinstance(rule_ids, list)
            or any(not isinstance(item, str) for item in rule_ids)
        ):
            raise ValueError("scheduled detection rule IDs must be a list of strings")
        service, principal = self._detection_components()
        return service.run_scheduled(
            principal,
            as_of=self._graph_time(payload.get("as_of")),
            rule_ids=rule_ids,
        )

    def _content_components(
        self, role: str = "author"
    ) -> Tuple[DetectionContentService, ContentPrincipal]:
        if self.content_service is None or self.content_principal is None:
            raise RuntimeError("content_not_configured")
        if role not in {"author", "reviewer", "publisher"}:
            raise ValueError("content service role is invalid")
        principal = self.content_principal.model_copy(
            update={"actor_id": "system://local-content-%s" % role}
        )
        return self.content_service, principal

    def content_list(self, filters: Dict[str, str]) -> List[Any]:
        if set(filters) - {"status", "limit", "offset"}:
            raise ValueError("unknown content filter")
        service, principal = self._content_components()
        return service.list(
            principal,
            status=RuleContentStatus(filters["status"]) if "status" in filters else None,
            limit=int(filters.get("limit", "100")),
            offset=int(filters.get("offset", "0")),
        )

    def content_detail(self, content_id: str) -> Any:
        service, principal = self._content_components()
        return service.get(principal, content_id)

    def content_history(self, content_id: str) -> List[Any]:
        service, principal = self._content_components()
        return service.history(principal, content_id)

    def content_health(self) -> Any:
        service, principal = self._content_components()
        return service.health(principal)

    def content_packs(self) -> List[Any]:
        service, principal = self._content_components()
        return service.list_packs(principal)

    def content_create(self, payload: Dict[str, Any]) -> Any:
        if set(payload) != {"definition"}:
            raise ValueError("content creation fields must be exact")
        service, principal = self._content_components()
        return service.create_draft(
            principal, DetectionRuleDefinition.model_validate(payload["definition"])
        )

    def content_update(self, content_id: str, payload: Dict[str, Any]) -> Any:
        if set(payload) != {"definition"}:
            raise ValueError("content update fields must be exact")
        service, principal = self._content_components()
        return service.update_draft(
            principal, content_id,
            DetectionRuleDefinition.model_validate(payload["definition"]),
        )

    def content_action(self, content_id: str, action: str, payload: Dict[str, Any]) -> Any:
        role = (
            "reviewer" if action == "review"
            else "publisher" if action in {"shadow", "shadow-evaluate", "publish", "rollback"}
            else "author"
        )
        service, principal = self._content_components(role)
        if action == "validate":
            if set(payload) != {"suite"}:
                raise ValueError("content validation fields must be exact")
            return service.validate(
                principal, content_id, RuleTestSuite.model_validate(payload["suite"])
            )
        if action in {"backtest", "shadow-evaluate"}:
            if set(payload) != {"events"} or not isinstance(payload["events"], list):
                raise ValueError("content evaluation fields must be exact")
            events = [AgentEvent.model_validate(item) for item in payload["events"]]
            return service.backtest(
                principal, content_id, events, shadow=action == "shadow-evaluate"
            )
        if action == "submit":
            if payload:
                raise ValueError("content submission accepts no fields")
            return service.submit(principal, content_id)
        if action == "review":
            if set(payload) != {"decision", "comment"}:
                raise ValueError("content review fields must be exact")
            return service.review(
                principal, content_id, ReviewDecision(str(payload["decision"])),
                str(payload["comment"]),
            )
        if action == "shadow":
            if payload:
                raise ValueError("shadow deployment accepts no fields")
            return service.deploy_shadow(principal, content_id)
        if action == "publish":
            if set(payload) != {"expected_definition_sha256"}:
                raise ValueError("content publication fields must be exact")
            return service.publish(
                principal, content_id,
                expected_definition_sha256=str(payload["expected_definition_sha256"]),
            )
        if action == "rollback":
            if set(payload) != {"new_version", "reason"}:
                raise ValueError("content rollback fields must be exact")
            return service.rollback(
                principal, content_id, new_version=str(payload["new_version"]),
                reason=str(payload["reason"]),
            )
        raise ValueError("unknown content action")

    def content_pack_export(self, payload: Dict[str, Any]) -> Any:
        if set(payload) != {"content_ids", "name", "description", "version"}:
            raise ValueError("content pack export fields must be exact")
        if not isinstance(payload["content_ids"], list) or any(
            not isinstance(item, str) for item in payload["content_ids"]
        ):
            raise ValueError("content pack IDs must be strings")
        service, principal = self._content_components("publisher")
        return service.export_pack(
            principal, payload["content_ids"], name=str(payload["name"]),
            description=str(payload["description"]), version=str(payload["version"]),
        )

    def content_pack_import(self, payload: Dict[str, Any]) -> List[Any]:
        if set(payload) != {"pack"}:
            raise ValueError("content pack import fields must be exact")
        service, principal = self._content_components()
        return service.import_pack(
            principal, SignedContentPack.model_validate(payload["pack"])
        )

    def enrichment_health(self) -> Any:
        if self.enrichment_principal is None:
            raise RuntimeError("enrichment_not_configured")
        return self.pipeline.enricher.health(self.enrichment_principal)

    def _analyst_components(self) -> Tuple[AiAnalystService, AnalystPrincipal]:
        if self.analyst_service is None or self.analyst_principal is None:
            raise RuntimeError("analyst_not_configured")
        return self.analyst_service, self.analyst_principal

    def analyst_runs(self, filters: Dict[str, str]) -> List[Any]:
        if set(filters) - {"limit", "offset"}:
            raise ValueError("unknown analyst run filter")
        service, principal = self._analyst_components()
        return service.list_runs(
            principal,
            limit=int(filters.get("limit", "100")),
            offset=int(filters.get("offset", "0")),
        )

    def analyst_run(self, run_id: str) -> Any:
        service, principal = self._analyst_components()
        return service.get(principal, run_id)

    def analyst_run_for_finding(self, finding_id: str) -> Any:
        service, principal = self._analyst_components()
        return service.get_for_finding(principal, finding_id)

    def analyst_feedback(self, filters: Dict[str, str]) -> List[Any]:
        if set(filters) - {"run_id"}:
            raise ValueError("unknown analyst feedback filter")
        service, principal = self._analyst_components()
        return service.list_feedback(principal, run_id=filters.get("run_id"))

    def analyst_add_feedback(self, run_id: str, payload: Dict[str, Any]) -> Any:
        if set(payload) not in ({"rating", "reason"}, {"rating", "reason", "role"}):
            raise ValueError("analyst feedback fields must be exact")
        service, principal = self._analyst_components()
        return service.add_feedback(
            principal,
            run_id,
            rating=AnalystFeedbackRating(str(payload["rating"])),
            reason=str(payload["reason"]),
            role=AnalystRole(str(payload["role"])) if payload.get("role") else None,
        )

    def analyst_health(self) -> Any:
        service, principal = self._analyst_components()
        return service.health(principal)

    def _model_gateway_components(
        self,
    ) -> Tuple[ModelGatewayService, ModelGatewayPrincipal]:
        if self.model_gateway_service is None or self.model_gateway_principal is None:
            raise RuntimeError("model_gateway_not_configured")
        return self.model_gateway_service, self.model_gateway_principal

    def model_gateway_health(self) -> Any:
        service, principal = self._model_gateway_components()
        return service.health(principal)

    def model_gateway_routes(self) -> List[Any]:
        service, principal = self._model_gateway_components()
        return service.list_routes(principal)

    def model_gateway_prompts(self) -> List[Any]:
        service, principal = self._model_gateway_components()
        return service.list_prompts(principal)

    def model_gateway_qualifications(self) -> List[Any]:
        service, principal = self._model_gateway_components()
        return service.list_qualifications(principal)

    def model_gateway_calls(self, filters: Dict[str, str]) -> List[Any]:
        if set(filters) - {"limit", "offset"}:
            raise ValueError("unknown model gateway call filter")
        service, principal = self._model_gateway_components()
        return service.list_calls(
            principal,
            limit=int(filters.get("limit", "100")),
            offset=int(filters.get("offset", "0")),
        )

    def model_gateway_secrets(self) -> List[Any]:
        service, principal = self._model_gateway_components()
        return service.list_secrets(principal)

    def model_gateway_audit(self, filters: Dict[str, str]) -> List[Any]:
        if set(filters) - {"limit"}:
            raise ValueError("unknown model gateway audit filter")
        service, principal = self._model_gateway_components()
        return service.audit(principal, limit=int(filters.get("limit", "100")))

    def model_gateway_qualify(
        self, route_id: str, revision: int, payload: Dict[str, Any]
    ) -> Any:
        required = {
            "test_suite_version", "evidence_sha256", "metrics", "reviewed_by"
        }
        if set(payload) not in (required, required | {"valid_for_hours"}):
            raise ValueError("model qualification fields must be exact")
        service, principal = self._model_gateway_components()
        return service.qualify(
            principal,
            route_id=route_id,
            revision=revision,
            test_suite_version=str(payload["test_suite_version"]),
            evidence_sha256=str(payload["evidence_sha256"]),
            metrics=QualificationMetrics.model_validate(payload["metrics"]),
            reviewed_by=str(payload["reviewed_by"]),
            valid_for_hours=int(payload.get("valid_for_hours", 168)),
        )

    def model_gateway_register_prompt(self, payload: Dict[str, Any]) -> Any:
        if set(payload) != {
            "prompt_id", "version", "workload", "system_instructions",
            "output_schema_sha256",
        }:
            raise ValueError("model prompt fields must be exact")
        service, principal = self._model_gateway_components()
        return service.register_prompt(
            principal,
            prompt_id=str(payload["prompt_id"]),
            version=int(payload["version"]),
            workload=str(payload["workload"]),
            system_instructions=str(payload["system_instructions"]),
            output_schema_sha256=str(payload["output_schema_sha256"]),
        )

    def model_gateway_register_route(self, payload: Dict[str, Any]) -> Any:
        if set(payload) != set(RouteConfiguration.model_fields):
            raise ValueError("model route fields must be exact")
        service, principal = self._model_gateway_components()
        return service.register_route(
            principal, RouteConfiguration.model_validate(payload)
        )

    def model_gateway_route_action(
        self, route_id: str, revision: int, action: str, payload: Dict[str, Any]
    ) -> Any:
        if payload:
            raise ValueError("model route lifecycle actions take an empty object")
        service, principal = self._model_gateway_components()
        if action == "shadow":
            return service.promote_shadow(principal, route_id, revision)
        if action == "activate":
            return service.activate(principal, route_id, revision)
        raise ValueError("unknown model route lifecycle action")

    def model_gateway_rollback(self, route_id: str, payload: Dict[str, Any]) -> Any:
        if payload:
            raise ValueError("model route rollback takes an empty object")
        service, principal = self._model_gateway_components()
        return service.rollback(principal, route_id)

    def model_gateway_register_secret(self, payload: Dict[str, Any]) -> Any:
        if set(payload) != {"secret_id", "version", "environment_variable"}:
            raise ValueError("model secret fields must be exact")
        service, principal = self._model_gateway_components()
        return service.register_secret(
            principal,
            secret_id=str(payload["secret_id"]),
            version=int(payload["version"]),
            environment_variable=str(payload["environment_variable"]),
        )

    def model_gateway_retire_secret(
        self, secret_id: str, version: int, payload: Dict[str, Any]
    ) -> Any:
        if payload:
            raise ValueError("model secret retirement takes an empty object")
        service, principal = self._model_gateway_components()
        return service.retire_secret(principal, secret_id, version)

    def _behavior_components(self) -> Tuple[BehavioralRiskService, BehaviorPrincipal]:
        if self.behavior_service is None or self.behavior_principal is None:
            raise RuntimeError("behavior_not_configured")
        return self.behavior_service, self.behavior_principal

    def behavior_baselines(self, filters: Dict[str, str]) -> List[Any]:
        if set(filters) - {"state", "limit", "offset"}:
            raise ValueError("unknown behavior baseline filter")
        service, principal = self._behavior_components()
        return service.list_baselines(
            principal,
            state=BaselineState(filters["state"]) if "state" in filters else None,
            limit=int(filters.get("limit", "100")),
            offset=int(filters.get("offset", "0")),
        )

    def behavior_assessments(self, filters: Dict[str, str]) -> List[Any]:
        if set(filters) - {"anomalies_only", "limit", "offset"}:
            raise ValueError("unknown behavior assessment filter")
        anomalies = filters.get("anomalies_only", "false")
        if anomalies not in {"true", "false"}:
            raise ValueError("behavior anomaly filter must be true or false")
        service, principal = self._behavior_components()
        return service.list_assessments(
            principal,
            anomalies_only=anomalies == "true",
            limit=int(filters.get("limit", "100")),
            offset=int(filters.get("offset", "0")),
        )

    def behavior_assessment(self, assessment_id: str) -> Any:
        service, principal = self._behavior_components()
        return service.get_assessment(principal, assessment_id)

    def behavior_health(self) -> Any:
        service, principal = self._behavior_components()
        return service.health(principal)

    def behavior_config(self) -> List[Any]:
        service, principal = self._behavior_components()
        return service.config_history(principal)

    def behavior_drift(self, filters: Dict[str, str]) -> Any:
        if set(filters) - {"entity_ref"}:
            raise ValueError("unknown behavior drift filter")
        service, principal = self._behavior_components()
        return service.drift(principal, entity_ref=filters.get("entity_ref"))

    def behavior_tune(self, payload: Dict[str, Any]) -> Any:
        if set(payload) != {"config", "reason"}:
            raise ValueError("behavior tuning fields must be exact")
        service, principal = self._behavior_components()
        return service.register_config(
            principal,
            BehaviorTuningInput.model_validate(payload["config"]),
            reason=str(payload["reason"]),
        )

    def _correlation_components(self) -> Tuple[IncidentCorrelationService, CorrelationPrincipal]:
        if self.correlation_service is None or self.correlation_principal is None:
            raise RuntimeError("correlation_not_configured")
        return self.correlation_service, self.correlation_principal

    def correlation_incidents(self, filters: Dict[str, str]) -> List[Any]:
        if set(filters) - {"status", "limit", "offset"}:
            raise ValueError("unknown correlation incident filter")
        service, principal = self._correlation_components()
        return service.list_incidents(
            principal,
            status=CorrelationIncidentStatus(filters["status"]) if "status" in filters else None,
            limit=int(filters.get("limit", "100")),
            offset=int(filters.get("offset", "0")),
        )

    def correlation_incident(self, incident_id: str) -> Any:
        service, principal = self._correlation_components()
        return service.get(principal, incident_id)

    def correlation_decisions(self, filters: Dict[str, str]) -> List[Any]:
        if set(filters) - {"limit"}:
            raise ValueError("unknown correlation decision filter")
        service, principal = self._correlation_components()
        return service.list_decisions(principal, limit=int(filters.get("limit", "100")))

    def correlation_health(self) -> Any:
        service, principal = self._correlation_components()
        return service.health(principal)

    def correlation_suppressions(self) -> List[Any]:
        service, principal = self._correlation_components()
        return service.list_suppressions(principal)

    def correlation_transition(self, incident_id: str, payload: Dict[str, Any]) -> Any:
        if set(payload) != {"status", "reason"}:
            raise ValueError("correlation transition fields must be exact")
        service, principal = self._correlation_components()
        return service.transition(
            principal, incident_id, CorrelationIncidentStatus(str(payload["status"])),
            reason=str(payload["reason"]),
        )

    def correlation_merge(self, payload: Dict[str, Any]) -> Any:
        if set(payload) != {"incident_ids", "reason"} or not isinstance(payload["incident_ids"], list):
            raise ValueError("correlation merge fields are invalid")
        service, principal = self._correlation_components()
        return service.merge(principal, payload["incident_ids"], reason=str(payload["reason"]))

    def correlation_split(self, incident_id: str, payload: Dict[str, Any]) -> CorrelationSplitResult:
        if set(payload) != {"finding_ids", "reason"} or not isinstance(payload["finding_ids"], list):
            raise ValueError("correlation split fields are invalid")
        service, principal = self._correlation_components()
        source, child = service.split(
            principal, incident_id, payload["finding_ids"], reason=str(payload["reason"])
        )
        return CorrelationSplitResult(source=source, child=child)

    def correlation_create_suppression(self, payload: Dict[str, Any]) -> Any:
        if set(payload) != {"alert_type", "agent_ref", "reason", "expires_at"}:
            raise ValueError("correlation suppression fields must be exact")
        service, principal = self._correlation_components()
        return service.create_suppression(
            principal,
            alert_type=str(payload["alert_type"]),
            agent_ref=str(payload["agent_ref"]) if payload["agent_ref"] is not None else None,
            reason=str(payload["reason"]),
            expires_at=datetime.fromisoformat(str(payload["expires_at"]).replace("Z", "+00:00")),
        )

    def correlation_revoke_suppression(self, suppression_id: str, payload: Dict[str, Any]) -> Any:
        if set(payload) != {"reason"}:
            raise ValueError("suppression revocation fields must be exact")
        service, principal = self._correlation_components()
        return service.revoke_suppression(principal, suppression_id, reason=str(payload["reason"]))

    def _simulation_components(self) -> Tuple[SimulationService, SimulationPrincipal]:
        if self.simulation_service is None or self.simulation_principal is None:
            raise RuntimeError("simulation_not_configured")
        return self.simulation_service, self.simulation_principal

    def simulation_catalog(self) -> Any:
        service, principal = self._simulation_components()
        return service.catalog(principal)

    def simulation_health(self) -> Any:
        service, principal = self._simulation_components()
        return service.health(principal)

    def simulation_scenarios(self, filters: Dict[str, str]) -> Any:
        if set(filters) - {"source", "variant", "attack", "framework", "limit", "offset"}:
            raise ValueError("unknown simulation scenario filter")
        attack = filters.get("attack")
        if attack is not None and attack not in {"true", "false"}:
            raise ValueError("simulation attack filter is invalid")
        service, principal = self._simulation_components()
        return service.list_scenarios(
            principal,
            source=SimulationScenarioSource(filters["source"]) if "source" in filters else None,
            variant=SimulationVariant(filters["variant"]) if "variant" in filters else None,
            attack=attack == "true" if attack is not None else None,
            framework=filters.get("framework"),
            limit=int(filters.get("limit", "100")),
            offset=int(filters.get("offset", "0")),
        )

    def simulation_scenario(self, scenario_id: str, version: str) -> Any:
        service, principal = self._simulation_components()
        return service.get_scenario(principal, scenario_id, version)

    def simulation_mutate(self, payload: Dict[str, Any]) -> Any:
        service, principal = self._simulation_components()
        return service.mutate(
            principal, SimulationMutationRequest.model_validate(payload)
        )

    def simulation_import(self, payload: Dict[str, Any]) -> Any:
        service, principal = self._simulation_components()
        return service.import_scenarios(
            principal, SimulationImportRequest.model_validate(payload)
        )

    def simulation_run(self, payload: Dict[str, Any]) -> Any:
        service, principal = self._simulation_components()
        return service.run(principal, SimulationRunRequest.model_validate(payload))

    def simulation_runs(self, filters: Dict[str, str]) -> Any:
        if set(filters) - {"scenario_id", "passed", "limit", "offset"}:
            raise ValueError("unknown simulation run filter")
        passed = filters.get("passed")
        if passed is not None and passed not in {"true", "false"}:
            raise ValueError("simulation pass filter is invalid")
        service, principal = self._simulation_components()
        return service.list_runs(
            principal,
            scenario_id=filters.get("scenario_id"),
            passed=passed == "true" if passed is not None else None,
            limit=int(filters.get("limit", "100")),
            offset=int(filters.get("offset", "0")),
        )

    def simulation_run_detail(self, run_id: str) -> Any:
        service, principal = self._simulation_components()
        return service.get_run(principal, run_id)

    def simulation_replay(self, run_id: str, payload: Dict[str, Any]) -> Any:
        service, principal = self._simulation_components()
        return service.replay(
            principal, run_id, SimulationReplayRequest.model_validate(payload)
        )

    def simulation_audit(self, filters: Dict[str, str]) -> List[Any]:
        if set(filters) - {"limit"}:
            raise ValueError("unknown simulation audit filter")
        service, principal = self._simulation_components()
        return service.audit(principal, limit=int(filters.get("limit", "200")))

    def _evaluation_components(
        self,
    ) -> Tuple[ContinuousEvaluationService, EvaluationPrincipal]:
        if self.evaluation_service is None or self.evaluation_principal is None:
            raise RuntimeError("evaluation_not_configured")
        return self.evaluation_service, self.evaluation_principal

    def evaluation_catalog(self) -> Any:
        service, principal = self._evaluation_components()
        return service.catalog(principal)

    def evaluation_health(self) -> Any:
        service, principal = self._evaluation_components()
        return service.health(principal)

    def evaluation_runs(self, filters: Dict[str, str]) -> Any:
        if set(filters) - {"candidate_id", "gate_state", "limit", "offset"}:
            raise ValueError("unknown evaluation run filter")
        service, principal = self._evaluation_components()
        return service.list_runs(
            principal,
            candidate_id=filters.get("candidate_id"),
            gate_state=(
                EvaluationGateState(filters["gate_state"])
                if "gate_state" in filters
                else None
            ),
            limit=int(filters.get("limit", "100")),
            offset=int(filters.get("offset", "0")),
        )

    def evaluation_run_detail(self, run_id: str) -> Any:
        service, principal = self._evaluation_components()
        return service.get_run(principal, run_id)

    def evaluation_run(self, payload: Dict[str, Any]) -> Any:
        service, principal = self._evaluation_components()
        return service.run(principal, EvaluationRunRequest.model_validate(payload))

    def evaluation_approve_baseline(
        self, run_id: str, payload: Dict[str, Any]
    ) -> Any:
        service, principal = self._evaluation_components()
        return service.approve_baseline(
            principal,
            run_id,
            EvaluationBaselineApprovalRequest.model_validate(payload),
        )

    def evaluation_feedback(self, filters: Dict[str, str]) -> Any:
        if set(filters) - {"state", "limit", "offset"}:
            raise ValueError("unknown evaluation feedback filter")
        service, principal = self._evaluation_components()
        return service.list_feedback(
            principal,
            state=(
                EvaluationFeedbackState(filters["state"])
                if "state" in filters
                else None
            ),
            limit=int(filters.get("limit", "100")),
            offset=int(filters.get("offset", "0")),
        )

    def evaluation_feedback_detail(self, proposal_id: str) -> Any:
        service, principal = self._evaluation_components()
        return service.get_feedback(principal, proposal_id)

    def evaluation_submit_feedback(self, payload: Dict[str, Any]) -> Any:
        service, principal = self._evaluation_components()
        return service.submit_feedback(
            principal, EvaluationFeedbackProposalRequest.model_validate(payload)
        )

    def evaluation_review_feedback(
        self, proposal_id: str, payload: Dict[str, Any]
    ) -> Any:
        service, principal = self._evaluation_components()
        return service.review_feedback(
            principal,
            proposal_id,
            EvaluationFeedbackReviewRequest.model_validate(payload),
        )

    def evaluation_promote_feedback(
        self, proposal_id: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        service, principal = self._evaluation_components()
        proposal, dataset = service.promote_feedback(
            principal,
            proposal_id,
            EvaluationFeedbackPromotionRequest.model_validate(payload),
        )
        return {
            "schema_version": "1.0.0",
            "proposal": proposal.model_dump(mode="json"),
            "dataset": dataset.model_dump(mode="json"),
        }

    def evaluation_audit(self, filters: Dict[str, str]) -> List[Any]:
        if set(filters) - {"limit"}:
            raise ValueError("unknown evaluation audit filter")
        service, principal = self._evaluation_components()
        return service.audit(principal, limit=int(filters.get("limit", "200")))

    def _administration_components(
        self,
    ) -> Tuple[AdministrationService, AdministrationPrincipal]:
        if self.administration_service is None or self.administration_principal is None:
            raise RuntimeError("administration_not_configured")
        return self.administration_service, self.administration_principal

    def administration_snapshot(self) -> Any:
        service, principal = self._administration_components()
        return service.snapshot(principal)

    def administration_health(self) -> Any:
        return self.administration_snapshot().health

    def administration_audit(self, filters: Dict[str, str]) -> List[Any]:
        if set(filters) - {"limit"}:
            raise ValueError("unknown administration audit filter")
        service, principal = self._administration_components()
        return service.list_audit(
            principal, limit=int(filters.get("limit", "200"))
        )

    def administration_checkpoint(self) -> Any:
        service, principal = self._administration_components()
        return service.create_audit_checkpoint(principal)

    def external_capabilities(self) -> Any:
        service, principal = self._integration_components()
        return service.capabilities(principal)

    def external_events(self, filters: Dict[str, str]) -> Any:
        if set(filters) - {"limit", "cursor", "event_types"}:
            raise ValueError("unknown external event filter")
        event_types = filters.get("event_types")
        parsed_types = event_types.split(",") if event_types else None
        if parsed_types is not None and any(not item for item in parsed_types):
            raise ValueError("external event types are invalid")
        service, principal = self._integration_components()
        return service.stream_events(
            principal,
            limit=int(filters.get("limit", "100")),
            cursor=filters.get("cursor"),
            event_types=parsed_types,
        )

    def external_destinations(self) -> List[Any]:
        service, principal = self._integration_components()
        return service.destinations(principal)

    def external_deliveries(self, filters: Dict[str, str]) -> Any:
        if set(filters) - {"state", "destination_id", "limit", "offset"}:
            raise ValueError("unknown external delivery filter")
        service, principal = self._integration_components()
        state = (
            IntegrationDeliveryState(filters["state"])
            if "state" in filters
            else None
        )
        return service.list_deliveries(
            principal,
            state=state,
            destination_id=filters.get("destination_id"),
            limit=int(filters.get("limit", "100")),
            offset=int(filters.get("offset", "0")),
        )

    def external_delivery(self, delivery_id: str) -> Any:
        service, principal = self._integration_components()
        return service.get_delivery(principal, delivery_id)

    def external_health(self) -> Any:
        service, principal = self._integration_components()
        return service.health(principal)

    def external_audit(self, filters: Dict[str, str]) -> List[Any]:
        if set(filters) - {"limit"}:
            raise ValueError("unknown external audit filter")
        service, principal = self._integration_components()
        return service.audit(principal, limit=int(filters.get("limit", "200")))

    def external_process(self, payload: Dict[str, Any]) -> Any:
        request = IntegrationProcessRequest.model_validate(payload)
        service, principal = self._integration_components()
        return service.process_due(principal, limit=request.limit)

    def external_redrive(self, delivery_id: str, payload: Dict[str, Any]) -> Any:
        request = IntegrationRedriveRequest.model_validate(payload)
        service, principal = self._integration_components()
        return service.redrive(principal, delivery_id, reason=request.reason)


def make_handler(
    application: AuthorizationApplication,
    bearer_token: str,
    ingestion_gateway: Optional[IngestionGateway] = None,
    external_api_authenticator: Optional[ExternalApiAuthenticator] = None,
) -> Type[BaseHTTPRequestHandler]:
    if len(bearer_token) < 32:
        raise ValueError("ingestion bearer token must contain at least 32 characters")

    class AuthorizationHandler(BaseHTTPRequestHandler):
        server_version = "agentsec/0.1"

        def _json(
            self,
            status: HTTPStatus,
            payload: Dict[str, Any],
            *,
            headers: Optional[Mapping[str, str]] = None,
        ) -> None:
            encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status.value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(encoded)

        def _authenticated(self) -> bool:
            return bearer_is_valid(self.headers.get("Authorization", ""), bearer_token)

        def _public_principal(
            self, scope: str
        ) -> Optional[ExternalApiPrincipal]:
            if external_api_authenticator is None:
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return None
            try:
                principal = external_api_authenticator.authenticate(
                    self.headers.get("Authorization", "")
                )
                external_api_authenticator.authorize(principal, scope)
                application.assert_external_tenant(principal)
                return principal
            except ExternalApiAuthenticationError:
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            except ExternalApiAuthorizationError:
                self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return None

        @staticmethod
        def _single_filters(query: str) -> Dict[str, str]:
            raw = parse_qs(query, keep_blank_values=False)
            if any(len(values) != 1 for values in raw.values()):
                raise ValueError("one value per public API filter is required")
            return {key: values[0] for key, values in raw.items()}

        def _read_raw(self) -> bytes:
            if self.headers.get_content_type() != "application/json":
                raise TypeError("content_type_must_be_application_json")
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ValueError("invalid_size") from exc
            if size <= 0 or size > MAX_REQUEST_BYTES:
                raise OverflowError("invalid_size")
            return self.rfile.read(size)

        @staticmethod
        def _decode_payload(raw: bytes) -> Dict[str, Any]:
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("request body must be an object")
            return payload

        def _read_payload_with_raw(self) -> Tuple[Dict[str, Any], bytes]:
            raw = self._read_raw()
            payload = self._decode_payload(raw)
            return payload, raw

        def _read_payload(self) -> Dict[str, Any]:
            return self._read_payload_with_raw()[0]

        @staticmethod
        def _gateway_status(receipt: GatewayReceipt) -> HTTPStatus:
            return {
                GatewayEventStatus.ACCEPTED: HTTPStatus.ACCEPTED,
                GatewayEventStatus.DUPLICATE: HTTPStatus.OK,
                GatewayEventStatus.PROCESSING: HTTPStatus.ACCEPTED,
                GatewayEventStatus.REJECTED: HTTPStatus.BAD_REQUEST,
                GatewayEventStatus.CONFLICT: HTTPStatus.CONFLICT,
                GatewayEventStatus.BACKPRESSURE: HTTPStatus.SERVICE_UNAVAILABLE,
            }[receipt.status]

        def _telemetry_post(self, parsed_path: str) -> None:
            if ingestion_gateway is None:
                self._json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"error": "telemetry_gateway_unavailable"},
                )
                return
            if self.headers.get_content_type() != "application/json":
                self._json(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    {"error": "content_type_must_be_application_json"},
                )
                return
            try:
                raw = self._read_raw()
                principal = ingestion_gateway.authenticate(
                    method="POST",
                    path=parsed_path,
                    headers=self.headers,
                    body=raw,
                )
                payload = self._decode_payload(raw)
                if parsed_path == "/v1/telemetry":
                    cost = 1
                    events: Optional[List[Dict[str, object]]] = None
                else:
                    if set(payload) != {"events"} or not isinstance(payload["events"], list):
                        raise ValueError("batch body must contain only an events list")
                    if not 1 <= len(payload["events"]) <= ingestion_gateway.max_batch_events:
                        raise ValueError("batch event count is invalid")
                    if any(not isinstance(item, dict) for item in payload["events"]):
                        raise ValueError("batch telemetry records must be objects")
                    events = payload["events"]
                    cost = len(events)
                admitted, retry_after = ingestion_gateway.admit(principal, cost=cost)
                if not admitted:
                    self._json(
                        HTTPStatus.TOO_MANY_REQUESTS,
                        {"error": "rate_limited"},
                        headers={"Retry-After": str(retry_after)},
                    )
                    return
                if events is None:
                    response: Any = ingestion_gateway.ingest_one(principal, payload)
                    status = self._gateway_status(response)
                else:
                    response = ingestion_gateway.ingest_batch(principal, events)
                    status = (
                        HTTPStatus.ACCEPTED
                        if response.rejected == 0
                        and response.conflicts == 0
                        and response.backpressured == 0
                        else HTTPStatus.MULTI_STATUS
                    )
            except GatewayAuthenticationError:
                self._json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "workload_authentication_failed"},
                )
                return
            except TypeError:
                self._json(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    {"error": "content_type_must_be_application_json"},
                )
                return
            except OverflowError:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "invalid_size"})
                return
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError, ValidationError):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
                return
            self._json(status, response.model_dump(mode="json"))

        def _public_get(self, parsed: Any) -> None:
            path = parsed.path
            delivery_match = re.fullmatch(
                r"/api/v1/integrations/deliveries/(idl_[0-9a-f]{32})", path
            )
            entity_match = re.fullmatch(
                r"/api/v1/entities/(cmp_[A-Za-z0-9]+)", path
            )
            finding_match = re.fullmatch(
                r"/api/v1/findings/(fnd_[A-Za-z0-9]+)", path
            )
            incident_match = re.fullmatch(
                r"/api/v1/incidents/(inc_[A-Za-z0-9]+)", path
            )
            scope = (
                EXTERNAL_CAPABILITIES
                if path == "/api/v1/capabilities"
                else EXTERNAL_EVENTS_READ
                if path in {"/api/v1/events", "/api/v1/events/stream"}
                else EXTERNAL_ENTITIES_READ
                if path == "/api/v1/entities" or entity_match is not None
                else EXTERNAL_RULES_READ
                if path == "/api/v1/rules"
                else EXTERNAL_FINDINGS_READ
                if path == "/api/v1/findings" or finding_match is not None
                else EXTERNAL_INCIDENTS_READ
                if path == "/api/v1/incidents" or incident_match is not None
                else EXTERNAL_INTEGRATIONS_READ
                if path in {
                    "/api/v1/integrations",
                    "/api/v1/integrations/deliveries",
                }
                or delivery_match is not None
                else None
            )
            if scope is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            principal = self._public_principal(scope)
            if principal is None:
                return
            try:
                filters = self._single_filters(parsed.query)
                if path == "/api/v1/capabilities":
                    if filters:
                        raise ValueError("capability filters are not supported")
                    response: Any = application.public_capabilities(principal)
                elif path in {"/api/v1/events", "/api/v1/events/stream"}:
                    response = application.public_events(principal, filters)
                elif path == "/api/v1/entities":
                    response = application.inventory_list(filters)
                elif entity_match is not None:
                    if filters:
                        raise ValueError("entity detail filters are not supported")
                    response = application.inventory_detail(entity_match.group(1))
                elif path == "/api/v1/rules":
                    if filters:
                        raise ValueError("rule filters are not supported")
                    response = {
                        "schema_version": "1.0.0",
                        "rules": [
                            item.model_dump(mode="json")
                            for item in application.detection_rules()
                        ],
                    }
                elif path == "/api/v1/findings":
                    response = application.public_findings(principal, filters)
                elif finding_match is not None:
                    if filters:
                        raise ValueError("finding detail filters are not supported")
                    response = application.public_finding(
                        principal, finding_match.group(1)
                    )
                elif path == "/api/v1/incidents":
                    response = {
                        "schema_version": "1.0.0",
                        "incidents": [
                            item.model_dump(mode="json")
                            for item in application.correlation_incidents(filters)
                        ],
                    }
                elif incident_match is not None:
                    if filters:
                        raise ValueError("incident detail filters are not supported")
                    response = application.correlation_incident(
                        incident_match.group(1)
                    )
                elif path == "/api/v1/integrations":
                    if filters:
                        raise ValueError("integration filters are not supported")
                    response = application.public_integrations(principal)
                elif path == "/api/v1/integrations/deliveries":
                    response = application.public_deliveries(principal, filters)
                else:
                    assert delivery_match is not None
                    if filters:
                        raise ValueError("delivery detail filters are not supported")
                    response = application.public_delivery(
                        principal, delivery_match.group(1)
                    )
                payload = (
                    response.model_dump(mode="json")
                    if isinstance(response, StrictModel)
                    else response
                )
            except KeyError:
                self._json(HTTPStatus.NOT_FOUND, {"error": "record_not_found"})
                return
            except RuntimeError as exc:
                error = str(exc)
                allowed = {
                    "search_not_configured", "inventory_not_configured",
                    "detection_not_configured", "correlation_not_configured",
                    "integration_not_configured",
                }
                self._json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"error": error if error in allowed else "service_unavailable"},
                )
                return
            except (
                ExternalApiAuthorizationError,
                SearchAuthorizationError,
                InventoryAuthorizationError,
                DetectionAuthorizationError,
                CorrelationAuthorizationError,
                IntegrationAuthorizationError,
            ):
                self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            except (SearchQueryError, ValueError, ValidationError):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
                return
            self._json(HTTPStatus.OK, payload)

        def _public_post(self, parsed: Any) -> None:
            redrive_match = re.fullmatch(
                r"/api/v1/integrations/deliveries/(idl_[0-9a-f]{32})/redrive",
                parsed.path,
            )
            scope = (
                EXTERNAL_SEARCH
                if parsed.path == "/api/v1/search"
                else EXTERNAL_INTEGRATIONS_OPERATE
                if parsed.path == "/api/v1/integrations/process"
                or redrive_match is not None
                else None
            )
            if scope is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            principal = self._public_principal(scope)
            if principal is None:
                return
            if parsed.query:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
                return
            if self.headers.get_content_type() != "application/json":
                self._json(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    {"error": "content_type_must_be_application_json"},
                )
                return
            try:
                payload = self._read_payload()
                if parsed.path == "/api/v1/search":
                    response: Any = application.search(payload)
                elif parsed.path == "/api/v1/integrations/process":
                    response = application.public_integration_process(
                        principal, payload
                    )
                else:
                    assert redrive_match is not None
                    response = application.public_integration_redrive(
                        principal, redrive_match.group(1), payload
                    )
                output = (
                    response.model_dump(mode="json")
                    if isinstance(response, StrictModel)
                    else response
                )
            except KeyError:
                self._json(HTTPStatus.NOT_FOUND, {"error": "record_not_found"})
                return
            except RuntimeError as exc:
                error = str(exc)
                allowed = {"search_not_configured", "integration_not_configured"}
                self._json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"error": error if error in allowed else "service_unavailable"},
                )
                return
            except (ExternalApiAuthorizationError, IntegrationAuthorizationError):
                self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            except IntegrationConflictError:
                self._json(HTTPStatus.CONFLICT, {"error": "conflict"})
                return
            except (SearchQueryError, ValueError, ValidationError):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
                return
            self._json(HTTPStatus.OK, output)

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            if parsed.path == "/healthz":
                self._json(HTTPStatus.OK, health_payload())
                return
            if parsed.path.startswith("/api/v1/"):
                self._public_get(parsed)
                return
            if not self._authenticated():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            try:
                if parsed.path == "/v1/evaluations/catalog":
                    if parsed.query:
                        raise ValueError("evaluation catalog filters are not supported")
                    payload = application.evaluation_catalog().model_dump(mode="json")
                elif parsed.path == "/v1/evaluations/health":
                    if parsed.query:
                        raise ValueError("evaluation health filters are not supported")
                    payload = application.evaluation_health().model_dump(mode="json")
                elif parsed.path == "/v1/evaluations/runs":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per evaluation run filter is required")
                    payload = application.evaluation_runs(
                        {key: values[0] for key, values in raw_filters.items()}
                    ).model_dump(mode="json")
                elif re.fullmatch(r"/v1/evaluations/runs/evrun_[0-9a-f]{32}", parsed.path):
                    if parsed.query:
                        raise ValueError("evaluation run filters are not supported")
                    payload = application.evaluation_run_detail(
                        parsed.path.split("/")[4]
                    ).model_dump(mode="json")
                elif parsed.path == "/v1/evaluations/feedback":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per evaluation feedback filter is required")
                    payload = application.evaluation_feedback(
                        {key: values[0] for key, values in raw_filters.items()}
                    ).model_dump(mode="json")
                elif re.fullmatch(r"/v1/evaluations/feedback/evfb_[0-9a-f]{32}", parsed.path):
                    if parsed.query:
                        raise ValueError("evaluation feedback filters are not supported")
                    payload = application.evaluation_feedback_detail(
                        parsed.path.split("/")[4]
                    ).model_dump(mode="json")
                elif parsed.path == "/v1/evaluations/audit":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per evaluation audit filter is required")
                    entries = application.evaluation_audit(
                        {key: values[0] for key, values in raw_filters.items()}
                    )
                    payload = {
                        "schema_version": "1.0.0",
                        "entries": [item.model_dump(mode="json") for item in entries],
                        "count": len(entries),
                    }
                elif parsed.path == "/v1/administration":
                    if parsed.query:
                        raise ValueError("administration snapshot filters are not supported")
                    payload = application.administration_snapshot().model_dump(mode="json")
                elif parsed.path == "/v1/administration/health":
                    if parsed.query:
                        raise ValueError("administration health filters are not supported")
                    payload = application.administration_health().model_dump(mode="json")
                elif parsed.path == "/v1/administration/audit":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per administration audit filter is required")
                    entries = application.administration_audit(
                        {key: values[0] for key, values in raw_filters.items()}
                    )
                    payload = {
                        "schema_version": "1.0.0",
                        "entries": [item.model_dump(mode="json") for item in entries],
                        "count": len(entries),
                    }
                elif parsed.path == "/v1/simulation/catalog":
                    if parsed.query:
                        raise ValueError("simulation catalog filters are not supported")
                    payload = application.simulation_catalog().model_dump(mode="json")
                elif parsed.path == "/v1/simulation/health":
                    if parsed.query:
                        raise ValueError("simulation health filters are not supported")
                    payload = application.simulation_health().model_dump(mode="json")
                elif parsed.path == "/v1/simulation/scenarios":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per simulation scenario filter is required")
                    payload = application.simulation_scenarios(
                        {key: values[0] for key, values in raw_filters.items()}
                    ).model_dump(mode="json")
                elif re.fullmatch(
                    r"/v1/simulation/scenarios/sim_[a-z0-9_]{3,96}/versions/[0-9]+\.[0-9]+\.[0-9]+",
                    parsed.path,
                ):
                    if parsed.query:
                        raise ValueError("simulation scenario filters are not supported")
                    parts = parsed.path.split("/")
                    payload = application.simulation_scenario(
                        parts[4], parts[6]
                    ).model_dump(mode="json")
                elif parsed.path == "/v1/simulation/runs":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per simulation run filter is required")
                    payload = application.simulation_runs(
                        {key: values[0] for key, values in raw_filters.items()}
                    ).model_dump(mode="json")
                elif re.fullmatch(r"/v1/simulation/runs/simrun_[0-9a-f]{32}", parsed.path):
                    if parsed.query:
                        raise ValueError("simulation run filters are not supported")
                    payload = application.simulation_run_detail(
                        parsed.path.split("/")[4]
                    ).model_dump(mode="json")
                elif parsed.path == "/v1/simulation/audit":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per simulation audit filter is required")
                    entries = application.simulation_audit(
                        {key: values[0] for key, values in raw_filters.items()}
                    )
                    payload = {
                        "schema_version": "1.0.0",
                        "entries": [item.model_dump(mode="json") for item in entries],
                        "count": len(entries),
                    }
                elif parsed.path == "/v1/external/capabilities":
                    if parsed.query:
                        raise ValueError("external capability filters are not supported")
                    payload = application.external_capabilities().model_dump(mode="json")
                elif parsed.path == "/v1/external/events":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per external event filter is required")
                    payload = application.external_events(
                        {key: values[0] for key, values in raw_filters.items()}
                    ).model_dump(mode="json")
                elif parsed.path == "/v1/external/destinations":
                    if parsed.query:
                        raise ValueError("external destination filters are not supported")
                    payload = {
                        "schema_version": "1.0.0",
                        "destinations": [
                            item.model_dump(mode="json")
                            for item in application.external_destinations()
                        ],
                    }
                elif parsed.path == "/v1/external/deliveries":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per external delivery filter is required")
                    payload = application.external_deliveries(
                        {key: values[0] for key, values in raw_filters.items()}
                    ).model_dump(mode="json")
                elif parsed.path == "/v1/external/health":
                    if parsed.query:
                        raise ValueError("external health filters are not supported")
                    payload = application.external_health().model_dump(mode="json")
                elif parsed.path == "/v1/external/audit":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per external audit filter is required")
                    payload = {
                        "schema_version": "1.0.0",
                        "audit": [
                            item.model_dump(mode="json")
                            for item in application.external_audit(
                                {key: values[0] for key, values in raw_filters.items()}
                            )
                        ],
                    }
                elif re.fullmatch(
                    r"/v1/external/deliveries/idl_[0-9a-f]{32}", parsed.path
                ):
                    if parsed.query:
                        raise ValueError("external delivery detail filters are not supported")
                    payload = application.external_delivery(
                        parsed.path.split("/")[4]
                    ).model_dump(mode="json")
                elif parsed.path == "/v1/model-gateway/health":
                    if parsed.query:
                        raise ValueError("model gateway health filters are not supported")
                    payload = application.model_gateway_health().model_dump(mode="json")
                elif parsed.path == "/v1/model-gateway/routes":
                    if parsed.query:
                        raise ValueError("model gateway route filters are not supported")
                    items = application.model_gateway_routes()
                    payload = {"schema_version": "1.0.0", "routes": [item.model_dump(mode="json") for item in items]}
                elif parsed.path == "/v1/model-gateway/prompts":
                    if parsed.query:
                        raise ValueError("model gateway prompt filters are not supported")
                    items = application.model_gateway_prompts()
                    payload = {"schema_version": "1.0.0", "prompts": [item.model_dump(mode="json") for item in items]}
                elif parsed.path == "/v1/model-gateway/qualifications":
                    if parsed.query:
                        raise ValueError("model gateway qualification filters are not supported")
                    items = application.model_gateway_qualifications()
                    payload = {"schema_version": "1.0.0", "qualifications": [item.model_dump(mode="json") for item in items]}
                elif parsed.path == "/v1/model-gateway/calls":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per model gateway call filter is required")
                    items = application.model_gateway_calls(
                        {key: values[0] for key, values in raw_filters.items()}
                    )
                    payload = {"schema_version": "1.0.0", "calls": [item.model_dump(mode="json") for item in items]}
                elif parsed.path == "/v1/model-gateway/secrets":
                    if parsed.query:
                        raise ValueError("model gateway secret filters are not supported")
                    items = application.model_gateway_secrets()
                    payload = {"schema_version": "1.0.0", "secrets": [item.model_dump(mode="json") for item in items]}
                elif parsed.path == "/v1/model-gateway/audit":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per model gateway audit filter is required")
                    items = application.model_gateway_audit(
                        {key: values[0] for key, values in raw_filters.items()}
                    )
                    payload = {"schema_version": "1.0.0", "audit": [item.model_dump(mode="json") for item in items]}
                elif parsed.path == "/v1/analyst/runs":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per analyst filter is required")
                    items = application.analyst_runs(
                        {key: values[0] for key, values in raw_filters.items()}
                    )
                    payload = {"schema_version": "1.0.0", "runs": [item.model_dump(mode="json") for item in items]}
                elif parsed.path == "/v1/analyst/feedback":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per analyst feedback filter is required")
                    items = application.analyst_feedback(
                        {key: values[0] for key, values in raw_filters.items()}
                    )
                    payload = {"schema_version": "1.0.0", "feedback": [item.model_dump(mode="json") for item in items]}
                elif parsed.path == "/v1/analyst/health":
                    if parsed.query:
                        raise ValueError("analyst health filters are not supported")
                    payload = application.analyst_health().model_dump(mode="json")
                elif re.fullmatch(r"/v1/analyst/runs/air_[0-9a-f]{32}", parsed.path):
                    if parsed.query:
                        raise ValueError("analyst run filters are not supported")
                    payload = application.analyst_run(parsed.path.split("/")[4]).model_dump(mode="json")
                elif re.fullmatch(r"/v1/analyst/findings/fnd_[A-Za-z0-9]+", parsed.path):
                    if parsed.query:
                        raise ValueError("analyst finding filters are not supported")
                    payload = application.analyst_run_for_finding(parsed.path.split("/")[4]).model_dump(mode="json")
                elif parsed.path == "/v1/response/executions":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per response filter is required")
                    payload = application.response_executions(
                        {key: values[0] for key, values in raw_filters.items()}
                    ).model_dump(mode="json")
                elif parsed.path == "/v1/response/health":
                    if parsed.query:
                        raise ValueError("response health filters are not supported")
                    payload = application.response_health().model_dump(mode="json")
                elif parsed.path == "/v1/response/connectors":
                    if parsed.query:
                        raise ValueError("response connector filters are not supported")
                    payload = {
                        "schema_version": "1.0.0",
                        "connectors": [
                            item.model_dump(mode="json")
                            for item in application.response_connectors()
                        ],
                    }
                elif parsed.path == "/v1/response/control":
                    if parsed.query:
                        raise ValueError("response control filters are not supported")
                    payload = application.response_control().model_dump(mode="json")
                elif parsed.path == "/v1/response/playbooks":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per response playbook filter is required")
                    payload = application.response_playbooks(
                        {key: values[0] for key, values in raw_filters.items()}
                    ).model_dump(mode="json")
                elif re.fullmatch(r"/v1/response/executions/rex_[0-9a-f]{32}", parsed.path):
                    if parsed.query:
                        raise ValueError("response detail filters are not supported")
                    payload = application.response_execution(
                        parsed.path.split("/")[4]
                    ).model_dump(mode="json")
                elif parsed.path == "/v1/notifications":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per notification filter is required")
                    payload = application.list_notifications(
                        {key: values[0] for key, values in raw_filters.items()}
                    ).model_dump(mode="json")
                elif parsed.path == "/v1/notifications/health":
                    if parsed.query:
                        raise ValueError("notification health filters are not supported")
                    payload = application.notification_health().model_dump(mode="json")
                elif parsed.path == "/v1/notification-destinations":
                    if parsed.query:
                        raise ValueError("notification destination filters are not supported")
                    payload = application.notification_destinations().model_dump(mode="json")
                elif re.fullmatch(r"/v1/notifications/ntf_[0-9a-f]{32}", parsed.path):
                    if parsed.query:
                        raise ValueError("notification detail filters are not supported")
                    payload = application.get_notification(
                        parsed.path.split("/")[3]
                    ).model_dump(mode="json")
                elif parsed.path == "/v1/cases":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per case filter is required")
                    payload = application.list_cases(
                        {key: values[0] for key, values in raw_filters.items()}
                    ).model_dump(mode="json")
                elif parsed.path == "/v1/cases/health":
                    if parsed.query:
                        raise ValueError("case health filters are not supported")
                    payload = application.case_health().model_dump(mode="json")
                elif parsed.path == "/v1/case-teams":
                    if parsed.query:
                        raise ValueError("case team filters are not supported")
                    payload = {
                        "schema_version": "1.0.0",
                        "teams": [
                            item.model_dump(mode="json")
                            for item in application.case_teams()
                        ],
                    }
                elif re.fullmatch(r"/v1/cases/case_[0-9a-f]{32}", parsed.path):
                    if parsed.query:
                        raise ValueError("case detail filters are not supported")
                    payload = application.get_case(
                        parsed.path.split("/")[3]
                    ).model_dump(mode="json")
                elif parsed.path == "/v1/enrichment/health":
                    if parsed.query:
                        raise ValueError("enrichment health filters are not supported")
                    payload = application.enrichment_health().model_dump(mode="json")
                elif parsed.path == "/v1/correlation/incidents":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per correlation filter is required")
                    items = application.correlation_incidents(
                        {key: values[0] for key, values in raw_filters.items()}
                    )
                    payload = {"schema_version": "1.0.0", "incidents": [item.model_dump(mode="json") for item in items]}
                elif parsed.path == "/v1/correlation/decisions":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per correlation filter is required")
                    items = application.correlation_decisions(
                        {key: values[0] for key, values in raw_filters.items()}
                    )
                    payload = {"schema_version": "1.0.0", "decisions": [item.model_dump(mode="json") for item in items]}
                elif parsed.path == "/v1/correlation/health":
                    if parsed.query:
                        raise ValueError("correlation health filters are not supported")
                    payload = application.correlation_health().model_dump(mode="json")
                elif parsed.path == "/v1/correlation/suppressions":
                    if parsed.query:
                        raise ValueError("correlation suppression filters are not supported")
                    payload = {"schema_version": "1.0.0", "suppressions": [item.model_dump(mode="json") for item in application.correlation_suppressions()]}
                elif re.fullmatch(r"/v1/correlation/incidents/inc_[A-Za-z0-9]+", parsed.path):
                    if parsed.query:
                        raise ValueError("correlation incident filters are not supported")
                    payload = application.correlation_incident(parsed.path.split("/")[4]).model_dump(mode="json")
                elif parsed.path in {"/v1/behavior/baselines", "/v1/behavior/assessments"}:
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per behavior filter is required")
                    filters = {key: values[0] for key, values in raw_filters.items()}
                    items = (
                        application.behavior_baselines(filters)
                        if parsed.path.endswith("/baselines")
                        else application.behavior_assessments(filters)
                    )
                    payload = {
                        "schema_version": "1.0.0",
                        "baselines" if parsed.path.endswith("/baselines") else "assessments": [
                            item.model_dump(mode="json") for item in items
                        ],
                    }
                elif parsed.path == "/v1/behavior/health":
                    if parsed.query:
                        raise ValueError("behavior health filters are not supported")
                    payload = application.behavior_health().model_dump(mode="json")
                elif parsed.path == "/v1/behavior/config":
                    if parsed.query:
                        raise ValueError("behavior config filters are not supported")
                    payload = {
                        "schema_version": "1.0.0",
                        "configs": [
                            item.model_dump(mode="json")
                            for item in application.behavior_config()
                        ],
                    }
                elif parsed.path == "/v1/behavior/drift":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per behavior drift filter is required")
                    payload = application.behavior_drift(
                        {key: values[0] for key, values in raw_filters.items()}
                    ).model_dump(mode="json")
                elif re.fullmatch(r"/v1/behavior/assessments/bhas_[A-Za-z0-9]+", parsed.path):
                    payload = application.behavior_assessment(
                        parsed.path.split("/")[4]
                    ).model_dump(mode="json")
                elif parsed.path == "/v1/detection/content":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per content filter is required")
                    filters = {key: values[0] for key, values in raw_filters.items()}
                    payload = {
                        "schema_version": "1.0.0",
                        "content": [
                            item.model_dump(mode="json")
                            for item in application.content_list(filters)
                        ],
                    }
                elif parsed.path == "/v1/detection/content/health":
                    if parsed.query:
                        raise ValueError("content health filters are not supported")
                    payload = application.content_health().model_dump(mode="json")
                elif parsed.path == "/v1/detection/content/packs":
                    if parsed.query:
                        raise ValueError("content pack filters are not supported")
                    payload = {
                        "schema_version": "1.0.0",
                        "packs": [item.model_dump(mode="json") for item in application.content_packs()],
                    }
                elif re.fullmatch(r"/v1/detection/content/drc_[A-Za-z0-9]+/history", parsed.path):
                    payload = {
                        "schema_version": "1.0.0",
                        "history": [
                            item.model_dump(mode="json")
                            for item in application.content_history(parsed.path.split("/")[4])
                        ],
                    }
                elif re.fullmatch(r"/v1/detection/content/drc_[A-Za-z0-9]+", parsed.path):
                    payload = application.content_detail(parsed.path.split("/")[4]).model_dump(mode="json")
                elif parsed.path == "/v1/detection/rules":
                    if parsed.query:
                        raise ValueError("detection rule filters are not supported")
                    payload = {
                        "schema_version": "1.0.0",
                        "rules": [
                            item.model_dump(mode="json")
                            for item in application.detection_rules()
                        ],
                    }
                elif parsed.path == "/v1/detection/health":
                    if parsed.query:
                        raise ValueError("detection health filters are not supported")
                    payload = {
                        "schema_version": "1.0.0",
                        "rules": [
                            item.model_dump(mode="json")
                            for item in application.detection_health()
                        ],
                    }
                elif parsed.path in {
                    "/v1/posture/checks", "/v1/posture/findings", "/v1/posture/trends"
                }:
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per posture filter is required")
                    filters = {key: values[0] for key, values in raw_filters.items()}
                    if parsed.path.endswith("/checks"):
                        payload = {"checks": [item.model_dump(mode="json") for item in application.posture_checks(filters)]}
                    elif parsed.path.endswith("/trends"):
                        payload = application.posture_trends(filters).model_dump(mode="json")
                    else:
                        payload = application.posture_findings(filters).model_dump(mode="json")
                elif parsed.path == "/v1/posture/summary":
                    payload = application.posture_summary().model_dump(mode="json")
                elif re.fullmatch(r"/v1/posture/findings/pstf_[0-9a-f]{32}", parsed.path):
                    payload = application.posture_detail(parsed.path.split("/")[4]).model_dump(mode="json")
                elif parsed.path in {"/v1/graph", "/v1/graph/summary"}:
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per graph filter is required")
                    filters = {key: values[0] for key, values in raw_filters.items()}
                    graph_result = (
                        application.graph_summary(filters)
                        if parsed.path.endswith("/summary")
                        else application.graph_snapshot(filters)
                    )
                    payload = graph_result.model_dump(mode="json")
                elif parsed.path == "/v1/inventory/summary":
                    payload = application.inventory_summary().model_dump(mode="json")
                elif parsed.path == "/v1/inventory":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per inventory filter is required")
                    filters = {key: values[0] for key, values in raw_filters.items()}
                    payload = application.inventory_list(filters).model_dump(mode="json")
                elif re.fullmatch(r"/v1/inventory/cmp_[A-Za-z0-9]+", parsed.path):
                    payload = application.inventory_detail(parsed.path.split("/")[3]).model_dump(
                        mode="json"
                    )
                elif parsed.path == "/v1/hunts":
                    payload = {
                        "schema_version": "1.0.0",
                        "hunts": [
                            item.model_dump(mode="json")
                            for item in application.list_hunts()
                        ],
                    }
                elif re.fullmatch(r"/v1/evidence/evd_[A-Za-z0-9]+/pivot", parsed.path):
                    evidence_id = parsed.path.split("/")[3]
                    payload = application.evidence_pivot(evidence_id).model_dump(
                        mode="json"
                    )
                elif parsed.path == "/v1/incidents":
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per filter is required")
                    filters = {key: values[0] for key, values in raw_filters.items()}
                    payload = application.list_incidents(filters).model_dump(mode="json")
                elif parsed.path == "/v1/telemetry/sources":
                    if ingestion_gateway is None:
                        self._json(
                            HTTPStatus.SERVICE_UNAVAILABLE,
                            {"error": "telemetry_gateway_unavailable"},
                        )
                        return
                    raw_filters = parse_qs(parsed.query, keep_blank_values=False)
                    if any(len(values) != 1 for values in raw_filters.values()):
                        raise ValueError("one value per filter is required")
                    if set(raw_filters) - {"tenant_id", "source_id"}:
                        raise ValueError("unknown source-health filter")
                    payload = {
                        "schema_version": "1.0.0",
                        "sources": [
                            item.model_dump(mode="json")
                            for item in ingestion_gateway.store.source_health(
                                tenant_id=(raw_filters.get("tenant_id") or [None])[0],
                                source_id=(raw_filters.get("source_id") or [None])[0],
                            )
                        ],
                    }
                elif parsed.path == "/v1/telemetry/queue":
                    if ingestion_gateway is None:
                        self._json(
                            HTTPStatus.SERVICE_UNAVAILABLE,
                            {"error": "telemetry_gateway_unavailable"},
                        )
                        return
                    payload = ingestion_gateway.store.queue_summary().model_dump(mode="json")
                else:
                    match = re.fullmatch(
                        r"/v1/incidents/(fnd_[A-Za-z0-9]+)(/timeline)?", parsed.path
                    )
                    if match is None:
                        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                        return
                    finding_id, timeline_suffix = match.groups()
                    if timeline_suffix:
                        payload = {
                            "schema_version": "2.0.0",
                            "finding_id": finding_id,
                            "timeline": [
                                item.model_dump(mode="json")
                                for item in application.get_timeline(finding_id)
                            ],
                        }
                    else:
                        payload = application.get_incident(finding_id).model_dump(
                            mode="json"
                        )
            except KeyError:
                self._json(HTTPStatus.NOT_FOUND, {"error": "record_not_found"})
                return
            except RuntimeError as exc:
                error = str(exc)
                if error not in {
                    "search_not_configured", "inventory_not_configured", "graph_not_configured",
                    "posture_not_configured", "detection_not_configured",
                    "content_not_configured", "behavior_not_configured", "correlation_not_configured",
                    "enrichment_not_configured", "analyst_not_configured",
                    "model_gateway_not_configured", "case_not_configured",
                    "notification_not_configured", "response_not_configured",
                    "integration_not_configured", "simulation_not_configured",
                    "evaluation_not_configured", "administration_not_configured"
                }:
                    error = "service_unavailable"
                self._json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"error": error},
                )
                return
            except (
                SearchAuthorizationError, InventoryAuthorizationError,
                GraphAuthorizationError, PostureAuthorizationError,
                DetectionAuthorizationError, ContentAuthorizationError,
                BehaviorAuthorizationError, CorrelationAuthorizationError,
                EnrichmentAuthorizationError,
                AnalystAuthorizationError,
                ModelGatewayAuthorizationError,
                CaseAuthorizationError,
                NotificationAuthorizationError,
                ResponseAuthorizationError,
                IntegrationAuthorizationError,
                SimulationAuthorizationError,
                EvaluationAuthorizationError,
                AdministrationAuthorizationError,
            ):
                self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            except (SearchQueryError, ValueError, ValidationError):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_filter"})
                return
            self._json(HTTPStatus.OK, payload)

        def do_POST(self) -> None:
            parsed = urlsplit(self.path)
            if parsed.path.startswith("/api/v1/"):
                self._public_post(parsed)
                return
            if parsed.path in {"/v1/telemetry", "/v1/telemetry/batch"}:
                self._telemetry_post(parsed.path)
                return
            if not self._authenticated():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            if self.headers.get_content_type() != "application/json":
                self._json(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    {"error": "content_type_must_be_application_json"},
                )
                return
            try:
                payload = self._read_payload()
                qualification_match = re.fullmatch(
                    r"/v1/model-gateway/routes/(mrt_[A-Za-z0-9_.-]+)/(\d+)/qualify",
                    parsed.path,
                )
                lifecycle_match = re.fullmatch(
                    r"/v1/model-gateway/routes/(mrt_[A-Za-z0-9_.-]+)/(\d+)/(shadow|activate)",
                    parsed.path,
                )
                rollback_match = re.fullmatch(
                    r"/v1/model-gateway/routes/(mrt_[A-Za-z0-9_.-]+)/rollback",
                    parsed.path,
                )
                secret_retire_match = re.fullmatch(
                    r"/v1/model-gateway/secrets/(sec_[A-Za-z0-9_.-]+)/(\d+)/retire",
                    parsed.path,
                )
                case_action_match = re.fullmatch(
                    r"/v1/cases/(case_[0-9a-f]{32})/(assign|acknowledge|comments|tasks|attachments|relationships|start|request-review|review|close)",
                    parsed.path,
                )
                case_task_match = re.fullmatch(
                    r"/v1/cases/(case_[0-9a-f]{32})/tasks/(ctk_[0-9a-f]{32})/transition",
                    parsed.path,
                )
                case_attachment_scan_match = re.fullmatch(
                    r"/v1/cases/(case_[0-9a-f]{32})/attachments/(cat_[0-9a-f]{32})/scan",
                    parsed.path,
                )
                notification_ack_match = re.fullmatch(
                    r"/v1/notifications/(ntf_[0-9a-f]{32})/acknowledge",
                    parsed.path,
                )
                provider_ack_match = re.fullmatch(
                    r"/v1/notification-deliveries/(ndv_[0-9a-f]{32})/provider-acknowledge",
                    parsed.path,
                )
                notification_redrive_match = re.fullmatch(
                    r"/v1/notification-deliveries/(ndv_[0-9a-f]{32})/redrive",
                    parsed.path,
                )
                response_execution_action_match = re.fullmatch(
                    r"/v1/response/executions/(rex_[0-9a-f]{32})/(request-live|approve|execute|request-rollback|approve-rollback|rollback)",
                    parsed.path,
                )
                external_redrive_match = re.fullmatch(
                    r"/v1/external/deliveries/(idl_[0-9a-f]{32})/redrive",
                    parsed.path,
                )
                simulation_replay_match = re.fullmatch(
                    r"/v1/simulation/runs/(simrun_[0-9a-f]{32})/replay",
                    parsed.path,
                )
                evaluation_baseline_match = re.fullmatch(
                    r"/v1/evaluations/runs/(evrun_[0-9a-f]{32})/baseline",
                    parsed.path,
                )
                evaluation_review_match = re.fullmatch(
                    r"/v1/evaluations/feedback/(evfb_[0-9a-f]{32})/review",
                    parsed.path,
                )
                evaluation_promote_match = re.fullmatch(
                    r"/v1/evaluations/feedback/(evfb_[0-9a-f]{32})/promote",
                    parsed.path,
                )
                if parsed.path == "/v1/administration/checkpoints":
                    if parsed.query or payload:
                        raise ValueError("administration checkpoint request must be empty")
                    response = application.administration_checkpoint()
                elif parsed.path == "/v1/evaluations/runs":
                    if parsed.query:
                        raise ValueError("evaluation run query parameters are not supported")
                    response = application.evaluation_run(payload)
                elif evaluation_baseline_match is not None:
                    if parsed.query:
                        raise ValueError("evaluation baseline query parameters are not supported")
                    response = application.evaluation_approve_baseline(
                        evaluation_baseline_match.group(1), payload
                    )
                elif parsed.path == "/v1/evaluations/feedback":
                    if parsed.query:
                        raise ValueError("evaluation feedback query parameters are not supported")
                    response = application.evaluation_submit_feedback(payload)
                elif evaluation_review_match is not None:
                    if parsed.query:
                        raise ValueError("evaluation review query parameters are not supported")
                    response = application.evaluation_review_feedback(
                        evaluation_review_match.group(1), payload
                    )
                elif evaluation_promote_match is not None:
                    if parsed.query:
                        raise ValueError("evaluation promotion query parameters are not supported")
                    response = application.evaluation_promote_feedback(
                        evaluation_promote_match.group(1), payload
                    )
                elif parsed.path == "/v1/simulation/mutations":
                    if parsed.query:
                        raise ValueError("simulation mutation query parameters are not supported")
                    response = application.simulation_mutate(payload)
                elif parsed.path == "/v1/simulation/imports":
                    if parsed.query:
                        raise ValueError("simulation import query parameters are not supported")
                    response = application.simulation_import(payload)
                elif parsed.path == "/v1/simulation/runs":
                    if parsed.query:
                        raise ValueError("simulation run query parameters are not supported")
                    response = application.simulation_run(payload)
                elif simulation_replay_match is not None:
                    if parsed.query:
                        raise ValueError("simulation replay query parameters are not supported")
                    response = application.simulation_replay(
                        simulation_replay_match.group(1), payload
                    )
                elif parsed.path == "/v1/external/process":
                    if parsed.query:
                        raise ValueError("external process query parameters are not supported")
                    response = application.external_process(payload)
                elif external_redrive_match is not None:
                    if parsed.query:
                        raise ValueError("external redrive query parameters are not supported")
                    response = application.external_redrive(
                        external_redrive_match.group(1), payload
                    )
                elif response_execution_action_match is not None:
                    if parsed.query:
                        raise ValueError("response mutation query parameters are not supported")
                    execution_id, action = response_execution_action_match.groups()
                    if action == "request-live":
                        response = application.response_request_live(execution_id, payload)
                    elif action == "approve":
                        response = application.response_approve(execution_id, payload)
                    elif action == "execute":
                        response = application.response_execute(execution_id, payload)
                    elif action == "request-rollback":
                        response = application.response_request_rollback(execution_id, payload)
                    elif action == "approve-rollback":
                        response = application.response_approve(
                            execution_id, payload, rollback=True
                        )
                    else:
                        response = application.response_execute(
                            execution_id, payload, rollback=True
                        )
                elif parsed.path == "/v1/response/control":
                    if parsed.query:
                        raise ValueError("response control query parameters are not supported")
                    response = application.response_set_kill_switch(payload)
                elif parsed.path == "/v1/response/playbooks":
                    if parsed.query:
                        raise ValueError("response playbook query parameters are not supported")
                    response = application.response_create_playbook(payload)
                elif parsed.path == "/v1/response/playbooks/action":
                    if parsed.query:
                        raise ValueError("response playbook query parameters are not supported")
                    response = application.response_playbook_action(payload)
                elif parsed.path == "/v1/notifications/process":
                    if parsed.query:
                        raise ValueError("notification process query parameters are not supported")
                    response = application.notification_process(payload)
                elif notification_ack_match is not None:
                    if parsed.query:
                        raise ValueError("notification mutation query parameters are not supported")
                    response = application.notification_acknowledge(
                        notification_ack_match.group(1), payload
                    )
                elif provider_ack_match is not None:
                    if parsed.query:
                        raise ValueError("notification mutation query parameters are not supported")
                    response = application.notification_provider_acknowledge(
                        provider_ack_match.group(1), payload
                    )
                elif notification_redrive_match is not None:
                    if parsed.query:
                        raise ValueError("notification mutation query parameters are not supported")
                    response = application.notification_redrive(
                        notification_redrive_match.group(1), payload
                    )
                elif case_action_match is not None:
                    if parsed.query:
                        raise ValueError("case mutation query parameters are not supported")
                    case_id, action = case_action_match.groups()
                    response = {
                        "assign": application.case_assign,
                        "acknowledge": application.case_acknowledge,
                        "comments": application.case_comment,
                        "tasks": application.case_task,
                        "attachments": application.case_attachment,
                        "relationships": application.case_relationship,
                        "start": application.case_start,
                        "request-review": application.case_request_review,
                        "review": application.case_review,
                        "close": application.case_close,
                    }[action](case_id, payload)
                elif parsed.path == "/v1/case-teams":
                    if parsed.query:
                        raise ValueError("case team query parameters are not supported")
                    response = application.case_team_create(payload)
                elif case_task_match is not None:
                    if parsed.query:
                        raise ValueError("case mutation query parameters are not supported")
                    response = application.case_task_transition(
                        case_task_match.group(1), case_task_match.group(2), payload
                    )
                elif case_attachment_scan_match is not None:
                    if parsed.query:
                        raise ValueError("case mutation query parameters are not supported")
                    response = application.case_attachment_scan(
                        case_attachment_scan_match.group(1),
                        case_attachment_scan_match.group(2),
                        payload,
                    )
                elif qualification_match is not None:
                    response = application.model_gateway_qualify(
                        qualification_match.group(1),
                        int(qualification_match.group(2)),
                        payload,
                    )
                elif lifecycle_match is not None:
                    response = application.model_gateway_route_action(
                        lifecycle_match.group(1),
                        int(lifecycle_match.group(2)),
                        lifecycle_match.group(3),
                        payload,
                    )
                elif rollback_match is not None:
                    response = application.model_gateway_rollback(
                        rollback_match.group(1), payload
                    )
                elif parsed.path == "/v1/model-gateway/prompts":
                    response = application.model_gateway_register_prompt(payload)
                elif parsed.path == "/v1/model-gateway/routes":
                    response = application.model_gateway_register_route(payload)
                elif parsed.path == "/v1/model-gateway/secrets":
                    response = application.model_gateway_register_secret(payload)
                elif secret_retire_match is not None:
                    response = application.model_gateway_retire_secret(
                        secret_retire_match.group(1),
                        int(secret_retire_match.group(2)),
                        payload,
                    )
                elif parsed.path == "/v1/authorize":
                    response: Any = application.authorize(payload)
                elif re.fullmatch(r"/v1/analyst/runs/air_[0-9a-f]{32}/feedback", parsed.path):
                    response = application.analyst_add_feedback(
                        parsed.path.split("/")[4], payload
                    )
                elif parsed.path == "/v1/correlation/incidents/merge":
                    response = application.correlation_merge(payload)
                elif parsed.path == "/v1/correlation/suppressions":
                    response = application.correlation_create_suppression(payload)
                elif re.fullmatch(r"/v1/correlation/suppressions/sup_[A-Za-z0-9]+/revoke", parsed.path):
                    response = application.correlation_revoke_suppression(parsed.path.split("/")[4], payload)
                elif re.fullmatch(r"/v1/correlation/incidents/inc_[A-Za-z0-9]+/transition", parsed.path):
                    response = application.correlation_transition(parsed.path.split("/")[4], payload)
                elif re.fullmatch(r"/v1/correlation/incidents/inc_[A-Za-z0-9]+/split", parsed.path):
                    response = application.correlation_split(parsed.path.split("/")[4], payload)
                elif parsed.path == "/v1/behavior/config":
                    response = application.behavior_tune(payload)
                elif parsed.path == "/v1/detection/content":
                    response = application.content_create(payload)
                elif parsed.path == "/v1/detection/content/packs/export":
                    response = application.content_pack_export(payload)
                elif parsed.path == "/v1/detection/content/packs/import":
                    imported = application.content_pack_import(payload)
                    self._json(
                        HTTPStatus.OK,
                        {"schema_version": "1.0.0", "content": [item.model_dump(mode="json") for item in imported]},
                    )
                    return
                elif re.fullmatch(
                    r"/v1/detection/content/drc_[A-Za-z0-9]+/(?:validate|backtest|submit|review|shadow|shadow-evaluate|publish|rollback)",
                    parsed.path,
                ):
                    parts = parsed.path.split("/")
                    response = application.content_action(parts[4], parts[5], payload)
                elif parsed.path == "/v1/detection/scheduled":
                    response = application.detection_scheduled(payload)
                elif parsed.path == "/v1/posture/scans":
                    response = application.posture_scan(payload)
                elif re.fullmatch(r"/v1/posture/findings/pstf_[0-9a-f]{32}/exceptions", parsed.path):
                    response = application.posture_exception(parsed.path.split("/")[4], payload)
                elif re.fullmatch(r"/v1/posture/exceptions/pste_[A-Za-z0-9]+/revoke", parsed.path):
                    response = application.posture_revoke_exception(parsed.path.split("/")[4], payload)
                elif parsed.path == "/v1/graph/reachability":
                    response = application.graph_reachability(payload)
                elif parsed.path == "/v1/graph/blast-radius":
                    response = application.graph_blast_radius(payload)
                elif parsed.path == "/v1/graph/attack-paths":
                    response = application.graph_attack_paths(payload)
                elif parsed.path == "/v1/inventory/discover":
                    response = application.inventory_discover(payload)
                elif re.fullmatch(
                    r"/v1/inventory/cmp_[A-Za-z0-9]+/governance", parsed.path
                ):
                    response = application.inventory_governance(
                        parsed.path.split("/")[3], payload
                    )
                elif parsed.path == "/v1/search":
                    response = application.search(payload)
                elif parsed.path == "/v1/search/aggregate":
                    response = application.aggregate(payload)
                elif parsed.path == "/v1/hunts":
                    response = application.save_hunt(payload)
                else:
                    hunt_match = re.fullmatch(
                        r"/v1/hunts/(hunt_[A-Za-z0-9]+)/execute", parsed.path
                    )
                    if hunt_match is not None:
                        response = application.execute_hunt(hunt_match.group(1), payload)
                    else:
                        match = re.fullmatch(
                            r"/v1/incidents/(fnd_[A-Za-z0-9]+)/transition", parsed.path
                        )
                        if match is None:
                            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                            return
                        response = application.transition_incident(match.group(1), payload)
            except TypeError:
                self._json(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    {"error": "content_type_must_be_application_json"},
                )
                return
            except OverflowError:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "invalid_size"})
                return
            except KeyError:
                self._json(HTTPStatus.NOT_FOUND, {"error": "record_not_found"})
                return
            except CaseConflictError:
                self._json(HTTPStatus.CONFLICT, {"error": "case_version_or_state_conflict"})
                return
            except NotificationConflictError:
                self._json(
                    HTTPStatus.CONFLICT,
                    {"error": "notification_version_or_state_conflict"},
                )
                return
            except ResponseConflictError:
                self._json(
                    HTTPStatus.CONFLICT,
                    {"error": "response_version_or_state_conflict"},
                )
                return
            except ResponseExecutionError:
                self._json(
                    HTTPStatus.CONFLICT,
                    {"error": "response_execution_gate_closed"},
                )
                return
            except IntegrationConflictError:
                self._json(
                    HTTPStatus.CONFLICT,
                    {"error": "integration_delivery_state_conflict"},
                )
                return
            except SimulationConflictError:
                self._json(
                    HTTPStatus.CONFLICT,
                    {"error": "simulation_request_or_record_conflict"},
                )
                return
            except EvaluationConflictError:
                self._json(
                    HTTPStatus.CONFLICT,
                    {"error": "evaluation_request_or_state_conflict"},
                )
                return
            except AdministrationConflictError:
                self._json(
                    HTTPStatus.CONFLICT,
                    {"error": "administration_version_or_state_conflict"},
                )
                return
            except RuntimeError as exc:
                error = str(exc)
                if error not in {
                    "search_not_configured", "inventory_not_configured", "graph_not_configured",
                    "posture_not_configured", "detection_not_configured",
                    "content_not_configured", "behavior_not_configured", "correlation_not_configured",
                    "enrichment_not_configured", "analyst_not_configured",
                    "model_gateway_not_configured", "case_not_configured",
                    "notification_not_configured", "response_not_configured",
                    "integration_not_configured", "simulation_not_configured",
                    "evaluation_not_configured", "administration_not_configured"
                }:
                    error = "service_unavailable"
                self._json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"error": error},
                )
                return
            except (
                SearchAuthorizationError, InventoryAuthorizationError,
                GraphAuthorizationError, PostureAuthorizationError,
                DetectionAuthorizationError, ContentAuthorizationError,
                BehaviorAuthorizationError, CorrelationAuthorizationError,
                EnrichmentAuthorizationError,
                AnalystAuthorizationError,
                ModelGatewayAuthorizationError,
                CaseAuthorizationError,
                NotificationAuthorizationError,
                ResponseAuthorizationError,
                IntegrationAuthorizationError,
                SimulationAuthorizationError,
                EvaluationAuthorizationError,
                AdministrationAuthorizationError,
            ):
                self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                SearchQueryError,
                ValueError,
                ValidationError,
            ):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
                return
            self._json(
                HTTPStatus.OK,
                response.model_dump(mode="json")
                if isinstance(response, StrictModel)
                else response,
            )

        def do_PUT(self) -> None:
            parsed = urlsplit(self.path)
            if not self._authenticated():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            hunt_match = re.fullmatch(r"/v1/hunts/(hunt_[A-Za-z0-9]+)", parsed.path)
            content_match = re.fullmatch(
                r"/v1/detection/content/(drc_[A-Za-z0-9]+)", parsed.path
            )
            if hunt_match is None and content_match is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            try:
                payload = self._read_payload()
                response = (
                    application.update_hunt(hunt_match.group(1), payload)
                    if hunt_match is not None
                    else application.content_update(content_match.group(1), payload)  # type: ignore[union-attr]
                )
            except TypeError:
                self._json(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    {"error": "content_type_must_be_application_json"},
                )
                return
            except KeyError:
                self._json(HTTPStatus.NOT_FOUND, {"error": "record_not_found"})
                return
            except RuntimeError as exc:
                error = str(exc)
                if error not in {"search_not_configured", "content_not_configured"}:
                    error = "service_unavailable"
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": error})
                return
            except (SearchAuthorizationError, ContentAuthorizationError):
                self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            except (OverflowError, UnicodeDecodeError, json.JSONDecodeError, SearchQueryError, ValueError, ValidationError):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
                return
            self._json(HTTPStatus.OK, response.model_dump(mode="json"))

        def do_DELETE(self) -> None:
            parsed = urlsplit(self.path)
            if not self._authenticated():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            match = re.fullmatch(r"/v1/hunts/(hunt_[A-Za-z0-9]+)", parsed.path)
            if match is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            try:
                application.delete_hunt(match.group(1))
            except KeyError:
                self._json(HTTPStatus.NOT_FOUND, {"error": "record_not_found"})
                return
            except RuntimeError:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "search_not_configured"})
                return
            except SearchAuthorizationError:
                self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            self._json(HTTPStatus.OK, {"deleted": match.group(1)})

        def log_message(self, format: str, *args: object) -> None:
            # Avoid default request logging because event IDs and paths can be sensitive.
            return

    return AuthorizationHandler


def serve(
    *,
    host: str,
    port: int,
    bearer_token: str,
    application: Optional[AuthorizationApplication] = None,
    ingestion_gateway: Optional[IngestionGateway] = None,
    external_api_authenticator: Optional[ExternalApiAuthenticator] = None,
) -> None:
    app = application or AuthorizationApplication()
    server = ThreadingHTTPServer(
        (host, port),
        make_handler(
            app,
            bearer_token,
            ingestion_gateway,
            external_api_authenticator,
        ),
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return
    finally:
        server.server_close()


def application_from_environment(
    pipeline: Optional[SecurityPipeline] = None,
) -> AuthorizationApplication:
    """Build optional durable product stores from explicit local settings."""

    active_pipeline = pipeline or build_pipeline_from_environment()
    search_database = os.environ.get("AGENTSEC_SEARCH_DB", "")
    inventory_database = os.environ.get("AGENTSEC_INVENTORY_DB", "")
    graph_database = os.environ.get("AGENTSEC_GRAPH_DB", "")
    posture_database = os.environ.get("AGENTSEC_POSTURE_DB", "")
    detection_database = os.environ.get("AGENTSEC_DETECTION_DB", "")
    content_database = os.environ.get("AGENTSEC_CONTENT_DB", "")
    behavior_database = os.environ.get("AGENTSEC_BEHAVIOR_DB", "")
    correlation_database = os.environ.get("AGENTSEC_CORRELATION_DB", "")
    enrichment_database = os.environ.get("AGENTSEC_ENRICHMENT_DB", "")
    enrichment_config = os.environ.get("AGENTSEC_ENRICHMENT_CONFIG", "")
    analyst_database = os.environ.get("AGENTSEC_ANALYST_DB", "")
    analyst_recording = os.environ.get("AGENTSEC_ANALYST_RECORDING", "")
    model_gateway_database = os.environ.get("AGENTSEC_MODEL_GATEWAY_DB", "")
    model_gateway_config = os.environ.get("AGENTSEC_MODEL_GATEWAY_CONFIG", "")
    case_database = os.environ.get("AGENTSEC_CASE_DB", "")
    notification_database = os.environ.get("AGENTSEC_NOTIFICATION_DB", "")
    notification_config = os.environ.get("AGENTSEC_NOTIFICATION_CONFIG", "")
    response_database = os.environ.get("AGENTSEC_RESPONSE_DB", "")
    response_config = os.environ.get("AGENTSEC_RESPONSE_CONFIG", "")
    integration_database = os.environ.get("AGENTSEC_INTEGRATION_DB", "")
    integration_config = os.environ.get("AGENTSEC_INTEGRATION_CONFIG", "")
    integration_cursor_secret = os.environ.get(
        "AGENTSEC_INTEGRATION_CURSOR_SECRET", ""
    )
    simulation_database = os.environ.get("AGENTSEC_SIMULATION_DB", "")
    evaluation_database = os.environ.get("AGENTSEC_EVALUATION_DB", "")
    evaluation_policy = os.environ.get("AGENTSEC_EVALUATION_POLICY", "")
    evaluation_recording = os.environ.get("AGENTSEC_EVALUATION_RECORDING", "")
    administration_database = os.environ.get("AGENTSEC_ADMIN_DB", "")
    administration_config = os.environ.get("AGENTSEC_ADMIN_CONFIG", "")
    repository: Optional[CanonicalRepository] = None
    search_service: Optional[SearchService] = None
    search_principal: Optional[SearchPrincipal] = None
    inventory_service: Optional[InventoryService] = None
    inventory_principal: Optional[InventoryPrincipal] = None
    graph_service: Optional[SecurityGraphService] = None
    graph_principal: Optional[GraphPrincipal] = None
    posture_service: Optional[PostureService] = None
    posture_principal: Optional[PosturePrincipal] = None
    detection_service: Optional[DetectionService] = None
    detection_principal: Optional[DetectionPrincipal] = None
    content_service: Optional[DetectionContentService] = None
    content_principal: Optional[ContentPrincipal] = None
    behavior_service: Optional[BehavioralRiskService] = None
    behavior_principal: Optional[BehaviorPrincipal] = None
    correlation_service: Optional[IncidentCorrelationService] = None
    correlation_principal: Optional[CorrelationPrincipal] = None
    enrichment_principal: Optional[EnrichmentPrincipal] = None
    analyst_service: Optional[AiAnalystService] = None
    analyst_principal: Optional[AnalystPrincipal] = None
    model_gateway_service: Optional[ModelGatewayService] = None
    model_gateway_principal: Optional[ModelGatewayPrincipal] = None
    case_service: Optional[CaseService] = None
    case_principal: Optional[CasePrincipal] = None
    notification_service: Optional[NotificationService] = None
    notification_principal: Optional[NotificationPrincipal] = None
    response_service: Optional[ResponseAutomationService] = None
    response_principal: Optional[ResponsePrincipal] = None
    integration_service: Optional[IntegrationService] = None
    integration_principal: Optional[IntegrationPrincipal] = None
    simulation_service: Optional[SimulationService] = None
    simulation_principal: Optional[SimulationPrincipal] = None
    evaluation_service: Optional[ContinuousEvaluationService] = None
    evaluation_principal: Optional[EvaluationPrincipal] = None
    administration_service: Optional[AdministrationService] = None
    administration_principal: Optional[AdministrationPrincipal] = None
    search_tenant = os.environ.get("AGENTSEC_SEARCH_TENANT", "")
    if search_database:
        canonical_database = os.environ.get("AGENTSEC_CANONICAL_DB", "")
        cursor_secret = os.environ.get("AGENTSEC_SEARCH_CURSOR_SECRET", "")
        if not canonical_database or not search_tenant or len(cursor_secret) < 32:
            raise ValueError(
                "live search requires AGENTSEC_CANONICAL_DB, AGENTSEC_SEARCH_TENANT, "
                "and AGENTSEC_SEARCH_CURSOR_SECRET with at least 32 characters"
            )
        repository = CanonicalRepository(canonical_database)
        search_service = SearchService(
            search_database, cursor_secret=cursor_secret.encode("utf-8")
        )
        search_principal = SearchPrincipal(
            tenant_id=search_tenant,
            actor_id="system://local-service",
            permissions={
                READ_PERMISSION,
                INDEX_PERMISSION,
                HUNT_WRITE_PERMISSION,
                EVIDENCE_READ_PERMISSION,
            },
        )
        search_service.synchronize(search_principal, repository)
    if inventory_database:
        inventory_tenant = os.environ.get("AGENTSEC_INVENTORY_TENANT", search_tenant)
        if not inventory_tenant:
            raise ValueError(
                "live inventory requires AGENTSEC_INVENTORY_TENANT or AGENTSEC_SEARCH_TENANT"
            )
        inventory_service = InventoryService(inventory_database)
        inventory_principal = InventoryPrincipal(
            tenant_id=inventory_tenant,
            actor_id="system://local-service",
            permissions={
                INVENTORY_READ,
                INVENTORY_DISCOVER,
                INVENTORY_WRITE,
                INVENTORY_ADMIN,
            },
        )
        registry_path = os.environ.get("AGENTSEC_INVENTORY_MODEL_REGISTRY", "")
        if registry_path:
            inventory_service.import_model_registry(
                inventory_principal, ModelRegistry.from_path(Path(registry_path))
            )
    if graph_database:
        graph_tenant = os.environ.get(
            "AGENTSEC_GRAPH_TENANT",
            inventory_principal.tenant_id if inventory_principal is not None else search_tenant,
        )
        if not graph_tenant:
            raise ValueError(
                "live graph requires AGENTSEC_GRAPH_TENANT, AGENTSEC_INVENTORY_TENANT, "
                "or AGENTSEC_SEARCH_TENANT"
            )
        graph_service = SecurityGraphService(graph_database)
        graph_principal = GraphPrincipal(
            tenant_id=graph_tenant,
            actor_id="system://local-service",
            permissions={GRAPH_READ, GRAPH_WRITE, GRAPH_ANALYZE},
        )
        if inventory_service is not None and inventory_principal is not None:
            if inventory_principal.tenant_id != graph_tenant:
                graph_service.close()
                raise ValueError("live inventory and graph tenants must match")
            components = []
            offset = 0
            while True:
                page = inventory_service.list_components(
                    inventory_principal, limit=200, offset=offset
                )
                components.extend(page.components)
                offset += len(page.components)
                if offset >= page.total:
                    break
            if components:
                graph_service.ingest_inventory(
                    graph_principal,
                    components,
                    inventory_service.all_relationships(inventory_principal),
                )
    if posture_database:
        if inventory_service is None or inventory_principal is None:
            raise ValueError("live posture requires AGENTSEC_INVENTORY_DB")
        posture_tenant = os.environ.get("AGENTSEC_POSTURE_TENANT", inventory_principal.tenant_id)
        if posture_tenant != inventory_principal.tenant_id:
            raise ValueError("live posture and inventory tenants must match")
        posture_service = PostureService(posture_database)
        posture_principal = PosturePrincipal(
            tenant_id=posture_tenant,
            actor_id="system://local-service",
            permissions={POSTURE_READ, POSTURE_SCAN, POSTURE_ADMIN},
        )
        posture_service.install_defaults(posture_principal)
    if detection_database:
        detection_tenant = os.environ.get(
            "AGENTSEC_DETECTION_TENANT",
            (
                inventory_principal.tenant_id
                if inventory_principal is not None
                else search_tenant
            ),
        )
        if not detection_tenant:
            raise ValueError(
                "live detection requires AGENTSEC_DETECTION_TENANT, "
                "AGENTSEC_INVENTORY_TENANT, or AGENTSEC_SEARCH_TENANT"
            )
        detection_service = DetectionService(detection_database)
        detection_principal = DetectionPrincipal(
            tenant_id=detection_tenant,
            actor_id="system://local-service",
            permissions={DETECTION_READ, DETECTION_RUN, DETECTION_ADMIN},
        )
        detection_service.install_defaults(detection_principal)
    if content_database:
        if detection_service is None or detection_principal is None:
            raise ValueError("live detection content requires AGENTSEC_DETECTION_DB")
        signing_key = os.environ.get("AGENTSEC_CONTENT_SIGNING_KEY", "")
        if len(signing_key.encode("utf-8")) < 32:
            raise ValueError(
                "live detection content requires AGENTSEC_CONTENT_SIGNING_KEY "
                "with at least 32 bytes"
            )
        content_service = DetectionContentService(
            content_database,
            detection_service=detection_service,
            detection_principal=detection_principal,
            signer=PocHmacSigner(signing_key.encode("utf-8")),
        )
        content_principal = ContentPrincipal(
            tenant_id=detection_principal.tenant_id,
            actor_id="system://local-content-admin",
            permissions={
                CONTENT_READ, CONTENT_WRITE, CONTENT_REVIEW,
                CONTENT_PUBLISH, CONTENT_ADMIN,
            },
        )
    if behavior_database:
        behavior_tenant = os.environ.get(
            "AGENTSEC_BEHAVIOR_TENANT",
            (
                detection_principal.tenant_id
                if detection_principal is not None
                else inventory_principal.tenant_id
                if inventory_principal is not None
                else search_tenant
            ),
        )
        if not behavior_tenant:
            raise ValueError(
                "live behavior analytics requires AGENTSEC_BEHAVIOR_TENANT, "
                "AGENTSEC_DETECTION_TENANT, AGENTSEC_INVENTORY_TENANT, or "
                "AGENTSEC_SEARCH_TENANT"
            )
        behavior_service = BehavioralRiskService(behavior_database)
        behavior_principal = BehaviorPrincipal(
            tenant_id=behavior_tenant,
            actor_id="system://local-behavior-engine",
            permissions={BEHAVIOR_READ, BEHAVIOR_ANALYZE, BEHAVIOR_ADMIN},
        )
        behavior_service.install_default(behavior_principal)
    if correlation_database:
        correlation_tenant = os.environ.get(
            "AGENTSEC_CORRELATION_TENANT",
            (
                behavior_principal.tenant_id
                if behavior_principal is not None
                else detection_principal.tenant_id
                if detection_principal is not None
                else inventory_principal.tenant_id
                if inventory_principal is not None
                else search_tenant
            ),
        )
        if not correlation_tenant:
            raise ValueError(
                "live correlation requires AGENTSEC_CORRELATION_TENANT or another configured product tenant"
            )
        correlation_service = IncidentCorrelationService(correlation_database)
        correlation_principal = CorrelationPrincipal(
            tenant_id=correlation_tenant,
            actor_id="system://local-correlation-engine",
            permissions={CORRELATION_READ, CORRELATION_WRITE, CORRELATION_ADMIN},
        )
    if bool(enrichment_database) != bool(enrichment_config):
        raise ValueError(
            "live enrichment requires both AGENTSEC_ENRICHMENT_DB and AGENTSEC_ENRICHMENT_CONFIG"
        )
    if enrichment_config:
        enrichment_tenant = os.environ.get(
            "AGENTSEC_ENRICHMENT_TENANT",
            (
                correlation_principal.tenant_id
                if correlation_principal is not None
                else behavior_principal.tenant_id
                if behavior_principal is not None
                else detection_principal.tenant_id
                if detection_principal is not None
                else inventory_principal.tenant_id
                if inventory_principal is not None
                else search_tenant
            ),
        )
        if not enrichment_tenant:
            raise ValueError(
                "live enrichment requires AGENTSEC_ENRICHMENT_TENANT or another configured product tenant"
            )
        enrichment_engine, enrichment_principal = enrichment_engine_from_config(
            enrichment_config,
            database_path=enrichment_database,
            tenant_id=enrichment_tenant,
        )
        active_pipeline.enricher = enrichment_engine
    if bool(model_gateway_database) != bool(model_gateway_config):
        raise ValueError(
            "model gateway requires both AGENTSEC_MODEL_GATEWAY_DB and AGENTSEC_MODEL_GATEWAY_CONFIG"
        )
    if model_gateway_config:
        if active_pipeline.ai_mode.value == "off":
            raise ValueError(
                "model gateway requires AGENTSEC_AI_MODE=shadow, advisory, or semantic_hold"
            )
        model_gateway_tenant = os.environ.get(
            "AGENTSEC_MODEL_GATEWAY_TENANT",
            (
                enrichment_principal.tenant_id
                if enrichment_principal is not None
                else correlation_principal.tenant_id
                if correlation_principal is not None
                else behavior_principal.tenant_id
                if behavior_principal is not None
                else detection_principal.tenant_id
                if detection_principal is not None
                else inventory_principal.tenant_id
                if inventory_principal is not None
                else search_tenant
            ),
        )
        if not model_gateway_tenant:
            raise ValueError(
                "model gateway requires AGENTSEC_MODEL_GATEWAY_TENANT or another configured product tenant"
            )
        model_gateway_service, model_gateway_principal = model_gateway_from_config(
            model_gateway_database,
            model_gateway_config,
            tenant_id=model_gateway_tenant,
        )
        active_pipeline.reasoner = GovernedSecurityReasoner(
            model_gateway_service,
            model_gateway_principal,
            mode=active_pipeline.ai_mode,
        )
    if analyst_recording and not analyst_database:
        raise ValueError(
            "AI analyst recording requires AGENTSEC_ANALYST_DB"
        )
    if analyst_database and not (analyst_recording or model_gateway_service):
        raise ValueError(
            "AI analyst requires AGENTSEC_ANALYST_RECORDING or the model gateway"
        )
    if analyst_database:
        if active_pipeline.ai_mode.value == "off":
            raise ValueError(
                "AI analyst requires AGENTSEC_AI_MODE=shadow, advisory, or semantic_hold"
            )
        analyst_tenant = os.environ.get(
            "AGENTSEC_ANALYST_TENANT",
            (
                model_gateway_principal.tenant_id
                if model_gateway_principal is not None
                else enrichment_principal.tenant_id
                if enrichment_principal is not None
                else correlation_principal.tenant_id
                if correlation_principal is not None
                else behavior_principal.tenant_id
                if behavior_principal is not None
                else detection_principal.tenant_id
                if detection_principal is not None
                else inventory_principal.tenant_id
                if inventory_principal is not None
                else search_tenant
            ),
        )
        if not analyst_tenant:
            raise ValueError(
                "AI analyst requires AGENTSEC_ANALYST_TENANT or another configured product tenant"
            )
        if analyst_recording:
            analyst_service, analyst_principal = analyst_service_from_recording(
                analyst_database,
                analyst_recording,
                tenant_id=analyst_tenant,
            )
        else:
            assert model_gateway_service is not None
            assert model_gateway_principal is not None
            if analyst_tenant != model_gateway_principal.tenant_id:
                raise ValueError("AI analyst and model gateway tenants must match")
            analyst_service = AiAnalystService(
                analyst_database,
                reasoner=GovernedAnalystRoleReasoner(
                    model_gateway_service,
                    model_gateway_principal,
                    mode=active_pipeline.ai_mode,
                ),
            )
            analyst_principal = AnalystPrincipal(
                tenant_id=analyst_tenant,
                actor_id="system://local-ai-analyst",
                permissions={"analyst:read", "analyst:run", "analyst:feedback", "analyst:admin"},
            )
        active_pipeline.analyst_service = analyst_service
        active_pipeline.analyst_principal = analyst_principal
        active_pipeline.reasoner = None
    if case_database:
        case_tenant = os.environ.get(
            "AGENTSEC_CASE_TENANT",
            (
                analyst_principal.tenant_id
                if analyst_principal is not None
                else model_gateway_principal.tenant_id
                if model_gateway_principal is not None
                else enrichment_principal.tenant_id
                if enrichment_principal is not None
                else correlation_principal.tenant_id
                if correlation_principal is not None
                else behavior_principal.tenant_id
                if behavior_principal is not None
                else detection_principal.tenant_id
                if detection_principal is not None
                else inventory_principal.tenant_id
                if inventory_principal is not None
                else search_tenant
            ),
        )
        if not case_tenant:
            raise ValueError(
                "live cases require AGENTSEC_CASE_TENANT or another configured product tenant"
            )
        case_service, case_principal = case_service_from_environment(
            case_database, tenant_id=case_tenant
        )
        active_pipeline.case_service = case_service
        active_pipeline.case_principal = case_principal
    if bool(notification_database) != bool(notification_config):
        raise ValueError(
            "live notifications require both AGENTSEC_NOTIFICATION_DB and "
            "AGENTSEC_NOTIFICATION_CONFIG"
        )
    if notification_database:
        notification_tenant = os.environ.get(
            "AGENTSEC_NOTIFICATION_TENANT",
            (
                case_principal.tenant_id
                if case_principal is not None
                else analyst_principal.tenant_id
                if analyst_principal is not None
                else model_gateway_principal.tenant_id
                if model_gateway_principal is not None
                else enrichment_principal.tenant_id
                if enrichment_principal is not None
                else correlation_principal.tenant_id
                if correlation_principal is not None
                else behavior_principal.tenant_id
                if behavior_principal is not None
                else detection_principal.tenant_id
                if detection_principal is not None
                else inventory_principal.tenant_id
                if inventory_principal is not None
                else search_tenant
            ),
        )
        if not notification_tenant:
            raise ValueError(
                "live notifications require AGENTSEC_NOTIFICATION_TENANT or "
                "another configured product tenant"
            )
        notification_service, notification_principal = (
            notification_service_from_environment(
                notification_database,
                policy_path=notification_config,
                tenant_id=notification_tenant,
            )
        )
        active_pipeline.notification_service = notification_service
        active_pipeline.notification_principal = notification_principal
    if bool(response_database) != bool(response_config):
        raise ValueError(
            "live response automation requires both AGENTSEC_RESPONSE_DB and "
            "AGENTSEC_RESPONSE_CONFIG"
        )
    if response_database:
        response_tenant = os.environ.get(
            "AGENTSEC_RESPONSE_TENANT",
            (
                notification_principal.tenant_id
                if notification_principal is not None
                else case_principal.tenant_id
                if case_principal is not None
                else analyst_principal.tenant_id
                if analyst_principal is not None
                else model_gateway_principal.tenant_id
                if model_gateway_principal is not None
                else enrichment_principal.tenant_id
                if enrichment_principal is not None
                else correlation_principal.tenant_id
                if correlation_principal is not None
                else behavior_principal.tenant_id
                if behavior_principal is not None
                else detection_principal.tenant_id
                if detection_principal is not None
                else inventory_principal.tenant_id
                if inventory_principal is not None
                else search_tenant
            ),
        )
        if not response_tenant:
            raise ValueError(
                "live response automation requires AGENTSEC_RESPONSE_TENANT or "
                "another configured product tenant"
            )
        response_service, response_principal = response_service_from_environment(
            response_database,
            policy_path=response_config,
            tenant_id=response_tenant,
        )
        active_pipeline.response_service = response_service
        active_pipeline.response_principal = response_principal
    integration_values = (
        bool(integration_database),
        bool(integration_config),
        bool(integration_cursor_secret),
    )
    if any(integration_values) and not all(integration_values):
        raise ValueError(
            "external integrations require AGENTSEC_INTEGRATION_DB, "
            "AGENTSEC_INTEGRATION_CONFIG, and AGENTSEC_INTEGRATION_CURSOR_SECRET"
        )
    if integration_database:
        integration_service, integration_principal = integration_service_from_config(
            integration_database,
            integration_config,
            cursor_secret=integration_cursor_secret,
        )
        expected_integration_tenant = os.environ.get(
            "AGENTSEC_INTEGRATION_TENANT",
            (
                response_principal.tenant_id
                if response_principal is not None
                else notification_principal.tenant_id
                if notification_principal is not None
                else case_principal.tenant_id
                if case_principal is not None
                else analyst_principal.tenant_id
                if analyst_principal is not None
                else model_gateway_principal.tenant_id
                if model_gateway_principal is not None
                else enrichment_principal.tenant_id
                if enrichment_principal is not None
                else correlation_principal.tenant_id
                if correlation_principal is not None
                else behavior_principal.tenant_id
                if behavior_principal is not None
                else detection_principal.tenant_id
                if detection_principal is not None
                else inventory_principal.tenant_id
                if inventory_principal is not None
                else search_tenant
            ),
        )
        if (
            expected_integration_tenant
            and integration_principal.tenant_id != expected_integration_tenant
        ):
            integration_service.close()
            raise ValueError("external integration and product tenants must match")
    if simulation_database:
        simulation_tenant = os.environ.get(
            "AGENTSEC_SIMULATION_TENANT",
            (
                integration_principal.tenant_id
                if integration_principal is not None
                else response_principal.tenant_id
                if response_principal is not None
                else notification_principal.tenant_id
                if notification_principal is not None
                else case_principal.tenant_id
                if case_principal is not None
                else analyst_principal.tenant_id
                if analyst_principal is not None
                else model_gateway_principal.tenant_id
                if model_gateway_principal is not None
                else enrichment_principal.tenant_id
                if enrichment_principal is not None
                else correlation_principal.tenant_id
                if correlation_principal is not None
                else behavior_principal.tenant_id
                if behavior_principal is not None
                else detection_principal.tenant_id
                if detection_principal is not None
                else inventory_principal.tenant_id
                if inventory_principal is not None
                else search_tenant
            ),
        )
        if not simulation_tenant:
            raise ValueError(
                "simulation lab requires AGENTSEC_SIMULATION_TENANT or another configured product tenant"
            )
        simulation_service, simulation_principal = simulation_service_from_environment(
            simulation_database, tenant_id=simulation_tenant
        )
    if (evaluation_policy or evaluation_recording) and not evaluation_database:
        raise ValueError(
            "evaluation policy or recording requires AGENTSEC_EVALUATION_DB"
        )
    if evaluation_database:
        evaluation_tenant = os.environ.get(
            "AGENTSEC_EVALUATION_TENANT",
            (
                simulation_principal.tenant_id
                if simulation_principal is not None
                else integration_principal.tenant_id
                if integration_principal is not None
                else response_principal.tenant_id
                if response_principal is not None
                else notification_principal.tenant_id
                if notification_principal is not None
                else case_principal.tenant_id
                if case_principal is not None
                else analyst_principal.tenant_id
                if analyst_principal is not None
                else model_gateway_principal.tenant_id
                if model_gateway_principal is not None
                else enrichment_principal.tenant_id
                if enrichment_principal is not None
                else correlation_principal.tenant_id
                if correlation_principal is not None
                else behavior_principal.tenant_id
                if behavior_principal is not None
                else detection_principal.tenant_id
                if detection_principal is not None
                else inventory_principal.tenant_id
                if inventory_principal is not None
                else search_tenant
            ),
        )
        if not evaluation_tenant:
            raise ValueError(
                "continuous evaluation requires AGENTSEC_EVALUATION_TENANT or another configured product tenant"
            )
        evaluation_service, evaluation_principal = evaluation_service_from_environment(
            evaluation_database,
            tenant_id=evaluation_tenant,
            policy_path=evaluation_policy or None,
            recording_path=evaluation_recording or None,
        )
    if administration_config and not administration_database:
        raise ValueError("administration config requires AGENTSEC_ADMIN_DB")
    if administration_database:
        administration_tenant = os.environ.get(
            "AGENTSEC_ADMIN_TENANT",
            (
                evaluation_principal.tenant_id
                if evaluation_principal is not None
                else simulation_principal.tenant_id
                if simulation_principal is not None
                else integration_principal.tenant_id
                if integration_principal is not None
                else response_principal.tenant_id
                if response_principal is not None
                else notification_principal.tenant_id
                if notification_principal is not None
                else case_principal.tenant_id
                if case_principal is not None
                else analyst_principal.tenant_id
                if analyst_principal is not None
                else model_gateway_principal.tenant_id
                if model_gateway_principal is not None
                else enrichment_principal.tenant_id
                if enrichment_principal is not None
                else correlation_principal.tenant_id
                if correlation_principal is not None
                else behavior_principal.tenant_id
                if behavior_principal is not None
                else detection_principal.tenant_id
                if detection_principal is not None
                else inventory_principal.tenant_id
                if inventory_principal is not None
                else search_tenant
            ),
        )
        if not administration_tenant:
            raise ValueError(
                "administration requires AGENTSEC_ADMIN_TENANT or another configured product tenant"
            )
        administration_service, administration_principal = (
            administration_service_from_environment(
                administration_database,
                tenant_id=administration_tenant,
                config_path=administration_config or None,
            )
        )
    if (
        search_service is None
        and inventory_service is None
        and graph_service is None
        and posture_service is None
        and detection_service is None
        and content_service is None
        and behavior_service is None
        and correlation_service is None
        and enrichment_principal is None
        and analyst_service is None
        and model_gateway_service is None
        and case_service is None
        and notification_service is None
        and response_service is None
        and integration_service is None
        and simulation_service is None
        and evaluation_service is None
        and administration_service is None
    ):
        return AuthorizationApplication(active_pipeline)
    return AuthorizationApplication(
        active_pipeline,
        canonical_repository=repository,
        search_service=search_service,
        search_principal=search_principal,
        inventory_service=inventory_service,
        inventory_principal=inventory_principal,
        graph_service=graph_service,
        graph_principal=graph_principal,
        posture_service=posture_service,
        posture_principal=posture_principal,
        detection_service=detection_service,
        detection_principal=detection_principal,
        content_service=content_service,
        content_principal=content_principal,
        behavior_service=behavior_service,
        behavior_principal=behavior_principal,
        correlation_service=correlation_service,
        correlation_principal=correlation_principal,
        enrichment_principal=enrichment_principal,
        analyst_service=analyst_service,
        analyst_principal=analyst_principal,
        model_gateway_service=model_gateway_service,
        model_gateway_principal=model_gateway_principal,
        case_service=case_service,
        case_principal=case_principal,
        notification_service=notification_service,
        notification_principal=notification_principal,
        response_service=response_service,
        response_principal=response_principal,
        integration_service=integration_service,
        integration_principal=integration_principal,
        simulation_service=simulation_service,
        simulation_principal=simulation_principal,
        evaluation_service=evaluation_service,
        evaluation_principal=evaluation_principal,
        administration_service=administration_service,
        administration_principal=administration_principal,
        inventory_application_id=os.environ.get(
            "AGENTSEC_INVENTORY_APPLICATION_ID", "authorization-service"
        ),
    )


def main() -> int:
    bearer_token = os.environ.get("AGENTSEC_INGEST_TOKEN", "")
    host = os.environ.get("AGENTSEC_BIND_HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("AGENTSEC_PORT", "8080"))
    except ValueError as exc:
        raise ValueError("AGENTSEC_PORT must be an integer") from exc
    ingestion_gateway = gateway_from_environment()
    external_policy = os.environ.get("AGENTSEC_EXTERNAL_API_CLIENTS_CONFIG", "")
    external_api_authenticator = (
        ExternalApiAuthenticator.from_config(external_policy)
        if external_policy
        else None
    )
    serve(
        host=host,
        port=port,
        bearer_token=bearer_token,
        application=application_from_environment(),
        ingestion_gateway=ingestion_gateway,
        external_api_authenticator=external_api_authenticator,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
