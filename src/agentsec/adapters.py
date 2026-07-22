"""Equivalent custom-dispatcher and framework-callback event normalization."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, Optional, Set

from pydantic import Field

from .contracts import AgentEvent, StrictModel, TrustClass
from .synthetic import ScenarioDefinition, SyntheticSocWorkflow, WorkflowRun


class FrameworkToolProposal(StrictModel):
    tenant_id: str
    run_id: str
    workload_id: str
    tool: Optional[str] = None
    canonical_operation: str
    resource_uri: str
    destination_uri: Optional[str] = None
    source_kind: str
    source_reference: str
    source_trust: TrustClass
    data_labels: Set[str] = Field(default_factory=set)
    effective_operations: Set[str] = Field(default_factory=set)
    security_indicators: Set[str] = Field(default_factory=set)
    approved: bool = False
    effectful: bool = True
    declared_schema_hash: Optional[str] = None
    observed_schema_hash: Optional[str] = None
    event_attributes: Dict[str, str] = Field(default_factory=dict)
    event_schema_version: str = "1.0.0"
    proposal_id: str
    proposed_at: datetime


class CustomAgentAdapter:
    """Wraps the minimal custom dispatcher using the canonical contract directly."""

    adapter_name = "custom-dispatcher-v1"

    def normalize_tool_proposal(self, payload: Dict[str, object]) -> AgentEvent:
        return AgentEvent.model_validate(payload)

    def normalize(self, definition: ScenarioDefinition) -> AgentEvent:
        return self.normalize_tool_proposal(definition.event.model_dump(mode="json"))


class CallbackFrameworkAdapter:
    """Maps framework callback vocabulary without leaking framework field names."""

    adapter_name = "callback-framework-v1"

    def normalize_tool_proposal(self, proposal: FrameworkToolProposal) -> AgentEvent:
        return AgentEvent(
            schema_version=proposal.event_schema_version,
            event_id=proposal.proposal_id,
            occurred_at=proposal.proposed_at,
            tenant_id=proposal.tenant_id,
            flow_id=proposal.run_id,
            agent_id=proposal.workload_id,
            operation=proposal.canonical_operation,
            resource=proposal.resource_uri,
            destination=proposal.destination_uri,
            source_type=proposal.source_kind,
            source_id=proposal.source_reference,
            source_trust=proposal.source_trust,
            data_classes=proposal.data_labels,
            authority_operations=proposal.effective_operations,
            indicators=proposal.security_indicators,
            approval_present=proposal.approved,
            is_effectful=proposal.effectful,
            tool_name=proposal.tool,
            declared_tool_schema_digest=proposal.declared_schema_hash,
            observed_tool_schema_digest=proposal.observed_schema_hash,
            attributes=proposal.event_attributes,
        )

    def normalize(self, definition: ScenarioDefinition) -> AgentEvent:
        return self.normalize_tool_proposal(
            framework_proposal_from_event(definition.event)
        )


def framework_proposal_from_event(event: AgentEvent) -> FrameworkToolProposal:
    """Fixture bridge used to prove both adapters emit identical contracts."""

    return FrameworkToolProposal(
        tenant_id=event.tenant_id,
        run_id=event.flow_id,
        workload_id=event.agent_id,
        tool=event.tool_name,
        canonical_operation=event.operation,
        resource_uri=event.resource,
        destination_uri=event.destination,
        source_kind=event.source_type,
        source_reference=event.source_id,
        source_trust=event.source_trust,
        data_labels=event.data_classes,
        effective_operations=event.authority_operations,
        security_indicators=event.indicators,
        approved=event.approval_present,
        effectful=event.is_effectful,
        declared_schema_hash=event.declared_tool_schema_digest,
        observed_schema_hash=event.observed_tool_schema_digest,
        event_attributes=event.attributes,
        event_schema_version=event.schema_version,
        proposal_id=event.event_id,
        proposed_at=event.occurred_at,
    )


class AdapterWorkflowRunner:
    """Runs either adapter through the identical protected workflow contract."""

    def __init__(self, adapter: object) -> None:
        self.adapter = adapter

    def run(self, definition: ScenarioDefinition) -> WorkflowRun:
        normalized = self.adapter.normalize(definition)
        adapted = definition.model_copy(update={"event": normalized})
        return SyntheticSocWorkflow().run(adapted, protected=True)
