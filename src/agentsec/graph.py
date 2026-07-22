"""Metadata-only temporal causal graph and source-to-sink reconstruction."""

from __future__ import annotations

from collections import deque
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from pydantic import Field

from .contracts import EventProcessingResult, StrictModel, utc_now


class GraphNode(StrictModel):
    node_id: str
    node_type: str
    tenant_id: str
    labels: Dict[str, str] = Field(default_factory=dict)


class GraphEdge(StrictModel):
    edge_id: str
    source_node_id: str
    target_node_id: str
    edge_type: str
    tenant_id: str
    flow_id: str
    source_event_id: str
    observed_at: datetime = Field(default_factory=utc_now)


class CausalPath(StrictModel):
    tenant_id: str
    flow_id: str
    source_node_id: str
    sink_node_id: str
    node_ids: List[str]
    edge_ids: List[str]


class CausalGraph:
    def __init__(self) -> None:
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[str, GraphEdge] = {}

    def _node(self, node_id: str, node_type: str, tenant_id: str, **labels: str) -> None:
        self.nodes.setdefault(
            node_id,
            GraphNode(
                node_id=node_id,
                node_type=node_type,
                tenant_id=tenant_id,
                labels=labels,
            ),
        )

    def _edge(
        self,
        source: str,
        target: str,
        edge_type: str,
        result: EventProcessingResult,
        suffix: str,
    ) -> None:
        event = result.event
        edge_id = "%s:%s:%s" % (event.event_id, edge_type, suffix)
        self.edges[edge_id] = GraphEdge(
            edge_id=edge_id,
            source_node_id=source,
            target_node_id=target,
            edge_type=edge_type,
            tenant_id=event.tenant_id,
            flow_id=event.flow_id,
            source_event_id=event.event_id,
            observed_at=event.occurred_at,
        )

    def ingest(self, result: EventProcessingResult) -> None:
        event = result.event
        source = "source:%s" % event.source_id
        agent = "agent:%s" % event.agent_id
        resource = "resource:%s" % event.resource
        self._node(source, "source", event.tenant_id, trust=event.source_trust.value)
        self._node(agent, "agent", event.tenant_id)
        self._node(resource, "resource", event.tenant_id)
        self._edge(source, agent, "INFLUENCES", result, "source-agent")
        self._edge(agent, resource, "CALLS", result, "agent-resource")
        previous = resource
        if event.destination:
            destination = "destination:%s" % event.destination
            self._node(destination, "destination", event.tenant_id)
            self._edge(resource, destination, "SENDS_TO", result, "resource-destination")
            previous = destination
        for index, item in enumerate(result.alerts):
            decision = "decision:%s" % item.judgment.alert_id
            finding = "finding:%s" % item.finding.finding_id
            self._node(
                decision,
                "decision",
                event.tenant_id,
                action=item.judgment.action.value,
            )
            self._node(
                finding,
                "finding",
                event.tenant_id,
                severity=item.finding.severity.value,
            )
            self._edge(previous, decision, "AUTHORIZED_BY", result, "decision-%d" % index)
            self._edge(decision, finding, "PARENT_OF", result, "finding-%d" % index)

    def path(self, source_node_id: str, sink_node_id: str, flow_id: str) -> Optional[CausalPath]:
        queue = deque([(source_node_id, [source_node_id], [])])
        visited: Set[str] = set()
        adjacency: Dict[str, List[Tuple[str, str]]] = {}
        for edge in self.edges.values():
            if edge.flow_id != flow_id:
                continue
            adjacency.setdefault(edge.source_node_id, []).append(
                (edge.target_node_id, edge.edge_id)
            )
        while queue:
            current, nodes, edges = queue.popleft()
            if current == sink_node_id:
                tenant_id = self.nodes[current].tenant_id
                return CausalPath(
                    tenant_id=tenant_id,
                    flow_id=flow_id,
                    source_node_id=source_node_id,
                    sink_node_id=sink_node_id,
                    node_ids=nodes,
                    edge_ids=edges,
                )
            if current in visited:
                continue
            visited.add(current)
            for next_node, edge_id in adjacency.get(current, []):
                queue.append((next_node, nodes + [next_node], edges + [edge_id]))
        return None
