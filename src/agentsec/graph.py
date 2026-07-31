"""Metadata-only temporal causal graph and source-to-sink reconstruction."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from enum import Enum
import hashlib
import heapq
import json
import re
import sqlite3
import threading
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from pydantic import Field

from .contracts import EventProcessingResult, Severity, StrictModel, utc_now


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


GRAPH_READ = "graph:read"
GRAPH_WRITE = "graph:write"
GRAPH_ANALYZE = "graph:analyze"
MAX_GRAPH_NODES = 10000
MAX_ANALYSIS_NODES = 5000


class GraphAuthorizationError(PermissionError):
    """Raised when a tenant graph principal lacks a required permission."""


class SecurityNodeType(str, Enum):
    APPLICATION = "application"
    AGENT = "agent"
    MODEL = "model"
    TOOL = "tool"
    DATA_STORE = "data_store"
    SOURCE = "source"
    RESOURCE = "resource"
    DESTINATION = "destination"
    DECISION = "decision"
    FINDING = "finding"


class SecurityEdgeType(str, Enum):
    CONTAINS = "contains"
    USES_MODEL = "uses_model"
    USES_TOOL = "uses_tool"
    ACCESSES = "accesses"
    INFLUENCES = "influences"
    CALLS = "calls"
    SENDS_TO = "sends_to"
    AUTHORIZED_BY = "authorized_by"
    PRODUCES = "produces"


class GraphPrincipal(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=1, max_length=256)
    permissions: Set[str] = Field(default_factory=set, max_length=16)

    @classmethod
    def _permission_pattern(cls) -> re.Pattern[str]:
        return re.compile(r"[a-z]+:[a-z]+")

    def model_post_init(self, __context: Any) -> None:
        if any(self._permission_pattern().fullmatch(item) is None for item in self.permissions):
            raise ValueError("graph permissions must use namespace:operation")


def _safe_labels(value: Dict[str, str]) -> Dict[str, str]:
    if len(value) > 32:
        raise ValueError("graph labels are limited to 32 fields")
    forbidden = re.compile(
        r"(?:prompt|content|argument|result|secret|token|password|credential|authorization|api[_-]?key)",
        re.IGNORECASE,
    )
    for key, item in value.items():
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", key):
            raise ValueError("graph label key is invalid")
        if forbidden.search(key):
            raise ValueError("sensitive graph label is forbidden")
        if not isinstance(item, str) or len(item) > 512:
            raise ValueError("graph label value is invalid")
    return value


class GraphNodeInput(StrictModel):
    node_id: str = Field(min_length=3, max_length=512)
    node_type: SecurityNodeType
    name: str = Field(min_length=1, max_length=256)
    risk_score: int = Field(default=0, ge=0, le=100)
    criticality: Severity = Severity.MEDIUM
    labels: Dict[str, str] = Field(default_factory=dict)
    source_ref: str = Field(min_length=1, max_length=512)
    observed_at: datetime = Field(default_factory=utc_now)

    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("graph time must include a timezone")
        return value

    def model_post_init(self, __context: Any) -> None:
        self._aware(self.observed_at)
        _safe_labels(self.labels)


class GraphEdgeInput(StrictModel):
    edge_id: str = Field(min_length=3, max_length=512)
    source_node_id: str = Field(min_length=3, max_length=512)
    target_node_id: str = Field(min_length=3, max_length=512)
    edge_type: SecurityEdgeType
    weight: float = Field(ge=0.1, le=100.0)
    risk_factors: List[str] = Field(default_factory=list, max_length=64)
    evidence_refs: List[str] = Field(default_factory=list, max_length=64)
    source_ref: str = Field(min_length=1, max_length=512)
    observed_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        if self.source_node_id == self.target_node_id:
            raise ValueError("security graph self edges are forbidden")
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("graph time must include a timezone")
        if any(not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", item) for item in self.risk_factors):
            raise ValueError("graph risk factor is invalid")
        if any(not 1 <= len(item) <= 512 for item in self.evidence_refs):
            raise ValueError("graph evidence reference is invalid")


class SecurityGraphNode(StrictModel):
    tenant_id: str
    node_id: str
    version: int = Field(ge=1)
    node_type: SecurityNodeType
    name: str
    risk_score: int = Field(ge=0, le=100)
    criticality: Severity
    labels: Dict[str, str]
    source_ref: str
    valid_from: datetime
    valid_to: Optional[datetime] = None
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SecurityGraphEdge(StrictModel):
    tenant_id: str
    edge_id: str
    version: int = Field(ge=1)
    source_node_id: str
    target_node_id: str
    edge_type: SecurityEdgeType
    weight: float = Field(ge=0.1, le=100.0)
    risk_factors: List[str]
    evidence_refs: List[str]
    source_ref: str
    valid_from: datetime
    valid_to: Optional[datetime] = None
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SecurityGraphSnapshot(StrictModel):
    tenant_id: str
    as_of: datetime
    nodes: List[SecurityGraphNode]
    edges: List[SecurityGraphEdge]
    truncated: bool = False


class GraphIngestResult(StrictModel):
    tenant_id: str
    nodes_written: int = Field(ge=0)
    edges_written: int = Field(ge=0)
    node_versions_created: int = Field(ge=0)
    edge_versions_created: int = Field(ge=0)
    observed_at: datetime


class WeightedAttackPath(StrictModel):
    tenant_id: str
    source_node_id: str
    target_node_id: str
    node_ids: List[str]
    edge_ids: List[str]
    total_weight: float = Field(ge=0.0)
    exposure_score: int = Field(ge=0, le=100)
    risk_factors: List[str]
    as_of: datetime


class AttackPathResult(StrictModel):
    tenant_id: str
    source_node_id: str
    target_node_id: str
    paths: List[WeightedAttackPath]
    explored_states: int = Field(ge=0)
    truncated: bool
    as_of: datetime


class ReachableNode(StrictModel):
    node_id: str
    depth: int = Field(ge=0)
    risk_score: int = Field(ge=0, le=100)
    via_edge_id: Optional[str] = None


class ReachabilityResult(StrictModel):
    tenant_id: str
    origin_node_id: str
    direction: str = Field(pattern=r"^(outbound|inbound)$")
    reachable: List[ReachableNode]
    max_depth: int = Field(ge=1, le=20)
    truncated: bool
    as_of: datetime


class BlastRadiusResult(StrictModel):
    tenant_id: str
    origin_node_id: str
    impacted_nodes: List[ReachableNode]
    impacted_count: int = Field(ge=0)
    high_risk_count: int = Field(ge=0)
    maximum_risk_score: int = Field(ge=0, le=100)
    as_of: datetime


class SecurityGraphSummary(StrictModel):
    tenant_id: str
    as_of: datetime
    node_count: int = Field(ge=0)
    edge_count: int = Field(ge=0)
    by_node_type: Dict[SecurityNodeType, int]
    high_risk_nodes: int = Field(ge=0)
    external_destinations: int = Field(ge=0)


def _record_digest(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _entity_node_id(kind: str, value: str) -> str:
    candidate = "%s:%s" % (kind, value)
    if len(candidate) <= 512:
        return candidate
    return "%s:sha256:%s" % (kind, hashlib.sha256(value.encode("utf-8")).hexdigest())


def _entity_name(value: str) -> str:
    return value if len(value) <= 256 else value[:255] + "…"


class SecurityGraphService:
    """Durable temporal graph with bounded reachability and attack-path analysis."""

    def __init__(
        self, path: str, *, clock: Callable[[], datetime] = utc_now
    ) -> None:
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
            raise ValueError("graph clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    def _migrate(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS security_graph_nodes (
                tenant_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                node_type TEXT NOT NULL,
                name TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                criticality TEXT NOT NULL,
                labels_json TEXT NOT NULL,
                source_ref TEXT NOT NULL,
                valid_from TEXT NOT NULL,
                valid_to TEXT,
                record_sha256 TEXT NOT NULL,
                PRIMARY KEY (tenant_id, node_id, version)
            );
            CREATE TABLE IF NOT EXISTS security_graph_edges (
                tenant_id TEXT NOT NULL,
                edge_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                source_node_id TEXT NOT NULL,
                target_node_id TEXT NOT NULL,
                edge_type TEXT NOT NULL,
                weight REAL NOT NULL,
                risk_factors_json TEXT NOT NULL,
                evidence_refs_json TEXT NOT NULL,
                source_ref TEXT NOT NULL,
                valid_from TEXT NOT NULL,
                valid_to TEXT,
                record_sha256 TEXT NOT NULL,
                PRIMARY KEY (tenant_id, edge_id, version)
            );
            CREATE TABLE IF NOT EXISTS security_graph_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                action TEXT NOT NULL,
                subject TEXT NOT NULL,
                occurred_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS security_graph_current_node
                ON security_graph_nodes(tenant_id, node_id) WHERE valid_to IS NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS security_graph_current_edge
                ON security_graph_edges(tenant_id, edge_id) WHERE valid_to IS NULL;
            CREATE INDEX IF NOT EXISTS security_graph_node_time
                ON security_graph_nodes(tenant_id, valid_from, valid_to, node_type);
            CREATE INDEX IF NOT EXISTS security_graph_edge_time_source
                ON security_graph_edges(tenant_id, valid_from, valid_to, source_node_id);
            CREATE INDEX IF NOT EXISTS security_graph_edge_time_target
                ON security_graph_edges(tenant_id, valid_from, valid_to, target_node_id);
            """
        )

    @staticmethod
    def _require(principal: GraphPrincipal, permission: str) -> None:
        if permission not in principal.permissions:
            raise GraphAuthorizationError("missing permission: %s" % permission)

    def _audit(self, principal: GraphPrincipal, action: str, subject: str) -> None:
        self._connection.execute(
            "INSERT INTO security_graph_audit(tenant_id, actor_id, action, subject, occurred_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (principal.tenant_id, principal.actor_id, action, subject[:512], self._now().isoformat()),
        )

    @staticmethod
    def _node_row(row: sqlite3.Row) -> SecurityGraphNode:
        return SecurityGraphNode(
            tenant_id=row["tenant_id"], node_id=row["node_id"], version=row["version"],
            node_type=row["node_type"], name=row["name"], risk_score=row["risk_score"],
            criticality=row["criticality"], labels=json.loads(row["labels_json"]),
            source_ref=row["source_ref"], valid_from=row["valid_from"], valid_to=row["valid_to"],
            record_sha256=row["record_sha256"],
        )

    @staticmethod
    def _edge_row(row: sqlite3.Row) -> SecurityGraphEdge:
        return SecurityGraphEdge(
            tenant_id=row["tenant_id"], edge_id=row["edge_id"], version=row["version"],
            source_node_id=row["source_node_id"], target_node_id=row["target_node_id"],
            edge_type=row["edge_type"], weight=row["weight"],
            risk_factors=json.loads(row["risk_factors_json"]),
            evidence_refs=json.loads(row["evidence_refs_json"]), source_ref=row["source_ref"],
            valid_from=row["valid_from"], valid_to=row["valid_to"], record_sha256=row["record_sha256"],
        )

    def _put_node(self, principal: GraphPrincipal, item: GraphNodeInput) -> bool:
        payload = item.model_dump(mode="json", exclude={"observed_at"})
        digest = _record_digest(payload)
        observed = item.observed_at.astimezone(timezone.utc).isoformat()
        current = self._connection.execute(
            "SELECT * FROM security_graph_nodes WHERE tenant_id = ? AND node_id = ? "
            "AND valid_to IS NULL",
            (principal.tenant_id, item.node_id),
        ).fetchone()
        if current is not None and current["record_sha256"] == digest:
            return False
        if current is not None and observed < current["valid_from"]:
            raise ValueError("late graph node revisions must be replayed in chronological order")
        version = 1 + int(
            self._connection.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM security_graph_nodes "
                "WHERE tenant_id = ? AND node_id = ?",
                (principal.tenant_id, item.node_id),
            ).fetchone()["version"]
        )
        if current is not None:
            if observed == current["valid_from"]:
                raise ValueError("conflicting graph node revisions share one timestamp")
            self._connection.execute(
                "UPDATE security_graph_nodes SET valid_to = ? WHERE tenant_id = ? "
                "AND node_id = ? AND version = ?",
                (observed, principal.tenant_id, item.node_id, current["version"]),
            )
        self._connection.execute(
            "INSERT INTO security_graph_nodes(tenant_id, node_id, version, node_type, name, risk_score, "
            "criticality, labels_json, source_ref, valid_from, valid_to, record_sha256) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)",
            (
                principal.tenant_id, item.node_id, version, item.node_type.value, item.name,
                item.risk_score, item.criticality.value, json.dumps(item.labels, sort_keys=True),
                item.source_ref, observed, digest,
            ),
        )
        return True

    def _put_edge(self, principal: GraphPrincipal, item: GraphEdgeInput) -> bool:
        for node_id in (item.source_node_id, item.target_node_id):
            exists = self._connection.execute(
                "SELECT 1 FROM security_graph_nodes WHERE tenant_id = ? AND node_id = ? "
                "AND valid_to IS NULL",
                (principal.tenant_id, node_id),
            ).fetchone()
            if exists is None:
                raise ValueError("graph edge references an unknown current node")
        payload = item.model_dump(mode="json", exclude={"observed_at"})
        digest = _record_digest(payload)
        observed = item.observed_at.astimezone(timezone.utc).isoformat()
        current = self._connection.execute(
            "SELECT * FROM security_graph_edges WHERE tenant_id = ? AND edge_id = ? "
            "AND valid_to IS NULL",
            (principal.tenant_id, item.edge_id),
        ).fetchone()
        if current is not None and current["record_sha256"] == digest:
            return False
        if current is not None:
            if (
                current["source_node_id"] != item.source_node_id
                or current["target_node_id"] != item.target_node_id
                or current["edge_type"] != item.edge_type.value
            ):
                raise ValueError("graph edge identity cannot change endpoints or type")
            if observed <= current["valid_from"]:
                raise ValueError("graph edge revisions must be chronological")
        version = 1 + int(
            self._connection.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM security_graph_edges "
                "WHERE tenant_id = ? AND edge_id = ?",
                (principal.tenant_id, item.edge_id),
            ).fetchone()["version"]
        )
        if current is not None:
            self._connection.execute(
                "UPDATE security_graph_edges SET valid_to = ? WHERE tenant_id = ? "
                "AND edge_id = ? AND version = ?",
                (observed, principal.tenant_id, item.edge_id, current["version"]),
            )
        self._connection.execute(
            "INSERT INTO security_graph_edges(tenant_id, edge_id, version, source_node_id, "
            "target_node_id, edge_type, weight, risk_factors_json, evidence_refs_json, source_ref, "
            "valid_from, valid_to, record_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)",
            (
                principal.tenant_id, item.edge_id, version, item.source_node_id,
                item.target_node_id, item.edge_type.value, item.weight,
                json.dumps(sorted(set(item.risk_factors))),
                json.dumps(sorted(set(item.evidence_refs))), item.source_ref, observed, digest,
            ),
        )
        return True

    def ingest(
        self,
        principal: GraphPrincipal,
        nodes: Sequence[GraphNodeInput],
        edges: Sequence[GraphEdgeInput],
    ) -> GraphIngestResult:
        self._require(principal, GRAPH_WRITE)
        if not nodes and not edges:
            raise ValueError("graph ingest must contain nodes or edges")
        if len(nodes) > MAX_GRAPH_NODES or len(edges) > MAX_GRAPH_NODES * 5:
            raise ValueError("graph ingest batch exceeds the safety limit")
        observed_at = max(
            [item.observed_at for item in nodes] + [item.observed_at for item in edges]
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                node_versions = sum(self._put_node(principal, item) for item in nodes)
                edge_versions = sum(self._put_edge(principal, item) for item in edges)
                self._audit(principal, "graph.ingest", "%d/%d" % (len(nodes), len(edges)))
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return GraphIngestResult(
            tenant_id=principal.tenant_id,
            nodes_written=len(nodes), edges_written=len(edges),
            node_versions_created=node_versions, edge_versions_created=edge_versions,
            observed_at=observed_at,
        )

    @staticmethod
    def _event_graph(result: EventProcessingResult) -> Tuple[List[GraphNodeInput], List[GraphEdgeInput]]:
        event = result.event
        at = event.occurred_at
        source = _entity_node_id("source", event.source_id)
        agent = _entity_node_id("agent", event.agent_id)
        resource = _entity_node_id("resource", event.resource)
        source_risk = 70 if event.source_trust.value in {"external-untrusted", "suspected-adversarial"} else 20
        nodes = [
            GraphNodeInput(
                node_id=source, node_type=SecurityNodeType.SOURCE, name=_entity_name(event.source_id),
                risk_score=source_risk, labels={"trust": event.source_trust.value},
                source_ref=source, observed_at=at,
            ),
            GraphNodeInput(
                node_id=agent, node_type=SecurityNodeType.AGENT, name=_entity_name(event.agent_id),
                risk_score=0, labels={}, source_ref=agent, observed_at=at,
            ),
            GraphNodeInput(
                node_id=resource, node_type=SecurityNodeType.RESOURCE, name=_entity_name(event.resource),
                risk_score=60 if "secret" in event.data_classes else 20,
                criticality=Severity.CRITICAL if "secret" in event.data_classes else Severity.MEDIUM,
                labels={"resource_class": event.resource.split(":", 1)[0]},
                source_ref=resource, observed_at=at,
            ),
        ]
        edges = [
            GraphEdgeInput(
                edge_id="%s:influences" % event.event_id, source_node_id=source,
                target_node_id=agent, edge_type=SecurityEdgeType.INFLUENCES,
                weight=5.0 if source_risk >= 60 else 35.0,
                risk_factors=["UNTRUSTED_INFLUENCE"] if source_risk >= 60 else [],
                evidence_refs=["event://%s" % event.event_id], source_ref="event://%s" % event.event_id,
                observed_at=at,
            ),
            GraphEdgeInput(
                edge_id="%s:calls" % event.event_id, source_node_id=agent,
                target_node_id=resource, edge_type=SecurityEdgeType.CALLS,
                weight=10.0 if event.is_effectful else 30.0,
                risk_factors=["EFFECTFUL_OPERATION"] if event.is_effectful else [],
                evidence_refs=["event://%s" % event.event_id], source_ref="event://%s" % event.event_id,
                observed_at=at,
            ),
        ]
        destination: Optional[str] = None
        if event.destination:
            destination = _entity_node_id("destination", event.destination)
            nodes.append(
                GraphNodeInput(
                    node_id=destination, node_type=SecurityNodeType.DESTINATION,
                    name=_entity_name(event.destination), risk_score=70,
                    labels={"scope": "external" if event.destination.startswith(("http://", "https://")) else "opaque"},
                    source_ref=destination, observed_at=at,
                )
            )
            if not result.alerts:
                edges.append(
                    GraphEdgeInput(
                        edge_id="%s:sends" % event.event_id, source_node_id=resource,
                        target_node_id=destination, edge_type=SecurityEdgeType.SENDS_TO,
                        weight=3.0 if "secret" in event.data_classes else 15.0,
                        risk_factors=["EXTERNAL_DESTINATION"] + (["SENSITIVE_DATA_PATH"] if event.data_classes else []),
                        evidence_refs=["event://%s" % event.event_id], source_ref="event://%s" % event.event_id,
                        observed_at=at,
                    )
                )
        for index, item in enumerate(result.alerts):
            decision = "decision:%s" % item.alert.alert_id
            finding = "finding:%s" % item.finding.finding_id
            nodes.extend(
                [
                    GraphNodeInput(
                        node_id=decision, node_type=SecurityNodeType.DECISION,
                        name=item.judgment.action.value, risk_score=item.triage.risk_score,
                        criticality=item.triage.severity,
                        labels={"action": item.judgment.action.value},
                        source_ref="alert://%s" % item.alert.alert_id, observed_at=at,
                    ),
                    GraphNodeInput(
                        node_id=finding, node_type=SecurityNodeType.FINDING,
                        name=item.alert.title, risk_score=item.triage.risk_score,
                        criticality=item.finding.severity,
                        labels={"severity": item.finding.severity.value},
                        source_ref="finding://%s" % item.finding.finding_id, observed_at=at,
                    ),
                ]
            )
            decision_weight = {
                "deny": 90.0,
                "require_approval": 55.0,
                "allow_with_obligations": 20.0,
                "allow": 5.0,
            }[item.judgment.action.value]
            edges.extend(
                [
                    GraphEdgeInput(
                        edge_id="%s:decision:%d" % (event.event_id, index),
                        source_node_id=resource, target_node_id=decision,
                        edge_type=SecurityEdgeType.AUTHORIZED_BY, weight=decision_weight,
                        risk_factors=["SECURITY_DECISION_%s" % item.judgment.action.value.upper()],
                        evidence_refs=list(item.alert.evidence), source_ref="alert://%s" % item.alert.alert_id,
                        observed_at=at,
                    ),
                    GraphEdgeInput(
                        edge_id="%s:finding:%d" % (event.event_id, index),
                        source_node_id=decision, target_node_id=finding,
                        edge_type=SecurityEdgeType.PRODUCES, weight=1.0,
                        risk_factors=["SECURITY_FINDING"], evidence_refs=list(item.alert.evidence),
                        source_ref="finding://%s" % item.finding.finding_id, observed_at=at,
                    ),
                ]
            )
            if destination is not None:
                edges.append(
                    GraphEdgeInput(
                        edge_id="%s:sends:%d" % (event.event_id, index),
                        source_node_id=decision,
                        target_node_id=destination,
                        edge_type=SecurityEdgeType.SENDS_TO,
                        weight=3.0 if "secret" in event.data_classes else 15.0,
                        risk_factors=["EXTERNAL_DESTINATION"]
                        + (["SENSITIVE_DATA_PATH"] if event.data_classes else []),
                        evidence_refs=list(item.alert.evidence),
                        source_ref="alert://%s" % item.alert.alert_id,
                        observed_at=at,
                    )
                )
        return nodes, edges

    def ingest_processing_result(
        self, principal: GraphPrincipal, result: EventProcessingResult
    ) -> GraphIngestResult:
        if result.event.tenant_id != principal.tenant_id:
            raise GraphAuthorizationError("cross-tenant event graph ingest is forbidden")
        nodes, edges = self._event_graph(result)
        return self.ingest(principal, nodes, edges)

    def ingest_inventory(
        self,
        principal: GraphPrincipal,
        components: Sequence[Any],
        relationships: Sequence[Any],
        *,
        observed_at: Optional[datetime] = None,
    ) -> GraphIngestResult:
        if any(item.tenant_id != principal.tenant_id for item in components) or any(
            item.tenant_id != principal.tenant_id for item in relationships
        ):
            raise GraphAuthorizationError("cross-tenant inventory graph ingest is forbidden")
        at = observed_at or self._now()
        nodes = [
            GraphNodeInput(
                node_id=item.component_id,
                node_type=SecurityNodeType(item.kind.value),
                name=item.name,
                risk_score=item.risk_score,
                criticality=item.criticality,
                labels={
                    "status": item.status.value,
                    "source": item.source.value,
                    **({"owner": item.owner_ref} if item.owner_ref else {}),
                },
                source_ref="inventory://%s" % item.component_id,
                observed_at=at,
            )
            for item in components
        ]
        relationship_types = {
            "contains": SecurityEdgeType.CONTAINS,
            "uses_model": SecurityEdgeType.USES_MODEL,
            "uses_tool": SecurityEdgeType.USES_TOOL,
            "accesses": SecurityEdgeType.ACCESSES,
        }
        edges = [
            GraphEdgeInput(
                edge_id="inventory:%s:%s:%s" % (
                    item.source_component_id, item.relationship.value, item.target_component_id
                ),
                source_node_id=item.source_component_id,
                target_node_id=item.target_component_id,
                edge_type=relationship_types[item.relationship.value],
                weight=10.0,
                risk_factors=[], evidence_refs=[item.source_ref],
                source_ref=item.source_ref, observed_at=at,
            )
            for item in relationships
        ]
        return self.ingest(principal, nodes, edges)

    def snapshot(
        self,
        principal: GraphPrincipal,
        *,
        as_of: Optional[datetime] = None,
        limit: int = MAX_GRAPH_NODES,
    ) -> SecurityGraphSnapshot:
        self._require(principal, GRAPH_READ)
        if not 1 <= limit <= MAX_GRAPH_NODES:
            raise ValueError("graph snapshot limit is invalid")
        point = as_of or self._now()
        if point.tzinfo is None or point.utcoffset() is None:
            raise ValueError("graph snapshot time must include a timezone")
        point = point.astimezone(timezone.utc)
        encoded = point.isoformat()
        with self._lock:
            nodes = self._connection.execute(
                "SELECT * FROM security_graph_nodes WHERE tenant_id = ? AND valid_from <= ? "
                "AND (valid_to IS NULL OR valid_to > ?) ORDER BY node_type, node_id LIMIT ?",
                (principal.tenant_id, encoded, encoded, limit + 1),
            ).fetchall()
            node_ids = {row["node_id"] for row in nodes[:limit]}
            edges = self._connection.execute(
                "SELECT * FROM security_graph_edges WHERE tenant_id = ? AND valid_from <= ? "
                "AND (valid_to IS NULL OR valid_to > ?) ORDER BY edge_type, edge_id LIMIT ?",
                (principal.tenant_id, encoded, encoded, limit * 5 + 1),
            ).fetchall()
            self._audit(principal, "graph.snapshot", encoded)
        active_edges = [
            self._edge_row(row)
            for row in edges
            if row["source_node_id"] in node_ids and row["target_node_id"] in node_ids
        ]
        truncated = len(nodes) > limit or len(edges) > limit * 5
        return SecurityGraphSnapshot(
            tenant_id=principal.tenant_id,
            as_of=point,
            nodes=[self._node_row(row) for row in nodes[:limit]],
            edges=active_edges[: limit * 5],
            truncated=truncated,
        )

    @staticmethod
    def _topology(snapshot: SecurityGraphSnapshot, direction: str = "outbound") -> Dict[str, List[Tuple[str, SecurityGraphEdge]]]:
        adjacency: Dict[str, List[Tuple[str, SecurityGraphEdge]]] = {}
        for edge in snapshot.edges:
            source, target = (
                (edge.source_node_id, edge.target_node_id)
                if direction == "outbound"
                else (edge.target_node_id, edge.source_node_id)
            )
            adjacency.setdefault(source, []).append((target, edge))
        for values in adjacency.values():
            values.sort(key=lambda pair: (pair[1].weight, pair[1].edge_id))
        return adjacency

    def reachability(
        self,
        principal: GraphPrincipal,
        origin_node_id: str,
        *,
        direction: str = "outbound",
        max_depth: int = 8,
        max_nodes: int = MAX_ANALYSIS_NODES,
        as_of: Optional[datetime] = None,
    ) -> ReachabilityResult:
        self._require(principal, GRAPH_ANALYZE)
        if direction not in {"outbound", "inbound"}:
            raise ValueError("graph direction is invalid")
        if not 1 <= max_depth <= 20 or not 1 <= max_nodes <= MAX_ANALYSIS_NODES:
            raise ValueError("reachability safety limit is invalid")
        snapshot = self.snapshot(
            principal.model_copy(update={"permissions": principal.permissions | {GRAPH_READ}}),
            as_of=as_of,
            limit=MAX_GRAPH_NODES,
        )
        nodes = {item.node_id: item for item in snapshot.nodes}
        if origin_node_id not in nodes:
            raise KeyError(origin_node_id)
        adjacency = self._topology(snapshot, direction)
        queue = deque([(origin_node_id, 0, None)])
        visited: Set[str] = set()
        reachable: List[ReachableNode] = []
        truncated = False
        while queue:
            node_id, depth, via = queue.popleft()
            if node_id in visited:
                continue
            visited.add(node_id)
            if node_id != origin_node_id:
                reachable.append(
                    ReachableNode(
                        node_id=node_id,
                        depth=depth,
                        risk_score=nodes[node_id].risk_score,
                        via_edge_id=via,
                    )
                )
                if len(reachable) >= max_nodes:
                    truncated = bool(queue or adjacency.get(node_id))
                    break
            if depth >= max_depth:
                if adjacency.get(node_id):
                    truncated = True
                continue
            for next_id, edge in adjacency.get(node_id, []):
                if next_id not in visited:
                    queue.append((next_id, depth + 1, edge.edge_id))
        reachable.sort(key=lambda item: (item.depth, -item.risk_score, item.node_id))
        return ReachabilityResult(
            tenant_id=principal.tenant_id, origin_node_id=origin_node_id,
            direction=direction, reachable=reachable, max_depth=max_depth,
            truncated=truncated or snapshot.truncated, as_of=snapshot.as_of,
        )

    def blast_radius(
        self,
        principal: GraphPrincipal,
        origin_node_id: str,
        *,
        max_depth: int = 8,
        as_of: Optional[datetime] = None,
    ) -> BlastRadiusResult:
        result = self.reachability(
            principal, origin_node_id, max_depth=max_depth, as_of=as_of
        )
        return BlastRadiusResult(
            tenant_id=principal.tenant_id,
            origin_node_id=origin_node_id,
            impacted_nodes=result.reachable,
            impacted_count=len(result.reachable),
            high_risk_count=sum(item.risk_score >= 60 for item in result.reachable),
            maximum_risk_score=max((item.risk_score for item in result.reachable), default=0),
            as_of=result.as_of,
        )

    def attack_paths(
        self,
        principal: GraphPrincipal,
        source_node_id: str,
        target_node_id: str,
        *,
        max_paths: int = 5,
        max_depth: int = 12,
        max_states: int = 20000,
        as_of: Optional[datetime] = None,
    ) -> AttackPathResult:
        self._require(principal, GRAPH_ANALYZE)
        if not 1 <= max_paths <= 20 or not 1 <= max_depth <= 20 or not 1 <= max_states <= 50000:
            raise ValueError("attack-path safety limit is invalid")
        snapshot = self.snapshot(
            principal.model_copy(update={"permissions": principal.permissions | {GRAPH_READ}}),
            as_of=as_of,
        )
        node_ids = {item.node_id for item in snapshot.nodes}
        if source_node_id not in node_ids or target_node_id not in node_ids:
            raise KeyError("attack path endpoint does not exist")
        adjacency = self._topology(snapshot)
        queue: List[Tuple[float, Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]] = [
            (0.0, (source_node_id,), (), ())
        ]
        paths: List[WeightedAttackPath] = []
        explored = 0
        while queue and len(paths) < max_paths and explored < max_states:
            weight, nodes, edge_ids, factors = heapq.heappop(queue)
            explored += 1
            current = nodes[-1]
            if current == target_node_id:
                paths.append(
                    WeightedAttackPath(
                        tenant_id=principal.tenant_id,
                        source_node_id=source_node_id,
                        target_node_id=target_node_id,
                        node_ids=list(nodes),
                        edge_ids=list(edge_ids),
                        total_weight=round(weight, 3),
                        exposure_score=max(0, min(100, round(100 - weight))),
                        risk_factors=sorted(set(factors)),
                        as_of=snapshot.as_of,
                    )
                )
                continue
            if len(edge_ids) >= max_depth:
                continue
            for next_id, edge in adjacency.get(current, []):
                if next_id in nodes:
                    continue
                heapq.heappush(
                    queue,
                    (
                        weight + edge.weight,
                        nodes + (next_id,),
                        edge_ids + (edge.edge_id,),
                        factors + tuple(edge.risk_factors),
                    ),
                )
        return AttackPathResult(
            tenant_id=principal.tenant_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            paths=paths,
            explored_states=explored,
            truncated=bool(queue) and (len(paths) >= max_paths or explored >= max_states),
            as_of=snapshot.as_of,
        )

    def summary(
        self, principal: GraphPrincipal, *, as_of: Optional[datetime] = None
    ) -> SecurityGraphSummary:
        snapshot = self.snapshot(principal, as_of=as_of)
        counts = {kind: 0 for kind in SecurityNodeType}
        for node in snapshot.nodes:
            counts[node.node_type] += 1
        return SecurityGraphSummary(
            tenant_id=principal.tenant_id,
            as_of=snapshot.as_of,
            node_count=len(snapshot.nodes),
            edge_count=len(snapshot.edges),
            by_node_type=counts,
            high_risk_nodes=sum(node.risk_score >= 60 for node in snapshot.nodes),
            external_destinations=sum(
                node.node_type == SecurityNodeType.DESTINATION
                and node.labels.get("scope") == "external"
                for node in snapshot.nodes
            ),
        )


__all__ = [
    "AttackPathResult",
    "BlastRadiusResult",
    "CausalGraph",
    "CausalPath",
    "GRAPH_ANALYZE",
    "GRAPH_READ",
    "GRAPH_WRITE",
    "GraphAuthorizationError",
    "GraphEdgeInput",
    "GraphIngestResult",
    "GraphNodeInput",
    "GraphPrincipal",
    "ReachabilityResult",
    "SecurityEdgeType",
    "SecurityGraphEdge",
    "SecurityGraphNode",
    "SecurityGraphService",
    "SecurityGraphSnapshot",
    "SecurityGraphSummary",
    "SecurityNodeType",
    "WeightedAttackPath",
]
