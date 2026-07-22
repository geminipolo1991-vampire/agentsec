"""Signed declared/observed Agent Bill of Materials registry and drift engine."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Set

from pydantic import Field

from .contracts import AgentEvent, StrictModel, new_id, utc_now
from .crypto import PocHmacSigner


class ToolManifestEntry(StrictModel):
    tool_name: str
    operation: str
    schema_digest: str
    allowed_destinations: Set[str] = Field(default_factory=set)


class AbomManifest(StrictModel):
    schema_version: str = "1.0.0"
    manifest_id: str = Field(default_factory=lambda: new_id("abom"))
    tenant_id: str
    agent_id: str
    owner_id: str
    build_digest: str
    system_instruction_digest: str
    model_profile_ids: Set[str]
    tools: List[ToolManifestEntry]
    allowed_data_classes: Set[str]
    allowed_destinations: Set[str]
    policy_bundle_digest: str
    evidence_source: str = "declared"
    created_at: datetime = Field(default_factory=utc_now)
    signature_algorithm: str = PocHmacSigner.algorithm
    signature: str = ""

    def unsigned_payload(self) -> Dict[str, object]:
        return self.model_dump(mode="json", exclude={"signature"})


class AbomObservation(StrictModel):
    observation_id: str = Field(default_factory=lambda: new_id("abomobs"))
    tenant_id: str
    agent_id: str
    event_id: str
    tool_name: Optional[str]
    operation: str
    schema_digest: Optional[str]
    destination: Optional[str]
    data_classes: Set[str]
    observed_at: datetime = Field(default_factory=utc_now)


class AbomDiff(StrictModel):
    tenant_id: str
    agent_id: str
    manifest_id: Optional[str]
    unknown_agent: bool = False
    unknown_tools: Set[str] = Field(default_factory=set)
    changed_tool_schemas: Set[str] = Field(default_factory=set)
    new_operations: Set[str] = Field(default_factory=set)
    new_destinations: Set[str] = Field(default_factory=set)
    new_data_classes: Set[str] = Field(default_factory=set)

    @property
    def drifted(self) -> bool:
        return any(
            [
                self.unknown_agent,
                self.unknown_tools,
                self.changed_tool_schemas,
                self.new_operations,
                self.new_destinations,
                self.new_data_classes,
            ]
        )


class AbomRegistry:
    def __init__(self, signer: PocHmacSigner) -> None:
        self.signer = signer
        self._approved: Dict[str, AbomManifest] = {}
        self._observations: List[AbomObservation] = []

    @staticmethod
    def _key(tenant_id: str, agent_id: str) -> str:
        return "%s/%s" % (tenant_id, agent_id)

    def sign(self, manifest: AbomManifest) -> AbomManifest:
        unsigned = manifest.model_copy(update={"signature": ""})
        return unsigned.model_copy(
            update={"signature": self.signer.sign(unsigned.unsigned_payload())}
        )

    def approve(self, manifest: AbomManifest) -> None:
        if not self.signer.verify(manifest.unsigned_payload(), manifest.signature):
            raise ValueError("ABOM signature is invalid")
        key = self._key(manifest.tenant_id, manifest.agent_id)
        if key in self._approved and self._approved[key].manifest_id == manifest.manifest_id:
            raise ValueError("ABOM manifest version already exists")
        self._approved[key] = manifest

    def approved(self, tenant_id: str, agent_id: str) -> Optional[AbomManifest]:
        return self._approved.get(self._key(tenant_id, agent_id))

    def observe(self, event: AgentEvent) -> AbomDiff:
        observation = AbomObservation(
            tenant_id=event.tenant_id,
            agent_id=event.agent_id,
            event_id=event.event_id,
            tool_name=event.tool_name,
            operation=event.operation,
            schema_digest=event.observed_tool_schema_digest,
            destination=event.destination,
            data_classes=event.data_classes,
        )
        self._observations.append(observation)
        manifest = self.approved(event.tenant_id, event.agent_id)
        if manifest is None:
            return AbomDiff(
                tenant_id=event.tenant_id,
                agent_id=event.agent_id,
                manifest_id=None,
                unknown_agent=True,
            )

        tools = {entry.tool_name: entry for entry in manifest.tools}
        unknown_tools: Set[str] = set()
        changed: Set[str] = set()
        operations = {entry.operation for entry in manifest.tools}
        if event.tool_name:
            entry = tools.get(event.tool_name)
            if entry is None:
                unknown_tools.add(event.tool_name)
            elif (
                event.observed_tool_schema_digest
                and event.observed_tool_schema_digest != entry.schema_digest
            ):
                changed.add(event.tool_name)
        new_destinations = (
            {event.destination}
            if event.destination and event.destination not in manifest.allowed_destinations
            else set()
        )
        return AbomDiff(
            tenant_id=event.tenant_id,
            agent_id=event.agent_id,
            manifest_id=manifest.manifest_id,
            unknown_tools=unknown_tools,
            changed_tool_schemas=changed,
            new_operations={event.operation} - operations,
            new_destinations=new_destinations,
            new_data_classes=event.data_classes - manifest.allowed_data_classes,
        )

    @property
    def observation_count(self) -> int:
        return len(self._observations)
