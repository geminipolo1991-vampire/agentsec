"""Exact-action, expiring, single-use approval tokens for the PoC gateway."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, Set

from pydantic import Field

from .contracts import AgentEvent, StrictModel, new_id, utc_now
from .crypto import PocHmacSigner, canonical_bytes


def event_binding(event: AgentEvent, policy_version: str) -> Dict[str, object]:
    return {
        "tenant_id": event.tenant_id,
        "agent_id": event.agent_id,
        "event_id": event.event_id,
        "flow_id": event.flow_id,
        "operation": event.operation,
        "resource": event.resource,
        "destination": event.destination,
        "data_classes": sorted(event.data_classes),
        "tool_name": event.tool_name,
        "declared_tool_schema_digest": event.declared_tool_schema_digest,
        "observed_tool_schema_digest": event.observed_tool_schema_digest,
        "policy_version": policy_version,
    }


class ApprovalToken(StrictModel):
    schema_version: str = "1.0.0"
    token_id: str = Field(default_factory=lambda: new_id("approval"))
    approver_id: str
    tenant_id: str
    agent_id: str
    event_id: str
    flow_id: str
    policy_version: str
    binding_digest: str
    nonce: str = Field(default_factory=lambda: new_id("nonce"))
    issued_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    max_execution_count: int = Field(default=1, ge=1, le=1)
    signature_algorithm: str = PocHmacSigner.algorithm
    signature: str = ""

    def unsigned_payload(self) -> Dict[str, object]:
        return self.model_dump(mode="json", exclude={"signature"})


class ApprovalService:
    def __init__(self, signer: PocHmacSigner) -> None:
        self._signer = signer
        self._consumed_nonces: Set[str] = set()

    def issue(
        self,
        event: AgentEvent,
        *,
        approver_id: str,
        policy_version: str,
        ttl: timedelta = timedelta(minutes=5),
    ) -> ApprovalToken:
        now = utc_now()
        digest = hashlib.sha256(
            canonical_bytes(event_binding(event, policy_version))
        ).hexdigest()
        unsigned = ApprovalToken(
            approver_id=approver_id,
            tenant_id=event.tenant_id,
            agent_id=event.agent_id,
            event_id=event.event_id,
            flow_id=event.flow_id,
            policy_version=policy_version,
            binding_digest=digest,
            issued_at=now,
            expires_at=now + ttl,
        )
        return unsigned.model_copy(
            update={"signature": self._signer.sign(unsigned.unsigned_payload())}
        )

    def verify_and_consume(
        self, token: ApprovalToken, event: AgentEvent, *, policy_version: str
    ) -> bool:
        if token.nonce in self._consumed_nonces:
            return False
        if not self._signer.verify(token.unsigned_payload(), token.signature):
            return False
        now = utc_now()
        if not (token.issued_at <= now < token.expires_at):
            return False
        expected = hashlib.sha256(
            canonical_bytes(event_binding(event, policy_version))
        ).hexdigest()
        if token.binding_digest != expected:
            return False
        if (
            token.tenant_id != event.tenant_id
            or token.agent_id != event.agent_id
            or token.event_id != event.event_id
            or token.flow_id != event.flow_id
            or token.policy_version != policy_version
        ):
            return False
        self._consumed_nonces.add(token.nonce)
        return True

