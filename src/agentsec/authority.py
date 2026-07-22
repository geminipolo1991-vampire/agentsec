"""Delegated-authority attenuation and pre-effect authorization."""

from __future__ import annotations

import fnmatch
from datetime import datetime, timedelta
from typing import Dict, Iterable, Optional, Set

from pydantic import Field, field_validator, model_validator

from .contracts import AgentEvent, StrictModel, new_id, utc_now
from .crypto import PocHmacSigner


def _valid_scope_pattern(value: str) -> bool:
    return "?" not in value and "[" not in value and ("*" not in value or value.endswith("*"))


def _contains_pattern(parent: str, child: str) -> bool:
    if parent == "*" or parent == child:
        return True
    if parent.endswith("*"):
        return child.startswith(parent[:-1])
    return False


def _scopes_are_subset(children: Iterable[str], parents: Iterable[str]) -> bool:
    parent_list = list(parents)
    return all(any(_contains_pattern(parent, child) for parent in parent_list) for child in children)


class AuthorityGrant(StrictModel):
    schema_version: str = "1.0.0"
    grant_id: str = Field(default_factory=lambda: new_id("grant"))
    issuer: str
    subject: str
    tenant_id: str
    environment: str
    operations: Set[str]
    resources: Set[str]
    destinations: Set[str] = Field(default_factory=set)
    data_classes: Set[str] = Field(default_factory=set)
    delegation_depth: int = Field(default=0, ge=0)
    max_delegation_depth: int = Field(default=0, ge=0)
    max_execution_count: int = Field(default=1, ge=1)
    valid_from: datetime = Field(default_factory=utc_now)
    valid_until: datetime = Field(default_factory=lambda: utc_now() + timedelta(minutes=15))
    parent_grant_id: Optional[str] = None
    signature_algorithm: str = PocHmacSigner.algorithm
    signature: str = ""

    @field_validator("resources", "destinations")
    @classmethod
    def patterns_must_be_restricted(cls, values: Set[str]) -> Set[str]:
        if any(not _valid_scope_pattern(value) for value in values):
            raise ValueError("scope patterns support only exact values or a trailing '*'")
        return values

    @model_validator(mode="after")
    def validity_window_must_be_ordered(self) -> "AuthorityGrant":
        if self.valid_from.tzinfo is None or self.valid_until.tzinfo is None:
            raise ValueError("grant times must be timezone aware")
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be later than valid_from")
        if self.delegation_depth > self.max_delegation_depth:
            raise ValueError("delegation depth exceeds grant maximum")
        return self

    def unsigned_payload(self) -> Dict[str, object]:
        return self.model_dump(mode="json", exclude={"signature"})


class AuthorityError(ValueError):
    pass


class AuthorityService:
    def __init__(self, signer: PocHmacSigner) -> None:
        self._signer = signer
        self._use_counts: Dict[str, int] = {}

    def sign(self, grant: AuthorityGrant) -> AuthorityGrant:
        unsigned = grant.model_copy(update={"signature": ""})
        return unsigned.model_copy(update={"signature": self._signer.sign(unsigned.unsigned_payload())})

    def verify_signature(self, grant: AuthorityGrant) -> bool:
        return self._signer.verify(grant.unsigned_payload(), grant.signature)

    def issue_root(
        self,
        *,
        issuer: str,
        subject: str,
        tenant_id: str,
        environment: str,
        operations: Set[str],
        resources: Set[str],
        destinations: Optional[Set[str]] = None,
        data_classes: Optional[Set[str]] = None,
        max_delegation_depth: int = 0,
        max_execution_count: int = 1,
        valid_for: timedelta = timedelta(minutes=15),
    ) -> AuthorityGrant:
        now = utc_now()
        return self.sign(
            AuthorityGrant(
                issuer=issuer,
                subject=subject,
                tenant_id=tenant_id,
                environment=environment,
                operations=operations,
                resources=resources,
                destinations=destinations or set(),
                data_classes=data_classes or set(),
                max_delegation_depth=max_delegation_depth,
                max_execution_count=max_execution_count,
                valid_from=now,
                valid_until=now + valid_for,
            )
        )

    def delegate(
        self,
        parent: AuthorityGrant,
        *,
        subject: str,
        operations: Set[str],
        resources: Set[str],
        destinations: Optional[Set[str]] = None,
        data_classes: Optional[Set[str]] = None,
        max_execution_count: int = 1,
        valid_until: Optional[datetime] = None,
    ) -> AuthorityGrant:
        if not self.verify_signature(parent):
            raise AuthorityError("parent signature is invalid")
        next_depth = parent.delegation_depth + 1
        if next_depth > parent.max_delegation_depth:
            raise AuthorityError("maximum delegation depth exceeded")
        child_destinations = destinations or set()
        child_data_classes = data_classes or set()
        if not operations.issubset(parent.operations):
            raise AuthorityError("delegation would expand operations")
        if not _scopes_are_subset(resources, parent.resources):
            raise AuthorityError("delegation would expand resource scope")
        if child_destinations and not _scopes_are_subset(
            child_destinations, parent.destinations
        ):
            raise AuthorityError("delegation would expand destination scope")
        if not child_data_classes.issubset(parent.data_classes):
            raise AuthorityError("delegation would expand data classes")
        if max_execution_count > parent.max_execution_count:
            raise AuthorityError("delegation would expand execution count")
        child_expiry = valid_until or parent.valid_until
        if child_expiry > parent.valid_until:
            raise AuthorityError("delegation would expand validity window")
        now = utc_now()
        if child_expiry <= now:
            raise AuthorityError("child grant would already be expired")
        child = AuthorityGrant(
            issuer=parent.subject,
            subject=subject,
            tenant_id=parent.tenant_id,
            environment=parent.environment,
            operations=operations,
            resources=resources,
            destinations=child_destinations,
            data_classes=child_data_classes,
            delegation_depth=next_depth,
            max_delegation_depth=parent.max_delegation_depth,
            max_execution_count=max_execution_count,
            valid_from=max(now, parent.valid_from),
            valid_until=child_expiry,
            parent_grant_id=parent.grant_id,
        )
        return self.sign(child)

    def authorize(self, grant: AuthorityGrant, event: AgentEvent, consume: bool = False) -> bool:
        now = utc_now()
        if not self.verify_signature(grant):
            return False
        if event.tenant_id != grant.tenant_id or event.agent_id != grant.subject:
            return False
        if not (grant.valid_from <= now < grant.valid_until):
            return False
        if event.operation not in grant.operations:
            return False
        if not any(fnmatch.fnmatchcase(event.resource, scope) for scope in grant.resources):
            return False
        if event.destination is not None:
            if not grant.destinations or not any(
                fnmatch.fnmatchcase(event.destination, scope) for scope in grant.destinations
            ):
                return False
        if not event.data_classes.issubset(grant.data_classes):
            return False
        current_count = self._use_counts.get(grant.grant_id, 0)
        if current_count >= grant.max_execution_count:
            return False
        if consume:
            self._use_counts[grant.grant_id] = current_count + 1
        return True

