"""Conservative provenance propagation and metadata-only memory persistence."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Set

from pydantic import Field

from .contracts import StrictModel, TrustClass, new_id, utc_now


TRUST_RANK = {
    TrustClass.TRUSTED_CONTROL: 0,
    TrustClass.AUTHENTICATED_USER: 1,
    TrustClass.INTERNAL_DATA: 2,
    TrustClass.EXTERNAL_UNTRUSTED: 3,
    TrustClass.UNKNOWN: 4,
    TrustClass.SUSPECTED_ADVERSARIAL: 5,
}


class ProvenanceRecord(StrictModel):
    schema_version: str = "1.0.0"
    provenance_id: str = Field(default_factory=lambda: new_id("prov"))
    tenant_id: str
    source_type: str
    source_id: str
    trust_class: TrustClass
    confidentiality_labels: Set[str] = Field(default_factory=set)
    integrity_labels: Set[str] = Field(default_factory=set)
    content_digest: str
    parent_provenance_ids: List[str] = Field(default_factory=list)
    transform_type: Optional[str] = None
    sanitizer_attestation_id: Optional[str] = None
    first_seen_at: datetime = Field(default_factory=utc_now)


class MemoryReference(StrictModel):
    memory_id: str
    tenant_id: str
    value_digest: str
    provenance_ids: List[str]


class ProvenanceStore:
    def __init__(self) -> None:
        self._records: Dict[str, ProvenanceRecord] = {}
        self._memory: Dict[str, MemoryReference] = {}

    def add_source(
        self,
        *,
        tenant_id: str,
        source_type: str,
        source_id: str,
        trust_class: TrustClass,
        content: bytes,
        confidentiality_labels: Optional[Set[str]] = None,
        integrity_labels: Optional[Set[str]] = None,
    ) -> ProvenanceRecord:
        record = ProvenanceRecord(
            tenant_id=tenant_id,
            source_type=source_type,
            source_id=source_id,
            trust_class=trust_class,
            confidentiality_labels=confidentiality_labels or set(),
            integrity_labels=integrity_labels or set(),
            content_digest=hashlib.sha256(content).hexdigest(),
        )
        self._records[record.provenance_id] = record
        return record

    def transform(
        self,
        *,
        tenant_id: str,
        source_type: str,
        source_id: str,
        parent_ids: Iterable[str],
        output_content: bytes,
        transform_type: str,
        sanitizer_attestation_id: Optional[str] = None,
    ) -> ProvenanceRecord:
        ordered_ids = list(dict.fromkeys(parent_ids))
        if not ordered_ids:
            raise ValueError("a transform must retain at least one parent")
        parents = [self._records[parent_id] for parent_id in ordered_ids]
        if any(parent.tenant_id != tenant_id for parent in parents):
            raise ValueError("cross-tenant provenance transform rejected")
        worst_trust = max(parents, key=lambda item: TRUST_RANK[item.trust_class]).trust_class
        confidentiality = set().union(
            *(parent.confidentiality_labels for parent in parents)
        )
        integrity = set().union(*(parent.integrity_labels for parent in parents))
        record = ProvenanceRecord(
            tenant_id=tenant_id,
            source_type=source_type,
            source_id=source_id,
            trust_class=worst_trust,
            confidentiality_labels=confidentiality,
            integrity_labels=integrity,
            content_digest=hashlib.sha256(output_content).hexdigest(),
            parent_provenance_ids=ordered_ids,
            transform_type=transform_type,
            sanitizer_attestation_id=sanitizer_attestation_id,
        )
        self._records[record.provenance_id] = record
        return record

    def write_memory(
        self, *, memory_id: str, tenant_id: str, value: bytes, provenance_ids: List[str]
    ) -> MemoryReference:
        if not provenance_ids:
            raise ValueError("memory writes require provenance")
        records = [self._records[item] for item in provenance_ids]
        if any(record.tenant_id != tenant_id for record in records):
            raise ValueError("cross-tenant memory provenance rejected")
        reference = MemoryReference(
            memory_id=memory_id,
            tenant_id=tenant_id,
            value_digest=hashlib.sha256(value).hexdigest(),
            provenance_ids=list(dict.fromkeys(provenance_ids)),
        )
        self._memory[memory_id] = reference
        return reference

    def read_memory(self, memory_id: str, tenant_id: str) -> MemoryReference:
        reference = self._memory[memory_id]
        if reference.tenant_id != tenant_id:
            raise KeyError(memory_id)
        return reference

    def get(self, provenance_id: str) -> ProvenanceRecord:
        return self._records[provenance_id]
