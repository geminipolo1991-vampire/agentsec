# Module 3 — Canonical AI-security data model

Status: verified on 2026-07-23  
Canonical contract version: 1.0.0

## Comparison baseline

The existing pipeline had useful but stage-coupled contracts: `AgentEvent`,
`SecurityAlert`, `Finding`, `Judgment`, `ResponseRecord`, and a UI-focused
`IncidentDetail`. Evidence was primarily a list of strings. An incident was a
privacy-safe presentation of one finding rather than a first-class correlation
record. There was no canonical Entity, Evidence, Investigation, or Action
object, no referential-integrity boundary across records, and no explicit
schema migration mechanism.

## Implemented remediation

- Added nine distinct, strict, tenant-scoped records:
  - `EventRecord`
  - `EvidenceRecord`
  - `EntityRecord`
  - `AlertRecord`
  - `FindingRecord`
  - `IncidentRecord`
  - `InvestigationRecord`
  - `JudgmentRecord`
  - `ActionRecord`
- Every record has an exact `record_type`, exact schema version, timestamp,
  tenant, bounded identity, and record-specific lifecycle fields.
- `EvidenceRecord` separates a bounded claim, source, subject references,
  integrity status, data classes, provenance references, and SHA-256 content
  receipt. The canonical projection never copies detector evidence content.
- `EntityRecord` supplies the common identity layer required for inventory,
  graph, posture, behavioral analytics, and correlation modules.
- `IncidentRecord` accepts multiple findings and entities; it is separate from
  the existing one-finding `IncidentDetail` compatibility/read model.
- `InvestigationRecord` has explicit hypothesis, status, assigned analyst,
  steps, evidence, and conclusion fields.
- `JudgmentRecord` binds subject, judge type, deterministic baseline, evidence,
  policy, confidence, abstention, and uncertainty. It rejects any final action
  weaker than deterministic policy.
- `ActionRecord` binds incident, judgment, executor, targets, approval reference,
  evidence, lifecycle, result, and simulated/real mode. Terminal status and
  completion time must agree.
- `CanonicalBundle` validates one-tenant scope, globally unique record IDs, and
  all Entity/Event/Evidence/Alert/Finding/Incident/Investigation/Judgment/Action
  references.
- `CanonicalRecordEnvelope` digest-binds a discriminated record union and
  records source version plus applied migrations.
- `CanonicalMigrator` validates current records and performs a documented,
  strict migration from the 0.9 beta identity/tenant/timestamp field shape for
  every record type. Unknown/future versions fail closed.
- Compatibility adapters project Module 1 telemetry and legacy `AgentEvent`
  into canonical events.
- A complete legacy `PipelineResult` adapter creates a reference-valid canonical
  entity/evidence/event/alert/finding/incident/judgment/action bundle without
  copying raw event attributes or detector evidence values.

## Security invariants

1. Canonical bundles cannot mix tenants.
2. All security-significant references must resolve to the expected record type.
3. Record IDs are unique across one bundle, preventing type-confusion aliases.
4. Canonical records are strict and reject unknown fields.
5. Evidence content is represented by a bounded claim and cryptographic receipt,
   not an unbounded raw payload.
6. Judgment cannot weaken deterministic policy.
7. Action lifecycle state cannot claim completion without a completion time or
   retain a completion time while non-terminal.
8. Envelope mutation invalidates its digest.
9. Unsupported record types and schema versions fail closed; migration history
   is explicit and digest-bound.

## Verification evidence

- `tests/test_canonical_datamodel.py`
  - reference-valid projection contains all nine first-class types;
  - raw event canary exclusion;
  - tenant isolation and unresolved reference rejection;
  - judgment/action lifecycle invariants;
  - envelope mutation detection;
  - 0.9-to-1.0 migration for every record type;
  - current-version identity validation and future-version rejection;
  - Module 1 telemetry compatibility projection.
- Eleven generated schemas cover the nine records, canonical envelope, and
  reference-valid bundle.

## Deferred dependencies, not Module 3 completion shortcuts

- This module defines canonical records and compatibility projection; Module 4
  persists them transactionally and manages retention/restore.
- Module 5 indexes these records for search and hunting.
- Modules 6–8 populate and analyze durable entity/inventory/graph/posture state.
- Module 12 performs real multi-finding correlation and incident creation.
- Modules 14–19 create full investigation, judgment, escalation, and response
  activity rather than fabricating absent records during compatibility import.

## Acceptance closure

Module 3 passed its seven focused compatibility, integrity, privacy, migration,
and lifecycle tests plus the complete repository regression gate:

- 164 total Python tests and 5 TypeScript SDK tests;
- 2 analyst UI production build/render contract tests;
- 58 generated schema checks and 10 deterministic report checks;
- clean-package install reproduction, Python 3.9 compilation, secret scan,
  dependency check, release audit, workflow/Codex demos, all evaluation modes,
  and component ablation.

The canonical model boundary is complete. Durable repositories, indexing,
correlation, and workflow population remain explicitly assigned to their
approved downstream modules.
