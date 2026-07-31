# Module 12 — Finding correlation and incident creation

Status: verified on 2026-07-24  
Correlation contracts: 1.0.0

## Comparison baseline

The prior product deduplicated one alert fingerprint into one in-memory finding
and rendered that finding as an incident detail. Multiple alerts from the same
event remained separate records. There was no durable first-class incident ID,
correlation decision receipt, bounded grouping, attack-sequence reconstruction,
multi-finding risk rollup, suppression, automatic reopen, merge, split, or
campaign-level analyst workspace.

## Implemented remediation

- Added `src/agentsec/correlation.py`, a tenant-scoped SQLite WAL/full-sync
  correlation service with current incidents, unique finding links,
  correlation decisions, suppression rules, digests, and indexed lifecycle.
- Added privacy-safe correlation signals derived only from an authoritative
  `PipelineResult`: finding/alert/event IDs, risk and decision metadata,
  attack stage, and hashed flow, agent, source, resource, tool, destination,
  and evidence references. Raw prompt/tool/model content and raw identifiers
  are absent.
- Added deterministic candidate scoring for same flow, same hashed agent,
  shared hashed entities, same alert family, and attack-sequence extension.
  Candidate scores/reasons are retained even when no candidate crosses the
  attach threshold.
- Added a four-hour active correlation window, a seven-day closed-incident
  reopen window, a fixed attach threshold, 200-candidate read bound, and a
  500-finding incident cap.
- Added first-class `inc_*` incidents with ordered finding links, reconstructed
  attack stages, deduplicated entity/evidence sets, severity/priority/risk
  rollup, revision, lifecycle, reopen count, parent/supersession relations,
  canonical digest, and immutable audit entries.
- Added risk rollup from maximum finding risk, bounded multi-finding increase,
  and multi-stage sequence increase. Original finding risk and authorization
  decisions remain unchanged and visible.
- Added automatic reopen when a new matching finding meets threshold within the
  governed reopen horizon; stale active incidents are not silently extended.
- Added time-bounded exact alert-type/optional hashed-agent suppressions with
  creation/revocation identity, reason, expiry, digest, and suppressed-decision
  receipt. Suppression affects incident creation only, never detection or
  authorization.
- Added audited lifecycle transitions, analyst merge of 2–20 incidents, source
  supersession without deletion, and split of a proper finding subset into a
  parent-linked child incident. Unique finding ownership is preserved.
- Integrated post-response correlation into the pipeline. Correlation failure
  is sanitized and non-executive: it cannot suppress an alert, change the
  most-restrictive action, or prevent the existing per-finding investigation
  trace.
- Added explicit environment assembly with `AGENTSEC_CORRELATION_DB` and an
  explicit/inherited aligned tenant plus separate read/write/admin permissions.
- Added authenticated APIs for incident list/detail, health, decisions,
  suppressions, transition, merge, split, create, and revoke.
- Added fixed token-owning loopback routes with exact IDs and governance
  payloads. Arbitrary commands, filters, identity, and mutation are rejected.
- Replaced the duplicate Incidents view with a live no-fallback correlation
  workbench: campaign queue, risk rollup, ordered attack sequence, link reasons
  and scores, hashed entities/evidence, decision ledger, digest/audit receipt,
  lifecycle, merge, and split.
- Added eleven generated schemas for principal, signal, link, sequence, audit,
  incident, candidate, decision, suppression, health, and split result.

## Security invariants

1. Correlation runs only after the authoritative security response; it cannot
   alter or relax detection, triage, judgment, or effect enforcement.
2. Each tenant/finding has exactly one durable correlation decision and at most
   one current incident link. Idempotent retries return the original decision.
3. Grouping is deterministic, explainable, thresholded, tenant-scoped, time
   bounded, and capped. No model-generated claim is accepted as a link.
4. Raw identities/content do not enter correlation state; entity, flow, and
   evidence values are hashed namespace-qualified references.
5. Ordered attack sequence is derived from recorded event time and known alert
   stages; it is not reconstructed from missing historical content.
6. Suppression never removes or changes a finding and never affects
   authorization. It records an explicit time-bounded decision instead of
   creating an incident link.
7. Merge retains superseded incident history; split requires a proper subset;
   neither operation deletes finding evidence.
8. Closed incidents reopen only through an audited explicit transition or a
   thresholded new matching finding within the configured horizon.
9. Incident and decision digests are verified on read; mutation or malformed
   relations fail closed.
10. Correlation outage produces a sanitized health signal while deterministic
    security processing and per-finding evidence remain available.

## Interfaces

Read routes:

- `GET /v1/correlation/incidents` and `/{incident_id}`
- `GET /v1/correlation/decisions`
- `GET /v1/correlation/health`
- `GET /v1/correlation/suppressions`

Governed write routes:

- `POST /v1/correlation/incidents/{incident_id}/transition`
- `POST /v1/correlation/incidents/merge`
- `POST /v1/correlation/incidents/{incident_id}/split`
- `POST /v1/correlation/suppressions`
- `POST /v1/correlation/suppressions/{suppression_id}/revoke`

The browser receives narrower fixed `/api/correlation` projections. Current UI
writes expose transition, merge, and split; suppression governance remains on
the authenticated service API until Module 20 adds the full administration
experience.

## Verification evidence

- `tests/test_incident_correlation.py` covers multi-finding grouping, decision
  reasons, sequence/risk reconstruction, privacy, automatic reopen,
  suppression/revocation, merge/split, durability/tamper, permissions/tenant,
  concurrent idempotency, bounds, pipeline outage behavior, authenticated APIs,
  and environment assembly.
- `tests/test_live_ui_bridge.py` covers fixed list/detail/health/decision,
  transition/merge/split routes and invalid ID/payload refusal.
- Existing pipeline, finding, incident, service, canonical/search, and UI tests
  preserve all prior compatibility and enforcement behavior.
- UI production source/render contracts cover the no-fallback campaign queue,
  sequence/link proof, decision ledger, lifecycle, merge, split, responsive
  layout, and server rendering.

## Deferred dependencies, not Module 12 completion shortcuts

- Module 13 adds asynchronous live enrichment connectors; this module links the
  recorded evidence that exists without inventing missing context.
- Modules 14–16 add governed AI analyst and evidence judgment, which may
  recommend but cannot directly mutate correlation links.
- Module 17 expands these incident records with assignments, comments, tasks,
  attachments, SLA collaboration, and review.
- Module 20 supplies authenticated human identity and the full accessible UI;
  Module 24 supplies managed signatures, distributed transactions/stores, HA,
  backup, and platform audit.

## Acceptance closure

Eight focused correlation tests, thirteen bridge tests, and the production UI
build/render/source contracts pass. The complete repository gate also passed:

- 252 Python tests and 5 TypeScript SDK tests;
- 2 analyst UI production build/render contract tests;
- 148 generated schema checks and 10 deterministic report checks;
- clean-package install reproduction, Python compilation, secret scan,
  dependency check, release audit, workflow/Codex demos, all evaluation modes,
  and component ablation.

The module audit reports 12/24 approved modules verified. Durable explainable
grouping, first-class multi-finding incidents, ordered attack sequences, risk
rollup, automatic reopen, time-bounded suppression, merge, split, health,
authenticated API/bridge, and the live no-fallback Incidents workbench are
complete. Asynchronous live enrichment, governed AI analysis/judgment,
collaborative case management, product-wide analyst identity, managed
signatures, distributed transactions/storage, and platform operations remain
explicitly assigned to Modules 13–17, 20, and 24.
