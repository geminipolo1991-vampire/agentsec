# Module 17 — Incident and Case Management

Status: verified  
Contracts: 1.0.0  
Policy: case-management-2026-07-24.1

## Comparison baseline

Module 12 already correlates findings into durable first-class incidents, while
the original investigation projection exposes privacy-safe event, detection,
triage, enrichment, judgment, escalation, response, and analyst evidence. The
service also supported a small in-memory finding lifecycle.

That was not yet a SOC case-management system. There was no durable human work
record, accountable team assignment, separate acknowledgment and resolution
clocks, collaborative notes or tasks, safe attachment registry, relationship
governance, independent closure review, replay-safe mutation protocol, or
tamper-evident case audit. Analysts could inspect why a finding existed but
could not conduct and prove a complete investigation lifecycle.

## Implemented remediation

- Added a tenant-scoped SQLite case service. Every recorded pipeline finding
  creates or reuses one durable case after correlation and binds both the
  finding ID and any first-class correlation incident ID.
- Added strict case, team, principal, comment, task, attachment, relationship,
  review, audit, page, health, and request contracts with generated JSON
  Schemas. Unknown fields and invalid identities fail validation.
- Added permission-scoped principals and durable teams. Assignment requires a
  known team, and an assignee or task owner must be a member of that team.
  Non-admin readers cannot access cases outside their team set.
- Added accountable assignment, explicit acknowledgment, investigation start,
  closure-review request, independent approval or change request, attributed
  close, and reopen transitions with optimistic case versions.
- Added separate acknowledgment and resolution SLA deadlines, derived on-track,
  at-risk, breached, or met state, plus queue health for acknowledgment breach,
  resolution breach, unassigned cases, open tasks, and closed work.
- Added redacted analyst comments and bounded investigation tasks. Open or
  in-progress tasks prevent resolution approval.
- Added metadata-only attachment registration with safe basenames, media-type
  allowlisting, size bounds, a SHA-256 content commitment, and restricted
  evidence reference. A separate scanner records a final clean or quarantined
  result; anything other than clean prevents approval. Binary content never
  enters the case database, API, or browser.
- Added bounded case/finding/correlation relationships with a required redacted
  rationale, type-specific ID validation, duplicate rejection, and parent-cycle
  detection.
- Added four-eyes closure: the actor requesting resolution cannot approve it.
  Approval is impossible until tasks are complete and attachment metadata has
  a clean scanner verdict. Closing requires a prior independent approval.
- Added deterministic replay identities for case mutations and child records.
  Identical retries return the original signed result; different concurrent
  writes against the same version fail with a conflict. SQLite
  `BEGIN IMMEDIATE` protects this across independent service connections.
- Made team creation replay-safe when its durable definition is identical and
  fail closed when the same team ID is redefined.
- Added a sequence-numbered hash chain for every case mutation. The signed case
  record binds both the exact audit count and audit head, detecting edits,
  reordering, insertion, and tail deletion before any current case is returned.
- Exposed authenticated service and loopback-bridge APIs for the case queue,
  health, teams, details, assignments, acknowledgment, comments, tasks,
  attachment scan state, relationships, lifecycle, and review.
- Added a live **Cases** workspace with no fixture fallback. It presents queue
  health, ownership, both SLA clocks, collaboration, evidence metadata,
  relationship context, independent review, and the complete audit chain.
- Kept case creation post-decision and non-executive. A case-store outage is
  sanitized as `case_management_unavailable` and cannot change the enforcement
  decision or erase the existing finding trace.

## Lifecycle

```text
pipeline finding + optional correlated incident
                  |
                  v
                OPEN -- acknowledge/assign --> OPEN
                  |
                  v
            INVESTIGATING -- comments / tasks / evidence / links --> INVESTIGATING
                  |
                  v
            PENDING_REVIEW
              |          |
       request changes   independent approval
              |          |
              v          v
       INVESTIGATING   RESOLVED -- attributed close --> CLOSED
                                                    |
                                                    +-- reopen --> INVESTIGATING
```

Every arrow is version-checked, permission-checked, replay-safe, attributed,
and appended to the case audit chain. Model output cannot traverse an arrow.

## Security invariants

1. Case work is tenant-scoped and permission-scoped; a browser cannot submit an
   actor identity or expand the server-held principal.
2. A finding maps to at most one case per tenant, including after restart or
   pipeline retry.
3. Case collaboration is downstream of deterministic enforcement and cannot
   relax, replay, or authorize an agent effect.
4. Assignments and task owners must belong to a durable allowed team.
5. All analyst-entered prose is bounded and redacted before persistence.
6. Attachments are metadata commitments only. Unsafe filenames, unsupported
   media types, oversize records, and invalid evidence references are rejected.
7. Open tasks and non-clean attachments make approval impossible.
8. Resolution request and approval require different authenticated identities.
9. A stale version cannot overwrite a newer case; identical retries are
   deterministic and do not append duplicate child records or audit entries.
10. Every present case binds its complete audit count and head; any nested
    digest error or missing audit tail fails the read closed.

## Data and interface contract

`CaseRecord` owns privacy-safe title/summary, finding and correlated-incident
references, priority/severity, queue and ownership, acknowledgment/resolution
deadlines, lifecycle attribution, optimistic version, policy version, audit
count/head, and a record digest. `CaseDetail` returns that record with verified
comments, tasks, attachment metadata, relationships, reviews, and ordered audit
entries. `CaseHealth` is an aggregate operational view and is not a substitute
for the authoritative case detail.

Private product routes are:

- `GET /v1/cases`, `/v1/cases/health`, `/v1/cases/{case_id}`;
- `GET|POST /v1/case-teams`;
- `POST /v1/cases/{case_id}/{assign|acknowledge|comments|tasks|attachments|relationships|start|request-review|review|close}`;
- `POST /v1/cases/{case_id}/tasks/{task_id}/transition`;
- `POST /v1/cases/{case_id}/attachments/{attachment_id}/scan`.

The local product assembly enables this module only when `AGENTSEC_CASE_DB` is
set. `AGENTSEC_CASE_TENANT` is explicit or inherited from another configured
product tenant, and all configured product-store tenants must match.

## Verification evidence

The focused gate covers restart durability, automatic finding/correlation
binding, redaction, idempotent pipeline retry, team replay and conflicting
redefinition, permission/tenant/team isolation, assignment membership,
acknowledgment and resolution SLA, complete collaboration, unsafe filename
rejection, attachment scan gating, independent review, close/reopen, duplicate
and cyclic relationships, child capacity, same-process and cross-service
version races, nested audit mutation, audit-tail deletion, authenticated HTTP,
browser actor-spoof rejection, environment bootstrap, and outage isolation.

The production UI build and source/render contracts verify the live case route,
empty/offline state, ownership and SLA surfaces, attachment metadata boundary,
review gate, and visible hash-bound audit.

## Honest limitations and assigned follow-on work

- The local bearer maps to bounded service-side demonstration identities; it is
  not production human authentication, session management, or enterprise RBAC.
  Those controls belong to Module 20 and Module 24.
- SQLite WAL/full-sync is durable on one node but is not a distributed case
  database, cross-region recovery mechanism, or high-availability deployment.
- Local SHA-256 commitments are tamper-evident, not managed signatures or
  independent timestamps. Managed keys and immutable external audit retention
  belong to Module 24.
- Attachment content upload, malware sandboxing, quarantine storage, and
  retrieval are deliberately absent. Only a scanner-attributed metadata verdict
  is recorded; production object/evidence storage remains external.
- Escalation delivery and paging are provided by verified Module 18. Response
  execution, rollback, and kill switches belong to Module 19.
- The case UI is an operational MVP, not a complete query/report designer,
  notification inbox, or multi-user real-time collaboration layer.

## Acceptance closure

The focused closure gate passed 68 case, pipeline, service, incident,
correlation, bridge, schema-contract, and runtime tests; its dedicated case
suite passed all 10 lifecycle, authorization, replay, concurrency, capacity,
SLA, attachment, relationship, and tamper tests. The production UI build and
both UI contracts passed, and all 212 generated schemas matched their canonical
models.

The complete `make verify` gate passed with 313 Python tests, five TypeScript
SDK tests, ten deterministic evaluation records, clean-package reproduction,
bytecode compilation, secret scanning, dependency integrity, release audit,
protected/unprotected workflow and recorded Codex demonstrations, all eight
evaluation modes, and component ablation. Deterministic, Codex-shadow, and
semantic-hold modes retained zero completed forbidden effects and zero false
blocks on the bounded corpus.

The full gate deliberately observed 16/24 before catalog promotion. The
post-promotion module audit records final Module 17 closure at 17/24.
