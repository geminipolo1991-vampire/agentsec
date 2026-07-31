# Module 5 — Search and threat hunting

Status: verified on 2026-07-23  
Search contracts: 1.0.0

## Comparison baseline

Before this loop, Module 4 could retrieve one canonical record by exact tenant,
type, and ID or return its revision history. The incident store supported only a
small fixed filter set. There was no indexed cross-record query language,
aggregation, pagination, saved hunt, evidence pivot, analyst hunting API, or
hunting UI. Searching canonical data would have required privileged database
access or an unbounded application-side scan.

## Implemented remediation

- Durable SQLite derived index over the latest active canonical revisions.
- Integrity-gated synchronization: a broken Module 4 hash chain is refused.
- All nine canonical record types receive allowlisted analyst projections.
- Raw event attributes, protected evidence ciphertext, key references, and
  arbitrary canonical payload serialization are excluded from the index.
- Strict recursive-descent query parser with boolean `AND`, `OR`, `NOT`,
  parentheses, typed comparisons, safe contains matching, and `*` match-all.
- Allowlisted fields and sort keys; query length, term count, nesting, page,
  offset, and aggregation-bucket limits.
- Parameterized SQL compiler. User text never becomes a table, column,
  operator, sort expression, or raw SQL fragment.
- Tenant identity comes only from `SearchPrincipal`, never from a query or
  browser payload.
- Separate read, index, saved-hunt-write, and evidence-read permissions.
- Stable ordering and HMAC-SHA256 opaque pagination cursors bound to tenant,
  query digest, sort, offset, and expiry.
- Count-by aggregations for direct and multi-valued indexed fields.
- Durable saved-hunt create/list/get/update/delete/execute with tenant scoping,
  owner-only mutation, validation, and audit events.
- Evidence pivots return the canonical Evidence metadata projection and linked
  indexed records. The API structurally forbids protected content.
- Live authorization results are atomically committed to the canonical system
  of record and projected into search before the decision response returns.
- Authenticated product routes cover search, aggregation, hunt lifecycle and
  execution, and evidence pivots. Missing search configuration fails closed.
- The loopback UI bridge proxies only bounded search operations and retains the
  service bearer token on the server side.
- The analyst UI provides a live query editor, record table, aggregations,
  saved hunts, signed next-page navigation, and evidence pivots. Its empty state
  explicitly states that no fixed/sample alerts are displayed.

## Query examples

```text
record_type = "alert" AND severity >= "high"
(risk_score >= 70 OR confidence >= 0.9) AND NOT status = "closed"
evidence_id = "evd_0123456789abcdef"
title ~ "untrusted content"
```

The language is intentionally not SQL. Unsupported fields, bare string values,
comments, semicolons, functions, joins, and arbitrary clauses fail validation.

## Security invariants

1. A caller cannot select, inject, or cross into another tenant through query
   text, a cursor, a saved hunt, or an evidence ID.
2. Search and index permissions are separate; evidence pivots require an
   additional permission.
3. Only a fixed field/type/operator vocabulary is compiled.
4. Cursor mutation, tenant reuse, query reuse, sort mismatch, excessive offset,
   and expiry fail closed.
5. A canonical integrity failure prevents repository synchronization.
6. Mutable canonical revisions replace their prior search projection; stale
   field values do not remain searchable.
7. Saved-hunt mutation is restricted to its tenant and owner.
8. Protected evidence content has no path into an index document, search hit,
   pivot response, or browser result.
9. The UI renders successful empty results and unavailable states honestly; it
   never substitutes fixtures.

## Verification evidence

- `tests/test_search_hunting.py`
  - all nine canonical types and typed nested boolean queries;
  - unknown-field, type, injection-syntax, depth/term/cost rejection;
  - tenant and permission isolation;
  - concurrent idempotent indexing and bounded indexed query;
  - cursor pagination, mutation, tenant, query, and sort binding;
  - aggregations and saved-hunt lifecycle/owner controls;
  - metadata-only evidence pivots;
  - mutable revision replacement and canonical integrity refusal;
  - authenticated product API and live authorization-to-search flow.
- `tests/test_live_ui_bridge.py`
  - loopback-only upstream, server-side bearer, bounded request fields, and
    evidence ID validation.
- UI build and contract tests verify the hunting surface and prohibit fixed
  alert fixtures.
- Eight generated JSON Schemas cover the public Module 5 models.

## Deferred dependencies, not Module 5 completion shortcuts

- SQLite is the fully tested local reference adapter. A distributed OpenSearch,
  ClickHouse, or PostgreSQL search adapter and index replication are deployment
  concerns.
- Module 20 will apply product-wide authenticated analyst identity and UI
  accessibility/navigation standards.
- Module 21 will version and publish the broader external API/streaming surface.
- Module 24 will provide platform SSO/RBAC administration, managed key custody,
  multi-tenant provisioning, SLOs, and disaster recovery.

## Acceptance closure

Module 5 passed ten focused search tests plus bridge, API, storage, data-model,
and analyst UI tests. The complete repository gate also passed:

- 182 Python tests and 5 TypeScript SDK tests;
- 2 analyst UI production build/render contract tests;
- 74 generated schema checks and 10 deterministic report checks;
- clean-package install reproduction, Python 3.9 compilation, secret scan,
  dependency check, release audit, workflow/Codex demos, all evaluation modes,
  and component ablation.

The local indexed hunting boundary is complete. Distributed adapters,
product-wide authenticated analyst identity, external API publication, and
managed key custody remain explicitly assigned to deployment adapters and
Modules 20, 21, and 24.
