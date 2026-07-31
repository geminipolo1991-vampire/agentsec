# Module 6 — Agent application and model inventory

Status: verified on 2026-07-23  
Inventory contracts: 1.0.0

## Comparison baseline

Before this loop, `AbomRegistry` held one approved signed manifest per agent and
its runtime observations only in process memory. `ModelRegistry` loaded static
provider profiles from a JSON file. Neither was an inventory system: there was
no durable application, agent, model, tool, or data-store identity; no component
relationships; no trusted governance boundary; no permission view;
configuration history, discovery idempotency, risk rollup, inventory API, and
inventory UI were absent.

## Implemented remediation

- Transactional SQLite inventory with WAL, full synchronization, foreign keys,
  a busy timeout, tenant keys, natural-identity uniqueness, and restart tests.
- First-class application, agent, model, tool, and data-store component kinds.
- Stable tenant-bound component IDs derived from kind and external identity.
- Active, unmanaged, and retired lifecycle states plus declared, observed, and
  imported provenance.
- Owner, criticality, tags, parent application, last-seen time, effective
  permissions, safe configuration, risk score, and reason codes on every
  component.
- Explicit read, discover, write, and admin permissions. Tenant comes only from
  the configured `InventoryPrincipal`.
- Discovery observations are strict, bounded, metadata-only, idempotent, and
  conflict-detecting. Concurrent duplicates create one observation.
- One observation can discover an application, agent, pinned model, and tool,
  plus contains/uses-model/uses-tool relationships in one transaction.
- Telemetry and authorization-event adapters intentionally ignore attributes,
  prompt content, tool arguments/results, and content evidence.
- Untrusted discovery cannot assign or overwrite owner, criticality, approval,
  or retired state. Governance changes require inventory admin authority.
- Effective permissions record operation, resource scope, allow/deny effect,
  approval state, and a bounded source reference.
- Configuration keys are allowlisted; secret-, token-, password-, credential-,
  authorization-, and API-key-shaped fields are structurally rejected.
- Append-only configuration revision history binds version, current/previous
  SHA-256 digest, changed fields, observation time, source, and record time.
- Signed ABOM import verifies the signature and atomically creates declared
  application, agent, tools, approved permissions, relationships, ownership,
  build/system/policy digests, and tool schemas.
- Model-registry import atomically inventories each provider profile without
  resolving or persisting API key environment values.
- Deterministic component risk explains missing owners, unmanaged discovery,
  criticality, unapproved/effectful permissions, and configuration change.
- Application rollups expose maximum risk, component/high-risk/unowned counts,
  unapproved permission count, and combined reasons.
- Filtered, indexed and bounded list queries plus tenant summary, component
  detail, relationship, history, risk, discovery, and governance APIs.
- The live authorization path discovers the configured application, agent, and
  tool before returning its response when inventory is enabled.
- The server-side loopback bridge exposes inventory reads without exposing the
  product bearer token.
- The analyst Inventory view shows only live data: component/risk metrics,
  owners, lifecycle, sources, permissions, configuration history, and explicit
  offline/empty states. It has no inventory fixture.

## Security invariants

1. Component, relationship, observation, revision, query, and audit state are
   tenant-scoped; a payload cannot choose a different principal tenant.
2. Observed telemetry is discovery evidence, not governance authority.
3. Natural identity cannot be rebound to another component ID or kind.
4. Duplicate observations are stable; changed content under one observation ID
   is a conflict.
5. Configuration revisions are append-only and digest chained to the previous
   state.
6. Configuration accepts only documented scalar metadata keys and refuses
   credential-shaped fields.
7. ABOM declarations are accepted only with a valid signature.
8. Provider API keys are never resolved or copied by model inventory import.
9. Application risk is calculated from persisted child components and cannot be
   supplied by the observed workload.
10. The browser receives no service token and no fabricated component when the
    inventory is empty or unavailable.

## Verification evidence

- `tests/test_inventory.py`
  - durable application/agent/model/tool discovery and relationships;
  - concurrent idempotency and observation-ID conflict;
  - governance protection and application risk rollup;
  - configuration version/digest/changed-field history and unsafe-key refusal;
  - signed ABOM and secret-free model registry imports;
  - telemetry/authorization adapter content exclusion;
  - permission/tenant isolation, filters, pagination, and 400-component query;
  - authenticated inventory API and live authorization discovery;
  - explicit environment assembly and invalid-configuration startup failure.
- Existing ABOM, model provider, service, bridge, and UI tests remain regression
  evidence.
- Generated JSON Schemas cover every public inventory contract.

## Deferred dependencies, not Module 6 completion shortcuts

- The SQLite adapter is the verified local product implementation. Fleet-scale
  collectors and distributed databases are deployment adapters.
- Module 7 consumes inventory relationships to construct persisted attack paths.
- Module 8 evaluates configuration and permission posture against versioned
  checks.
- Module 20 applies product-wide authenticated analyst UX and accessibility.
- Module 24 supplies SSO/RBAC administration, managed key custody, tenant
  provisioning, audit export, SLOs, backup, and disaster recovery.

## Acceptance closure

Module 6 passed nine focused inventory tests plus the existing ABOM, model
provider, service, bridge, and UI regressions. The complete repository gate also
passed:

- 191 Python tests and 5 TypeScript SDK tests;
- 2 analyst UI production build/render contract tests;
- 86 generated schema checks and 10 deterministic report checks;
- clean-package install reproduction, Python 3.9 compilation, secret scan,
  dependency check, release audit, workflow/Codex demos, all evaluation modes,
  and component ablation.

The local discovery-backed inventory boundary is complete. Fleet-scale
collectors, distributed adapters, attack-path analysis, posture checks,
product-wide authenticated analyst identity, and managed platform controls stay
explicitly assigned to deployment adapters and Modules 7, 8, 20, and 24.
