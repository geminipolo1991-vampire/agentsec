# Module 7 — AI security graph and attack paths

Status: verified on 2026-07-23  
Graph contracts: 1.0.0

## Comparison baseline

Before this loop, `CausalGraph` was a compatibility helper holding nodes and
edges in Python dictionaries for one process. It accepted pipeline results and
could run an unweighted breadth-first search for one flow. It had no durable or
tenant-authorized state, inventory topology, graph revisions, alternative or
weighted paths, blast radius, bounded reachability, historical views, product
API, bridge contract, or analyst UI. A destination was also drawn before the
security decision, which did not represent the reference-monitor boundary.

## Implemented remediation

- Preserved the original `CausalGraph` contract for compatibility while adding
  a separate durable `SecurityGraphService` product boundary.
- Transactional SQLite storage with WAL, full synchronization, busy timeout,
  tenant/version primary keys, indexed time/source/target queries, and unique
  current revisions.
- First-class application, agent, model, tool, data-store, source, resource,
  destination, decision, and finding nodes.
- Contains, uses-model, uses-tool, accesses, influences, calls, sends-to,
  authorized-by, and produces directed edge types.
- Canonical SHA-256 digest per node/edge revision and chronological
  `valid_from`/`valid_to` intervals. Repeated identical observations are
  idempotent; late, same-time conflicting, and endpoint/type-changing
  revisions fail closed.
- Explicit tenant principal with separate read, write, and analysis
  permissions. Cross-tenant event and inventory ingestion is rejected.
- Metadata-only inventory adapter consumes Module 6 components and
  relationships. Startup synchronizes the current tenant inventory and live
  authorization discovery adds newly observed topology.
- Event adapter records untrusted influence, effectful calls, sensitive paths,
  external destinations, deterministic decisions, and findings without prompt
  or tool content.
- Authorization decisions sit between resource and potential destination.
  Blocked paths remain investigable but restrictive controls increase path
  cost and surface exact decision reason codes.
- Long resource or destination metadata receives a stable SHA-256 entity ID
  and bounded display name, so maximum valid event fields cannot overflow graph
  contracts.
- Directional reachability uses bounded breadth-first traversal with maximum
  depth/node limits, deterministic ordering, path evidence, and truncation.
- Blast radius reports impacted nodes, high-risk count, and maximum risk from
  bounded downstream reachability.
- Weighted attack paths use a bounded priority queue, deterministic edge
  ordering, simple-path cycle prevention, path/depth/state ceilings, exposure
  score, combined risk factors, and explicit truncation.
- Current and timezone-aware historical snapshots drive every analysis.
- Authenticated service routes expose graph snapshot, summary, reachability,
  blast radius, and attack paths with exact payload/filter allowlists.
- Environment assembly is explicit through `AGENTSEC_GRAPH_DB` and a fixed
  graph tenant. Misaligned search, inventory, and graph tenants fail startup.
- The loopback bridge keeps the product bearer token server-side, validates
  graph timestamps/node IDs/bounds, and exposes only fixed graph routes.
- The live Security Graph UI includes current/historical metrics, a clickable
  SVG topology, high-risk and highlighted path states, exact source/target
  controls, node dossiers, weighted alternatives, blast-radius results, and
  honest loading/empty/offline states. It contains no topology fixture.
- Thirteen new generated JSON Schemas cover all public graph contracts.

## Security invariants

1. Tenant identity comes from the configured graph principal, never a request
   body or graph record.
2. Search, inventory, and graph principals configured in one application must
   use the same tenant; authorization rejects tenant mismatch before pipeline
   or product-state mutation.
3. Graph writes are atomic. An invalid node, dangling edge, identity change, or
   temporal conflict rolls back the entire batch.
4. Edge endpoints must exist as current nodes and self edges are forbidden.
5. Historical revisions are append-only intervals and never overwrite prior
   observations.
6. Traversal cannot run without analysis authority and always has fixed safety
   ceilings.
7. Cycles cannot enter returned attack paths.
8. Raw prompt/content/tool argument/result, secrets, tokens, passwords,
   credentials, authorization data, and API-key-shaped graph labels are
   structurally refused.
9. The browser never receives the service bearer token and cannot submit an
   arbitrary graph command or unbounded analysis.
10. Empty or unavailable graph state is displayed honestly; no sample topology
    is substituted.

## Verification evidence

- `tests/test_security_graph.py`
  - durable event graph and restart reconstruction;
  - correct decision-before-destination paths and restrictive exposure cost;
  - repeated entities and maximum-length metadata;
  - alternative weighted path ordering and cycle prevention;
  - outbound/inbound reachability, depth truncation, and blast radius;
  - temporal node/edge history and timezone enforcement;
  - tenant and permission isolation;
  - unsafe-label, dangling-edge, identity-change, and bound refusal;
  - concurrent duplicate idempotency;
  - 800-node/edge indexed bounded-analysis performance;
  - inventory topology consumption, live authorization ingestion, authenticated
    graph APIs, exact request rejection, and explicit environment assembly.
- `tests/test_abom_graph_checkpoint.py` retains compatibility source-to-sink
  and no-raw-prompt coverage.
- `tests/test_live_ui_bridge.py` verifies fixed, bounded graph forwarding while
  the bearer remains server-side.
- `ui/tests/source-contract.test.mjs` and
  `ui/tests/rendered-html.test.mjs` verify the production build, live-only graph
  workspace, required analysis controls, risk/path styles, and server render.
- Generated schemas cover graph principals, inputs, persisted nodes/edges,
  snapshots, ingest results, weighted paths, reachability, blast radius, and
  summary.

## Deferred dependencies, not Module 7 completion shortcuts

- The verified SQLite graph is the local product adapter. A distributed graph
  or relational cluster adapter and fleet-scale graph maintenance are
  deployment concerns.
- Module 8 consumes graph and inventory risk for posture findings and
  remediation workflows.
- Module 9 adds richer detection content that can contribute graph edges and
  risk factors.
- Module 12 correlates multiple findings and paths into first-class incidents.
- Module 20 supplies product-wide authenticated analyst identity and completes
  cross-module UI accessibility/navigation.
- Module 24 supplies SSO/RBAC administration, managed key custody, platform
  encryption, audit export, SLOs, backup, and disaster recovery.

## Acceptance closure

Eleven focused Module 7 tests and the compatibility graph suite pass. The
service, inventory, bridge, generated-schema, and analyst UI focused regressions
also pass. The complete repository gate passed:

- 202 Python tests and 5 TypeScript SDK tests;
- 2 analyst UI production build/render contract tests;
- 99 generated schema checks and 10 deterministic report checks;
- clean-package install reproduction, Python 3.9 compilation, secret scan,
  dependency check, release audit, workflow/Codex demos, all evaluation modes,
  and component ablation.

The durable temporal graph, graph APIs, inventory/event integration, and live
analyst attack-path workspace are complete. Distributed data-plane adapters,
posture evaluation, multi-finding correlation, product-wide identity, and
managed platform controls remain explicitly assigned to deployment adapters
and Modules 8, 12, 20, and 24.
