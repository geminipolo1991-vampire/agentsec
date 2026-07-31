# Module 13 — Enrichment engine

Status: verified on 2026-07-24  
Connector contracts: 1.0.0

## Comparison baseline

The prior pipeline already produced a useful nine-source, metadata-only,
fail-explicit `EnrichmentSnapshot`. Those sources connected local provenance,
authority, classification, ABOM drift, model profile, observations, causal
path, and repeat frequency to explainable triage. Execution was synchronous,
however, and there was no external connector contract, tenant/field access
policy, concurrent live-source execution, cache age, stale policy, timeout
isolation, circuit breaker, durable connector health, runtime assembly, or
authenticated observability surface.

## Implemented remediation

- Preserved all nine deterministic built-ins and their existing order/status/
  confidence/failure behavior, so current detection and triage remain backward
  compatible.
- Added a strict connector SDK: `EnrichmentConnectorSpec`, governed request and
  payload contracts, callable-client adapter, and exact-HTTPS JSON adapter.
- Added immutable connector name/version, required input fields, output fact
  allowlist, individual deadline, fresh TTL, maximum stale horizon, and
  mandatory-context declaration.
- Added tenant-scoped read/execute/admin principals with explicit allowed
  connectors and input fields. Denied or unavailable required fields return a
  visible `policy_denied` result without calling the upstream.
- Added a metadata-only request builder. It can send only selected hashed
  event/flow/agent/source/resource/destination/tool references and bounded
  classifications; it never sends raw prompt/tool content or raw identifiers.
- Added independent output controls: maximum 64 facts, declared fact keys only,
  hashed evidence-reference syntax, aware timestamps, 64-KiB request/fact
  bounds, and strict no-extra-field validation.
- Added bounded concurrent execution with absolute per-source timeouts plus an
  awaitable `collect_async` facade. One slow connector cannot serialize all
  other live enrichments.
- Added an HTTPS JSON adapter with credential-free endpoint validation, normal
  platform TLS verification, redirects disabled, per-call timeout, 1-MiB
  response cap, strict JSON schema validation, and injected transport support
  for deterministic testing.
- Added a tenant-scoped SQLite WAL/full-sync cache keyed by SHA-256 over the
  governed connector input. Fresh cache hits avoid network calls; expired
  entries may be used only inside an explicit maximum-stale horizon after an
  outage. Stale results are forced to `partial` and expose age and original
  expiry.
- Added durable success, failure, timeout, cache-hit, stale-fallback,
  consecutive-failure, last-outcome, and last-latency state. A configurable
  consecutive-failure threshold opens a timed circuit; an open circuit serves
  eligible labeled stale context or reports unavailable.
- Extended every source result with connector version, cache status, freshness,
  expiry, and policy decision. Extended each snapshot with connector/cache/
  stale/timeout counts and a SHA-256 digest of the effective access policy.
- Added those fields to the authoritative enrichment timeline and analyst
  evidence cards. The UI shows live connector count, cache hits, stale and
  timeout counts, policy digest, connector version, age, and policy outcome.
- Added bounded, secret-free JSON runtime configuration, an example connector
  file, bearer lookup by environment-variable name, durable database/tenant
  assembly, tenant alignment, and authenticated `GET /v1/enrichment/health`.
- Added eight generated contracts for the principal, connector spec, request,
  payload, connector health, health summary, HTTP configuration, and runtime
  configuration; the existing snapshot schema now includes freshness and policy
  evidence.

## Security invariants

1. Connector context may add uncertainty or risk but cannot create authority,
   suppress deterministic detection, or relax the most-restrictive action.
2. Only an execution principal for the event tenant may call live connectors;
   registration requires separate admin permission and health requires read.
3. Connector and input-field access is deny-by-default and explicit. Missing or
   denied required input is recorded, not silently omitted.
4. Raw prompts, tool arguments/results, raw identifiers, headers, and secrets do
   not enter connector requests, cache keys, payload state, health, or UI.
5. Connector facts do not become trusted merely because they are schema valid;
   source/version, evidence, freshness, cache status, policy decision, and
   failure behavior remain visible to downstream judgment and analysts.
6. Fresh and stale cache states cannot be confused. Stale data is bounded by
   policy, forced partial, age labeled, and never used beyond `stale_until`.
7. Calls are deadline bounded and circuit protected. Timeout/failure is
   fail-explicit and cannot block or weaken the deterministic security path.
8. Bearer values are taken from named environment variables only and are not
   serialized into the connector configuration, outbound JSON body, database,
   health response, snapshot, logs, or schemas.
9. HTTP connectors require an exact HTTPS URL, reject URL credentials and
   fragments, refuse redirects, validate TLS, and cap response size.
10. All health and runtime state is tenant scoped; service startup rejects
    mismatched configured product tenants.

## Interfaces and operation

The connector SDK supports `CallableEnrichmentConnector` for a native CMDB,
inventory, reputation, vulnerability, or identity client and
`HttpJsonEnrichmentConnector` for a strict JSON service. The example runtime
file is `configs/enrichment-connectors.example.json`.

Local runtime requires:

- `AGENTSEC_ENRICHMENT_DB` — connector cache/health SQLite path;
- `AGENTSEC_ENRICHMENT_CONFIG` — absolute bounded runtime JSON path;
- `AGENTSEC_ENRICHMENT_TENANT` — explicit tenant, or a matching inherited
  product-store tenant;
- connector-specific bearer environment variables named by the config.

`GET /v1/enrichment/health` requires the service bearer and returns only
aggregate connector health and circuit/cache state. Per-event evidence remains
inside the authoritative incident `Enrichment` tab and pipeline result.

## Verification evidence

`tests/test_enrichment_connectors.py` covers concurrent entry, metadata
minimization, policy denial, cross-tenant refusal, fresh cache, stale-on-error,
freshness evidence, timeouts, circuit opening, durable restart state, async use,
output allowlists, HTTP bounds, governed registration, environment assembly,
and the authenticated health route. `tests/test_enrichment_integration.py`
preserves the fully connected nine-built-in pipeline proof. Service, pipeline,
incident, schema, and production UI suites provide compatibility coverage.

## Honest limitations and assigned follow-on work

- Schema-valid upstream facts are assertions, not independent truth. Module 16
  adds claim-to-evidence validation, contradictions, and human judgment gates.
- The local runtime does not provide private link, DNS pinning, connector mTLS,
  upstream attestation, cluster-wide budgets/rate limits, or managed secret
  rotation. Module 24 owns those platform controls.
- Cache and health state use local database integrity, not managed signatures,
  transparency anchoring, replicated storage, or distributed transactions;
  those remain explicit Module 24 responsibilities.
- Module 15 supplies provider/model-specific routing, budgets, health, privacy,
  secret lifecycle, and rollback. Those are not mislabeled as enrichment.

## Acceptance closure

Ten focused live-connector tests and the existing fully connected built-in
integration test pass, including the explicit proof that connector outage
cannot weaken a deterministic denial. Pipeline, incident, and service focused
compatibility suites pass. The production UI build, server render, and source
contracts pass with the new live/cache/stale/timeout/policy evidence.

The complete repository gate also passed:

- 262 Python tests and 5 TypeScript SDK tests;
- 2 analyst UI production build/render contract tests;
- 156 generated schema checks and 10 deterministic report checks;
- clean-package install reproduction, Python compilation, secret scan,
  dependency check, release audit, workflow/Codex demos, all evaluation modes,
  and component ablation.

The module audit reports 13/24 approved modules verified. The original nine
built-ins plus governed concurrent live connectors, callable and exact-HTTPS
SDK adapters, tenant/field/fact access policy, durable fresh/maximum-stale
cache, deadline/circuit isolation, full freshness provenance, runtime assembly,
authenticated health, and analyst-visible evidence are complete. Governed AI
analyst roles, provider/model governance, claim validation, collaborative case
management, and platform-wide managed identity/keys/HA remain explicitly
assigned to Modules 14–17, 20, and 24.
