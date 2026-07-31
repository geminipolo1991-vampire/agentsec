# Module 2 — Ingestion gateway

Status: verified on 2026-07-23  
Module contracts: `GatewayReceipt` / `GatewayBatchResponse` 1.0.0

## Comparison baseline

Before this loop, the HTTP process exposed one shared-bearer authorization route
and incident read/write routes. Module 1 SDK transports referred to telemetry
paths, but those paths did not exist. Alert deduplication, health, and the hash
chain were process-local. There was no workload identity, credential-to-tenant
binding, signed-request replay defense, telemetry batch API, rate limit,
backpressure, durable intake queue, retry lease, dead letter, redrive, or source
health endpoint.

## Implemented remediation

- HMAC-SHA256 workload authentication binding method, path, raw body digest,
  timestamp, nonce, and credential ID.
- Durable nonce consumption and a bounded five-minute timestamp window; exact
  request replay fails before payload parsing.
- Credential-resolved tenant, source, and application allowlist enforcement.
- Strict single and batch telemetry routes:
  - `POST /v1/telemetry`
  - `POST /v1/telemetry/batch`
- Per-credential token-bucket admission with `429` and `Retry-After`.
- SQLite transactions, full synchronization, WAL for file-backed stores,
  process-safe busy timeout, and foreign-key enforcement.
- Durable `(tenant_id, event_id)` idempotency across service restarts.
- Content-conflict detection when one event ID is reused with changed content.
- Expiring capacity reservations to make admission and queue backpressure safe
  across concurrent gateway processes.
- Bounded durable queue, leases, expired-lease recovery, retry delay, dead
  letter, explicit redrive, and idempotent success acknowledgement.
- Only Module 1 safe `TelemetryEnvelope` data is persisted; raw input is reduced
  to a one-way request hash and is absent from the queue/database.
- Source-health counters for accepted, duplicate, rejected, rate-limited,
  backpressured, processed, pending, processing, and dead-letter activity.
- Admin-authenticated health APIs:
  - `GET /v1/telemetry/sources`
  - `GET /v1/telemetry/queue`
- Python and TypeScript signed SDK transports. Content remains excluded by SDK
  clients unless the caller explicitly opts into collection.
- Environment construction is fail-closed and enables telemetry routes only
  when an explicit workload credential configuration exists.

## Security invariants

1. The submitted tenant/source/application is never trusted over the workload
   credential binding.
2. Signatures are checked against the exact received bytes before JSON parsing.
3. A valid signature nonce is accepted once within the replay window.
4. Duplicate identity is tenant-scoped and survives restart.
5. Reusing an event ID for different content is a conflict, not a duplicate.
6. Queue capacity is reserved transactionally; overload returns backpressure
   without silently dropping accepted work.
7. Exceptions and malformed input are represented by fixed reason codes; raw
   request or downstream exception text is never persisted or returned.
8. The durable spool contains safe envelopes, not prompt, response, tool
   argument, result, credential, or signature material.

## Verification evidence

- `tests/test_ingestion_gateway.py`
  - body/path/time/nonce signature binding and replay rejection;
  - credential-to-tenant/source/application binding;
  - raw-content canary absence from SQLite;
  - restart-persistent idempotency and event-ID conflict rejection;
  - concurrent duplicate admission;
  - rate limit and capacity backpressure;
  - bounded batch and partial outcome accounting;
  - queue retry, dead letter, safe error code, redrive, and success;
  - signed HTTP intake plus protected source/queue health routes.
- `tests/test_telemetry_collection.py` verifies the Python signed SDK transport.
- `sdk/typescript/test/sdk.test.mjs` verifies the TypeScript signed SDK
  transport and secret non-disclosure.
- Generated contracts:
  - `gateway-workload-principal.schema.json`
  - `gateway-ingestion-receipt.schema.json`
  - `gateway-batch-response.schema.json`
  - `gateway-source-health.schema.json`
  - `gateway-queue-summary.schema.json`

## Deferred dependencies, not Module 2 completion shortcuts

- The queue spool is an intake/retry boundary, not the Module 4 evidence store.
- Canonical cross-product Event/Finding/Incident migrations belong to Module 3.
- Indexed hunting and retention management belong to Modules 5 and 4.
- User/team RBAC, SSO, service-identity rotation, encryption key custody, and
  centralized admin audit belong to Module 24.
- Production distributed brokers and database adapters can implement these
  contracts; this repository verifies the complete behavior locally with
  dependency-free SQLite.

These dependencies remain explicit and are assigned to their approved modules.

## Acceptance closure

Module 2 passed its focused security and failure-mode tests plus the complete
repository regression gate:

- 10 ingestion gateway tests and 20 Module 1 telemetry/SDK integration tests;
- 5 TypeScript SDK tests;
- 157 total Python tests;
- 2 analyst UI production build/render contract tests;
- 47 generated schema checks and 10 deterministic report checks;
- clean-package install reproduction, Python 3.9 compilation, secret scan,
  dependency check, release audit, workflow/Codex demos, all evaluation modes,
  and component ablation.

The module meets its defined local product boundary. Production broker/database
clustering, long-term evidence retention, and platform identity are explicit
downstream adapter and module responsibilities, not silently claimed here.
