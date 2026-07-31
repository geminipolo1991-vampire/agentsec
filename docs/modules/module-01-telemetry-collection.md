# Module 1 — AI telemetry collection

Status: verified on 2026-07-23  
Module contract: `TelemetryInput` / `TelemetryEnvelope` 1.0.0

## Comparison baseline

Before this module loop, AgentSec accepted only the metadata-only `AgentEvent`
effect proposal, two synthetic adapter shapes, and allowlisted demo fixtures.
There was no general AI runtime telemetry envelope, Python/TypeScript collection
client, provider-call collector, OpenTelemetry mapping, MCP JSON-RPC mapping,
bounded replay, collection privacy mode, or source-health accounting.

The existing `AgentEvent` remains the pre-effect authorization contract. Runtime
telemetry is not treated as authority and cannot self-assert trust, permissions,
approval, or tool-manifest integrity.

## Implemented remediation

- Strict provider-neutral telemetry context and event-kind contracts.
- Separate ephemeral `TelemetryInput` from safe downstream
  `TelemetryEnvelope`.
- Metadata-only, redacted, and protected-raw collection policies.
- Protected-raw mode fails closed unless a `ContentProtector` is configured.
- Content digests, byte counts, classifications, redaction receipts, and
  omission reasons; no implicit raw-content copy.
- Attribute allowlist, JSON type/depth/count bounds, content-size limits, batch
  limits, and timezone-aware timestamps.
- Python embedded collector plus Python delivery client.
- Dependency-free TypeScript/JavaScript client with content transmission off by
  default.
- OpenAI Responses and Anthropic Messages adapters.
- OpenTelemetry GenAI span adapter.
- LangChain callback adapter without a runtime LangChain dependency.
- Generic tool-call and MCP `tools/call` JSON-RPC adapters.
- JSONL replay with file, line, record, and batch limits.
- Source health for acceptance, rejection, duplication, lateness, sequence
  gaps, out-of-order activity, omitted content, and redaction counts.
- Thread-safe event-ID reservation so concurrent duplicates accept exactly once
  within a collector process.
- Trusted gateway bridge from a protected tool telemetry envelope into the
  existing `AgentEvent` enforcement pipeline. Trust, authority, approval, and
  manifest digests must be supplied by the gateway and are never inferred from
  SDK content.

## Security invariants

1. Raw content exists only in ephemeral collector input or an explicitly
   approved client transmission.
2. Metadata-only envelopes contain content digest and size, not content.
3. Redacted envelopes contain only a bounded redacted preview.
4. Protected-raw envelopes require an injected protector, key reference, and
   algorithm receipt.
5. Invalid input and protection failures return fixed reason codes without
   echoing the rejected payload.
6. SDK telemetry cannot grant authority or provide trusted approval.
7. Unknown metadata attributes fail closed by default.
8. Duplicate event IDs are observable and not reaccepted in the collector
   process.

## Verification evidence

- `tests/test_telemetry_collection.py`
  - privacy modes and canary exclusion;
  - malformed/unknown input rejection;
  - duplicate, late, missing-sequence, out-of-order, and oversized telemetry;
  - concurrent duplicate capture;
  - batch, stream, and JSONL replay;
  - OpenAI, Anthropic, OpenTelemetry, LangChain, tool, and MCP mappings;
  - trusted bridge into deterministic pre-effect enforcement;
  - Python delivery SDK and endpoint restrictions.
- `sdk/typescript/test/sdk.test.mjs`
  - content-off default;
  - explicit content opt-in;
  - strict event/context checks;
  - batch bounds;
  - HTTPS/loopback endpoint restrictions and credential handling.
- Generated schemas:
  - `telemetry-context.schema.json`
  - `telemetry-input.schema.json`
  - `telemetry-envelope.schema.json`
  - `telemetry-capture-receipt.schema.json`
  - `telemetry-source-health.schema.json`
  - `telemetry-batch-result.schema.json`

## Deferred dependencies, not Module 1 completion shortcuts

- Durable deduplication, authenticated telemetry routes, quotas, queues, DLQ,
  and replay protection belong to Module 2.
- Canonical Event/Finding/Incident/Entity evolution belongs to Module 3.
- Durable evidence storage, key custody, retention, and backup belong to Module
  4 and Module 24.
- Collector fleet discovery and persistent entity inventory belong to Module 6.
- Production search and source-health dashboards belong to Modules 5 and 20.

These dependencies must be delivered in their own loops; this module does not
claim they already exist.

## Acceptance closure

Module 1 passed its focused security and failure-mode tests plus the complete
repository regression gate:

- 18 Python telemetry collection tests;
- 4 TypeScript SDK tests;
- 145 total Python tests;
- 2 analyst UI build/render contract tests;
- 42 generated schema checks and 10 deterministic report checks;
- clean-package install reproduction, compilation, secret scan, dependency
  check, release audit, workflow/Codex demos, all evaluation modes, and
  component ablation.

The module meets its defined boundary. The durable ingestion, evidence, search,
inventory, and administration dependencies listed above remain assigned to
their approved downstream modules and do not weaken this acceptance.
