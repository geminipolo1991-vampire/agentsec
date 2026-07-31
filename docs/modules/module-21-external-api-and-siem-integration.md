# Module 21 — External API and SIEM integration

Status: verified after compare → remediate → focused verification → full
regression verification.

## Objective

Publish the privacy-safe product record to external SIEM and data platforms
without making external delivery part of the authorization decision. Provide a
versioned, scoped consumer API and Python/TypeScript clients, while retaining
the signed workload telemetry API delivered by Module 2.

## Comparison and gaps

Before this module, AgentSec already had versioned single and batch telemetry
ingestion, private search/inventory/detection/finding/correlation routes, an
allowlisted `SocFindingExport`, and an early Splunk HEC helper. The gaps were:

- no common durable SIEM outbox, delivery attempt record, retry scheduler,
  dead-letter queue, or redrive control;
- no distinction between HTTP acceptance and provider acknowledgment;
- no Splunk indexer-ack poll and no Elastic bulk-item acknowledgment;
- no signed webhook, RFC 5424 over TLS, CEF over TLS, or OTLP HTTP JSON
  adapters;
- no signed, tenant-bound event-stream cursor;
- no independent external-client identity, tenant, and scope contract;
- no fixed public API joining event stream, search, entity, rule, finding,
  incident, and integration status;
- no external consumer client in either SDK; and
- external export failures were not represented as bounded post-decision
  health without affecting enforcement.

## Delivered architecture

`src/agentsec/integrations.py` is the single integration plane. A sanitized
`ExternalSecurityEvent` is constructed from `SocFindingExport`; it is not a
serialization of an event, prompt, model response, tool payload, or evidence
record. The event and every delivery carry canonical SHA-256 commitments.

SQLite stores the tenant event stream, one idempotent delivery per enabled
destination, bounded attempts, provider-reference hashes, receipt hashes, and
a chained audit ledger. WAL, foreign keys, immediate mutation transactions,
stable IDs, exponential retry, explicit dead-letter state, and governed
redrive provide single-node durability. Restarting the service reuses the same
outbox and does not duplicate an event/destination delivery.

The connector supports six exact adapters:

| Adapter | Transport and proof |
| --- | --- |
| Splunk HEC | HTTPS event request followed by bounded `/services/collector/ack` polling when indexer acknowledgment is enabled. |
| Elastic | HTTPS NDJSON bulk `create`; every returned item must report a successful status. |
| Signed webhook | HTTPS JSON with event ID, idempotency key, explicit body digest, timestamp, and an HMAC signature that binds timestamp plus body. |
| Syslog | RFC 5424 message over TLS with RFC 6587 octet framing; success proves transport acceptance, not downstream indexing. |
| CEF | Escaped CEF record over TLS with RFC 6587 octet framing; success proves transport acceptance, not downstream indexing. |
| OpenTelemetry | OTLP HTTP JSON logs; HTTP success with zero rejected log records is required. |

HTTP adapters require HTTPS, exact allowed hosts, fixed protocol paths, no URL
credentials/query/fragment, no redirect, bounded time/response size, and
public DNS resolution at connection time. Syslog and CEF require `tls://`, an
explicit port, an allowed public host, certificate validation, and SNI.
Credentials are resolved from environment-variable names in policy and never
written to SQLite, delivery records, audit, API output, or SDK payloads.

## API surfaces

The existing private bearer API exposes `/v1/external/*` for service operators:
capabilities, event stream, destinations, deliveries/detail, health, audit,
processing, and redrive. It shares the administrative service bearer and is
not an enterprise client boundary.

The public consumer boundary is separately authenticated under `/api/v1`.
Each bearer maps at runtime to one client ID, tenant, and exact scopes. Public
and private tokens are deliberately not interchangeable.

| Scope | Public routes |
| --- | --- |
| `external:capabilities` | `GET /api/v1/capabilities` |
| `external:events:read` | `GET /api/v1/events`, `GET /api/v1/events/stream` |
| `external:search` | `POST /api/v1/search` |
| `external:entities:read` | `GET /api/v1/entities`, entity detail |
| `external:rules:read` | `GET /api/v1/rules` |
| `external:findings:read` | `GET /api/v1/findings`, finding detail |
| `external:incidents:read` | `GET /api/v1/incidents`, incident detail |
| `external:integrations:read` | integration health/destinations and delivery list/detail |
| `external:integrations:operate` | process due deliveries and redrive a dead letter |

The capability document also declares signed workload ingestion at
`POST /v1/telemetry` and `POST /v1/telemetry/batch`. The ingestion gateway
continues to use workload HMAC, nonce replay protection, source/tenant binding,
rate limits, idempotency, and backpressure; the public SIEM bearer cannot
replace that credential.

`AgentSecExternalApiClient` in Python and TypeScript exposes only fixed routes,
requires HTTPS except explicit loopback testing, bounds paging and IDs, and
keeps the bearer in the authorization header. The TypeScript package continues
to include the content-minimizing telemetry SDK.

## Pipeline behavior and failure isolation

After the deterministic pipeline result and evidence-ledger verification are
committed, each alert is projected and enqueued. An integration exception is
caught at that post-decision boundary, normalized to
`integration_enqueue_failed`, and shown in integration health. It can
never change `allow`, `hold`, `deny`, or `effect_allowed`. Successful retry or
enqueue clears the bounded signal.

## Configuration

- `configs/external-integrations.example.json` contains six disabled
  destinations at reserved `.invalid` hosts and secret-variable names only.
- `configs/external-api-clients.example.json` contains enabled scoped client
  definitions and token-variable names only. With the checked-in empty
  environment values, neither client can authenticate.
- `AGENTSEC_INTEGRATION_DB`, `AGENTSEC_INTEGRATION_CONFIG`, and
  `AGENTSEC_INTEGRATION_CURSOR_SECRET` are an all-or-none runtime group.
- `AGENTSEC_INTEGRATION_TENANT`, when supplied, must match the policy and every
  configured product store.
- `AGENTSEC_EXTERNAL_API_CLIENTS_CONFIG` enables the independent client policy;
  enabled clients without runtime token values cannot authenticate.

## Verification evidence

Focused gates cover all six wire formats, Splunk two-stage acknowledgment,
Elastic/OTLP rejection semantics, webhook signature shape, TLS framing,
endpoint SSRF/plaintext/path rejection, durable idempotency and restart,
signed cursor tamper/tenant/filter binding, missing credentials, retries,
dead-letter/redrive, record/audit tamper, pipeline outage isolation, private
HTTP administration, public token/scope/tenant separation, privacy canaries,
and fixed-route Python/TypeScript clients.

Commands:

```bash
PYTHONPATH=src python3 -m unittest \
  tests.test_external_integrations tests.test_external_api_http -v
node --test sdk/typescript/test/*.test.mjs
PYTHONPATH=src python3 tools/generate_schemas.py --check
make verify
```

The final `make verify` result is recorded when this module is promoted in the
catalog.

## Protocol references

The adapters follow the wire and acknowledgment contracts in the
[Splunk HEC indexer-acknowledgment documentation](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.4/get-data-with-http-event-collector/about-http-event-collector-indexer-acknowledgment),
[Elasticsearch Bulk API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-bulk),
[RFC 5424](https://www.rfc-editor.org/rfc/rfc5424),
[RFC 6587](https://www.rfc-editor.org/rfc/rfc6587), and the
[OpenTelemetry OTLP specification](https://opentelemetry.io/docs/specs/otlp/).
These references define protocol shape; they do not qualify any vendor
deployment or prove downstream retention.

## Honest limitations

All connector tests use injected transports. Checked-in destinations are
disabled and non-routable, and no Splunk, Elastic, webhook, syslog, CEF, or
OpenTelemetry product is certified. TLS transport acceptance for syslog/CEF is
not proof of indexing. SQLite, the scheduler, cursor key, bearer registry, HMAC
signatures, and audit commitments are single-node reference controls. Module 24
owns managed identity/secrets/keys, mTLS or workload identity, egress proxies,
distributed queue leases, reconciliation after uncertain effects, immutable
audit retention, HA/DR, vendor qualification, and operational SLOs.

## Acceptance closure

Module 21 is verified. The focused gate passed 20 integration tests, 4 public
HTTP contract tests, 5 private service regressions, and 6 TypeScript SDK tests.
The pre-promotion catalog audit reported 20/24 verified modules. The complete
repository gate then passed 362 Python tests, 6 TypeScript SDK tests, the
production UI build and 2 UI tests, zero-warning lint, clean-install
reproduction, 283 generated-schema checks, 10 deterministic evaluation
records, compilation, secret/dependency checks, the release audit, workflow
and Codex demonstrations, all evaluation modes, and the control ablation. The
post-promotion audit reports 21/24. No external destination, model provider, or
AWS resource was contacted.
