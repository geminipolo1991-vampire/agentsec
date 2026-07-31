# AI-Agent Security

This repository implements a provider-neutral security reference monitor and a
closed-loop SOC workflow for AI agents. The executable lifecycle is:

```text
Agent event -> Detection -> Ingestion -> Enrichment -> Explainable triage
            -> Judgment -> Escalation -> Response -> Incident record
```

The complete component, data, security, deployment, and pilot-target design is
in [`docs/architecture.md`](docs/architecture.md).
The traceable completion boundary for the approved 24-module full product is in
[`docs/module-maturity-matrix.md`](docs/module-maturity-matrix.md).

The deterministic security path does not depend on an LLM. Codex is represented
by versioned offline single-verdict and five-role analyst recordings; model
output can preserve or tighten a deterministic decision, never relax it. The AI
analyst is evidence-bounded, non-executive, and explicit about alternatives,
uncertainty, disagreement, abstention, and unavailable roles. Disabled-by-default
OpenAI Responses and Anthropic Messages adapters implement both the verdict and
five-role contracts behind the Module 15 model gateway. Live calls require an
immutable prompt and exact-model route, current independent qualification,
shadow/activation lifecycle, privacy-compatible routing, credential fingerprint,
transactional budget, and healthy circuit. Credentials alone cannot enable AI.

## Research PoC

The PoC forges local benign and malicious agent events and runs them through two
agent adapter styles, a controlled tool gateway, deterministic detectors, an
idempotent hash-chained ledger, formal enrichment, explainable triage, judgment,
escalation, and simulated safe response. Supporting controls cover attenuating authority, exact approvals,
provenance, ABOM drift, causal paths, signed checkpoints, effect reconciliation,
privacy transforms, Splunk HEC contracts, and provider-neutral model review. It
never contacts a real enterprise system or sends test data externally.

Run the verification suite:

```bash
make test
```

Run the safe demonstration:

```bash
make demo
```

Compare vulnerable and protected four-agent workflows. Both sides use mock tools;
"unprotected" means the forbidden effect reaches only the local fake receiver:

```bash
make workflow-demo
```

Replay the structured verdicts reviewed by Codex in shadow mode. The recording is
offline and versioned; this command does not pretend to make a live API call:

```bash
make codex-demo
```

Run the versioned corpus evaluation, ablations, and all verification gates:

```bash
make evaluate
make evaluate-all
make ablate
make continuous-evaluate
make verify
```

`make module-audit` independently checks that all 24 modules retain explicit
implementation, automated verification, and honest limitation evidence.

Regenerate Pydantic-derived JSON Schemas with `make schemas`; `make
check-schemas` fails when committed contracts drift. `make reports` regenerates
digest-bound evaluation records; `make check-reports` fails on byte drift. `make
clean-install` builds the package offline in a fresh virtual environment and
reproduces the deterministic evaluation and protected workflow demo.
`make verify` also scans for common committed secrets, validates installed
dependencies, and writes the machine-readable `reports/release-audit.json`.

Run the local authorization service only with an explicit bearer token:

```bash
AGENTSEC_INGEST_TOKEN='replace-with-at-least-32-random-characters' \
  AGENTSEC_AI_MODE=shadow \
  PYTHONPATH=src python3 -m agentsec serve --host 127.0.0.1 --port 8080
```

`POST /v1/authorize` accepts the strict `AgentEvent` contract and returns an
allowlist-built decision plus privacy-safe incident details derived from the
exact `PipelineResult` used for enforcement. The detail includes ingestion,
triage contributions, enrichment, judgment, escalation, response, audit, and
validation evidence; raw attributes and prompt content are never echoed.
Private incident list, detail, timeline, and audited transition routes expose
the same recorded data through `IncidentDetail` 2.0.0.

The Module 2 ingestion gateway is enabled only with explicit workload
credentials and a durable local spool:

```bash
AGENTSEC_INGEST_TOKEN='replace-with-at-least-32-random-characters' \
AGENTSEC_GATEWAY_DB='./agentsec-gateway.db' \
AGENTSEC_WORKLOAD_CREDENTIALS_JSON='[{"credential_id":"demo-sdk","secret":"replace-with-at-least-32-random-characters","tenant_id":"tenant-demo","source_id":"sdk://python/demo","application_ids":["demo-app"]}]' \
PYTHONPATH=src python3 -m agentsec serve --host 127.0.0.1 --port 8080
```

Use the signed Python or TypeScript SDK transport for `POST /v1/telemetry` and
`POST /v1/telemetry/batch`. The gateway binds workload identity to tenant,
source, and allowed applications; rejects request replay; applies rate limits
and queue backpressure; and durably spools only privacy-safe telemetry
envelopes. Source and queue health are available to the private admin bearer at
`GET /v1/telemetry/sources` and `GET /v1/telemetry/queue`.

The Module 3 canonical data plane defines separate, versioned Event, Evidence,
Entity, Alert, Finding, Incident, Investigation, Judgment, and Action records.
Reference-valid bundles, digest-bound envelopes, strict 0.9-to-1.0 migration,
and privacy-safe adapters from the current enforcement pipeline are implemented
in `src/agentsec/datamodel.py`; the existing contracts remain compatibility
inputs rather than being silently redefined.

Module 4 adds the durable local system of record in
`src/agentsec/storage.py`: transactional canonical revisions, per-tenant
append-only hash chains, ciphertext-only evidence blobs, durable signed
checkpoints, retention/legal hold, and manifest-verified backup/restore. SQLite
is the dependency-free reference adapter; this product work does not recreate
or modify any AWS environment.

Module 5 adds tenant-scoped indexed search and threat hunting in
`src/agentsec/search.py`. Its bounded query language supports typed boolean
predicates, safe text matching, aggregations, signed pagination, saved hunts,
and evidence-to-record pivots. Only allowlisted canonical metadata enters the
index; protected evidence ciphertext and raw telemetry attributes are excluded.
The authenticated service routes are available when the local search settings
below are explicitly configured.

Module 6 adds a durable discovery-backed AI asset inventory in
`src/agentsec/inventory.py`. It normalizes applications, agents, model profiles,
tools, and data stores; records relationships and effective permissions;
preserves configuration revisions; separates untrusted observations from
governed owner/criticality state; and calculates explainable component and
application risk rollups. Discovery adapters accept privacy-safe telemetry,
authorization events, signed ABOM manifests, and the model registry.

Module 7 replaces the former process-local path helper with a durable temporal
AI security graph in `src/agentsec/graph.py`. Inventory topology and live
authorization outcomes become tenant-scoped, versioned nodes and directed
evidence edges. Bounded reachability, blast radius, and weighted cycle-safe
attack paths are available through authenticated APIs and the live Security
Graph analyst workspace. Raw prompts, tool arguments, authorization headers,
tokens, and credential-shaped labels are structurally excluded.

Module 8 adds durable AI security posture management in
`src/agentsec/posture.py`. Eight versioned deterministic checks evaluate the
live inventory for ownership, lifecycle, excessive/unapproved permissions,
tool and prompt contract pinning, policy binding, and component risk. Findings
retain safe evidence, framework mappings, remediation, resolution history,
posture trends, and time-bounded accepted-risk exceptions with expiry and
revocation. The live Posture workspace contains no fallback findings.

Module 9 replaces the default six-class detector with a versioned
detection-as-code runtime in `src/agentsec/detection.py`. Strict event,
sequence, threshold, correlation, and semantic rules run in streaming or
scheduled mode over bounded metadata-only windows. Rule versions, execution
audit, health, OWASP/MITRE/NIST mappings, and scheduled replay are durable when
the detection database below is configured. The original six Python classes
remain compatibility plug-ins for ablation and custom extensions.

Module 10 adds a signed detection-content control plane in
`src/agentsec/content.py`. Rules move through draft, deterministic validation,
backtest, independent review, shadow evaluation, exact-digest publication, and
retirement. Increasing-version rollback, signed content packs, lifecycle/rule
health, authenticated APIs, and a live no-fallback Rule Studio preserve the
complete proof behind every active detection.

Module 11 adds a durable metadata-only behavioral risk engine in
`src/agentsec/behavior.py`. It evaluates agent, source, tool, and destination
activity against the prior accepted-event baseline before learning, exposes the
probability and contribution of every deviation, combines anomaly and context
risk, rejects alerted/restricted events from learning, monitors drift, and
keeps immutable tuning history. Hashed entity references, authenticated APIs,
and the live no-fallback Risk Analytics workspace make the complete evidence
visible without storing raw prompts, tool payloads, or destination identities.

Module 12 adds a durable first-class incident correlation service in
`src/agentsec/correlation.py`. Authoritative findings are grouped by bounded
time, flow, hashed entities, and attack-sequence extension; every attach/create/
reopen/suppress decision retains its score and reasons. Multi-finding risk
rollup, ordered campaign sequence, governed lifecycle, merge, split,
time-bounded suppression, APIs, and the live Incidents workbench preserve the
original finding evidence and never affect authorization.

Module 13 adds governed live enrichment connectors around the nine built-in
sources. Callable and exact-HTTPS JSON adapters run concurrently with per-source
deadlines, tenant/field/fact allowlists, durable fresh and maximum-stale cache
semantics, circuit breakers, policy digests, and authenticated connector health.
Missing or stale context is explicit and cannot weaken enforcement.

Module 14 adds a durable, tenant-scoped AI security analyst engine in
`src/agentsec/analyst.py`. Triage, investigation, judge, escalation, and
response-advisor roles query only governed evidence, cite returned evidence
IDs, preserve alternatives and uncertainty, and record abstention or failure
without inventing a conclusion. Tool receipts, disagreement records, run
digests, health, and redacted inert feedback are visible through authenticated
APIs and the incident **AI Analyst** tab. The recorded Codex configuration is a
reproducible test artifact, not a live provider call, and no role can execute a
response or weaken deterministic enforcement.

Enable live canonical search by starting the local service with explicit
database, tenant, and cursor-signing settings:

```bash
AGENTSEC_INGEST_TOKEN='replace-with-at-least-32-random-characters' \
  AGENTSEC_CANONICAL_DB='/tmp/agentsec-canonical.sqlite3' \
  AGENTSEC_SEARCH_DB='/tmp/agentsec-search.sqlite3' \
  AGENTSEC_SEARCH_TENANT='tenant-lab' \
  AGENTSEC_SEARCH_CURSOR_SECRET='replace-with-32-random-cursor-characters' \
  AGENTSEC_INVENTORY_DB='/tmp/agentsec-inventory.sqlite3' \
  AGENTSEC_INVENTORY_TENANT='tenant-lab' \
  AGENTSEC_INVENTORY_APPLICATION_ID='authorization-service' \
  AGENTSEC_GRAPH_DB='/tmp/agentsec-graph.sqlite3' \
  AGENTSEC_GRAPH_TENANT='tenant-lab' \
  AGENTSEC_POSTURE_DB='/tmp/agentsec-posture.sqlite3' \
  AGENTSEC_POSTURE_TENANT='tenant-lab' \
  AGENTSEC_DETECTION_DB='/tmp/agentsec-detection.sqlite3' \
  AGENTSEC_DETECTION_TENANT='tenant-lab' \
  AGENTSEC_CONTENT_DB='/tmp/agentsec-content.sqlite3' \
  AGENTSEC_CONTENT_SIGNING_KEY='replace-with-at-least-32-random-content-key-bytes' \
  AGENTSEC_BEHAVIOR_DB='/tmp/agentsec-behavior.sqlite3' \
  AGENTSEC_BEHAVIOR_TENANT='tenant-lab' \
  AGENTSEC_CORRELATION_DB='/tmp/agentsec-correlation.sqlite3' \
  AGENTSEC_CORRELATION_TENANT='tenant-lab' \
  AGENTSEC_CASE_DB='/tmp/agentsec-cases.sqlite3' \
  AGENTSEC_CASE_TENANT='tenant-lab' \
  AGENTSEC_NOTIFICATION_DB='/tmp/agentsec-notifications.sqlite3' \
  AGENTSEC_NOTIFICATION_CONFIG="$PWD/configs/notification-policy.example.json" \
  AGENTSEC_NOTIFICATION_TENANT='tenant-lab' \
  AGENTSEC_RESPONSE_DB='/tmp/agentsec-response.sqlite3' \
  AGENTSEC_RESPONSE_CONFIG="$PWD/configs/response-playbooks.example.json" \
  AGENTSEC_RESPONSE_TENANT='tenant-lab' \
  AGENTSEC_ANALYST_DB='/tmp/agentsec-analyst.sqlite3' \
  AGENTSEC_ANALYST_RECORDING="$PWD/configs/codex-analyst-evaluation.json" \
  AGENTSEC_ANALYST_TENANT='tenant-lab' \
  AGENTSEC_AI_MODE=shadow \
  PYTHONPATH=src python3 -m agentsec serve --host 127.0.0.1 --port 8080
```

If the search variables are omitted, authorization remains available but the
search routes fail closed as unavailable. The product search API includes
`POST /v1/search`, `POST /v1/search/aggregate`, saved-hunt lifecycle routes
under `/v1/hunts`, and `GET /v1/evidence/{evidence_id}/pivot`.
Inventory routes include `GET /v1/inventory`, its summary and component detail,
`POST /v1/inventory/discover`, and an exact governance transition route. If
`AGENTSEC_INVENTORY_DB` is omitted, those routes fail closed as unavailable.
Graph routes include current or historical snapshots and summaries plus bounded
reachability, blast-radius, and weighted attack-path analysis. If
`AGENTSEC_GRAPH_DB` is omitted, those routes fail closed as unavailable while
authorization continues.
Posture routes include summary, versioned checks, bounded finding lists and
detail, historical trends, live scans, and exact accepted-risk creation and
revocation. `AGENTSEC_POSTURE_DB` requires inventory to be enabled and its
tenant must match; otherwise posture startup or routes fail closed.
Detection routes expose the current immutable rule records, execution health,
and exact scheduled runs. `AGENTSEC_DETECTION_DB` requires a detection tenant
(or inherits the configured inventory/search tenant), and every configured
product-store tenant must match.
Detection-content routes expose signed lifecycle records, history, health,
packs, validation/backtest/shadow evidence, review, publish, and rollback.
`AGENTSEC_CONTENT_DB` requires the detection store and
`AGENTSEC_CONTENT_SIGNING_KEY` with at least 32 bytes; otherwise content startup
or routes fail closed while authorization can remain independently configured.
Behavior routes expose privacy-safe baselines, assessments, detail, health,
configuration history, drift, and bounded tuning. `AGENTSEC_BEHAVIOR_DB`
enables this service; its tenant is explicit or inherited from another product
store and must match every configured tenant. Authorization still runs if the
behavior store is omitted. When configured behavior analysis fails during one
event, deterministic detection continues and triage records the missing
context rather than silently learning the event.
Correlation routes expose first-class incident list/detail, decision evidence,
health, suppression governance, lifecycle, merge, and split.
`AGENTSEC_CORRELATION_DB` enables post-response correlation; its tenant is
explicit or inherited from another configured product store and must match.
Correlation failure cannot alter the authorization result or erase the existing
per-finding investigation trace.
Case routes expose the durable human workflow under `/v1/cases` and
`/v1/case-teams`: ownership, acknowledgment and resolution SLA, comments,
tasks, safe attachment metadata, typed relationships, independent review,
closure/reopen, health, and the committed audit chain. `AGENTSEC_CASE_DB`
enables the case store; its explicit or inherited tenant must match every other
configured product tenant. Case failure is post-response and cannot alter the
authorization decision.
Notification routes expose the durable escalation outbox, delivery health,
destination readiness, detail, human acknowledgment, bounded processing, and
governed dead-letter redrive. `AGENTSEC_NOTIFICATION_DB` and
`AGENTSEC_NOTIFICATION_CONFIG` must be supplied together; the explicit or
inherited tenant must match every other product store. The policy names four
connector credential environment variables but never contains their values.
Missing credentials remain visible as not-ready destinations, and delivery
failure is post-response so it cannot change deterministic enforcement.
Response routes expose signed dry-run plans, exact approvals, connector
readiness, execution/verification attempts, rollback, kill-switch state,
health, and reviewed playbook revisions under `/v1/response`. Both
`AGENTSEC_RESPONSE_DB` and `AGENTSEC_RESPONSE_CONFIG` are required; the tenant
is explicit or inherited and must match every other product store. Connector
credentials are optional readiness inputs named by the policy. Without them,
the pipeline still records inert plans but every live request fails closed.
The AI analyst runtime requires both `AGENTSEC_ANALYST_DB` and
`AGENTSEC_ANALYST_RECORDING`, plus an AI mode other than `off`. Its tenant is
explicit or inherited from another configured product store and must match.
Authenticated routes under `/v1/analyst` expose bounded run lookup/listing,
finding lookup, aggregate health, and redacted feedback. An analyst outage is
post-response advisory failure and cannot alter the authorization result.

To replace the recorded analyst with governed live-provider candidates, copy
and review `configs/model-gateway.example.json`, replace every placeholder exact
model ID, export the provider keys referenced by that file, remove
`AGENTSEC_ANALYST_RECORDING`, and add:

```bash
AGENTSEC_MODEL_GATEWAY_DB='/tmp/agentsec-model-gateway.sqlite3' \
AGENTSEC_MODEL_GATEWAY_CONFIG="$PWD/configs/model-gateway.example.json" \
AGENTSEC_MODEL_GATEWAY_TENANT='tenant-lab' \
AGENTSEC_ANALYST_DB='/tmp/agentsec-analyst.sqlite3' \
AGENTSEC_AI_MODE=shadow
```

Configuration creates candidate routes only. Use the authenticated qualification
→ shadow → activation lifecycle after independently evaluating the exact route.
Qualifications expire and are removed from selection. Gateway APIs expose live
prompts, routes, qualifications, secret metadata, sanitized calls, health,
audit, and exact lifecycle mutations without returning credentials or raw model
payloads.

To enable live enrichment, copy
`configs/enrichment-connectors.example.json`, replace its example endpoints,
and export each bearer token under the environment-variable name referenced by
that file. Then add these settings to the service command:

```bash
AGENTSEC_ENRICHMENT_DB='/tmp/agentsec-enrichment.sqlite3' \
AGENTSEC_ENRICHMENT_CONFIG='/absolute/path/to/enrichment-connectors.json' \
AGENTSEC_ENRICHMENT_TENANT='tenant-lab' \
PYTHONPATH=src python3 -m agentsec serve --host 127.0.0.1 --port 8080
```

The database and config variables must be supplied together. The configuration
contains environment-variable names, never bearer values. The authenticated
`GET /v1/enrichment/health` route reports cache, timeout, stale-fallback, and
circuit health without returning connector requests or credentials.

Start the token-owning local UI bridge with the same bearer token in a second
terminal:

```bash
AGENTSEC_INGEST_TOKEN='replace-with-at-least-32-random-characters' \
  PYTHONPATH=src python3 tools/live_ui_bridge.py
```

Then start the UI in a third terminal:

```bash
cd ui
npm run dev
```

Container and no-ingress EC2 Tokyo preparation is documented in
[`deploy/ec2-tokyo/README.md`](deploy/ec2-tokyo/README.md). The template is
validation-only until an operator explicitly approves creating billable AWS
resources.

The research-PoC evidence matrix is in
[`docs/release-audit.md`](docs/release-audit.md). The result is not a production
authorization; read [`docs/limitations.md`](docs/limitations.md) before using or
extending it.

## External API and SIEM integrations

AgentSec now commits privacy-safe findings to a durable event stream and
idempotent SIEM outbox. The common integration plane supports acknowledged
Splunk HEC, Elastic bulk, signed HTTPS webhooks, RFC 5424 over TLS, CEF over TLS,
and OTLP HTTP JSON with bounded retry, dead-letter, redrive, receipt hashes, and
tamper-evident audit. Checked-in destinations are disabled `.invalid` examples;
tests do not contact a vendor.

Public SIEM/data-platform consumers use independently scoped, tenant-bound
bearers under `/api/v1` for capabilities, event streaming, search, entities,
rules, findings, incidents, and integration status. These tokens cannot call
the private `/v1` administrative API or replace signed workload telemetry
credentials. Python and TypeScript fixed-route clients are included.

Local configuration requires the integration database, policy, and cursor
secret together:

```bash
AGENTSEC_INTEGRATION_DB='/tmp/agentsec-integrations.sqlite3' \
AGENTSEC_INTEGRATION_CONFIG="$PWD/configs/external-integrations.example.json" \
AGENTSEC_INTEGRATION_TENANT='tenant-lab' \
AGENTSEC_INTEGRATION_CURSOR_SECRET='replace-with-at-least-32-random-characters' \
AGENTSEC_EXTERNAL_API_CLIENTS_CONFIG="$PWD/configs/external-api-clients.example.json" \
PYTHONPATH=src python3 -m agentsec serve --host 127.0.0.1 --port 8080
```

Copy both policies before enabling a destination or client. Set credential
values only in the referenced environment variables; never write them into the
JSON files. See
[`docs/modules/module-21-external-api-and-siem-integration.md`](docs/modules/module-21-external-api-and-siem-integration.md)
for the API/scopes, acknowledgment semantics, and production non-claims.

## Simulation and validation lab

AgentSec includes a durable tenant-scoped validation lab with six built-in
benign and adversarial scenarios, including a multi-stage RAG-injection-to-
egress chain. A constrained builder derives fixed Japanese, Spanish,
Unicode-confusable, zero-width, Base64, and mixed variants without accepting or
retaining raw prompts. Protected, control, and comparison runs expose explicit
expected-versus-observed alerts, actions, mock effects, alert/finding IDs,
reasons, signed scenario/run records, replay lineage, and a per-run local-only
sandbox receipt.

Enable the durable lab alongside the service:

```bash
AGENTSEC_SIMULATION_DB='/tmp/agentsec-simulation.sqlite3' \
AGENTSEC_SIMULATION_TENANT='tenant-lab' \
PYTHONPATH=src python3 -m agentsec serve --host 127.0.0.1 --port 8080
```

Open **Validation Lab** in the UI after starting the loopback bridge. The screen
uses only live API records and has no fixture fallback. The variants test
normalized metadata behavior; they do not claim raw-language or tokenizer
coverage. See
[`docs/modules/module-22-simulation-and-validation-lab.md`](docs/modules/module-22-simulation-and-validation-lab.md).

## Analyst interface

The responsive AgentSec Authorization Control Room is in [`ui/`](ui/). Its
incident queue polls sanitized decisions from the local product service through
the loopback-only [`tools/live_ui_bridge.py`](tools/live_ui_bridge.py).
It provides a seven-stage authoritative trace, enrichment and triage evidence,
pre-response model-verdict validation, the five-role AI analyst run, structured
claim-to-evidence judgment, mandatory evidence checks, contradictions,
calibrated confidence, tool receipts, human analyst transitions, a
policy catalog, evaluation comparison, live model-governance control plane, a
durable Case Workbench, a live Escalations outbox, a guarded Response and
playbook workspace, and an allowlisted POC event
forge. The case surface shows actual assignment, SLA, collaboration, review,
and hash-chain evidence without fixture fallback. The escalation surface shows
exact routes, on-call ownership, four delivery channels, retry/dead-letter
state, provider receipt hashes, human acknowledgment SLA, and its audit chain
without fixture fallback. The Response surface shows signed dry runs, hashed
targets, independent approvals, exact plan/policy digests, connector attempts,
post-effect verification, rollback, the kill switch, and reviewed playbook
revisions without fixture fallback. Historical entries without retained detail are
shown as `summary_only`; missing scores or explanations are never reconstructed.

The control room also exposes evidence-bound **Reports** and read-only
**Administration** workspaces. Their fixed `/api/platform` BFF projection
combines bounded health from the product planes with SHA-256-bound release,
evaluation, and module records. The bearer remains server-side; the receipt
explicitly does not claim human authentication, and missing data is never
replaced with presentation fixtures.
See [`ui/README.md`](ui/README.md) for the complete local startup.

## Simulation and Validation Lab

Module 22 adds a durable, tenant-scoped validation corpus and a dedicated
**Validation Lab** workspace. It includes six mapped built-in scenarios,
including a multi-stage RAG injection-to-exfiltration chain; deterministic
Japanese, Spanish, encoded, confusable, zero-width, and mixed variants; strict
untrusted import; protected/control comparison; exact-digest replay; mock-only
sandbox receipts; and hash-chained audit evidence.

Enable it alongside the local authenticated service:

```bash
AGENTSEC_SIMULATION_DB='/tmp/agentsec-simulation.sqlite3' \
AGENTSEC_SIMULATION_TENANT='tenant-lab' \
PYTHONPATH=src python3 -m agentsec serve --host 127.0.0.1 --port 8080
```

Then start the existing loopback bridge and UI. The browser can select only a
catalog scenario, fixed mutation profile, run mode, or signed replay; it cannot
submit raw content, arbitrary events, effects, paths, or destinations. Variant
coverage begins after normalization and is not a raw-prompt evasion claim. See
[`docs/modules/module-22-simulation-and-validation-lab.md`](docs/modules/module-22-simulation-and-validation-lab.md).

## Evaluation and Continuous Improvement

Module 23 adds a sealed-label, 42-case evaluation plane beside the compact
effect/ablation benchmark. It reports precision/recall, completed effects,
benign completion, severity, evidence citations, exact and safe actions,
abstention, Brier score, calibration error, schema validity, and latency overall,
per use case, and per split. Twenty-four cases are holdouts.

The committed release compares a recorded Codex candidate with a deterministic
baseline and fails closed on absolute or drift thresholds:

```bash
make continuous-evaluate
```

To enable durable authenticated runs, baselines, feedback, dataset promotion,
and audit locally, set `AGENTSEC_EVALUATION_DB`,
`AGENTSEC_EVALUATION_TENANT`, `AGENTSEC_EVALUATION_POLICY`, and optionally
`AGENTSEC_EVALUATION_RECORDING` as shown in [`.env.example`](.env.example).
Feedback requires separate submitter, reviewer, and publisher identities and is
never applied directly to a model or runtime policy. See
[`docs/modules/module-23-evaluation-and-continuous-improvement.md`](docs/modules/module-23-evaluation-and-continuous-improvement.md).

## Administration, platform security, and audit

Module 24 adds a tenant-scoped administration control plane for the reference
product: six human RBAC roles, provisioned signed assertions, MFA/step-up for
high-impact operations, workload identity rotation/revocation, external-only
credential and key references, two-person key activation, independent access
reviews, residency/retention/encryption policy, append-only administrative
audit with signed checkpoints, SLO measurements, recovery-drill receipts, and
independently verified artifact/SBOM/provenance attestations.

Enable it locally only with explicit runtime keys:

```bash
AGENTSEC_ADMIN_DB='/tmp/agentsec-administration.sqlite3' \
AGENTSEC_ADMIN_TENANT='tenant-lab' \
AGENTSEC_ADMIN_CONFIG="$PWD/configs/administration.example.json" \
AGENTSEC_ADMIN_ASSERTION_KEY='replace-with-at-least-32-random-characters' \
AGENTSEC_ADMIN_CHECKPOINT_KEY='replace-with-a-different-32-character-key' \
PYTHONPATH=src python3 -m agentsec serve --host 127.0.0.1 --port 8080
```

The example assertion signer and checkpoint signer are local HMAC adapters.
They do not prove enterprise IdP federation, KMS/HSM custody, geographic
placement, distributed HA, or production readiness. The live Administration
UI keeps those flags explicitly false. See
[`docs/modules/module-24-administration-platform-security-and-audit.md`](docs/modules/module-24-administration-platform-security-and-audit.md).

The long-form design is in
[`agent-security-detailed-implementation-plan.md`](agent-security-detailed-implementation-plan.md).

## Safety invariants

- Every effect is judged before execution.
- Delegation can preserve or reduce authority, never expand it.
- Untrusted provenance survives transformations and handoffs.
- `deny > require_approval > allow_with_obligations > allow`.
- Model failure cannot disable deterministic enforcement.
- Model tightening requires known evidence and calibrated validation; invalid
  or overconfident advice is held for human review.
- AI analyst roles are read-only advisors and never receive effect authority.
- Case creation and analyst collaboration are post-decision and cannot alter
  the deterministic authorization result.
- Pipeline response summaries remain simulated. Module 19 live response is a
  separate opt-in path that requires reviewed connectors, credentials, an exact
  plan approval, and a distinct executor; the checked-in configuration has no
  routable endpoint or credential.
