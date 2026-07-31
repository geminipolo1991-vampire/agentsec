# Module 15 — Model Gateway and AI Governance

Status: verified  
Gateway contracts: 1.0.0  
Policy: model-gateway-2026-07-24.1

## Comparison baseline

Before this module, AgentSec had safe OpenAI Responses and Anthropic Messages
adapters, exact endpoint allowlists, privacy-transformed verdict evidence,
schema-bound output, local citation validation, normalized failure, and a
configuration-only fallback registry. Module 14 supplied the five-role analyst
engine through a reproducible recorded Codex configuration.

That was not a deployable AI control plane. Profiles had no durable
qualification evidence; prompts were constants; and the product had no
candidate/shadow/active lifecycle, privacy-class routing, transactional
budgets, circuit state, credential-version fingerprint, qualification expiry,
sanitized call ledger, or exact rollback. The UI showed fixed provider cards
rather than observed state, and live providers did not implement the five roles.

## Implemented remediation

- Added a tenant-scoped SQLite ModelGatewayService with WAL/full-sync
  durability, bounded reads, explicit permissions, canonical digests, restart
  verification, and a hash-only governance audit.
- Added immutable prompt versions binding workload, complete instructions,
  output-schema digest, author, timestamp, and prompt digest. Prompt invariants
  require read-only, evidence-as-data, untrusted-instruction, and non-executive
  language.
- Added immutable route revisions binding provider, exact model ID, exact HTTPS
  endpoint, secret metadata version, prompt version, workload, allowed AI modes,
  privacy classes, region, priority, explicit fallback, budgets, output bound,
  timeout, and route digest.
- Restricted destinations to the exact official OpenAI Responses or Anthropic
  Messages host and path. Alternate schemes, hosts, paths, credentials in URLs,
  queries, fragments, and SSRF targets are rejected.
- Added expiring, evidence-digest-bound qualification. Passing requires at least
  five fixtures, 100% schema and citation validity, zero forbidden effects,
  zero privacy-canary leaks, zero deterministic relaxations, and a passed
  fallback test.
- Bound qualification to exact route digest, prompt digest, and model ID.
  Executor and reviewer must differ; activation must use an actor distinct from
  the reviewer. Validity is bounded to 1–720 hours, seven days by default.
- Added candidate → shadow → active → retired lifecycle. Activation verifies
  current qualification and credential fingerprint. Superseded revisions stay
  as history; rollback restores only a current, credential-ready prior revision.
- Added secret metadata containing only environment-variable name, SHA-256
  fingerprint, version, stage, actor, and timestamps. Values never enter the
  database, APIs, UI, audit details, or call receipts. Unexpected environment
  changes fail readiness until explicit rotation.
- Added privacy-aware selection for primary and fallback routes. Secret-egress
  alerts and secret/credential/PII/restricted markers force restricted
  classification, so internal-only routes never receive that evidence.
- Added atomic requests/minute, tokens/day, and concurrency reservations under
  BEGIN IMMEDIATE. Reservations charge an input estimate plus maximum output;
  failure is conservatively charged. Exhaustion denies before provider creation.
- Added route health, failure counts, normalized errors, latency, circuit
  opening/recovery, and fallback only to independently active, qualified,
  privacy-compatible, mode-compatible, healthy routes.
- Added sanitized calls binding route/model/prompt/workload/mode/privacy,
  reservation/usage, latency, provider request ID, output digest, status/error,
  and timestamps—never raw prompts, evidence, outputs, headers, or credentials.
- Hardened HTTPS with redirect refusal, one-MiB default response cap,
  content-type validation, exact endpoint allowlists, timeout normalization,
  and bounded JSON parsing.
- Added live OpenAI and Anthropic five-role adapters. Both use structured output,
  handle refusal/truncation, pin response identity, locally validate contracts,
  restrict citations, and reject non-judge actions or deterministic relaxation.
- Added governed pipeline and analyst adapters. Each of the five roles receives
  its own gateway receipt, and provider identity must match a current qualified
  analyst route.
- Added fail-explicit environment assembly. Gateway database/config must be
  paired, non-off AI mode and tenant alignment are mandatory, and an analyst
  database may use either recorded Codex or the governed live gateway.
- Added authenticated health, route, prompt, qualification, call, secret
  metadata, audit, qualification, shadow, activation, rollback, secret
  registration, and retirement APIs.
- Replaced static provider cards with a live control-plane UI showing stage,
  exact model, qualification/expiry, circuit, secret readiness, privacy/modes,
  budgets, fallback, prompt/schema versions, review evidence, and call receipts.
  Offline/empty state never invents readiness or demonstration calls.
- Added generated schemas, a candidate-only example configuration, focused
  backend/API/runtime/bridge/UI tests, and public package exports.

## Security invariants

1. No active, unexpired, passed exact qualification means no provider call.
2. Candidates cannot skip shadow; qualification review and activation require
   separated actors.
3. Any model, endpoint, prompt, secret, privacy, mode, budget, timeout, or
   fallback change requires a new immutable revision and qualification.
4. Credential values exist only in process environment and provider headers.
5. Privacy compatibility applies to primary and fallback before construction.
6. Budget and concurrency reservations are transactional and race-safe.
7. Failure, refusal, malformed output, fabricated citation, wrong model,
   redirect, oversized response, invalid content type, timeout, open circuit,
   expired qualification, missing secret, and budget denial fail closed without
   weakening deterministic enforcement.
8. Models are read-only and non-executive. Only the judge may recommend an
   action, and it cannot relax deterministic policy.
9. Route and prompt reads verify digests; tampering remains detectable after
   restart.
10. UI and bridge report observed state only and never synthesize health,
    qualification, calls, credentials, or raw content.

## Interfaces and operation

Required environment:

- AGENTSEC_AI_MODE set to shadow, advisory, or semantic_hold;
- AGENTSEC_MODEL_GATEWAY_DB;
- AGENTSEC_MODEL_GATEWAY_CONFIG;
- AGENTSEC_MODEL_GATEWAY_TENANT, explicit or inherited from an aligned service;
- each credential variable named by the configuration.

For live five-role analysis, add AGENTSEC_ANALYST_DB and an aligned analyst
tenant, and omit AGENTSEC_ANALYST_RECORDING. Supplying the recording retains the
offline Codex path. Configuration import creates candidates only; operators must
qualify, shadow, and activate exact revisions separately.

Authenticated reads are:

- GET /v1/model-gateway/health
- GET /v1/model-gateway/routes
- GET /v1/model-gateway/prompts
- GET /v1/model-gateway/qualifications
- GET /v1/model-gateway/calls?limit=&offset=
- GET /v1/model-gateway/secrets
- GET /v1/model-gateway/audit?limit=

Lifecycle mutations are:

- POST /v1/model-gateway/routes/{route_id}/{revision}/qualify
- POST /v1/model-gateway/routes/{route_id}/{revision}/shadow
- POST /v1/model-gateway/routes/{route_id}/{revision}/activate
- POST /v1/model-gateway/routes/{route_id}/rollback
- POST /v1/model-gateway/secrets
- POST /v1/model-gateway/secrets/{secret_id}/{version}/retire

The example in configs/model-gateway.example.json uses placeholder model IDs and
creates no active route. Replace IDs, evaluate those exact IDs, independently
review the evidence digest, shadow, then activate.

## Provider contract basis

The OpenAI adapter uses the Responses API with store false and structured output
under text.format. It handles explicit refusal and still performs local schema,
evidence, identity, and authority checks. This follows the official
[Responses migration differences](https://developers.openai.com/api/docs/guides/migrate-to-responses#additional-differences),
[Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs),
and [Responses create reference](https://developers.openai.com/api/reference/resources/responses/methods/create).
Schema adherence is not treated as factual correctness.

The Anthropic adapter retains its provider-native Messages structured-output
contract and normalizes into the same local security checks. Any provider API or
exact-model change requires requalification.

## Verification evidence

Focused tests cover immutable definitions, exact/expiring qualification,
four-eyes lifecycle, SSRF, tenant/permissions, privacy denial, secret-alert
classification, transactional budgets, circuits/fallback, rotation, staged
revision/rollback, audit, restart tamper detection, five governed analyst roles,
OpenAI/Anthropic validation, redirect/content-type/size bounds, authenticated
APIs, runtime assembly, loopback bridge, and production UI contracts.

## Honest limitations and assigned follow-on work

- Schema and citation validity do not prove claims. Module 16 owns claim
  validation, contradictions, calibration, injection resistance, and human
  judgment gates.
- This module does not choose a currently marketed model, infer residency,
  calculate billing, or claim provider-account zero-data-retention. Those facts
  must be externally verified and captured in qualification.
- SQLite is not distributed quota/state. Module 24 owns replicated state,
  distributed concurrency, managed secrets/keys, HA/DR, SSO/MFA/RBAC, and
  organization audit.
- Lifecycle APIs use the authenticated service principal. Module 24 must add
  attributable human/workload identity for production mutation.
- Qualification evidence is digest-bound rather than the corpus itself. Module
  23 owns representative evaluations, drift, improvement proposals, and release
  rollback.
- Transport deadlines do not provide an external worker kill. Production
  isolation is assigned to Module 24.

## Acceptance closure

Module 15 passed its focused gate with 69 backend, provider, analyst, runtime,
service, and bridge tests. The production UI build and both UI contract tests
passed, and all 183 generated JSON schemas matched their source contracts.

The complete `make verify` gate then passed with 295 Python tests, five
TypeScript SDK tests, clean-package reproduction, bytecode compilation, secret
scan, dependency integrity, release audit, protected/unprotected workflow and
recorded Codex demonstrations, all seven evaluation modes, and control
ablation. The deterministic and Codex-shadow evaluations retained 100% recall,
zero false blocks, and zero completed forbidden effects on the bounded corpus.

The full gate initially reported 14/24 because catalog promotion is deliberately
performed only after successful verification. The post-promotion module audit
is the final recorded closure check for 15/24.
