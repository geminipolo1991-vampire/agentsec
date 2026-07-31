# Module 14 — AI Analyst Engine

Status: verified on 2026-07-24  
Analyst contracts: 1.0.0  
Policy: `ai-analyst-2026-07-24.1`

## Comparison baseline

The prior product had strong deterministic detection, evidence enrichment,
explainable triage, judgment, escalation, response, and incident detail. It also
had one provider-neutral `SecurityReasoner` verdict and a recorded Codex shadow
artifact. That boundary was deliberately narrow but was not a SOC analyst
engine: there were no separate triage/investigation/judge/escalation/response
roles, evidence-query receipts, mandatory alternatives, responsible abstention,
cross-role disagreement, durable analyst runs, run health, analyst feedback, or
a dedicated investigation view.

## Implemented remediation

- Added strict contracts for analyst roles, role status, run status, evidence
  items, alternatives, role requests/results, tool receipts, disagreements,
  durable runs, feedback, and aggregate health.
- Added exactly five ordered roles: triage, investigation, judge, escalation,
  and response advisor. Their fixed objectives constrain the work and make role
  omission or reordering invalid.
- Added a read-only evidence tool that builds one allowlisted manifest from the
  exact authoritative pipeline result and returns only the evidence kinds
  required by each role.
- Added digest-bound tool receipts containing requested kinds, returned
  evidence IDs, result count, and timestamp. Accepted role and alternative
  citations must be a subset of the tool result.
- Required every completed role to expose a summary, confidence, cited
  evidence, at least one alternative, and uncertainty. Non-completed roles must
  carry an abstention/unavailability reason and cannot recommend an action.
- Normalized timeout, malformed output, role/provider/model mismatch, and
  fabricated citations to a visible unavailable role instead of accepting or
  inventing a conclusion.
- Added a disagreement register for deterministic-versus-judge relaxation or
  tightening, cross-role conflict, abstention, and unavailable roles. P0/P1 or
  disagreement sets the human-review flag.
- Structurally fixed `executive_authority=false`. The advisory result is the
  more restrictive of deterministic policy and an accepted judge proposal;
  weaker model advice is retained as rejected disagreement and cannot affect
  the already completed effect decision.
- Placed the engine after deterministic response in `SecurityPipeline`. An
  analyst outage records a fixed availability state and returns the unchanged
  authoritative pipeline result.
- Added an immutable recorded Codex five-role configuration with exact provider,
  model, recording, role templates, reason codes, uncertainty, and response/
  escalation advice. It is reproducible offline evidence, not a live API claim.
- Added recursive redaction for all model-authored prose before durable or UI
  storage. Raw event attributes and identifiers never enter the model evidence
  manifest; evidence IDs are governed namespace hashes.
- Added tenant-scoped SQLite WAL/full-sync persistence with alert idempotency,
  canonical run/feedback SHA-256 integrity checks, exact read/run/feedback
  permissions, cross-tenant denial, bounded pagination, and restart proof.
- Added redacted attributable feedback that is structurally marked
  `applied_to_model=false`; feedback cannot retrain a model or alter a decision.
- Added authenticated run list/detail, finding lookup, feedback list/create,
  and health APIs under `/v1/analyst`, plus explicit environment assembly and
  tenant alignment.
- Added the complete run to authoritative `IncidentDetail`, never summary-only
  detail, and a dedicated **AI Analyst** UI tab showing roles, evidence,
  alternatives, uncertainty, abstention, advice, tool receipts, disagreements,
  human review, identity, timestamps, and digests.
- Added twelve generated JSON Schemas for the new public/configuration contracts.

## Security invariants

1. Deterministic policy and the already recorded effect decision remain the
   authority; the AI analyst never executes a tool effect or response.
2. Model advice may be preserved or tightened for human consideration but can
   never weaken deterministic action, create authority, or create approval.
3. Every role uses a bounded read-only evidence query and can cite only evidence
   returned by that query. Fabricated citations fail closed as unavailable.
4. Completed roles must show evidence, alternatives, confidence, and uncertainty;
   missing support is never silently converted into a conclusion.
5. Abstention and unavailability are responsible terminal role states with no
   action recommendation and explicit human-review evidence.
6. Raw prompts, model output, memory, tool arguments/results, arbitrary
   attributes, raw identifiers, headers, credentials, tokens, and secrets do
   not enter analyst requests, durable runs, health, feedback, APIs, or UI.
7. Model-authored prose and analyst feedback are recursively redacted before
   persistence. Feedback is inert until a separately governed evaluation loop.
8. Run and feedback reads verify canonical digests; conflicting/tampered state,
   cross-tenant access, missing permissions, and invalid pagination fail closed.
9. The five roles and their tool receipts must remain complete and in governed
   order. Role/provider/model identity mismatch is rejected.
10. Engine outage, timeout, refusal, invalid output, or restart cannot alter the
    deterministic security path or erase the per-alert investigation record.

## Interfaces and operation

Local recorded-Codex execution requires:

- `AGENTSEC_ANALYST_DB` — analyst run/feedback SQLite path;
- `AGENTSEC_ANALYST_RECORDING` — absolute or repository-relative recorded role
  configuration path;
- `AGENTSEC_ANALYST_TENANT` — explicit tenant, or a matching inherited product
  tenant; and
- `AGENTSEC_AI_MODE=shadow`, `advisory`, or `semantic_hold`.

Both database and recording must be supplied. AI mode `off`, incomplete
configuration, or tenant mismatch fails startup rather than creating a partial
analyst service.

Authenticated APIs are:

- `GET /v1/analyst/runs?limit=&offset=`;
- `GET /v1/analyst/runs/{run_id}`;
- `GET /v1/analyst/findings/{finding_id}`;
- `GET /v1/analyst/health`;
- `GET /v1/analyst/feedback?run_id=`; and
- `POST /v1/analyst/runs/{run_id}/feedback` with exact rating, role, and reason
  fields.

The same typed run is embedded in full authoritative incident detail and shown
in the UI. Historical or summary-only incidents do not receive reconstructed
AI analysis.

## Verification evidence

`tests/test_ai_analyst.py` covers the complete recorded Codex role sequence,
evidence/tool receipts, alternatives, non-executive authority, incident detail,
relaxation rejection, responsible abstention, bounded timeout, fabricated
citation rejection, model-prose redaction, durable idempotency/integrity,
permissions, tenant isolation, inert feedback, health, environment assembly,
and authenticated HTTP APIs. Pipeline, incident, service, provider, schema, and
production UI suites provide compatibility and presentation coverage.

## Honest limitations and assigned follow-on work

- The Codex role engine currently uses a checked-in offline recording. Module 15
  owns live OpenAI/Claude role adapters, qualification, prompt registry, routing,
  privacy policy, budgets, health, secret lifecycle, and rollback.
- A schema-valid, correctly cited model claim is not necessarily true. Module 16
  adds claim-to-evidence verification, contradiction handling, mandatory
  evidence policies, calibration, injection resistance, and human judgment
  gates.
- Feedback is intentionally not learning. Module 23 owns representative
  evaluation, approved improvement proposals, drift monitoring, and rollback.
- The local database and fixed service identity are not production human IAM,
  managed signing, replicated storage, or organization audit. Module 24 owns
  SSO/MFA/RBAC, managed keys, HA, DR, and platform operations.
- The worker timeout cannot kill arbitrary provider code already executing;
  qualified live transports must implement their own network deadline and
  process-isolation guarantees.

## Acceptance closure

Nine focused analyst tests pass, including recorded Codex role execution,
stronger/weaker and cross-role disagreement, responsible abstention, timeout,
fabricated citation rejection, model/service outage, redaction, durable
integrity/idempotency, tenant/permission boundaries, inert feedback, environment
assembly, authenticated APIs, and authoritative incident/UI detail. The
provider, pipeline, incident, service, and production UI compatibility suites
also pass.

The complete repository gate passed:

- 271 Python tests and 5 TypeScript SDK tests;
- 2 analyst UI production build/render contract tests;
- 168 generated schema checks and 10 deterministic report checks;
- clean-package install reproduction, Python compilation, secret scan,
  dependency check, release audit, workflow/Codex demos, all evaluation modes,
  and component ablation.

The module audit reports 14/24 approved modules verified. The bounded five-role
engine, evidence-query receipts, alternatives, uncertainty, responsible
abstention, disagreement, non-executive action bound, durable integrity-checked
runs/feedback/health, authenticated APIs, recorded Codex test configuration,
and authoritative analyst UI are complete. Live provider/model governance,
claim validation, collaborative cases, evaluated learning, and managed platform
identity/keys/HA remain explicitly assigned to Modules 15, 16, 17, 23, and 24.
