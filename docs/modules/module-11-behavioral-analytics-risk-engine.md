# Module 11 — Behavioral analytics and risk engine

Status: verified on 2026-07-24  
Behavior contracts: 1.0.0

## Comparison baseline

Modules 1–10 collected, normalized, stored, searched, mapped, posture-checked,
and deterministically detected AI-agent metadata. Triage had a reproducible
static score and a process-local repeat counter, but the product did not learn
normal behavior per entity. It had no durable baseline, evaluate-before-learn
boundary, learning eligibility decision, explainable probability, composite
behavioral/context risk, drift window, tuning history, health surface, or live
risk-analytics workspace.

## Implemented remediation

- Added `src/agentsec/behavior.py`, a tenant-scoped SQLite WAL/full-sync service
  for versioned behavior configuration, entity baselines, event assessments,
  entity scores, learning decisions, drift observations, and audit records.
- Added metadata-only feature extraction for operation, resource/destination
  class, source trust, UTC hour, effect/approval state, sensitive-data class,
  authority gap, and tool-schema drift. Arbitrary attributes, raw prompts,
  model text, tool arguments/results, headers, tokens, and credentials are not
  features and are not copied.
- Added privacy-safe agent, source, tool, and destination entity references as
  namespace-qualified truncated SHA-256 values. Raw source, agent, tool, and
  destination identifiers never enter baseline records.
- Added evaluate-before-learn ordering. The pipeline assesses the event against
  the prior accepted-event profile, completes detection and authorization, and
  only then learns an event that was allowed and produced no security alert.
  Alerted or restricted events receive a final rejected-learning receipt.
- Added cold-start behavior: fewer than the configured minimum observations
  remains `learning` and cannot independently create an anomaly alert.
- Added explainable categorical and boolean deviations with observed value,
  expected distribution/rate, smoothed probability, bounded contribution,
  rationale, entity reference, and evidence references.
- Added per-entity anomaly scores and confidence plus an event composite score
  combining the highest prior-baseline deviation with bounded contextual risk.
  Threshold-crossing assessments emit a typed `behavioral_anomaly` alert and
  can require approval or deny a high-risk effect.
- Integrated the behavioral receipt into triage scoring and authoritative
  incident detail: assessment ID, anomaly score, composite risk, drift state,
  contribution, warning/outage behavior, and evidence remain visible to an
  analyst. Behavioral failure never suppresses deterministic detection.
- Added bounded recent-window drift for the tenant and individual hashed
  entities, with insufficient-data, stable, warning, and critical states.
- Added immutable, increasing-version tuning configuration with strict bounds,
  a fixed 100-point weight sum, warning-before-critical invariants, reason,
  actor, timestamp, canonical digest, history, and tamper verification.
- Added baseline canonical digests and read-time verification. Observation
  counts are capped with deterministic decay; assessments have retention and
  pagination caps; duplicate event IDs are idempotent only when the feature
  digest is identical.
- Added separate behavior read, analyze, and admin permissions and strict
  tenant alignment in explicit environment assembly through
  `AGENTSEC_BEHAVIOR_DB` and `AGENTSEC_BEHAVIOR_TENANT`.
- Added authenticated read APIs for baselines, assessments, anomaly lists,
  detail, health, configuration history, and drift plus an exact bounded
  configuration activation API.
- Added a token-owning loopback projection with fixed routes, hashed entity and
  assessment ID validation, exact tuning fields, local-origin writes, and no
  bearer-token exposure.
- Added the live **Risk Analytics** workspace with health metrics, anomaly
  queue, full factor evidence, entity scores, learning receipts, tenant/entity
  drift, privacy-safe baseline table, governed tuning, and immutable history.
  It has explicit empty/offline states and no fallback data.
- Added ten generated JSON Schemas for behavior principal, feature, factor,
  entity score, assessment, baseline, tuning input/config, drift, and health.

## Security invariants

1. An event is evaluated against the stored prior baseline before any part of
   that event can update the baseline.
2. Only an allowed event with zero processed security alerts is eligible for
   learning; the final learned/rejected state is immutable and idempotent.
3. Cold-start profiles cannot independently classify an event as anomalous.
4. Durable baselines contain hashed entity references and bounded metadata
   classes, never raw prompts, payloads, tool data, destinations, or identity
   strings.
5. Duplicate event IDs with different behavior features fail closed.
6. Baselines and tuning records are digest-verified on read; configuration
   versions must increase and their weights must total exactly 100.
7. Entity/event pages, histories, windows, retention, and observations have
   fixed upper bounds. Decay prevents unbounded learned count growth.
8. Behavioral analysis can tighten a decision but cannot suppress or relax a
   deterministic alert. An analysis outage is recorded as missing context and
   deterministic enforcement continues conservatively.
9. The browser can access only fixed behavioral routes through the loopback
   bridge. It cannot submit events, entity identities, executable logic, or
   arbitrary configuration fields.
10. Drift reports recent model behavior; they do not automatically retrain,
    lower thresholds, dismiss alerts, or mutate deterministic rules.

## Interfaces

Read routes:

- `GET /v1/behavior/baselines`
- `GET /v1/behavior/assessments`
- `GET /v1/behavior/assessments/{assessment_id}`
- `GET /v1/behavior/health`
- `GET /v1/behavior/config`
- `GET /v1/behavior/drift?entity_ref={hashed_ref}`

Governed write route:

- `POST /v1/behavior/config` with exactly `config` and `reason`.

The loopback bridge projects fixed equivalents under `/api/behavior`, including
the fixed anomaly-only list `/api/behavior/anomalies`. Baseline and assessment
lists are capped at 200. No arbitrary query, raw identity, or event-ingestion
surface is exposed to the browser.

## Verification evidence

- `tests/test_behavioral_risk.py` covers evaluate-before-learn, explainable
  composite anomalies, cold start, final learning decisions, pipeline alert and
  incident evidence, allowed/no-alert learning, durable privacy-safe baselines,
  configuration versioning/tamper detection, drift/health, tenant/permissions,
  conflicting IDs, concurrent idempotency, bounded scale, APIs, and explicit
  environment assembly.
- `tests/test_live_ui_bridge.py` covers fixed read/write routes, anomaly-only
  projection, exact tuning fields, invalid raw entity/assessment references,
  server-side token custody, and refusal of arbitrary mutation.
- UI source and render contracts cover the live Risk Analytics surface,
  detailed factor proof, baseline/drift/tuning controls, no-fallback behavior,
  responsive layout, and production server rendering.
- Generated schemas make the behavior evidence and control contracts portable
  and drift-detectable.

## Deferred dependencies, not Module 11 completion shortcuts

- Module 12 correlates multiple findings and behavior assessments into a
  first-class incident rather than changing this event-level risk boundary.
- Modules 13–16 add live enrichment and governed multi-model analyst/judgment
  capabilities. Behavioral scoring stays deterministic and provider-neutral.
- Module 20 supplies product-wide authenticated analyst identity and the
  complete navigation/accessibility/reporting experience.
- Module 23 adds large blind datasets, calibration, feedback, and release drift
  gates beyond the deterministic behavioral regression here.
- Module 24 supplies SSO/RBAC, managed signing/key rotation, distributed data
  stores, global audit, HA, backup, and disaster recovery.

## Acceptance closure

Twelve focused behavioral tests, twelve bridge tests, and the production UI
build/render/source contracts pass. The complete repository gate also passed:

- 243 Python tests and 5 TypeScript SDK tests;
- 2 analyst UI production build/render contract tests;
- 137 generated schema checks and 10 deterministic report checks;
- clean-package install reproduction, Python compilation, secret scan,
  dependency check, release audit, workflow/Codex demos, all evaluation modes,
  and component ablation.

The module audit reports 11/24 approved modules verified. Durable privacy-safe
baselines, evaluate-before-learn, governed eligibility, explainable anomalies,
composite risk, drift, immutable tuning, health/API/bridge surfaces, incident
evidence, and the live Risk Analytics workspace are complete. Multi-finding
correlation, live enrichment and model governance, larger calibration/evaluation,
product-wide analyst identity, managed signing, distributed stores, and platform
operations remain explicitly assigned to Modules 12–16, 20, 23, and 24.
