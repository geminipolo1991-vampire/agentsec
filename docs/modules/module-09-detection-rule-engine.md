# Module 9 — Detection and rule engine

Status: verified on 2026-07-24  
Detection contracts: 1.0.0

## Comparison baseline

Before this loop, `DetectionEngine` iterated six hard-coded Python classes over
one `AgentEvent`. Those rules protected the research scenarios, but definitions
were not data contracts or durable records. There was no tenant authorization,
immutable version history, declarative expression model, event window, sequence,
threshold, correlation, scheduled replay, semantic rule boundary, execution
audit, health, framework propagation, product API, or bounded retention.

## Implemented remediation

- Replaced the default pipeline detector with strict declarative
  detection-as-code while preserving the six Python plug-ins for existing
  ablation and extension compatibility.
- Added event, sequence, threshold, correlation, and semantic rule kinds with
  streaming, scheduled, or dual execution modes.
- Added an allowlisted event-field vocabulary and typed equality, membership,
  collection, existence, and field-to-field operators. Arbitrary field paths,
  expressions, regex, SQL, Python, and request-supplied code are impossible.
- Added AND plus optional OR predicate groups, bounded condition/step counts,
  windows, thresholds, grouping fields, evidence fields, strings, mappings,
  tags, and rule selection.
- Added strict rule-shape validation so fields for one rule kind cannot be
  smuggled into another kind.
- Added immutable tenant-scoped rule versions with natural numeric ordering,
  canonical SHA-256 definition digests, supersession history, and separate
  read/run/admin permissions.
- Added ten default AI-security rules: the six original deterministic controls,
  injection-to-egress sequence, flow egress threshold, memory/egress
  correlation, and a disabled semantic reference profile.
- Mapped default content to OWASP LLM, MITRE ATLAS, and NIST AI RMF and
  propagated mappings plus exact rule versions into `SecurityAlert`, canonical
  alert records, and the safe search projection.
- Added durable metadata-only event windows and execution history in SQLite
  with WAL, full synchronization, indexed tenant/time access, event-ID conflict
  refusal, an observed-time retention watermark, and a hard 10,000-event cap.
- Explicitly removes the event `attributes` map before persistence; prompts,
  model/tool content, credentials, and arbitrary attributes are unavailable to
  declarative rules and scheduled replay.
- Added ordered distinct-event sequence reconstruction, grouped thresholds,
  unordered distinct-event correlation, event rules, and bounded scheduled
  replay over durable windows.
- Added a provider-neutral semantic verdict contract with minimum confidence,
  known-evidence enforcement, fixed prefilters, and per-rule failure isolation.
  Semantic outage or invalid output is recorded and cannot suppress or relax
  deterministic detections.
- Added per-rule execution records containing mode, status, evaluated count,
  matched event IDs, alert IDs, duration, fixed error code, and timestamps.
- Added current rule health derived from persisted match/error execution state.
- Added authenticated read-only rule and health endpoints plus an exact
  scheduled-execution endpoint. Content authoring/promotion remains Module 10.
- Added explicit local assembly with `AGENTSEC_DETECTION_DB` and a fixed tenant;
  configured product-store tenants must align.
- Generated nine strict JSON Schemas for the new public detection contracts.

## Security invariants

1. The configured principal supplies tenant and permissions; an event or API
   payload cannot choose a different rule tenant.
2. A rule version is immutable. Changed content requires a strictly increasing
   version and preserves prior definitions.
3. Rule content is validated data, never executable source, SQL, regex, shell,
   template, or unrestricted attribute access.
4. Only fixed metadata fields can be evaluated or retained; `AgentEvent`
   attributes are replaced by an empty map before persistence.
5. Duplicate event IDs are idempotent only when their safe canonical metadata
   digest matches; conflicting reuse fails closed.
6. Windows, event count, threshold, conditions, steps, mappings, evidence, rule
   selection, and scheduled time are bounded.
7. Sequence and correlation require distinct stored events; one event cannot
   satisfy multiple steps merely because it has overlapping fields.
8. Semantic output can create only its configured rule alert, must cite known
   event references, and cannot modify deterministic rule outcomes.
9. A semantic rule error is sanitized, audited, and isolated; remaining rules
   still execute.
10. Every alert binds its rule ID/version, framework mappings, safe evidence,
    and stable fingerprint before entering the existing immutable lifecycle.

## Verification evidence

- `tests/test_detection_engine.py`
  - ten-rule default content and exact six-control compatibility;
  - immutable natural version history and restart durability;
  - streaming sequence, threshold, and distinct-event correlation;
  - scheduled-only durable replay before and after restart;
  - semantic match, confidence, evidence, outage isolation, and health;
  - tenant, permission, schema, arbitrary-field, selection, and privacy refusal;
  - authenticated live rule/health/authorization/scheduled APIs;
  - explicit environment assembly;
  - 400-event bounded performance and concurrent duplicate capture.
- Existing pipeline, synthetic workflow, evaluation/ablation, canonical model,
  search, service, schema, and release tests remain regression evidence.
- Generated schemas cover principals, conditions, predicates, definitions,
  records, semantic verdicts, executions, batches, and health.

## Deferred dependencies, not Module 9 completion shortcuts

- Module 10 adds authoring, review, test, backtest, shadow promotion, rollback,
  content packs, signing, and analyst content-management UI.
- Module 11 adds learned behavioral baselines and composite entity risk.
- Module 12 correlates produced alerts and findings into first-class incidents;
  Module 9 correlation remains event-rule correlation.
- Module 15 qualifies and governs live OpenAI/Claude semantic providers.
- Module 22 expands safe simulation corpora and detection validation labs.
- Module 24 supplies distributed scheduling/storage, SSO/RBAC administration,
  managed key custody, platform audit export, SLOs, backup, and DR.

## Acceptance closure

Ten focused detection tests plus pipeline, workflow, evaluation, canonical,
search, service, schema, and API checks pass. The complete repository gate also
passed:

- 220 Python tests and 5 TypeScript SDK tests;
- 2 analyst UI production build/render contract tests;
- 119 generated schema checks and 10 deterministic report checks;
- clean-package install reproduction, Python compilation, secret scan,
  dependency check, release audit, workflow/Codex demos, all evaluation modes,
  and component ablation.

The local versioned detection runtime, durable metadata windows, execution
audit, product API, and compatibility boundary are complete. Content authoring
and promotion, learned analytics, alert-to-incident correlation, live provider
qualification, validation labs, distributed scheduling, and managed platform
controls remain explicitly assigned to Modules 10–12, 15, 22, and 24.
