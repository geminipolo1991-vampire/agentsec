# Module 10 — Detection content management

Status: verified on 2026-07-24  
Content contracts: 1.0.0

## Comparison baseline

Module 9 made detection definitions strict, immutable, tenant-scoped data, but
its administrative registry activated a version immediately. It had no safe
authoring state, deterministic test evidence, historical backtest, independent
review, shadow gate, publication acknowledgement, rollback workflow, portable
signed packs, content-health summary, analyst API, or Rule Studio. The service
also had no content-signing key or content-specific permissions.

## Implemented remediation

- Added a separate content control plane in `src/agentsec/content.py` in front
  of the live Module 9 registry. Draft content cannot affect detection until all
  release gates pass.
- Added append-only lifecycle states: draft, in review, approved, rejected,
  shadow, published, and retired. Every transition creates a new immutable
  revision rather than overwriting evidence.
- Added canonical SHA-256 definition and record digests plus HMAC signatures for
  every revision. All reads verify both digest and signature and fail closed on
  stored-content tampering.
- Added separate content read, write, review, publish, and admin permissions,
  fixed tenant binding, author ownership, and a four-eyes rule that forbids an
  author from reviewing their own content.
- Added deterministic rule test suites with exact expected alert event IDs,
  false-positive and false-negative evidence, duration, sanitized errors, and
  definition-digest binding. Edits invalidate all earlier validation,
  backtest, review, and shadow evidence.
- Added bounded backtest and shadow evaluation over up to 1,000 strict
  `AgentEvent` records. Only typed metadata and result IDs/counts are persisted;
  raw prompts, tool arguments, model output, attributes, and credentials are
  not copied into content evidence.
- Added fail-closed promotion: passing tests are required before review;
  independent approval is required before shadow; completed error-free shadow
  evidence is required before publication; and publication requires an exact
  acknowledgement of the current definition digest.
- Added publication into the immutable Module 9 live registry, automatic
  retirement of the prior published content record, increasing-version
  rollback that clones only previously published reviewed content, and duplicate
  preflight before the live registry is mutated.
- Added signed content-pack export, verification, tamper detection, import as
  non-active drafts, tenant isolation, version collision refusal, and pack
  history.
- Added content health with lifecycle counts, failed validation count, and live
  per-rule evaluation/match/error health.
- Added authenticated lifecycle APIs with exact request fields and generic
  errors. Until Module 24 supplies authenticated user identity, the local API
  uses explicit, distinct author, reviewer, and publisher service identities;
  it never trusts an actor name supplied by the browser.
- Added explicit local assembly through `AGENTSEC_CONTENT_DB` and a signing key
  of at least 32 bytes. Content startup requires the Module 9 detection store
  and exact tenant alignment.
- Added a loopback Rule Studio bridge. Browser validation/backtest/shadow
  requests select only known synthetic presets; the token-owning bridge expands
  them into strict events and does not expose the service bearer token.
- Added the live Rule Studio UI: signed library, declarative JSON editor,
  lifecycle gates, deterministic test/backtest/shadow proof, digest-aware
  publish, rollback, signed-pack export, health metrics, and append-only revision
  history. It has explicit empty/offline state and contains no fallback rules.
- Generated eight strict JSON Schemas for content principals, suites, results,
  records, pack entries, signed packs, and health.

## Security invariants

1. A draft, rejected, in-review, approved, or shadow rule cannot become active
   detection content without the exact allowed transition sequence.
2. Rule identity and version are immutable within one content record; an edit
   can change only the rule body and resets all derived evidence.
3. Validation evidence is accepted only for the current canonical definition
   digest and must have zero false positives, false negatives, or errors.
4. The author cannot review their own content. Browser-supplied identity is not
   used as an authorization decision.
5. Shadow publication requires error-free evidence and an exact digest
   acknowledgement; stale or forged acknowledgements fail closed.
6. Rollback is a new increasing version, not an overwrite, and may clone only a
   revision that was actually published.
7. Every durable content revision and pack is signed. Digest, signature,
   tenant, entry digest, and version collision checks precede import/use.
8. Rule logic remains Module 9 declarative data. Content APIs cannot introduce
   executable expressions, SQL, regex, Python, shell, arbitrary event fields,
   or unrestricted attributes.
9. Tests and backtests are bounded to 1,000 events. The browser-facing bridge is
   narrower and accepts at most 100 allowlisted presets.
10. Content and detection have separate SQLite transactions. Local publication
    orders all validations before live-registry mutation and documents that a
    production cross-store outbox/transaction belongs to Module 24 rather than
    claiming distributed atomicity.

## Interfaces

Read routes:

- `GET /v1/detection/content`
- `GET /v1/detection/content/health`
- `GET /v1/detection/content/packs`
- `GET /v1/detection/content/{content_id}`
- `GET /v1/detection/content/{content_id}/history`

Write routes:

- `POST /v1/detection/content` and `PUT /v1/detection/content/{content_id}`
- `POST .../{validate|backtest|submit|review|shadow|shadow-evaluate|publish|rollback}`
- `POST /v1/detection/content/packs/{export|import}`

The local bridge projects these under `/api/detection/content`. Content
creation/update accepts a strict definition. Evaluation accepts only preset
names and expands them server-side. Review, publish, and rollback payloads are
exact and bounded.

## Verification evidence

- `tests/test_detection_content.py`
  - full signed four-eyes test/backtest/review/shadow/publish lifecycle;
  - validation failure, evidence invalidation, rejection/rework, and stale
    digest refusal;
  - increasing-version rollback and prior-version retirement;
  - signed pack verification, tamper refusal, and import-as-draft;
  - tenant/permission/integrity boundaries and concurrent duplicate creation;
  - 400-event bounded backtest;
  - authenticated HTTP lifecycle including fixed distinct service identities;
  - explicit environment assembly and missing detection dependency refusal.
- `tests/test_live_ui_bridge.py` verifies local-only token custody, fixed content
  routes, preset-only event expansion, invalid preset/action refusal, and no
  forwarding of the browser's preset abstraction to the product service.
- UI source/render contracts verify the live Rule Studio surface, all release
  controls, explicit no-fallback state, responsive layout, and production
  server rendering.

## Deferred dependencies, not Module 10 completion shortcuts

- Module 11 supplies behavioral/anomaly content and risk tuning; Module 12
  correlates generated findings into incidents.
- Module 15 qualifies live semantic providers and governs their prompts/models.
- Module 20 expands the complete authenticated analyst experience beyond this
  delivered Rule Studio workspace.
- Module 22 expands simulation corpora and a general validation lab; the preset
  suite here is intentionally bounded content evidence.
- Module 24 replaces fixed local service identities and HMAC/SQLite adapters
  with SSO/RBAC, managed key custody/rotation, distributed publication outbox,
  platform audit, HA, backup, and DR.

## Acceptance closure

Nine focused content tests, eleven bridge tests, and the production UI
build/render/source contracts pass. The complete repository gate also passed:

- 230 Python tests and 5 TypeScript SDK tests;
- 2 analyst UI production build/render contract tests;
- 127 generated schema checks and 10 deterministic report checks;
- clean-package install reproduction, Python compilation, secret scan,
  dependency check, release audit, workflow/Codex demos, all evaluation modes,
  and component ablation.

The module audit reports 10/24 approved modules verified. Signed detection
content lifecycle, exact evidence gates, four-eyes local identities, Rule
Studio, rollback, packs, health, API, and bridge boundaries are complete.
Behavioral analytics, finding correlation, provider qualification, broader
validation labs, product-wide analyst identity, managed key custody,
distributed publication reconciliation, and platform operation remain
explicitly assigned to Modules 11, 12, 15, 20, 22, and 24.
