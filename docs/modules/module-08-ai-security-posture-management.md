# Module 8 — AI security posture management

Status: verified on 2026-07-24  
Posture contracts: 1.0.0

## Comparison baseline

Before this loop, the inventory assigned explainable component risk, but the
product had no posture-management boundary. It had no versioned checks,
repeatable configuration scans, durable posture findings, evidence-backed
remediation, accepted-risk lifecycle, historical scores, posture API, bridge
contract, or live analyst dashboard.

## Implemented remediation

- Added a tenant-scoped `PostureService` backed by transactional SQLite with
  WAL, full synchronization, busy timeout, audit records, durable scans,
  findings, checks, and exceptions.
- Added separate posture read, scan, and administration permissions.
- Added immutable versioned check definitions with canonical SHA-256 digests,
  natural numeric version ordering, history, and current-version uniqueness.
- Installed eight default checks for ownership, managed lifecycle, permission
  approval, effectful permission review, tool-schema pinning, prompt-version
  pinning, agent-policy binding, and excessive component risk.
- Mapped default content to OWASP LLM, NIST AI RMF, and MITRE ATLAS references.
- Evaluated the current Module 6 inventory deterministically, with bounded
  component/check selection and no request-selected tenant.
- Created stable deduplicated findings containing check version, component,
  risk, safe observed facts, inventory/configuration evidence references,
  remediation steps, mappings, first/last seen times, and resolution state.
- Re-scans reopen persistent failures and resolve corrected or retired
  components without deleting finding history.
- Calculated reproducible posture scores from passing and failing evaluations
  and stored scan trends with open and accepted-risk counts.
- Added time-bounded accepted-risk exceptions with exact owner, approver,
  reason, maximum 366-day expiry, automatic expiry/reopen, explicit revocation,
  and duplicate-active-exception refusal.
- Added authenticated summary, check, finding, detail, trend, scan, exception,
  and revocation service routes with exact fields and bounded filters.
- Added explicit environment assembly through `AGENTSEC_POSTURE_DB`; posture
  cannot start without a matching inventory tenant.
- Added a restricted loopback bridge for the same fixed posture operations; it
  keeps the product bearer token server-side and rejects arbitrary mutations.
- Added a live Posture analyst view with current metrics, scan control,
  remediation queue, finding dossier, observed evidence, framework mappings,
  remediation plan, score history, check coverage, accepted-risk creation and
  revocation, and honest loading/empty/offline states. It has no fixture data.
- Generated eleven strict JSON Schemas for public posture contracts.

## Security invariants

1. Tenant identity and posture permissions come from the configured principal,
   never from a scan, filter, finding, or exception request.
2. Search, inventory, graph, and posture principals in one application must
   have the same tenant or startup fails.
3. Check versions are immutable. A changed definition requires a strictly
   increasing version and supersedes rather than overwrites history.
4. Inventory observations are evaluated as evidence; they cannot grant
   governance authority or approve their own permissions.
5. Scan size, check selection, pages, offsets, trends, strings, and exception
   duration are bounded.
6. Finding IDs are tenant/check/component-derived and failures are upserted
   transactionally, so repeated scans do not create duplicate posture issues.
7. Exceptions cannot apply to resolved findings, cannot overlap, always expire,
   and can be revoked only by posture administration authority.
8. Expired or revoked acceptance reopens an unresolved finding; it never marks
   the underlying check as passing.
9. Finding evidence is metadata-only and excludes prompts, tool payloads,
   credentials, authorization headers, and unsafe inventory configuration.
10. The browser receives neither the service bearer token nor fabricated
    posture state when the service is empty or unavailable.

## Verification evidence

- `tests/test_posture.py`
  - immutable, durable, naturally ordered check versions;
  - explainable inventory scans, findings, summaries, and historical trends;
  - correction-driven resolution without history loss;
  - accepted-risk creation, duplicate refusal, expiry, reopen, and revocation;
  - tenant, permission, selection, pagination, and unsafe-input refusal;
  - authenticated API and exact-field rejection;
  - explicit environment dependency and default-content installation;
  - 400-component bounded performance and serialized concurrent writers.
- `tests/test_live_ui_bridge.py` verifies fixed posture forwarding, detail,
  scan, exception, and revocation while the bearer remains server-side.
- `ui/tests/source-contract.test.mjs` and
  `ui/tests/rendered-html.test.mjs` verify the production build and live-only
  posture analyst surface.
- Generated schema checks cover all eleven posture contracts.

## Deferred dependencies, not Module 8 completion shortcuts

- SQLite is the verified local product adapter; fleet scheduling and a
  distributed posture store are deployment-adapter concerns.
- Module 9 supplies richer event detections that can contribute posture and
  exposure context.
- Module 10 provides analyst-authored content lifecycle and promotion for
  detection rules; posture checks remain a distinct versioned content family.
- Module 12 correlates posture findings with detections and paths into
  first-class incidents.
- Module 17 supplies shared case assignment, comments, and remediation tasks.
- Modules 20 and 24 supply product-wide authenticated user experience, SSO,
  RBAC administration, managed key custody, platform audit, SLOs, and DR.

## Acceptance closure

Eight focused posture tests plus service, bridge, schema, and production UI
checks pass. The complete repository gate also passed:

- 210 Python tests and 5 TypeScript SDK tests;
- 2 analyst UI production build/render contract tests;
- 110 generated schema checks and 10 deterministic report checks;
- clean-package install reproduction, Python compilation, secret scan,
  dependency check, release audit, workflow/Codex demos, all evaluation modes,
  and component ablation.

The local posture-management boundary, authenticated API, accepted-risk
lifecycle, and live analyst workspace are complete. Distributed scheduling and
storage, richer detection content, multi-finding correlation, shared case
workflows, product-wide identity, and managed platform controls remain
explicitly assigned to deployment adapters and Modules 9, 12, 17, 20, and 24.
