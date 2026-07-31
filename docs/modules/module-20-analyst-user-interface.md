# Module 20 — Analyst User Interface

Status: verified  
UI contract: local-control-room-1.0.0  
Platform snapshot contract: agentsec.platform.snapshot/1.0

## Comparison baseline

Modules 5 through 19 had progressively added live product workspaces for
hunting, inventory, graph, posture, Rule Studio, behavior, incidents, cases,
notifications, model governance, and response. The interface was useful, but
the approved Module 20 outcome was not complete: there was no consolidated
source/service health plane, no evidence-bound reports workspace, no explicit
administration boundary, no fixed cross-product BFF receipt, and no complete
accessibility shell. Operational metrics could not be traced to one bounded
service/report snapshot, and the UI did not make the difference between
upstream service authentication and human identity assurance explicit.

The browser already used a loopback bridge for live data, but that bridge did
not have one fixed read-only platform endpoint. It could not combine health
from all product planes or bind displayed release/evaluation claims to the
committed repository reports. A general filesystem reader or proxy would have
closed the presentation gap by opening a larger security gap, so neither was
acceptable.

## Implemented remediation

- Added `GET /api/platform`, a fixed origin-restricted BFF projection. The BFF
  authenticates upstream with its server-held bearer and never returns that
  bearer, an authorization header, an upstream URL, or a credential value to
  the browser.
- Added 16 fixed health probes spanning incidents, telemetry source and queue,
  inventory, graph, posture, detection, content, behavior, correlation, cases,
  notifications, response, enrichment, analyst, and model-gateway planes.
  Each probe becomes either `available` with bounded scalar/count metrics or
  `unavailable` with a normalized safe error code; missing planes are never
  replaced with sample health.
- Added a strict metric reducer. Nested objects become counts and keys shaped
  like secrets, credentials, tokens, endpoints, URLs, or headers are excluded
  before the browser projection is formed.
- Added a fixed report allowlist for exactly the committed release audit,
  evaluation manifest, and 24-module catalog. The browser cannot submit a file
  name, path, command, report type, or repository location. Parsed records are
  size bounded and returned with exact SHA-256 commitments.
- Added a live Reports workspace with committed release criteria, discovered
  test count, production-readiness non-claim, deferred production controls,
  exact report digest, evaluation artifact record/file digests, module
  completion evidence, explicit offline state, refresh, and sanitized snapshot
  download.
- Added a read-only Administration workspace with real source/model/workflow
  health, service availability, bounded metrics, the BFF trust receipt, module
  completion, and explicit administrative/non-production boundaries.
- Added the platform snapshot to Overview so evaluation rates and release state
  come from the same committed evidence source. Unavailable evidence renders an
  em dash or an explicit gap; it is not reconstructed from browser fixtures.
- Completed the product navigation for all live module workspaces: Overview,
  Incidents, Cases, Escalations, Response, Inventory, Security Graph, Posture,
  Threat Hunting, Risk Analytics, Rule Studio, Policies, Evaluations,
  Integrations, Reports, and Administration.
- Added a keyboard skip link, focusable main landmark, current-page semantics,
  visible focus treatment, polite live regions for operational state, semantic
  captions/column and row headers for report tables, reduced-motion behavior,
  mobile breakpoints, and non-interactive operator identity presentation.
- Made UI lint a zero-warning gate with the Next.js core-web-vitals and
  TypeScript rule sets intact. External-service loading is scheduled from
  effects with cancellation, and render-time SLA/expiry labels use recorded
  service timestamps; no lint rule is disabled to admit client-side security
  decisions.

## Product flow

```text
browser control room
        |
        | fixed /api/* routes, loopback origin only
        v
token-owning BFF -------------------- browser never receives bearer
        |
        +--> fixed product health probes --> bounded safe metrics
        |
        +--> three fixed repository reports --> parsed values + SHA-256
        |
        v
Reports / Administration / Overview
        |
        +--> live value
        +--> explicit unavailable state
        `--> never a fixture fallback
```

## Security and truthfulness invariants

1. The platform endpoint is fixed and read-only; query parameters, alternate
   paths, traversal, and arbitrary report selection are rejected.
2. The BFF owns upstream authentication. Browser state receives neither the
   bearer nor a credential-shaped configuration value.
3. Upstream service authentication does not imply a verified human. The trust
   receipt records `human_identity_verified=false` and assigns SSO, MFA,
   tenant RBAC, access review, and non-repudiation to Module 24.
4. Every service is probed independently. A partial outage remains visible and
   cannot be converted into an all-healthy result.
5. Release criteria, test counts, evaluation artifacts, and module progress are
   read from committed machine-readable evidence with exact file digests.
6. The UI cannot mark a release criterion passed, change a module status, run a
   report, select a repository path, or create operational health.
7. A missing platform snapshot removes derived metrics rather than preserving a
   stale demonstration value.
8. Existing governed mutation workspaces keep their service-side fixed actors,
   strict bodies, versions, approvals, and audit. Administration adds no new
   mutation authority.

## Data and interface contract

`PlatformSnapshot` contains a schema version, source label, observation time,
BFF trust receipt, 16 service states with bounded metrics, parsed release and
evaluation summaries with file hashes, and the ordered 24-module catalog with
acceptance-record paths. It excludes raw prompts, tool arguments/results,
model payloads, evidence bodies, arbitrary attributes, service URLs, headers,
tokens, secrets, credentials, filesystem paths selected by a caller, and
provider response bodies.

The three repository paths are constants in `tools/live_ui_bridge.py` and are
resolved under the repository root. The fixed loader rejects unknown names,
non-object JSON, and oversized records. Service results pass through the safe
metric reducer; exception text is not returned as an operational metric.

## Verification evidence

The bridge suite proves the fixed authenticated snapshot, all 16 probes,
bounded report hashes, 24-module order/status, credential-shaped field
exclusion, query rejection, and unknown-report rejection. The UI source and
render contracts prove every workspace, live platform fetch, offline/no-fallback
behavior, report download, BFF boundary copy, exact digest surfaces, semantic
tables, skip navigation, current-page state, live regions, focus visibility,
and responsive/reduced-motion controls.

Focused closure passes 19 bridge tests, the zero-warning ESLint gate, the
production Vinext build, rendered HTML test, source contract, module catalog,
and repository whitespace check. The full repository gate passes 338 Python
tests, 5 TypeScript SDK tests, 261 generated-schema checks, 10 deterministic
evaluation records, clean-install reproduction, compilation, secret scan,
dependency validation, release audit, workflow and Codex demonstrations, all
eight evaluation modes, and the control ablation.

## Honest limitations and follow-on ownership

- This is an authenticated upstream BFF, not human authentication. The current
  local shell has no SSO, MFA, tenant-aware user session, per-human RBAC,
  privileged step-up, access review, or non-repudiation; Module 24 owns those.
- The control room is a local research UI. It is not a production multi-tenant
  web deployment, CDN/WAF design, managed session service, or SOC availability
  tier.
- Snapshot refresh is request based. It is not a metrics warehouse, distributed
  telemetry stream, long-term SLO system, or alert-on-health engine.
- The three reports are repository files under the local BFF trust boundary;
  their SHA-256 values are not managed signatures or independent timestamps.
- Accessibility is enforced by semantic/source/render contracts and keyboard/
  CSS behavior, but the repository does not claim certification against a
  formal WCAG conformance audit or assistive-technology test matrix.
- Service health is bounded product readiness, not proof that an external
  provider, connector, or analyst action succeeded. External API/SIEM delivery
  belongs to Module 21 and production platform assurance belongs to Module 24.

## Acceptance closure

Module 20 is verified. Implementation and focused verification passed first;
the pre-promotion audit reported 19/24. The complete `make verify` gate and
post-promotion catalog audit then passed with 20/24 approved modules verified.
No external provider or AWS resource was contacted.
