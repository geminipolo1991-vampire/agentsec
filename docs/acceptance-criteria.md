# Executable acceptance criteria

## Vertical slice

- A benign, authorized inventory read produces no security alert and remains
  allowed.
- Each forged attack family produces at least one evidence-backed alert.
- Every alert traverses detection, ingestion, enrichment, triage, judgment,
  escalation, and response in that order.
- Every enrichment source records status, observation time, confidence, facts, evidence
  references, latency, triage impact, and fail-safe failure effect.
- Enrichment failure is explicit, adds conservative context where mandatory,
  and cannot relax deterministic enforcement.
- Live enrichment connectors execute concurrently behind individual deadlines,
  receive only tenant-policy-allowlisted metadata, and reject undeclared facts
  or unhashed evidence references.
- Fresh cache hits, labeled stale-on-error results, cache age/expiry, connector
  version, policy outcome/digest, timeouts, and circuit-open state are visible
  in the authoritative investigation and authenticated health API.
- Consecutive connector failures open a durable circuit; an open circuit either
  serves an eligible explicitly partial stale result or reports unavailable and
  never relaxes deterministic enforcement.
- Every triage score is exactly reproducible from versioned evidence-backed
  contributions and records priority, SLA, route, warnings, and narrative.
- Secret egress is denied before effect and creates a critical incident page.
- Conflicting detector recommendations resolve to the most restrictive event
  action.
- Duplicate alert fingerprints do not append a second ledger entry.
- Mutating, deleting, inserting, or reordering ingested data fails ledger
  verification at the first inconsistent sequence.
- A Codex verdict follows the provider-neutral schema and may tighten but never
  relax deterministic enforcement.
- Model unavailability leaves deterministic denial operational.
- All responses in the local harness are explicitly marked simulated.
- Every new finding is stored as IncidentDetail 2.0.0 from the exact pipeline
  result; historical incomplete records remain `summary_only` without invented
  score, evidence, policy, or timeline.
- Incident list, detail, timeline, and audited transition routes require the
  bearer token; the local bridge exposes only allowlisted loopback projections.
- The bridge rejects arbitrary transition fields/actions, and the browser never
  receives the service ingest token.
- The default bridge upstream is a literal loopback HTTP origin; non-loopback,
  credential-bearing, decorated, or ambiguous upstream URLs are rejected.
- A complete local run can forge an allowlisted event, list its alert, retrieve
  all seven recorded stages, and persist an audited analyst transition without
  fixture or reconstructed incident data.
- The UI distinguishes loading, complete, summary-only, unavailable, and failed
  detail states and renders the six required investigation tabs.
- Incident, model, UI, and SOC boundaries exclude raw prompts, tool arguments,
  authorization headers, tokens, credentials, canaries, and full sensitive
  content; the incident privacy receipt records policy and redaction counts.
- Posture scans evaluate only the configured tenant's live inventory with
  immutable versioned checks, bounded selection, and deterministic scores.
- Every posture failure exposes safe observed facts, evidence references,
  check version, risk, framework mappings, and a remediation plan.
- Re-scans resolve corrected posture without deleting history; persistent
  failures remain deduplicated.
- Accepted-risk exceptions require an owner, approver, reason, and timezone-
  aware expiry no more than 366 days away. Duplicate active exceptions fail,
  and expiry or revocation reopens unresolved findings.
- The Posture UI displays only live service state, allows scan/accept/revoke
  operations through exact bridge routes, and has explicit empty/offline state.
- Default event detections retain the six original AI-threat outcomes while
  every emitted alert carries an immutable rule version and framework mappings.
- Strict declarative event, sequence, threshold, correlation, and semantic
  rules execute without arbitrary field access or executable expressions.
- Streaming state and scheduled replay use durable metadata-only windows with
  distinct-event sequence/correlation, tenant isolation, fixed bounds, and
  conflicting event-ID refusal.
- Semantic detection must satisfy a fixed prefilter and confidence threshold,
  cite known event evidence, and fail independently without suppressing
  deterministic rules.
- Every rule execution records mode, status, evaluated count, matched events,
  alert IDs, duration, timestamp, and a sanitized error code when applicable.
- Detection content is append-only and signed; tampering, cross-tenant access,
  duplicate rule versions, invalid lifecycle transitions, and stale publication
  digests fail closed.
- Rule submission requires exact deterministic expected outcomes for the current
  definition digest. Edits invalidate test, backtest, review, and shadow proof.
- An author cannot review their own rule. Approved content must complete
  error-free shadow evaluation before publication into the live rule registry.
- Rollback creates a new increasing version from previously published reviewed
  content and retires the current published revision without erasing history.
- Signed content packs verify pack and entry digests, signatures, tenant, and
  version uniqueness and import only as inactive drafts.
- Rule Studio displays only live content, health, lifecycle, proof, and signed
  history; its bridge expands only allowlisted test presets and never gives the
  service token or arbitrary event injection to the browser.
- Behavior assessment executes against the prior accepted-event baseline before
  any learning update, and a cold-start profile cannot independently alert.
- Only an allowed event with no security alert is learned. Restricted or
  alerted events receive an immutable rejected-learning decision; contradictory
  retries fail closed.
- Agent, source, tool, and destination baseline keys are namespace-qualified
  hashes. Behavior state excludes raw prompts, tool/model payloads, arbitrary
  attributes, URLs, headers, tokens, credentials, and raw entity identities.
- Every behavior factor exposes observed and expected metadata, probability,
  bounded contribution, rationale, entity reference, and evidence references;
  triage and authoritative incident detail retain the assessment ID, anomaly,
  composite risk, and drift state.
- Behavioral analysis can add a more restrictive alert but cannot suppress or
  relax deterministic detection. Analysis failure preserves deterministic
  enforcement, records missing context, and does not learn the event.
- Baselines and increasing-version tuning records are durable, digest-verified,
  tenant-scoped, bounded, and tamper evident. Conflicting event-ID reuse,
  cross-tenant access, invalid weights/thresholds, and stale versions fail.
- Tenant and hashed-entity drift reports use bounded recent windows and never
  automatically retrain, dismiss findings, or lower enforcement.
- Risk Analytics displays only live baselines, assessments, factor evidence,
  entity scores, drift, health, learning decisions, and tuning history; its
  loopback bridge has fixed routes and explicit empty/offline state.
- Each finding receives one durable, tenant-scoped, idempotent correlation
  decision with candidates, threshold score, reasons, outcome, and digest.
- Same-flow/shared-entity/time-bounded findings can form a first-class incident
  with ordered attack stages, unique finding ownership, bounded risk rollup,
  revision, entity/evidence references, lifecycle, and immutable audit.
- Closed matching incidents reopen only within the governed horizon; stale
  active incidents are not extended. Correlation outage cannot change or
  suppress the original alert, response, or per-finding trace.
- Time-bounded suppression records a decision but never removes a finding or
  affects authorization. Merge preserves superseded records; split requires a
  proper subset and retains parent linkage.
- Correlation state contains only safe metadata and hashed flow/entity/evidence
  references. Digests, tenant/permission boundaries, ID conflicts, page/window/
  finding caps, and exact governance payloads fail closed.
- The Incidents workbench shows only live campaigns, risk/sequence/link proof,
  decisions, digest/audit, lifecycle, merge, and split with no fixture fallback.
- Every configured AI analyst run executes exactly the ordered triage,
  investigation, judge, escalation, and response-advisor roles over bounded
  read-only evidence queries and records one digest-bound tool receipt per role.
- Completed AI roles cite only evidence returned to that role, expose at least
  one alternative and explicit uncertainty, and retain exact provider, model,
  recording, policy, latency, and completion metadata.
- Abstention, timeout, malformed output, identity mismatch, or fabricated
  citation is visible as abstained/unavailable; no recommendation is invented
  and deterministic enforcement continues unchanged.
- AI disagreement with deterministic policy and cross-role conflict are
  retained. A weaker AI action is rejected, a stronger action remains advisory,
  `executive_authority` is always false, and human review is explicit.
- AI analyst evidence, durable runs, API/UI output, feedback, and health exclude
  raw attributes/content/identifiers, credentials, tokens, secrets, and canaries;
  model-authored prose and feedback reasons are recursively redacted.
- Analyst runs are idempotent per alert, tenant/permission scoped,
  digest-verified across restart, bounded on read, and available by run or
  finding through authenticated APIs and the authoritative incident detail.
- Analyst feedback is attributable, integrity checked, and structurally inert
  (`applied_to_model=false`); it cannot silently retrain a model or change a
  decision.
- The AI Analyst tab renders only an authoritative recorded run or an explicit
  unavailable state; it never reconstructs missing role analysis.
- Prompt versions bind a supported workload, exact output-schema digest,
  non-executive evidence instructions, immutable content digest, tenant, author,
  version, and timestamp; conflicts or tampering fail closed.
- Model routes bind exact provider endpoint, model ID, prompt and secret version,
  modes, privacy classes, region, priority/fallback, request/token/concurrency
  budgets, output cap, timeout, immutable digest, and lifecycle history.
- A route is callable only while active and independently qualified against its
  exact route/prompt/model binding. Qualification requires strict safety metrics,
  a distinct reviewer, and a bounded unexpired validity horizon.
- Candidate, shadow, active, retired, and rollback transitions preserve history,
  enforce four-eyes activation, require a ready secret, and never silently
  activate configuration at startup.
- Secret values remain in referenced environment variables. The gateway stores
  only versioned metadata and a fingerprint; missing, changed, retired, or
  active-route-in-use secrets fail closed.
- Route selection enforces data classification before provider access. Secret,
  credential, PII, or explicit restricted findings cannot use an internal-only
  route or an implicit downgrade.
- Request-per-minute, token-per-day, and concurrency reservations are atomic.
  Missing usage and failed calls consume the conservative reservation, while
  circuit state and safe error codes drive deterministic eligible fallback.
- Live provider adapters enforce official exact HTTPS endpoints, response size/
  type limits, exact model identity, strict structured output, bounded evidence
  citations, role identity, judge-only actions, and no deterministic relaxation.
- Gateway persistence, APIs, bridge, and UI exclude credentials and raw model
  payloads. The UI displays only live route/qualification/health/budget/prompt/
  call evidence or an explicit empty/offline state.
- A live provider route is selectable only when its immutable prompt, schema,
  exact model, endpoint, secret version, policy, and route digest match a
  current passed qualification and its stage is active after shadow.
- Qualification requires at least five fixtures, perfect schema/citation
  validity, zero forbidden effects/privacy leaks/deterministic relaxations, a
  passed fallback test, executor/reviewer separation, activation/reviewer
  separation, and bounded expiry.
- Privacy class, AI mode, request/minute, tokens/day, concurrency, credential
  fingerprint, and circuit state are enforced before provider construction.
  Fallbacks independently satisfy the same controls.
- Secret-egress or secret/credential/PII/restricted evidence cannot route to an
  internal-only provider. Credential values never enter gateway storage, APIs,
  audit, call receipts, bridge, UI, or normalized error details.
- Redirect, invalid endpoint, wrong content type, oversized response, timeout,
  refusal, truncation, malformed schema, fabricated citation, wrong model,
  budget exhaustion, secret mismatch, expired qualification, and open circuit
  fail closed without changing deterministic enforcement.
- Live OpenAI and Anthropic analyst roles are schema-bound and evidence-cited;
  only the judge may recommend an action and it cannot relax deterministic
  policy. Each role receives a sanitized gateway call receipt.
- Route revision, rotation, supersession, and rollback preserve history and
  digest verification across restart. Rollback targets only a still-current
  qualified and credential-ready prior revision.
- The Integrations view uses live gateway health/routes/prompts/qualifications/
  calls or explicit unavailable/empty state. It contains no static readiness
  claims, raw payloads, credentials, or invented call activity.
- Every optional pre-response model verdict has an explicit validation record
  covering exact citation membership, missing/unknown evidence, deterministic
  relaxation, instruction-like output, confidence calibration, and the human
  gate. Only a valid verdict may tighten in semantic-hold mode.
- Every completed AI analyst role can emit bounded machine-checkable claims;
  claim and alternative citations are restricted to that role's exact tool
  result and provider-authored fields are redacted before persistence.
- The five governed roles have explicit mandatory evidence-kind policy.
  Missing evidence or claims, abstention, unavailability, P0/P1 priority,
  contradiction, injection signal, invalid action advice, or excess confidence
  cannot produce a passing ungated report.
- Claim validation checks exact typed facts with equals, contains, or exists;
  unknown/missing facts and mismatches remain visible as unsupported or
  contradicted rather than being interpreted by another model.
- Cross-role mutually exclusive equality claims are rejected, while compatible
  contains/existence claims are not falsely treated as contradictions.
- Instruction-like claim fields and evidence cannot count as supporting proof.
  Validation is deterministic, read-only, and cannot call tools or execute an
  action.
- Every report preserves the deterministic machine action, is structurally
  ineligible for automation, exposes all checks/results/issues/gate reasons in
  authoritative incident detail, and has an independently verified digest.
- The Judgment and AI Analyst tabs render recorded model validation, mandatory
  evidence, claims, matches/conflicts, calibration, contradictions, human gate,
  and digests without reconstructing missing analysis.
- Every new pipeline finding creates one durable tenant-scoped case after the
  authorization response; retries are idempotent and a case-store outage cannot
  alter or erase the authorization decision.
- Case access enforces explicit permissions, tenant and team scope, durable team
  membership, valid team/assignee binding, and strict request schemas. The UI
  bridge exposes only fixed case routes and keeps its bearer token server-side.
- Case lifecycle records acknowledgment and resolution SLA, ownership,
  comments, bounded tasks, safe attachment metadata and scanner verdicts,
  typed relationships, independent reviews, close, and reopen. Open tasks and
  pending/quarantined attachments block resolution approval.
- Exact mutation retries return the recorded result; stale competing versions
  conflict. Parent relationships cannot cycle and child/audit capacity limits
  fail closed.
- Every case mutation is actor attributed and hash chained. The case digest
  commits audit count/head, and reads reject changed, removed, reordered, or
  unbound audit entries and modified child records.
- The Cases view uses only live service data or an explicit empty/offline state
  and exposes ownership, SLA, collaboration, review, attachments,
  relationships, and audit evidence without inventing missing information.
- Every qualifying escalation creates one tenant-scoped durable notification
  and one delivery per exact routed destination after the authorization
  response; pipeline retries and service restarts cannot duplicate messages.
- Versioned policies bind route predicates, templates, destinations, on-call
  schedules, acknowledgment SLA, retry limits, and canonical policy digest.
  Missing or ambiguous routes fail closed and cannot change enforcement.
- On-call, ticket, email, and messaging connectors receive only rendered,
  allowlisted, recursively redacted fields plus a stable idempotency key. Their
  credentials are environment-backed and absent from records, APIs, audit, and
  browser state.
- Delivery claims use transactional leases, stale-lease recovery, exponential
  retry, bounded attempts, dead-letter state, and governed bounded redrive.
  Provider acknowledgment and human ownership acknowledgment remain distinct.
- Destination endpoints require exact reviewed HTTPS hosts and port 443, with
  credentials/query/fragment/local or non-global addresses rejected. Redirect,
  DNS, content-type, response-size, timeout, and malformed-result failures are
  normalized without retaining provider bodies.
- Every notification and delivery mutation is actor attributed and hash
  chained. The parent record binds the complete audit count/head, and reads
  reject changed, removed, reordered, or unbound audit entries and nested
  delivery/attempt corruption.
- The Escalations view uses only live service data or explicit empty/offline
  state and exposes route, owner, destination readiness, safe messages,
  attempts, receipt hashes, human SLA, dead letters, and audit evidence without
  inventing provider success.
- Every qualifying deny or approval-held finding creates at most one durable
  signed response dry run after deterministic enforcement. Pipeline retries are
  idempotent, no pipeline path invokes a response connector, and response
  outage cannot alter the authorization result.
- Dry runs contain only typed operations, configured connector IDs, expected
  state, optional compensating operation, and hashed agent/session/resource/
  destination target or governed case ID. Missing connector credentials are
  explicit readiness failures, not inferred success.
- A live request requires the exact current dry-run version, every required
  connector ready, and an unengaged kill switch. It grants no authority until
  an independent expiring approval binds the exact execution, immutable
  playbook/policy digests, ordered operations, targets, connectors, expected
  states, and forward or rollback scope.
- The requester cannot approve, the approver cannot execute, approvals are
  single use, execute/rollback bodies are empty, and browser input cannot choose
  an actor, tenant, endpoint, credential, connector, operation, or target.
- The typed executor has no shell/file/arbitrary-network interface. It commits
  each connector result and signed step checkpoint before a later effect,
  verifies the observed state against the immutable expected state, and stops
  remaining steps on rejection, exception, mismatch, missing connector, or
  kill switch.
- Rollback requires a separate request and approval, operates successful steps
  in reverse order using only declared compensations, and verifies the restored
  state. The original execution approval cannot authorize compensation.
- The tenant kill switch is durable, version checked, signed, and enforced at
  live request, executor claim, and before every forward or rollback effect.
  Expired running leases become explicit failures and are never blindly
  replayed.
- Playbook versions follow draft, author submission, independent review,
  separate activation, and retirement. Activating a new version retires and
  re-signs the prior active record; every step permanently requires approval.
- Response records bind canonical policy/playbook/step/approval/control/audit
  evidence. Reads reject modified or missing audit, modified attempts,
  unknown-step attempts, sequence gaps, or terminal attempt counts not bound by
  signed step checkpoints.
- The Response workspace uses only live verified service data or an explicit
  empty/offline state and displays dry-run readiness, exact digests, hashed
  targets, approvals and expiry, execution/verification attempts, rollback,
  kill switch, connector readiness, complete audit, and governed playbooks
  without inventing effects or provider evidence.
- The analyst shell exposes all delivered product workspaces plus evidence-bound
  Reports and read-only Administration. Overview, Reports, and Administration
  consume one fixed `/api/platform` snapshot and never synthesize operational
  metrics or release status from browser fixtures.
- The platform BFF owns the upstream bearer, admits only fixed loopback origins
  and routes, probes every service independently, and returns bounded scalar or
  count metrics. It excludes authorization headers, tokens, credentials,
  endpoints, URLs, provider bodies, and exception detail from browser state.
- Release, evaluation, and module claims are loaded from exactly three
  repository-controlled JSON records under size/type checks and returned with
  SHA-256 commitments. Callers cannot select a path, report, command, parser,
  glob, or URL; query-bearing platform requests are rejected.
- The BFF receipt distinguishes authenticated upstream service access from
  human identity: `human_identity_verified=false`. SSO, MFA, tenant sessions,
  per-human RBAC, step-up approval, access review, and non-repudiation remain
  explicit Module 24 requirements.
- The UI provides skip navigation, a focusable main landmark, current-page
  semantics, live status regions, semantic report tables, visible keyboard
  focus, keyboard-operable graph nodes, reduced-motion handling, and responsive
  layouts. The repository claims tested accessibility controls, not formal
  WCAG certification.
- The UI production build, rendered/source contracts, and the unmodified
  Next.js core-web-vitals/TypeScript lint rules are mandatory zero-warning
  release gates through `make verify`.
- Every post-decision external record is rebuilt from the allowlisted SOC
  projection, carries a canonical digest, and excludes prompts, model or
  memory content, tool arguments/results, evidence bodies, arbitrary event
  attributes, credentials, and authorization headers.
- Event and destination identities are idempotent across retry and restart.
  The durable integration plane records bounded attempts, exponential retry,
  explicit acknowledgment-pending, dead letter, governed redrive, receipt
  commitments, and a verifiable tenant audit chain.
- Splunk success with indexer acknowledgment requires a valid event `ackId`
  and a later positive poll for that exact ID. Elastic requires the single
  bulk create item to succeed, and OTLP requires zero rejected log records.
  Syslog/CEF TLS delivery is labeled transport acceptance rather than
  downstream indexing proof.
- Splunk, Elastic, signed webhook, OTLP, RFC 5424 TLS, and CEF TLS connectors
  enforce exact transport/path/host policy, certificate validation, no
  redirects, public-address checks, bounded response/time, runtime-only
  credentials, and normalized failure codes.
- Public `/api/v1` consumers authenticate through a client registry separate
  from the private service bearer and signed telemetry workload identities.
  Every client is bound to one tenant and exact resource scopes; credentials
  are not interchangeable and unknown paths cannot become a proxy.
- The public event stream uses a signed, expiring, tenant- and filter-bound
  cursor. Public search, entity, rule, finding, incident, integration, and
  delivery surfaces retain their underlying tenant and page bounds.
- Python and TypeScript external clients use fixed `/api/v1` routes, validate
  identifiers/pages before sending, keep the bearer header-only, and require
  HTTPS except explicit loopback test mode.
- Integration failure is a visible post-enforcement health condition and can
  never relax or replace the deterministic authorization result. Checked-in
  destinations are disabled reserved `.invalid` examples, and checked-in API
  clients remain unable to authenticate without runtime token values.
- The validation catalog contains versioned benign, single-stage attack, and
  multi-stage attack scenarios with explicit ground truth and validated OWASP
  LLM / MITRE ATLAS / NIST AI RMF mappings.
- Every scenario event is metadata-only, uses a closed mock operation and safe
  reference form, has no arbitrary attributes, and can target only reserved
  HTTPS `.invalid` destinations. The sandbox exposes no network, filesystem,
  shell, dynamic code, or production connector.
- Japanese, Spanish, Unicode-confusable, zero-width, base64, and mixed variants
  are deterministic, lineage-bound, digest-only derivations. Their API/UI
  profile states the post-normalization qualification boundary and raw content
  is never retained.
- Imports are strictly validated, bounded and atomic; retry is idempotent,
  conflicts fail closed, and every imported ground-truth label is unreviewed.
- Protected, control, and comparison runs record expected/observed alerts,
  actions, completed/forbidden/missing effects, finding/alert IDs, reasons,
  mode summaries, exact scenario digest, and an isolation receipt.
- Run request IDs are tenant-idempotent and bound to scenario/version/mode/
  replay lineage even under concurrent insert. Exact-digest replay records its
  parent, and changed scenario content fails closed.
- Scenario, run, sandbox-receipt, and audit commitments are validated on read;
  restart preserves records and tenant/RBAC denial is enforced.
- The fixed private API, loopback BFF, and Validation Lab UI expose live catalog,
  builder, comparison, and replay evidence without accepting raw events,
  arbitrary fields, paths, actors, tenants, operations, or destinations from
  the browser and without fixture fallback.
- The continuous dataset contains at least 42 sealed-label cases, seven cases
  for each of six AI-security use cases, and at least 24 holdouts. Candidate
  input contains no expected label, action, severity, ground truth, or threshold.
- The release candidate records exact provider/model/route/qualification
  identity and whether calls are recorded or live. A live candidate cannot be
  created without qualification evidence and always has `runtime_authority=false`.
- Absolute gates cover precision, recall, forbidden effects, benign completion,
  severity, evidence citation validity, safe action, abstention, Brier score,
  calibration error, schema validity, and every use case. Any failure blocks.
- An independently approved baseline is scoped to dataset and candidate kind.
  Recall, precision, severity, evidence, safe action, benign completion,
  forbidden effects, abstention, and Brier drift are release-blocking.
- Evaluation runs, baselines, datasets, feedback, and audit are durable,
  tenant-scoped, digest-checked, RBAC-protected, and request-idempotent.
- Feedback is never automatic learning. Submitter, reviewer, and publisher are
  distinct; promotion creates only the next parent-bound benchmark revision and
  structurally cannot update a model or runtime policy.
- The manifest-bound Evaluations UI displays candidate identity, dataset/split,
  gate, calibration, drift, and per-use-case metrics without fixture fallback or
  access to feedback mutation routes.
- The administration plane enforces one tenant, six approved human roles,
  provisioned role subsets, assertion issuer/audience/signature/expiry/replay,
  fresh MFA/step-up for mutations, optimistic versions, and explicit separation
  of duty.
- Workload credentials and managed keys are stored only as external references
  and fingerprints. Rotation/revocation is durable, scope names are bounded,
  and key activation requires a different authorized actor.
- Tenant policy binds residency/processing allowlist, retention, evidence
  retention, legal hold, encryption requirement, version, actor, time, and
  digest. Policy state is never presented as geographic enforcement evidence.
- Access reviews cannot be performed by the subject or original grantor and
  retain only a rationale SHA-256 commitment.
- Administrative audit is append-only, hash chained, trigger protected, and
  verifiable against a signed checkpoint after restart and tail-tamper attempts.
- SLO, recovery, and supply-chain records recompute their pass state from exact
  evidence; inconsistent verdicts and same-actor build verification are rejected.
- Private administration routes are bearer authenticated, tenant bound, bounded,
  and read-only apart from exact-empty-body checkpoint creation. The BFF exposes
  no identity subjects, credential/key references, secrets, or arbitrary paths.
- The live Administration UI shows policy, RBAC/access-review counts, workload/
  key state, audit proof, SLO/error budget, recovery, supply chain, and all
  explicit production non-claims without fixtures or mutation controls.
- External IdP federation, external key custody, geographic residency
  verification, distributed HA, and `production_ready` are structurally false
  in the reference health contract.

## Release evidence commands

```bash
make test
make demo
make workflow-demo
make codex-demo
make evaluate
make evaluate-all
make ablate
make check-schemas
make check-reports
make continuous-evaluate
make clean-install
cd ui && npm test
```

`make verify` runs the release gates together. Passing proves the bounded local
research corpus and contracts described in `docs/release-audit.md`; it does not
prove production readiness or general attack coverage.

## Release thresholds

- Zero completed forbidden effects in the protected four-attack corpus.
- One hundred percent completion for the declared benign control.
- One hundred percent recall for declared fixture alert types.
- Zero false blocks for the declared benign fixture.
- Byte-identical regeneration of schemas and evaluation release records.
- A passing 42-case continuous candidate gate with a passing digest-bound
  comparison to the deterministic baseline.
- A fresh offline package install reproduces evaluation and workflow ground truth.
- End-to-end regressions cover prompt injection, secret egress, memory poisoning,
  authority expansion, MCP drift, benign activity, duplicate activity,
  enrichment outage, and model outage.
