# Limitations and bypasses

This release satisfies the local research-PoC definition of done. It is not a
production security boundary and is not authorized to protect real workloads.

## Enforcement and observation

- Only the included adapters and mock tools are forced through the controlled
  gateway. An uninstrumented SDK, direct network client, subprocess, or alternate
  credential path can bypass it. Production must enforce egress and tool access
  independently of agent code.
- The independent observer reconciles supplied SDK and gateway records; it is not
  a network sensor and cannot prove that an omitted side effect never happened.
- Detection now supports durable versioned event, sequence, threshold,
  correlation, and provider-neutral semantic rules over metadata-only windows.
  It still does not implement token-level taint, semantic intent proof, full URL
  canonicalization, or covert-channel detection.
- Content validation proves only the supplied deterministic event suite and
  bounded backtest/shadow sample; it does not prove general detection accuracy,
  future-data performance, or absence of adversarial evasion.
- Behavioral analytics learns simple metadata frequencies per hashed entity. It
  is not sequence embedding, graph ML, causal proof, production-scale UEBA, or
  evidence that a rare event is malicious. Cold start, baseline poisoning,
  seasonal change, coordinated low-and-slow behavior, shared identities, and
  adversarial mimicry remain risks despite evaluate-before-learn and
  allowed/no-alert learning eligibility.
- Correlation uses deterministic time/flow/entity/stage heuristics, not causal
  proof. Shared infrastructure can over-group and adversarially varied metadata
  can under-group. Merge, split, suppression, and closure require qualified
  analyst review; current local identities are service/demo identities.
- Live enrichment is bounded and fail-explicit, but its facts are only as
  trustworthy and current as the configured external source. The worker timeout
  cannot forcibly terminate arbitrary third-party Python code already running;
  connector transports must enforce their own I/O deadlines and be safe to
  abandon. SQLite cache/health is single-node, cached metadata has no managed
  signature or external transparency anchor, and stale fallback can preserve an
  obsolete fact until its declared horizon. Production requires connector
  qualification, source authentication/attestation, distributed cache/state,
  secret rotation, egress controls, metrics export, and externally managed
  audit. Module 24 records reference policy and assurance but does not supply
  those deployment services.
- Live enrichment trusts the configured upstream to interpret hashed metadata
  and return truthful metadata facts; a valid schema is not proof that the fact
  is correct. The runtime provides exact HTTPS endpoints, normal TLS validation,
  deadlines, response limits, cache age, stale labels, and circuit breakers,
  but it does not provide private-link routing, DNS pinning, connector mTLS,
  upstream attestation, or global rate/budget coordination. Only administrator-
  reviewed endpoints should be configured, and high-impact facts still require
  evidence validation and human gates in Modules 16 and 24.
- Pipeline effect summaries and evaluation containment remain simulated. Module
  19 adds a separate opt-in response gateway that can contact a reviewed
  connector only after explicit credentials and independent approval; the
  checked-in `.invalid` endpoints and empty credentials cannot touch hosts,
  identities, networks, or tickets.
- Notification delivery uses typed provider-neutral HTTPS gateway contracts for
  on-call, ticket, email, and messaging channels. The contracts, endpoint
  restrictions, retries, DLQ, acknowledgment, and fake-transport tests are
  implemented, but no PagerDuty, ServiceNow, Slack/Teams, SES, or other vendor
  adapter is certified. The checked-in endpoints are `.invalid`; real gateway
  compatibility, rate limits, signatures, quotas, and account behavior require
  separate qualification.
- Outbox processing is explicitly invoked through the private API in this local
  product. There is no production scheduler/worker fleet. Provider
  acknowledgment currently enters through the private bearer-protected API,
  not a vendor-specific signed callback verifier. Real callback authentication,
  replay defense, asynchronous scheduling, and operational SLOs remain required.
- Response execution uses typed provider-neutral HTTPS gateway contracts and
  injected fake connectors in tests. No real session, agent, identity, network,
  or ticket provider is certified, and no vendor-specific idempotency,
  verification, rollback, rate-limit, or account behavior is claimed.
- The response adapter validates public HTTPS endpoints and bounded typed
  results, but it is not a managed egress proxy or process sandbox. Production
  needs isolated connector workers, hard cancellation, mTLS/workload identity,
  DNS/route controls, vendor qualification, and network observation.
- Response approvals use fixed logical requester, approver, and executor IDs
  behind one local bearer. The state machine enforces separation and exact-plan
  binding, but it does not prove two humans authenticated. Module 24 adds a
  provisioned signed-assertion reference plane with MFA and access review; the
  response API is not yet bound to an enterprise per-human session.

## State, identity, and cryptography

- Telemetry intake and the canonical Module 3 repository are transactional
  SQLite state and survive restart. Canonical revisions have tenant hash chains,
  protected evidence, signed checkpoints, retention/holds, and verified local
  backup/restore. Detection rules, sanitized windows, and execution audit are
  durable when explicitly configured. Detection-content revisions, validation
  results, packs, and health are also durable and signed when explicitly
  configured. Behavioral configurations, baselines, assessments, entity
  scores, and audit records are durable when explicitly configured;
  baselines/configurations have canonical digests but no managed signature or
  external transparency anchor. Case records, notification outbox deliveries,
  attempts, acknowledgments, teams, collaboration, reviews, operation replays,
  response playbooks/executions/approvals/attempts/control, and audit chains are
  durable in single-node SQLite when explicitly configured. The legacy
  authorization pipeline stores, approvals,
  authority-use counters, ABOM observations, provenance, and Splunk dead
  letters remain process memory. There is no clustered replication or
  platform-wide transaction boundary.
- Enrichment cache entries and connector health/circuit counters are durable
  SQLite WAL/full-sync state when explicitly configured. They carry freshness
  and policy evidence but currently use local database integrity rather than a
  managed signing key or external transparency anchor. Module 24 adds local
  signed administration checkpoints but does not claim external custody.
- Authoritative incident details are generated from the exact in-process
  pipeline result, stored in an indexed in-memory IncidentStore, and returned
  through private APIs, but are not yet persisted in a durable incident database.
- The hash chain detects mutation only when a trustworthy checkpoint is retained
  separately. The included anchor is another in-process object.
- `PocHmacSigner` uses one shared HMAC key. It has no hardware-backed custody,
  asymmetric attribution, rotation, revocation, transparency log, or compromise
  recovery.
- Content publication mutates the content and detection SQLite databases in a
  validated order but cannot make a distributed atomicity claim. A crash after
  live-rule registration and before lifecycle commit requires operator
  reconciliation; a production transactional outbox/reconciler belongs to the
  platform module.
- Authorization, incident, case, notification, and telemetry-admin APIs use one bearer and
  have no authenticated human sessions or mTLS. The case service applies
  server-held permission/team principals and distinct requester/reviewer demo
  identities, but those identities do not prove which human acted. Module 24's
  reference assertion verifier is not yet a shared enterprise session for these
  module APIs. Telemetry
  intake separately uses HMAC workload
  signatures, durable replay nonces, credential-bound tenant/source identity,
  rate limits, and transactional queue admission. Credential rotation,
  service-to-service mTLS, user RBAC, and clustered storage remain absent;
  loopback/private-network placement is required.
- The local content API uses distinct fixed author, reviewer, and publisher
  service identities to preserve the four-eyes invariant. These are honest
  machine identities, not authenticated human attribution. Module 24 implements
  those concepts in its administration domain, not external federation or a
  retroactive per-human identity for this content route.

## Models and data

- Codex testing is a versioned offline recording produced during development; it
  is not a live Codex API call or an independent blinded judge.
- The five-role AI analyst is a bounded orchestration and evidence-accounting
  reference, not proof that a model is a qualified SOC analyst. The recorded
  roles are deterministic fixtures. They do not perform open-ended tool use,
  retrieve external intelligence, execute response, or establish ground truth.
- Role timeouts, abstentions, unavailable output, fabricated citations, and
  disagreements are visible and conservative, but the local worker pool cannot
  forcibly terminate provider code already executing. Live transports must
  enforce their own deadlines and process isolation.
- Analyst runs and feedback are durable only in single-node SQLite with local
  SHA-256 integrity checks. Feedback is deliberately inert. Module 23 can admit
  it to a new benchmark revision only through separate submitter, reviewer, and
  publisher identities; it never performs automatic learning. Module 24 adds a
  local human-RBAC and signed-checkpoint reference, while enterprise SSO,
  externally managed signing, distributed state, and HA remain deployment work.
- The evidence validator proves that a typed claim agrees with recorded
  allowlisted metadata; it does not prove source authenticity, causality,
  malicious intent, or real-world ground truth. Its instruction patterns are a
  bounded deterministic guard, not complete semantic injection detection.
- Judgment confidence ceilings are explainable safety policy, not statistically
  calibrated probabilities. Module 23 measures Brier score, calibration error,
  per-use-case reliability, false blocks, and release drift on its controlled
  synthetic corpus only; those results do not establish production calibration.
- Human gates now open a durable single-node case workflow with assignment,
  comments, tasks, acknowledgment/resolution SLA, safe attachment metadata,
  typed relationships, and server-enforced independent review. The local
  shared bearer token still does not authenticate two distinct humans. Module
  24 supplies reference SSO-assertion/RBAC/access-review contracts, but this
  case route is not connected to an enterprise session or organization archive.
- OpenAI and Anthropic tests use injected fake transports. The live adapters and
  model gateway are implemented, but checked-in routes are candidates with
  placeholder exact IDs; no current provider model, account, availability,
  pricing, residency, or retention claim is made without external verification
  and a current exact qualification.
- The continuous benchmark has 42 metadata-only synthetic cases. Its seven
  variants begin after normalization and do not prove raw-prompt evasion,
  production prevalence, provider nondeterminism, multilingual semantics,
  latency, cost, or third-party red-team coverage.
- The committed Codex continuous track is an offline recorded fixture. It is not
  a live Codex API call or independent model/vendor qualification. A live OpenAI
  or Anthropic candidate requires an exact route and external qualification
  commitment and remains non-executive.
- Absolute and drift gates can prevent a known measured regression; they cannot
  detect a threat family absent from ground truth. New feedback changes only a
  versioned benchmark after three-actor governance and never changes production.
- Gateway prompts, routes, qualifications, health, budgets, calls, and secret
  fingerprints are durable single-node SQLite. This is not a global distributed
  quota, managed secret store, provider billing ledger, organization retention
  control, or HA control plane. Local service identities preserve structural
  separation but are not human SSO/MFA attribution.
- The five-scenario corpus is intentionally small. The two holdout fixtures are
  version-separated but visible in the repository, so they are regression
  holdouts rather than secret or statistically representative benchmarks.
- Metadata minimization and canary tests reduce disclosure risk but do not replace
  provider privacy, retention, data-residency, and legal review.
- The model gateway provides durable single-node governance, not independent
  proof that a provider/model is safe or capable. Qualification stores an exact
  externally produced evidence digest and strict aggregate metrics; automated
  provider tests use fake transports and no current OpenAI or Anthropic model is
  claimed qualified by this repository.
- Qualifications expire and route/prompt/model changes require a new revision,
  but provider-side behavior can change behind an unchanged identifier. Blind
  holdouts, repeated live canaries, drift evaluation, and operator revocation
  remain necessary.
- Gateway budgets cover requests, tokens, and concurrency, not currency cost,
  organizational quota, or globally distributed usage. SQLite transactions and
  circuit state coordinate one process/database only.
- Evidence validation proves consistency with allowlisted recorded facts, not
  ground truth, causation, attacker intent, or the correctness of upstream
  telemetry. Confidence ceilings are policy heuristics. The controlled Module 23
  calibration report is not representative of arbitrary customer traffic.
- Injection isolation uses bounded lexical signals plus structured fact
  comparison. It deliberately fails toward human review, can over-escalate
  benign security discussion, and cannot certify that arbitrary content is
  safe. Raw content stays outside the model/incident contract.
- The judgment report can require a human and Module 17 now provides assignment,
  acknowledgment, task, SLA, review, and closure workflow. It still cannot
  execute a response or prove that an external party was notified; those
  controls belong to Modules 19 and 18 respectively.
- Secrets are environment-backed with fingerprint/rotation enforcement, not a
  managed vault, workload identity, HSM, automatic rotation, or compromise
  recovery. Prompt and route records use local SHA-256 integrity, not managed
  signatures or an external transparency log.
- Cases are durable only in single-node SQLite. Local transactions and
  optimistic versions coordinate independent processes sharing that database,
  while local SHA-256 provides tamper evidence. This is not clustered
  concurrency, managed backup, point-in-time restore, HA/DR, managed signing,
  or independent timestamping.
- Case attachment support is metadata-only. The service does not accept, store,
  scan, preview, or download file bytes; production blob custody and content
  security remain deliberately unimplemented.
- Case child/audit records are explicitly capacity bounded. A case reaching a
  bound fails further additions closed and requires an archival/export design
  before production-scale use.
- Guarded response connectors are provider-neutral typed HTTP gateway
  contracts. The checked-in endpoints are reserved `.invalid` hosts and the
  default credentials are empty; no vendor API or external asset has been
  exercised or certified.
- Response dry run validates the local immutable plan, hashed targets,
  operations, connector presence, and control state. It does not invoke a
  provider sandbox or prove downstream authorization, quota, race behavior, or
  the absence of an external side effect.
- The response UI uses a local shared bearer mapped to fixed requester,
  approver, executor, author, reviewer, and publisher identities. Separation of
  duties is enforced in the service state machine, but it is not proof that two
  distinct authenticated humans acted. Module 24 proves the corresponding local
  administration state machine, not enterprise federation or response-session
  attribution.
- Response records use local canonical SHA-256 integrity under the service trust
  boundary. They are not HSM-backed signatures, external timestamps, or an
  immutable transparency log. An administrator with database and code control
  remains inside the reference trust boundary.
- SQLite and local execution leases provide single-node durability, not a
  distributed workflow engine. A process loss after an external effect but
  before its checkpoint becomes visible as uncertain/fail-closed state and
  requires operator reconciliation; it is deliberately not auto-replayed.
- The generic HTTPS response gateway inherits strict host, TLS, redirect,
  timeout, and size controls but is not a managed egress proxy and cannot
  remove every DNS/network race. Production requires private qualified
  gateways, workload identity, managed secrets and egress, connector
  observability, SLOs, backup/DR, and HA.
- The Module 20 BFF proves server-to-server bearer custody and fixed loopback
  routing only. It does not authenticate a human. Module 24 provides a separate
  signed-assertion, RBAC, step-up, and access-review reference service, but the
  browser BFF remains read-only and deliberately reports
  `human_identity_verified=false`.
- Reports and service health are request-time projections from local product
  services and three committed repository files. They are not a metrics lake,
  distributed health monitor, managed audit archive, independent timestamp, or
  signed transparency service.
- The UI has semantic, keyboard, focus, reduced-motion, responsive, source, and
  rendered-HTML accessibility gates. No formal WCAG certification or complete
  browser/assistive-technology compatibility claim has been made.
- External SIEM connectors are verified with injected transports only. The
  checked-in Splunk, Elastic, webhook, syslog, CEF, and OTLP destinations are
  disabled reserved `.invalid` examples; no vendor endpoint or account is
  certified by the repository.
- Splunk indexer acknowledgment and Elastic/OTLP item rejection are modeled
  explicitly. RFC 5424/CEF TLS success proves only that the peer accepted the
  framed bytes, not that a downstream SIEM indexed, retained, or alerted on
  them.
- The integration stream/outbox, retry scheduler, audit chain, and client
  registry are durable single-node controls. They are not a distributed queue,
  managed scheduler, immutable audit service, managed key/secret store, mTLS
  identity plane, HA service, or disaster-recovery system.
- Public API scopes and tenants are enforced, but bearer clients are configured
  from a local policy and environment. Rotation overlap, revocation service,
  enterprise client lifecycle, rate plans, API gateway/WAF, and workload
  attestation remain production platform work. Module 24 stores rotation and
  revocation metadata but does not operate an enterprise credential service.
- Simulation variants qualify downstream handling of an already-normalized
  security signal and retain stimulus digests only. They do not prove raw-text
  Japanese/Spanish detection, tokenizer robustness, decoding, content
  sanitation, or open-ended adversarial coverage.
- Simulation control effects run only in `MockEnterpriseTools`. This proves the
  expected local protected-versus-control delta, not a real agent framework,
  model provider, vendor tool, cloud account, or production egress boundary.
- Simulation framework mappings and repository-authored ground truth are
  curated validation metadata, not OWASP, MITRE, or NIST certification.
  Imported ground truth remains explicitly unreviewed.
- The scenario/run store, replay ledger, and isolation receipt use local SQLite
  and SHA-256 commitments. They are not managed sandbox infrastructure,
  independent attestation, HSM signing, immutable storage, distributed
  execution, managed backup, HA, or disaster recovery.
- The Module 22 lab executes a small curated corpus in local deterministic mock
  tools. It is not a malware sandbox, provider sandbox, live red-team system,
  enterprise integration test, or evidence of general attack coverage.
- Japanese, Spanish, base64, Unicode-confusable, zero-width, and mixed profiles
  preserve a declared normalized security signal and change only stimulus
  commitments. They do not test raw-language/tokenizer/decoder/preprocessor
  robustness and cannot support an adversarial-evasion claim.
- Imported scenario labels are deliberately unreviewed. A valid import proves
  schema and sandbox safety, not that its expected alerts, actions, mappings, or
  attack label are correct.
- Simulation runs instantiate the reference pipeline and mock enterprise tools;
  they do not exercise configured live model providers, response connectors,
  SIEM destinations, or external systems. The control arm intentionally permits
  mock forbidden effects to establish a local comparison only.
- The simulation catalog, request-idempotency store, replay ledger, and audit
  chain are single-node SQLite/SHA-256 controls. They are not HSM signatures,
  independent timestamps, immutable storage, distributed execution, managed
  isolation, backup/restore, or HA/DR.

## Administration and platform assurance

- Module 24 uses a bounded HMAC-signed assertion as a local test adapter. It is
  not OIDC or SAML federation, JWKS rotation, SCIM, enterprise session
  revocation, adaptive access, or proof that the fixed actors in Modules 10,
  17–19 are authenticated humans.
- Administration stores external credential/key references and fingerprints
  only. This proves that raw material is absent from that database; it does not
  prove KMS/HSM custody, external rotation, revocation propagation, access
  policy, deletion, or compromise recovery.
- Residency, processing-region, retention, legal-hold, and encryption settings
  are digest-bound tenant policy. They do not attest actual geographic
  placement, provider processing location, deletion jobs, or encryption state.
- Audit UPDATE/DELETE triggers, a local hash chain, and a signed checkpoint
  provide single-node tamper evidence. An administrator controlling the host,
  process, database, and signer remains inside the trust boundary. No external
  WORM archive, transparency anchor, trusted timestamp, or non-repudiation is
  claimed.
- SLO, recovery, and supply-chain pass states are recomputed from committed
  evidence, but the service does not schedule probes/backups, fail over traffic,
  generate SBOM/provenance, run CI scanners, or qualify those producers.
- `AdministrationHealth` intentionally keeps external IdP federation, external
  key custody, geographic residency verification, distributed HA, and
  production readiness false. A healthy reference service is not a production
  authorization.

## Deployment and operations

- The clean Python package install and workflow demonstration are reproduced by
  `make clean-install`. The prior AWS demo was deliberately deleted; current
  optimization and verification are local-only. The templates remain structural
  release artifacts and no live deployment is claimed.
- The Tokyo template is a single private EC2 research node. It allows broad HTTPS
  egress, depends on operator-provided subnet/endpoints and secrets, and has no
  HA, autoscaling, private load balancer, WAF, durable database, SIEM durability,
  SLO, backup, or disaster recovery.
- Direct OpenAI or Anthropic calls leave AWS; EC2 region `ap-northeast-1` does not
  imply model-processing residency in Tokyo.

Any production pilot must close or explicitly accept these items and meet the
Production v1 gates in `docs/release-audit.md`.
