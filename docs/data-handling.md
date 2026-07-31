# Data handling

The default collection mode records metadata plus one-way content digests and
byte counts only. Raw prompts, model responses, tool results, memory content,
credentials, authorization headers, and secrets are prohibited in general alert
attributes. Redacted previews require an explicit collector policy. Protected-raw
collection requires an injected content protector and is rejected by the default
environment-built gateway because key custody is not configured.

The ingestion gateway persists only the safe `TelemetryEnvelope`. Its SQLite
spool contains normalized metadata, content-evidence receipts, and a one-way
canonical request hash for durable idempotency; it does not retain the submitted
`TelemetryInput`, workload secret, signature, nonce body, or raw content. Invalid
input and downstream failures are represented by fixed reason codes without raw
exception text.

The canonical repository persists Module 3 records and hash-chain receipts.
Sensitive evidence content can enter storage only as a `ProtectedEvidenceBlob`
created by an external authenticated protector. The blob's plaintext SHA-256
must equal the canonical evidence receipt and its ciphertext SHA-256 must match
the submitted ciphertext. Retention removes payload/ciphertext bytes while
preserving digests and an auditable policy tombstone; a legal hold blocks that
operation.

Allowed model-review fields are alert/finding IDs, normalized operation and
resource classes, destination class, trust labels, data-classification labels,
policy/manifest versions, reason codes, and redacted evidence references.

Allowed external SOC fields are the same metadata subset plus severity, status,
owner reference, case ID, and a restricted evidence pivot. Export construction
must begin from this allowlist; it must not serialize raw evidence and remove
fields afterward.

Recursive redaction, model-bundle, and SOC-export tests use canary values to prove
that configured secrets and raw content are absent. The legacy Splunk helper
receives only `SocFindingExport`; Module 21 further rebuilds that projection as
a digest-bound `ExternalSecurityEvent`, and its durable dead letter references
only that same allowlisted event.
Provider requests set storage off where the API supports it, but deploying a live
profile still requires a separate privacy, residency, retention, and contractual
review. Redaction is defense in depth; the preferred control remains never
placing raw content in the model/export contract.

## Detection window boundary

The Module 9 detection store serializes `AgentEvent` from an explicit model dump
with `attributes` excluded and replaced by an empty object. Rules can access
only the fixed `DetectionEventField` enumeration: identity/flow, operation,
resource/destination metadata, source/trust, classifications, authority labels,
approval/effect flags, tool identity, and schema digests. Raw prompts, model
responses, tool arguments/results, memory content, arbitrary attributes,
headers, and credentials are neither queryable nor persisted by this engine.

Semantic detection receives the same strict event contract and fixed rule
definition. Returned evidence references must already be the event, source,
flow, or agent reference supplied to that call. Provider payload policy and
live provider retention remain governed by Modules 15 and 24.

## Detection-content boundary

Module 10 persists strict rule definitions, lifecycle identity/timestamps,
canonical digests/signatures, expected and actual event IDs, alert types,
counts, durations, fixed errors, review comments, and content-pack metadata. It
does not persist the validation/backtest `AgentEvent` objects. Those events pass
through an isolated Module 9 evaluator, whose own window strips the arbitrary
attributes map before storage, and the temporary evaluator is closed after the
result is produced.

The local Rule Studio bridge does not accept arbitrary test events. The browser
selects at most 100 names from five fixed synthetic presets; the token-owning
bridge generates strict metadata events and forwards them to the private
service. Rule definitions remain declarative allowlisted data and cannot query
raw prompt/tool/model content or arbitrary attributes. Review comments remain
free-form bounded metadata and must not contain secrets. Module 24 supplies a
product administration audit, not content-level DLP or an external archive.

## Behavioral analytics boundary

Module 11 derives only a fixed metadata feature vector: event ID/time,
operation, resource and destination classes, source-trust label, UTC hour,
effect/approval flags, sensitive-data presence, authority gap, and schema-drift
flag. Durable agent, source, tool, and destination keys are namespace-qualified
truncated SHA-256 references. Baselines store bounded counts, observation time,
revision/config version, and a canonical digest. They do not store raw source
IDs, agent IDs, tool names, destination URLs, resources, prompt text, memory,
model output, tool arguments/results, arbitrary attributes, credentials,
authorization headers, or secret values.

Assessments store event ID, feature digest, hashed entity scores, deviation
factors, probability/contribution/rationale/evidence, anomaly/composite scores,
drift state, final learning decision, configuration version, and timestamp.
Learning occurs only after an allowed, alert-free security outcome. A rejected
event is retained as assessment evidence but cannot modify the accepted-event
baseline. Retention and pagination are bounded.

The local Risk Analytics bridge accepts only fixed behavior reads and one exact
complete tuning object plus a bounded reason. It validates assessment and
hashed-entity references, owns the private bearer token, and exposes neither a
browser event-ingestion path nor raw entity lookup. Tuning reasons are bounded
free-form metadata and must not contain sensitive content. Module 24 supplies
a product administration audit, not content-level DLP or an external archive.

## Finding-correlation boundary

Module 12 consumes the already allowlisted authoritative pipeline result and
persists finding/alert/event IDs, risk/priority/decision labels, attack stage,
timestamps, correlation score/reasons, and namespace-qualified hashes of flow,
agent, source, resource, tool, destination, and evidence references. It does not
persist raw prompts, model text, memory, tool arguments/results, arbitrary
attributes, URLs, headers, tokens, credentials, or raw entity identities.

Merge and split move unique finding links without deleting the superseded
incident record. Suppression keeps bounded rule metadata and a suppressed
decision receipt; it never removes the underlying finding. Analyst reasons are
bounded free-form metadata and must not contain secrets. Managed redaction,
human identity, and platform audit can be governed by Module 24 only for calls
made through its verified principal boundary.

## Live enrichment connector boundary

Module 13 connector requests are constructed from a fixed metadata allowlist.
Depending on tenant policy, a connector may receive namespace-qualified
SHA-256 references for event, flow, agent, source, resource, destination, and
tool plus bounded operation, resource/destination class, source type/trust,
data-class, environment, and authority-operation labels. It never receives raw
prompt/model/memory content, tool arguments/results, arbitrary attributes, raw
resource or destination values, authorization headers, provider credentials,
or connector bearer tokens.

Connector output is accepted only through a strict source/version contract,
allowlisted fact keys, bounded scalar/string-list values, and hashed evidence
references. The durable cache contains tenant, connector name, a SHA-256 input
key, the validated metadata response, and fresh/stale timestamps. Health state
contains counters, current circuit horizon, last outcome/latency, and no request
body. Runtime configuration contains endpoint URLs and environment-variable
names; secret values are resolved at startup and never cached or exposed by the
health API or analyst UI.

Fresh, stale, timeout, policy-denied, circuit-open, and failed outcomes are
explicit evidence. A stale result is downgraded to partial and carries its age
and original expiry. Missing connector data can increase uncertainty but cannot
grant authority, suppress deterministic detection, or weaken enforcement.

## AI analyst boundary

Module 14 builds a fresh evidence manifest from an explicit allowlist over the
authoritative `PipelineResult`; it does not serialize the event and redact it
afterward. The manifest can contain alert/detector metadata, hashed evidence
references, allowlisted enrichment facts with freshness state, triage
contributions, ledger digests, deterministic judgment, escalation, response,
and privacy-safe finding identifiers. Raw prompt/model/memory content, tool
arguments/results, arbitrary event attributes, raw resource/destination/source/
agent/tool identifiers, authorization headers, provider credentials, tokens,
canaries, and secret values are excluded.

Each role receives only the evidence kinds required for its objective. The
tool receipt records requested kinds, returned governed evidence IDs, count,
timestamp, and digest—not a hidden raw payload. Model-authored prose is
recursively redacted before durable storage. Citations, including citations on
alternatives, must be a subset of that role's tool results; fabricated evidence
causes an unavailable role rather than durable model prose.

The analyst database stores tenant, run/finding/alert IDs, role outcomes,
alternatives, uncertainty, non-executive recommendations, tool receipts,
disagreements, timestamps, policy/model/recording identity, and canonical
digests. Feedback stores the authenticated actor reference, rating, optional
role, redacted reason, timestamp, and digest. Feedback is explicitly
`applied_to_model=false`; no online learning or prompt mutation occurs.

The recorded Codex configuration contains bounded response templates and model
identity only. It is test evidence, not a provider request. Live provider
payload minimization, budgets, secrets, and routing are governed by Module 15;
provider account retention/residency approval and managed custody remain Module
24 responsibilities.

## Evidence-validation boundary

Module 16 reads only the existing privacy-safe model bundle and analyst evidence
manifest. It stores typed claim statements, bounded fact keys/operators/values,
governed evidence IDs, mandatory-kind checks, matched/conflicting IDs, source
counts, calibrated confidence, fixed issue codes/messages, human-gate reasons,
policy/timestamps, and canonical digests. It does not retrieve raw prompts,
provider payloads, tool arguments/results, arbitrary event attributes, headers,
credentials, tokens, or protected evidence blobs.

Instruction-like values are identified by code and evidence reference; the UI
does not need the offending raw content. Validation is part of the already
tenant-scoped analyst run and authoritative incident response, so it inherits
their permission, redaction, pagination, and integrity boundaries.

## Model gateway boundary

The model-gateway database stores immutable prompts, prompt/schema digests,
exact model and route metadata, allowed modes/privacy classes, budget limits,
qualification metrics/evidence digests/expiry, secret environment-variable
names and value fingerprints, lifecycle/audit hashes, circuit counters, and
sanitized call receipts.

It does not store secret values, Authorization or API-key headers, provider
request bodies, analyst evidence content, raw prompt/model/memory/tool content,
raw provider outputs, arbitrary event attributes, canaries, or full sensitive
content. Call receipts retain provider request identity, token counts, latency,
normalized outcome, and output SHA-256 only.

Privacy-class route filtering occurs before provider construction and applies to
fallbacks. Secret-egress and secret/credential/PII/restricted indicators force
restricted classification. OpenAI requests set storage off, but this does not
establish provider organization retention or residency; those require separate
external verification.

## Incident investigation boundary

IncidentDetail 2.0.0 is constructed from an explicit field allowlist over the
exact recorded PipelineResult. It does not serialize AgentEvent and redact it
afterward. The raw event `attributes` map is never copied. Source, resource,
destination, detector evidence, and model evidence values cross the UI boundary
only as namespace-qualified truncated SHA-256 references. Free-form audit actor
and reason strings pass through recursive redaction.

Allowed incident fields are IDs, timestamps, agent/operation metadata, trust and
classification labels, detector/rule versions, reason codes, ledger receipts,
enrichment statuses and metadata-only facts, score contributions, routing,
policy/model metadata, response disposition, lifecycle audit, and hashed
references. Specifically prohibited fields are raw prompts, raw tool arguments
or results, memory content, authorization headers, AWS credentials, ingest or
provider tokens, secret values, canary values, and full sensitive content.

Live enrichment connectors receive a second, narrower allowlist selected by a
tenant-scoped execution principal. Supported inputs are namespace-qualified
truncated SHA-256 references and bounded classifications; raw event, agent,
source, resource, destination, and tool identifiers are not sent. Connector
requests and facts are capped at 64 KiB, HTTPS responses at 1 MiB, evidence
references must use the hashed-reference format, and returned fact keys must be
declared by the connector. The durable enrichment store contains a SHA-256
input key, the validated metadata payload, freshness/stale deadlines, and
aggregate health—not request bodies or bearer tokens. Configuration names the
environment variable holding a connector bearer token; the value remains only
in connector process memory and the outbound Authorization header.

Every incident includes a privacy receipt with the redaction policy version,
evidence-handling policy, detail availability, redaction count, hashed-reference
count, and explicit false flags for all prohibited content classes. A
`summary_only` record contains no enrichment, triage, judgment, response,
timeline, or contributions because reconstructing those fields would create
unverifiable evidence.

## Evidence validation boundary

The pre-response validator stores evidence IDs and validation metadata only:
status, claimed/calibrated confidence, human-gate state, tightening eligibility,
and bounded reason codes. It never stores the provider request/response, raw
prompt, headers, credentials, or evidence content.

Five-role claims are constrained to a subject, bounded fact key, typed expected
value, deterministic operator, and governed evidence IDs. Validation compares
those fields only with the already allowlisted analyst evidence manifest.
Instruction-like evidence remains visible by hashed ID but is ineligible to
support a claim. Reports retain matched/conflicting IDs, source counts,
mandatory-kind results, contradictions, issues, deterministic action, and
digests. They do not add raw forensic content to the incident or UI boundary.

## Case-management boundary

The case store retains tenant, safe title and summary, finding/correlation
references, priority/severity/queue, team and actor references, acknowledgment
and resolution deadlines, attributed lifecycle timestamps, optimistic version,
policy version, and canonical digests. Child records contain redacted comments,
bounded task metadata, safe attachment metadata, typed relationships, review
decisions, and audit commitments.

Attachment content never crosses the case API and is never stored. A record is
limited to an allowlisted media type, safe basename, bounded byte count,
SHA-256, governed evidence reference, uploader, scan status, scanner digest,
and timestamps. Pending or quarantined metadata blocks case approval. Future
blob storage or download is outside this module and requires object-level
authorization, malware/content-disarm scanning, retention, and legal-hold
design.

Every mutation is tenant/team authorized, recursively redacts free text,
rejects unknown request fields, and writes a bounded digest of audit details
rather than the details themselves. The case record binds audit count and head;
the chain contains actor reference, action, status transition, detail digest,
time, sequence, prior hash, and entry hash. Local actor references and SHA-256
are tamper-evidence metadata, not proof of human identity or an external
timestamp/signature.

The Cases UI receives this verified contract through fixed loopback bridge
routes. It does not receive the service bearer token, raw incident event,
prompt, model payload, tool arguments/results, attachment bytes, provider
credentials, headers, secret values, canaries, or arbitrary database rows.

## Escalation and notification boundary

The notification store receives only the already sanitized escalation result:
tenant, finding/case references, alert type, priority/severity, deterministic
decision, escalation level, policy/route/schedule/template identities, queue,
hashed evidence references, timestamps, delivery state, acknowledgment state,
and canonical digests. It does not receive the original event, raw prompts,
model or memory content, tool arguments/results, arbitrary attributes, headers,
credentials, tokens, canaries, or full evidence.

Templates may reference only a fixed scalar allowlist. Rendering recursively
redacts the bounded values before durable persistence and delivery. Each
destination receives the safe subject/body, channel metadata, notification and
delivery identities, and a stable idempotency key. Connector credential values
are read from the named environment variable only during service assembly;
policy, database, health, API, bridge, UI, and audit records never expose the
value or the environment-variable name.

Provider bodies and raw references are not retained. Successful transport
stores only response status, bounded latency, normalized outcome, and SHA-256
commitments for the provider reference and acknowledgment receipt. Failures
store an allowlisted error code. Attempts, redrives, provider acknowledgment,
and human ownership acknowledgment are separate records so transport success is
never presented as proof that an analyst accepted the incident.

The Escalations UI receives verified notification/detail/health/destination
contracts through fixed loopback routes. It may show rendered safe messages,
safe error codes, delivery and acknowledgment state, digests, and audit history;
it cannot submit an actor identity, choose an arbitrary destination/endpoint,
mark a provider acknowledgment, read a credential, or proxy an arbitrary
upstream request.

## Response automation boundary

The response store receives only the already sanitized pipeline outcome and
references required to plan containment: tenant, finding/alert/case/correlation
IDs; playbook and policy identities/digests; deterministic decision metadata;
hashed agent, session, resource, and destination targets; typed operations and
expected states; readiness/state/version/timestamps; fixed service actor IDs;
and canonical commitments. It never receives the original event attributes,
raw prompts or memory, model payloads, tool arguments/results, source content,
authorization headers, connector credentials, or arbitrary evidence.

Connector policy contains endpoint and credential-variable metadata, while the
credential value is read only into connector memory during service assembly.
The read APIs, bridge, UI, database, playbook, attempts, audit, and health output
never expose the value or an outbound authorization header. UI connector status
exposes connector identity, operation allowlist, enabled state, and readiness;
it omits endpoint and credential-variable name.

An outbound request contains only execution/step identity, a typed operation,
privacy-safe target reference, exact expected state, optional case ID, stable
idempotency key, timestamp, and request digest. Provider bodies are bounded and
discarded. Provider references and verification evidence references are hashed
before persistence. Failures retain only normalized safe error codes and
bounded latency.

Approvals store a fixed approver identity, scope, exact plan digest, redacted
reason, issue/expiry/consumption time, and digest. They do not contain human
session tokens or credentials. The local bearer-to-fixed-role mapping proves
state separation but is not per-human authentication.

The Response UI receives verified execution/detail/health/control/playbook and
connector-status contracts through fixed loopback routes. It cannot supply an
actor, permission, connector, endpoint, target, operation, credential, provider
receipt, or arbitrary upstream path. The editor can submit a strict declarative
playbook draft only; separate fixed service roles govern review and activation.

## Guarded response boundary

The response store receives only the already sanitized pipeline result and
governed case/correlation references. Persisted execution fields are bounded
finding/alert/case references, classifications, immutable policy/playbook IDs
and digests, fixed service-actor references, state/version/timestamps, connector
IDs, typed operations, expected-state labels, safe error codes, and canonical
commitments. Raw prompts, model content, tool arguments/results, memory,
arbitrary event attributes, authorization headers, bearer values, provider
bodies, canaries, and secret values never enter the response database.

Session, agent, resource, and destination targets are converted to namespace-
qualified truncated SHA-256 references before the dry run is persisted. A case
target uses the already governed opaque case ID. The UI and API do not expose a
reverse mapping. Provider references and verification evidence are retained
only as full SHA-256 commitments; attempts retain phase, outcome, bounded
latency, safe error code, time, and their own digest.

The signed policy contains a connector's exact endpoint, allowed host, and the
name of its credential environment variable, but public response status omits
all three. The credential value is read only during service assembly and kept
in connector memory for the outbound authorization header. It is not written to
policy output, SQLite, schemas, health, audit, bridge state, or browser code.

Approval reasons and playbook review comments are recursively redacted and
bounded before persistence. Approval records contain the exact plan digest,
scope, fixed approver identity, issue/expiry/consumption times, and canonical
digest. Audit entries store a redacted detail digest rather than arbitrary
detail text. The execution commits the exact audit count/head, and terminal
step attempt counts make missing or unbound attempt rows detectable.

The Response UI receives only verified execution/detail/health/control/
connector-status/playbook contracts through fixed loopback routes. Browser
requests cannot specify an actor, tenant, endpoint, credential, target,
connector, operation, or provider evidence for an existing execution. Execute
and rollback bodies must be empty; the server reconstructs the exact signed
plan and selects the fixed executor identity.

## Analyst UI and platform snapshot boundary

The browser receives sanitized module contracts through fixed loopback routes.
The platform snapshot adds only schema/source/time, an upstream-authentication
receipt, bounded service states and scalar/count metrics, selected fields from
the committed release/evaluation records, file SHA-256 commitments, and the
ordered module catalog. It excludes prompts, model content, tool inputs/results,
evidence bodies, arbitrary event attributes, endpoint URLs, authorization
headers, tokens, credential values, secret-variable names, and raw provider
responses.

The BFF recognizes only three constant report names mapped to repository-owned
paths. Callers cannot submit a path, glob, URL, command, report type, or parser.
Files are size bounded and must parse as JSON objects. Health responses pass
through a reducer that keeps bounded top-level scalar values and collection
counts while excluding credential-, token-, secret-, header-, URL-, and
endpoint-shaped fields. Errors become a normalized unavailable state rather
than returning exception detail.

The downloaded report snapshot is the same sanitized browser projection. It is
not a copy of the source files, service configuration, database, or bearer.
The BFF receipt explicitly says that human identity is not established; it must
not be used as evidence of an authenticated analyst.

## Administration data boundary

The Module 24 database stores tenant policy, provisioned identity metadata,
email SHA-256 commitments, roles, external workload credential references and
fingerprints, external key references and fingerprints, access-review rationale
SHA-256, SLO/recovery/supply-chain evidence, immutable audit commitments, and
signed checkpoint metadata. It never accepts or stores passwords, bearer
tokens, assertion signing keys, checkpoint signing keys, private/encryption key
material, raw provider credentials, or access-review prose.

Assertion and checkpoint keys are explicit runtime environment values. Signed
assertions are verified, replay IDs are retained through expiry, and only the
derived principal is returned. Audit details are hashed before persistence.
The UI projection removes identity subjects, email commitments, credential/key
references, assertion data, runtime variable names, and configuration paths; it
retains policy metadata, counts, pass states, and integrity digests only.

Residency and retention are policy metadata, not proof of infrastructure
placement or deletion. The health contract exposes those unverified boundaries
as literal false flags so they cannot become presentation-only production
claims.

## External API and SIEM boundary

Only `ExternalSecurityEvent` crosses the integration boundary. It is rebuilt
from the allowlisted SOC finding export and contains bounded identifiers,
classification, decision/escalation state, evidence pivot, ledger-integrity
label, timestamp, and canonical digest. It never contains prompts, responses,
tool arguments/results, memory, source text, arbitrary event attributes,
evidence bodies, authorization headers, or credentials.

The durable outbox stores that allowlist event, delivery state, safe error
codes, acknowledgment times, and SHA-256 commitments for provider references
and receipts. The raw Splunk acknowledgment ID is private state used only for
the subsequent ack poll and is not returned by API/SDK records. Connector
credentials are resolved from policy-named environment variables at runtime;
neither values nor variable names appear in public status.

Public API client policy stores client ID, tenant, scopes, enabled state, and a
token-variable name. Token values remain runtime-only. The public router emits
only fixed product contracts, rejects cross-tenant access, and cannot proxy an
arbitrary path or URL. Public and administrative bearers cannot substitute for
one another.

## Simulation and validation boundary

Simulation persists only the canonical metadata event, scenario/run metadata,
explicit ground truth, bounded result classifications, opaque alert/finding
references, normalized reason codes, lineage, timestamps, and SHA-256
commitments. Scenario event attributes must be empty. Raw prompts, document or
memory bodies, model input/output, tool arguments/results, arbitrary metadata,
credentials, authorization headers, scripts, files, and real destination data
are rejected or never accepted.

Allowed destinations use reserved credential-free HTTPS `.invalid` names.
Multilingual and obfuscation profiles retain a stimulus digest and fixed
transformation/locale labels only; they do not retain transformed text.
Imported ground truth is marked unreviewed. The sandbox receipt records only
isolation booleans and bounded counts. The browser receives these allowlisted
records through fixed BFF routes; it cannot submit a raw scenario or choose a
tenant, actor, operation, effect implementation, URL, or service credential.

## Simulation and validation boundary

The simulation database stores strict normalized `AgentEvent` metadata,
scenario and step labels, ground truth, framework mappings, one-way stimulus
digests, lineage, trust state, run observations, alert/finding identifiers,
mock effect outcomes, sandbox receipts, audit entries, timestamps, and canonical
record commitments. Raw prompts, documents, memories, model responses, tool
arguments/results, arbitrary event attributes, credentials, authorization
headers, and provider bodies are prohibited from the scenario contract.

Variant profiles record a locale, fixed transformation names, and a one-way
derived stimulus commitment. They do not retain the transformed source text.
The API and UI explicitly state that Japanese, Spanish, encoded, confusable,
zero-width, and mixed variants begin after collector normalization; these
records cannot be used to infer raw-content detector qualification.

Imports accept strict metadata drafts only and always set their labels to
unreviewed. The browser cannot import a scenario or provide an event,
destination, operation, actor, tenant, raw payload, or arbitrary upstream path.
All displayed scenario/run content comes from the authenticated service or an
explicit unavailable state.

## Continuous evaluation boundary

The evaluation dataset reuses only strict normalized simulation metadata. A
blind case contains bounded agent-event metadata, variant and framework labels,
and a stimulus commitment. Sealed ground truth contains expected alert types,
severity, action, forbidden-effect classification, and allowlisted evidence
references. It contains no raw prompt, response, document, memory, tool body,
arbitrary attributes, credential, provider payload, or authorization header.

Candidate execution receives the blind case only. Labels are joined after the
candidate returns and are committed separately. Result records retain bounded
predictions, classifications, evidence references, confidence, abstention,
latency, safe-effect state, and digests. The committed release reports use a
fixed zero timing value and make no performance claim.

The durable evaluation database stores dataset revisions, sanitized reports,
candidate identity and route/qualification commitments, baselines, feedback
proposals, reviewer/publisher identity labels, one-way rationale and source
feedback commitments, and a chained audit. It does not store provider secrets
or raw model request/response bodies. `source_applied_to_model`,
`applied_to_model`, and `applied_to_runtime_policy` are structurally false.

The Evaluations UI receives only the fixed, manifest-bound baseline and
candidate release records. It does not receive sealed per-case events or ground
truth, feedback mutation APIs, the SQLite database, the service bearer, policy
secrets, or provider credentials.
