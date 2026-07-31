# Module 18 — Escalation and Notification

Status: verified  
Contracts: 1.0.0  
Policy: notification-policy-2026-07-24.1

## Comparison baseline

The original workflow emitted an escalation intent with a level, queue, case
reference, reason, and timestamp. That was useful investigation evidence, but
it did not prove that an accountable human or external operations system had
received anything. The existing SIEM helper was an in-memory export projection,
not an escalation delivery service.

There was no versioned routing policy, on-call schedule, channel template,
credential readiness state, delivery outbox, idempotency key, provider receipt,
human acknowledgment clock, retry schedule, dead-letter queue, redrive control,
or durable delivery audit. A pipeline could say "incident page" without paging
anyone or preserving evidence that delivery failed.

## Implemented remediation

- Added a tenant-scoped SQLite notification service with WAL, full synchronous
  commits, immediate transactions, bounded records, and restart-safe outbox,
  delivery, attempt, and audit tables.
- Added a signed policy containing ordered routes, versioned on-call schedules,
  four typed destinations, safe templates, acknowledgment SLAs, retry policy,
  and exact channel/template references. Invalid or ambiguous policy fails at
  startup.
- Added `on_call`, `ticket`, `email`, and `messaging` connectors behind one
  bounded interface. Channel-specific wrappers reject mismatches rather than
  allowing a destination to be driven by the wrong adapter.
- Added strict outbound endpoint validation: HTTPS, port 443, exact host
  allowlist, no URL user information, query, or fragment, public DNS
  resolution, no local/link-local/private target, redirect rejection, bounded
  response, safe normalized errors, and connector timeouts.
- Kept credentials outside policy and durable state. Destinations name an
  environment variable; the value exists only in connector memory and its
  outbound authorization header. APIs expose readiness, never the endpoint,
  credential name, or credential value.
- Added deterministic first-match routing from the authoritative finding's
  priority, escalation level, and alert type. The selected route and exact
  policy digest, schedule ID/version, on-call actor, queue, case/correlation
  references, and acknowledgment deadline are committed to the notification.
- Added safe template rendering from an explicit metadata allowlist. No raw
  event attributes, prompts, model payloads, tool arguments, secrets,
  credentials, headers, or arbitrary evidence content can enter a message.
- Added one idempotent notification per tenant/finding and one deterministic
  idempotency key per rendered channel delivery. Pipeline retries return the
  same record and do not resend or duplicate audit entries.
- Added optimistic worker claims, a bounded in-flight lease for crash recovery,
  exponential retry, maximum attempts, dead-letter transition, maximum five
  operator redrives, and stable idempotency across retries and redrives.
- Added provider acceptance, asynchronous provider acknowledgment, safe hashed
  provider reference/receipt evidence, latency, attempt outcome, and normalized
  error codes. Provider response strings are never retained.
- Added a separate human acknowledgment state and SLA. The selected on-call
  actor—or an explicitly authorized administrator—must acknowledge the exact
  current version; stale, duplicate, unauthorized, and cross-tenant writes fail.
- Added a sequence-numbered notification audit chain. The notification record
  binds the exact audit count/head, and reads reject edits, insertion,
  reordering, or tail deletion. Every attempt and delivery also has an
  independently verified canonical digest.
- Added exact health for pending, retry-scheduled, provider-ACK-pending,
  dead-letter, human-SLA-breach, destination-readiness, and oldest-pending state.
- Inserted routing after the authorization/response decision and case creation.
  Notification outage is sanitized as `notification_routing_unavailable` and
  cannot change a deterministic allow, hold, or deny result.
- Exposed authenticated fixed APIs for queue/detail/health/destinations,
  delivery processing, human acknowledgment, provider acknowledgment, and
  dead-letter redrive. The loopback bridge validates exact IDs and bodies and
  has no arbitrary upstream proxy route.
- Added a live **Escalations** workspace with no fixture fallback. It displays
  route/schedule ownership, policy and record commitments, connector readiness,
  channel messages, attempts/retries/dead letters, provider proof hashes, human
  SLA, acknowledgment, redrive, and the complete delivery audit.

## Delivery lifecycle

```text
authoritative finding + escalation intent + case
                       |
                       v
              signed route selected
                       |
                       v
       durable notification + channel deliveries
                       |
              bounded worker claim
             /         |          \
            v          v           v
       delivered   ACK_PENDING   retry scheduled
                         |             |
               provider callback      +-- max attempts --> DEAD LETTER
                         |                                   |
                         v                                   +-- governed redrive
                   acknowledged

human ownership: PENDING -- exact actor/version + note --> ACKNOWLEDGED
                         \-- deadline passes -----------> BREACHED
```

Provider delivery and human ownership are deliberately separate. A ticket
provider can acknowledge receipt without proving that the on-call analyst has
accepted the incident, and a human acknowledgment cannot fabricate a provider
receipt.

## Security invariants

1. Notification work is tenant and permission scoped. Browser payloads cannot
   select a principal, route, endpoint, credential, template, or actor.
2. Routing is downstream of deterministic enforcement and cannot replay,
   authorize, or relax an agent effect.
3. One tenant/finding creates at most one notification; retries and redrives
   retain a stable message digest and idempotency key.
4. Templates interpolate only bounded privacy-safe metadata, and every rendered
   message is schema validated before persistence or connector access.
5. A connector must match its channel, resolve to an allowed public HTTPS host,
   reject redirects, and return a bounded typed result.
6. Secrets, endpoints, credential variable names, raw provider responses, and
   authorization headers do not cross notification read APIs or the UI bridge.
7. A provider callback supplies only a SHA-256 receipt commitment; it cannot
   acknowledge human ownership. The browser has no provider-ACK mutation.
8. Human acknowledgment is version checked and limited to the routed on-call
   identity unless the server-held principal has explicit administration scope.
9. Worker crashes recover only expired claims; concurrent workers cannot claim
   the same delivery, and retry/dead-letter/redrive bounds fail closed.
10. Notification, delivery, attempt, and audit integrity is verified on read;
    a missing audit tail invalidates the enclosing notification.

## Data and interface contract

`NotificationRecord` contains only finding/alert references, classifications,
decision and escalation metadata, queue/case/correlation references, route and
policy commitments, on-call schedule/actor, delivery/acknowledgment state,
version, timestamps, and audit/record commitments. `NotificationDelivery`
contains the safe rendered message, destination/template references,
idempotency and message digests, status, bounded retry state, timestamps, safe
error code, and hashed provider evidence. `NotificationDetail` combines that
record with verified deliveries, attempts, and audit entries.

Private product routes are:

- `GET /v1/notifications`, `/v1/notifications/health`, and
  `/v1/notifications/{notification_id}`;
- `GET /v1/notification-destinations`;
- `POST /v1/notifications/process`;
- `POST /v1/notifications/{notification_id}/acknowledge`;
- `POST /v1/notification-deliveries/{delivery_id}/provider-acknowledge`;
- `POST /v1/notification-deliveries/{delivery_id}/redrive`.

The local assembly requires both `AGENTSEC_NOTIFICATION_DB` and
`AGENTSEC_NOTIFICATION_CONFIG`. `AGENTSEC_NOTIFICATION_TENANT` is explicit or
inherited from another configured product tenant. The four connector values are
optional readiness inputs named by policy; a missing value makes that
destination visible as not ready without preventing authorization startup.

## Verification evidence

The dedicated tests cover signed policy routing, all four channels, template
rendering, on-call selection, idempotency, restart verification, secret/privacy
exclusion, provider and human acknowledgment separation, health and SLA,
retry/DLQ/redrive, attempt audit, stale in-flight recovery, concurrent workers,
tenant/permission isolation, exact pagination count, audit-tail tampering,
typed connector mismatch, outbound endpoint rejection, response bounds,
degraded credential readiness, pipeline integration and outage isolation,
authenticated strict HTTP APIs, actor-spoof rejection, safe destination output,
and environment assembly.

The bridge tests prove fixed paths and exact bodies for every read/mutation,
reject path traversal and arbitrary fields, and keep the bearer server-side.
The production UI build and source/render contracts prove the live escalation
route, operational controls, visible evidence, explicit empty/offline state,
and absence of fixture notifications.

Focused closure passed 72 notification, bridge, pipeline, service, case,
correlation, schema-contract, and runtime tests. The dedicated notification
suite passed all 11 tests. The production UI build and both UI contracts passed,
and all 234 generated schemas reproduce their canonical models exactly.

## Honest limitations and assigned follow-on work

- The example endpoints use reserved `.invalid` hosts and no external provider
  account was contacted. Fake transports verify the protocol, state machine,
  and failure controls, not a current PagerDuty, Jira, Slack, Teams, SES, or
  other SaaS integration. Exact provider adapters require independent
  qualification before use.
- Provider acknowledgment currently uses the private authenticated product API,
  not per-provider webhook signature verification, timestamp/replay protection,
  or provider workload identity. Those production identities belong to Module
  24.
- DNS is checked before the standard HTTPS client connects, but this reference
  adapter is not a production egress proxy and cannot eliminate every
  DNS-rebinding/network race. Production requires managed egress, private
  connector gateways, pinned policy, and network telemetry.
- The local shared bearer maps browser actions to a server-held administrative
  principal. It proves authorization/state invariants, not the identity of the
  human who clicked. SSO/MFA, per-user RBAC, and access review belong to Modules
  20 and 24.
- SQLite and the manual process endpoint implement a durable single-node outbox,
  not a distributed worker fleet, clustered queue/database, or multi-region
  delivery SLO. HA, backup, DR, and autonomous supervised workers belong to
  Module 24.
- This module proves escalation delivery; it does not execute containment,
  rollback, credential revocation, or any other response action. That boundary
  belongs to Module 19.

## Acceptance closure

The complete `make verify` gate passed with 325 Python tests, five TypeScript
SDK tests, 234 generated schemas, ten deterministic evaluation records,
clean-package reproduction, bytecode compilation, secret scanning, dependency
integrity, release audit, protected/unprotected workflow and recorded Codex
demonstrations, all eight evaluation modes, and component ablation.
Deterministic, Codex-shadow, and semantic-hold modes retained zero completed
forbidden effects and zero false blocks on the bounded corpus.

The production UI build and both UI source/render contracts also passed after
the final live Escalations integration. The full gate deliberately observed
17/24 before promotion. The post-promotion module audit records final Module 18
closure at 18/24.
