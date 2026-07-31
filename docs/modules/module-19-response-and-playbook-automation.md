# Module 19 — Response and Playbook Automation

Status: verified  
Contracts: 1.0.0  
Policy: response-policy-2026-07-24.1

## Comparison baseline

The original enforcement workflow produced a `SafeResponse` summary after the
deterministic judgment. That summary was deliberately simulated and useful as
investigation evidence, but it could not operate a connector, prove a changed
external state, compensate an earlier action, or stop response execution across
the tenant. The existing approval primitive was event scoped and process local;
it did not authorize an exact response plan.

There was no durable playbook revision, dry-run plan, target selector, response
connector contract, connector readiness state, requester/approver/executor
separation, expiring single-use approval, exact-plan binding, per-step
checkpoint, post-effect verification, rollback approval, execution lease,
tenant kill switch, attempt ledger, response audit, operational health, strict
private API, or live analyst workspace.

## Implemented remediation

- Added a separate tenant-scoped response control plane. The authoritative
  pipeline may create an inert plan after its decision, but the pipeline
  principal has no approval or execution permission and no pipeline method can
  call a connector.
- Added a signed provider-neutral policy with typed connectors, allowed
  operations, exact HTTPS endpoints/hosts, environment-backed credential
  references, trigger predicates, immutable playbook versions, ordered steps,
  expected states, bounded timeouts, and compensating operations.
- Added deterministic explicit-priority playbook selection for deny and
  require-approval results. Priority wins before version and stable ID,
  independent of input or SQL order. One tenant/finding creates at most one
  execution record, so event retries and service restarts cannot duplicate a
  plan.
- Added a side-effect-free dry run that resolves only privacy-safe targets,
  records connector readiness, and exposes explicit warnings. Session, agent,
  resource, and destination identifiers become truncated SHA-256 references;
  only an already governed case ID remains direct.
- Added live-request gating. The current dry run, every connector, the current
  execution revision, and the tenant kill switch must pass before the record can
  enter `awaiting_approval`.
- Added independent, expiring, single-use approvals bound to the exact tenant,
  execution, finding, immutable playbook/policy digests, scope, ordered
  operation, hashed target, expected state, and connector for every applicable
  step. A requester cannot approve and an approver cannot execute.
- Added a typed executor with no shell, file, command, or arbitrary URL
  interface. It emits a stable idempotency key, calls only an operation declared
  for the selected connector, records the result before moving forward, and
  verifies the observed state against the signed expected state.
- Added fail-closed ordered execution. A rejected connector result, exception,
  verification mismatch, missing connector, or engaged kill switch stops later
  steps. Every completed step is checkpointed and signed before the next
  external effect begins.
- Added explicit rollback as a second workflow: operator request, separately
  scoped exact-plan approval, distinct executor, reverse step order,
  compensating typed operation, and post-rollback verification. Rollback is not
  inferred from the original execution approval.
- Added a durable tenant-wide kill switch with optimistic revision control and
  signed state. It is checked at live request, executor claim, and before every
  forward or rollback step.
- Added bounded execution leases. An abandoned `running` or `rolling_back`
  claim becomes a visible failure after its lease expires instead of silently
  resuming an uncertain external effect.
- Added immutable playbook lifecycle states: draft, in review, independently
  approved/rejected, separately activated, and retired. Activating a new
  version rewrites and re-signs the prior active record as retired.
- Added SQLite WAL/FULL durability for playbooks, executions, approvals,
  attempts, audit, and control state. Optimistic versions and immediate
  transactions protect competing mutations on the single-node adapter.
- Added canonical record, step, approval, attempt, control, playbook, and audit
  digests. Execution records bind the complete audit count/head; terminal step
  checkpoints bind exact attempt membership and reads detect edited, removed,
  reordered, unknown-step, or unbound evidence.
- Added exact health for dry runs, approval queues, running/succeeded/failed and
  rollback states, verification failures, active playbooks, connector readiness,
  kill-switch revision, and execution latency.
- Added an HTTPS response-gateway adapter reusing strict notification transport
  controls: exact reviewed public host, port 443, TLS validation, no redirect,
  bounded response, typed JSON, timeout, and safe normalized error behavior.
  Credentials remain only in connector memory and the outbound authorization
  header.
- Added authenticated fixed service routes for execution queue/detail/health,
  connectors, control, playbooks, request/approve/execute, and the independent
  rollback lifecycle. Fixed server-side principals perform each action; request
  bodies cannot choose an actor, endpoint, credential, operation, or target.
- Added strict loopback-bridge route and body validators with no arbitrary
  upstream proxy. IDs, versions, reasons, TTL, playbook definitions, actions,
  and empty execute/rollback bodies are checked before forwarding.
- Added a live **Response** workspace with no fixture fallback. It exposes inert
  plans, readiness warnings, exact digests, hashed targets, approval scope and
  expiry, step checkpoints, attempts, expected/observed proof hashes, rollback,
  kill switch, connector readiness, complete audit, and governed playbook
  author/review/activation.

## Control flow

```text
deterministic deny / approval hold
                |
                v
       idempotent inert dry run
       (hashed targets, no connector)
                |
        operator requests live
                |
 connector readiness + kill switch + version
                |
                v
       independent exact-plan approval
       (expires, one use, digest bound)
                |
      distinct executor claims lease
                |
  typed step -> checkpoint -> verify expected state
                |
      success ---------------- failure
         |                        |
         v                        v
   SUCCEEDED             stop remaining steps
         |
     rollback requested
         |
  independent rollback approval
         |
 reverse typed compensation -> verify -> ROLLED_BACK
```

The simulated response embedded in the synchronous authorization result remains
the enforcement explanation. This module is a separate opt-in post-decision
plane; it cannot replay, permit, or weaken the original agent action.

## Security invariants

1. Pipeline creation is dry-run only. It has no connector, approval, or
   executor authority.
2. A raw agent/session/resource/destination identifier, prompt, tool argument,
   model payload, header, token, credential, secret, or provider body cannot
   enter a response record, read API, audit entry, or browser state.
3. Live execution requires the exact current plan, a ready typed connector, an
   unengaged current kill switch, and an unexpired independent approval.
4. The requester, approver, and executor are structurally distinct fixed
   principals. The browser cannot submit any of those identities.
5. Approval is scoped separately to forward execution or rollback and binds
   every executable plan field. Any plan mutation invalidates it.
6. The executor can call only typed policy-declared HTTP gateway operations. It
   has no general command, shell, file, import, or arbitrary-network facility.
7. A connector acceptance is not success. The expected external state must be
   independently verified before the step succeeds or a later step starts.
8. The kill switch is checked before every external effect. Its state is
   durable, versioned, signed, and tenant scoped.
9. Rollback is a new independently approved action and runs only compensating
   operations declared in the immutable playbook.
10. Reads verify enclosing records, step and attempt membership, approval
    digests, and the complete execution audit chain before presenting evidence.

## Data and private interface contract

`ResponseExecution` contains only finding/alert/case/correlation references,
immutable playbook/policy commitments, mode/state, readiness warnings, fixed
actor references, approval references, kill-switch revision, privacy-safe
ordered steps, optimistic version, timestamps, and audit/record commitments.
`ResponseStepPlan` contains a typed operation, configured connector ID, hashed
target or case ID, expected state, optional compensation, readiness/state,
attempt count, safe error code, and hashed provider/verification evidence.
`ResponseExecutionDetail` adds verified approvals, attempts, and audit entries.

Private product routes are:

- `GET /v1/response/executions`, `/v1/response/executions/{execution_id}`,
  `/v1/response/health`, `/v1/response/connectors`, `/v1/response/control`, and
  `/v1/response/playbooks`;
- `POST /v1/response/executions/{execution_id}/request-live`, `/approve`, and
  `/execute`;
- `POST /v1/response/executions/{execution_id}/request-rollback`,
  `/approve-rollback`, and `/rollback`;
- `POST /v1/response/control`, `/v1/response/playbooks`, and
  `/v1/response/playbooks/action`.

Runtime assembly requires both `AGENTSEC_RESPONSE_DB` and
`AGENTSEC_RESPONSE_CONFIG`. `AGENTSEC_RESPONSE_TENANT` is explicit or inherited
and must match every other configured product tenant. Credential variables are
named by policy; missing values create a visible not-ready state without
preventing inert plan creation.

## Verification evidence

The dedicated suite covers inert/idempotent/durable plan creation, privacy-safe
targets, restart verification, pipeline outage isolation, permission and tenant
scope, connector readiness, request/approval/executor separation, exact-plan
binding, approval consumption, forward execution, post-effect verification,
verification failure, rollback and verification, kill switch, health,
playbook lifecycle separation, retired-version integrity, audit deletion,
attempt deletion, fixed authenticated HTTP APIs, actor-spoof rejection,
environment assembly, and secret-safe connector status.

The bridge suite covers every fixed read/mutation route, exact bodies, path
traversal rejection, actor/command-field rejection, playbook validation, and
server-side bearer custody. The production UI build and source/render contracts
cover live-only response state, all guarded actions, connector/approval/attempt/
audit evidence, explicit empty/offline behavior, and the playbook editor.

Focused closure passes 55 response, bridge, pipeline, service,
schema-contract, and runtime tests. The dedicated response/bridge slice passes
29 tests, including terminal attempt-membership deletion and complete-tenant
health at 205 executions. The production Vinext build and both UI contracts
pass.

## Honest limitations and assigned follow-on work

- The checked-in gateways use reserved `.invalid` hosts and empty credentials.
  No external identity, agent control plane, network policy, ticket, or other
  vendor asset was contacted. The generic contract is not vendor certification.
- Dry run resolves and validates the immutable local plan and connector
  readiness; it does not call a provider-specific sandbox or predict provider
  authorization, race, quota, or downstream side effects.
- The local shared bearer maps UI actions to fixed service principals. It proves
  separation in the state machine, not which humans requested and approved the
  action. Per-human SSO/MFA, RBAC, step-up authentication, access review, and
  non-repudiation belong to Modules 20 and 24.
- Canonical SHA-256 values detect accidental/unauthorized row changes under the
  service trust boundary but are not keyed signatures, external timestamps, or
  an immutable transparency service. Managed signing belongs to Module 24.
- SQLite, local locks, and a bounded lease provide durable single-node
  coordination, not a distributed workflow engine. A crash after an external
  effect but before its local checkpoint deliberately surfaces uncertain/fail-
  closed state and needs operator reconciliation; it is never auto-replayed.
- The provider-neutral adapter cannot eliminate every DNS/network race and is
  not a production egress proxy. Managed egress, workload identity, private
  gateways, secrets, connector certification, observability, SLOs, backup/DR,
  and HA belong to Module 24.
- Playbook editing is strict JSON and fixed-form local UI authoring. Module 20
  owns the complete authenticated analyst experience, accessible design system,
  reporting, and administrative UX.

## Acceptance closure

Module 19 is verified. The complete `make verify` gate passed while the catalog
honestly reported 18/24: 337 Python tests, 5 TypeScript SDK tests, 261 generated
schema checks, 10 deterministic evaluation records, clean-install reproduction,
compilation, secret scan, dependency validation, release audit, workflow and
Codex demonstrations, all evaluation modes, and the control ablation. Promotion
then produced a valid 19/24 module audit; the dedicated response/bridge slice and
production UI contracts also pass after promotion.
