# AgentSec Control Room UI

Responsive analyst interface for the AI-Agent Security research PoC. The alert
queue reads sanitized live authorization decisions through a loopback bridge.
It does not use fixed alert fixtures; without the local service it shows an
explicit offline/empty state.

Views:

- Overview and incident decision queue
- Seven-stage authorization trace
- Seven-tab incident investigation workspace, including the five-role AI analyst run
- Live indexed threat-hunting query editor, aggregations, saved hunts, and safe evidence pivots
- Live temporal AI security graph, weighted attack paths, and blast-radius analysis
- Live signed Rule Studio with test, review, shadow, publish, rollback, and audit evidence
- Live Risk Analytics with hashed baselines, anomaly evidence, drift, and governed tuning
- Live correlated Incidents with sequence, link proof, risk rollup, merge, and split
- Live Cases with assignment, acknowledgment/resolution SLA, comments, tasks, attachment scan state, relationships, four-eyes review, and hash-chain audit
- Live Escalations with policy routes, four channel destinations, delivery attempts, dead letters, provider receipt proof, human acknowledgment SLA, and hash-chain audit
- Live Response with inert dry runs, hashed targets, separation-of-duty approvals, typed connector execution, post-effect verification, rollback, kill switch, and reviewed playbook revisions
- Live Validation Lab with versioned scenarios, fixed multilingual/obfuscation variants, protected/control ground truth, replay, and signed sandbox evidence
- Deterministic policy catalog
- Eight-mode effect/ablation comparison plus a 42-case blind continuous gate with per-use-case, calibration, candidate identity, and baseline-drift evidence
- Live model gateway routes, qualifications, budgets, circuits, prompt digests, and sanitized calls
- Live Reports with committed release criteria, evaluation artifact digests, module completion, and sanitized snapshot download
- Read-only Administration with tenant policy, RBAC/access review, workload/key lifecycle, immutable audit, SLO/recovery/supply-chain evidence, and explicit production non-claims
- Allowlisted live POC event forge

## Complete local POC

Run the complete live product locally in three terminals from the repository
root. Use the same token in terminals 1 and 2; replace the example before using
this outside an isolated local demo.

Terminal 1 — local AgentSec service:

```bash
AGENTSEC_INGEST_TOKEN='local-demo-token-change-me-1234567890' \
  AGENTSEC_CANONICAL_DB='/tmp/agentsec-canonical.sqlite3' \
  AGENTSEC_SEARCH_DB='/tmp/agentsec-search.sqlite3' \
  AGENTSEC_SEARCH_TENANT='tenant-lab' \
  AGENTSEC_SEARCH_CURSOR_SECRET='local-search-cursor-change-me-123456789' \
  AGENTSEC_INVENTORY_DB='/tmp/agentsec-inventory.sqlite3' \
  AGENTSEC_INVENTORY_TENANT='tenant-lab' \
  AGENTSEC_INVENTORY_APPLICATION_ID='authorization-service' \
  AGENTSEC_GRAPH_DB='/tmp/agentsec-graph.sqlite3' \
  AGENTSEC_GRAPH_TENANT='tenant-lab' \
  AGENTSEC_POSTURE_DB='/tmp/agentsec-posture.sqlite3' \
  AGENTSEC_POSTURE_TENANT='tenant-lab' \
  AGENTSEC_DETECTION_DB='/tmp/agentsec-detection.sqlite3' \
  AGENTSEC_DETECTION_TENANT='tenant-lab' \
  AGENTSEC_CONTENT_DB='/tmp/agentsec-content.sqlite3' \
  AGENTSEC_CONTENT_SIGNING_KEY='local-content-signing-key-change-me-123456789' \
  AGENTSEC_BEHAVIOR_DB='/tmp/agentsec-behavior.sqlite3' \
  AGENTSEC_BEHAVIOR_TENANT='tenant-lab' \
  AGENTSEC_CORRELATION_DB='/tmp/agentsec-correlation.sqlite3' \
  AGENTSEC_CORRELATION_TENANT='tenant-lab' \
  AGENTSEC_CASE_DB='/tmp/agentsec-cases.sqlite3' \
  AGENTSEC_CASE_TENANT='tenant-lab' \
  AGENTSEC_NOTIFICATION_DB='/tmp/agentsec-notifications.sqlite3' \
  AGENTSEC_NOTIFICATION_CONFIG="$PWD/configs/notification-policy.example.json" \
  AGENTSEC_NOTIFICATION_TENANT='tenant-lab' \
  AGENTSEC_RESPONSE_DB='/tmp/agentsec-response.sqlite3' \
  AGENTSEC_RESPONSE_CONFIG="$PWD/configs/response-playbooks.example.json" \
  AGENTSEC_RESPONSE_TENANT='tenant-lab' \
  AGENTSEC_SIMULATION_DB='/tmp/agentsec-simulation.sqlite3' \
  AGENTSEC_SIMULATION_TENANT='tenant-lab' \
  AGENTSEC_ADMIN_DB='/tmp/agentsec-administration.sqlite3' \
  AGENTSEC_ADMIN_TENANT='tenant-lab' \
  AGENTSEC_ADMIN_CONFIG="$PWD/configs/administration.example.json" \
  AGENTSEC_ADMIN_ASSERTION_KEY='local-admin-assertion-change-me-123456789' \
  AGENTSEC_ADMIN_CHECKPOINT_KEY='local-admin-checkpoint-change-me-123456' \
  AGENTSEC_ANALYST_DB='/tmp/agentsec-analyst.sqlite3' \
  AGENTSEC_ANALYST_RECORDING="$PWD/configs/codex-analyst-evaluation.json" \
  AGENTSEC_ANALYST_TENANT='tenant-lab' \
  AGENTSEC_AI_MODE=shadow \
  PYTHONPATH=src python3 -m agentsec serve --host 127.0.0.1 --port 8080
```

Terminal 2 — token-owning loopback bridge (local mode is the default):

```bash
AGENTSEC_INGEST_TOKEN='local-demo-token-change-me-1234567890' \
  PYTHONPATH=src python3 tools/live_ui_bridge.py
```

Terminal 3 — UI:

```bash
cd ui
npm run dev
```

Open <http://localhost:3000>. Choose an allowlisted scenario and select
**Forge live event**. The service executes the real local pipeline, persists the
authoritative incident and canonical search projections, and the UI refreshes
with the recorded details. Open **Threat Hunting** to query those live records;
open **Inventory** to inspect the live discovered application, agent, model, and
tool components, permissions, risk, and configuration history. No alert or
inventory fixture is displayed. Open **Security Graph** to inspect the live
topology, select source and target nodes, highlight weighted paths, calculate
blast radius, or load a historical timestamp. The graph also has no fixture
fallback. Open **Posture** to run the versioned checks over the current
inventory, inspect safe evidence and remediation, review score trends, and
create or revoke time-bounded risk exceptions. No posture fixture is displayed.
Open **Rule Studio** to author a strict declarative rule, run deterministic
positive/benign tests, backtest safe presets, submit for an independent review,
evaluate it in shadow, acknowledge its exact digest, publish it to the live
detection engine, inspect signed revision history, or create a new-version
rollback. No rule fixture is displayed: the workspace is empty/offline when the
content service is not configured.
Open **Risk Analytics** to inspect the actual accepted-event baselines, anomaly
and composite scores, per-factor probability/contribution/rationale/evidence,
entity-level scoring, final learning eligibility, tenant/entity drift, and
immutable tuning versions. Entity references are hashed and the workspace
shows no fallback records when the behavior service is empty or offline.
Open **Incidents** to inspect first-class campaign records, the ordered attack
sequence, every linked finding and grouping reason/score, risk rollup,
correlation decision ledger, digest/audit receipt, and governed lifecycle,
merge, or split. No fallback incident is shown when correlation is unavailable.
Open **Cases** to operate the durable human workflow: assign a team/member,
acknowledge and investigate, add redacted notes and tasks, inspect safe
attachment metadata and relationships, request independent review, close or
reopen, and verify the committed audit chain. No case fixture is shown when the
case service is empty or unavailable.
Open **Escalations** to inspect the live policy route, versioned on-call owner,
ticket/email/messaging/on-call delivery messages, attempts, safe error codes,
provider receipt hashes, human acknowledgment clock, dead-letter redrive, and
committed audit chain. The checked-in policy uses `.invalid` endpoints and no
credentials, so it demonstrates a secret-safe not-ready state without sending
network traffic. Configure only reviewed HTTPS gateways and export the four
credential variables named by the policy when testing real delivery.
Open **Response** to inspect every signed dry run, readiness warning, hashed
target, exact plan and policy digest, independent approval, connector attempt,
post-effect verification, rollback, kill switch, and audit entry. The playbook
editor creates drafts only; author, reviewer, and activator are fixed separate
service identities. The checked-in endpoints use `.invalid` hosts and the
credential variables are empty, so live execution is visibly not ready and no
external asset is changed. Configure only an independently reviewed response
gateway before exercising live actions.
Open **Validation Lab** to select a versioned built-in scenario, derive a fixed
Japanese, Spanish, Unicode-confusable, zero-width, Base64, or mixed metadata
variant, and run protected/control comparisons. The view shows explicit ground
truth, observed alerts/actions/mock effects, alert and finding IDs, replay
lineage, signed scenario/run records, and a local-only sandbox receipt. It does
not accept or retain raw prompts and shows no fixture when the simulation
service is unavailable.
Open **Integrations** to inspect only the live model control plane: exact model
routes and stages, unexpired qualification, privacy/mode policy, budget use,
circuit and secret readiness, immutable prompt/schema digests, independent test
evidence, and sanitized calls. When the gateway is absent or empty, the view is
explicitly offline/empty and does not display static provider readiness cards.
Open **Reports** to inspect the committed release audit, evaluation manifest,
exact file/record digests, production non-claim, and 24-module ledger. Open
**Administration** to inspect live tenant policy, role/access-review counts,
workload and managed-key state, append-only audit checkpoint, SLO/error budget,
recovery drill, supply-chain attestation, fixed product health probes, and the
BFF trust receipt. It explicitly reports that enterprise IdP/KMS/residency/HA
and production readiness are not verified. Both read `GET /api/platform`; if
the bridge, service, or report is
unavailable, the corresponding value remains unavailable and is never replaced
by a sample metric.

Open **Evaluations** to inspect the manifest-bound deterministic baseline and
recorded Codex candidate. The workspace shows the PASS/BLOCK/HOLD gate, 42-case
and 24-holdout corpus profile, exact candidate identity, Brier/calibration
scores, drift receipt, and recall/severity/evidence/safe-action metrics for each
AI-security use case. The three-actor feedback boundary is descriptive; the
browser cannot submit, review, or publish benchmark corrections.

The default command above intentionally uses the recorded Codex analyst and
does not require external credentials. For a governed live-provider trial,
review `configs/model-gateway.example.json`, replace its placeholder exact model
IDs, export the referenced provider keys, remove `AGENTSEC_ANALYST_RECORDING`,
and add `AGENTSEC_MODEL_GATEWAY_DB`, `AGENTSEC_MODEL_GATEWAY_CONFIG`, and
`AGENTSEC_MODEL_GATEWAY_TENANT`. Startup seeds candidates only; qualification,
shadow observation, and explicit activation are still required.
If port 3000 is occupied,
vinext may use port 3001; both local origins are allowlisted by the bridge.

The bridge binds only to `127.0.0.1:8765`, accepts browser writes only from the
local UI origins, and never sends `AGENTSEC_INGEST_TOKEN` to the browser. The
bridge owns the token, and its upstream URL is restricted to a literal
`127.0.0.1` HTTP origin. Arbitrary commands and arbitrary event payloads are not
accepted.

Build and test:

```bash
npm run build
npm run lint
npm test
```

The model provider remains `codex-recorded-shadow`; deterministic policy makes
the enforcement decision. Public UI hosting remains disabled for this POC.

## Investigation MVP

New events forged while the bridge is running include a presentation-oriented
investigation trace. Select an alert marked **COMPLETE**,
then walk through:

1. **Summary** — policy proof, detector confidence, safe evidence references, and why triage treated the alert as real
2. **Timeline** — actual timestamps, outcomes, and allowlisted evidence for all seven stages
3. **Enrichment** — nine built-in plus configured live-source cards with status, connector version, policy decision, confidence, facts, hashed evidence, latency, cache freshness/staleness, and failure behavior
4. **Triage** — actual risk score, priority, contribution breakdown, route, SLA, warnings, and ledger receipt
5. **Judgment** — detector recommendation, deterministic action, model citation/confidence validation, human gate, non-executive Codex review, and final authoritative action
6. **AI Analyst** — five governed roles, mandatory evidence, structured claims, exact matches/conflicts, calibrated confidence, contradictions, injection isolation, alternatives, uncertainty, tool receipts, report/run digests, and explicit non-executive status
7. **Response & Audit** — escalation, effect status, containment, privacy receipt, state history, and human analyst transitions

The current source implements an **AUTHORITATIVE PIPELINE RESULT** derived from
the exact pipeline result used for enforcement. Missing historical detail is
never replayed or reconstructed; older records remain **SUMMARY ONLY**. The
in-memory store is not a durable production incident database, so restarting the
service clears the local incident queue.
