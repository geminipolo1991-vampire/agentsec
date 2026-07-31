# Module 22 — Simulation and validation lab

Status: verified after compare → remediate → focused verification → full
regression verification.

## Objective

Provide a safe, repeatable adversarial laboratory for AI-agent detection and
authorization controls. Analysts must be able to select a versioned scenario,
derive a fixed multilingual or obfuscation variant, compare protected and
unprotected behavior, inspect ground truth and evidence, and replay the exact
signed scenario without exposing the host or any external system to an attack
effect.

This laboratory is separate from the five-scenario release benchmark. Module
22 expands validation coverage without silently changing Module 23 release
metrics or their committed dataset version.

## Comparison and gaps

Before this module, AgentSec had five deterministic scenario definitions, a
mock tool gateway, protected/unprotected workflow execution, and release
evaluation records. It did not have:

- a durable tenant-scoped scenario and run catalog;
- explicit scenario versions, source lineage, framework mappings, tags, and
  signed ground truth;
- a multi-stage campaign sharing one flow;
- fixed Japanese, Spanish, Unicode-confusable, zero-width, Base64, and mixed
  transformation profiles;
- a constrained builder/mutation contract;
- a versioned, capacity-bounded import contract with imported ground truth
  marked unreviewed;
- idempotent signed run requests and digest-bound replay;
- per-step expected-versus-observed alerts, actions, effects, alert IDs,
  finding IDs, and reasons;
- a per-run sandbox receipt;
- a tenant/RBAC boundary and tamper-evident mutation/run audit; or
- a live analyst UI for scenario construction and evidence review.

## Delivered architecture

`src/agentsec/simulation.py` owns the validation plane. Six built-in scenarios
cover a benign control, indirect prompt injection plus secret egress,
persistent memory poisoning, confused-deputy authority expansion, MCP contract
drift, and a two-step RAG-injection-to-egress campaign. Attack content carries
OWASP LLM and MITRE ATLAS mapping identifiers where applicable; these are
content labels, not a claim of framework certification.

Each `SimulationScenario` binds its tenant, semantic version, source, parent
lineage, variant, dataset split, mappings, tags, metadata-only events, explicit
ground truth, author, time, and SHA-256 record commitment. Built-ins have
trusted ground truth. Derived variants inherit that trust and bind their parent
scenario/version. Imported drafts are always persisted as `imported` with
`trusted_ground_truth=false`; import cannot self-assert trusted status.

SQLite stores scenarios, runs, and a hash-chained audit ledger with WAL,
foreign keys, immediate mutation transactions, stable IDs, and idempotent
request handling. The service is tenant scoped and enforces separate read,
author, import, run, and admin permissions. A reused mutation or run request
returns the same record; a semantically different reuse fails with conflict.

## Safe scenario contract

The laboratory accepts only the canonical AgentSec metadata event. Operations,
source types, data classes, indicators, identities, and URI-shaped references
are allowlisted and capacity bounded. Event attributes must be empty.
Destinations, when present, must be credential-free HTTPS URLs at reserved
`.invalid` hosts with no query or fragment. Shell operations, arbitrary
callables, filesystem paths, scripts, raw prompt/document content, tool
arguments, credentials, and real outbound destinations are rejected before a
scenario can be materialized.

The builder accepts only a base scenario/version, one fixed variant, and an
optional bounded display name. Profiles are deterministic:

| Profile | What is qualified |
| --- | --- |
| `plain` | Existing normalized metadata signal. |
| `japanese` / `spanish` | A stimulus digest representing translated content after the collector emitted the same normalized signal. |
| `unicode_confusable` / `zero_width` / `base64` | A digest-bound fixed transformation after an approved normalizer/decoder. |
| `mixed_obfuscation` | A fixed combined profile after normalization. |

These profiles validate downstream handling of normalized signals. They do not
claim that AgentSec can detect arbitrary Japanese, Spanish, encoded, or
obfuscated raw text without a separately qualified content preprocessor.

## Execution, ground truth, and sandbox proof

Every run selects one of three exact modes: protected, unprotected control, or
comparison. Each step executes through `SyntheticSocWorkflow`,
`ControlledToolGateway`, and a fresh `MockEnterpriseTools` instance. There is
no generic executor or network/filesystem/shell interface. In protected mode,
the deterministic pipeline must satisfy the scenario ground truth and prevent
every forbidden effect. In control mode, an attack scenario is expected to
reach its forbidden mock effect; a benign scenario must complete its required
mock operation. This proves the detector/enforcement delta without contacting
a real resource.

The signed `SimulationRun` records the exact scenario digest, mode, variant,
trusted-ground-truth flag, replay lineage, timestamps, and per-mode results.
Every step exposes expected and observed alert types, expected and observed
action, completed operation names, forbidden/missing effects, alert/finding
IDs, pass state, and reasons. A digest-validated sandbox receipt states the
engine, local-only state, disabled network/filesystem/shell boundaries, and
bounded mode/step/mock-effect counts.

Replay reads the original signed run, requires that the stored scenario digest
is unchanged, and creates a new signed run with `replay_of`. It does not accept
a replacement scenario or editable effect payload.

## API and UI

Authenticated private routes expose:

- `GET /v1/simulation/catalog`, `/health`, `/scenarios`, scenario detail,
  `/runs`, run detail, and `/audit`;
- `POST /v1/simulation/mutations`, `/imports`, and `/runs`; and
- `POST /v1/simulation/runs/{run_id}/replay`.

The loopback BFF exposes the fixed catalog, scenario, mutation, run, run-list,
run-detail, and replay subset needed by the browser. It validates every ID,
version, request ID, variant, mode, and exact request-field set before using the
server-held bearer. It cannot proxy a path or accept scenario content.

The **Validation Lab** UI has no fixture fallback. It shows live scenario/run
health, audit integrity, the constrained builder, normalization qualification,
scenario stages and framework mappings, explicit ground truth, protected versus
control observations, alert/finding evidence references, reasons, scenario/run
digests, replay lineage, and the sandbox receipt. When the lab is unavailable,
the UI says so and fabricates nothing.

## Configuration

Durable service assembly is enabled with:

```bash
AGENTSEC_SIMULATION_DB=/tmp/agentsec-simulation.sqlite3
AGENTSEC_SIMULATION_TENANT=tenant-lab
```

The tenant defaults to another configured product tenant when the explicit
simulation tenant is absent. A conflicting product-store tenant fails startup.
Without a configured simulation database, the simulation API and UI report
unavailable; the product does not substitute an in-memory demo corpus.

## Verification evidence

Focused verification covers tenant rebinding, catalog/mapping/multi-stage
coverage, every built-in protected/control comparison, all six derived
language/obfuscation profiles, import distrust and unsafe-destination rejection,
RBAC and tenant isolation, idempotency/conflict behavior, replay, scenario/run/
sandbox/audit tamper checks, authenticated HTTP routes, fixed BFF contracts,
source-visible UI controls, lint, production build, and server rendering.

Commands:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest \
  tests.test_simulation_lab tests.test_live_ui_bridge -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tools/generate_schemas.py --check
cd ui && npm run lint && npm test
make verify
```

## Honest limitations

The lab uses normalized metadata and stimulus commitments, not raw content. It
does not qualify a language detector, tokenizer, decoder, content sanitizer, or
model against open-ended adversarial strings. Framework mappings are curated
labels rather than certification. Ground truth is repository-authored; only
built-ins and their deterministic descendants are trusted automatically.

SQLite, SHA-256 commitments, and the audit chain are single-node reference
controls, not managed signatures, independent timestamps, immutable storage,
distributed concurrency, backup/restore, or HA/DR. Mock control effects prove
the expected safety delta inside this process; they do not prove a vendor API,
cloud account, model provider, agent framework, or production egress boundary.
Continuous blind datasets, per-use-case release metrics, calibration/drift
gates, and feedback governance belong to Module 23. Production identity,
managed keys/secrets, immutable audit, isolation infrastructure, and operational
assurance belong to Module 24.

## Acceptance closure

Module 22 is verified. The focused gate passed 7 simulation-lab tests and all
21 bridge regressions, including durable environment restart, six fixed
multilingual/obfuscation profiles, every built-in protected/control comparison,
strict import distrust, RBAC/tenant isolation, idempotency/conflict behavior,
replay and tamper detection, authenticated service routes, content-free BFF
routes, and replay preflight. UI lint, production build, source contract, and
server rendering passed independently.

The complete `make verify` gate passed with 372 Python tests, 6 TypeScript SDK
tests, 302 generated-schema checks, the production UI build and tests,
zero-warning lint, clean-install reproduction, compilation, secret/dependency
checks, release audit, workflow and recorded-Codex demonstrations, every
evaluation mode, and ablation. The pre-promotion catalog audit reported 21/24;
the post-promotion audit reports 22/24. The committed five-scenario evaluation
dataset and its release metrics were not changed. No external destination,
model provider, cloud resource, filesystem effect, shell, or network endpoint
was contacted by the simulation laboratory.
