# Module 23 — Evaluation and continuous improvement

Status: verified after compare → remediate → focused verification → full
regression verification.

## Objective

Qualify AgentSec detection, enforcement, evidence, and model-assisted analysis
against a versioned blind benchmark before a release is allowed. The evaluator
must measure outcomes rather than fluent explanations, preserve exact candidate
identity, expose per-use-case quality and calibration, compare with an approved
baseline, and turn analyst feedback into a reviewed dataset proposal without
allowing feedback to train a model or change production directly.

This control plane complements the small five-scenario effect-ablation suite in
`src/agentsec/evaluation.py`. The original suite remains a fast deterministic
regression. Module 23 adds a larger, independently versioned release-qualification
track and does not reinterpret the original metrics.

## Comparison and gaps

Before this module, AgentSec had a versioned five-scenario corpus, deterministic
and recorded-Codex modes, control ablations, committed JSON reports, and a
manifest integrity check. It did not have:

- a candidate-blind execution contract that excludes expected labels;
- enough cases to gate every supported use case and transformation profile;
- explicit development, validation, and holdout splits;
- per-use-case precision, recall, severity, evidence, and action agreement;
- benign completion, forbidden-effect, schema, abstention, calibration, and
  latency metrics in one signed report;
- exact provider, model, route, qualification, dataset, policy, and baseline
  commitments;
- an explicit qualified live-provider candidate boundary;
- baseline approval and release-blocking drift thresholds;
- durable tenant/RBAC runs, idempotency, restart recovery, and chained audit;
- a controlled analyst-feedback-to-dataset workflow with separation of duties;
- a CI gate that fails when the committed continuous reports drift; or
- an analyst UI that exposes candidate identity, release state, calibration,
  drift, and per-use-case evidence.

## Delivered architecture

`src/agentsec/continuous_evaluation.py` owns the Module 23 plane.

```text
versioned sealed dataset
  |-- candidate-visible BlindEvaluationCase (metadata + stimulus commitment)
  `-- evaluator-only ground truth (digest committed)
                         |
           exact qualified candidate adapter
          / deterministic | recorded | live \
                         |
             isolated fresh pipeline per case
                         |
       effect + alert + severity + evidence + action result
                         |
        aggregate / split / per-use-case metrics
                         |
        absolute gates + approved-baseline drift gates
                         |
      immutable run + SQLite audit + CI report manifest
                         |
          private API + evidence-only Evaluations UI
```

The built-in `benchmark-2026.07.24.1` dataset contains 42 cases: six use cases
times seven fixed variants. The variants are plain, Japanese, Spanish, Unicode
confusable, zero-width, Base64, and mixed obfuscation. Six plain cases are the
development split, twelve language cases are validation, and the remaining 24
cases are holdout regressions. The use cases cover a benign control, prompt
injection plus egress, memory poisoning, authority expansion, MCP supply-chain
drift, and a multi-stage RAG-to-egress sequence.

These repository-visible holdouts protect against accidental regression; they
are not secret, statistically representative, or independent external test
data. Variant qualification begins after the collector or preprocessor emits
normalized metadata. It does not prove open-ended raw-text, multilingual,
encoding, or tokenizer robustness.

## Blinding and integrity

Each sealed case contains a `BlindEvaluationCase` and separate
`EvaluationGroundTruth`. Candidate code receives only the blind object. Its
schema deliberately has no attack label, expected alerts, expected severity,
expected action, forbidden-effect label, or allowed evidence list. The blind
stimulus, ground truth, complete dataset, threshold policy, candidate route,
candidate qualification, baseline, report, and committed artifact all have
canonical SHA-256 commitments. Pydantic validation rejects a changed commitment
on load.

This is process-level blinding, not protection against a malicious candidate
that reads this public repository by another channel. Production qualification
needs a separately controlled evaluation service and confidential external
holdout store.

Every case gets a fresh `SecurityPipeline` and controlled mock effect boundary.
Provider exceptions and invalid model output become an abstained, schema-invalid,
effect-denied result; they never become a passing or permissive prediction.
Evidence citations are valid only when they reference evidence produced for the
current case. Unknown or fabricated references fail the evidence gate.

## Metrics and release policy

The evaluator produces overall, split, and per-use-case metrics for:

- alert precision and detector recall;
- forbidden-effect attack success and benign-task completion;
- exact and within-one severity agreement;
- evidence-reference validity;
- exact and safe-action agreement;
- abstention and selective accuracy;
- Brier score and expected calibration error;
- output-schema validity; and
- mean and p95 case latency.

`configs/continuous-evaluation-policy.json` is digest bound. The current bounded
release corpus requires 42 cases, seven cases per use case, perfect precision,
recall, benign completion, severity, evidence, safe action, and schema validity,
zero forbidden effects, at most ten percent abstention, Brier score at most
0.05, and expected calibration error at most 0.10. These strict fixture
thresholds are appropriate because every expected result is deterministic.
They are not a promise of these rates on real-world traffic.

An approved candidate run can become a baseline only through
`evaluation:review`. Later reports bind the active baseline record digest and
apply maximum-regression checks to effect safety, precision, recall, severity,
evidence, action, benign completion, abstention, and Brier score. Any failed
absolute or drift check produces `block`; an unqualified live candidate produces
`hold` or is rejected before execution. CI accepts only a passing candidate with
a passing, digest-matched baseline comparison.

## Candidate tracks and live-model boundary

Three candidate kinds are explicit:

| Track | Provider activity | Purpose |
| --- | --- | --- |
| `deterministic` | None | Trusted control baseline using the AgentSec deterministic pipeline. |
| `recorded_model` | None | Reproducible Codex recording with exact model/profile and recording commitments. |
| `live_model` | Only on an explicit run | Injected provider adapter with exact provider/model, route digest, and non-empty qualification digest. |

The repository release uses recorded Codex, not a live API call. A live
OpenAI- or Anthropic-backed candidate must be constructed explicitly with
`live_model_candidate`; it cannot be inferred from an API key or silently
activated. The adapter receives no runtime response authority. Its route and
qualification commitments must be created by the model-gateway governance
process, and provider network egress occurs only when an authorized operator
submits that exact candidate run. Module 23 evaluates a configured candidate;
it does not claim that any current provider model is generally qualified.

## Durable service, API, and authorization

`ContinuousEvaluationService` persists datasets, run records, approved
baselines, feedback proposals, and a tenant hash-chained audit ledger in SQLite.
It uses WAL, foreign keys, immediate mutation transactions, canonical record
commitments, stable IDs, bounded pages, and request idempotency. Reusing a
request ID with identical meaning returns the original record; changing its
meaning fails with conflict. Reads validate signed records after restart.

Permissions are separate: `evaluation:read`, `evaluation:run`,
`evaluation:feedback`, `evaluation:review`, and `evaluation:admin`. A principal
tenant must equal the service tenant. Product assembly also rejects a Module 23
tenant that differs from another configured product plane.

Authenticated private routes expose:

- `GET /v1/evaluations/catalog`, `/health`, `/runs`, run detail, `/feedback`,
  feedback detail, and `/audit`;
- `POST /v1/evaluations/runs`;
- `POST /v1/evaluations/runs/{run_id}/baseline`; and
- `POST /v1/evaluations/feedback`, feedback review, and feedback promotion.

IDs, enum filters, pagination, payload schemas, content type, and bearer access
are validated. The browser does not receive a generic evaluation proxy. The
Evaluations workspace consumes only the fixed, manifest-bound baseline and
candidate release records projected by `/api/platform`.

## Governed improvement workflow

Analyst feedback is evidence for review, never an online-learning command.
Promotion requires three distinct identities:

1. A submitter commits the source feedback/run/rating, target case, proposed
   ground truth, and rationale hashes.
2. A different reviewer approves or rejects that exact proposal.
3. A third publisher promotes an approved proposal into a new immutable dataset
   version with parent-dataset lineage.
4. The new dataset must be evaluated again and pass absolute and drift gates.

The proposal and health records permanently state
`source_applied_to_model=false`, `applied_to_model=false`,
`applied_to_runtime_policy=false`, `direct_learning_enabled=false`, and
`runtime_policy_mutation_enabled=false`. This workflow cannot update detector
rules, prompts, model weights/routes, thresholds, authorization policy,
playbooks, or response actions.

## UI and committed release evidence

`tools/write_release_reports.py` deterministically creates
`continuous-baseline.json` and `continuous.json` along with the original release
records. The evaluation manifest binds the byte SHA-256 and internal record
digest of every artifact. `tools/verify_continuous_evaluation.py` validates the
artifact hashes, schemas, policy digest, candidate kinds, provider identity,
minimum case/split/use-case coverage, absolute gate, drift result, and exact
baseline digest. `make check-reports`, `make continuous-evaluate`, and therefore
`make verify` fail closed on drift.

The fixed loopback BFF loads only allowlisted report filenames under size bounds
and verifies their manifest hashes before projection. The Evaluations UI shows
the 42-case profile, holdout count, release and drift state, exact candidate
identity, provider/model/route/record commitments, recall, severity, evidence,
abstention, Brier score, calibration error, and a six-row per-use-case table. It
also explains the three-actor feedback boundary. Missing or invalid records
produce an unavailable state; the screen does not invent evaluation values.

## Configuration

Enable the durable local evaluation plane with:

```bash
AGENTSEC_EVALUATION_DB=/tmp/agentsec-evaluation.sqlite3
AGENTSEC_EVALUATION_TENANT=tenant-lab
AGENTSEC_EVALUATION_POLICY=configs/continuous-evaluation-policy.json
AGENTSEC_EVALUATION_RECORDING=configs/codex-evaluation.json
```

The tenant may inherit another configured product tenant. A policy or recording
without a database fails startup. The recording is optional; without it the
service exposes only the deterministic candidate unless the embedding
application explicitly injects another qualified candidate.

## Verification evidence

Focused tests cover dataset size and every variant, split and label blinding,
dataset/policy/report tamper rejection, recorded-Codex absolute gates,
per-use-case metrics, calibration, weak-candidate regression blocking,
provider outage, invalid output, fabricated evidence, explicit live-candidate
qualification, durable runs and baselines, request idempotency/conflict,
restart recovery, tenant/RBAC isolation, audit integrity, authenticated HTTP
routes, three-actor feedback promotion, fixed manifest-bound BFF projection,
schema generation, UI source contracts, lint, production build, and server
rendering.

Commands:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest \
  tests.test_continuous_evaluation tests.test_live_ui_bridge -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tools/generate_schemas.py --check
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tools/verify_continuous_evaluation.py
cd ui && npm run lint && npm test
make verify
```

## Honest limitations

The 42 cases are deterministic, repository-authored, repository-visible, and
derived from six scenario families. They do not estimate production prevalence,
novel attack recall, real false-positive rate, demographic or language fairness,
provider reliability, cost, or tail latency. The confidence values make the
fixture calibration checks reproducible; they are not empirical probability
calibration against a representative population. A live qualification requires
separately governed confidential holdouts, repeated canaries, independent
labeling, statistical confidence intervals, and current provider review.

Recorded Codex proves reproducibility, not a current live Codex call. No OpenAI
or Anthropic endpoint is contacted by the committed tests, and no provider is
claimed qualified. SHA-256 commitments and a local audit chain provide tamper
evidence, not trusted signatures, external timestamps, or immutable retention.
SQLite is a single-node reference store, not distributed scheduling, global
quota, managed backup/restore, HA/DR, or a production analytics warehouse.
Per-human SSO/MFA, organization RBAC, managed service identity, KMS/HSM keys,
immutable audit storage, retention/residency administration, operational SLOs,
and supply-chain enforcement belong to Module 24.

## Acceptance closure

Module 23 is verified. The focused gate passed all 9 continuous-evaluation
tests and all 21 bridge regressions, including sealed-label blinding, 42-case
variant/split coverage, recorded-Codex metrics, absolute and baseline-drift
blocking, provider outage and fabricated evidence, live-candidate qualification,
durable baseline and feedback governance, authenticated HTTP routes, manifest-
bound UI projection, and tamper rejection. The UI production build, source and
render contracts, and zero-warning lint also passed.

The complete `make verify` gate passed with 381 Python tests, 6 TypeScript SDK
tests, 326 generated-schema checks, 12 deterministic manifest-bound evaluation
records, the continuous release gate, clean-install reproduction, compilation,
secret and dependency checks, release audit, workflow and recorded-Codex demos,
all eight original evaluation modes, and ablation. The post-promotion module
catalog reports 23/24. No live model provider, external destination, cloud
resource, shell, or production effect was contacted by Module 23 verification.
