# AI-Agent Security

This repository implements a provider-neutral security reference monitor and a
closed-loop SOC workflow for AI agents. The executable lifecycle is:

```text
Agent event -> Detection -> Ingestion -> Triage -> Judgment
            -> Escalation -> Response -> Verified outcome
```

The complete component, data, security, deployment, and pilot-target design is
in [`docs/architecture.md`](docs/architecture.md).

The deterministic security path does not depend on an LLM. Codex is represented
by a versioned offline shadow-review record; model output can preserve or tighten
a deterministic decision, never relax it. Disabled-by-default OpenAI Responses
and Anthropic Messages adapters implement the same locally validated contract.

## Research PoC

The PoC forges local benign and malicious agent events and runs them through two
agent adapter styles, a controlled tool gateway, deterministic detectors, an
idempotent hash-chained ledger, triage, judgment, escalation, and simulated safe
response. Supporting controls cover attenuating authority, exact approvals,
provenance, ABOM drift, causal paths, signed checkpoints, effect reconciliation,
privacy transforms, Splunk HEC contracts, and provider-neutral model review. It
never contacts a real enterprise system or sends test data externally.

Run the verification suite:

```bash
make test
```

Run the safe demonstration:

```bash
make demo
```

Compare vulnerable and protected four-agent workflows. Both sides use mock tools;
"unprotected" means the forbidden effect reaches only the local fake receiver:

```bash
make workflow-demo
```

Replay the structured verdicts reviewed by Codex in shadow mode. The recording is
offline and versioned; this command does not pretend to make a live API call:

```bash
make codex-demo
```

Run the versioned corpus evaluation, ablations, and all verification gates:

```bash
make evaluate
make evaluate-all
make ablate
make verify
```

Regenerate Pydantic-derived JSON Schemas with `make schemas`; `make
check-schemas` fails when committed contracts drift. `make reports` regenerates
digest-bound evaluation records; `make check-reports` fails on byte drift. `make
clean-install` builds the package offline in a fresh virtual environment and
reproduces the deterministic evaluation and protected workflow demo.
`make verify` also scans for common committed secrets, validates installed
dependencies, and writes the machine-readable `reports/release-audit.json`.

Run the local authorization service only with an explicit bearer token:

```bash
AGENTSEC_INGEST_TOKEN='replace-with-at-least-32-random-characters' \
  PYTHONPATH=src python3 -m agentsec serve --host 127.0.0.1 --port 8080
```

`POST /v1/authorize` accepts the strict `AgentEvent` contract and returns an
allowlist-built decision plus privacy-safe incident details derived from the
exact `PipelineResult` used for enforcement. The detail includes ingestion,
triage contributions, enrichment, judgment, escalation, response, audit, and
validation evidence; raw attributes and prompt content are never echoed.

Container and no-ingress EC2 Tokyo preparation is documented in
[`deploy/ec2-tokyo/README.md`](deploy/ec2-tokyo/README.md). The template is
validation-only until an operator explicitly approves creating billable AWS
resources.

The research-PoC evidence matrix is in
[`docs/release-audit.md`](docs/release-audit.md). The result is not a production
authorization; read [`docs/limitations.md`](docs/limitations.md) before using or
extending it.

## Analyst interface

The responsive AgentSec Authorization Control Room is in [`ui/`](ui/). Its
incident queue polls sanitized live decisions from the private Tokyo EC2
service through the loopback-only [`tools/live_ui_bridge.py`](tools/live_ui_bridge.py).
It also provides a six-stage decision trace, policy catalog, evaluation
comparison, provider readiness view, and an allowlisted live POC event forge.
See [`ui/README.md`](ui/README.md) for the two-terminal startup steps.

The long-form design is in
[`agent-security-detailed-implementation-plan.md`](agent-security-detailed-implementation-plan.md).

## Safety invariants

- Every effect is judged before execution.
- Delegation can preserve or reduce authority, never expand it.
- Untrusted provenance survives transformations and handoffs.
- `deny > require_approval > allow_with_obligations > allow`.
- Model failure cannot disable deterministic enforcement.
- Test responses are simulated and cannot touch real systems.
