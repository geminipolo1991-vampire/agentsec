# Release audit

Audit target: local research PoC, dataset
`synthetic-corpus-2026-07-22.1`. Production v1 is explicitly excluded.

## Research-PoC definition of done

| Requirement | Executable evidence | Result |
|---|---|---|
| Two agent implementations share contracts | `tests/test_agent_adapters.py` | Pass |
| Effects cross the reference monitor; mismatched observation is detected | `tests/test_synthetic_workflow.py`, `tests/test_adapters_observation_splunk.py` | Pass for included adapters/tools |
| Four attacks plus benign control reproduce | `make workflow-demo`, `reports/evaluation/unprotected.json` | Pass |
| Authority attenuates across delegation | `tests/test_enforcement_primitives.py` | Pass |
| Provenance survives tool result, transform, handoff, and memory | `tests/test_enforcement_primitives.py` | Pass |
| Deterministic policies gate forbidden effects | `reports/evaluation/deterministic.json` | Pass: 0% forbidden-effect success |
| Claude/OpenAI use one validated interface | `tests/test_provider_adapters.py`, `tests/test_providers.py` | Pass with fake transports; live disabled |
| AI cannot remediate or relax enforcement | `tests/test_pipeline.py`, `prompts/semantic_detector/v1.md` | Pass |
| Canary/raw values stay out of Splunk exports | `tests/test_privacy.py`, `tests/test_adapters_observation_splunk.py` | Pass |
| Post-checkpoint ledger mutation is detected | `tests/test_abom_graph_checkpoint.py`, `tests/test_ledger_and_findings.py` | Pass |
| Baseline, ablation, and holdout records are immutable | `make check-reports`, `reports/evaluation/manifest.json` | Pass |
| A clean deployment reproduces the demonstration | `make clean-install` | Pass for clean Python package plus external config install |
| Limitations and bypasses are explicit | `docs/limitations.md` | Pass |

The digest manifest binds the corpus implementation, recorded Codex input, eight
evaluation modes, and the ablation record. `make check-reports` regenerates them
in memory and fails on byte drift.

## Release thresholds

- Protected forbidden-effect attack success: 0% (4/4 attacks prevented).
- Benign completion: 100% (1/1).
- Detector recall against declared fixtures: 100%.
- False block rate against declared benign fixtures: 0%.
- Telemetry-only and static-allowlist baselines reproduce 100% attack success;
  sink-only and provenance-without-authority baselines expose narrower gaps.
- Full-system result does not depend on AI; control ablations expose provenance,
  authority, ABOM, and especially gateway contributions.

These are corpus results, not population estimates. See `docs/limitations.md`.

## Production-v1 verdict

**Not authorized.** Durable state, independent enforcement/telemetry, revocable
production identity and signing, multi-tenant isolation, real connector tests,
HA/backup/restore, SLOs, pilot ownership, and organizational approvals remain
open. The EC2 Tokyo files are a hardened deployment scaffold, not evidence of a
live production control.
