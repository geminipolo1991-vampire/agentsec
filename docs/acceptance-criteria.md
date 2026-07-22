# Executable acceptance criteria

## Vertical slice

- A benign, authorized inventory read produces no security alert and remains
  allowed.
- Each forged attack family produces at least one evidence-backed alert.
- Every alert traverses detection, ingestion, triage, judgment, escalation, and
  response in that order.
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
make clean-install
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
- A fresh offline package install reproduces evaluation and workflow ground truth.
