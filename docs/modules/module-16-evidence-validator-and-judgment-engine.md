# Module 16 — Evidence Validator and Judgment Engine

Status: verified  
Contracts: 1.0.0  
Policy: evidence-judgment-2026-07-24.1

## Comparison baseline

Modules 9, 13, 14, and 15 already supplied deterministic detections, bounded
enrichment, five read-only analyst roles, provider schema validation, exact
provider identity, and citation allowlists. The existing judge also enforced
the most-restrictive action order and rejected model relaxation.

Those controls established provenance, but not truth. A provider could cite a
known evidence ID without proving that its conclusion matched a recorded fact;
role prose had no machine-checkable assertion; mandatory evidence varied by
convention; incompatible role conclusions were not compared; confidence was
not bounded by evidence strength; and an invalid model tightening was not
distinguished from a validated one. The incident UI exposed citations and
disagreements, but not the proof used to accept, reject, or gate each claim.

## Implemented remediation

- Added `EvidenceJudgmentValidator`, a deterministic and non-executive layer
  used both by the pre-response policy judge and the five-role analyst run.
- Added pre-response `ModelVerdictValidation`. It reconstructs the exact
  privacy-transformed evidence allowlist, detects missing or unknown citations,
  rejects action relaxation, scans bounded model fields for instruction-like
  control language, applies a deterministic evidence-confidence ceiling, and
  records whether a tightening is eligible.
- Changed semantic hold so a model can tighten only when verdict validation is
  `valid`. Unknown evidence, missing evidence, injection-like output,
  deterministic relaxation, or overconfidence leaves the deterministic action
  unchanged and records a human gate.
- Added structured `AnalystClaim` contracts with a stable claim ID, subject,
  bounded fact key, `equals`/`contains`/`exists` operator, typed expected value,
  and one or more governed evidence IDs.
- Extended recorded Codex and live OpenAI/Anthropic structured-output paths to
  carry claims. Claim and alternative citations must be contained in the exact
  read-only evidence-tool result for that role.
- Added role-specific mandatory evidence policy: detector+triage for triage,
  detector+enrichment for investigation, detector+judgment for judge,
  triage+escalation for escalation, and judgment+response for response advice.
  Alternative-only citations cannot make the primary conclusion complete.
- Validated claims against exact typed facts. Unknown references and missing
  facts are unsupported; mismatched values are contradicted; exact facts are
  verified; and instruction-bearing claim fields or evidence cannot count as
  support.
- Added conservative confidence calibration from verified evidence count,
  independent supporting source count, verified ledger evidence, and complete
  source state. Model confidence above the evidence ceiling creates a human
  gate and cannot be used as policy authority.
- Versioned the recorded Codex evaluation fixture and calibrated its MCP-drift
  tightening from 0.98 to 0.88 so it remains below the reproducible 0.89
  evidence ceiling; the overconfident variant is separately tested as held.
- Added cross-role contradiction checks for mutually exclusive equality claims.
  Compatible existence and contains assertions are deliberately not treated as
  contradictions.
- Added explicit passed/human-review/rejected reports, mandatory-evidence
  checks, per-claim outcomes, contradictions, issues, gate reasons, calibrated
  confidence, and an immutable report digest. The machine action is structurally
  equal to the deterministic action and `automation_eligible` is always false.
- Bound the report into the durable analyst-run digest and verify both digests
  on every read, including after restart. Recomputing only the outer digest
  cannot conceal validation-report mutation.
- Exposed pre-response model-validation evidence in the Judgment tab and the
  complete five-role evidence-judgment report in the AI Analyst tab. Missing
  data remains missing; the UI does not infer claims, evidence, confidence, or
  policy outcomes.
- Added dedicated JSON Schemas and focused backend, provider, pipeline,
  persistence-integrity, incident, UI-build, and UI-contract coverage.

## Decision flow

```text
detector action + triage
        │
        ├─ optional model verdict
        │      └─ citation / relaxation / injection / confidence validation
        │             ├─ valid tightening → most-restrictive action
        │             └─ otherwise → deterministic action + human gate
        │
        └─ deterministic escalation and safe response
               └─ five governed analyst roles
                      └─ mandatory evidence + structured claim validation
                             ├─ passed
                             ├─ human review
                             └─ rejected
```

The post-response analyst report explains and challenges the recorded result;
it never reopens or changes the machine action. Human case workflow belongs to
Module 17, while real response execution belongs to Module 19.

## Security invariants

1. A model never creates authority and never makes a decision less restrictive.
2. A model tightening is ineligible until all cited IDs are known and its
   confidence is within the deterministic evidence ceiling.
3. Five-role analysis is read-only, post-response, and always non-executive.
4. Mandatory evidence is role-specific and must be cited by the primary result
   or a structured claim, not merely hidden in an alternative.
5. Model prose is not treated as proof. Every accepted assertion is tied to a
   bounded operator, exact fact key, typed expected value, and governed IDs.
6. Instruction-like claim fields and evidence are isolated as data, rejected
   from support, and routed to a human gate.
7. Cross-role equality conflicts invalidate both claims and reject the report.
8. P0/P1 results, unavailable/abstained roles, missing claims, missing mandatory
   evidence, contradictions, invalid action advice, and confidence excess all
   require explicit human review.
9. `machine_action == deterministic_action`, `automation_eligible == false`,
   and a non-passing report cannot omit its human gate.
10. Durable report and run digests are independently verified before display.

## Data and interface contract

The pre-response `Judgment.model_validation` records policy version, status,
cited/unknown IDs, claimed/calibrated confidence, human-gate state,
tightening eligibility, and bounded reason codes. It does not store prompt
content, provider output, headers, credentials, or evidence bodies.

`AiAnalystRun.validation` records five mandatory-evidence checks, per-claim
support/conflict IDs, independent-source count, confidence calibration,
contradictions, bounded issues, gate reasons, status, deterministic machine
action, timestamp, and SHA-256. The authoritative incident detail carries this
same validated object; no separate UI calculation is authoritative.

Generated standalone schemas include `model-verdict-validation`,
`analyst-claim`, `judgment-mandatory-evidence-check`,
`judgment-claim-validation-result`, `judgment-contradiction`,
`judgment-validation-issue`, and `judgment-validation-report`.

## Verification evidence

The focused gate covers supported facts, missing mandatory evidence, missing
claims, unknown citations, contradicted values, model relaxation, validated and
held tightening, confidence excess, role/model injection output, instruction-
bearing evidence, compatible contains assertions, P0/P1 human gates, abstention,
provider outage, provider schema/citation validation, recorded Codex execution,
redaction, tenant permission, idempotency, nested digest tampering, incident
serialization, production UI build, and UI source/render contracts.

## Honest limitations and assigned follow-on work

- This is deterministic evidence consistency, not independent ground truth or
  proof of attacker intent. An authoritative-but-wrong upstream fact can still
  support a claim.
- Confidence ceilings are conservative policy heuristics, not statistically
  calibrated probabilities. Representative calibration, blinded evaluation,
  drift measurement, and improvement approval belong to Module 23.
- Injection detection is a bounded lexical defense layered on structured data
  isolation. It can over-escalate paraphrases and cannot prove an input safe.
- Claims operate on allowlisted metadata facts, not raw prompts, tool results,
  memory, or arbitrary forensic content. Secure evidence pivots remain the path
  to deeper investigation.
- The gate records that a human is required but does not assign, acknowledge,
  or close a case. Module 17 owns collaborative case state and SLA.
- Local SHA-256 and SQLite do not provide managed signing, independent
  timestamping, distributed durability, or human identity. Module 24 owns those
  production controls.

## Acceptance closure

The focused closure gate passed 89 judgment, pipeline, analyst, provider,
model-gateway, incident, service, and bridge tests. The production UI build and
both UI source/render contracts passed independently, all 190 generated schemas
matched their canonical models, and the pre-promotion catalog/diff audits were
clean.

The complete `make verify` gate passed with 302 Python tests, five TypeScript SDK
tests, ten deterministic evaluation records, clean-package reproduction,
bytecode compilation, secret scan, dependency integrity, release audit,
protected/unprotected workflow and recorded Codex demonstrations, all eight
evaluation modes, and component ablation. The protected deterministic,
Codex-shadow, and semantic-hold modes retained zero completed forbidden effects
and zero false blocks on the bounded corpus.

The full gate deliberately observed 15/24 before catalog promotion. The
post-promotion module audit records the final Module 16 closure at 16/24.
