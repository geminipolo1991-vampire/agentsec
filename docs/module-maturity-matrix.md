# AgentSec approved 24-module delivery matrix

This document tracks the full product plan approved by the user. It must not be
replaced by a list of existing PoC files or used to claim that partial reference
implementations are a complete product. The machine-readable authority is
[`configs/module-catalog.json`](../configs/module-catalog.json).

## Status vocabulary

- **Not started:** no loop has compared and remediated the approved module.
- **In progress:** the module loop is actively implementing or verifying.
- **Implemented:** target behavior exists, but its complete regression and
  acceptance audit has not passed.
- **Verified:** implementation, module tests, full regressions, security/failure
  gates, and the module acceptance record all pass.

Only `verified` counts toward the 24-module completion objective.

## Current matrix

| ID | Approved product module | Status |
| --- | --- | --- |
| M01 | AI telemetry collection | Verified |
| M02 | Ingestion gateway | Verified |
| M03 | Canonical AI-security data model | Verified |
| M04 | Evidence ledger and storage | Verified |
| M05 | Search and threat hunting | Verified |
| M06 | Agent application and model inventory | Verified |
| M07 | AI security graph and attack paths | Verified |
| M08 | AI security posture management | Verified |
| M09 | Detection and rule engine | Verified |
| M10 | Detection content management | Verified |
| M11 | Behavioral analytics and risk engine | Verified |
| M12 | Finding correlation and incident creation | Verified |
| M13 | Enrichment engine | Verified |
| M14 | AI Analyst Engine | Verified |
| M15 | Model gateway and AI governance | Verified |
| M16 | Evidence validator and judgment engine | Verified |
| M17 | Incident and case management | Verified |
| M18 | Escalation and notification | Verified |
| M19 | Response and playbook automation | Verified |
| M20 | Analyst user interface | Verified |
| M21 | External API and SIEM integration | Verified |
| M22 | Simulation and validation lab | Verified |
| M23 | Evaluation and continuous improvement | Verified |
| M24 | Administration platform security and audit | Verified |

Run the honest progress audit with:

```bash
make module-audit
```

The final objective may be declared complete only when this command also passes:

```bash
make goal-audit
```

`goal-audit` intentionally fails while any module is not verified.
