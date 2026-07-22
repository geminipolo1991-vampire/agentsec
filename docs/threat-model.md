# Threat model

## Protected effects

- Reading or exporting secrets and protected data.
- Writing or deleting persistent data.
- Isolating hosts or changing identities.
- Sending content outside an approved trust zone.
- Executing a delegated operation beyond the originating authority.

## Initial attackers

- An external document author injecting agent instructions.
- An actor poisoning persistent memory for a later session.
- A low-privilege agent invoking a more privileged response agent.
- A changed or malicious MCP server expanding a tool schema or destination.
- An agent suppressing or mutating its own telemetry.

## Trust boundaries

The normalized event producer is not sufficient evidence for high-risk effects.
Production enforcement requires an independent gateway or tool adapter. The model
reasoner is outside the deterministic trust boundary and cannot create authority,
remove approval requirements, or relax denial.

## Initial misuse-case mapping

| Scenario | Observable violation | Initial control |
|---|---|---|
| Indirect injection | Untrusted source-to-effect path | Deny before effect |
| Secret exfiltration | Secret at external sink | Deny and page |
| Memory poisoning | Cross-session untrusted influence | Deny and investigate |
| Confused deputy | Operation outside effective grant | Deny |
| MCP drift | Declared/observed digest mismatch | Hold for approval |

## Residual risk

The PoC now includes effect reconciliation and signed checkpoints, but both are
in-process reference implementations. It does not claim token-level information
flow, a production immutable ledger, independent network telemetry, or real
containment. The complete bypass inventory is in `docs/limitations.md`.
