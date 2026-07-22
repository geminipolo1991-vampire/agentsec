# Provider outage runbook

1. Confirm deterministic authorization and ledger verification remain healthy.
2. Set AI mode to `off` or `shadow`; never bypass deterministic denial or exact
   approval requirements.
3. Inspect normalized provider failures and request IDs without logging API keys,
   prompt content, or raw evidence.
4. Use an evaluated fallback profile only when its allowed mode and data classes
   match the active request.
5. Replay the immutable corpus before re-enabling `semantic_hold`.
6. Record outage window, model/profile versions, affected analyses, fallback
   decisions, and recovery evidence in the incident case.

