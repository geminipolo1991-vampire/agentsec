# Authorization-control outage runbook

1. Stop new effectful execution at the gateway. Do not route around the reference
   monitor or treat timeout as allow.
2. Permit only explicitly classified non-effectful reads that have a separate,
   tested degraded-mode policy; the PoC defaults to fail closed.
3. Verify service health, schema compatibility, model-independent policy loading,
   ledger state, and the most recent external checkpoint.
4. Preserve attempted-effect metadata and the normalized error without recording
   raw prompts, tool arguments, credentials, or evidence content.
5. Restore from a known package/config digest, run `make verify`, then canary one
   benign read before reopening effectful traffic.
6. Record the outage window, attempted effects, operator decisions, restored
   versions, checkpoint verification, and residual risk.
