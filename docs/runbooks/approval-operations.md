# Approval operations runbook

1. Review the normalized operation, resource, destination, agent, tenant, flow,
   data classes, tool/ABOM digests, and active policy version.
2. Resolve the evidence pivot independently. Never approve instructions embedded
   in untrusted evidence or accept an agent's self-asserted authority.
3. Issue the shortest practical exact-action token. The PoC fixes the execution
   count at one and binds every security-relevant field plus policy version.
4. If any bound field changes, reject the token and restart review. Never edit or
   reuse a token.
5. Confirm the gateway consumed the nonce and that completed-effect observation
   matches the approved event. Escalate missing or duplicate observations.
6. On suspected signer compromise, stop approvals and effects, retain evidence,
   replace the PoC signer with a production revocable key design, and re-review
   all outstanding actions.
