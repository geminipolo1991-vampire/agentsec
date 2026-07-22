# Limitations and bypasses

This release satisfies the local research-PoC definition of done. It is not a
production security boundary and is not authorized to protect real workloads.

## Enforcement and observation

- Only the included adapters and mock tools are forced through the controlled
  gateway. An uninstrumented SDK, direct network client, subprocess, or alternate
  credential path can bypass it. Production must enforce egress and tool access
  independently of agent code.
- The independent observer reconciles supplied SDK and gateway records; it is not
  a network sensor and cannot prove that an omitted side effect never happened.
- Detection is metadata/rule based. It does not implement token-level taint,
  semantic intent proof, full URL canonicalization, or covert-channel detection.
- Mock effects and containment never touch hosts, identities, tickets, mail, or
  external receivers. They demonstrate ordering and ground truth, not connector
  correctness.

## State, identity, and cryptography

- Alerts, findings, approvals, authority-use counters, ABOM observations,
  provenance, dead letters, and checkpoints are process memory. Restart loses
  them; there is no backup, restore, replication, or transaction boundary.
- Authoritative incident details are generated from the exact in-process
  pipeline result and returned with the authorization response, but are not yet
  persisted in a durable incident database.
- The hash chain detects mutation only when a trustworthy checkpoint is retained
  separately. The included anchor is another in-process object.
- `PocHmacSigner` uses one shared HMAC key. It has no hardware-backed custody,
  asymmetric attribution, rotation, revocation, transparency log, or compromise
  recovery.
- The bearer-token service is single-tenant in behavior, has no rate limit,
  authorization roles, replay cache, mTLS, request signature, or distributed
  concurrency control. Loopback/private-network placement is required.

## Models and data

- Codex testing is a versioned offline recording produced during development; it
  is not a live Codex API call or an independent blinded judge.
- OpenAI and Anthropic tests use injected fake transports. Live profiles are
  disabled, exact model IDs are environment supplied, and no claim is made about
  a current provider model until that profile is separately evaluated.
- The five-scenario corpus is intentionally small. The two holdout fixtures are
  version-separated but visible in the repository, so they are regression
  holdouts rather than secret or statistically representative benchmarks.
- Metadata minimization and canary tests reduce disclosure risk but do not replace
  provider privacy, retention, data-residency, and legal review.

## Deployment and operations

- The clean Python package install and workflow demonstration are reproduced by
  `make clean-install`. Docker and AWS were unavailable in the development host,
  so the OCI image and CloudFormation template are validated structurally, not by
  a live EC2 launch.
- The Tokyo template is a single private EC2 research node. It allows broad HTTPS
  egress, depends on operator-provided subnet/endpoints and secrets, and has no
  HA, autoscaling, private load balancer, WAF, durable database, SIEM durability,
  SLO, backup, or disaster recovery.
- Direct OpenAI or Anthropic calls leave AWS; EC2 region `ap-northeast-1` does not
  imply model-processing residency in Tokyo.

Any production pilot must close or explicitly accept these items and meet the
Production v1 gates in `docs/release-audit.md`.
