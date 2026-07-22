# AgentSec Tokyo deployment completion audit

Recorded: 2026-07-22T10:09:42Z

This audit maps the deployment objective to current authoritative evidence.
It contains no runtime secret value or provider credential.

| Requirement | Evidence | Result |
| --- | --- | --- |
| Isolated Tokyo infrastructure | `agentsec-demo-foundation` is `CREATE_COMPLETE`; its outputs identify the dedicated VPC and public/private subnets in `ap-northeast-1`. | Proven |
| Existing AWS resources unchanged | The foundation accepts no existing network IDs; both reviewed initial change sets contained only `Add` actions; the service uses only foundation outputs and the dedicated repository/secret. | Proven |
| Immutable, verified backend image | Service parameter pins `agentsec-demo-backend@sha256:06d001ec...ae8dd`; ECR reports Docker v2 manifest, scan `COMPLETE`, and zero findings. | Proven |
| Least-privilege runtime access | The runtime role has only `AmazonSSMManagedInstanceCore`, one-secret read, ECR login, and pull access to `agentsec-demo-backend`. | Proven |
| Private SSM-managed EC2 service | `agentsec-demo-service` is `CREATE_COMPLETE`; instance has no public IP, zero ingress rules, TCP/443-only egress, required IMDSv2, encrypted gp3 storage, and SSM `Online`. | Proven |
| Healthy authorization runtime | Final SSM command `5c3617cd-f2c6-4e74-9a6c-8f111ae1472f` succeeded with response code 0 and an empty error stream; container is healthy and loopback-bound. | Proven |
| Benign behavior | Live benign inventory event returned `allow`, `effect_allowed=true`, no alerts, and `ledger_verified=true`. | Proven |
| Adversarial behavior | Live injection-plus-secret-egress event returned `deny`, `effect_allowed=false`, both expected alerts, and `ledger_verified=true`; the raw-event canary was not echoed. | Proven |
| UI and public exposure disabled | No UI resource exists in either stack; EC2 has no public IP or ingress and the service binds to `127.0.0.1:8080`. | Proven |
| Live model providers disabled | Live probe reports shadow mode, `codex-recorded-shadow`, and no OpenAI or Anthropic API keys. | Proven |
| Operations and cleanup documented | `deploy/ec2-tokyo/OPERATIONS.md` covers deployment gates, image release, secret handling, SSM verification, immutable updates, ownership checks, and exact approval-gated cleanup order. | Proven |

Machine-readable resource and verification evidence is in
`reports/deployment/ec2-tokyo-20260722.json`.
