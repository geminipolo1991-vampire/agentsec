# EC2 Tokyo deployment preparation

This artifact prepares a single-instance research PoC in AWS Asia Pacific
(Tokyo), region `ap-northeast-1`. It does not deploy anything automatically.
The deployment uses two stacks:

- `foundation.json` creates a new, isolated `10.42.0.0/16` VPC, public NAT
  subnet, private application subnet, routes, and an immutable ECR repository.
  It accepts no existing VPC or subnet IDs and therefore cannot update the
  account's current network resources.
- `cloudformation.json` creates the private EC2 authorization service in the
  foundation stack's VPC and private subnet after an immutable image has been
  pushed and a dedicated runtime secret has been created.

Security defaults:

- No public IP and no security-group ingress.
- Administration through AWS Systems Manager Session Manager.
- IMDSv2 required with container-compatible hop limit 2.
- Encrypted gp3 root storage.
- Runtime secrets read from the single named AgentSec secret into a mode-0600
  env file; IAM access is scoped to its Secrets Manager ARN suffix.
- Container runs read-only, without Linux capabilities, and with
  `no-new-privileges`.
- Authorization service is published only on instance loopback. Use SSM port
  forwarding for the PoC; introduce an authenticated private load balancer or
  service mesh before multi-host use.
- Outbound TCP 443 is permitted for management, ECR, Secrets Manager, and model
  APIs. Production should replace broad HTTPS egress with VPC endpoints plus an
  allowlisting egress proxy.

## Preconditions

1. Build and test the image locally or in CI with `make verify`.
2. Validate and review the isolated foundation stack. Execute it only after all
   planned resource changes are `Add` operations.
3. Push an immutable image and pass its digest URI, not a moving tag.
4. Create a new Secrets Manager secret whose value uses Docker env-file syntax. It
   must contain `AGENTSEC_INGEST_TOKEN=<at-least-32-random-characters>`. Add model
   IDs/API keys only after enabling an evaluated provider profile.
5. Select an approved Amazon Linux 2023 AMI with current SSM Agent. The bootstrap
   relies on the AWS CLI included in the AWS-provided AMI and installs Docker
   through DNF.
6. Use only the new foundation stack outputs as service-stack inputs.

Validate without deploying:

```bash
aws cloudformation validate-template \
  --region ap-northeast-1 \
  --template-body file://deploy/ec2-tokyo/foundation.json

aws cloudformation validate-template \
  --region ap-northeast-1 \
  --template-body file://deploy/ec2-tokyo/cloudformation.json
```

## Existing-resource boundary

The deployment operator must not delete, modify, tag, attach to, or reuse any
resource that predates the AgentSec deployment. Use stack names beginning with
`agentsec-demo-`, require a CloudFormation change-set review before execution,
and reject any foundation change whose action is not `Add`. Cleanup is limited
to resources created by the two AgentSec stacks and requires a separate explicit
operator decision.

The dashboard in `ui/` is not part of either stack. It remains local and cannot
reach the loopback-only backend until a separately authorized authenticated
private access design is implemented.

Deployment creates billable resources and therefore remains an explicit operator
action. Provide all parameters and review the change set before execution.

The Tokyo location applies to EC2 resources. Direct calls to OpenAI or Anthropic
remain external provider processing and must be evaluated separately for data
residency, privacy, and contractual requirements.

See [`OPERATIONS.md`](OPERATIONS.md) for the deployment gates, runtime checks,
immutable update process, and cleanup boundary.

## Current deployment

The approved research demo was deployed on 2026-07-22. Both
`agentsec-demo-foundation` and `agentsec-demo-service` reached
`CREATE_COMPLETE`. The backend remains private and loopback-bound; the UI was
not deployed, and live OpenAI and Anthropic profiles remain disabled. The
sanitized resource, scan, control, and end-to-end verification evidence is in
[`reports/deployment/ec2-tokyo-20260722.json`](../../reports/deployment/ec2-tokyo-20260722.json).
