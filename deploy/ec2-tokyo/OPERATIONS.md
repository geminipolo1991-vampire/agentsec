# AgentSec Tokyo demo operations

This runbook applies only to resources created by the AgentSec deployment in
`ap-northeast-1`. Existing account resources are read-only and must never be
deleted, modified, tagged, attached to, or reused.

The current deployment evidence is recorded in
[`reports/deployment/ec2-tokyo-20260722.json`](../../reports/deployment/ec2-tokyo-20260722.json).
It intentionally excludes the runtime secret value and all provider
credentials.

## Resource ownership

The deployment uses these CloudFormation stack boundaries:

- `agentsec-demo-foundation`: isolated VPC, public NAT subnet, private service
  subnet, internet gateway, NAT gateway, Elastic IP, route tables, and ECR
  repository.
- `agentsec-demo-service`: security group, EC2 instance, instance profile, and
  least-privilege runtime role.

The dedicated secret is named `agentsec-demo/runtime`. Every owned resource is
tagged `Project=ai-agent-security`; stack-managed resources also use
`ManagedBy=cloudformation` where the resource supports tags.

## Deployment gates

Before executing either stack:

1. Run `make verify` and require every gate to pass.
2. Validate the template with AWS CloudFormation in `ap-northeast-1`.
3. Create a change set and inspect every action.
4. For initial deployment, require every action to be `Add`.
5. Reject any reference to a VPC, subnet, route table, gateway, repository,
   secret, role, security group, or instance that predates AgentSec.
6. Obtain explicit operator approval before executing billable changes.

## Image release

Build for the `t3` instance architecture and never deploy a moving tag:

```bash
docker buildx build --platform linux/amd64 --load \
  --tag agent-security:RELEASE_ID .
```

After the foundation stack succeeds, authenticate to its ECR repository, push
one unique tag, wait for the ECR vulnerability scan, and resolve the registry
digest. Pass the repository URI with `@sha256:...` to the service stack.

## Runtime secret

Create `agentsec-demo/runtime` as a raw Docker env file in Secrets Manager. The
service stack takes this exact name and constructs a least-privilege ARN pattern
for the six-character suffix that Secrets Manager appends:

```dotenv
AGENTSEC_INGEST_TOKEN=GENERATED_VALUE_WITH_AT_LEAST_32_CHARACTERS
AGENTSEC_AI_MODE=shadow
AGENTSEC_MODEL_PROFILE=codex-recorded-shadow
```

Never add this file, the token, provider keys, or retrieved secret material to
the repository, command output, deployment reports, or chat. Live OpenAI and
Anthropic profiles remain disabled.

## Runtime verification

The service has no public IP and no inbound security-group rules. Verify that:

- the EC2 instance reports as an SSM managed node;
- `agentsec.service` and its container are healthy;
- `GET http://127.0.0.1:8080/healthz` succeeds on the instance;
- a benign inventory event returns `allow`, `effect_allowed=true`, and
  `ledger_verified=true`;
- the forged indirect-injection and secret-egress event returns `deny`,
  `effect_allowed=false`, both expected alert types, and
  `ledger_verified=true`.

Use SSM Run Command for automated checks. Session Manager port forwarding is
optional for an operator who has installed the local Session Manager plugin.
The checked-in [`runtime-check.sh`](runtime-check.sh) is the authoritative
remote probe. It verifies systemd and container health, loopback-only binding,
digest pinning, benign allow behavior, adversarial denial with both expected
alerts, ledger integrity, and non-echo of a raw-event canary. It consumes the
bearer token only inside the container and emits a sanitized JSON result.

To send it without installing the Session Manager plugin:

```bash
probe_b64=$(base64 < deploy/ec2-tokyo/runtime-check.sh | tr -d '\n')
command_id=$(aws ssm send-command \
  --region ap-northeast-1 \
  --profile agentsec-deploy \
  --instance-ids INSTANCE_ID \
  --document-name AWS-RunShellScript \
  --parameters "{\"commands\":[\"printf '%s' '$probe_b64' | base64 -d > /tmp/agentsec-runtime-check.sh\",\"chmod 0700 /tmp/agentsec-runtime-check.sh\",\"/tmp/agentsec-runtime-check.sh\"]}" \
  --query 'Command.CommandId' \
  --output text)

aws ssm get-command-invocation \
  --region ap-northeast-1 \
  --profile agentsec-deploy \
  --command-id "$command_id" \
  --instance-id INSTANCE_ID
```

## Updating

Publish every update as a new immutable ECR tag and digest. The current PoC
uses EC2 user data for first boot; do not assume an in-place CloudFormation
parameter update will rerun bootstrap. Create a reviewed replacement service
stack or explicitly replace the AgentSec-owned instance for a new image.

## Cleanup boundary

Cleanup is never automatic and requires a separate explicit operator decision.
Inventory stack resources first and confirm their stack ownership. Remove only
the resources recorded in the deployment evidence. Never broaden cleanup
commands by tag, wildcard, VPC, Region, or account.

After receiving a separate cleanup approval, use this order:

1. Re-run `describe-stack-resources` for both exact stack names and compare the
   physical IDs with the deployment record. Stop if any ownership evidence is
   inconsistent.
2. Delete only the `agentsec-demo-service` stack and wait for
   `stack-delete-complete`. This terminates the AgentSec instance and deletes
   its attached root volume, role, profile, and security group.
3. Schedule deletion of only `agentsec-demo/runtime`, using a recovery window;
   never use force deletion for the demo secret.
4. List images in only `agentsec-demo-backend`, review the exact digests, and
   delete those images only after a second confirmation. Do not use a wildcard
   repository selection.
5. Delete only the now-empty `agentsec-demo-foundation` stack and wait for its
   completion. This removes the AgentSec NAT gateway, Elastic IP, routes,
   subnets, VPC, and empty ECR repository.

The ECR repository uses `EmptyOnDelete=false`, so step 5 fails safely while any
image remains. No cleanup step is authorized by deployment approval.
