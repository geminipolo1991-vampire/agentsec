# Detailed implementation plan: AI-agent security platform and research PoC

## 1. Objective

Build an AI-powered agent security platform that can:

1. Observe agent, model, tool, memory, MCP and agent-to-agent activity.
2. Establish which human or service an agent acts for and what authority it actually possesses.
3. Carry provenance and delegated authority across an entire multi-agent workflow.
4. Stop unsafe effects before execution through a synchronous reference monitor.
5. Use Claude Opus or OpenAI GPT-5.6/GPT-5.5 agents for semantic detection, investigation, explanation, adversarial testing and rule proposals.
6. Reconstruct cross-agent attack paths for analysts.
7. Maintain an observed Agent Bill of Materials and detect drift.
8. Produce tamper-evident security records.
9. Export only approved findings and identity metadata to Splunk.
10. Provide reproducible evidence for a security-research PoC.

The main research claim is:

> A reference monitor that combines transitive provenance with attenuated delegated authority can prevent multi-agent attacks that appear legitimate when each agent and tool call is evaluated independently.

## 2. Architectural rules

These are implementation invariants, not optional features.

### 2.1 Effect-before-event rule

Every effectful action must pass through the authorization interface before the tool, MCP server, agent, network destination or operating-system operation is invoked.

An effect includes:

- Reading protected data.
- Writing or deleting data.
- Sending content outside a trust zone.
- Executing code or shell commands.
- Changing permissions or identity configuration.
- Creating, modifying or invoking another agent.
- Writing persistent memory.
- Approving, publishing or activating a security policy.

Telemetry after the effect is useful for investigation but does not satisfy enforcement.

### 2.2 Authority-narrowing rule

Delegation may preserve or reduce authority; it may never expand authority. The effective grant for an action is the intersection of:

- Human/service principal authority.
- Current task authority.
- Delegator authority.
- Callee workload authority.
- Tool/resource policy.
- Data-classification policy.
- Destination policy.
- Environment and tenant policy.
- Expiration, execution-count and delegation-depth constraints.

### 2.3 Provenance-preservation rule

Summarization, transformation, delegation and memory persistence must retain links to their source evidence. Sanitization adds an attestation; it does not silently erase parent provenance.

The PoC tracks structural causal exposure—what data was present and eligible to influence an action. It must not claim perfect token-level or neural semantic taint tracking.

### 2.4 Most-restrictive-decision rule

The final outcome is the most restrictive applicable result:

```text
deny > require_approval > allow_with_obligations > allow
```

AI analysis may make a decision more restrictive. It cannot override a deterministic denial, create authority, remove an approval requirement or expand a destination/data scope.

### 2.5 AI-independence rule

Claude/OpenAI failure must not disable the deterministic policy gate. Supported AI modes are:

- `off`: no model call.
- `shadow`: analyze without affecting execution.
- `advisory`: attach risk and recommendation to an approval or finding.
- `semantic_hold`: hold only policy-selected actions for AI review; failure follows a deterministic fallback policy.

Start the PoC with `shadow` and `advisory`. Enable `semantic_hold` only for explicitly selected actions after evaluation.

### 2.6 Sensitive-data rule

Prompts, responses, memory contents, tool arguments and raw evidence remain in the restricted platform store unless a field-level policy explicitly allows export. Content capture is disabled by default.

### 2.7 Independent-observation rule

High-risk effects need an observation point outside the agent process, such as an MCP gateway, egress proxy or tool service. A compromised agent cannot be trusted to report its own behavior completely.

### 2.8 Version-everything rule

Every decision must reference exact versions of:

- Event and request schemas.
- Policy bundle.
- Agent manifest/ABOM.
- Prompt template.
- AI provider and model ID.
- Tool schema.
- Data-classification configuration.
- Redaction rules.

## 3. Logical architecture

### 3.1 Runtime enforcement plane

Components:

- Python agent SDK.
- Framework adapters.
- MCP reverse proxy.
- Tool/action normalizer.
- Flow-context verifier.
- Authority calculator.
- Deterministic policy decision point.
- Approval and obligation service.
- Independent egress observer.

### 3.2 Control plane

Components:

- Non-human identity registry.
- Declared and observed ABOM registry.
- Policy bundle registry.
- Model and prompt registry.
- Tool schema registry.
- Data classification and destination registry.
- Signing-key and checkpoint configuration.

### 3.3 Evidence and analytics plane

Components:

- OpenTelemetry collector.
- Durable event stream.
- Restricted raw evidence store.
- Hot event/finding store.
- Hash-chain and checkpoint service.
- Temporal causal graph builder.
- Stateful detector engine.
- Finding and case service.

### 3.4 AI reasoning plane

Components:

- Provider-neutral model interface.
- OpenAI Responses API adapter.
- Claude Messages API adapter.
- Model router and fallback policy.
- Privacy-aware evidence assembler.
- Structured-output validator.
- Semantic detector agent.
- SOC investigator agent.
- Adversarial-test generator agent.
- Detection-policy proposal agent.

### 3.5 Integration plane

Components:

- Field-allowlisted Splunk transformer.
- Splunk HEC client.
- Analyst evidence pivot.
- Approval interface.
- Minimal inventory, causal-path and finding views.

## 4. Reference implementation stack

Use simple, replaceable components for the PoC.

| Area | PoC implementation | Production direction |
|---|---|---|
| Language | Python 3.12+ | Python SDK/services plus TypeScript SDK |
| Service API | FastAPI and Pydantic | Same contracts behind hardened deployment |
| Schema | JSON Schema generated from Pydantic | Registry-backed, versioned schemas |
| Telemetry | OpenTelemetry SDK and Collector | HA collectors with disk buffering and mTLS |
| Deterministic policy | OPA/Rego with signed bundles | Replicated/local policy evaluation |
| Operational store | PostgreSQL | PostgreSQL plus ClickHouse/OpenSearch if measured need exists |
| Raw evidence | MinIO/S3-compatible object storage | Encrypted object storage with retention and object lock |
| Event transport | Redpanda/Kafka-compatible local broker | Managed Kafka or equivalent |
| Graph | PostgreSQL node/edge tables | Retain relational model or adopt temporal graph DB after measurement |
| Cryptography | RFC 8785 canonical JSON, SHA-256 and Ed25519 | KMS/HSM-backed signing and rotation |
| AI providers | OpenAI Responses API and Claude Messages API | Provider-neutral routing with approved model profiles |
| Deployment | Docker Compose | Kubernetes or managed container platform after PoC |
| SOC | Splunk HEC test index | Dedicated sourcetype/index and production runbooks |

Do not introduce a graph database, feature store, ML training pipeline or Kubernetes merely because the production platform may eventually use one.

## 5. Repository structure

```text
agent-security/
  pyproject.toml
  Makefile
  README.md
  .env.example
  .github/
    CODEOWNERS
    workflows/
  docs/
    architecture.md
    threat-model.md
    trust-boundaries.md
    data-handling.md
    policy-model.md
    ai-safety-model.md
    limitations.md
    runbooks/
    adr/
  schemas/
    action-request/
    decision/
    flow-envelope/
    security-event/
    abom/
    finding/
    approval/
    ai-analysis/
    scenario/
    fixtures/
  sdk/python/agentsec/
    context/
    hooks/
    telemetry/
    redaction/
    client/
  adapters/
    langgraph/
    custom/
  gateways/mcp/
    discovery/
    normalization/
    authorization/
    forwarding/
  services/
    policy/
    registry/
    approval/
    lineage/
    ledger/
    graph/
    detector/
    findings/
    ai_reasoning/
  integrations/
    splunk/
  harness/
    agents/
    tools/
    mcp_servers/
    receivers/
    scenarios/
  evaluation/
    runner/
    baselines/
    metrics/
    reports/
    frozen/
  policies/
    source/
    bundles/
    fixtures/
  prompts/
    semantic_detector/
    investigator/
    adversarial_generator/
    policy_proposer/
  deploy/
    compose/
    otel/
    opa/
    redpanda/
    postgres/
    minio/
  tests/
    unit/
    property/
    contract/
    integration/
    adversarial/
    privacy/
    failure/
    performance/
```

Apply CODEOWNERS review to `schemas/`, `policies/`, `prompts/`, `services/policy/`, `services/ledger/`, `services/approval/` and `integrations/splunk/`.

## 6. Canonical data contracts

Freeze contracts before building framework-specific logic.

### 6.1 AgentIdentity

Required fields:

- `tenant_id`
- `agent_id`
- `workload_uri`
- `owner_id`
- `purpose`
- `environment`
- `lifecycle_status`
- `build_digest`
- `framework_name`
- `framework_version`
- `deployment_identity`
- `created_at`
- `revoked_at`

Rules:

- `workload_uri` must be stable and unique within the tenant.
- Lifecycle status is one of `declared`, `observed`, `approved`, `suspended`, `revoked`.
- Observing an unknown agent creates a finding; it does not make the agent trusted.

### 6.2 ABOMManifest

Required fields:

- Manifest ID and schema version.
- Agent identity and owner.
- Build/image digest.
- System-instruction digest.
- Allowed model provider/model profiles.
- Tool names, canonical operations and schema digests.
- MCP/A2A server identities and endpoint classes.
- Credential references and scopes.
- Allowed data classes.
- Allowed destinations and network zones.
- Approval requirements.
- Policy-bundle digest.
- Declared/observed evidence source.
- Signature and signer identity.

Never include raw credentials, prompts or secrets.

### 6.3 ProvenanceRecord

Required fields:

- `provenance_id`
- `source_type`: user, control, email, ticket, document, web, tool, memory, agent or system.
- `source_id`
- `trust_class`: trusted-control, authenticated-user, internal-data, external-untrusted, suspected-adversarial or unknown.
- `confidentiality_labels`
- `integrity_labels`
- `content_digest`
- `parent_provenance_ids`
- `transform_type`
- `sanitizer_attestation_id`
- `first_seen_at`
- `tenant_id`

Propagation rule: output provenance is the union of all input parents plus the transform record.

### 6.4 AuthorityGrant

Required fields:

- Grant ID, issuer and subject.
- Canonical operations.
- Resource patterns.
- Destination patterns.
- Allowed data classifications.
- Tenant/environment constraints.
- Maximum delegation depth.
- Maximum execution count.
- Validity window.
- Parent grant ID.
- Signature.

Attenuation rule: child grants must be a subset of every parent dimension.

### 6.5 FlowEnvelope

Required fields:

- `flow_id`
- `step_id`
- `parent_step_ids`
- `parent_event_digests`
- `actor`
- `on_behalf_of`
- `task_digest`
- `authority_grant_ids`
- `provenance_ids`
- `abom_digest`
- `policy_bundle_digest`
- `issued_at`
- `expires_at`
- `nonce`
- `signature`

The envelope contains references and digests, not raw content.

### 6.6 ActionRequest

Required fields:

- Request ID and flow envelope.
- Canonical operation.
- Canonical resource.
- Destination and trust zone.
- Argument digest.
- Data-classification labels.
- Tool/server identity and schema digest.
- Requested credential reference.
- Risk tier.
- Whether an irreversible side effect is expected.

### 6.7 Decision

Required fields:

- `decision_id`
- `action`: allow, allow_with_obligations, require_approval or deny.
- Stable reason codes.
- Matched policy rules.
- Evidence/provenance references.
- Effective-authority digest.
- Required obligations.
- Approval specification if applicable.
- Policy and ABOM versions.
- Decision mode: deterministic, AI-shadow, AI-advisory or AI-hold.
- Decision latency.
- Signature.

### 6.8 ApprovalToken

Bind the token to:

- Actor and human approver.
- Exact operation, resource and destination.
- Argument and data-label digest.
- Flow and step.
- Policy version.
- Expiration.
- Execution-count limit.
- Approval reason.
- Signature and nonce.

Revalidate every bound field immediately before execution.

### 6.9 SecurityEvent

Required fields:

- Tenant, producer and event type.
- Event and observed timestamps.
- Producer sequence number.
- Trace, span, flow and step IDs.
- Parent event digests.
- Attempted/completed/failed effect state.
- Decision and finding references.
- Previous event hash and current event hash.
- Checkpoint reference.
- Schema, policy and ABOM versions.

### 6.10 AIAnalysis

Required fields:

- Analysis ID and analysis type.
- Provider and exact model ID.
- Model-profile and prompt-template version.
- Input evidence IDs and input digest.
- Structured verdict.
- Confidence or calibrated score.
- Evidence citations.
- Uncertainty and missing evidence.
- Proposed action.
- Tool calls made by the security agent.
- Provider request ID, token usage and latency.
- Output digest and validation status.

Store an analyst-facing rationale summary, not hidden chain-of-thought.

### 6.11 Finding

Required fields:

- Finding ID, type, status and severity.
- Agent/identity/tool/resource/destination references.
- Flow and causal-path references.
- Deterministic evidence and optional AI analysis.
- Detector and policy versions.
- Approval/remediation state.
- Splunk export state.
- Creation, update and closure audit records.

## 7. Internal service APIs

### 7.1 Policy service

- `POST /v1/authorize`
- `POST /v1/decisions/{id}/revalidate`
- `GET /v1/policy-bundles/{digest}`
- `GET /v1/policy-bundles/current`
- `POST /v1/policy-bundles/verify`

`POST /v1/authorize` must be idempotent for the same request ID and digest. It must not execute the tool.

### 7.2 Registry service

- `POST /v1/agents/declare`
- `POST /v1/agents/observe`
- `GET /v1/agents/{agent_id}`
- `POST /v1/abom/manifests`
- `POST /v1/abom/observations`
- `GET /v1/abom/{agent_id}/diff`
- `POST /v1/identities/{id}/revoke`

### 7.3 Approval service

- `POST /v1/approvals`
- `GET /v1/approvals/{id}`
- `POST /v1/approvals/{id}/approve`
- `POST /v1/approvals/{id}/deny`
- `POST /v1/approval-tokens/verify`

### 7.4 Lineage service

- `POST /v1/provenance`
- `POST /v1/provenance/transform`
- `GET /v1/provenance/{id}`
- `GET /v1/flows/{flow_id}/lineage`
- `GET /v1/flows/{flow_id}/path-to/{step_id}`

### 7.5 Ledger service

- `POST /v1/events`
- `POST /v1/checkpoints`
- `GET /v1/checkpoints/{producer_id}/latest`
- `POST /v1/verify`
- `GET /v1/verify/{job_id}`

### 7.6 Finding service

- `POST /v1/findings`
- `GET /v1/findings/{id}`
- `GET /v1/findings`
- `POST /v1/findings/{id}/assign`
- `POST /v1/findings/{id}/close`

### 7.7 AI reasoning service

- `POST /v1/ai/analyze-action`
- `POST /v1/ai/investigate-finding`
- `POST /v1/ai/generate-scenarios`
- `POST /v1/ai/propose-policy`
- `GET /v1/ai/model-profiles`
- `POST /v1/ai/model-profiles/{id}/evaluate`

Only internal service identities may call these endpoints. Each endpoint uses a distinct agent identity, prompt and tool allowlist.

## 8. Synchronous authorization flow

Implement this exact order:

1. Receive the proposed action before tool execution.
2. Parse and validate the `ActionRequest` schema.
3. Authenticate the calling workload.
4. Verify flow-envelope signature, expiry, nonce and parent continuity.
5. Resolve the current approved ABOM.
6. Compare observed tool/server/model/schema/destination with the ABOM.
7. Canonicalize the operation, resource and destination.
8. Resolve the parent authority chain.
9. Compute effective authority by intersection.
10. Resolve provenance references and data classifications.
11. Evaluate deterministic policy.
12. If denied, emit an attempted-effect event and return denial.
13. If approval is required, create an exact-action approval request and return pending status.
14. If obligations apply, transform a copy of the arguments and recompute the argument digest.
15. If policy selects AI shadow/advisory review, enqueue an analysis without blocking the action.
16. If policy selects semantic hold, call the AI reasoning service with minimum necessary evidence.
17. Validate AI structured output; AI may only preserve or restrict the deterministic decision.
18. Revalidate policy, ABOM and approval token immediately before execution.
19. Execute the tool through the controlled adapter/gateway.
20. Emit completed or failed effect event independently of the agent's own telemetry.

## 9. Ordered implementation stages

The stages define dependency order, not schedule estimates.

## Stage A — Project foundation

### A1. Establish repository controls

Implementation tasks:

- Create the monorepo structure.
- Configure formatter, linter, type checker, unit-test runner and dependency lock.
- Configure secret scanning, dependency scanning and container scanning.
- Add CODEOWNERS and protected review paths.
- Add a CI job that generates schemas and fails on uncommitted schema drift.
- Add a CI job that rejects policy or prompt changes without associated tests.

Artifacts:

- Repository skeleton.
- CI configuration.
- Contributor guide.
- Security disclosure policy.

Verification:

- A deliberately malformed schema fails CI.
- A test secret fails CI.
- An unreviewed policy change is blocked by repository rules.

### A2. Complete threat model

Implementation tasks:

- Draw trust boundaries for the agent process, MCP gateway, policy service, identity service, raw store, AI provider and Splunk.
- Enumerate protected assets and effectful operations.
- Model attackers controlling external content, MCP servers, low-privilege agents, memory entries and telemetry producers.
- Model failure of the policy service, AI provider, broker, raw store and identity service.
- Document assumptions about host compromise and independent gateways.
- Map each attack to OWASP Agentic risk categories for analyst vocabulary.

Artifacts:

- Threat-model document.
- Data-flow diagram.
- Misuse-case catalog.
- Risk acceptance log.

Exit criteria:

- Every PoC attack has an entry point, trust-boundary crossing, intended effect, detector and enforcement point.
- Every high-risk effect has an independent observation point.

### A3. Define data-handling policy

Implementation tasks:

- Classify metadata, prompts, tool arguments, results, memory and secrets.
- Define which fields may enter AI-provider requests.
- Define which fields may enter Splunk.
- Define redaction order and behavior when redaction fails.
- Define separate access roles for raw evidence, findings and policy management.
- Create canary strings for each sensitive data class.

Exit criteria:

- A machine-readable field allowlist exists for AI input and Splunk export.
- Prohibited fields are tested, not merely documented.

## Stage B — Synthetic SOC environment

### B1. Implement mock enterprise systems

Build deterministic local services for:

- Incident ticket intake.
- External document/attachment retrieval.
- Asset inventory lookup.
- Knowledge-base/RAG retrieval.
- Persistent memory read/write.
- Honeytoken secret retrieval.
- Ticket comment/update.
- Host isolation.
- Deletion.
- External diagnostic upload.

Every mock tool must:

- Have a strict input/output schema.
- Expose attempted and completed effects.
- Be resettable.
- Never touch real enterprise systems.
- Return deterministic fixture data.
- Accept a correlation/flow ID.

### B2. Implement the four-agent workflow

Agents:

- Coordinator: receives incident and assigns work.
- Triage agent: extracts facts and determines next steps.
- Enrichment agent: queries inventory and knowledge tools.
- Response agent: proposes or performs approved response actions.

Requirements:

- Implement one framework-based version and one minimal custom-agent version.
- Keep tool schemas identical between implementations.
- Ensure the unprotected workflow can complete benign tasks.
- Ensure the unprotected workflow is vulnerable to the planned attacks.

### B3. Implement malicious components

- Malicious ticket/document content containing indirect instructions.
- Poisoned memory record used by another session.
- Low-privilege agent attempting to delegate excessive authority.
- MCP server that changes tool description, schema or destination.
- Fake exfiltration receiver that records honeytoken arrival.
- Telemetry mutation utility for integrity tests.

### B4. Implement scenario ground truth

Each scenario file must declare:

- Initial state.
- User task.
- Source trust labels.
- Required effects.
- Allowed optional effects.
- Forbidden effects.
- Expected approval points.
- Expected provenance path.
- Expected authority chain.
- Expected detector findings.
- Reset procedure.

Exit criteria:

- A runner can determine success from actual effects without an LLM grader.
- Benign and malicious scenarios can be replayed from clean state.

## Stage C — Schemas and persistence model

### C1. Implement Pydantic models and JSON Schemas

- Implement every contract in Section 6.
- Generate JSON Schema artifacts.
- Add positive and negative fixtures.
- Add schema-version and compatibility metadata.
- Reject unknown security-critical fields unless explicitly versioned.

### C2. Implement database migrations

Create tables for:

- Agents and workload identities.
- Declared and observed ABOM manifests.
- Tool/server schemas.
- Policies and policy bundles.
- Provenance records and transforms.
- Authority grants and delegation links.
- Action requests and decisions.
- Approvals and tokens.
- Security events and checkpoints.
- Graph nodes and edges.
- Findings and cases.
- AI analyses and provider calls.
- Export records and dead letters.

Add indexes on tenant, agent, flow, trace, event time, finding status, tool identity, destination, policy version and ABOM digest.

### C3. Add contract tests

- Round-trip serialization tests.
- Cross-version compatibility tests.
- Invalid signature/nonce/expiry fixtures.
- Unknown enum and field behavior.
- Maximum field length and payload size tests.
- Canonical serialization fixtures used by hashing code.

Exit criteria:

- SDK, gateway and services consume the same generated schema fixtures.

## Stage D — Agent SDK and framework adapters

### D1. Implement framework-neutral SDK

Public interfaces:

- `start_run()`
- `record_model_call()`
- `record_tool_proposal()`
- `authorize_tool_call()`
- `record_tool_result()`
- `record_memory_read()`
- `record_memory_write()`
- `delegate()`
- `attach_provenance()`
- `current_flow_context()`

Requirements:

- Use context variables so flow state follows async execution safely.
- Generate trace/span IDs compatible with OpenTelemetry.
- Separate metadata capture from optional content capture.
- Provide local buffering when collectors are unavailable.
- Avoid logging secrets through exceptions.
- Expose a no-op/shadow mode for migration.

### D2. Implement framework adapter

- Map framework lifecycle callbacks to SDK operations.
- Capture model request/response metadata.
- Capture proposed tool call before execution.
- Capture tool result, error and retry.
- Capture memory reads/writes.
- Capture agent delegation and handoff.
- Add contract tests using fixture workflows.

### D3. Implement custom-agent adapter

- Wrap custom dispatcher and model client.
- Produce identical normalized events.
- Prove the schema does not depend on framework-specific field names.

### D4. Implement redaction

- Apply local rules before data leaves the process.
- Redact credentials, tokens, keys, authorization headers and configured PII.
- Mark redaction status and rule version.
- Fail closed for configured sensitive content export.
- Add canary tests to every event type.

Exit criteria:

- Both agent implementations produce equivalent event sequences for the same logical workflow.
- Content capture can be disabled without breaking detection metadata.

## Stage E — MCP gateway and tool normalization

### E1. Implement MCP reverse proxy

- Terminate client connection and create a controlled upstream connection.
- Authenticate agent workload.
- Observe tool discovery and calculate tool-schema digests.
- Intercept calls before forwarding.
- Create an `ActionRequest` and call the policy service.
- Enforce deny, approval and obligations.
- Record upstream result and errors.
- Prevent direct upstream credentials from reaching the agent when possible.

### E2. Implement canonical action mapping

Map framework/tool-specific calls to:

```text
operation + resource + destination + data classes + effect class
```

Examples:

- `send_email` → `external.send`, recipient domain, attachment data classes.
- `delete_messages` → `data.delete`, mailbox resource, destructive flag.
- `isolate_endpoint` → `host.isolate`, asset ID, critical action.
- `run_query` → `data.read`, dataset/resource classification.
- `execute_shell` → `code.execute`, host/container, command digest.

Unknown mappings at sensitive sinks must not default to low risk.

### E3. Detect MCP drift

- Compare server identity and certificate/workload identity.
- Compare tool names, descriptions and input/output schemas.
- Compare declared destinations and network zone.
- Compare requested credential scope.
- Generate ABOM observation and finding.
- Make drift available to the inline policy decision.

### E4. Add independent egress observation

- Route fake external send/upload through a controlled gateway.
- Record attempted and completed egress separately.
- Compare SDK-reported effects with gateway-observed effects.
- Create a missing-telemetry finding when they differ.

Exit criteria:

- No PoC MCP or egress effect can bypass authorization silently.

## Stage F — Identity and observed ABOM

### F1. Implement agent registry

- Declare agent identity, owner, purpose and environment.
- Bind agent to workload credential/public key.
- Support suspend and revoke.
- Return approved manifest and policy references.
- Audit every registry mutation.

### F2. Implement declared ABOM

- Create signed manifest submission endpoint.
- Validate model, tool, MCP, destination and credential entries.
- Store immutable versions.
- Require owner and security approval for privileged changes.

### F3. Implement observed ABOM

Build observations from:

- SDK runtime events.
- MCP discovery.
- Model-provider calls.
- Tool calls.
- Credential references.
- Network destinations.
- System/prompt configuration digests.

### F4. Implement drift engine

Detect:

- Unknown agent.
- New model/provider.
- New or changed tool.
- New MCP/A2A endpoint.
- Expanded credential scope.
- New data class.
- New destination.
- Changed system-instruction digest.
- Missing approval policy for high-risk effect.

Exit criteria:

- The poisoned MCP mode generates a stable, evidence-backed drift finding.
- An unknown agent is observed but never automatically trusted.

## Stage G — Provenance and delegated authority

### G1. Implement source tagging

Assign provenance when content enters through:

- User input.
- Control/system instructions.
- Ticket/email/document sources.
- Web retrieval.
- Tool result.
- Memory read.
- Agent message.

### G2. Implement propagation

- Attach provenance IDs to every model-visible message and tool result.
- Create transform records for summaries and extracted fields.
- Union parent labels conservatively.
- Preserve confidentiality labels independently of trust labels.
- Keep content digests stable without storing content in envelopes.

### G3. Implement memory persistence

- Store provenance alongside every memory object.
- Restore provenance on read.
- Prevent callers from replacing provenance with a higher-trust label.
- Record cross-session and cross-agent memory use.

### G4. Implement delegation context

- Sign parent flow/step and authority references.
- Derive child authority as a subset.
- Enforce delegation-depth and execution-count limits.
- Detect missing parent, broken digest, expired grant and nonce replay.
- Pass only references/digests needed by the downstream agent.

### G5. Implement provenance queries

- Retrieve all sources visible to a proposed action.
- Produce source-to-sink path.
- Distinguish direct content flow from contextual exposure.
- Return transform and sanitizer attestations.

Exit criteria:

- An untrusted document can be traced through summary, delegation, memory and final tool proposal.
- A child agent cannot receive broader authority than the parent.

## Stage H — Deterministic policy, approval and obligations

### H1. Implement policy service

- Load signed Rego bundles.
- Validate bundle signature and version.
- Expose idempotent authorize endpoint.
- Produce stable reason codes and evidence IDs.
- Emit decision event before returning.
- Cache only verified policy data.
- Invalidate cache on policy, ABOM, identity or classification change.

### H2. Implement core inline policies

Required policies:

1. Untrusted or unknown provenance to external send/publish.
2. Authority amplification across delegation.
3. Broken/expired/replayed flow context.
4. ABOM drift at an effect boundary.
5. Destructive action without exact approval.
6. Sensitive data to disallowed destination.
7. Secret access followed by egress in the same flow.
8. Code execution with untrusted influence.
9. Excessive delegation depth or fan-out.
10. Unknown canonical action at a high-risk tool.

### H3. Implement approval workflow

- Create pending request containing human-readable and machine-readable action details.
- Display exact operation, resource, destination, data classes and provenance summary.
- Require approver identity and justification.
- Mint exact-action-bound token.
- Reject mutation after approval.
- Support deny, expiry, cancellation and limited execution count.
- Log all approval activity.

### H4. Implement obligations

- Redact fields.
- Pin destination.
- Force dry-run.
- Reduce result size.
- Remove attachment.
- Substitute scoped credential.
- Apply rate/execution limit.
- Require result validation.

Recompute digests and authorization after obligations modify the request.

### H5. Implement degraded behavior

Configure by risk tier:

- Low risk: cached verified policy may allow while buffering evidence.
- Medium risk: require cached verified policy; otherwise approval.
- High risk: deny or approval when dependencies are unavailable.
- Critical risk: deny.

Exit criteria:

- Every policy has positive, negative and boundary fixtures.
- A deterministic denial cannot be relaxed by AI output or approval-token misuse.

## Stage I — Event pipeline and tamper-evident ledger

### I1. Implement OTel mapping

- Create agent-run, model-call, tool-proposal, policy-decision, tool-effect, memory and delegation spans/events.
- Use shared trace/flow IDs.
- Keep raw content in linked restricted objects rather than general span attributes.
- Version security-specific fields.

### I2. Implement durable ingestion

- Configure collector authentication and local disk queue.
- Publish normalized topics/streams by event type.
- Partition by tenant and agent/flow to preserve relevant ordering.
- Add idempotency keys and dead-letter handling.
- Monitor queue depth and rejected events.

### I3. Implement event canonicalization and hash chain

```text
h[i] = SHA256(canonical_event[i] || h[i-1] || producer_id || sequence[i])
```

- Use deterministic JSON canonicalization.
- Maintain monotonic producer sequence.
- Reject duplicate sequence/nonces.
- Record sequence gaps.
- Verify cross-language fixtures.

### I4. Implement signed checkpoints

- Sign checkpoint containing producer, sequence and current hash.
- Store checkpoint outside the producer's administrative boundary.
- Verify checkpoint chain.
- Expose CLI/API reporting the first broken sequence.

### I5. Compare independent observations

- Join SDK-proposed, policy-decided, gateway-attempted and tool-completed events.
- Detect missing or contradictory stages.
- Create integrity/coverage finding.

Exit criteria:

- Mutation, deletion, insertion and reordering tests are detected.
- The system documents that it is tamper-evident, not universally tamper-proof.

## Stage J — Causal graph and detection engine

### J1. Implement graph model

Node types:

- Human/service principal.
- Agent/workload.
- Model invocation.
- Tool/MCP server.
- Resource.
- Data/provenance object.
- Memory object.
- Credential reference.
- Destination.
- Decision, approval and finding.

Edge types:

- `ACTS_FOR`
- `DELEGATES_TO`
- `CALLS`
- `READS`
- `WRITES`
- `SENDS_TO`
- `INFLUENCED_BY`
- `USES_CREDENTIAL`
- `AUTHORIZED_BY`
- `APPROVED_BY`
- `PARENT_OF`

Every edge includes tenant, flow, event time, source event digest and confidence/evidence class.

### J2. Implement deterministic graph detectors

- First-seen high-risk agent-to-tool edge.
- Confused-deputy path from low-trust source to privileged sink.
- Untrusted memory write affecting another session/agent.
- Unusual delegation depth or fan-out.
- Credential used across unexpected resource classes.
- Secret-read followed by external send.
- New destination after MCP/tool drift.
- Missing parent or event stage.

### J3. Implement finding lifecycle

- Deduplicate by detector, agent, resource and causal-path digest.
- Track open, acknowledged, investigating, contained and closed.
- Preserve detector version and evidence.
- Allow analyst comments without modifying original evidence.
- Link related findings into a case.

Exit criteria:

- A source-to-sink path can be reconstructed without querying raw prompt text.

## Stage K — AI reasoning and security agents

### K1. Implement provider-neutral interface

Interface inputs:

- Analysis type.
- Model profile.
- System prompt/template version.
- Evidence bundle.
- Allowed read-only tools.
- Required JSON schema.
- Token/cost and tool-call limits.
- Safety identifier/correlation metadata.

Interface outputs:

- Validated `AIAnalysis`.
- Provider request metadata.
- Tool-call trace.
- Explicit error category.

### K2. Implement OpenAI adapter

- Use the Responses API.
- Keep model ID configurable; support approved GPT-5.6/GPT-5.5 profiles.
- Request structured output matching the analysis schema.
- Preserve provider response/request IDs.
- Limit tools to the current security-agent role.
- Propagate trace metadata without secrets.
- Handle rate limits, provider refusal, invalid schema and transport errors.

### K3. Implement Claude adapter

- Use the Claude Messages API.
- Keep Claude Opus model ID configurable.
- Produce the same provider-neutral output schema.
- Implement equivalent tool and usage recording.
- Handle provider-specific refusal/error structures behind common categories.

### K4. Implement model registry/router

Each profile declares:

- Provider and exact model ID.
- Approved use cases.
- Reasoning/effort configuration.
- Prompt template and version.
- Tool allowlist.
- Input data classes permitted.
- Maximum input/output/tool use.
- Fallback profile.
- Failure behavior.
- Evaluation report digest.
- Approval status.

Do not silently change production model IDs through a moving alias unless that behavior is explicitly approved.

### K5. Implement privacy-aware evidence assembler

- Select evidence by ID and detector need.
- Prefer metadata, summaries and labeled excerpts over full raw content.
- Delimit untrusted content as evidence, never instructions.
- Include original user/task intent separately from untrusted evidence.
- Remove secrets and prohibited data classes.
- Record exactly which evidence fields were sent.
- Hash the assembled input.

### K6. Implement semantic detector agent

Analyze:

- Goal drift from original task.
- Tool-call necessity and scope.
- Conflict between trusted instructions and external content.
- Suspicious multi-agent delegation purpose.
- Semantic relationship between untrusted source and proposed sink.

Output must include:

- Verdict.
- Confidence/uncertainty.
- Evidence IDs.
- Conflicting instruction IDs.
- Suggested disposition.
- Missing evidence.

### K7. Implement SOC investigator agent

Allowed tools should be read-only:

- Fetch finding.
- Fetch ABOM diff.
- Fetch causal path.
- Fetch policy decision.
- Fetch identity/authority chain.
- Fetch redacted evidence excerpt.
- Search related findings.
- Query allowed Splunk evidence.

The investigator may create a report or recommendation. It cannot approve, change policy, revoke identity or remediate.

### K8. Implement adversarial generator agent

- Generate prompt-injection variants from scenario templates.
- Mutate source channel, wording, encoding, delegation depth and memory placement.
- Produce expected attack goal and candidate forbidden effect.
- Pass generated cases through schema validation, deduplication and human/research review.
- Never treat the generator's own expected verdict as ground truth.

### K9. Implement policy-proposal agent

- Consume false-positive/false-negative cases.
- Propose a policy diff, rationale and affected scenarios.
- Run static validation and full corpus replay.
- Produce impact report.
- Require human approval and signed publication.
- Prevent the proposal agent from writing directly to active policy storage.

### K10. Implement decision combiner

Rules:

- Deterministic deny remains deny.
- Deterministic approval remains at least approval.
- AI may downgrade allow to approval/deny only in configured semantic-hold mode.
- Invalid/low-confidence AI output follows configured deterministic fallback.
- Provider disagreement produces uncertainty or approval; it never expands authority.

### K11. Evaluate AI agents

Measure by model profile:

- Precision, recall and false-positive rate.
- Calibration/confidence reliability.
- Evidence-grounding rate.
- Unsupported-claim rate.
- Tool-call correctness.
- Prompt-injection resistance when evidence is malicious.
- Cost, tokens and runtime latency.
- Provider disagreement.
- Failure/fallback behavior.

Exit criteria:

- Claude and OpenAI adapters pass the same contract suite.
- AI output cannot bypass deterministic controls.
- Every analysis is reproducible from versioned input evidence and configuration, subject to documented model nondeterminism.

## Stage L — Splunk and analyst workflow

### L1. Implement export transformer

Construct a new export object only from allowlisted fields. Do not serialize a raw object and then remove prohibited fields.

Allowed examples:

- Finding ID, type, severity and status.
- Agent/workload identity and owner reference.
- Canonical operation/resource class/destination class.
- Provenance trust classes and source IDs.
- Policy, detector and ABOM versions.
- Decision and approval state.
- Integrity status.
- Restricted evidence pivot URL/ID.

Prohibited examples:

- Full prompts/responses.
- Raw tool results.
- Memory contents.
- Credentials/secrets.
- Full sensitive arguments.
- Hidden reasoning.

### L2. Implement HEC client

- Use dedicated source type.
- Add idempotency/event ID behavior.
- Implement retry and dead-letter storage.
- Validate TLS and secret handling.
- Record export status and response metadata.
- Test against a non-production index.

### L3. Implement analyst views

Minimal views:

- Finding summary.
- Causal source-to-sink path.
- Agent identity and effective authority.
- Declared-versus-observed ABOM diff.
- Pending approval with exact action details.
- Ledger/checkpoint integrity status.
- AI analysis with evidence IDs and uncertainty.

Exit criteria:

- Canary strings never appear in exported Splunk events.
- Analyst can pivot from Splunk to restricted platform evidence.

## Stage M — Adversarial corpus and research evaluation

### M1. Implement scenario runner

- Reset environment.
- Load exact agent/model/policy/ABOM configuration.
- Execute scenario.
- Record proposed, blocked and completed effects.
- Record model/tool traces and provider metadata.
- Compare actual effects with ground truth.
- Persist immutable run record.
- Support repeated runs and deterministic fixtures where possible.

### M2. Implement baseline modes

Required configurations:

1. No security platform.
2. Telemetry only.
3. Static per-agent tool allowlist.
4. Deterministic sink policy without provenance.
5. Provenance without delegated-authority intersection.
6. Full deterministic provenance-authority system.
7. Full system plus AI shadow analysis.
8. Optional semantic-hold configuration.

### M3. Build benign corpus

Include legitimate:

- External sends to approved destinations.
- Destructive actions with proper approval.
- Memory reuse across sessions.
- Delegation to privileged agent within narrowed scope.
- MCP schema upgrade approved in ABOM.
- Secret read without egress.
- Similar language to attacks but benign intent.

### M4. Build attack corpus

Attack families:

- Indirect prompt injection through ticket/document/tool result.
- Persistent memory poisoning.
- Cross-agent confused deputy and authority amplification.
- MCP description/schema poisoning.
- Sensitive-data exfiltration.
- Destructive action without valid approval.
- Approval token mutation/replay.
- Broken/stripped delegation context.
- Shadow agent and ABOM drift.
- Telemetry suppression/tampering.
- Prompt injection targeting the security investigator agent.

### M5. Freeze development and holdout sets

- Keep attack templates and paraphrases separated.
- Keep holdout cases inaccessible to policy/prompt authors.
- Record dataset version and digest.
- Do not change ground truth after observing results without documented correction.

### M6. Compute metrics

Primary metrics:

- Forbidden-effect attack success rate.
- Benign task completion.
- Required-effect completion.
- False-block rate.
- Approval burden.
- Detector precision/recall.
- Provenance continuity.
- Authority-violation detection.
- p50/p95/p99 gate latency.
- End-to-end overhead.
- AI analysis quality and calibration.
- Export canary leakage.
- Integrity-test coverage.

Report denominators, confidence intervals and results by attack family, model, framework and delegation depth.

### M7. Run ablations

Remove or disable one component at a time:

- Provenance propagation.
- Authority intersection.
- ABOM drift.
- Independent egress observation.
- Graph correlation.
- AI semantic analysis.
- Memory provenance.
- Checkpoint verification.

Exit criteria:

- Results demonstrate which component contributes to prevention/detection.
- Failures and bypasses are included, not hidden.

## Stage N — Verification, hardening and release

### N1. Unit and property testing

- Authority never expands.
- Approval token cannot authorize a mutated action.
- Nonce cannot be replayed.
- Expired context fails.
- Canonical event hashes are stable.
- Policy result is deterministic for identical versioned inputs.
- AI result cannot relax deterministic outcome.

### N2. Contract testing

- Framework adapters emit equivalent events.
- Both AI providers satisfy the common interface.
- MCP tools normalize consistently.
- Schema compatibility rules are enforced.
- Splunk transformer cannot access prohibited fields.

### N3. Integration testing

- Agent → SDK/gateway → policy → approval → tool → ledger → graph → finding → Splunk.
- Memory write → different session read → sensitive sink.
- Agent A → Agent B → Agent C with authority attenuation.
- Policy/ABOM update invalidates cache.
- Provider failure leaves deterministic enforcement operational.

### N4. Failure and chaos testing

- Policy service unavailable or slow.
- AI providers unavailable, refusing or rate-limited.
- Broker unavailable and disk buffer full.
- Database/object store unavailable.
- Clock skew.
- Duplicate delivery.
- Delegation loop/fan-out.
- Signing-key revocation.
- Checkpoint anchor unavailable.
- Splunk HEC unavailable.

### N5. Security testing

- Authentication and authorization testing on every internal API.
- Tenant-isolation tests.
- SSRF and destination-validation tests in MCP/AI tools.
- Prompt injection against security agents.
- Tool-output injection.
- Approval-token forgery/replay/mutation.
- Policy-bundle and ABOM signature bypass.
- Log/evidence access-control testing.
- Dependency/container scanning.
- External review of crypto and policy-critical code.

### N6. Reproducible release

- Pin dependencies and container digests.
- Provide one-command local deployment.
- Seed deterministic fixtures.
- Publish scenario runner instructions.
- Archive policy, prompt, schema, ABOM and dataset versions.
- Produce live demo and offline recording.
- Document limitations and non-claims.

## Stage O — Production platformization

### O1. Identity and cryptography

- Replace local keys with workload identity and KMS/HSM-backed signing.
- Implement rotation, revocation and emergency key compromise workflow.
- Require mTLS between platform services.
- Separate tenant and environment trust roots where required.

### O2. Multi-tenancy and access control

- Tenant-scoped storage and queries.
- Administrative RBAC and separation of duties.
- Separate raw-evidence, finding, policy and approval permissions.
- Complete tenant-isolation penetration tests.

### O3. Reliability

- Replicate policy and registry data needed by runtime gates.
- Keep verified local policy cache.
- Implement idempotent ingestion and replay.
- Define backup, restore and disaster-recovery procedures.
- Define SLOs for authorization, event durability and detector lag.

### O4. Scale

- Partition by tenant and agent/flow.
- Measure before introducing specialized stores.
- Load-test event ingestion, policy decisions, graph construction and analyst queries.
- Cap AI concurrency, tokens and spend by tenant/use case.

### O5. Policy and prompt lifecycle

- Draft → validate → corpus replay → review → sign → publish → monitor → rollback.
- Require the same lifecycle for AI prompts and model profiles.
- Prevent moving model aliases from changing behavior without evaluation and approval.

### O6. Controlled onboarding

Rollout modes:

1. Observe only.
2. AI/detector shadow mode.
3. Human approval for selected risks.
4. Enforce critical/high-risk deterministic policies.
5. Expand enforcement based on measured evidence.

Every onboarded agent requires an owner, purpose, declared ABOM, identity, data classification, tool inventory, risk tier, rollback path and support runbook.

## 10. PoC demonstration specification

The demo should prove the security issue and control, not tour the interface.

### Demo A — Indirect injection and egress

1. Load incident containing malicious external instructions.
2. Run without enforcement and show honeytoken reaching fake receiver.
3. Run with static tool allowlist and show why the call still appears valid.
4. Run with provenance-authority enforcement.
5. Show denial before egress.
6. Show source-to-sink path and matched rule.

### Demo B — Persistent memory poisoning

1. Write poisoned memory in one session.
2. Start a new session or agent.
3. Retrieve memory and propose sensitive effect.
4. Show restored provenance and enforcement decision.

### Demo C — Confused deputy

1. Low-privilege agent delegates to response agent.
2. Response agent possesses a broader standing capability.
3. Show effective authority intersection.
4. Show denial of the excessive operation.

### Demo D — MCP drift and log integrity

1. Change approved MCP schema/description/destination.
2. Show observed ABOM diff.
3. Attempt high-risk call and show approval/deny.
4. Edit or remove a ledger event.
5. Run verifier and show first broken sequence/checkpoint.

### Demo E — AI security agent

1. Generate a finding from one attack.
2. Invoke Claude Opus or GPT-based investigator with read-only tools.
3. Show evidence-backed causal summary and uncertainty.
4. Show that the agent cannot remediate or publish a rule.
5. Generate a policy proposal and route it through corpus replay and human review.

## 11. Final definitions of done

### Research PoC

- Two agent implementations use the same contracts.
- All effectful tools pass through the reference monitor or independent gateway.
- Four core attack chains and benign controls are reproducible.
- Authority never expands across delegation.
- Provenance survives tool results, transforms, memory and agent handoff.
- Core deterministic policies block or gate forbidden effects.
- Claude and OpenAI security agents operate through the same validated interface.
- AI agents have restricted identities/tools and cannot directly remediate.
- Raw sensitive canaries do not appear in Splunk exports.
- Ledger mutations are detected after checkpointing.
- Baseline, ablation and holdout results are generated from immutable run records.
- Clean deployment reproduces the demonstration.
- Limitations and bypasses are documented.

### Production v1

- Runtime bypasses are prevented or independently detected.
- Identities, policies, manifests, prompts, model profiles, approvals and checkpoints are signed and revocable.
- High-risk degraded behavior is tested.
- Tenant, raw-evidence and administrative boundaries are independently tested.
- Policy/prompt/model releases require evaluation, approval and rollback.
- Operational SLOs, alerts, runbooks, backup and restore exist.
- Real pilot agents have named owners and accepted risk/approval profiles.
- Security, privacy, platform, SOC and application owners approve production operation.

## 12. Implementation priorities

If scope must be reduced, preserve these in order:

1. Synthetic vulnerable workflow and effect-based ground truth.
2. Canonical action and decision contracts.
3. Tool/MCP interception before effects.
4. Signed context and authority attenuation.
5. Provenance across delegation and memory.
6. Deterministic inline policies and exact approvals.
7. Independent effect observation and tamper-evident records.
8. Baselines, attack corpus and measured evaluation.
9. AI semantic detector and investigator agents.
10. ABOM drift and graph correlation.
11. Splunk export and analyst views.
12. Detection-policy copilot and broader production connectors.

Do not trade away enforcement correctness, ground truth or reproducibility to build a larger dashboard.
