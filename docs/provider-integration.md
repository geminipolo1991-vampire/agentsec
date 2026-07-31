# Provider integration and governed model boundary

`OpenAIResponsesReasoner` and `AnthropicMessagesReasoner` implement the same
`SecurityReasoner` protocol. Both receive only a privacy-transformed evidence
bundle, request schema-constrained JSON, validate the output locally, reject
unknown evidence citations, normalize provider failure, and expose request/model
metadata without credentials.

OpenAIAnalystRoleReasoner and AnthropicAnalystRoleReasoner expose the same five
read-only role contract used by the AI analyst engine. Provider-authored
identity/timestamps are not accepted; role, schema, citation, authority, and
deterministic non-relaxation are validated locally.

OpenAI uses `POST /v1/responses` and a strict JSON Schema under `text.format`.
Anthropic uses `POST /v1/messages` and JSON Schema under
`output_config.format`. Exact model IDs have no source-code default: deployment
configuration must select and evaluate a pinned model profile.

Live calls are disabled until credentials are deliberately provided. The current
automated suite uses injected fake transports and the recorded Codex review, so
it verifies request/response contracts without sending evidence to any provider.

Live credentials alone cannot enable a call. ModelGatewayService additionally
requires an immutable exact-model route, immutable prompt/schema version,
environment-backed secret fingerprint, current passed qualification, candidate
to shadow to active lifecycle, compatible mode/privacy class, available
transactional request/token/concurrency budget, and closed health circuit.
Provider failure may use only an independently qualified compatible fallback.
The call ledger stores digests and usage metadata, never raw inputs or outputs.

The dependency-free HTTPS transport refuses redirects, bounds response bytes,
requires a JSON content type, and uses exact HTTPS host/path allowlists. OpenAI
requests set store false; this request property does not replace provider
organization retention, residency, or account-policy verification.

The request shapes follow the official [OpenAI Structured Outputs
guide](https://developers.openai.com/api/docs/guides/structured-outputs) and
[Responses migration guide](https://developers.openai.com/api/docs/guides/migrate-to-responses#additional-differences).
The exact request fields are also checked against the official
[Responses create reference](https://developers.openai.com/api/reference/resources/responses/methods/create).
Structured output is an output-shape control, not proof that a claim is true;
AgentSec therefore retains application-side validation. Module 16 now requires
typed provider claims and checks each fact/operator against its exact cited
evidence, applies mandatory-evidence and confidence policy, detects conflicting
claims and instruction-like output, and emits a human gate when support is not
sufficient.

Anthropic request shapes follow the official
[Claude Structured Outputs
guide](https://platform.claude.com/docs/en/build-with-claude/structured-outputs).
Claude authentication/version headers follow the official [Claude API
overview](https://platform.claude.com/docs/en/api/overview).

Operational configuration and the complete lifecycle are documented in
docs/modules/module-15-model-gateway-and-ai-governance.md; the checked-in
example creates candidates only and contains no active provider claim.

Module 23 adds a separate evaluation qualification track. A live evaluation
candidate must bind the exact provider/model, route digest, and an external
qualification digest before an authorized run can invoke it. The model receives
only the blinded case, never expected labels or gate thresholds, and remains
non-executive. A new OpenAI or Claude route must pass the 42-case absolute gate,
per-use-case checks, privacy canaries, and approved-baseline drift before its
evaluation record can support a release decision. The committed track remains
recorded Codex and makes no live-provider claim.
