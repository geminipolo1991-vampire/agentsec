# Provider integration boundary

`OpenAIResponsesReasoner` and `AnthropicMessagesReasoner` implement the same
`SecurityReasoner` protocol. Both receive only a privacy-transformed evidence
bundle, request schema-constrained JSON, validate the output locally, reject
unknown evidence citations, normalize provider failure, and expose request/model
metadata without credentials.

OpenAI uses `POST /v1/responses` and a strict JSON Schema under `text.format`.
Anthropic uses `POST /v1/messages` and JSON Schema under
`output_config.format`. Exact model IDs have no source-code default: deployment
configuration must select and evaluate a pinned model profile.

Live calls are disabled until credentials are deliberately provided. The current
automated suite uses injected fake transports and the recorded Codex review, so
it verifies request/response contracts without sending evidence to any provider.

The request shapes follow the official [OpenAI Structured Outputs
guide](https://developers.openai.com/api/docs/guides/structured-outputs) and
[Claude Structured Outputs
guide](https://platform.claude.com/docs/en/build-with-claude/structured-outputs).
Claude authentication/version headers follow the official [Claude API
overview](https://platform.claude.com/docs/en/api/overview).
