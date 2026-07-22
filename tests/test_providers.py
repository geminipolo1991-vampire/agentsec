from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from agentsec.contracts import AiMode, DecisionAction
from agentsec.model_registry import ModelRegistry, ReasonerRouter
from agentsec.pipeline import SecurityPipeline
from agentsec.providers import (
    AnthropicMessagesReasoner,
    OpenAIResponsesReasoner,
    validate_provider_endpoint,
)
from agentsec.reasoning import ModelUnavailableError, RecordedCodexReasoner
from agentsec.scenarios import forge_scenarios


class RecordingTransport:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def post(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


def verdict_text(evidence_ids, action="deny"):
    return json.dumps(
        {
            "action": action,
            "confidence": 0.97,
            "evidence_ids": evidence_ids,
            "reason_codes": ["PROVIDER_STRUCTURED_TEST"],
            "uncertainty": None,
        }
    )


class ProviderAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        event = forge_scenarios()["mcp_schema_drift"]
        result = SecurityPipeline().process(event)
        self.alert = result.alerts[0].alert
        self.triage = result.alerts[0].triage
        self.evidence_ids = list(self.alert.evidence)

    def test_openai_request_and_response_follow_provider_contract(self) -> None:
        transport = RecordingTransport(
            {
                "status": "completed",
                "error": None,
                "output": [
                    {
                        "type": "message",
                        "content": [
                            {
                                "type": "output_text",
                                "text": verdict_text(self.evidence_ids),
                            }
                        ],
                    }
                ],
            }
        )
        adapter = OpenAIResponsesReasoner(
            api_key="openai-test-secret",
            model_id="openai-exact-evaluated-model",
            transport=transport,
        )

        verdict = adapter.analyze(self.alert, self.triage)
        call = transport.calls[0]

        self.assertEqual(verdict.provider, "openai")
        self.assertEqual(verdict.action, DecisionAction.DENY)
        self.assertEqual(call["url"], "https://api.openai.com/v1/responses")
        self.assertFalse(call["payload"]["store"])
        self.assertTrue(call["payload"]["text"]["format"]["strict"])
        self.assertEqual(call["payload"]["tools"] if "tools" in call["payload"] else [], [])
        self.assertNotIn("openai-test-secret", json.dumps(call["payload"]))

    def test_anthropic_request_and_response_follow_provider_contract(self) -> None:
        transport = RecordingTransport(
            {
                "stop_reason": "end_turn",
                "content": [
                    {"type": "text", "text": verdict_text(self.evidence_ids)}
                ],
            }
        )
        adapter = AnthropicMessagesReasoner(
            api_key="anthropic-test-secret",
            model_id="anthropic-exact-evaluated-model",
            transport=transport,
        )

        verdict = adapter.analyze(self.alert, self.triage)
        call = transport.calls[0]

        self.assertEqual(verdict.provider, "anthropic")
        self.assertEqual(call["url"], "https://api.anthropic.com/v1/messages")
        self.assertEqual(call["headers"]["anthropic-version"], "2023-06-01")
        self.assertEqual(
            call["payload"]["output_config"]["format"]["type"], "json_schema"
        )
        self.assertNotIn("anthropic-test-secret", json.dumps(call["payload"]))

    def test_provider_cannot_cite_unsupplied_evidence(self) -> None:
        transport = RecordingTransport(
            {
                "status": "completed",
                "error": None,
                "output": [
                    {
                        "type": "message",
                        "content": [
                            {
                                "type": "output_text",
                                "text": verdict_text(["invented-evidence-id"]),
                            }
                        ],
                    }
                ],
            }
        )
        adapter = OpenAIResponsesReasoner(
            api_key="test-secret", model_id="exact-model", transport=transport
        )

        with self.assertRaisesRegex(ModelUnavailableError, "outside the supplied"):
            adapter.analyze(self.alert, self.triage)

    def test_refusal_and_truncation_use_deterministic_fallback(self) -> None:
        transport = RecordingTransport({"stop_reason": "max_tokens", "content": []})
        adapter = AnthropicMessagesReasoner(
            api_key="test-secret", model_id="exact-model", transport=transport
        )

        with self.assertRaisesRegex(ModelUnavailableError, "max_tokens"):
            adapter.analyze(self.alert, self.triage)

    def test_endpoint_allowlist_blocks_ssrf_and_plain_http(self) -> None:
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            validate_provider_endpoint(
                "http://api.openai.com/v1/responses",
                {"api.openai.com"},
                "/v1/responses",
            )
        with self.assertRaisesRegex(ValueError, "host"):
            validate_provider_endpoint(
                "https://169.254.169.254/latest/meta-data",
                {"api.openai.com"},
                "/v1/responses",
            )


class ModelRegistryTests(unittest.TestCase):
    def test_profiles_require_environment_configuration_and_no_keys_in_file(self) -> None:
        path = Path("configs/model-profiles.json")
        registry = ModelRegistry.from_path(path)
        encoded = path.read_text(encoding="utf-8")

        self.assertNotIn("sk-", encoded)
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "model ID"):
                registry.resolve_environment("openai-api-tokyo")

    def test_router_uses_explicit_enabled_fallback_without_cycle(self) -> None:
        registry = ModelRegistry.from_path(Path("configs/model-profiles.json"))
        codex = RecordedCodexReasoner.from_path(Path("configs/codex-evaluation.json"))
        router = ReasonerRouter(
            {"codex-recorded-shadow": codex}, registry=registry
        )

        selected = router.select("openai-api-tokyo", AiMode.SHADOW)

        self.assertIs(selected, codex)


if __name__ == "__main__":
    unittest.main()
