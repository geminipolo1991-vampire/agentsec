from __future__ import annotations

import json
import unittest

from agentsec.providers import AnthropicMessagesReasoner, OpenAIResponsesReasoner
from agentsec.reasoning import ModelUnavailableError
from agentsec.scenarios import forge_scenarios
from agentsec.pipeline import SecurityPipeline
from agentsec.workflow import Triager


class FakeTransport:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def post(self, url, headers, payload, timeout_seconds):
        self.calls.append(
            {
                "url": url,
                "headers": headers,
                "payload": payload,
                "timeout_seconds": timeout_seconds,
            }
        )
        return self.response


def alert_and_triage():
    event = forge_scenarios()["mcp_schema_drift"]
    alert = SecurityPipeline().detector.detect(event)[0]
    return alert, Triager().assess(alert)


def verdict_text(evidence_id):
    return json.dumps(
        {
            "action": "deny",
            "confidence": 0.97,
            "evidence_ids": [evidence_id],
            "reason_codes": ["UNAPPROVED_SCHEMA_CHANGE"],
            "uncertainty": None,
        }
    )


class ProviderAdapterTests(unittest.TestCase):
    def test_openai_responses_request_and_response_are_normalized(self) -> None:
        alert, triage = alert_and_triage()
        transport = FakeTransport(
            {
                "id": "resp_test_1",
                "status": "completed",
                "model": "gpt-configured-test",
                "error": None,
                "output": [
                    {
                        "type": "message",
                        "content": [
                            {"type": "output_text", "text": verdict_text(alert.evidence[0])}
                        ],
                    }
                ],
                "usage": {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120},
            }
        )
        reasoner = OpenAIResponsesReasoner(
            model_id="gpt-configured-test",
            api_key="openai-test-key-never-log",
            transport=transport,
        )

        verdict = reasoner.analyze(alert, triage)
        call = transport.calls[0]

        self.assertEqual(verdict.provider, "openai")
        self.assertEqual(call["payload"]["text"]["format"]["type"], "json_schema")
        self.assertTrue(call["payload"]["text"]["format"]["strict"])
        self.assertFalse(call["payload"]["store"])
        self.assertNotIn("openai-test-key-never-log", json.dumps(call["payload"]))
        self.assertEqual(reasoner.last_call.request_id, "resp_test_1")

    def test_anthropic_messages_request_and_response_are_normalized(self) -> None:
        alert, triage = alert_and_triage()
        transport = FakeTransport(
            {
                "id": "msg_test_1",
                "model": "claude-configured-test",
                "stop_reason": "end_turn",
                "content": [
                    {"type": "text", "text": verdict_text(alert.evidence[0])}
                ],
                "usage": {"input_tokens": 90, "output_tokens": 18},
            }
        )
        reasoner = AnthropicMessagesReasoner(
            model_id="claude-configured-test",
            api_key="anthropic-test-key-never-log",
            transport=transport,
        )

        verdict = reasoner.analyze(alert, triage)
        call = transport.calls[0]

        self.assertEqual(verdict.provider, "anthropic")
        self.assertEqual(
            call["payload"]["output_config"]["format"]["type"], "json_schema"
        )
        self.assertEqual(call["headers"]["anthropic-version"], "2023-06-01")
        self.assertNotIn("anthropic-test-key-never-log", json.dumps(call["payload"]))
        self.assertEqual(reasoner.last_call.usage["total_tokens"], 108)

    def test_unknown_model_evidence_citation_is_rejected(self) -> None:
        alert, triage = alert_and_triage()
        transport = FakeTransport(
            {
                "id": "resp_test_bad",
                "status": "completed",
                "model": "gpt-configured-test",
                "error": None,
                "output": [
                    {
                        "type": "message",
                        "content": [
                            {"type": "output_text", "text": verdict_text("fabricated-evidence")}
                        ],
                    }
                ],
            }
        )
        reasoner = OpenAIResponsesReasoner(
            model_id="gpt-configured-test", api_key="test-key", transport=transport
        )

        with self.assertRaisesRegex(ModelUnavailableError, "unknown evidence"):
            reasoner.analyze(alert, triage)

    def test_anthropic_refusal_uses_normalized_failure(self) -> None:
        alert, triage = alert_and_triage()
        reasoner = AnthropicMessagesReasoner(
            model_id="claude-configured-test",
            api_key="test-key",
            transport=FakeTransport(
                {
                    "id": "msg_refusal",
                    "model": "claude-configured-test",
                    "stop_reason": "refusal",
                    "content": [{"type": "text", "text": "refused"}],
                }
            ),
        )

        with self.assertRaisesRegex(ModelUnavailableError, "refusal"):
            reasoner.analyze(alert, triage)

    def test_extra_structured_output_field_is_rejected_locally(self) -> None:
        alert, triage = alert_and_triage()
        raw = json.loads(verdict_text(alert.evidence[0]))
        raw["execute_remediation"] = True
        transport = FakeTransport(
            {
                "id": "resp_extra_field",
                "status": "completed",
                "model": "gpt-configured-test",
                "error": None,
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": json.dumps(raw)}],
                    }
                ],
            }
        )
        reasoner = OpenAIResponsesReasoner(
            model_id="gpt-configured-test", api_key="test-key", transport=transport
        )

        with self.assertRaisesRegex(ModelUnavailableError, "schema validation"):
            reasoner.analyze(alert, triage)

    def test_unexpected_response_model_id_is_rejected(self) -> None:
        alert, triage = alert_and_triage()
        transport = FakeTransport(
            {
                "id": "resp_wrong_model",
                "status": "completed",
                "model": "moving-alias-returned-different-model",
                "error": None,
                "output": [
                    {
                        "type": "message",
                        "content": [
                            {"type": "output_text", "text": verdict_text(alert.evidence[0])}
                        ],
                    }
                ],
            }
        )
        reasoner = OpenAIResponsesReasoner(
            model_id="gpt-configured-test", api_key="test-key", transport=transport
        )

        with self.assertRaisesRegex(ModelUnavailableError, "model ID"):
            reasoner.analyze(alert, triage)


if __name__ == "__main__":
    unittest.main()
