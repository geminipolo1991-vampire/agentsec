from __future__ import annotations

import json
import unittest

from agentsec.analyst import BoundedAnalystEvidenceTool
from agentsec.contracts import AnalystRole, AnalystRoleRequest, utc_now
from agentsec.providers import (
    AnthropicAnalystRoleReasoner,
    AnthropicMessagesReasoner,
    OpenAIAnalystRoleReasoner,
    OpenAIResponsesReasoner,
)
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


def analyst_request():
    item = SecurityPipeline().process(forge_scenarios()["mcp_schema_drift"]).alerts[0]
    tool = BoundedAnalystEvidenceTool()
    evidence, _ = tool.query(
        run_id="air_" + "a" * 32,
        role=AnalystRole.JUDGE,
        manifest=tool.manifest(item),
    )
    return AnalystRoleRequest(
        run_id="air_" + "a" * 32,
        role=AnalystRole.JUDGE,
        alert_id=item.alert.alert_id,
        objective="Judge the supplied evidence without executing an effect.",
        deterministic_action=item.judgment.action,
        priority=item.triage.priority,
        evidence=evidence,
        requested_at=utc_now(),
    )


def analyst_text(request, evidence_id=None):
    evidence_id = evidence_id or request.evidence[0].evidence_id
    return json.dumps(
        {
            "role": "judge",
            "status": "completed",
            "summary": "The bounded evidence supports preserving the deterministic control.",
            "hypothesis": "The detector hypothesis remains plausible.",
            "recommended_action": request.deterministic_action.value,
            "confidence": 0.94,
            "evidence_ids": [evidence_id],
            "claims": [
                {
                    "statement": "The cited evidence contains a recorded alert type.",
                    "subject": request.alert_id,
                    "fact_key": "alert_type",
                    "operator": "exists",
                    "expected_value": None,
                    "evidence_ids": [evidence_id],
                }
            ],
            "reason_codes": ["LIVE_PROVIDER_ROLE_TEST"],
            "alternatives": [
                {
                    "title": "Preserve deterministic control",
                    "rationale": "Human review can confirm scope before any change.",
                    "recommended_action": request.deterministic_action.value,
                    "evidence_ids": [evidence_id],
                }
            ],
            "uncertainties": ["Metadata is not proof of compromise."],
        }
    )


class ProviderAdapterTests(unittest.TestCase):
    def test_openai_analyst_role_is_schema_bound_and_evidence_cited(self) -> None:
        request = analyst_request()
        transport = FakeTransport(
            {
                "id": "resp_analyst_1",
                "status": "completed",
                "model": "gpt-analyst-qualified",
                "error": None,
                "output": [
                    {
                        "type": "message",
                        "content": [
                            {"type": "output_text", "text": analyst_text(request)}
                        ],
                    }
                ],
                "usage": {"input_tokens": 120, "output_tokens": 40, "total_tokens": 160},
            }
        )
        reasoner = OpenAIAnalystRoleReasoner(
            api_key="openai-analyst-key-never-log",
            model_id="gpt-analyst-qualified",
            transport=transport,
        )
        result = reasoner.analyze_role(request)
        call = transport.calls[0]
        self.assertEqual(result.role, AnalystRole.JUDGE)
        self.assertEqual(result.provider, "openai")
        self.assertFalse(call["payload"]["store"])
        self.assertTrue(call["payload"]["text"]["format"]["strict"])
        self.assertNotIn("openai-analyst-key-never-log", json.dumps(call["payload"]))

    def test_anthropic_analyst_role_and_fabricated_citation_are_normalized(self) -> None:
        request = analyst_request()
        good = FakeTransport(
            {
                "id": "msg_analyst_1",
                "model": "claude-analyst-qualified",
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": analyst_text(request)}],
                "usage": {"input_tokens": 100, "output_tokens": 35},
            }
        )
        reasoner = AnthropicAnalystRoleReasoner(
            api_key="anthropic-analyst-key-never-log",
            model_id="claude-analyst-qualified",
            transport=good,
        )
        result = reasoner.analyze_role(request)
        self.assertEqual(result.provider, "anthropic")
        self.assertEqual(reasoner.last_call.usage["total_tokens"], 135)
        self.assertNotIn(
            "anthropic-analyst-key-never-log", json.dumps(good.calls[0]["payload"])
        )

        fabricated = FakeTransport(
            {
                "id": "msg_analyst_bad",
                "model": "claude-analyst-qualified",
                "stop_reason": "end_turn",
                "content": [
                    {
                        "type": "text",
                        "text": analyst_text(
                            request, "outside_sha256:" + "f" * 24
                        ),
                    }
                ],
            }
        )
        bad = AnthropicAnalystRoleReasoner(
            api_key="test-key",
            model_id="claude-analyst-qualified",
            transport=fabricated,
        )
        with self.assertRaisesRegex(ModelUnavailableError, "unknown evidence"):
            bad.analyze_role(request)

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
