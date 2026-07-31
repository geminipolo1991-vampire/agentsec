from __future__ import annotations

import json
import unittest

from agentsec.contracts import (
    AnalystEvidenceItem,
    AnalystRole,
    AnalystRoleRequest,
    DecisionAction,
    utc_now,
)
from agentsec.providers import (
    AnthropicAnalystRoleReasoner,
    OpenAIAnalystRoleReasoner,
)
from agentsec.reasoning import ModelUnavailableError


class RecordingTransport:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def post(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


def role_request(role=AnalystRole.JUDGE):
    evidence_id = "analyst-alert_sha256:" + "a" * 24
    return AnalystRoleRequest(
        run_id="air_" + "b" * 32,
        role=role,
        alert_id="alr_test_gateway",
        objective="Assess the security evidence without executing any action.",
        deterministic_action=DecisionAction.DENY,
        priority="P1",
        evidence=[
            AnalystEvidenceItem(
                evidence_id=evidence_id,
                kind="detector",
                source="test-detector",
                observed_at=utc_now(),
                facts={"reason_codes": ["PROMPT_INJECTION"]},
            )
        ],
        requested_at=utc_now(),
    )


def payload(request, *, action="deny", evidence_id=None):
    evidence_id = evidence_id or request.evidence[0].evidence_id
    return json.dumps(
        {
            "role": request.role.value,
            "status": "completed",
            "summary": "The cited detector evidence supports preserving the deterministic control.",
            "hypothesis": "Untrusted content attempted to influence agent behavior.",
            "recommended_action": action if request.role == AnalystRole.JUDGE else None,
            "escalation_advice": "Queue an independent human review.",
            "response_advice": ["Preserve the deny decision."],
            "confidence": 0.97,
            "evidence_ids": [evidence_id],
            "claims": [
                {
                    "statement": "The detector recorded the cited prompt-injection reason code.",
                    "subject": request.alert_id,
                    "fact_key": "reason_codes",
                    "operator": "contains",
                    "expected_value": "PROMPT_INJECTION",
                    "evidence_ids": [evidence_id],
                }
            ],
            "reason_codes": ["CITED_SECURITY_EVIDENCE"],
            "alternatives": [
                {
                    "title": "Preserve deterministic control",
                    "rationale": "The cited evidence supports the existing decision.",
                    "recommended_action": "deny",
                    "evidence_ids": [evidence_id],
                }
            ],
            "uncertainties": ["Independent identity context was unavailable."],
            "abstention_reason": None,
        }
    )


class AnalystProviderAdapterTests(unittest.TestCase):
    def test_openai_role_adapter_is_stateless_structured_and_locally_validated(self):
        request = role_request()
        transport = RecordingTransport(
            {
                "id": "resp_role_test",
                "status": "completed",
                "error": None,
                "model": "gpt-exact-role-test",
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": payload(request)}],
                    }
                ],
                "usage": {"input_tokens": 120, "output_tokens": 40, "total_tokens": 160},
            }
        )
        adapter = OpenAIAnalystRoleReasoner(
            api_key="test-openai-role-credential",
            model_id="gpt-exact-role-test",
            transport=transport,
        )

        result = adapter.analyze_role(request)
        call = transport.calls[0]

        self.assertEqual(result.provider, "openai")
        self.assertEqual(result.recommended_action, DecisionAction.DENY)
        self.assertEqual(len(result.claims), 1)
        self.assertEqual(result.claims[0].fact_key, "reason_codes")
        self.assertFalse(call["payload"]["store"])
        self.assertTrue(call["payload"]["text"]["format"]["strict"])
        self.assertNotIn("test-openai-role-credential", json.dumps(call["payload"]))
        self.assertEqual(adapter.last_call.usage["total_tokens"], 160)

    def test_anthropic_role_adapter_uses_schema_and_normalizes_usage(self):
        request = role_request(AnalystRole.TRIAGE)
        transport = RecordingTransport(
            {
                "id": "msg_role_test",
                "model": "claude-exact-role-test",
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": payload(request)}],
                "usage": {"input_tokens": 110, "output_tokens": 35},
            }
        )
        adapter = AnthropicAnalystRoleReasoner(
            api_key="test-anthropic-role-credential",
            model_id="claude-exact-role-test",
            transport=transport,
        )

        result = adapter.analyze_role(request)

        self.assertEqual(result.provider, "anthropic")
        self.assertIsNone(result.recommended_action)
        self.assertEqual(
            transport.calls[0]["payload"]["output_config"]["format"]["type"],
            "json_schema",
        )
        self.assertEqual(adapter.last_call.usage["total_tokens"], 145)

    def test_unknown_citation_and_deterministic_relaxation_are_rejected(self):
        request = role_request()
        for text, expected in (
            (payload(request, evidence_id="analyst-alert_sha256:" + "f" * 24), "unknown evidence"),
            (payload(request, action="allow"), "deterministic relaxation"),
        ):
            adapter = OpenAIAnalystRoleReasoner(
                api_key="test-credential",
                model_id="gpt-exact-role-test",
                transport=RecordingTransport(
                    {
                        "status": "completed",
                        "error": None,
                        "model": "gpt-exact-role-test",
                        "output": [
                            {
                                "type": "message",
                                "content": [{"type": "output_text", "text": text}],
                            }
                        ],
                    }
                ),
            )
            with self.assertRaisesRegex(ModelUnavailableError, expected):
                adapter.analyze_role(request)


if __name__ == "__main__":
    unittest.main()
