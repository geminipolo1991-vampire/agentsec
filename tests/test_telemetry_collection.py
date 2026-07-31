from __future__ import annotations

import base64
import hashlib
import hmac
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agentsec.contracts import DecisionAction, TrustClass
from agentsec.pipeline import SecurityPipeline
from agentsec.redaction import Redactor
from agentsec.telemetry import (
    AnthropicMessagesTelemetryAdapter,
    AgentSecTelemetryClient,
    CaptureStatus,
    CollectionMode,
    CollectorConfig,
    JsonlTelemetryReplayer,
    LangChainCallbackTelemetryAdapter,
    McpJsonRpcTelemetryAdapter,
    HttpTelemetryDeliveryTransport,
    OpenAIResponsesTelemetryAdapter,
    OpenTelemetrySpanAdapter,
    ProtectedContent,
    SignedHttpTelemetryDeliveryTransport,
    TelemetryCollector,
    TelemetryContext,
    TelemetryEventKind,
    TelemetryInput,
    ToolCallTelemetryAdapter,
    agent_event_from_telemetry,
    validate_telemetry_endpoint,
)


CANARY = "MODULE1-RAW-SECRET-CANARY"


class FakeContentProtector:
    def protect(self, payload, *, field_name, context):
        return ProtectedContent(
            ciphertext=base64.b64encode(payload).decode("ascii"),
            key_reference="test-key://%s/%s" % (context.tenant_id, field_name),
            algorithm="TEST-ONLY-BASE64",
        )


class RecordingDeliveryTransport:
    def __init__(self):
        self.events = []
        self.batches = []

    def send(self, event):
        self.events.append(event)
        return {"status": "accepted"}

    def send_batch(self, events):
        self.batches.append(events)
        return {"accepted": len(events)}


class RecordingHttpClient:
    def __init__(self):
        self.calls = []

    def post(self, **kwargs):
        self.calls.append(kwargs)
        return {"status": "accepted"}


def context(**updates):
    values = {
        "tenant_id": "tenant-a",
        "application_id": "support-app",
        "agent_id": "triage-agent",
        "session_id": "session-1",
        "trace_id": "trace-1",
        "source_id": "sdk://python/support-app",
        "source_type": "python-sdk",
        "collector_id": "collector-local",
        "environment": "test",
    }
    values.update(updates)
    return TelemetryContext(**values)


def telemetry_input(**updates):
    values = {
        "event_id": "tel_module1_001",
        "context": context(),
        "kind": TelemetryEventKind.MODEL_REQUEST,
        "operation": "model.generate",
        "resource": "model://test/model",
        "sequence": 1,
        "content": {"input": {"prompt": "summarize the ticket"}},
    }
    values.update(updates)
    return TelemetryInput(**values)


class PrivacyBoundaryTests(unittest.TestCase):
    def test_metadata_only_capture_never_copies_raw_content(self) -> None:
        item = telemetry_input(content={"input": {"prompt": CANARY}})

        captured = TelemetryCollector().capture(item)
        encoded = captured.model_dump_json()

        self.assertEqual(captured.receipt.status, CaptureStatus.ACCEPTED)
        self.assertNotIn(CANARY, encoded)
        self.assertEqual(
            captured.event.content_evidence[0].byte_length,
            len(json.dumps({"prompt": CANARY}, separators=(",", ":"), sort_keys=True)),
        )
        self.assertIsNone(captured.event.content_evidence[0].redacted_preview)
        self.assertRegex(captured.event.content_evidence[0].sha256, r"^[0-9a-f]{64}$")

    def test_redacted_mode_keeps_only_bounded_redacted_preview(self) -> None:
        collector = TelemetryCollector(
            CollectorConfig(collection_mode=CollectionMode.REDACTED),
            redactor=Redactor(canaries={CANARY}),
        )

        captured = collector.capture(
            telemetry_input(
                content={
                    "input": {
                        "prompt": "process %s" % CANARY,
                        "api_key": "secret-provider-key-value",
                    }
                }
            )
        )
        evidence = captured.event.content_evidence[0]

        self.assertEqual(captured.receipt.status, CaptureStatus.ACCEPTED)
        self.assertNotIn(CANARY, captured.model_dump_json())
        self.assertNotIn("secret-provider-key-value", captured.model_dump_json())
        self.assertIn("[REDACTED]", evidence.redacted_preview)
        self.assertGreaterEqual(evidence.redaction_count, 2)

    def test_encrypted_raw_mode_requires_explicit_protector(self) -> None:
        with self.assertRaisesRegex(ValueError, "ContentProtector"):
            TelemetryCollector(
                CollectorConfig(collection_mode=CollectionMode.ENCRYPTED_RAW)
            )

        collector = TelemetryCollector(
            CollectorConfig(collection_mode=CollectionMode.ENCRYPTED_RAW),
            protector=FakeContentProtector(),
        )
        captured = collector.capture(telemetry_input(content={"input": CANARY}))
        evidence = captured.event.content_evidence[0]

        self.assertEqual(captured.receipt.status, CaptureStatus.ACCEPTED)
        self.assertNotIn(CANARY, captured.model_dump_json())
        self.assertEqual(evidence.protection_algorithm, "TEST-ONLY-BASE64")
        self.assertEqual(evidence.key_reference, "test-key://tenant-a/input")
        self.assertIsNone(evidence.redacted_preview)

    def test_oversized_content_is_omitted_but_metadata_is_observable(self) -> None:
        collector = TelemetryCollector(
            CollectorConfig(max_content_bytes=8)
        )

        captured = collector.capture(telemetry_input(content={"input": "long-value"}))

        self.assertEqual(captured.receipt.status, CaptureStatus.ACCEPTED)
        self.assertEqual(
            captured.event.content_evidence[0].omitted_reason, "content_size_limit"
        )
        self.assertEqual(captured.source_health.omitted_content_fields, 1)
        self.assertEqual(captured.source_health.status, "degraded")


class CollectorReliabilityTests(unittest.TestCase):
    def test_duplicate_late_gap_and_out_of_order_activity_is_measured(self) -> None:
        collector = TelemetryCollector(CollectorConfig(late_after_seconds=1))
        old = datetime.now(timezone.utc) - timedelta(minutes=10)

        first = collector.capture(telemetry_input(occurred_at=old, sequence=1))
        duplicate = collector.capture(telemetry_input(occurred_at=old, sequence=1))
        third = collector.capture(
            telemetry_input(event_id="tel_module1_003", occurred_at=old, sequence=3)
        )
        second = collector.capture(
            telemetry_input(event_id="tel_module1_002", occurred_at=old, sequence=2)
        )

        self.assertEqual(first.receipt.status, CaptureStatus.ACCEPTED)
        self.assertEqual(duplicate.receipt.status, CaptureStatus.DUPLICATE)
        self.assertEqual(second.source_health.accepted_events, 3)
        self.assertEqual(second.source_health.duplicate_events, 1)
        self.assertEqual(second.source_health.late_events, 3)
        self.assertEqual(second.source_health.observed_sequence_gaps, 1)
        self.assertEqual(second.source_health.out_of_order_events, 1)
        self.assertEqual(third.source_health.last_sequence, 3)

    def test_malformed_and_unknown_attribute_inputs_are_rejected_without_echo(self) -> None:
        collector = TelemetryCollector(
            CollectorConfig(allowed_attribute_keys={"safe"})
        )

        malformed = collector.capture(
            {
                "event_id": "tel_bad_001",
                "context": {"collector_id": "bad", "source_id": "source"},
                "content": {"input": CANARY},
            }
        )
        unknown = collector.capture(
            telemetry_input(attributes={"unsafe": CANARY})
        )

        self.assertEqual(malformed.receipt.status, CaptureStatus.REJECTED)
        self.assertEqual(unknown.receipt.status, CaptureStatus.REJECTED)
        self.assertNotIn(CANARY, malformed.model_dump_json())
        self.assertNotIn(CANARY, unknown.model_dump_json())
        self.assertEqual(unknown.receipt.reason_codes, ["unknown_telemetry_attributes"])

    def test_batch_and_stream_paths_share_capture_semantics(self) -> None:
        collector = TelemetryCollector(CollectorConfig(max_batch_events=2))
        items = [
            telemetry_input(event_id="tel_batch_001", sequence=1),
            telemetry_input(event_id="tel_batch_002", sequence=2),
            telemetry_input(event_id="tel_batch_003", sequence=3),
        ]

        batch = collector.capture_batch(items)

        self.assertEqual(batch.accepted, 2)
        self.assertEqual(batch.rejected, 1)
        self.assertEqual(batch.receipts[-1].reason_codes, ["batch_event_limit_exceeded"])

        stream_collector = TelemetryCollector()
        captures = list(stream_collector.capture_stream(items[:2]))
        self.assertEqual([item.receipt.status for item in captures], [
            CaptureStatus.ACCEPTED,
            CaptureStatus.ACCEPTED,
        ])

    def test_bounded_jsonl_replay_reports_bad_records_and_duplicates(self) -> None:
        collector = TelemetryCollector()
        payload = telemetry_input(event_id="tel_replay_001").model_dump(mode="json")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(
                json.dumps(payload) + "\n" + "not-json\n" + json.dumps(payload) + "\n",
                encoding="utf-8",
            )

            result = JsonlTelemetryReplayer(collector).replay(path)

        self.assertEqual(result.accepted, 1)
        self.assertEqual(result.rejected, 1)
        self.assertEqual(result.duplicates, 1)
        self.assertIn("invalid_jsonl_record", result.receipts[1].reason_codes)

    def test_concurrent_duplicate_capture_accepts_exactly_once(self) -> None:
        collector = TelemetryCollector()
        item = telemetry_input(event_id="tel_concurrent_001")

        with ThreadPoolExecutor(max_workers=8) as executor:
            captures = list(executor.map(lambda _index: collector.capture(item), range(32)))

        statuses = [capture.receipt.status for capture in captures]
        self.assertEqual(statuses.count(CaptureStatus.ACCEPTED), 1)
        self.assertEqual(statuses.count(CaptureStatus.DUPLICATE), 31)

    def test_duplicate_identity_is_tenant_scoped(self) -> None:
        collector = TelemetryCollector()
        first = telemetry_input(event_id="tel_shared_name")
        second = telemetry_input(
            event_id="tel_shared_name",
            context=context(tenant_id="tenant-b"),
        )

        self.assertEqual(collector.capture(first).receipt.status, CaptureStatus.ACCEPTED)
        self.assertEqual(collector.capture(second).receipt.status, CaptureStatus.ACCEPTED)


class PythonSdkTests(unittest.TestCase):
    def test_client_excludes_content_by_default_and_requires_explicit_opt_in(self) -> None:
        transport = RecordingDeliveryTransport()
        default_client = AgentSecTelemetryClient(transport)
        content_client = AgentSecTelemetryClient(transport, include_content=True)
        item = telemetry_input(content={"input": CANARY})

        default_client.emit(item)
        content_client.emit(item)

        self.assertEqual(transport.events[0].content, {})
        self.assertEqual(transport.events[1].content, {"input": CANARY})
        self.assertEqual(item.content, {"input": CANARY})

    def test_http_transport_validates_origin_and_keeps_token_out_of_payload(self) -> None:
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            validate_telemetry_endpoint("http://agentsec.example.test")
        with self.assertRaisesRegex(ValueError, "credentials"):
            validate_telemetry_endpoint("https://user:pass@agentsec.example.test")
        self.assertEqual(
            validate_telemetry_endpoint(
                "http://127.0.0.1:8080", allow_loopback_http=True
            ),
            "http://127.0.0.1:8080",
        )
        http_client = RecordingHttpClient()
        transport = HttpTelemetryDeliveryTransport(
            endpoint="http://127.0.0.1:8080",
            token="module1-test-token",
            allow_loopback_http=True,
            http_client=http_client,
        )

        transport.send(telemetry_input(content={}))

        self.assertEqual(http_client.calls[0]["url"], "http://127.0.0.1:8080/v1/telemetry")
        self.assertEqual(
            http_client.calls[0]["headers"]["Authorization"],
            "Bearer module1-test-token",
        )
        self.assertNotIn("module1-test-token", json.dumps(http_client.calls[0]["payload"]))

    def test_signed_http_transport_binds_path_body_timestamp_and_nonce(self) -> None:
        http_client = RecordingHttpClient()
        secret = "signed-sdk-secret-that-is-at-least-thirty-two-characters"
        transport = SignedHttpTelemetryDeliveryTransport(
            endpoint="http://127.0.0.1:8080",
            credential_id="python-sdk-test",
            secret=secret,
            allow_loopback_http=True,
            http_client=http_client,
        )

        transport.send(telemetry_input(content={}))

        call = http_client.calls[0]
        headers = call["headers"]
        body = json.dumps(
            call["payload"], separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        canonical = ("POST\n/v1/telemetry\n%s\n%s\n%s" % (
            headers["X-AgentSec-Timestamp"],
            headers["X-AgentSec-Nonce"],
            hashlib.sha256(body).hexdigest(),
        )).encode("utf-8")
        expected = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-AgentSec-Key-Id"], "python-sdk-test")
        self.assertEqual(headers["X-AgentSec-Signature"], "v1=%s" % expected)
        self.assertNotIn(secret, json.dumps(call))


class AdapterTests(unittest.TestCase):
    allowed = {
        "api_operation",
        "provider_status",
        "provider_request_id",
        "finish_reason",
        "otel_span_name",
    }

    def collector(self):
        return TelemetryCollector(
            CollectorConfig(allowed_attribute_keys=self.allowed)
        )

    def test_openai_responses_adapter_collects_usage_without_raw_content(self) -> None:
        events = OpenAIResponsesTelemetryAdapter.normalize(
            context(),
            {"model": "gpt-test", "input": CANARY},
            {
                "id": "resp-1",
                "model": "gpt-test",
                "status": "completed",
                "output": [{"type": "message", "content": CANARY}],
                "usage": {"input_tokens": 12, "output_tokens": 7},
            },
            sequence_start=1,
        )

        result = self.collector().capture_batch(events)

        self.assertEqual(result.accepted, 2)
        self.assertNotIn(CANARY, result.model_dump_json())
        self.assertEqual(result.events[1].input_tokens, 12)
        self.assertEqual(result.events[1].output_tokens, 7)
        self.assertTrue(result.events[1].success)

    def test_anthropic_messages_adapter_collects_stop_reason_and_usage(self) -> None:
        events = AnthropicMessagesTelemetryAdapter.normalize(
            context(),
            {"model": "claude-test", "messages": [{"role": "user", "content": CANARY}]},
            {
                "id": "msg-1",
                "model": "claude-test",
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": CANARY}],
                "usage": {"input_tokens": 9, "output_tokens": 4},
            },
            sequence_start=3,
        )

        result = self.collector().capture_batch(events)

        self.assertEqual(result.accepted, 2)
        self.assertNotIn(CANARY, result.model_dump_json())
        self.assertEqual(result.events[1].attributes["finish_reason"], "end_turn")
        self.assertEqual(result.events[1].sequence, 4)

    def test_tool_adapter_separates_arguments_and_results_from_metadata(self) -> None:
        events = ToolCallTelemetryAdapter.normalize(
            context(),
            tool_name="ticket_export",
            operation="external.send",
            resource="ticket://123",
            destination="https://receiver.invalid",
            arguments={"token": CANARY},
            result={"status": CANARY},
            sequence_start=5,
        )

        result = self.collector().capture_batch(events)

        self.assertEqual(result.accepted, 2)
        self.assertNotIn(CANARY, result.model_dump_json())
        self.assertEqual(result.events[0].kind, TelemetryEventKind.TOOL_CALL_REQUEST)
        self.assertEqual(result.events[1].kind, TelemetryEventKind.TOOL_CALL_RESULT)
        self.assertEqual(result.events[0].destination, "https://receiver.invalid")

    def test_trusted_gateway_context_bridges_tool_telemetry_into_enforcement(self) -> None:
        events = ToolCallTelemetryAdapter.normalize(
            context(),
            tool_name="ticket_export",
            operation="external.send",
            resource="ticket://123",
            destination="https://receiver.invalid",
            arguments={"ticket": CANARY},
            result={"status": "not-executed"},
            data_classes={"secret"},
            indicators={"indirect_prompt_injection"},
        )
        captured = self.collector().capture(events[0])

        event = agent_event_from_telemetry(
            captured.event,
            source_trust=TrustClass.EXTERNAL_UNTRUSTED,
            authority_operations={"external.send"},
        )
        result = SecurityPipeline().process(event)

        self.assertEqual(result.overall_action, DecisionAction.DENY)
        self.assertEqual(
            {item.alert.alert_type for item in result.alerts},
            {"indirect_prompt_injection", "secret_egress"},
        )
        self.assertNotIn(CANARY, result.model_dump_json())

    def test_otel_adapter_uses_only_allowlisted_semantic_fields(self) -> None:
        event = OpenTelemetrySpanAdapter.normalize(
            context(),
            {
                "event_id": "tel_otel_001",
                "name": "chat completion",
                "span_id": "span-1",
                "start_time": datetime.now(timezone.utc).isoformat(),
                "attributes": {
                    "gen_ai.operation.name": "chat",
                    "gen_ai.provider.name": "openai",
                    "gen_ai.request.model": "gpt-test",
                    "gen_ai.input.messages": [{"content": CANARY}],
                    "gen_ai.output.messages": [{"content": CANARY}],
                    "gen_ai.usage.input_tokens": 3,
                    "gen_ai.usage.output_tokens": 2,
                    "untrusted.arbitrary.attribute": CANARY,
                },
            },
        )

        captured = self.collector().capture(event)

        self.assertEqual(captured.receipt.status, CaptureStatus.ACCEPTED)
        self.assertNotIn(CANARY, captured.model_dump_json())
        self.assertNotIn("untrusted.arbitrary.attribute", captured.model_dump_json())
        self.assertEqual(captured.event.context.provider, "openai")
        self.assertEqual(captured.event.input_tokens, 3)

    def test_langchain_callback_adapter_is_dependency_free_and_privacy_safe(self) -> None:
        events = LangChainCallbackTelemetryAdapter.normalize(
            context(),
            run_id="4ef55f17-7fac-4b50-bfb8-7f1bbbc1e92d",
            parent_run_id=None,
            provider="openai",
            model_id="gpt-test",
            prompts=[CANARY],
            generations=[[{"text": CANARY}]],
            sequence_start=10,
        )

        result = TelemetryCollector().capture_batch(events)

        self.assertEqual(result.accepted, 2)
        self.assertNotIn(CANARY, result.model_dump_json())
        self.assertEqual(result.events[0].attributes["framework_name"], "langchain")
        self.assertEqual(result.events[1].sequence, 11)

    def test_mcp_jsonrpc_adapter_collects_tools_call_and_rejects_other_methods(self) -> None:
        events = McpJsonRpcTelemetryAdapter.normalize(
            context(),
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "ticket_export", "arguments": {"token": CANARY}},
            },
            {"jsonrpc": "2.0", "id": 1, "result": {"status": CANARY}},
            operation="external.send",
            resource="ticket://123",
            sequence_start=20,
        )

        result = TelemetryCollector().capture_batch(events)

        self.assertEqual(result.accepted, 2)
        self.assertNotIn(CANARY, result.model_dump_json())
        self.assertEqual(result.events[0].attributes["mcp_jsonrpc_method"], "tools/call")
        with self.assertRaisesRegex(ValueError, "tools/call"):
            McpJsonRpcTelemetryAdapter.normalize(
                context(),
                {"jsonrpc": "2.0", "method": "resources/read", "params": {}},
                {"jsonrpc": "2.0", "result": {}},
                operation="data.read",
                resource="resource://1",
            )


if __name__ == "__main__":
    unittest.main()
