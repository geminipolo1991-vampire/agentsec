from __future__ import annotations

import importlib.util
import json
import subprocess
import unittest
from email.message import Message
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace


MODULE_PATH = Path(__file__).parents[1] / "tools" / "live_ui_bridge.py"
SPEC = importlib.util.spec_from_file_location("live_ui_bridge", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
bridge_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge_module)


class LiveUiBridgeTests(unittest.TestCase):
    def test_simulation_bridge_uses_only_fixed_builder_and_replay_contracts(self) -> None:
        calls = []

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self, _size):
                return b'{"schema_version":"1.0.0"}'

        def opener(request, timeout):
            calls.append((request.full_url, request.method, request.data, timeout))
            return FakeResponse()

        client = bridge_module.LocalServiceClient(
            base_url="http://127.0.0.1:8080",
            token="simulation-bridge-token-at-least-thirty-two-bytes",
            opener=opener,
        )
        client.simulation_catalog()
        client.simulation_health()
        client.simulation_scenario("sim_indirect_injection_egress", "1.0.0")
        client.simulation_mutate(
            {
                "base_scenario_id": "sim_indirect_injection_egress",
                "base_version": "1.0.0",
                "variant": "japanese",
                "name": None,
            }
        )
        client.simulation_run(
            {
                "request_id": "req_bridge001",
                "scenario_id": "sim_indirect_injection_egress",
                "version": "1.0.0",
                "mode": "comparison",
            }
        )
        client.simulation_runs()
        client.simulation_run_detail("simrun_" + "a" * 32)
        client.simulation_replay(
            "simrun_" + "a" * 32, {"request_id": "req_replay001"}
        )

        self.assertEqual(
            [(item[0].split("8080")[1], item[1]) for item in calls],
            [
                ("/v1/simulation/catalog", "GET"),
                ("/v1/simulation/health", "GET"),
                ("/v1/simulation/scenarios/sim_indirect_injection_egress/versions/1.0.0", "GET"),
                ("/v1/simulation/mutations", "POST"),
                ("/v1/simulation/runs", "POST"),
                ("/v1/simulation/runs?limit=100&offset=0", "GET"),
                ("/v1/simulation/runs/simrun_" + "a" * 32, "GET"),
                ("/v1/simulation/runs/simrun_" + "a" * 32 + "/replay", "POST"),
            ],
        )
        rendered = b"".join(item[2] or b"" for item in calls).decode("utf-8")
        self.assertNotIn("raw_prompt", rendered)
        with self.assertRaises(ValueError):
            bridge_module.validate_simulation_mutation(
                {
                    "base_scenario_id": "sim_indirect_injection_egress",
                    "base_version": "1.0.0",
                    "variant": "japanese",
                    "name": None,
                    "payload": "arbitrary",
                }
            )
        with self.assertRaises(ValueError):
            bridge_module.validate_simulation_run(
                {
                    "scenario_id": "../../etc/passwd",
                    "request_id": "req_bridge002",
                    "version": "1.0.0",
                    "mode": "comparison",
                }
            )

    def test_loopback_simulation_routes_are_fixed_and_content_free(self) -> None:
        calls = []
        run_id = "simrun_" + "a" * 32

        class FakeClient:
            def simulation_catalog(self):
                calls.append(("catalog", None))
                return {"schema_version": "1.0.0", "scenarios": {"scenarios": []}}

            def simulation_runs(self):
                calls.append(("runs", None))
                return {"schema_version": "1.0.0", "runs": [], "count": 0, "total": 0}

            def simulation_mutate(self, payload):
                calls.append(("mutate", dict(payload)))
                return {"scenario_id": "sim_mut_example", "version": "1.0.0"}

            def simulation_run(self, payload):
                calls.append(("run", dict(payload)))
                return {"run_id": run_id, "passed": True}

            def simulation_replay(self, selected_run_id, payload):
                calls.append(("replay", (selected_run_id, dict(payload))))
                return {"run_id": run_id, "replay_of": selected_run_id}

        handler_type = bridge_module.make_handler(
            bridge_module.LiveBridge(FakeClient(), cache_seconds=0), 8765
        )

        def invoke(method, path, payload=None):
            handler = handler_type.__new__(handler_type)
            handler.path = path
            handler.command = method
            handler.request_version = "HTTP/1.1"
            handler.server = SimpleNamespace(server_port=8765)
            handler.headers = Message()
            handler.headers["Host"] = "127.0.0.1:8765"
            handler.headers["Origin"] = "http://127.0.0.1:3000"
            encoded = b""
            if payload is not None:
                encoded = json.dumps(payload).encode("utf-8")
                handler.headers["Content-Type"] = "application/json"
                handler.headers["Content-Length"] = str(len(encoded))
            handler.rfile = BytesIO(encoded)
            handler.wfile = BytesIO()
            captured = {"status": None}
            handler.send_response = lambda status: captured.update(status=status)
            handler.send_header = lambda _key, _value: None
            handler.end_headers = lambda: None
            getattr(handler, "do_%s" % method)()
            body = json.loads(handler.wfile.getvalue()) if handler.wfile.getvalue() else None
            return captured["status"], body

        self.assertEqual(invoke("GET", "/api/simulation/catalog")[0], 200)
        self.assertEqual(invoke("GET", "/api/simulation/runs")[0], 200)
        invalid = {
            "base_scenario_id": "sim_indirect_injection_egress",
            "base_version": "1.0.0",
            "variant": "japanese",
            "name": None,
            "raw_prompt": "do not accept content",
        }
        self.assertEqual(invoke("POST", "/api/simulation/mutations", invalid)[0], 400)
        self.assertFalse(any(item[0] == "mutate" for item in calls))
        mutation = dict(invalid)
        mutation.pop("raw_prompt")
        self.assertEqual(invoke("POST", "/api/simulation/mutations", mutation)[0], 200)
        self.assertEqual(
            invoke(
                "POST",
                "/api/simulation/runs",
                {
                    "request_id": "req_bridge003",
                    "scenario_id": "sim_mut_example",
                    "version": "1.0.0",
                    "mode": "comparison",
                },
            )[0],
            200,
        )
        replay_path = "/api/simulation/runs/%s/replay" % run_id
        self.assertEqual(
            invoke("POST", replay_path, {"request_id": "req_replay003"})[0], 200
        )
        self.assertEqual(invoke("OPTIONS", replay_path)[0], 204)

    def test_make_event_accepts_only_allowlisted_presets(self) -> None:
        event = bridge_module.make_event("mcp_schema_drift")
        self.assertTrue(event["event_id"].startswith("evt_live_"))
        self.assertEqual(event["attributes"]["live_ui_preset"], "mcp_schema_drift")
        with self.assertRaisesRegex(ValueError, "unknown forge preset"):
            bridge_module.make_event("arbitrary_remote_command")

    def test_historical_authorization_is_marked_summary_only(self) -> None:
        authorization = {
            "schema_version": "1.0.0",
            "event_id": "evt_live_test",
            "overall_action": "deny",
            "effect_allowed": False,
            "ledger_verified": True,
            "alerts": [
                {
                    "alert_id": "alr_test",
                    "finding_id": "fnd_test12345678",
                    "alert_type": "authority_violation",
                    "severity": "high",
                    "decision": "deny",
                    "escalation": "soc_urgent",
                }
            ],
        }
        alerts, ledger = bridge_module.alerts_from_invocations(
            [
                {
                    "CommandId": "12345678-1234-1234-1234-123456789012",
                    "RequestedDateTime": "2026-07-22T19:50:29+09:00",
                    "CommandPlugins": [{"Output": json.dumps(authorization)}],
                }
            ]
        )
        self.assertTrue(ledger)
        self.assertEqual(alerts[0]["detailAvailability"], "summary_only")
        self.assertIsNone(alerts[0]["risk"])
        self.assertIsNone(alerts[0]["detail"])

    def test_aws_cli_uses_argument_lists_and_never_embeds_a_token(self) -> None:
        calls = []

        def runner(args, **kwargs):
            calls.append((args, kwargs))
            return subprocess.CompletedProcess(
                args,
                0,
                stdout=json.dumps({"CommandInvocations": []}),
                stderr="",
            )

        client = bridge_module.AwsSsmClient(
            profile="agentsec-deploy",
            region="ap-northeast-1",
            instance_id="i-082370aa89a20ff93",
            runner=runner,
        )
        self.assertEqual(client.list_alerts()["alerts"], [])
        self.assertFalse(calls[0][1]["shell"])
        rendered = " ".join(calls[0][0])
        self.assertNotIn("AGENTSEC_INGEST_TOKEN", rendered)
        self.assertIn("list-command-invocations", rendered)

    def test_local_client_is_loopback_only_and_keeps_token_server_side(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback"):
            bridge_module.LocalServiceClient(
                base_url="https://service.example/v1",
                token="x" * 32,
            )
        with self.assertRaisesRegex(ValueError, "32 visible"):
            bridge_module.LocalServiceClient(
                base_url="http://127.0.0.1:8080",
                token="too-short",
            )

        summary = {
            "finding_id": "fnd_local12345678",
            "event_id": "evt_local",
            "flow_id": "flow-local",
            "alert_type": "secret_egress",
            "title": "Local secret egress",
            "agent_id": "response-agent",
            "severity": "critical",
            "priority": "P0",
            "status": "contained",
            "decision": "deny",
            "effect_status": "blocked",
            "created_at": "2026-07-23T01:00:00Z",
            "updated_at": "2026-07-23T01:00:01Z",
            "detail_availability": "complete",
        }
        detail = {
            "detail_availability": "complete",
            "incident_id": summary["finding_id"],
            "summary": summary,
            "detection": {
                "alert_id": "alr_local",
                "title": summary["title"],
                "detected_at": summary["created_at"],
                "reason_codes": ["SECRET_EGRESS"],
            },
            "triage": {"risk_score": 96, "narrative": "Recorded policy match"},
            "judgment": {"policy_version": "policy-v2"},
            "validation": {"ledger_verified": True},
        }
        calls = []

        class FakeResponse:
            def __init__(self, payload):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size=-1):
                return json.dumps(self.payload).encode("utf-8")

        def opener(request, **kwargs):
            calls.append((request, kwargs))
            if request.full_url.endswith("/v1/incidents"):
                return FakeResponse({"incidents": [summary], "count": 1})
            if request.full_url.endswith("/v1/incidents/fnd_local12345678"):
                return FakeResponse(detail)
            raise AssertionError(request.full_url)

        client = bridge_module.LocalServiceClient(
            base_url="http://127.0.0.1:8080",
            token="local-test-token-with-at-least-32-characters",
            opener=opener,
        )
        payload = client.list_alerts()
        self.assertEqual(payload["source"], "local-service")
        self.assertTrue(payload["ledger_verified"])
        self.assertEqual(payload["alerts"][0]["id"], "alr_local")
        self.assertEqual(payload["alerts"][0]["risk"], 96)
        self.assertTrue(
            all(
                request.get_header("Authorization", "").startswith("Bearer ")
                for request, _kwargs in calls
            )
        )
        self.assertNotIn("local-test-token", json.dumps(payload))

    def test_model_gateway_bridge_uses_only_fixed_sanitized_read_routes(self) -> None:
        calls = []

        class FakeResponse:
            def __init__(self, payload):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size=-1):
                return json.dumps(self.payload).encode()

        def opener(request, **kwargs):
            calls.append(request.full_url)
            path = request.full_url.split("8080", 1)[1]
            payloads = {
                "/v1/model-gateway/health": {"routes": 1, "providers": []},
                "/v1/model-gateway/routes": {"routes": []},
                "/v1/model-gateway/prompts": {"prompts": []},
                "/v1/model-gateway/qualifications": {"qualifications": []},
                "/v1/model-gateway/calls?limit=100&offset=0": {"calls": []},
            }
            return FakeResponse(payloads[path])

        client = bridge_module.LocalServiceClient(
            base_url="http://127.0.0.1:8080",
            token="bridge-model-gateway-token-at-least-32-chars",
            opener=opener,
        )

        payload = client.model_gateway_status()

        self.assertEqual(payload["health"]["routes"], 1)
        self.assertEqual(len(calls), 5)
        self.assertTrue(all("/v1/model-gateway/" in item for item in calls))
        self.assertNotIn("credential", json.dumps(payload))

    def test_configuration_rejects_shell_metacharacters(self) -> None:
        with self.assertRaisesRegex(ValueError, "profile"):
            bridge_module.validate_config(
                "agentsec;whoami", "ap-northeast-1", "i-082370aa89a20ff93"
            )

    def test_model_gateway_bridge_forwards_only_fixed_sanitized_views(self) -> None:
        calls = []

        class FakeResponse:
            def __init__(self, payload):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size=-1):
                return json.dumps(self.payload).encode("utf-8")

        responses = {
            "/v1/model-gateway/health": {"policy_version": "model-gateway-test", "routes": 1, "providers": []},
            "/v1/model-gateway/routes": {"routes": [{"route_id": "mrt_test"}]},
            "/v1/model-gateway/prompts": {"prompts": [{"prompt_id": "prm_test"}]},
            "/v1/model-gateway/qualifications": {"qualifications": [{"qualification_id": "mql_test"}]},
            "/v1/model-gateway/calls?limit=100&offset=0": {"calls": [{"call_id": "mgc_test", "output_sha256": "a" * 64}]},
        }

        def opener(request, **kwargs):
            calls.append((request, kwargs))
            path = request.full_url.removeprefix("http://127.0.0.1:8080")
            if path not in responses:
                raise AssertionError(path)
            return FakeResponse(responses[path])

        client = bridge_module.LocalServiceClient(
            base_url="http://127.0.0.1:8080",
            token="model-gateway-bridge-token-at-least-32-characters",
            opener=opener,
        )
        payload = bridge_module.LiveBridge(client).model_gateway_status()
        self.assertEqual(payload["routes"][0]["route_id"], "mrt_test")
        self.assertEqual(payload["calls"][0]["call_id"], "mgc_test")
        self.assertEqual(len(calls), 5)
        self.assertTrue(all(request.method == "GET" for request, _ in calls))
        self.assertNotIn("model-gateway-bridge-token", json.dumps(payload))

    def test_local_search_bridge_forwards_only_bounded_product_requests(self) -> None:
        calls = []

        class FakeResponse:
            def __init__(self, payload):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size=-1):
                return json.dumps(self.payload).encode("utf-8")

        def opener(request, **kwargs):
            calls.append((request, kwargs))
            if request.full_url.endswith("/v1/search"):
                return FakeResponse({"query": "*", "hits": [], "total": 0, "elapsed_ms": 1})
            if request.full_url.endswith("/v1/search/aggregate"):
                return FakeResponse({"query": "*", "field": "record_type", "buckets": [], "elapsed_ms": 1})
            if request.full_url.endswith("/v1/hunts") and request.method == "GET":
                return FakeResponse({"hunts": []})
            if request.full_url.endswith("/v1/hunts"):
                return FakeResponse({"hunt_id": "hunt_test"})
            if request.full_url.endswith("/v1/evidence/evd_test123/pivot"):
                return FakeResponse({"evidence_id": "evd_test123", "protected_content_included": False})
            if request.full_url.endswith("/v1/inventory?limit=200"):
                return FakeResponse({"components": [], "total": 0, "limit": 200, "offset": 0})
            if request.full_url.endswith("/v1/inventory/summary"):
                return FakeResponse({"total_components": 0})
            if request.full_url.endswith("/v1/inventory/cmp_test123"):
                return FakeResponse({"component": {"component_id": "cmp_test123"}})
            if request.full_url.endswith("/v1/graph"):
                return FakeResponse({"tenant_id": "tenant-lab", "nodes": [], "edges": []})
            if request.full_url.endswith("/v1/graph/summary"):
                return FakeResponse({"tenant_id": "tenant-lab", "node_count": 0, "edge_count": 0})
            if request.full_url.endswith("/v1/graph/attack-paths"):
                return FakeResponse({"paths": [], "explored_states": 0, "truncated": False})
            if request.full_url.endswith("/v1/posture/summary"):
                return FakeResponse({"posture_score": 100, "open_findings": 0})
            if request.full_url.endswith("/v1/posture/checks"):
                return FakeResponse({"checks": []})
            if request.full_url.endswith("/v1/posture/findings?limit=200"):
                return FakeResponse({"findings": [], "total": 0})
            if request.full_url.endswith("/v1/posture/trends?limit=30"):
                return FakeResponse({"points": []})
            if request.full_url.endswith("/v1/posture/scans"):
                return FakeResponse({"posture_score": 100, "failing": 0})
            if request.full_url.endswith("/v1/posture/findings/pstf_0123456789abcdef0123456789abcdef"):
                return FakeResponse({"finding": {"finding_id": "pstf_0123456789abcdef0123456789abcdef"}})
            if request.full_url.endswith("/v1/posture/findings/pstf_0123456789abcdef0123456789abcdef/exceptions"):
                return FakeResponse({"exception_id": "pste_test123", "status": "active"})
            if request.full_url.endswith("/v1/posture/exceptions/pste_test123/revoke"):
                return FakeResponse({"exception_id": "pste_test123", "status": "revoked"})
            raise AssertionError(request.full_url)

        client = bridge_module.LocalServiceClient(
            base_url="http://127.0.0.1:8080",
            token="local-search-test-token-at-least-32-characters",
            opener=opener,
        )
        live = bridge_module.LiveBridge(client)
        self.assertEqual(live.search({"query": "*", "page_size": 25})["total"], 0)
        self.assertEqual(live.aggregate({"query": "*", "field": "record_type"})["buckets"], [])
        self.assertEqual(live.list_hunts()["hunts"], [])
        self.assertEqual(live.save_hunt({"name": "Alerts", "query": 'record_type = "alert"'})["hunt_id"], "hunt_test")
        self.assertFalse(live.evidence_pivot("evd_test123")["protected_content_included"])
        self.assertEqual(live.inventory()["total"], 0)
        self.assertEqual(live.inventory_summary()["total_components"], 0)
        self.assertEqual(live.inventory_detail("cmp_test123")["component"]["component_id"], "cmp_test123")
        self.assertEqual(live.graph()["nodes"], [])
        self.assertEqual(live.graph_summary()["node_count"], 0)
        self.assertEqual(
            live.graph_analysis(
                "/api/graph/attack-paths",
                {"source_node_id": "agent:one", "target_node_id": "tool:two"},
            )["paths"],
            [],
        )
        self.assertEqual(live.posture_summary()["posture_score"], 100)
        self.assertEqual(live.posture_checks()["checks"], [])
        self.assertEqual(live.posture_findings()["findings"], [])
        self.assertEqual(live.posture_trends()["points"], [])
        self.assertEqual(live.posture_scan({})["failing"], 0)
        posture_finding_id = "pstf_0123456789abcdef0123456789abcdef"
        self.assertEqual(live.posture_detail(posture_finding_id)["finding"]["finding_id"], posture_finding_id)
        exception_payload = {
            "reason": "Temporary approved risk during migration",
            "owner_ref": "team://security",
            "approved_by": "analyst://alice",
            "expires_at": "2026-07-30T00:00:00+00:00",
        }
        self.assertEqual(live.posture_exception(posture_finding_id, exception_payload)["status"], "active")
        self.assertEqual(
            live.posture_revoke_exception("pste_test123", {"reason": "Migration completed"})["status"],
            "revoked",
        )
        self.assertTrue(all(call[0].get_header("Authorization", "").startswith("Bearer ") for call in calls))
        with self.assertRaisesRegex(ValueError, "fields"):
            live.search({"query": "*", "tenant_id": "tenant-other"})
        with self.assertRaisesRegex(ValueError, "evidence ID"):
            live.evidence_pivot("../../secret")
        with self.assertRaisesRegex(ValueError, "component ID"):
            live.inventory_detail("../../inventory")
        with self.assertRaisesRegex(ValueError, "fields"):
            live.graph_analysis(
                "/api/graph/attack-paths",
                {
                    "source_node_id": "agent:one",
                    "target_node_id": "tool:two",
                    "command": "arbitrary",
                },
            )
        with self.assertRaisesRegex(ValueError, "fields"):
            live.posture_scan({"command": "arbitrary"})

    def test_fixed_remote_scripts_do_not_reconstruct_incident_data(self) -> None:
        command = bridge_module.build_remote_command(
            bridge_module.make_event("persistent_memory_poisoning")
        )
        self.assertTrue(command.startswith("printf '%s' '"))
        self.assertIn("docker exec -i agentsec python -", command)
        self.assertNotIn("suspected-adversarial", command)
        self.assertNotIn("Bearer ", command)
        self.assertNotIn(
            "build_pipeline_from_environment", bridge_module.REMOTE_AUTHORIZE_SCRIPT
        )
        self.assertNotIn("base_scores", bridge_module.REMOTE_AUTHORIZE_SCRIPT)
        self.assertNotIn(
            '"resource", "destination"', bridge_module.REMOTE_AUTHORIZE_SCRIPT
        )

    def test_authoritative_detail_is_forwarded_without_synthesized_score(self) -> None:
        detail = {
            "schema_version": "2.0.0",
            "trace_mode": "authoritative",
            "detail_availability": "complete",
            "incident_id": "fnd_rich12345678",
            "alert_type": "secret_egress",
            "summary": {
                "finding_id": "fnd_rich12345678",
                "event_id": "evt_rich",
                "flow_id": "flow-rich",
                "alert_type": "secret_egress",
                "title": "Live title",
                "agent_id": "response-agent",
                "severity": "critical",
                "priority": "P0",
                "status": "contained",
                "decision": "deny",
                "effect_status": "blocked",
                "created_at": "2026-07-22T20:00:00Z",
                "updated_at": "2026-07-22T20:00:01Z",
                "detail_availability": "complete",
            },
            "detection": {
                "title": "Live title",
                "reason_codes": ["LIVE_REASON"],
                "evidence_refs": ["evidence_sha256:abc"],
            },
            "event_context": {
                "agent_id": "response-agent",
                "operation": "external.send",
                "resource_class": "secret",
                "resource_ref": "resource_sha256:abc",
                "source_type": "document",
                "source_ref": "source_sha256:def",
                "source_trust": "external-untrusted",
                "destination_class": "external-network",
                "destination_ref": "destination_sha256:ghi",
            },
            "triage": {"risk_score": 97, "priority": "P0"},
            "judgment": {"policy_version": "policy-v2", "model_status": "not_requested"},
            "finding": {"status": "contained"},
            "response": {"effect_status": "blocked"},
        }
        wrapper = {
            "agentsec_live_ui": "2",
            "event": {"operation": "external.send"},
            "authorization": {
                "event_id": "evt_rich",
                "overall_action": "deny",
                "effect_allowed": False,
                "ledger_verified": True,
                "alerts": [
                    {
                        "alert_id": "alr_rich",
                        "finding_id": "fnd_rich12345678",
                        "alert_type": "secret_egress",
                        "severity": "critical",
                        "decision": "deny",
                        "escalation": "incident_page",
                    }
                ],
                "incidents": [detail],
            },
        }
        alerts, ledger = bridge_module.alerts_from_invocations(
            [
                {
                    "CommandId": "12345678-1234-1234-1234-123456789012",
                    "RequestedDateTime": "2026-07-22T20:00:00+09:00",
                    "CommandPlugins": [{"Output": json.dumps(wrapper)}],
                }
            ]
        )
        self.assertTrue(ledger)
        self.assertEqual(alerts[0]["detailAvailability"], "complete")
        self.assertEqual(alerts[0]["risk"], 97)
        self.assertEqual(alerts[0]["detail"], detail)
        self.assertNotIn("receiver.invalid", json.dumps(alerts))

    def test_transition_accepts_only_fixed_lifecycle_payload(self) -> None:
        class FakeClient:
            def list_alerts(self):
                return {
                    "alerts": [
                        {
                            "id": "alr_recent",
                            "finding": "fnd_recent12345678",
                            "detail": None,
                        }
                    ],
                    "ledger_verified": True,
                    "checked_at": "now",
                }

            def forge(self, _preset):
                return {"alerts": []}

            def transition(self, finding_id, *, action, actor, reason):
                self.transition_args = (finding_id, action, actor, reason)
                return {
                    "detail_availability": "complete",
                    "summary": {"finding_id": finding_id, "status": "investigating"},
                }

        live = bridge_module.LiveBridge(FakeClient(), cache_seconds=0)
        result = live.transition(
            "fnd_recent12345678",
            action="start_investigation",
            actor="analyst://alice",
            reason="Reviewing recorded evidence",
        )
        self.assertEqual(result["incident"]["summary"]["status"], "investigating")
        with self.assertRaisesRegex(ValueError, "fields must be exact"):
            bridge_module.validate_transition(
                {
                    "action": "close",
                    "actor": "analyst://alice",
                    "reason": "done",
                    "command": "whoami",
                }
            )
        with self.assertRaisesRegex(ValueError, "action"):
            live.transition(
                "fnd_recent12345678",
                action="execute_command",
                actor="analyst://alice",
                reason="not allowed",
            )

    def test_detection_content_bridge_uses_allowlisted_presets_and_fixed_routes(self) -> None:
        calls = []

        class FakeResponse:
            def __init__(self, payload):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size=-1):
                return json.dumps(self.payload).encode("utf-8")

        def opener(request, **kwargs):
            body = json.loads(request.data) if request.data else None
            calls.append((request.method, request.full_url, body, kwargs))
            if request.full_url.endswith("/v1/detection/content?limit=200&offset=0"):
                return FakeResponse({"content": []})
            if request.full_url.endswith("/v1/detection/content/health"):
                return FakeResponse({"total_content": 0})
            if request.full_url.endswith("/v1/detection/content/drc_test123/validate"):
                return FakeResponse({"content_id": "drc_test123", "status": "draft"})
            if request.full_url.endswith("/v1/detection/content/drc_test123"):
                return FakeResponse({"content_id": "drc_test123", "status": "draft"})
            raise AssertionError(request.full_url)

        client = bridge_module.LocalServiceClient(
            base_url="http://127.0.0.1:8080",
            token="content-bridge-test-token-at-least-32-characters",
            opener=opener,
        )
        live = bridge_module.LiveBridge(client)
        self.assertEqual(live.content_list()["content"], [])
        self.assertEqual(live.content_health()["total_content"], 0)
        definition_payload = {"definition": {"rule_id": "DET-TEST-001"}}
        self.assertEqual(
            live.content_update("drc_test123", definition_payload)["status"], "draft"
        )
        result = live.content_action(
            "drc_test123",
            "validate",
            {
                "name": "Positive and benign deterministic controls",
                "presets": ["indirect_injection_secret_egress", "benign_inventory_read"],
                "expected_alert_presets": ["indirect_injection_secret_egress"],
            },
        )
        self.assertEqual(result["content_id"], "drc_test123")
        method, _url, forwarded, _kwargs = calls[-1]
        self.assertEqual(method, "POST")
        self.assertEqual(set(forwarded), {"suite"})
        self.assertEqual(len(forwarded["suite"]["events"]), 2)
        self.assertEqual(
            forwarded["suite"]["expected_alert_event_ids"],
            [forwarded["suite"]["events"][0]["event_id"]],
        )
        self.assertNotIn("presets", forwarded)
        with self.assertRaisesRegex(ValueError, "presets"):
            live.content_action(
                "drc_test123", "validate", {"presets": ["arbitrary_command"]}
            )
        with self.assertRaisesRegex(ValueError, "action"):
            live.content_action("drc_test123", "execute", {})

    def test_behavior_bridge_exposes_only_fixed_privacy_safe_routes(self) -> None:
        calls = []

        class FakeResponse:
            def __init__(self, payload):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size=-1):
                return json.dumps(self.payload).encode("utf-8")

        def opener(request, **kwargs):
            body = json.loads(request.data) if request.data else None
            calls.append((request.method, request.full_url, body, kwargs))
            if request.full_url.endswith("/v1/behavior/baselines?limit=200&offset=0"):
                return FakeResponse({"baselines": []})
            if "/v1/behavior/assessments?" in request.full_url:
                return FakeResponse({"assessments": []})
            if request.full_url.endswith("/v1/behavior/health"):
                return FakeResponse({"total_baselines": 0, "anomalies": 0})
            if request.full_url.endswith("/v1/behavior/config"):
                return FakeResponse({"version": "1.1.0"} if request.method == "POST" else {"configs": []})
            if request.full_url.endswith("/v1/behavior/drift"):
                return FakeResponse({"state": "insufficient_data"})
            if request.full_url.endswith("/v1/behavior/assessments/bhas_test123"):
                return FakeResponse({"assessment_id": "bhas_test123"})
            raise AssertionError(request.full_url)

        client = bridge_module.LocalServiceClient(
            base_url="http://127.0.0.1:8080",
            token="behavior-bridge-test-token-at-least-32-characters",
            opener=opener,
        )
        live = bridge_module.LiveBridge(client)
        self.assertEqual(live.behavior_baselines()["baselines"], [])
        self.assertEqual(live.behavior_assessments()["assessments"], [])
        self.assertEqual(
            live.behavior_assessments(anomalies_only=True)["assessments"], []
        )
        self.assertEqual(live.behavior_health()["anomalies"], 0)
        self.assertEqual(live.behavior_config()["configs"], [])
        self.assertEqual(live.behavior_drift()["state"], "insufficient_data")
        self.assertEqual(
            live.behavior_assessment("bhas_test123")["assessment_id"],
            "bhas_test123",
        )
        config = {
            "config_id": "behavior-default",
            "version": "1.1.0",
            "minimum_observations": 5,
            "maximum_observations": 1000,
            "rare_probability": 0.08,
            "anomaly_threshold": 55,
            "operation_weight": 22,
            "destination_weight": 18,
            "source_trust_weight": 12,
            "time_weight": 8,
            "authority_weight": 18,
            "sensitive_weight": 14,
            "schema_drift_weight": 8,
            "drift_window_size": 50,
            "drift_warning_rate": 0.15,
            "drift_critical_rate": 0.35,
            "retention_days": 90,
        }
        self.assertEqual(
            live.behavior_tune(
                {"config": config, "reason": "Reviewed SOC tuning activation."}
            )["version"],
            "1.1.0",
        )
        anomaly_urls = [url for _method, url, _body, _kwargs in calls if "/assessments?" in url]
        self.assertTrue(any("anomalies_only=true" in url for url in anomaly_urls))
        self.assertTrue(all(call[0] in {"GET", "POST"} for call in calls))
        with self.assertRaisesRegex(ValueError, "config fields"):
            live.behavior_tune(
                {
                    "config": {**config, "command": "arbitrary"},
                    "reason": "Attempted arbitrary mutation is rejected.",
                }
            )
        with self.assertRaisesRegex(ValueError, "entity reference"):
            live.behavior_drift("agent://raw-identifier")
        with self.assertRaisesRegex(ValueError, "assessment ID"):
            live.behavior_assessment("../../secret")

    def test_correlation_bridge_exposes_fixed_incident_governance_routes(self) -> None:
        calls = []

        class FakeResponse:
            def __init__(self, payload): self.payload = payload
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def read(self, _size=-1): return json.dumps(self.payload).encode()

        def opener(request, **kwargs):
            body = json.loads(request.data) if request.data else None
            calls.append((request.method, request.full_url, body, kwargs))
            if request.full_url.endswith("/v1/correlation/incidents?limit=200&offset=0"):
                return FakeResponse({"incidents": []})
            if request.full_url.endswith("/v1/correlation/health"):
                return FakeResponse({"total_incidents": 0})
            if request.full_url.endswith("/v1/correlation/decisions?limit=200"):
                return FakeResponse({"decisions": []})
            if request.full_url.endswith("/v1/correlation/incidents/merge"):
                return FakeResponse({"incident_id": "inc_one"})
            if request.full_url.endswith("/v1/correlation/incidents/inc_one/split"):
                return FakeResponse({"source": {"incident_id": "inc_one"}, "child": {"incident_id": "inc_child"}})
            if request.full_url.endswith("/v1/correlation/incidents/inc_one/transition"):
                return FakeResponse({"incident_id": "inc_one", "status": "closed"})
            if request.full_url.endswith("/v1/correlation/incidents/inc_one"):
                return FakeResponse({"incident_id": "inc_one"})
            raise AssertionError(request.full_url)

        client = bridge_module.LocalServiceClient(
            base_url="http://127.0.0.1:8080",
            token="correlation-bridge-test-token-at-least-32-characters",
            opener=opener,
        )
        live = bridge_module.LiveBridge(client)
        self.assertEqual(live.correlation_incidents()["incidents"], [])
        self.assertEqual(live.correlation_health()["total_incidents"], 0)
        self.assertEqual(live.correlation_decisions()["decisions"], [])
        self.assertEqual(live.correlation_incident("inc_one")["incident_id"], "inc_one")
        self.assertEqual(live.correlation_transition("inc_one", {"status": "closed", "reason": "Analyst verified the evidence."})["status"], "closed")
        self.assertEqual(live.correlation_merge({"incident_ids": ["inc_one", "inc_two"], "reason": "Evidence confirms one coordinated campaign."})["incident_id"], "inc_one")
        self.assertEqual(live.correlation_split("inc_one", {"finding_ids": ["fnd_test123"], "reason": "Evidence confirms an unrelated activity group."})["child"]["incident_id"], "inc_child")
        with self.assertRaisesRegex(ValueError, "merge"):
            live.correlation_merge({"incident_ids": ["inc_one"], "reason": "too short"})
        with self.assertRaisesRegex(ValueError, "incident ID"):
            live.correlation_incident("../../secret")
        self.assertTrue(all(method in {"GET", "POST"} for method, _url, _body, _kwargs in calls))

    def test_case_bridge_exposes_only_fixed_collaboration_routes(self) -> None:
        calls = []
        case_id = "case_0123456789abcdef0123456789abcdef"
        task_id = "ctk_0123456789abcdef0123456789abcdef"
        attachment_id = "cat_0123456789abcdef0123456789abcdef"

        class FakeResponse:
            def __init__(self, payload): self.payload = payload
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def read(self, _size=-1): return json.dumps(self.payload).encode()

        def opener(request, **kwargs):
            body = json.loads(request.data) if request.data else None
            calls.append((request.method, request.full_url, body, kwargs))
            path = request.full_url.removeprefix("http://127.0.0.1:8080")
            if path == "/v1/cases?limit=200&offset=0":
                return FakeResponse({"cases": [], "count": 0, "limit": 200, "offset": 0})
            if path == "/v1/cases/health":
                return FakeResponse({"total_cases": 0, "open_tasks": 0})
            if path == "/v1/case-teams" and request.method == "GET":
                return FakeResponse({"teams": []})
            if path == "/v1/case-teams":
                return FakeResponse({"team_id": "team://soc"})
            if path == "/v1/cases/%s" % case_id:
                return FakeResponse({"case": {"case_id": case_id, "version": 1}})
            if path == "/v1/cases/%s/comments" % case_id:
                return FakeResponse({"case_id": case_id, "body": "Reviewed"})
            if path == "/v1/cases/%s/tasks/%s/transition" % (case_id, task_id):
                return FakeResponse({"task_id": task_id, "status": "in_progress"})
            if path == "/v1/cases/%s/attachments/%s/scan" % (case_id, attachment_id):
                return FakeResponse({"attachment_id": attachment_id, "scan_status": "clean"})
            raise AssertionError(path)

        client = bridge_module.LocalServiceClient(
            base_url="http://127.0.0.1:8080",
            token="case-bridge-test-token-at-least-32-characters",
            opener=opener,
        )
        live = bridge_module.LiveBridge(client)
        self.assertEqual(live.cases()["count"], 0)
        self.assertEqual(live.case_health()["total_cases"], 0)
        self.assertEqual(live.case_teams()["teams"], [])
        self.assertEqual(live.case_detail(case_id)["case"]["case_id"], case_id)
        self.assertEqual(
            live.case_action(case_id, "comments", {"expected_version": 1, "body": "Reviewed"})["body"],
            "Reviewed",
        )
        self.assertEqual(
            live.case_task_transition(case_id, task_id, {"expected_version": 2, "status": "in_progress"})["status"],
            "in_progress",
        )
        self.assertEqual(
            live.case_attachment_scan(
                case_id,
                attachment_id,
                {"expected_version": 3, "status": "clean", "scanner_ref": "scanner_sha256:" + "a" * 24},
            )["scan_status"],
            "clean",
        )
        self.assertEqual(
            live.case_team_create(
                {
                    "team_id": "team://soc",
                    "name": "Security operations",
                    "description": "Primary security operations team.",
                    "member_ids": ["analyst://alice"],
                }
            )["team_id"],
            "team://soc",
        )
        with self.assertRaisesRegex(ValueError, "mutation fields"):
            live.case_action(
                case_id,
                "comments",
                {"expected_version": 1, "body": "Reviewed", "command": "whoami"},
            )
        with self.assertRaisesRegex(ValueError, "case ID"):
            live.case_detail("../../secret")
        self.assertTrue(all(method in {"GET", "POST"} for method, _url, _body, _kwargs in calls))

    def test_notification_bridge_exposes_only_fixed_delivery_routes(self) -> None:
        calls = []
        notification_id = "ntf_0123456789abcdef0123456789abcdef"
        delivery_id = "ndv_0123456789abcdef0123456789abcdef"

        class FakeResponse:
            def __init__(self, payload): self.payload = payload
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def read(self, _size=-1): return json.dumps(self.payload).encode()

        def opener(request, **kwargs):
            body = json.loads(request.data) if request.data else None
            calls.append((request.method, request.full_url, body, kwargs))
            path = request.full_url.removeprefix("http://127.0.0.1:8080")
            if path == "/v1/notifications?limit=200&offset=0":
                return FakeResponse({"notifications": [], "count": 0, "limit": 200, "offset": 0})
            if path == "/v1/notifications/health":
                return FakeResponse({"total": 0, "dead_letters": 0})
            if path == "/v1/notification-destinations":
                return FakeResponse({"destinations": [], "count": 0})
            if path == "/v1/notifications/%s" % notification_id:
                return FakeResponse({"notification": {"notification_id": notification_id, "version": 1}})
            if path == "/v1/notifications/process":
                return FakeResponse({"claimed": 1, "delivered": 1})
            if path == "/v1/notifications/%s/acknowledge" % notification_id:
                return FakeResponse({"notification_id": notification_id, "acknowledgment_state": "acknowledged"})
            if path == "/v1/notification-deliveries/%s/provider-acknowledge" % delivery_id:
                return FakeResponse({"delivery_id": delivery_id, "status": "acknowledged"})
            if path == "/v1/notification-deliveries/%s/redrive" % delivery_id:
                return FakeResponse({"delivery_id": delivery_id, "status": "retry_scheduled"})
            raise AssertionError(path)

        client = bridge_module.LocalServiceClient(
            base_url="http://127.0.0.1:8080",
            token="notification-bridge-test-token-at-least-32-characters",
            opener=opener,
        )
        live = bridge_module.LiveBridge(client)
        self.assertEqual(live.notifications()["count"], 0)
        self.assertEqual(live.notification_health()["dead_letters"], 0)
        self.assertEqual(live.notification_destinations()["destinations"], [])
        self.assertEqual(
            live.notification_detail(notification_id)["notification"]["notification_id"],
            notification_id,
        )
        self.assertEqual(live.notification_process({"limit": 5})["claimed"], 1)
        self.assertEqual(
            live.notification_acknowledge(
                notification_id,
                {"expected_version": 1, "note": "Primary on-call accepted ownership."},
            )["acknowledgment_state"],
            "acknowledged",
        )
        self.assertEqual(
            live.notification_provider_acknowledge(
                delivery_id, {"provider_receipt_sha256": "a" * 64}
            )["status"],
            "acknowledged",
        )
        self.assertEqual(
            live.notification_redrive(
                delivery_id, {"reason": "Connector recovery was verified."}
            )["status"],
            "retry_scheduled",
        )
        with self.assertRaisesRegex(ValueError, "process fields"):
            live.notification_process({"limit": 1, "command": "whoami"})
        with self.assertRaisesRegex(ValueError, "notification ID"):
            live.notification_detail("../../secret")
        self.assertTrue(all(method in {"GET", "POST"} for method, _url, _body, _kwargs in calls))

    def test_response_bridge_exposes_only_fixed_guarded_routes(self) -> None:
        calls = []
        execution_id = "rex_0123456789abcdef0123456789abcdef"

        class FakeResponse:
            def __init__(self, payload): self.payload = payload
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def read(self, _size=-1): return json.dumps(self.payload).encode()

        def opener(request, **kwargs):
            body = json.loads(request.data) if request.data else None
            calls.append((request.method, request.full_url, body, kwargs))
            path = request.full_url.removeprefix("http://127.0.0.1:8080")
            responses = {
                "/v1/response/executions?limit=200&offset=0": {"executions": [], "count": 0},
                "/v1/response/health": {"total_executions": 0, "kill_switch_active": False},
                "/v1/response/connectors": {"connectors": []},
                "/v1/response/playbooks?limit=200&offset=0": {"playbooks": [], "count": 0},
                "/v1/response/executions/%s" % execution_id: {"execution": {"execution_id": execution_id, "version": 1}},
                "/v1/response/executions/%s/request-live" % execution_id: {"execution_id": execution_id, "status": "awaiting_approval"},
                "/v1/response/executions/%s/approve" % execution_id: {"approval_id": "rap_test"},
                "/v1/response/executions/%s/execute" % execution_id: {"execution_id": execution_id, "status": "succeeded"},
                "/v1/response/playbooks/action": {"status": "in_review"},
            }
            if path == "/v1/response/control":
                return FakeResponse(
                    {"kill_switch_active": request.method == "POST", "version": 2 if request.method == "POST" else 1}
                )
            if path not in responses:
                raise AssertionError(path)
            return FakeResponse(responses[path])

        client = bridge_module.LocalServiceClient(
            base_url="http://127.0.0.1:8080",
            token="response-bridge-test-token-at-least-32-characters",
            opener=opener,
        )
        live = bridge_module.LiveBridge(client)
        self.assertEqual(live.response_executions()["count"], 0)
        self.assertFalse(live.response_health()["kill_switch_active"])
        self.assertEqual(live.response_connectors()["connectors"], [])
        self.assertEqual(live.response_control()["version"], 1)
        self.assertEqual(live.response_playbooks()["count"], 0)
        self.assertEqual(
            live.response_detail(execution_id)["execution"]["execution_id"],
            execution_id,
        )
        self.assertEqual(
            live.response_action(
                execution_id,
                "request-live",
                {"expected_version": 1, "reason": "Exact plan reviewed."},
            )["status"],
            "awaiting_approval",
        )
        self.assertEqual(
            live.response_action(
                execution_id,
                "approve",
                {"expected_version": 2, "reason": "Independent approval granted."},
            )["approval_id"],
            "rap_test",
        )
        self.assertEqual(
            live.response_action(execution_id, "execute", {})["status"],
            "succeeded",
        )
        self.assertTrue(
            live.response_kill_switch(
                {"active": True, "expected_version": 1, "reason": "Emergency stop test."}
            )["kill_switch_active"]
        )
        self.assertEqual(
            live.response_playbook_action(
                {
                    "playbook_id": "playbook://response/test",
                    "version": 1,
                    "action": "submit",
                    "expected_revision": 1,
                    "comment": "Submit exact draft.",
                }
            )["status"],
            "in_review",
        )
        with self.assertRaisesRegex(ValueError, "response execution ID"):
            live.response_detail("../../secret")
        with self.assertRaisesRegex(ValueError, "empty body"):
            live.response_action(execution_id, "execute", {"command": "whoami"})
        self.assertTrue(all(method in {"GET", "POST"} for method, _url, _body, _kwargs in calls))

    def test_platform_snapshot_is_fixed_authenticated_and_report_bound(self) -> None:
        class PlatformClient:
            source = "local-service"

            def list_alerts(self):
                return {"alerts": [], "ledger_verified": True, "checked_at": "now"}

            def telemetry_sources(self):
                return {"sources": [{"source_id": "safe-source"}], "credential_token": "never-return"}

            def telemetry_queue(self):
                return {"pending": 2, "capacity": 100}

            def inventory_summary(self):
                return {"total_components": 4, "high_risk_components": 1}

            def graph_summary(self, _as_of=None):
                return {"node_count": 4, "edge_count": 3}

            def posture_summary(self):
                return {"posture_score": 84, "open_findings": 2}

            def detection_health(self):
                return {"rules": [{"rule_id": "safe"}], "errors": 0}

            def content_health(self):
                return {"published": 6, "validation_failures": 0}

            def behavior_health(self):
                return {"total_baselines": 3, "anomalies": 1}

            def correlation_health(self):
                return {"total_incidents": 2, "open_incidents": 1}

            def case_health(self):
                return {"total_cases": 2, "open_cases": 1}

            def notification_health(self):
                return {"total": 2, "dead_letters": 0}

            def response_health(self):
                return {"total_executions": 2, "failed": 0}

            def enrichment_health(self):
                return {"requests": 3, "failed": 0}

            def analyst_health(self):
                return {"total_runs": 2, "failed_runs": 0}

            def model_gateway_health(self):
                return {"routes": 2, "active_routes": 1, "secret_ready": True}

            def simulation_health(self):
                return {"scenarios": 6, "runs": 2, "audit_valid": True}

            def administration_health(self):
                return {
                    "status": "healthy",
                    "identities": 2,
                    "workloads": 1,
                    "active_keys": 1,
                    "audit_valid": True,
                    "production_ready": False,
                }

            def administration_snapshot(self):
                return {
                    "tenant": {
                        "tenant_id": "tenant-lab",
                        "display_name": "AgentSec laboratory",
                        "status": "active",
                        "residency_region": "ap-northeast-1",
                        "allowed_processing_regions": ["ap-northeast-1"],
                        "retention_days": 365,
                        "evidence_retention_days": 730,
                        "legal_hold": False,
                        "encryption_required": True,
                        "policy_version": 1,
                        "record_sha256": "1" * 64,
                    },
                    "identities": [
                        {"enabled": True, "roles": ["platform_administrator"]},
                        {"enabled": True, "roles": ["security_auditor"]},
                    ],
                    "workloads": [{"revoked_at": None}],
                    "keys": [{"state": "active"}],
                    "access_reviews": [{"decision": "certified"}],
                    "slo_measurements": [{
                        "objective": {"name": "Authorization availability"},
                        "observed": 0.9999,
                        "passed": True,
                        "error_budget_remaining": 0.8,
                    }],
                    "recovery_drills": [{
                        "passed": True,
                        "observed_rpo_minutes": 4,
                        "observed_rto_minutes": 12,
                        "integrity_verified": True,
                        "record_sha256": "2" * 64,
                    }],
                    "supply_chain_attestations": [{
                        "release_id": "release-2026.07.24.1",
                        "passed": True,
                        "signature_verified": True,
                        "artifact_sha256": "3" * 64,
                        "sbom_sha256": "4" * 64,
                        "provenance_sha256": "5" * 64,
                    }],
                    "latest_audit_checkpoint": {
                        "sequence": 12,
                        "current_sha256": "6" * 64,
                        "signature_algorithm": "hmac-sha256-poc",
                    },
                    "health": {
                        "audit_entries": 12,
                        "audit_valid": True,
                        "latest_slos_passed": True,
                        "latest_recovery_drill_passed": True,
                        "latest_supply_chain_attestation_passed": True,
                        "local_identity_adapter": True,
                        "external_idp_federated": False,
                        "external_key_custody_verified": False,
                        "geographic_residency_verified": False,
                        "distributed_ha_verified": False,
                        "production_ready": False,
                        "boundaries": ["Local adapter is not enterprise federation."],
                    },
                }

        platform_client = PlatformClient()
        live = bridge_module.LiveBridge(platform_client)
        snapshot = live.platform_snapshot()
        self.assertTrue(snapshot["bff"]["upstream_authenticated"])
        self.assertFalse(snapshot["bff"]["browser_service_auth_exposed"])
        self.assertFalse(snapshot["bff"]["human_identity_verified"])
        self.assertEqual(len(snapshot["services"]), 18)
        self.assertTrue(all(item["state"] == "available" for item in snapshot["services"]))
        sources = next(item for item in snapshot["services"] if item["service_id"] == "telemetry_sources")
        self.assertEqual(sources["metrics"]["sources_count"], 1)
        self.assertNotIn("never-return", json.dumps(snapshot))
        self.assertTrue(snapshot["reports"]["release"]["all_passed"])
        self.assertFalse(snapshot["reports"]["release"]["production_ready"])
        self.assertEqual(len(snapshot["reports"]["evaluation"]["artifacts"]), 11)
        self.assertEqual(len(snapshot["reports"]["evaluation"]["modes"]), 8)
        mode_rates = {
            item["mode"]: item["forbidden_effect_attack_success_rate"]
            for item in snapshot["reports"]["evaluation"]["modes"]
        }
        self.assertEqual(mode_rates["unprotected"], 1.0)
        self.assertEqual(mode_rates["deterministic"], 0.0)
        self.assertEqual(
            len(snapshot["reports"]["evaluation"]["ablation"]["results"]), 8
        )
        continuous = snapshot["reports"]["evaluation"]["continuous"]
        self.assertEqual(continuous["candidate"]["gate_state"], "pass")
        self.assertTrue(continuous["candidate"]["drift_passed"])
        self.assertEqual(continuous["candidate"]["case_count"], 42)
        self.assertEqual(continuous["candidate"]["splits"]["holdout"], 24)
        self.assertEqual(len(continuous["candidate"]["use_cases"]), 6)
        self.assertEqual(continuous["candidate"]["provider"], "codex")
        self.assertEqual(sum(item["status"] == "verified" for item in snapshot["modules"]), 24)
        administration = snapshot["administration"]
        self.assertEqual(administration["state"], "available")
        self.assertEqual(administration["tenant"]["residency_region"], "ap-northeast-1")
        self.assertEqual(administration["identity"]["role_counts"]["security_auditor"], 1)
        self.assertTrue(administration["assurance"]["audit_valid"])
        self.assertFalse(administration["identity"]["external_idp_federated"])
        self.assertFalse(administration["keys"]["external_custody_verified"])
        self.assertFalse(administration["assurance"]["geographic_residency_verified"])
        self.assertFalse(administration["assurance"]["distributed_ha_verified"])
        self.assertFalse(administration["assurance"]["production_ready"])
        self.assertNotIn("keyref://", json.dumps(administration))
        with self.assertRaisesRegex(ValueError, "unknown platform report"):
            bridge_module._load_fixed_platform_report("../../private")
        with self.assertRaisesRegex(ValueError, "unknown evaluation record"):
            bridge_module._load_fixed_evaluation_record("../../private.json", "0" * 64)

        handler_type = bridge_module.make_handler(live, 8765)

        def get(path):
            handler = handler_type.__new__(handler_type)
            handler.path = path
            handler.command = "GET"
            handler.request_version = "HTTP/1.1"
            handler.server = SimpleNamespace(server_port=8765)
            handler.headers = Message()
            handler.headers["Host"] = "127.0.0.1:8765"
            handler.headers["Origin"] = "http://127.0.0.1:3000"
            handler.wfile = BytesIO()
            captured = {"status": None, "headers": {}}
            handler.send_response = lambda status: captured.update(status=status)
            handler.send_header = lambda key, value: captured["headers"].update({key: value})
            handler.end_headers = lambda: None
            handler.do_GET()
            return captured["status"], json.loads(handler.wfile.getvalue())

        status, body = get("/api/platform")
        self.assertEqual((status, body["schema_version"]), (200, "1.0.0"))
        status, body = get("/api/platform?path=../../private")
        self.assertEqual((status, body["error"]), (400, "invalid_request"))

    def test_loopback_http_bridge_rejects_arbitrary_mutation(self) -> None:
        class FakeClient:
            transitions = []

            def list_alerts(self):
                return {
                    "alerts": [],
                    "ledger_verified": True,
                    "checked_at": "now",
                }

            def transition(self, finding_id, *, action, actor, reason):
                self.transitions.append((finding_id, action, actor, reason))
                return {
                    "detail_availability": "complete",
                    "summary": {
                        "finding_id": finding_id,
                        "status": "investigating",
                    },
                }

        client = FakeClient()
        live = bridge_module.LiveBridge(client, cache_seconds=0)
        handler_type = bridge_module.make_handler(live, 8765)

        def post(payload, *, origin="http://127.0.0.1:3000"):
            encoded = json.dumps(payload).encode("utf-8")
            handler = handler_type.__new__(handler_type)
            handler.path = "/api/alerts/fnd_http12345678/transition"
            handler.command = "POST"
            handler.request_version = "HTTP/1.1"
            handler.server = SimpleNamespace(server_port=8765)
            handler.headers = Message()
            handler.headers["Host"] = "127.0.0.1:8765"
            handler.headers["Origin"] = origin
            handler.headers["Content-Type"] = "application/json"
            handler.headers["Content-Length"] = str(len(encoded))
            handler.rfile = BytesIO(encoded)
            handler.wfile = BytesIO()
            captured = {"status": None, "headers": {}}
            handler.send_response = lambda status: captured.update(status=status)
            handler.send_header = (
                lambda key, value: captured["headers"].update({key: value})
            )
            handler.end_headers = lambda: None
            handler.do_POST()
            return captured["status"], json.loads(handler.wfile.getvalue())

        status, _ = post(
            {
                "action": "start_investigation",
                "actor": "analyst://bridge-test",
                "reason": "Reviewing the authoritative incident evidence",
                "command": "arbitrary-mutation",
            }
        )
        self.assertEqual(status, 400)
        self.assertEqual(client.transitions, [])

        status, payload = post(
            {
                "action": "start_investigation",
                "actor": "analyst://bridge-test",
                "reason": "Reviewing the authoritative incident evidence",
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["incident"]["summary"]["status"], "investigating")
        self.assertEqual(len(client.transitions), 1)

        status, _ = post(
            {
                "action": "close",
                "actor": "analyst://bridge-test",
                "reason": "Wrong origin must not reach the client",
            },
            origin="https://attacker.invalid",
        )
        self.assertEqual(status, 403)
        self.assertEqual(len(client.transitions), 1)

if __name__ == "__main__":
    unittest.main()
