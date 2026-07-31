from __future__ import annotations

import json
import tempfile
import unittest
from email.message import Message
from io import BytesIO
from unittest.mock import patch

from pydantic import ValidationError

from agentsec.service import AuthorizationApplication, application_from_environment, make_handler
from agentsec.pipeline import SecurityPipeline
from agentsec.simulation import (
    SIMULATION_ADMIN,
    SIMULATION_READ,
    SimulationAuthorizationError,
    SimulationConflictError,
    SimulationImportRequest,
    SimulationMutationRequest,
    SimulationPrincipal,
    SimulationReplayRequest,
    SimulationRun,
    SimulationRunRequest,
    SimulationSandboxReceipt,
    SimulationScenarioDraft,
    SimulationService,
    SimulationVariant,
    built_in_scenario_drafts,
)


class SimulationLabTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.service = SimulationService(
            self.directory.name + "/simulation.sqlite3", tenant_id="tenant-test"
        )
        self.principal = SimulationPrincipal(
            tenant_id="tenant-test",
            actor_id="analyst://simulation-test",
            permissions={SIMULATION_ADMIN},
        )

    def tearDown(self) -> None:
        self.service.close()
        self.directory.cleanup()

    def test_catalog_is_mapped_multistage_and_explicit_about_normalization(self) -> None:
        catalog = self.service.catalog(self.principal)

        self.assertEqual(catalog.health.scenarios, 6)
        self.assertEqual(len(catalog.variants), len(SimulationVariant))
        self.assertTrue(all(not item.raw_content_retained for item in catalog.variants))
        self.assertIn("metadata_only_no_raw_stimulus", catalog.safety_invariants)
        self.assertIn("no_network", catalog.safety_invariants)
        self.assertEqual(
            {step.event.tenant_id for item in catalog.scenarios.scenarios for step in item.steps},
            {"tenant-test"},
        )
        multistage = next(
            item for item in catalog.scenarios.scenarios if "multi-stage" in item.tags
        )
        self.assertEqual(len(multistage.steps), 2)
        mappings = {
            mapping
            for item in catalog.scenarios.scenarios
            for mapping in item.framework_mappings
        }
        self.assertTrue(any(item.startswith("OWASP-LLM") for item in mappings))
        self.assertTrue(any(item.startswith("MITRE-ATLAS-") for item in mappings))

    def test_every_builtin_comparison_passes_and_uses_only_mock_effects(self) -> None:
        scenarios = self.service.list_scenarios(self.principal).scenarios
        with patch("socket.create_connection", side_effect=AssertionError("network called")):
            for index, scenario in enumerate(scenarios):
                with self.subTest(scenario=scenario.scenario_id):
                    run = self.service.run(
                        self.principal,
                        SimulationRunRequest(
                            request_id="req_builtin%02d" % index,
                            scenario_id=scenario.scenario_id,
                            version=scenario.version,
                            mode="comparison",
                        ),
                    )
                    self.assertTrue(run.passed)
                    self.assertTrue(run.sandbox.local_only)
                    self.assertFalse(run.sandbox.network_enabled)
                    self.assertFalse(run.sandbox.filesystem_enabled)
                    self.assertFalse(run.sandbox.shell_enabled)
                    self.assertEqual(
                        run.sandbox.completed_steps,
                        sum(len(item.steps) for item in run.results),
                    )
                    protected, control = run.results
                    self.assertTrue(protected.protected)
                    self.assertFalse(control.protected)
                    self.assertEqual(protected.forbidden_effect_count, 0)
                    if scenario.attack:
                        self.assertGreater(control.forbidden_effect_count, 0)

    def test_fixed_multilingual_and_obfuscation_mutations_are_digest_bound(self) -> None:
        base = self.service.get_scenario(
            self.principal, "sim_indirect_injection_egress", "1.0.0"
        )
        variants = [
            SimulationVariant.JAPANESE,
            SimulationVariant.SPANISH,
            SimulationVariant.UNICODE_CONFUSABLE,
            SimulationVariant.ZERO_WIDTH,
            SimulationVariant.BASE64,
            SimulationVariant.MIXED_OBFUSCATION,
        ]
        derived = []
        for variant in variants:
            scenario = self.service.mutate(
                self.principal,
                SimulationMutationRequest(
                    base_scenario_id=base.scenario_id,
                    base_version=base.version,
                    variant=variant,
                ),
            )
            derived.append(scenario)
            self.assertEqual(scenario.parent_scenario_id, base.scenario_id)
            self.assertEqual(scenario.variant, variant)
            self.assertTrue(scenario.trusted_ground_truth)
            self.assertNotEqual(scenario.record_sha256, base.record_sha256)
            self.assertNotIn("raw_prompt", scenario.model_dump_json())
            run = self.service.run(
                self.principal,
                SimulationRunRequest(
                    request_id="req_variant%s" % len(derived),
                    scenario_id=scenario.scenario_id,
                    version=scenario.version,
                    mode="protected",
                ),
            )
            self.assertTrue(run.passed)
        self.assertEqual(len({item.scenario_id for item in derived}), len(variants))

    def test_import_is_strict_untrusted_and_rejects_unsafe_effects(self) -> None:
        original = built_in_scenario_drafts()[0]
        draft = original.model_copy(
            update={"scenario_id": "sim_imported_benign", "name": "Imported benign control"}
        )
        result = self.service.import_scenarios(
            self.principal, SimulationImportRequest(scenarios=[draft])
        )
        self.assertEqual(result.count, 1)
        self.assertFalse(result.imported[0].trusted_ground_truth)
        self.assertEqual(result.imported[0].source.value, "imported")

        step = original.steps[0]
        with self.assertRaisesRegex(ValidationError, "reserved HTTPS .invalid"):
            SimulationScenarioDraft(
                **original.model_dump(exclude={"scenario_id", "steps"}),
                scenario_id="sim_unsafe_destination",
                steps=[
                    step.model_copy(
                        update={
                            "event": step.event.model_copy(
                                update={"destination": "https://example.com/collect"}
                            )
                        }
                    )
                ],
            )

    def test_rbac_tenant_idempotency_conflict_replay_and_audit(self) -> None:
        reader = SimulationPrincipal(
            tenant_id="tenant-test",
            actor_id="analyst://reader",
            permissions={SIMULATION_READ},
        )
        with self.assertRaises(SimulationAuthorizationError):
            self.service.mutate(
                reader,
                SimulationMutationRequest(
                    base_scenario_id="sim_indirect_injection_egress",
                    base_version="1.0.0",
                    variant="japanese",
                ),
            )
        with self.assertRaises(SimulationAuthorizationError):
            self.service.catalog(
                reader.model_copy(update={"tenant_id": "tenant-other"})
            )

        request = SimulationRunRequest(
            request_id="req_idempotent1",
            scenario_id="sim_indirect_injection_egress",
            version="1.0.0",
            mode="comparison",
        )
        first = self.service.run(self.principal, request)
        self.assertEqual(first, self.service.run(self.principal, request))
        with self.assertRaises(SimulationConflictError):
            self.service.run(
                self.principal,
                request.model_copy(update={"scenario_id": "sim_benign_inventory"}),
            )
        replay = self.service.replay(
            self.principal,
            first.run_id,
            SimulationReplayRequest(request_id="req_replay001"),
        )
        self.assertEqual(replay.replay_of, first.run_id)
        self.assertTrue(replay.passed)
        self.assertTrue(self.service.health(self.principal).audit_valid)
        self.assertEqual(self.service.audit(self.principal)[-1].action, "simulation.run_replayed")

        payload = replay.model_dump(mode="json")
        payload["passed"] = False
        with self.assertRaisesRegex(ValidationError, "inconsistent|digest"):
            SimulationRun.model_validate(payload)
        receipt = replay.sandbox.model_dump(mode="json")
        receipt["network_enabled"] = True
        with self.assertRaisesRegex(ValidationError, "isolation|digest"):
            SimulationSandboxReceipt.model_validate(receipt)

    def test_authenticated_http_api_exposes_catalog_builder_runs_and_replay(self) -> None:
        token = "simulation-private-token-at-least-thirty-two-bytes"
        application = AuthorizationApplication(
            simulation_service=self.service, simulation_principal=self.principal
        )
        handler_type = make_handler(application, token)

        def request(method, path, body=None, *, authorized=True):
            handler = handler_type.__new__(handler_type)
            handler.path = path
            handler.command = method
            handler.request_version = "HTTP/1.1"
            handler.headers = Message()
            if authorized:
                handler.headers["Authorization"] = "Bearer %s" % token
            encoded = b""
            if body is not None:
                encoded = json.dumps(body).encode("utf-8")
                handler.headers["Content-Type"] = "application/json"
                handler.headers["Content-Length"] = str(len(encoded))
            handler.rfile = BytesIO(encoded)
            handler.wfile = BytesIO()
            captured = {"status": None}
            handler.send_response = lambda status: captured.update(status=status)
            handler.send_header = lambda _key, _value: None
            handler.end_headers = lambda: None
            getattr(handler, "do_%s" % method)()
            return captured["status"], json.loads(handler.wfile.getvalue())

        status, catalog = request("GET", "/v1/simulation/catalog")
        self.assertEqual(status, 200)
        self.assertEqual(catalog["health"]["scenarios"], 6)
        status, health = request("GET", "/v1/simulation/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["audit_valid"])
        status, mutated = request(
            "POST",
            "/v1/simulation/mutations",
            {
                "base_scenario_id": "sim_indirect_injection_egress",
                "base_version": "1.0.0",
                "variant": "japanese",
                "name": None,
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(mutated["variant"], "japanese")
        status, run = request(
            "POST",
            "/v1/simulation/runs",
            {
                "request_id": "req_httpbuild1",
                "scenario_id": mutated["scenario_id"],
                "version": mutated["version"],
                "mode": "comparison",
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(run["passed"])
        status, detail = request("GET", "/v1/simulation/runs/" + run["run_id"])
        self.assertEqual(status, 200)
        self.assertEqual(detail["record_sha256"], run["record_sha256"])
        status, replay = request(
            "POST",
            "/v1/simulation/runs/%s/replay" % run["run_id"],
            {"request_id": "req_httpreplay1"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(replay["replay_of"], run["run_id"])
        import_draft = built_in_scenario_drafts()[0].model_copy(
            update={"scenario_id": "sim_http_import", "name": "HTTP imported control"}
        )
        status, imported = request(
            "POST",
            "/v1/simulation/imports",
            {"schema_version": "1.0.0", "scenarios": [import_draft.model_dump(mode="json")]},
        )
        self.assertEqual(status, 200)
        self.assertFalse(imported["imported"][0]["trusted_ground_truth"])
        status, runs = request("GET", "/v1/simulation/runs?limit=100&offset=0")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(runs["count"], 2)
        status, audit = request("GET", "/v1/simulation/audit?limit=200")
        self.assertEqual(status, 200)
        self.assertEqual(audit["count"], len(audit["entries"]))
        status, _ = request("GET", "/v1/simulation/catalog", authorized=False)
        self.assertEqual(status, 401)

    def test_environment_assembly_uses_the_durable_simulation_database(self) -> None:
        database = self.directory.name + "/environment-simulation.sqlite3"
        with patch.dict(
            "os.environ",
            {
                "AGENTSEC_SIMULATION_DB": database,
                "AGENTSEC_SIMULATION_TENANT": "tenant-environment",
            },
            clear=True,
        ):
            application = application_from_environment(SecurityPipeline())
        self.assertEqual(application.simulation_catalog().health.scenarios, 6)
        application.simulation_service.close()
        reopened = SimulationService(database, tenant_id="tenant-environment")
        principal = SimulationPrincipal(
            tenant_id="tenant-environment",
            actor_id="analyst://reopen-test",
            permissions={SIMULATION_ADMIN},
        )
        self.assertEqual(reopened.health(principal).scenarios, 6)
        reopened.close()


if __name__ == "__main__":
    unittest.main()
