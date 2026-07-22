from __future__ import annotations

import json
import unittest
from pathlib import Path


class DeploymentReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = json.loads(
            Path("reports/deployment/ec2-tokyo-20260722.json").read_text(
                encoding="utf-8"
            )
        )

    def test_report_records_completed_private_deployment(self) -> None:
        deployment = self.report["deployment"]
        controls = self.report["runtime_controls"]

        self.assertEqual(deployment["foundation_stack"]["status"], "CREATE_COMPLETE")
        self.assertEqual(deployment["service_stack"]["status"], "CREATE_COMPLETE")
        self.assertFalse(deployment["existing_resources_modified"])
        self.assertFalse(controls["public_ip_assigned"])
        self.assertEqual(controls["security_group_ingress_rules"], 0)
        self.assertEqual(controls["service_binding"], "127.0.0.1:8080")

    def test_report_records_clean_image_and_expected_runtime_results(self) -> None:
        image = self.report["image"]
        verification = self.report["verification"]
        scenarios = {item["name"]: item for item in verification["scenarios"]}

        self.assertEqual(image["scan_status"], "COMPLETE")
        self.assertEqual(image["scan_finding_counts"], {})
        self.assertEqual(scenarios["benign_inventory_read"]["overall_action"], "allow")
        self.assertEqual(
            scenarios["indirect_injection_secret_egress"]["overall_action"],
            "deny",
        )
        self.assertEqual(
            set(scenarios["indirect_injection_secret_egress"]["alerts"]),
            {"indirect_prompt_injection", "secret_egress"},
        )
        self.assertTrue(all(item["ledger_verified"] for item in scenarios.values()))

    def test_report_proves_disabled_exposure_without_recording_secret(self) -> None:
        exposure = self.report["exposure"]
        controls = self.report["runtime_controls"]

        self.assertFalse(exposure["public_endpoint"])
        self.assertFalse(exposure["public_ui"])
        self.assertFalse(exposure["openai_live_enabled"])
        self.assertFalse(exposure["anthropic_live_enabled"])
        self.assertFalse(controls["live_provider_keys_present"])
        self.assertFalse(controls["runtime_secret_value_recorded"])


if __name__ == "__main__":
    unittest.main()
