from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
APPROVED_NAMES = [
    "AI telemetry collection",
    "Ingestion gateway",
    "Canonical AI-security data model",
    "Evidence ledger and storage",
    "Search and threat hunting",
    "Agent application and model inventory",
    "AI security graph and attack paths",
    "AI security posture management",
    "Detection and rule engine",
    "Detection content management",
    "Behavioral analytics and risk engine",
    "Finding correlation and incident creation",
    "Enrichment engine",
    "AI Analyst Engine",
    "Model gateway and AI governance",
    "Evidence validator and judgment engine",
    "Incident and case management",
    "Escalation and notification",
    "Response and playbook automation",
    "Analyst user interface",
    "External API and SIEM integration",
    "Simulation and validation lab",
    "Evaluation and continuous improvement",
    "Administration platform security and audit",
]


class ModuleCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = json.loads(
            (ROOT / "configs" / "module-catalog.json").read_text(encoding="utf-8")
        )

    def test_catalog_preserves_the_approved_scope_and_exact_module_order(self) -> None:
        self.assertEqual(self.payload["schema_version"], "2.0.0")
        self.assertEqual(self.payload["scope"], "Approved AgentSec 24-module full product")
        self.assertEqual(
            [item["id"] for item in self.payload["modules"]],
            ["M%02d" % value for value in range(1, 25)],
        )
        self.assertEqual(
            [item["name"] for item in self.payload["modules"]], APPROVED_NAMES
        )

    def test_progress_audit_accepts_honest_partial_status(self) -> None:
        completed = subprocess.run(
            [sys.executable, "tools/verify_module_catalog.py"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("approved product modules verified", completed.stdout)

    def test_completion_audit_accepts_exactly_the_verified_approved_scope(self) -> None:
        completed = subprocess.run(
            [sys.executable, "tools/verify_module_catalog.py", "--require-complete"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        incomplete = [
            item["id"] for item in self.payload["modules"] if item["status"] != "verified"
        ]
        self.assertEqual(incomplete, [])
        self.assertIn("24/24 approved product modules verified", completed.stdout)


if __name__ == "__main__":
    unittest.main()
