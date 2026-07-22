from __future__ import annotations

import unittest
from pathlib import Path


class DeploymentRuntimeCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.probe = Path("deploy/ec2-tokyo/runtime-check.sh").read_text(
            encoding="utf-8"
        )

    def test_probe_checks_private_hardened_runtime(self) -> None:
        self.assertIn("systemctl is-active --quiet agentsec.service", self.probe)
        self.assertIn('test "$container_health" = "healthy"', self.probe)
        self.assertIn('test "$published_port" = "127.0.0.1:8080"', self.probe)
        self.assertIn("*@sha256:*", self.probe)

    def test_probe_exercises_allow_deny_and_ledger_paths(self) -> None:
        self.assertIn('"benign_inventory_read"', self.probe)
        self.assertIn('"indirect_injection_secret_egress"', self.probe)
        self.assertIn('"indirect_prompt_injection", "secret_egress"', self.probe)
        self.assertIn('"ledger_verified": True', self.probe)
        self.assertIn("REMOTE_CANARY_MUST_NOT_ECHO", self.probe)
        self.assertIn('"model_profile": "codex-recorded-shadow"', self.probe)
        self.assertIn('"live_provider_keys_present": False', self.probe)

    def test_probe_never_reads_or_prints_host_secret_file(self) -> None:
        executable = "\n".join(
            line for line in self.probe.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertNotIn("/etc/agentsec/runtime.env", executable)
        self.assertNotIn("get-secret-value", executable)
        self.assertIn('os.environ["AGENTSEC_INGEST_TOKEN"]', executable)


if __name__ == "__main__":
    unittest.main()
