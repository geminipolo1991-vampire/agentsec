from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from pydantic import ValidationError

from agentsec.contracts import AgentEvent
from agentsec.scenarios import forge_scenarios


class SchemaContractTests(unittest.TestCase):
    def test_unknown_security_critical_field_is_rejected(self) -> None:
        payload = forge_scenarios()["benign_inventory_read"].model_dump(mode="json")
        payload["secret_override_allow"] = True

        with self.assertRaises(ValidationError):
            AgentEvent.model_validate(payload)

    def test_committed_schemas_have_no_drift(self) -> None:
        result = subprocess.run(
            [sys.executable, "tools/generate_schemas.py", "--check"],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_agent_event_schema_forbids_additional_properties(self) -> None:
        schema = json.loads(
            Path("schemas/generated/action-event.schema.json").read_text(encoding="utf-8")
        )

        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["default"], "1.0.0")

