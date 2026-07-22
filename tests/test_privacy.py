from __future__ import annotations

import json
import unittest

from agentsec.pipeline import SecurityPipeline
from agentsec.privacy import PrivacyTransformer
from agentsec.redaction import REDACTED, Redactor
from agentsec.scenarios import forge_scenarios


CANARY = "CANARY_SECRET_MUST_NEVER_LEAVE_RESTRICTED_STORE_7F31"


class RedactionTests(unittest.TestCase):
    def test_recursive_redaction_removes_sensitive_fields_and_values(self) -> None:
        payload = {
            "authorization": "Bearer abcdefghijklmnop",
            "nested": {
                "api_key": "super-secret-value",
                "message": "password=hunter2",
                "evidence": CANARY,
            },
        }

        result = Redactor({CANARY}).redact(payload)
        encoded = json.dumps(result.value, sort_keys=True)

        self.assertGreaterEqual(result.redaction_count, 4)
        self.assertNotIn("abcdefghijklmnop", encoded)
        self.assertNotIn("super-secret-value", encoded)
        self.assertNotIn("hunter2", encoded)
        self.assertNotIn(CANARY, encoded)
        self.assertIn(REDACTED, encoded)


class PrivacyTransformerTests(unittest.TestCase):
    def _result_with_canary(self):
        event = forge_scenarios()["indirect_injection_secret_egress"].model_copy(
            update={
                "source_id": "document://external/%s" % CANARY,
                "attributes": {
                    "authorization": "Bearer abcdefghijklmnop",
                    "raw_prompt": CANARY,
                },
            }
        )
        return SecurityPipeline().process(event)

    def test_model_bundle_redacts_canary_from_evidence_reference(self) -> None:
        result = self._result_with_canary()
        transformer = PrivacyTransformer({CANARY})
        alert = result.alerts[0]

        bundle = transformer.model_evidence(alert.alert, alert.triage)
        encoded = json.dumps(bundle.model_dump(mode="json"), sort_keys=True)

        self.assertNotIn(CANARY, encoded)
        self.assertNotIn("abcdefghijklmnop", encoded)
        self.assertGreater(bundle.redaction_count, 0)
        self.assertTrue(bundle.untrusted_evidence_is_data)

    def test_soc_export_is_allowlist_built_and_contains_no_raw_content(self) -> None:
        result = self._result_with_canary()
        transformer = PrivacyTransformer({CANARY})
        export = transformer.soc_export(result.alerts[0], ledger_valid=True)
        payload = export.model_dump(mode="json")
        encoded = json.dumps(payload, sort_keys=True)

        self.assertNotIn(CANARY, encoded)
        self.assertNotIn("raw_prompt", encoded)
        self.assertNotIn("receiver.invalid", encoded)
        self.assertNotIn("honeytoken", encoded)
        self.assertEqual(payload["resource_class"], "secret")
        self.assertEqual(payload["destination_class"], "external-network")
        self.assertEqual(payload["ledger_integrity"], "verified")

