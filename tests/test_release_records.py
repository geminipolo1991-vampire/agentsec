from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from agentsec.crypto import canonical_bytes
from agentsec.evaluation import EvaluationReleaseManifest


class ReleaseRecordTests(unittest.TestCase):
    def test_manifest_binds_all_committed_evaluation_records(self) -> None:
        root = Path(__file__).resolve().parents[1]
        payload = json.loads(
            (root / "reports/evaluation/manifest.json").read_text(encoding="utf-8")
        )
        manifest = EvaluationReleaseManifest.model_validate(payload)

        for artifact in manifest.artifacts:
            content = (root / artifact.path).read_bytes()
            self.assertEqual(hashlib.sha256(content).hexdigest(), artifact.sha256)
            report = json.loads(content)
            self.assertEqual(report["record_digest"], artifact.record_digest)
        for path, expected in manifest.input_digests.items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), expected)

        digest_payload = {
            "dataset_version": manifest.dataset_version,
            "artifacts": [item.model_dump(mode="json") for item in manifest.artifacts],
            "input_digests": manifest.input_digests,
        }
        self.assertEqual(
            hashlib.sha256(canonical_bytes(digest_payload)).hexdigest(),
            manifest.manifest_digest,
        )


if __name__ == "__main__":
    unittest.main()
