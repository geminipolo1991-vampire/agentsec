#!/usr/bin/env python3
"""Generate or verify deterministic, digest-bound evaluation release records."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsec.crypto import canonical_bytes  # noqa: E402
from agentsec.evaluation import (  # noqa: E402
    AblationReport,
    EvaluationArtifact,
    EvaluationMode,
    EvaluationReleaseManifest,
    EvaluationReport,
    EvaluationRunner,
)

REPORT_DIR = ROOT / "reports" / "evaluation"
INPUTS = (
    "configs/codex-evaluation.json",
    "src/agentsec/detection.py",
    "src/agentsec/evaluation.py",
    "src/agentsec/scenarios.py",
    "src/agentsec/synthetic.py",
)


def _render(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reports() -> Dict[str, Tuple[object, str]]:
    runner = EvaluationRunner(ROOT / "configs" / "codex-evaluation.json")
    records: Dict[str, Tuple[object, str]] = {}
    for mode in EvaluationMode:
        report: EvaluationReport = runner.run(mode)
        records[mode.value + ".json"] = (
            report.model_dump(mode="json"),
            report.record_digest,
        )
    ablation: AblationReport = runner.run_ablations()
    records["ablation.json"] = (
        ablation.model_dump(mode="json"),
        ablation.record_digest,
    )
    return records


def expected_files() -> Dict[str, str]:
    rendered: Dict[str, str] = {}
    artifacts = []
    for name, (record, record_digest) in sorted(_reports().items()):
        content = _render(record)
        rendered[name] = content
        artifacts.append(
            EvaluationArtifact(
                path="reports/evaluation/" + name,
                sha256=_sha256_bytes(content.encode("utf-8")),
                record_digest=record_digest,
            )
        )

    input_digests = {
        path: _sha256_bytes((ROOT / path).read_bytes()) for path in INPUTS
    }
    manifest_payload = {
        "dataset_version": EvaluationRunner.dataset_version,
        "artifacts": [item.model_dump(mode="json") for item in artifacts],
        "input_digests": input_digests,
    }
    manifest = EvaluationReleaseManifest(
        dataset_version=EvaluationRunner.dataset_version,
        artifacts=artifacts,
        input_digests=input_digests,
        manifest_digest=_sha256_bytes(canonical_bytes(manifest_payload)),
    )
    rendered["manifest.json"] = _render(manifest.model_dump(mode="json"))
    return rendered


def generate(check: bool) -> int:
    expected = expected_files()
    failures = []
    if not check:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
    for name, content in expected.items():
        path = REPORT_DIR / name
        if check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                failures.append(str(path.relative_to(ROOT)))
        else:
            path.write_text(content, encoding="utf-8")

    if REPORT_DIR.exists():
        extras = {
            path.name for path in REPORT_DIR.glob("*.json") if path.name not in expected
        }
        failures.extend(
            str((REPORT_DIR / name).relative_to(ROOT)) for name in sorted(extras)
        )
    if failures:
        print("evaluation report drift detected:")
        for failure in failures:
            print("- %s" % failure)
        return 1
    print("verified %d deterministic evaluation records" % len(expected))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    return generate(args.check)


if __name__ == "__main__":
    raise SystemExit(main())
