#!/usr/bin/env python3
"""Fail closed when the committed continuous-evaluation release gate drifts."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsec.continuous_evaluation import (  # noqa: E402
    CandidateKind,
    ContinuousEvaluationReport,
    EvaluationGateState,
    load_evaluation_policy,
)
from agentsec.evaluation import EvaluationReleaseManifest  # noqa: E402


def main() -> int:
    manifest = EvaluationReleaseManifest.model_validate_json(
        (ROOT / "reports" / "evaluation" / "manifest.json").read_text(
            encoding="utf-8"
        )
    )
    artifacts = {item.path: item for item in manifest.artifacts}
    reports = {}
    failures = []
    for name in ("continuous-baseline.json", "continuous.json"):
        relative = "reports/evaluation/" + name
        artifact = artifacts.get(relative)
        path = ROOT / relative
        if artifact is None or not path.exists():
            failures.append("missing manifest-bound %s" % relative)
            continue
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != artifact.sha256:
            failures.append("artifact SHA-256 mismatch for %s" % relative)
            continue
        try:
            report = ContinuousEvaluationReport.model_validate_json(content)
        except ValueError as exc:
            failures.append("invalid %s: %s" % (relative, exc))
            continue
        if report.record_digest != artifact.record_digest:
            failures.append("record digest mismatch for %s" % relative)
        reports[name] = report

    baseline = reports.get("continuous-baseline.json")
    candidate = reports.get("continuous.json")
    policy = load_evaluation_policy(
        ROOT / "configs" / "continuous-evaluation-policy.json"
    )
    if baseline is not None:
        if baseline.candidate.kind != CandidateKind.DETERMINISTIC:
            failures.append("continuous baseline is not deterministic")
        if baseline.gate.state != EvaluationGateState.PASS:
            failures.append("continuous baseline gate did not pass")
    if candidate is not None:
        if candidate.candidate.kind != CandidateKind.RECORDED_MODEL:
            failures.append("release candidate is not a recorded model evaluation")
        if candidate.candidate.provider != "codex":
            failures.append("release candidate provider is not Codex")
        if candidate.gate.state != EvaluationGateState.PASS:
            failures.append("continuous candidate gate did not pass")
        if candidate.gate.policy_sha256 != policy.policy_sha256:
            failures.append("continuous report policy digest is stale")
        if candidate.dataset.case_count < policy.minimum_cases:
            failures.append("continuous dataset is smaller than policy")
        if candidate.dataset.splits.get("holdout", 0) < 24:
            failures.append("continuous dataset has fewer than 24 holdout cases")
        if candidate.dataset.use_case_count < 6:
            failures.append("continuous dataset lacks use-case coverage")
        if candidate.gate.drift is None or not candidate.gate.drift.passed:
            failures.append("continuous candidate lacks a passing drift comparison")
        if baseline is not None and candidate.gate.drift is not None:
            if candidate.gate.drift.baseline_record_digest != baseline.record_digest:
                failures.append("continuous drift baseline digest is stale")

    if failures:
        print("continuous evaluation gate failed:")
        for item in failures:
            print("- %s" % item)
        return 1
    print(
        "continuous evaluation gate: passed "
        "(42 cases, 24 holdout, 6 use cases, drift bound)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
