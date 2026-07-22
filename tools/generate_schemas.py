#!/usr/bin/env python3
"""Generate or verify committed JSON Schemas from canonical Pydantic models."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Type

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pydantic import BaseModel  # noqa: E402

from agentsec.approval import ApprovalToken  # noqa: E402
from agentsec.authority import AuthorityGrant  # noqa: E402
from agentsec.contracts import (  # noqa: E402
    AgentEvent,
    EventProcessingResult,
    Finding,
    Judgment,
    ModelVerdict,
    PipelineResult,
    SecurityAlert,
)
from agentsec.ingestion import LedgerVerification  # noqa: E402
from agentsec.evaluation import (  # noqa: E402
    AblationReport,
    EvaluationReleaseManifest,
    EvaluationReport,
)
from agentsec.model_registry import ModelRegistry  # noqa: E402
from agentsec.privacy import ModelEvidenceBundle, SocFindingExport  # noqa: E402
from agentsec.provenance import ProvenanceRecord  # noqa: E402
from agentsec.providers import ProviderCallRecord, ProviderVerdictPayload  # noqa: E402
from agentsec.synthetic import ScenarioDefinition, WorkflowRun  # noqa: E402
from agentsec.service import AuthorizationResponse  # noqa: E402
from agentsec.abom import AbomDiff, AbomManifest  # noqa: E402
from agentsec.checkpoints import CheckpointVerification, LedgerCheckpoint  # noqa: E402
from agentsec.graph import CausalPath  # noqa: E402
from agentsec.adapters import FrameworkToolProposal  # noqa: E402
from agentsec.observation import ObservationFinding  # noqa: E402
from agentsec.incidents import IncidentDetail  # noqa: E402
from agentsec.splunk import SplunkDeadLetter, SplunkExportReceipt  # noqa: E402


MODELS: Dict[str, Type[BaseModel]] = {
    "action-event": AgentEvent,
    "security-alert": SecurityAlert,
    "model-verdict": ModelVerdict,
    "judgment": Judgment,
    "finding": Finding,
    "pipeline-result": PipelineResult,
    "event-processing-result": EventProcessingResult,
    "approval-token": ApprovalToken,
    "authority-grant": AuthorityGrant,
    "provenance-record": ProvenanceRecord,
    "ledger-verification": LedgerVerification,
    "scenario-definition": ScenarioDefinition,
    "workflow-run": WorkflowRun,
    "evaluation-report": EvaluationReport,
    "ablation-report": AblationReport,
    "evaluation-release-manifest": EvaluationReleaseManifest,
    "model-registry": ModelRegistry,
    "model-evidence-bundle": ModelEvidenceBundle,
    "soc-finding-export": SocFindingExport,
    "provider-call-record": ProviderCallRecord,
    "provider-verdict-payload": ProviderVerdictPayload,
    "authorization-response": AuthorizationResponse,
    "abom-manifest": AbomManifest,
    "abom-diff": AbomDiff,
    "ledger-checkpoint": LedgerCheckpoint,
    "checkpoint-verification": CheckpointVerification,
    "causal-path": CausalPath,
    "framework-tool-proposal": FrameworkToolProposal,
    "observation-finding": ObservationFinding,
    "incident-detail": IncidentDetail,
    "splunk-export-receipt": SplunkExportReceipt,
    "splunk-dead-letter": SplunkDeadLetter,
}


def render(model: Type[BaseModel]) -> str:
    return json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n"


def generate(output_dir: Path, check: bool) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    failures = []
    expected_names = set()
    for name, model in MODELS.items():
        path = output_dir / (name + ".schema.json")
        expected_names.add(path.name)
        expected = render(model)
        if check:
            if not path.exists() or path.read_text(encoding="utf-8") != expected:
                failures.append(str(path.relative_to(ROOT)))
        else:
            path.write_text(expected, encoding="utf-8")

    extras = {
        path.name for path in output_dir.glob("*.schema.json") if path.name not in expected_names
    }
    if check and extras:
        failures.extend(str(output_dir / name) for name in sorted(extras))
    if failures:
        print("schema drift detected:")
        for failure in failures:
            print("- %s" % failure)
        return 1
    print("verified %d generated schemas" % len(MODELS))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "schemas" / "generated")
    args = parser.parse_args()
    return generate(args.output, args.check)


if __name__ == "__main__":
    raise SystemExit(main())
