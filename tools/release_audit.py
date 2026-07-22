#!/usr/bin/env python3
"""Produce a deterministic, machine-readable research-PoC acceptance audit."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsec.adapters import CallbackFrameworkAdapter, CustomAgentAdapter  # noqa: E402
from agentsec.contracts import PipelineStage  # noqa: E402
from agentsec.evaluation import AblationComponent, EvaluationMode, EvaluationRunner  # noqa: E402
from agentsec.pipeline import SecurityPipeline  # noqa: E402
from agentsec.privacy import SocFindingExport  # noqa: E402
from agentsec.providers import (  # noqa: E402
    AnthropicMessagesReasoner,
    OpenAIResponsesReasoner,
    SECURITY_SYSTEM_PROMPT,
)
from agentsec.synthetic import forge_scenario_definitions  # noqa: E402


def criterion(identifier: str, passed: bool, evidence: list[str]) -> dict[str, object]:
    return {"id": identifier, "passed": passed, "evidence": evidence}


def main() -> int:
    runner = EvaluationRunner(ROOT / "configs" / "codex-evaluation.json")
    deterministic = runner.run(EvaluationMode.DETERMINISTIC)
    codex = runner.run(EvaluationMode.CODEX_SHADOW)
    ablations = runner.run_ablations()
    definitions = forge_scenario_definitions()
    attack_count = sum(
        bool(item.ground_truth.forbidden_completed_operations)
        for item in definitions.values()
    )
    benign_count = len(definitions) - attack_count

    lifecycle = SecurityPipeline().process(
        definitions["indirect_injection_secret_egress"].event
    )
    stage_order = [stage.value for stage in PipelineStage]
    observed_stage_order = [item.stage.value for item in lifecycle.alerts[0].timeline]
    profile = json.loads(
        (ROOT / "configs" / "model-profiles.json").read_text(encoding="utf-8")
    )
    providers = {item["provider"] for item in profile["profiles"]}
    export_fields = set(SocFindingExport.model_fields)
    prohibited_export_fields = {
        "prompt",
        "response",
        "attributes",
        "raw_evidence",
        "tool_arguments",
        "memory_content",
    }
    ablation_by_component = {item.component: item for item in ablations.results}
    report_manifest = ROOT / "reports" / "evaluation" / "manifest.json"
    discovered_tests = unittest.defaultTestLoader.discover(str(ROOT / "tests"))

    criteria = [
        criterion(
            "two_agent_implementations",
            CustomAgentAdapter.adapter_name != CallbackFrameworkAdapter.adapter_name,
            ["tests/test_agent_adapters.py", "src/agentsec/adapters.py"],
        ),
        criterion(
            "complete_security_lifecycle",
            observed_stage_order == stage_order,
            [" -> ".join(observed_stage_order)],
        ),
        criterion(
            "four_attacks_and_benign_control",
            attack_count == 4
            and benign_count >= 1
            and deterministic.metrics.forbidden_effect_attack_success_rate == 0.0
            and deterministic.metrics.benign_task_completion_rate == 1.0,
            [
                "attack_scenarios=%d" % attack_count,
                "benign_scenarios=%d" % benign_count,
                "reports/evaluation/deterministic.json",
            ],
        ),
        criterion(
            "authority_and_provenance_contribute",
            ablation_by_component[
                AblationComponent.AUTHORITY
            ].forbidden_effect_attack_success_rate
            > 0.0
            and ablation_by_component[
                AblationComponent.PROVENANCE
            ].forbidden_effect_attack_success_rate
            > 0.0
            and ablation_by_component[
                AblationComponent.MEMORY_PROVENANCE
            ].forbidden_effect_attack_success_rate
            > 0.0,
            ["reports/evaluation/ablation.json"],
        ),
        criterion(
            "provider_neutral_ai_boundary",
            {"codex", "openai", "anthropic"}.issubset(providers)
            and hasattr(OpenAIResponsesReasoner, "analyze")
            and hasattr(AnthropicMessagesReasoner, "analyze"),
            ["configs/model-profiles.json", "tests/test_provider_adapters.py"],
        ),
        criterion(
            "codex_shadow_cannot_relax",
            codex.metrics == deterministic.metrics
            and "cannot approve" in SECURITY_SYSTEM_PROMPT
            and "cannot" in SECURITY_SYSTEM_PROMPT,
            ["configs/codex-evaluation.json", "tests/test_pipeline.py"],
        ),
        criterion(
            "allowlist_only_soc_export",
            not (export_fields & prohibited_export_fields),
            ["src/agentsec/privacy.py", "tests/test_privacy.py"],
        ),
        criterion(
            "ledger_checkpoint_tamper_detection",
            (ROOT / "src" / "agentsec" / "checkpoints.py").exists(),
            ["tests/test_abom_graph_checkpoint.py"],
        ),
        criterion(
            "all_required_baselines_and_ablations",
            len(EvaluationMode) == 8
            and set(ablation_by_component) == set(AblationComponent)
            and len(AblationComponent) == 8,
            ["reports/evaluation/manifest.json"],
        ),
        criterion(
            "development_and_holdout_records",
            set(deterministic.split_metrics) == {"development", "holdout"}
            and report_manifest.exists(),
            ["reports/evaluation/manifest.json"],
        ),
        criterion(
            "clean_install_demo_gate",
            (ROOT / "tools" / "clean_room_verify.sh").exists()
            and (ROOT / "requirements.lock").exists(),
            ["tools/clean_room_verify.sh", "requirements.lock"],
        ),
        criterion(
            "limitations_and_non_claims",
            (ROOT / "docs" / "limitations.md").exists(),
            ["docs/limitations.md"],
        ),
    ]
    all_passed = all(bool(item["passed"]) for item in criteria)
    payload = {
        "schema_version": "1.0.0",
        "scope": "research-poc",
        "dataset_version": runner.dataset_version,
        "discovered_tests": discovered_tests.countTestCases(),
        "criteria": criteria,
        "all_passed": all_passed,
        "production_ready": False,
        "production_deferred": [
            "live provider qualification",
            "durable multi-tenant services",
            "KMS/HSM-backed identity and signing",
            "container and AWS deployment by an approved operator",
            "external security and privacy review",
        ],
    }
    output = ROOT / "reports" / "release-audit.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("research PoC release audit: %s" % ("passed" if all_passed else "failed"))
    print(str(output.relative_to(ROOT)))
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
