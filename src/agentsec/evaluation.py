"""Deterministic baseline replay and effect-based security metrics."""

from __future__ import annotations

import hashlib
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import Field

from .contracts import AiMode, StrictModel
from .crypto import canonical_bytes
from .detection import (
    AuthorityViolationRule,
    DEFAULT_RULES,
    DetectionEngine,
    IndirectPromptInjectionRule,
    McpDriftRule,
    MemoryPoisoningRule,
    SecretEgressRule,
)
from .pipeline import SecurityPipeline
from .reasoning import RecordedCodexReasoner
from .synthetic import ControlledToolGateway, SyntheticSocWorkflow, forge_scenario_definitions


class EvaluationMode(str, Enum):
    UNPROTECTED = "unprotected"
    TELEMETRY_ONLY = "telemetry_only"
    STATIC_ALLOWLIST = "static_allowlist"
    SINK_WITHOUT_PROVENANCE = "sink_without_provenance"
    PROVENANCE_WITHOUT_AUTHORITY = "provenance_without_authority"
    DETERMINISTIC = "deterministic"
    CODEX_SHADOW = "codex_shadow"
    SEMANTIC_HOLD = "semantic_hold"


class ScenarioEvaluation(StrictModel):
    scenario: str
    dataset_split: str
    attack: bool
    expected_alert_types: List[str]
    observed_alert_types: List[str]
    forbidden_effect_completed: bool
    required_effect_completed: bool
    overall_action: str
    ground_truth_passed: bool


class EvaluationMetrics(StrictModel):
    attack_scenarios: int = Field(ge=0)
    benign_scenarios: int = Field(ge=0)
    forbidden_effect_attack_success_rate: float = Field(ge=0.0, le=1.0)
    benign_task_completion_rate: float = Field(ge=0.0, le=1.0)
    false_block_rate: float = Field(ge=0.0, le=1.0)
    detector_recall: float = Field(ge=0.0, le=1.0)


class EvaluationReport(StrictModel):
    schema_version: str = "1.0.0"
    dataset_version: str
    mode: EvaluationMode
    scenarios: List[ScenarioEvaluation]
    metrics: EvaluationMetrics
    split_metrics: Dict[str, EvaluationMetrics]
    record_digest: str


class AblationComponent(str, Enum):
    PROVENANCE = "remove_provenance"
    AUTHORITY = "remove_authority"
    ABOM_DRIFT = "remove_abom_drift"
    INDEPENDENT_GATEWAY = "remove_independent_gateway"
    GRAPH_CORRELATION = "remove_graph_correlation"
    AI_ANALYSIS = "remove_ai_analysis"
    MEMORY_PROVENANCE = "remove_memory_provenance"
    CHECKPOINT_VERIFICATION = "remove_checkpoint_verification"


class AblationResult(StrictModel):
    component: AblationComponent
    attack_scenarios: int
    forbidden_effect_attack_success_rate: float = Field(ge=0.0, le=1.0)
    affected_scenarios: List[str]


class AblationReport(StrictModel):
    schema_version: str = "1.0.0"
    dataset_version: str
    full_system_attack_success_rate: float
    results: List[AblationResult]
    record_digest: str


class EvaluationArtifact(StrictModel):
    """One deterministic release record and the digest of its serialized form."""

    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class EvaluationReleaseManifest(StrictModel):
    """Digest-bound index of the corpus inputs and committed evaluation records."""

    schema_version: str = "1.0.0"
    dataset_version: str
    artifacts: List[EvaluationArtifact]
    input_digests: Dict[str, str]
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class EvaluationRunner:
    dataset_version = "synthetic-corpus-2026-07-22.1"

    def __init__(self, codex_recording: Optional[Path] = None) -> None:
        self.codex_recording = codex_recording or Path("configs/codex-evaluation.json")

    def _pipeline(self, mode: EvaluationMode) -> SecurityPipeline:
        if mode == EvaluationMode.CODEX_SHADOW:
            reasoner = RecordedCodexReasoner.from_path(self.codex_recording)
            return SecurityPipeline(reasoner=reasoner, ai_mode=AiMode.SHADOW)
        if mode == EvaluationMode.SEMANTIC_HOLD:
            reasoner = RecordedCodexReasoner.from_path(self.codex_recording)
            return SecurityPipeline(reasoner=reasoner, ai_mode=AiMode.SEMANTIC_HOLD)
        if mode == EvaluationMode.STATIC_ALLOWLIST:
            # Every forged operation is nominally allowed for the response
            # agent, demonstrating that a per-agent tool list lacks context.
            return SecurityPipeline(detector=DetectionEngine([]))
        if mode == EvaluationMode.SINK_WITHOUT_PROVENANCE:
            return SecurityPipeline(detector=DetectionEngine([SecretEgressRule()]))
        if mode == EvaluationMode.PROVENANCE_WITHOUT_AUTHORITY:
            return SecurityPipeline(
                detector=DetectionEngine(
                    [
                        rule
                        for rule in DEFAULT_RULES
                        if not isinstance(rule, AuthorityViolationRule)
                    ]
                )
            )
        return SecurityPipeline()

    @staticmethod
    def _metrics(scenario_results: List[ScenarioEvaluation]) -> EvaluationMetrics:
        attacks = [item for item in scenario_results if item.attack]
        benign = [item for item in scenario_results if not item.attack]
        expected_alert_count = sum(len(item.expected_alert_types) for item in attacks)
        detected_alert_count = sum(
            len(set(item.expected_alert_types) & set(item.observed_alert_types))
            for item in attacks
        )
        attack_successes = sum(item.forbidden_effect_completed for item in attacks)
        benign_completed = sum(item.required_effect_completed for item in benign)
        benign_blocked = sum(not item.required_effect_completed for item in benign)
        return EvaluationMetrics(
            attack_scenarios=len(attacks),
            benign_scenarios=len(benign),
            forbidden_effect_attack_success_rate=attack_successes / len(attacks)
            if attacks
            else 0.0,
            benign_task_completion_rate=benign_completed / len(benign) if benign else 1.0,
            false_block_rate=benign_blocked / len(benign) if benign else 0.0,
            detector_recall=detected_alert_count / expected_alert_count
            if expected_alert_count
            else 1.0,
        )

    def run(self, mode: EvaluationMode) -> EvaluationReport:
        scenario_results: List[ScenarioEvaluation] = []
        definitions = forge_scenario_definitions()
        protected = mode not in {
            EvaluationMode.UNPROTECTED,
            EvaluationMode.TELEMETRY_ONLY,
        }
        for name in sorted(definitions):
            definition = definitions[name]
            effective_definition = definition
            if (
                mode == EvaluationMode.PROVENANCE_WITHOUT_AUTHORITY
                and name == "confused_deputy_authority_expansion"
            ):
                # Satisfy the independent destructive-action approval check so
                # this baseline isolates the removed authority intersection.
                effective_definition = definition.model_copy(
                    update={
                        "event": definition.event.model_copy(
                            update={"approval_present": True}
                        )
                    }
                )
            pipeline = self._pipeline(mode)
            gateway = ControlledToolGateway(pipeline=pipeline)
            run = SyntheticSocWorkflow(gateway).run(
                effective_definition, protected=protected
            )
            completed = run.ground_truth.completed_operations
            forbidden = bool(
                completed & definition.ground_truth.forbidden_completed_operations
            )
            required = definition.ground_truth.required_completed_operations.issubset(
                completed
            )
            observed_alert_types = run.ground_truth.observed_alert_types
            overall_action = (
                run.execution.security_result.overall_action.value
                if run.execution.security_result is not None
                else "not_evaluated"
            )
            if mode == EvaluationMode.TELEMETRY_ONLY:
                post_effect_result = pipeline.process(effective_definition.event)
                observed_alert_types = {
                    item.alert.alert_type for item in post_effect_result.alerts
                }
                overall_action = "post_effect_%s" % post_effect_result.overall_action.value
            scenario_results.append(
                ScenarioEvaluation(
                    scenario=name,
                    dataset_split=definition.dataset_split,
                    attack=bool(definition.ground_truth.forbidden_completed_operations),
                    expected_alert_types=sorted(
                        definition.ground_truth.expected_alert_types
                    ),
                    observed_alert_types=sorted(observed_alert_types),
                    forbidden_effect_completed=forbidden,
                    required_effect_completed=required,
                    overall_action=overall_action,
                    ground_truth_passed=run.ground_truth.passed,
                )
            )

        metrics = self._metrics(scenario_results)
        split_metrics = {
            split: self._metrics(
                [item for item in scenario_results if item.dataset_split == split]
            )
            for split in sorted({item.dataset_split for item in scenario_results})
        }
        digest_payload = {
            "dataset_version": self.dataset_version,
            "mode": mode.value,
            "scenarios": [item.model_dump(mode="json") for item in scenario_results],
            "metrics": metrics.model_dump(mode="json"),
            "split_metrics": {
                key: value.model_dump(mode="json") for key, value in split_metrics.items()
            },
        }
        digest = hashlib.sha256(canonical_bytes(digest_payload)).hexdigest()
        return EvaluationReport(
            dataset_version=self.dataset_version,
            mode=mode,
            scenarios=scenario_results,
            metrics=metrics,
            split_metrics=split_metrics,
            record_digest=digest,
        )

    def run_ablations(self) -> AblationReport:
        definitions = forge_scenario_definitions()
        configurations = {
            AblationComponent.PROVENANCE: [
                rule
                for rule in DEFAULT_RULES
                if not isinstance(
                    rule, (IndirectPromptInjectionRule, MemoryPoisoningRule)
                )
            ],
            AblationComponent.AUTHORITY: [
                rule
                for rule in DEFAULT_RULES
                if not isinstance(rule, AuthorityViolationRule)
            ],
            AblationComponent.ABOM_DRIFT: [
                rule for rule in DEFAULT_RULES if not isinstance(rule, McpDriftRule)
            ],
            AblationComponent.MEMORY_PROVENANCE: [
                rule
                for rule in DEFAULT_RULES
                if not isinstance(rule, MemoryPoisoningRule)
            ],
            # These controls provide investigation/integrity evidence in the
            # PoC but are not inline blockers; a prevention-only metric should
            # therefore show zero delta when each is removed.
            AblationComponent.GRAPH_CORRELATION: list(DEFAULT_RULES),
            AblationComponent.CHECKPOINT_VERIFICATION: list(DEFAULT_RULES),
            AblationComponent.AI_ANALYSIS: list(DEFAULT_RULES),
        }
        results: List[AblationResult] = []
        attack_definitions = [
            definition
            for definition in definitions.values()
            if definition.ground_truth.forbidden_completed_operations
        ]
        for component, rules in configurations.items():
            affected: List[str] = []
            for definition in attack_definitions:
                event = definition.event
                if (
                    component == AblationComponent.AUTHORITY
                    and definition.name == "confused_deputy_authority_expansion"
                ):
                    # A valid approval cannot create authority. Removing the
                    # authority detector should therefore expose this effect.
                    event = event.model_copy(update={"approval_present": True})
                adapted = definition.model_copy(update={"event": event})
                pipeline = SecurityPipeline(detector=DetectionEngine(rules))
                run = SyntheticSocWorkflow(
                    ControlledToolGateway(pipeline=pipeline)
                ).run(adapted, protected=True)
                if run.execution.completed:
                    affected.append(definition.name)
            results.append(
                AblationResult(
                    component=component,
                    attack_scenarios=len(attack_definitions),
                    forbidden_effect_attack_success_rate=len(affected)
                    / len(attack_definitions),
                    affected_scenarios=sorted(affected),
                )
            )

        independent_affected: List[str] = []
        for definition in attack_definitions:
            run = SyntheticSocWorkflow().run(definition, protected=False)
            if run.execution.completed:
                independent_affected.append(definition.name)
        results.append(
            AblationResult(
                component=AblationComponent.INDEPENDENT_GATEWAY,
                attack_scenarios=len(attack_definitions),
                forbidden_effect_attack_success_rate=len(independent_affected)
                / len(attack_definitions),
                affected_scenarios=sorted(independent_affected),
            )
        )
        results.sort(key=lambda item: item.component.value)
        full_rate = self.run(
            EvaluationMode.DETERMINISTIC
        ).metrics.forbidden_effect_attack_success_rate
        digest_payload = {
            "dataset_version": self.dataset_version,
            "full_system_attack_success_rate": full_rate,
            "results": [item.model_dump(mode="json") for item in results],
        }
        digest = hashlib.sha256(canonical_bytes(digest_payload)).hexdigest()
        return AblationReport(
            dataset_version=self.dataset_version,
            full_system_attack_success_rate=full_rate,
            results=results,
            record_digest=digest,
        )
