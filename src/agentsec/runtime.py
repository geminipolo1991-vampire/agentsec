"""Fail-explicit runtime assembly from versioned profiles and environment secrets."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Mapping, Optional

from .contracts import AiMode
from .model_registry import ModelRegistry, ReasonerRouter
from .pipeline import SecurityPipeline
from .providers import AnthropicMessagesReasoner, OpenAIResponsesReasoner
from .reasoning import RecordedCodexReasoner, SecurityReasoner


def build_pipeline_from_environment(
    environment: Optional[Mapping[str, str]] = None,
) -> SecurityPipeline:
    values = environment or os.environ
    try:
        mode = AiMode(values.get("AGENTSEC_AI_MODE", AiMode.OFF.value))
    except ValueError as exc:
        raise ValueError("AGENTSEC_AI_MODE is invalid") from exc
    if mode == AiMode.OFF:
        return SecurityPipeline(ai_mode=AiMode.OFF)

    registry_path = Path(
        values.get("AGENTSEC_MODEL_REGISTRY", "configs/model-profiles.json")
    )
    recording_path = Path(
        values.get("AGENTSEC_CODEX_RECORDING", "configs/codex-evaluation.json")
    )
    selected_profile = values.get(
        "AGENTSEC_MODEL_PROFILE", "codex-recorded-shadow"
    )
    registry = ModelRegistry.from_path(registry_path)
    reasoners: Dict[str, SecurityReasoner] = {}

    for profile in registry.profiles:
        if not profile.enabled:
            continue
        if profile.provider == "codex":
            reasoners[profile.profile_id] = RecordedCodexReasoner.from_path(
                recording_path
            )
            continue
        model_id = values.get(profile.model_id_env or "", "")
        api_key = values.get(profile.api_key_env or "", "")
        if not model_id or not api_key:
            continue
        if profile.provider == "openai":
            reasoners[profile.profile_id] = OpenAIResponsesReasoner(
                api_key=api_key,
                model_id=model_id,
                endpoint=profile.endpoint
                or OpenAIResponsesReasoner.default_endpoint,
            )
        elif profile.provider == "anthropic":
            reasoners[profile.profile_id] = AnthropicMessagesReasoner(
                api_key=api_key,
                model_id=model_id,
                endpoint=profile.endpoint
                or AnthropicMessagesReasoner.default_endpoint,
            )
        else:
            raise ValueError("unsupported enabled provider: %s" % profile.provider)

    reasoner = ReasonerRouter(reasoners, registry).select(selected_profile, mode)
    return SecurityPipeline(reasoner=reasoner, ai_mode=mode)

