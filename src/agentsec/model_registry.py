"""Configuration-only provider profiles and explicit fallback routing."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import Field

from .contracts import AiMode, StrictModel
from .reasoning import SecurityReasoner


class ModelProfile(StrictModel):
    profile_id: str
    provider: str
    enabled: bool = False
    model_id_env: Optional[str] = None
    api_key_env: Optional[str] = None
    endpoint: Optional[str] = None
    allowed_modes: List[AiMode] = Field(default_factory=lambda: [AiMode.SHADOW])
    fallback_profile_id: Optional[str] = None
    prompt_version: str = "semantic-detector-v1"


class ModelRegistry(StrictModel):
    schema_version: str = "1.0.0"
    profiles: List[ModelProfile]

    @classmethod
    def from_path(cls, path: Path) -> "ModelRegistry":
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls.model_validate(raw)

    def get(self, profile_id: str) -> ModelProfile:
        matches = [profile for profile in self.profiles if profile.profile_id == profile_id]
        if len(matches) != 1:
            raise KeyError(profile_id)
        return matches[0]

    def resolve_environment(self, profile_id: str) -> Dict[str, str]:
        profile = self.get(profile_id)
        values: Dict[str, str] = {}
        if profile.model_id_env:
            value = os.environ.get(profile.model_id_env)
            if not value:
                raise ValueError("missing required model ID environment variable")
            values["model_id"] = value
        if profile.api_key_env:
            value = os.environ.get(profile.api_key_env)
            if not value:
                raise ValueError("missing required API key environment variable")
            values["api_key"] = value
        return values


class ReasonerRouter:
    def __init__(self, reasoners: Dict[str, SecurityReasoner], registry: ModelRegistry) -> None:
        self.reasoners = reasoners
        self.registry = registry

    def select(self, profile_id: str, mode: AiMode) -> SecurityReasoner:
        visited = set()
        current = profile_id
        while current is not None:
            if current in visited:
                raise ValueError("model fallback cycle detected")
            visited.add(current)
            profile = self.registry.get(current)
            if profile.enabled and mode in profile.allowed_modes and current in self.reasoners:
                return self.reasoners[current]
            current = profile.fallback_profile_id
        raise KeyError("no enabled reasoner profile for requested mode")

