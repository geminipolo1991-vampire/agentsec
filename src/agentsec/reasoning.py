"""Provider-neutral semantic security-analysis interface."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Protocol

from .contracts import ModelVerdict, SecurityAlert, TriageAssessment


class SecurityReasoner(Protocol):
    """Implemented by Codex now and later by OpenAI/Anthropic API adapters."""

    provider: str
    model_id: str

    def analyze(self, alert: SecurityAlert, triage: TriageAssessment) -> ModelVerdict:
        """Return validated structured output without causing side effects."""
        ...


class ModelUnavailableError(RuntimeError):
    """Normalized provider failure that never disables deterministic enforcement."""


class RecordedCodexReasoner:
    """Replays structured verdicts reviewed by Codex in this development session.

    This is deliberately named "recorded": it proves the provider contract and
    decision-combiner behavior without claiming that an automated test made a live
    model request. A live adapter can implement ``SecurityReasoner`` unchanged.
    """

    def __init__(self, recording: Dict[str, Any]) -> None:
        self.provider = str(recording["provider"])
        self.model_id = str(recording["model_id"])
        self.recording_id = str(recording["recording_id"])
        verdicts = recording.get("verdicts")
        if not isinstance(verdicts, dict):
            raise ValueError("recording verdicts must be an object")
        self._verdicts: Dict[str, Dict[str, Any]] = verdicts

    @classmethod
    def from_path(cls, path: Path) -> "RecordedCodexReasoner":
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        if not isinstance(raw, dict):
            raise ValueError("Codex recording must be a JSON object")
        return cls(raw)

    def analyze(self, alert: SecurityAlert, triage: TriageAssessment) -> ModelVerdict:
        raw = self._verdicts.get(alert.alert_type)
        if raw is None:
            raise ModelUnavailableError(
                "no recorded Codex verdict for alert type %s" % alert.alert_type
            )
        return ModelVerdict(
            provider=self.provider,
            model_id=self.model_id,
            action=raw["action"],
            confidence=raw["confidence"],
            evidence_ids=list(alert.evidence),
            reason_codes=list(raw["reason_codes"]),
            uncertainty=raw.get("uncertainty"),
        )
