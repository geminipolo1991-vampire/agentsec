"""Reconcile agent self-reporting with observations outside the agent process."""

from __future__ import annotations

from typing import List, Set

from pydantic import Field

from .contracts import StrictModel
from .synthetic import EffectObservation


class SdkEffectReport(StrictModel):
    event_id: str
    operation: str
    resource: str
    phase: str


class ObservationFinding(StrictModel):
    finding_type: str
    severity: str
    event_id: str
    reason_codes: List[str]
    sdk_phases: Set[str] = Field(default_factory=set)
    gateway_phases: Set[str] = Field(default_factory=set)


class ObservationReconciler:
    def reconcile(
        self,
        event_id: str,
        sdk_reports: List[SdkEffectReport],
        gateway_observations: List[EffectObservation],
    ) -> List[ObservationFinding]:
        sdk = {item.phase for item in sdk_reports if item.event_id == event_id}
        gateway = {
            item.phase for item in gateway_observations if item.event_id == event_id
        }
        findings: List[ObservationFinding] = []
        if "completed" in gateway and "completed" not in sdk:
            findings.append(
                ObservationFinding(
                    finding_type="missing_agent_telemetry",
                    severity="high",
                    event_id=event_id,
                    reason_codes=["GATEWAY_EFFECT_WITHOUT_SDK_COMPLETION"],
                    sdk_phases=sdk,
                    gateway_phases=gateway,
                )
            )
        if "completed" in sdk and "completed" not in gateway:
            findings.append(
                ObservationFinding(
                    finding_type="contradictory_effect_telemetry",
                    severity="high",
                    event_id=event_id,
                    reason_codes=["SDK_COMPLETION_WITHOUT_GATEWAY_EFFECT"],
                    sdk_phases=sdk,
                    gateway_phases=gateway,
                )
            )
        if not gateway and sdk:
            findings.append(
                ObservationFinding(
                    finding_type="gateway_bypass_suspected",
                    severity="critical",
                    event_id=event_id,
                    reason_codes=["SDK_EFFECT_WITHOUT_GATEWAY_OBSERVATION"],
                    sdk_phases=sdk,
                    gateway_phases=gateway,
                )
            )
        return findings

