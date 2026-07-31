"""Deterministic evidence validation, confidence calibration, and human gates."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from .contracts import (
    AnalystClaim,
    AnalystClaimOperator,
    AnalystEvidenceItem,
    AnalystRole,
    AnalystRoleResult,
    AnalystRoleStatus,
    ClaimValidationResult,
    ClaimValidationStatus,
    DecisionAction,
    JudgmentContradiction,
    JudgmentValidationIssue,
    JudgmentValidationReport,
    JudgmentValidationStatus,
    MandatoryEvidenceCheck,
    ModelVerdict,
    ModelVerdictValidation,
    SecurityAlert,
    TriageAssessment,
    utc_now,
)
from .crypto import canonical_bytes


JUDGMENT_VALIDATION_POLICY_VERSION = "evidence-judgment-2026-07-24.1"

ACTION_RANK = {
    DecisionAction.ALLOW: 0,
    DecisionAction.ALLOW_WITH_OBLIGATIONS: 1,
    DecisionAction.REQUIRE_APPROVAL: 2,
    DecisionAction.DENY: 3,
}

MANDATORY_EVIDENCE_KINDS: Mapping[AnalystRole, Tuple[str, ...]] = {
    AnalystRole.TRIAGE: ("detector", "triage"),
    AnalystRole.INVESTIGATION: ("detector", "enrichment"),
    AnalystRole.JUDGE: ("detector", "judgment"),
    AnalystRole.ESCALATION: ("triage", "escalation"),
    AnalystRole.RESPONSE_ADVISOR: ("judgment", "response"),
}

INSTRUCTION_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("PROMPT_OVERRIDE_LANGUAGE", re.compile(r"\bignore\s+(?:all\s+|any\s+|the\s+)?previous\b", re.I)),
    ("SYSTEM_PROMPT_REFERENCE", re.compile(r"\bsystem\s+prompt\b", re.I)),
    ("DEVELOPER_MESSAGE_REFERENCE", re.compile(r"\bdeveloper\s+message\b", re.I)),
    ("TOOL_EXECUTION_INSTRUCTION", re.compile(r"\b(?:execute|invoke|call)\s+(?:the\s+|a\s+)?(?:tool|command)\b", re.I)),
    ("POLICY_BYPASS_LANGUAGE", re.compile(r"\b(?:bypass|override|disable)\b.{0,48}\b(?:policy|guard|control)\b", re.I)),
    ("PROMPT_CONTROL_TOKEN", re.compile(r"<\|(?:system|developer|assistant|tool)[^>]*\|>", re.I)),
)


def _texts(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [text for item in value.values() for text in _texts(item)]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [text for item in value for text in _texts(item)]
    return []


def _instruction_codes(value: Any) -> List[str]:
    found: List[str] = []
    for text in _texts(value):
        for code, pattern in INSTRUCTION_PATTERNS:
            if pattern.search(text):
                found.append(code)
    return list(dict.fromkeys(found))


def _strict_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return float(left) == float(right)
    return type(left) is type(right) and left == right


def _contains(observed: Any, expected: Any) -> bool:
    if isinstance(observed, list):
        return any(_strict_equal(item, expected) for item in observed)
    if isinstance(observed, str) and isinstance(expected, str):
        return expected in observed
    return False


class EvidenceJudgmentValidator:
    """Validates model claims against the exact evidence manifest.

    This layer is deterministic and deliberately non-executive. A report can
    require human review, but its machine action is always the existing
    deterministic decision.
    """

    policy_version = JUDGMENT_VALIDATION_POLICY_VERSION

    def validate_model_verdict(
        self,
        *,
        alert: SecurityAlert,
        triage: TriageAssessment,
        verdict: ModelVerdict,
    ) -> ModelVerdictValidation:
        from .privacy import PrivacyTransformer

        allowed = set(PrivacyTransformer().model_evidence(alert, triage).evidence_ids)
        cited = list(dict.fromkeys(verdict.evidence_ids))
        unknown = [item for item in cited if item not in allowed]
        reason_codes: List[str] = []
        critical = False
        if not cited:
            reason_codes.append("MODEL_EVIDENCE_MISSING")
            critical = True
        if unknown:
            reason_codes.append("MODEL_EVIDENCE_UNKNOWN")
            critical = True
        deterministic_action = (
            DecisionAction.DENY
            if triage.severity.value == "critical"
            else alert.recommended_action
        )
        if ACTION_RANK[verdict.action] < ACTION_RANK[deterministic_action]:
            reason_codes.append("MODEL_RELAXATION_REJECTED")
            critical = True
        injection_codes = _instruction_codes(
            {"reason_codes": verdict.reason_codes, "uncertainty": verdict.uncertainty}
        )
        if injection_codes:
            reason_codes.extend(injection_codes)
            critical = True

        calibrated = 0.55
        if len(cited) >= 1:
            calibrated += 0.10
        if len(cited) >= 2:
            calibrated += 0.10
        if len(cited) >= 3:
            calibrated += 0.10
        if alert.confidence >= 0.95:
            calibrated += 0.04
        calibrated = round(min(calibrated, 0.99), 4)
        overconfident = verdict.confidence > calibrated + 0.01
        if overconfident:
            reason_codes.append("MODEL_CONFIDENCE_EXCEEDS_EVIDENCE")

        status = "rejected" if critical else "human_review" if overconfident else "valid"
        human_gate = status != "valid"
        if not reason_codes:
            reason_codes.append("MODEL_VERDICT_EVIDENCE_VALID")
        return ModelVerdictValidation(
            policy_version=self.policy_version,
            status=status,
            cited_evidence_ids=cited,
            unknown_evidence_ids=unknown,
            claimed_confidence=verdict.confidence,
            calibrated_confidence=calibrated,
            human_gate_required=human_gate,
            eligible_to_tighten=status == "valid",
            reason_codes=list(dict.fromkeys(reason_codes)),
        )

    @staticmethod
    def _model_authored_payload(result: AnalystRoleResult) -> Dict[str, Any]:
        return {
            "summary": result.summary,
            "hypothesis": result.hypothesis,
            "escalation_advice": result.escalation_advice,
            "response_advice": result.response_advice,
            "uncertainties": result.uncertainties,
            "abstention_reason": result.abstention_reason,
            "claims": [claim.model_dump(mode="python") for claim in result.claims],
            "alternatives": [
                {"title": item.title, "rationale": item.rationale}
                for item in result.alternatives
            ],
        }

    @staticmethod
    def _cited_ids(result: AnalystRoleResult) -> List[str]:
        # Mandatory policy is satisfied only by the evidence the role cites for
        # its result or structured claims. Evidence mentioned solely in an
        # alternative cannot be used to make the primary conclusion complete.
        return list(
            dict.fromkeys(
                result.evidence_ids
                + [evidence for claim in result.claims for evidence in claim.evidence_ids]
            )
        )

    @staticmethod
    def _calibrated_confidence(
        claim: AnalystClaim,
        evidence: Sequence[AnalystEvidenceItem],
        *,
        verified: bool,
    ) -> float:
        if not verified:
            return 0.0
        sources = {item.source for item in evidence}
        score = 0.55
        if len(evidence) >= 2:
            score += 0.10
        if len(sources) >= 2:
            score += 0.10
        if any(
            item.kind == "ingestion" and item.facts.get("ledger_verified") is True
            for item in evidence
        ):
            score += 0.10
        status_values = [item.facts.get("status") for item in evidence if "status" in item.facts]
        if status_values and all(value == "complete" for value in status_values):
            score += 0.05
        return round(min(score, 0.90), 4)

    def _validate_claim(
        self,
        role: AnalystRole,
        claim: AnalystClaim,
        claimed_confidence: float,
        manifest: Mapping[str, AnalystEvidenceItem],
    ) -> ClaimValidationResult:
        cited = [manifest[item] for item in claim.evidence_ids if item in manifest]
        missing = [item for item in claim.evidence_ids if item not in manifest]
        reason_codes: List[str] = []
        matched: List[str] = []
        conflicting: List[str] = []

        instruction_codes = _instruction_codes(
            {
                "statement": claim.statement,
                "subject": claim.subject,
                "fact_key": claim.fact_key,
                "expected_value": claim.expected_value,
            }
        )
        untrusted_evidence_ids = [
            item.evidence_id for item in cited if _instruction_codes(item.facts)
        ]
        if instruction_codes:
            status = ClaimValidationStatus.REJECTED
            reason_codes.extend(instruction_codes)
        elif untrusted_evidence_ids:
            status = ClaimValidationStatus.REJECTED
            reason_codes.append("UNTRUSTED_INSTRUCTION_EVIDENCE")
            conflicting.extend(untrusted_evidence_ids)
        elif missing:
            status = ClaimValidationStatus.UNSUPPORTED
            reason_codes.append("UNKNOWN_EVIDENCE_CITATION")
        else:
            for item in cited:
                if claim.fact_key not in item.facts:
                    continue
                observed = item.facts[claim.fact_key]
                supports = (
                    claim.operator == AnalystClaimOperator.EXISTS
                    or claim.operator == AnalystClaimOperator.EQUALS
                    and _strict_equal(observed, claim.expected_value)
                    or claim.operator == AnalystClaimOperator.CONTAINS
                    and _contains(observed, claim.expected_value)
                )
                if supports:
                    matched.append(item.evidence_id)
                else:
                    conflicting.append(item.evidence_id)
            if matched and not conflicting:
                status = ClaimValidationStatus.VERIFIED
                reason_codes.append("CLAIM_MATCHED_EVIDENCE")
            elif matched and conflicting:
                status = ClaimValidationStatus.CONTRADICTED
                reason_codes.append("EVIDENCE_VALUES_CONFLICT")
            elif conflicting:
                status = ClaimValidationStatus.CONTRADICTED
                reason_codes.append("CLAIM_CONTRADICTS_EVIDENCE")
            else:
                status = ClaimValidationStatus.UNSUPPORTED
                reason_codes.append("CLAIM_FACT_NOT_PRESENT")

        calibrated = self._calibrated_confidence(
            claim,
            [item for item in cited if item.evidence_id in matched],
            verified=status == ClaimValidationStatus.VERIFIED,
        )
        if claimed_confidence > calibrated + 0.05:
            reason_codes.append("CONFIDENCE_EXCEEDS_EVIDENCE")
        return ClaimValidationResult(
            claim_id=claim.claim_id,
            role=role,
            status=status,
            evidence_ids=claim.evidence_ids,
            matched_evidence_ids=matched,
            conflicting_evidence_ids=conflicting,
            independent_sources=len(
                {
                    item.source
                    for item in cited
                    if item.evidence_id in matched
                }
            ),
            claimed_confidence=claimed_confidence,
            calibrated_confidence=calibrated,
            reason_codes=list(dict.fromkeys(reason_codes)),
        )

    @staticmethod
    def _contradictions(
        roles: Sequence[AnalystRoleResult],
    ) -> List[JudgmentContradiction]:
        grouped: Dict[Tuple[str, str], List[AnalystClaim]] = {}
        for result in roles:
            for claim in result.claims:
                # Only equality assertions are mutually exclusive. Different
                # CONTAINS assertions may both be true for one list or string,
                # and EXISTS is compatible with either value assertion.
                if claim.operator != AnalystClaimOperator.EQUALS:
                    continue
                grouped.setdefault((claim.subject, claim.fact_key), []).append(claim)
        contradictions: List[JudgmentContradiction] = []
        for (subject, fact_key), claims in grouped.items():
            for left_index, left in enumerate(claims):
                left_value = json.dumps(left.expected_value, sort_keys=True)
                for right in claims[left_index + 1 :]:
                    if left_value == json.dumps(right.expected_value, sort_keys=True):
                        continue
                    contradictions.append(
                        JudgmentContradiction(
                            left_claim_id=left.claim_id,
                            right_claim_id=right.claim_id,
                            subject=subject,
                            fact_key=fact_key,
                            evidence_ids=list(
                                dict.fromkeys(left.evidence_ids + right.evidence_ids)
                            )[:16],
                            reason_code="CROSS_ROLE_CLAIM_CONTRADICTION",
                        )
                    )
        return contradictions[:32]

    @staticmethod
    def _report_digest(report: JudgmentValidationReport) -> str:
        payload = report.model_dump(mode="json", exclude={"report_sha256"})
        return hashlib.sha256(canonical_bytes(payload)).hexdigest()

    def validate(
        self,
        *,
        manifest: Sequence[AnalystEvidenceItem],
        role_results: Sequence[AnalystRoleResult],
        deterministic_action: DecisionAction,
        priority: str,
    ) -> JudgmentValidationReport:
        if [item.role for item in role_results] != list(AnalystRole):
            raise ValueError("judgment validation requires the complete governed role order")
        index = {item.evidence_id: item for item in manifest}
        if len(index) != len(manifest):
            raise ValueError("judgment evidence manifest contains duplicate IDs")

        issues: List[JudgmentValidationIssue] = []
        mandatory: List[MandatoryEvidenceCheck] = []
        claim_results: List[ClaimValidationResult] = []

        evidence_instruction_ids = [
            item.evidence_id for item in manifest if _instruction_codes(item.facts)
        ]
        if evidence_instruction_ids:
            issues.append(
                JudgmentValidationIssue(
                    code="UNTRUSTED_INSTRUCTION_EVIDENCE",
                    severity="critical",
                    message="Instruction-like evidence was isolated as data and requires human review.",
                    evidence_ids=evidence_instruction_ids[:16],
                )
            )

        for result in role_results:
            required = list(MANDATORY_EVIDENCE_KINDS[result.role])
            cited_items = [index[item] for item in self._cited_ids(result) if item in index]
            cited_kinds = sorted({item.kind for item in cited_items})
            missing_kinds = [item for item in required if item not in cited_kinds]
            passed = result.status == AnalystRoleStatus.COMPLETED and not missing_kinds
            mandatory.append(
                MandatoryEvidenceCheck(
                    role=result.role,
                    required_kinds=required,
                    cited_kinds=cited_kinds,
                    missing_kinds=missing_kinds,
                    passed=passed,
                )
            )
            if not passed:
                issues.append(
                    JudgmentValidationIssue(
                        code="MANDATORY_EVIDENCE_MISSING",
                        severity="error",
                        role=result.role,
                        message="The role did not cite every required evidence kind.",
                        evidence_ids=[item.evidence_id for item in cited_items[:16]],
                    )
                )
            if result.status == AnalystRoleStatus.COMPLETED and not result.claims:
                issues.append(
                    JudgmentValidationIssue(
                        code="STRUCTURED_CLAIM_MISSING",
                        severity="error",
                        role=result.role,
                        message="A completed role provided no machine-checkable claim.",
                        evidence_ids=result.evidence_ids[:16],
                    )
                )
            for code in _instruction_codes(self._model_authored_payload(result)):
                issues.append(
                    JudgmentValidationIssue(
                        code=code,
                        severity="critical",
                        role=result.role,
                        message="Instruction-like model output was rejected from judgment authority.",
                        evidence_ids=result.evidence_ids[:16],
                    )
                )
            for claim in result.claims:
                claim_results.append(
                    self._validate_claim(
                        result.role,
                        claim,
                        result.confidence or 0.0,
                        index,
                    )
                )

        contradictions = self._contradictions(role_results)
        contradicted_ids = {
            claim_id
            for item in contradictions
            for claim_id in (item.left_claim_id, item.right_claim_id)
        }
        claim_results = [
            item.model_copy(
                update={
                    "status": ClaimValidationStatus.CONTRADICTED,
                    "calibrated_confidence": 0.0,
                    "reason_codes": list(
                        dict.fromkeys(
                            item.reason_codes + ["CROSS_ROLE_CLAIM_CONTRADICTION"]
                        )
                    ),
                }
            )
            if item.claim_id in contradicted_ids
            else item
            for item in claim_results
        ]
        if contradictions:
            issues.append(
                JudgmentValidationIssue(
                    code="CROSS_ROLE_CLAIM_CONTRADICTION",
                    severity="critical",
                    message="Analyst roles asserted incompatible values for the same fact.",
                    evidence_ids=list(
                        dict.fromkeys(
                            evidence
                            for item in contradictions
                            for evidence in item.evidence_ids
                        )
                    )[:16],
                )
            )

        judge = next(item for item in role_results if item.role == AnalystRole.JUDGE)
        if (
            judge.recommended_action is not None
            and judge.recommended_action != deterministic_action
        ):
            issues.append(
                JudgmentValidationIssue(
                    code=(
                        "MODEL_RELAXATION_REJECTED"
                        if ACTION_RANK[judge.recommended_action]
                        < ACTION_RANK[deterministic_action]
                        else "MODEL_TIGHTENING_REQUIRES_HUMAN"
                    ),
                    severity="critical" if ACTION_RANK[judge.recommended_action] < ACTION_RANK[deterministic_action] else "warning",
                    role=AnalystRole.JUDGE,
                    message="A model action difference cannot change deterministic enforcement without human review.",
                    evidence_ids=judge.evidence_ids[:16],
                )
            )
        if priority in {"P0", "P1"}:
            issues.append(
                JudgmentValidationIssue(
                    code="HIGH_RISK_HUMAN_GATE",
                    severity="warning",
                    message="High-risk findings require explicit human judgment.",
                )
            )

        for item in claim_results:
            if "CONFIDENCE_EXCEEDS_EVIDENCE" in item.reason_codes:
                issues.append(
                    JudgmentValidationIssue(
                        code="CONFIDENCE_EXCEEDS_EVIDENCE",
                        severity="warning",
                        role=item.role,
                        message="Model confidence exceeded the deterministic evidence ceiling.",
                        evidence_ids=item.evidence_ids,
                    )
                )

        accepted = sum(
            item.status in {ClaimValidationStatus.VERIFIED, ClaimValidationStatus.PARTIAL}
            for item in claim_results
        )
        rejected = len(claim_results) - accepted
        critical = any(item.severity == "critical" for item in issues)
        human_gate = bool(issues) or rejected > 0
        status = (
            JudgmentValidationStatus.REJECTED
            if critical
            else JudgmentValidationStatus.HUMAN_REVIEW
            if human_gate
            else JudgmentValidationStatus.PASSED
        )
        calibrated_values = [
            item.calibrated_confidence
            for item in claim_results
            if item.status in {ClaimValidationStatus.VERIFIED, ClaimValidationStatus.PARTIAL}
        ]
        calibrated = (
            round(sum(calibrated_values) / len(calibrated_values), 4)
            if calibrated_values
            else 0.0
        )
        reason_codes = list(dict.fromkeys(item.code for item in issues))
        unsigned = JudgmentValidationReport(
            policy_version=self.policy_version,
            status=status,
            deterministic_action=deterministic_action,
            machine_action=deterministic_action,
            human_gate_required=human_gate,
            human_gate_reasons=reason_codes,
            mandatory_evidence=mandatory,
            claim_results=claim_results,
            contradictions=contradictions,
            issues=issues,
            accepted_claims=accepted,
            rejected_claims=rejected,
            calibrated_confidence=calibrated,
            validated_at=utc_now(),
            report_sha256="0" * 64,
        )
        return unsigned.model_copy(
            update={"report_sha256": self._report_digest(unsigned)}
        )

    def verify(self, report: JudgmentValidationReport) -> None:
        if self._report_digest(report) != report.report_sha256:
            raise ValueError("judgment validation report integrity verification failed")
