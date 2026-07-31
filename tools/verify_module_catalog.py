#!/usr/bin/env python3
"""Validate progress evidence for the approved 24-module product goal."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "configs" / "module-catalog.json"
EXPECTED_MODULES = [
    "AI telemetry collection",
    "Ingestion gateway",
    "Canonical AI-security data model",
    "Evidence ledger and storage",
    "Search and threat hunting",
    "Agent application and model inventory",
    "AI security graph and attack paths",
    "AI security posture management",
    "Detection and rule engine",
    "Detection content management",
    "Behavioral analytics and risk engine",
    "Finding correlation and incident creation",
    "Enrichment engine",
    "AI Analyst Engine",
    "Model gateway and AI governance",
    "Evidence validator and judgment engine",
    "Incident and case management",
    "Escalation and notification",
    "Response and playbook automation",
    "Analyst user interface",
    "External API and SIEM integration",
    "Simulation and validation lab",
    "Evaluation and continuous improvement",
    "Administration platform security and audit",
]
EXPECTED_IDS = ["M%02d" % value for value in range(1, 25)]
ALLOWED_STATUSES = {"not_started", "in_progress", "implemented", "verified"}


def _load() -> Dict[str, Any]:
    payload = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("module catalog must be an object")
    return payload


def _safe_repository_file(relative: object) -> bool:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        return False
    resolved = (ROOT / relative).resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return False
    return resolved.is_file()


def validate(*, require_complete: bool) -> List[str]:
    errors: List[str] = []
    try:
        payload = _load()
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return ["cannot load module catalog: %s" % exc]
    if payload.get("schema_version") != "2.0.0":
        errors.append("schema_version must be 2.0.0")
    if payload.get("scope") != "Approved AgentSec 24-module full product":
        errors.append("scope must preserve the approved 24-module full product")
    modules = payload.get("modules")
    if not isinstance(modules, list):
        return errors + ["modules must be a list"]
    identifiers = [item.get("id") for item in modules if isinstance(item, dict)]
    names = [item.get("name") for item in modules if isinstance(item, dict)]
    if identifiers != EXPECTED_IDS:
        errors.append("module IDs must be ordered exactly M01 through M24")
    if names != EXPECTED_MODULES:
        errors.append("module names/order do not match the approved product plan")

    for index, item in enumerate(modules, start=1):
        if not isinstance(item, dict):
            errors.append("module %d must be an object" % index)
            continue
        label = str(item.get("id", "module %d" % index))
        status = item.get("status")
        if status not in ALLOWED_STATUSES:
            errors.append("%s has an invalid status" % label)
            continue
        if not isinstance(item.get("remaining"), str) or not item["remaining"].strip():
            errors.append("%s must state remaining work" % label)
        implementation = item.get("implementation")
        verification = item.get("verification")
        if not isinstance(implementation, list) or not isinstance(verification, list):
            errors.append("%s implementation and verification must be lists" % label)
            continue
        if status in {"implemented", "verified"}:
            if not implementation or not verification:
                errors.append("%s needs implementation and verification evidence" % label)
            for relative in implementation + verification:
                if not _safe_repository_file(relative):
                    errors.append("%s evidence does not exist or escapes the repository: %s" % (label, relative))
            acceptance = item.get("acceptance_record")
            if not _safe_repository_file(acceptance):
                errors.append("%s needs an existing acceptance record" % label)
        if require_complete and status != "verified":
            errors.append("%s is not verified" % label)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="fail unless all 24 approved product modules are verified",
    )
    args = parser.parse_args()
    errors = validate(require_complete=args.require_complete)
    if errors:
        for error in errors:
            print("ERROR: %s" % error)
        return 1
    payload = _load()
    verified = sum(item["status"] == "verified" for item in payload["modules"])
    print("module catalog valid: %d/24 approved product modules verified" % verified)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
