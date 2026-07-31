#!/usr/bin/env python3
"""Restricted loopback bridge from the local UI to the AgentSec service.

The default upstream is a literal loopback HTTP origin. The browser never
receives the service bearer token. An optional remote adapter retains only fixed,
allowlisted service requests. The bridge never replays the pipeline and never
invents incident evidence.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Type
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen
from uuid import uuid4


DEFAULT_PROFILE = "agentsec-deploy"
DEFAULT_REGION = "ap-northeast-1"
DEFAULT_PORT = 8765
DEFAULT_LOCAL_SERVICE_URL = "http://127.0.0.1:8080"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MAX_BODY_BYTES = 8192
MAX_UPSTREAM_BODY_BYTES = 5 * 1024 * 1024
ALLOWED_ORIGINS = {
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
}
DISPLAY_TIMEZONE = timezone(timedelta(hours=9), name="JST")
FINDING_ID_PATTERN = re.compile(r"fnd_[A-Za-z0-9]+")
ACTOR_PATTERN = re.compile(r"(?:analyst|system)://[A-Za-z0-9_.@/-]{1,109}")
TRANSITION_ACTIONS = {
    "acknowledge",
    "start_investigation",
    "mark_contained",
    "close",
}
SEARCH_REQUEST_FIELDS = {"query", "page_size", "cursor", "sort_by", "sort_order"}
AGGREGATION_REQUEST_FIELDS = {"query", "field", "limit"}
SAVED_HUNT_FIELDS = {"name", "description", "query", "sort_by", "sort_order"}
EVIDENCE_ID_PATTERN = re.compile(r"evd_[A-Za-z0-9]+")
COMPONENT_ID_PATTERN = re.compile(r"cmp_[A-Za-z0-9]+")
POSTURE_FINDING_ID_PATTERN = re.compile(r"pstf_[0-9a-f]{32}")
POSTURE_EXCEPTION_ID_PATTERN = re.compile(r"pste_[A-Za-z0-9]+")
CONTENT_ID_PATTERN = re.compile(r"drc_[A-Za-z0-9]+")
CONTENT_ACTIONS = {
    "validate", "backtest", "submit", "review", "shadow",
    "shadow-evaluate", "publish", "rollback",
}
BEHAVIOR_ENTITY_PATTERN = re.compile(
    r"(?:agent|source|tool|destination)_sha256:[0-9a-f]{32}"
)
BEHAVIOR_TUNING_FIELDS = {
    "config_id", "version", "minimum_observations", "maximum_observations",
    "rare_probability", "anomaly_threshold", "operation_weight",
    "destination_weight", "source_trust_weight", "time_weight",
    "authority_weight", "sensitive_weight", "schema_drift_weight",
    "drift_window_size", "drift_warning_rate", "drift_critical_rate",
    "retention_days",
}
CORRELATED_INCIDENT_PATTERN = re.compile(r"inc_[A-Za-z0-9]+")
CORRELATION_SUPPRESSION_PATTERN = re.compile(r"sup_[A-Za-z0-9]+")
CASE_ID_PATTERN = re.compile(r"case_[0-9a-f]{32}")
CASE_TASK_ID_PATTERN = re.compile(r"ctk_[0-9a-f]{32}")
CASE_ATTACHMENT_ID_PATTERN = re.compile(r"cat_[0-9a-f]{32}")
NOTIFICATION_ID_PATTERN = re.compile(r"ntf_[0-9a-f]{32}")
NOTIFICATION_DELIVERY_ID_PATTERN = re.compile(r"ndv_[0-9a-f]{32}")
RESPONSE_EXECUTION_ID_PATTERN = re.compile(r"rex_[0-9a-f]{32}")
RESPONSE_PLAYBOOK_ID_PATTERN = re.compile(r"playbook://[A-Za-z0-9_.@/-]+")
RESPONSE_CONNECTOR_ID_PATTERN = re.compile(r"connector://[A-Za-z0-9_.@/-]+")
RESPONSE_STEP_ID_PATTERN = re.compile(r"step://[A-Za-z0-9_.@/-]+")
SIMULATION_SCENARIO_ID_PATTERN = re.compile(r"sim_[a-z0-9_]{3,96}")
SIMULATION_RUN_ID_PATTERN = re.compile(r"simrun_[0-9a-f]{32}")
SIMULATION_VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
SIMULATION_REQUEST_ID_PATTERN = re.compile(r"req_[A-Za-z0-9]{8,64}")
SIMULATION_VARIANTS = {
    "japanese", "spanish", "unicode_confusable", "zero_width", "base64",
    "mixed_obfuscation",
}
SIMULATION_RUN_MODES = {"protected", "control", "comparison"}
RESPONSE_EXECUTION_ACTIONS = {
    "request-live",
    "approve",
    "execute",
    "request-rollback",
    "approve-rollback",
    "rollback",
}
RESPONSE_EXECUTION_ID_PATTERN = re.compile(r"rex_[0-9a-f]{32}")
CASE_ACTIONS = {
    "assign", "acknowledge", "comments", "tasks", "attachments",
    "relationships", "start", "request-review", "review", "close",
}
GRAPH_ANALYSIS_PATHS = {
    "/api/graph/reachability",
    "/api/graph/blast-radius",
    "/api/graph/attack-paths",
}

PLATFORM_REPORT_PATHS = {
    "release": REPOSITORY_ROOT / "reports" / "release-audit.json",
    "evaluation": REPOSITORY_ROOT / "reports" / "evaluation" / "manifest.json",
    "modules": REPOSITORY_ROOT / "configs" / "module-catalog.json",
}

EVALUATION_MODE_FILES = (
    "unprotected.json",
    "telemetry_only.json",
    "static_allowlist.json",
    "sink_without_provenance.json",
    "provenance_without_authority.json",
    "deterministic.json",
    "codex_shadow.json",
    "semantic_hold.json",
)
EVALUATION_RECORD_FILES = frozenset(
    (
        *EVALUATION_MODE_FILES,
        "ablation.json",
        "continuous-baseline.json",
        "continuous.json",
    )
)


PRESETS: Dict[str, Dict[str, Any]] = {
    "indirect_injection_secret_egress": {
        "label": "Prompt injection + secret egress",
        "operation": "external.send",
        "resource": "secret://honeytoken/soc-api",
        "destination": "https://receiver.invalid/collect",
        "source_type": "document",
        "source_id": "document://external/live-poc",
        "source_trust": "external-untrusted",
        "data_classes": ["secret"],
        "authority_operations": ["external.send"],
        "indicators": ["indirect_prompt_injection"],
        "tool_name": "diagnostic_upload",
    },
    "persistent_memory_poisoning": {
        "label": "Persistent memory poisoning",
        "operation": "external.send",
        "resource": "ticket://internal/live-poc",
        "destination": "https://receiver.invalid/memory",
        "source_type": "memory",
        "source_id": "memory://prior-session/live-poc",
        "source_trust": "suspected-adversarial",
        "data_classes": ["internal"],
        "authority_operations": ["external.send"],
        "indicators": ["memory_poisoning"],
    },
    "confused_deputy_authority_expansion": {
        "label": "Authority expansion + destructive action",
        "operation": "host.isolate",
        "resource": "asset://host/poc-target",
        "source_type": "agent",
        "source_id": "agent://low-privilege-triage",
        "source_trust": "internal-data",
        "authority_operations": ["asset.read"],
        "indicators": ["delegation_authority_expansion"],
    },
    "mcp_schema_drift": {
        "label": "MCP tool contract drift",
        "operation": "external.upload",
        "resource": "diagnostic://bundle/live-poc",
        "destination": "https://new-destination.invalid/upload",
        "source_type": "tool",
        "source_id": "mcp://diagnostic-server",
        "source_trust": "unknown",
        "authority_operations": ["external.upload"],
        "tool_name": "upload_diagnostics",
        "declared_tool_schema_digest": "sha256:approved-v1",
        "observed_tool_schema_digest": "sha256:observed-v2",
    },
    "benign_inventory_read": {
        "label": "Benign inventory read",
        "operation": "asset.read",
        "resource": "asset://host/poc-lab",
        "source_type": "user",
        "source_id": "user://analyst/local-poc",
        "source_trust": "authenticated-user",
        "authority_operations": ["asset.read"],
        "is_effectful": False,
    },
}


REMOTE_AUTHORIZE_SCRIPT = r"""import base64
import json
import os
import sys
import urllib.request

event = json.loads(base64.b64decode(sys.argv[1]).decode("utf-8"))
request = urllib.request.Request(
    "http://127.0.0.1:8080/v1/authorize",
    data=json.dumps(event, separators=(",", ":")).encode("utf-8"),
    headers={
        "Authorization": "Bearer " + os.environ["AGENTSEC_INGEST_TOKEN"],
        "Content-Type": "application/json",
    },
    method="POST",
)
with urllib.request.urlopen(request, timeout=10) as response:
    authorization = json.loads(response.read().decode("utf-8"))
safe_event = {
    key: event.get(key)
    for key in (
        "event_id", "flow_id", "occurred_at", "agent_id", "operation",
        "source_type", "source_trust"
    )
}
print(json.dumps({
    "agentsec_live_ui": "2",
    "preset": event.get("attributes", {}).get("live_ui_preset", "unknown"),
    "event": safe_event,
    "authorization": authorization,
}, sort_keys=True))
"""


REMOTE_INCIDENT_SCRIPT = r"""import base64
import json
import os
import sys
import urllib.request

payload = json.loads(base64.b64decode(sys.argv[1]).decode("utf-8"))
request = urllib.request.Request(
    "http://127.0.0.1:8080/v1/incidents/" + payload["finding_id"],
    headers={"Authorization": "Bearer " + os.environ["AGENTSEC_INGEST_TOKEN"]},
    method="GET",
)
with urllib.request.urlopen(request, timeout=10) as response:
    incident = json.loads(response.read().decode("utf-8"))
print(json.dumps({"agentsec_live_incident": "1", "incident": incident}, sort_keys=True))
"""


REMOTE_TRANSITION_SCRIPT = r"""import base64
import json
import os
import sys
import urllib.request

payload = json.loads(base64.b64decode(sys.argv[1]).decode("utf-8"))
finding_id = payload.pop("finding_id")
request = urllib.request.Request(
    "http://127.0.0.1:8080/v1/incidents/" + finding_id + "/transition",
    data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    headers={
        "Authorization": "Bearer " + os.environ["AGENTSEC_INGEST_TOKEN"],
        "Content-Type": "application/json",
    },
    method="POST",
)
with urllib.request.urlopen(request, timeout=10) as response:
    incident = json.loads(response.read().decode("utf-8"))
print(json.dumps({"agentsec_live_transition": "1", "incident": incident}, sort_keys=True))
"""

# Kept as a narrow compatibility alias for tests and integrations that inspect
# the authorize script. It is never populated with a dynamic command.
REMOTE_SCRIPT = REMOTE_AUTHORIZE_SCRIPT


Runner = Callable[..., subprocess.CompletedProcess[str]]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_fixed_platform_report(name: str) -> tuple[Dict[str, Any], str]:
    path = PLATFORM_REPORT_PATHS.get(name)
    if path is None or path.parent not in {
        REPOSITORY_ROOT / "reports",
        REPOSITORY_ROOT / "reports" / "evaluation",
        REPOSITORY_ROOT / "configs",
    }:
        raise ValueError("unknown platform report")
    encoded = path.read_bytes()
    if len(encoded) > MAX_UPSTREAM_BODY_BYTES:
        raise RuntimeError("platform report is too large")
    payload = json.loads(encoded.decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("platform report is invalid")
    return payload, hashlib.sha256(encoded).hexdigest()


def _load_fixed_evaluation_record(
    filename: str, expected_sha256: str
) -> tuple[Dict[str, Any], str]:
    """Read one allowlisted committed evaluation and bind it to the manifest."""

    if filename not in EVALUATION_RECORD_FILES or re.fullmatch(
        r"[a-z_-]+\.json", filename
    ) is None:
        raise ValueError("unknown evaluation record")
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise RuntimeError("evaluation manifest digest is invalid")
    path = REPOSITORY_ROOT / "reports" / "evaluation" / filename
    if path.parent != REPOSITORY_ROOT / "reports" / "evaluation":
        raise ValueError("unknown evaluation record")
    encoded = path.read_bytes()
    if len(encoded) > MAX_UPSTREAM_BODY_BYTES:
        raise RuntimeError("evaluation record is too large")
    actual_sha256 = hashlib.sha256(encoded).hexdigest()
    if actual_sha256 != expected_sha256:
        raise RuntimeError("evaluation record does not match the manifest")
    payload = json.loads(encoded.decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("evaluation record is invalid")
    return payload, actual_sha256


def _platform_metrics(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Project bounded top-level health metrics without leaking configuration."""

    prohibited = {"secret", "credential", "token", "endpoint", "url", "header"}
    result: Dict[str, Any] = {}
    for key in sorted(payload):
        lowered = str(key).lower()
        if any(marker in lowered for marker in prohibited):
            continue
        value = payload[key]
        if value is None or isinstance(value, (bool, int, float)):
            result[str(key)] = value
        elif isinstance(value, str) and len(value) <= 128:
            result[str(key)] = value
        elif isinstance(value, (list, dict)):
            result["%s_count" % key] = len(value)
        if len(result) >= 48:
            break
    return result


def validate_config(profile: str, region: str, instance_id: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", profile):
        raise ValueError("invalid AWS profile name")
    if not re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-\d", region):
        raise ValueError("invalid AWS region")
    if not re.fullmatch(r"i-[0-9a-f]{8,17}", instance_id):
        raise ValueError("invalid EC2 instance ID")


def validate_local_service_url(value: str) -> str:
    """Accept only a literal loopback HTTP origin with no URL decorations."""

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid local service URL") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port is None
        or not 1024 <= port <= 65535
    ):
        raise ValueError("local service URL must be a loopback HTTP origin")
    return "http://127.0.0.1:%d" % port


def validate_service_token(token: str) -> str:
    if len(token) < 32 or any(not 33 <= ord(item) <= 126 for item in token):
        raise ValueError("AGENTSEC_INGEST_TOKEN must contain at least 32 visible characters")
    return token


def validate_finding_id(finding_id: str) -> None:
    if FINDING_ID_PATTERN.fullmatch(finding_id) is None:
        raise ValueError("invalid finding ID")


def validate_transition(payload: Mapping[str, Any]) -> None:
    if set(payload) != {"action", "actor", "reason"}:
        raise ValueError("transition fields must be exact")
    if payload.get("action") not in TRANSITION_ACTIONS:
        raise ValueError("invalid transition action")
    actor = payload.get("actor")
    reason = payload.get("reason")
    if not isinstance(actor, str) or ACTOR_PATTERN.fullmatch(actor) is None:
        raise ValueError("invalid transition actor")
    if not isinstance(reason, str) or not 3 <= len(reason.strip()) <= 256:
        raise ValueError("invalid transition reason")


def validate_case_id(case_id: str) -> None:
    if CASE_ID_PATTERN.fullmatch(case_id) is None:
        raise ValueError("invalid case ID")


def validate_case_action(action: str, payload: Mapping[str, Any]) -> None:
    allowed = {
        "assign": {"expected_version", "assigned_to", "team_id"},
        "acknowledge": {"expected_version"},
        "comments": {"expected_version", "body"},
        "tasks": {"expected_version", "title", "description", "assigned_to", "due_at"},
        "attachments": {
            "expected_version", "display_name", "media_type", "size_bytes",
            "content_sha256", "evidence_ref",
        },
        "relationships": {
            "expected_version", "kind", "target_type", "target_id", "reason",
        },
        "start": {"expected_version"},
        "request-review": {"expected_version"},
        "review": {"expected_version", "decision", "comment"},
        "close": {"expected_version"},
    }
    required = {
        "assign": {"expected_version"},
        "acknowledge": {"expected_version"},
        "comments": {"expected_version", "body"},
        "tasks": {"expected_version", "title", "description"},
        "attachments": allowed["attachments"],
        "relationships": {"expected_version", "kind", "target_type", "target_id"},
        "start": {"expected_version"},
        "request-review": {"expected_version"},
        "review": {"expected_version", "decision", "comment"},
        "close": {"expected_version"},
    }
    if (
        action not in CASE_ACTIONS
        or set(payload) - allowed[action]
        or not required[action].issubset(payload)
    ):
        raise ValueError("invalid case mutation fields")
    version = payload.get("expected_version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError("invalid case version")


def validate_case_task_transition(payload: Mapping[str, Any]) -> None:
    if set(payload) != {"expected_version", "status"}:
        raise ValueError("invalid case task transition fields")
    if payload.get("status") not in {"in_progress", "done", "cancelled"}:
        raise ValueError("invalid case task status")
    version = payload.get("expected_version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError("invalid case version")


def validate_case_attachment_scan(payload: Mapping[str, Any]) -> None:
    if set(payload) != {"expected_version", "status", "scanner_ref"}:
        raise ValueError("invalid case attachment scan fields")
    if payload.get("status") not in {"clean", "quarantined"}:
        raise ValueError("invalid attachment scan status")
    version = payload.get("expected_version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError("invalid case version")


def validate_case_team(payload: Mapping[str, Any]) -> None:
    if set(payload) != {"team_id", "name", "description", "member_ids"}:
        raise ValueError("invalid case team fields")
    if not isinstance(payload.get("member_ids"), list):
        raise ValueError("invalid case team members")


def validate_notification_process(payload: Mapping[str, Any]) -> None:
    if set(payload) - {"limit"}:
        raise ValueError("invalid notification process fields")
    limit = payload.get("limit", 20)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("invalid notification process limit")


def validate_notification_acknowledgment(payload: Mapping[str, Any]) -> None:
    if set(payload) != {"expected_version", "note"}:
        raise ValueError("invalid notification acknowledgment fields")
    version = payload.get("expected_version")
    note = payload.get("note")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError("invalid notification version")
    if not isinstance(note, str) or not 3 <= len(note.strip()) <= 512:
        raise ValueError("invalid notification acknowledgment note")


def validate_provider_acknowledgment(payload: Mapping[str, Any]) -> None:
    if set(payload) != {"provider_receipt_sha256"} or re.fullmatch(
        r"[0-9a-f]{64}", str(payload.get("provider_receipt_sha256", ""))
    ) is None:
        raise ValueError("invalid provider acknowledgment")


def validate_notification_redrive(payload: Mapping[str, Any]) -> None:
    if set(payload) != {"reason"}:
        raise ValueError("invalid notification redrive fields")
    reason = payload.get("reason")
    if not isinstance(reason, str) or not 3 <= len(reason.strip()) <= 512:
        raise ValueError("invalid notification redrive reason")


def validate_response_execution_id(execution_id: str) -> None:
    if RESPONSE_EXECUTION_ID_PATTERN.fullmatch(execution_id) is None:
        raise ValueError("invalid response execution ID")


def _valid_response_version(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 1


def _valid_response_reason(value: object) -> bool:
    return isinstance(value, str) and 3 <= len(value.strip()) <= 512


def validate_response_execution_action(
    action: str, payload: Mapping[str, Any]
) -> None:
    if action not in RESPONSE_EXECUTION_ACTIONS:
        raise ValueError("invalid response execution action")
    if action in {"execute", "rollback"}:
        if payload:
            raise ValueError("response execution body requires an empty body")
        return
    allowed = {"expected_version", "reason"}
    if action in {"approve", "approve-rollback"}:
        allowed.add("ttl_minutes")
    if set(payload) - allowed or not {"expected_version", "reason"}.issubset(payload):
        raise ValueError("invalid response execution mutation fields")
    if not _valid_response_version(payload.get("expected_version")):
        raise ValueError("invalid response execution version")
    if not _valid_response_reason(payload.get("reason")):
        raise ValueError("invalid response execution reason")
    if "ttl_minutes" in payload:
        ttl = payload["ttl_minutes"]
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= 60:
            raise ValueError("invalid response approval TTL")


def validate_response_control(payload: Mapping[str, Any]) -> None:
    if set(payload) != {"active", "expected_version", "reason"}:
        raise ValueError("invalid response control fields")
    if not isinstance(payload.get("active"), bool):
        raise ValueError("invalid response kill-switch state")
    if not _valid_response_version(payload.get("expected_version")):
        raise ValueError("invalid response control version")
    if not _valid_response_reason(payload.get("reason")):
        raise ValueError("invalid response control reason")


def validate_response_playbook(payload: Mapping[str, Any]) -> None:
    """Validate the editor envelope before forwarding it to the local service."""

    if set(payload) != {"definition"} or not isinstance(payload.get("definition"), dict):
        raise ValueError("invalid response playbook envelope")
    definition = payload["definition"]
    allowed = {
        "schema_version", "playbook_id", "version", "name", "description", "priority",
        "trigger", "steps", "enabled", "definition_sha256",
    }
    required = {"playbook_id", "version", "name", "description", "trigger", "steps"}
    if set(definition) - allowed or not required.issubset(definition):
        raise ValueError("invalid response playbook definition fields")
    if RESPONSE_PLAYBOOK_ID_PATTERN.fullmatch(str(definition.get("playbook_id", ""))) is None:
        raise ValueError("invalid response playbook ID")
    if not _valid_response_version(definition.get("version")):
        raise ValueError("invalid response playbook version")
    priority = definition.get("priority", 100)
    if (
        isinstance(priority, bool)
        or not isinstance(priority, int)
        or not 0 <= priority <= 1000
    ):
        raise ValueError("invalid response playbook priority")
    for field, maximum in (("name", 128), ("description", 512)):
        value = definition.get(field)
        if not isinstance(value, str) or not 3 <= len(value.strip()) <= maximum:
            raise ValueError("invalid response playbook text")
    trigger = definition.get("trigger")
    trigger_fields = {"priorities", "escalation_levels", "alert_types", "decisions"}
    if not isinstance(trigger, dict) or set(trigger) - trigger_fields:
        raise ValueError("invalid response playbook trigger")
    if not any(isinstance(trigger.get(field), list) and trigger[field] for field in trigger_fields):
        raise ValueError("response playbook trigger is empty")
    if any(field in trigger and not isinstance(trigger[field], list) for field in trigger_fields):
        raise ValueError("invalid response playbook trigger values")
    steps = definition.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 12:
        raise ValueError("invalid response playbook steps")
    step_allowed = {
        "step_id", "name", "operation", "connector_id", "target_selector",
        "expected_state", "rollback_operation", "rollback_expected_state",
        "timeout_seconds", "requires_approval",
    }
    step_required = {
        "step_id", "name", "operation", "connector_id", "target_selector",
        "expected_state",
    }
    for step in steps:
        if not isinstance(step, dict) or set(step) - step_allowed or not step_required.issubset(step):
            raise ValueError("invalid response playbook step fields")
        if RESPONSE_STEP_ID_PATTERN.fullmatch(str(step.get("step_id", ""))) is None:
            raise ValueError("invalid response step ID")
        if RESPONSE_CONNECTOR_ID_PATTERN.fullmatch(str(step.get("connector_id", ""))) is None:
            raise ValueError("invalid response connector ID")
        if step.get("requires_approval", True) is not True:
            raise ValueError("response playbook steps require approval")


def validate_response_playbook_action(payload: Mapping[str, Any]) -> None:
    if set(payload) != {
        "playbook_id", "version", "action", "expected_revision", "comment"
    }:
        raise ValueError("invalid response playbook action fields")
    if RESPONSE_PLAYBOOK_ID_PATTERN.fullmatch(str(payload.get("playbook_id", ""))) is None:
        raise ValueError("invalid response playbook ID")
    if not _valid_response_version(payload.get("version")) or not _valid_response_version(
        payload.get("expected_revision")
    ):
        raise ValueError("invalid response playbook revision")
    if payload.get("action") not in {"submit", "approve", "reject", "activate", "retire"}:
        raise ValueError("invalid response playbook action")
    if not _valid_response_reason(payload.get("comment")):
        raise ValueError("invalid response playbook comment")


def validate_response_mutation(payload: Mapping[str, Any]) -> None:
    validate_response_execution_action("request-live", payload)


def validate_response_approval(payload: Mapping[str, Any]) -> None:
    validate_response_execution_action("approve", payload)


def validate_response_empty(payload: Mapping[str, Any]) -> None:
    validate_response_execution_action("execute", payload)


def validate_response_kill_switch(payload: Mapping[str, Any]) -> None:
    validate_response_control(payload)


def validate_response_playbook_create(payload: Mapping[str, Any]) -> None:
    validate_response_playbook(payload)


def validate_search_request(payload: Mapping[str, Any]) -> None:
    if set(payload) - SEARCH_REQUEST_FIELDS:
        raise ValueError("search fields are invalid")
    query = payload.get("query", "*")
    if not isinstance(query, str) or not 1 <= len(query.strip()) <= 4096:
        raise ValueError("search query is invalid")
    page_size = payload.get("page_size", 50)
    if isinstance(page_size, bool) or not isinstance(page_size, int) or not 1 <= page_size <= 200:
        raise ValueError("search page size is invalid")
    for field in ("cursor", "sort_by", "sort_order"):
        if field in payload and not isinstance(payload[field], str):
            raise ValueError("search option is invalid")


def validate_aggregation_request(payload: Mapping[str, Any]) -> None:
    if set(payload) - AGGREGATION_REQUEST_FIELDS:
        raise ValueError("aggregation fields are invalid")
    if not isinstance(payload.get("query", "*"), str) or not isinstance(
        payload.get("field", "record_type"), str
    ):
        raise ValueError("aggregation request is invalid")
    limit = payload.get("limit", 20)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("aggregation limit is invalid")


def validate_saved_hunt(payload: Mapping[str, Any]) -> None:
    if set(payload) - SAVED_HUNT_FIELDS or not {"name", "query"}.issubset(payload):
        raise ValueError("saved hunt fields are invalid")
    if not isinstance(payload["name"], str) or not 1 <= len(payload["name"].strip()) <= 128:
        raise ValueError("saved hunt name is invalid")
    if not isinstance(payload["query"], str) or not 1 <= len(payload["query"].strip()) <= 4096:
        raise ValueError("saved hunt query is invalid")


def validate_graph_time(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise ValueError("graph time is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("graph time is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("graph time must include a timezone")
    return value


def validate_graph_node_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 3 <= len(value) <= 512
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError("graph node ID is invalid")
    return value


def validate_graph_analysis(path: str, payload: Mapping[str, Any]) -> None:
    if path == "/api/graph/reachability":
        allowed = {"origin_node_id", "direction", "max_depth", "max_nodes", "as_of"}
        required = {"origin_node_id"}
        if payload.get("direction", "outbound") not in {"outbound", "inbound"}:
            raise ValueError("graph direction is invalid")
        bounded = (("max_depth", 1, 20), ("max_nodes", 1, 5000))
    elif path == "/api/graph/blast-radius":
        allowed = {"origin_node_id", "max_depth", "as_of"}
        required = {"origin_node_id"}
        bounded = (("max_depth", 1, 20),)
    elif path == "/api/graph/attack-paths":
        allowed = {
            "source_node_id", "target_node_id", "max_paths", "max_depth", "max_states", "as_of"
        }
        required = {"source_node_id", "target_node_id"}
        bounded = (("max_paths", 1, 20), ("max_depth", 1, 20), ("max_states", 1, 50000))
    else:
        raise ValueError("unknown graph analysis")
    if set(payload) - allowed or not required.issubset(payload):
        raise ValueError("graph analysis fields are invalid")
    for field in required:
        validate_graph_node_id(payload[field])
    for field, minimum, maximum in bounded:
        value = payload.get(field)
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not minimum <= value <= maximum
        ):
            raise ValueError("graph analysis bound is invalid")
    if "as_of" in payload:
        validate_graph_time(payload["as_of"])


def validate_posture_scan(payload: Mapping[str, Any]) -> None:
    if set(payload) - {"check_ids"}:
        raise ValueError("posture scan fields are invalid")
    check_ids = payload.get("check_ids")
    if check_ids is not None and (
        not isinstance(check_ids, list)
        or len(check_ids) > 256
        or any(not isinstance(item, str) or re.fullmatch(r"PST-[A-Z0-9-]{3,64}", item) is None for item in check_ids)
    ):
        raise ValueError("posture check selection is invalid")


def validate_posture_exception(payload: Mapping[str, Any]) -> None:
    if set(payload) != {"reason", "owner_ref", "approved_by", "expires_at"}:
        raise ValueError("posture exception fields are invalid")
    if not isinstance(payload["reason"], str) or not 10 <= len(payload["reason"].strip()) <= 1024:
        raise ValueError("posture exception reason is invalid")
    for field in ("owner_ref", "approved_by"):
        if not isinstance(payload[field], str) or re.fullmatch(r"[A-Za-z0-9_.:/@-]{3,256}", payload[field]) is None:
            raise ValueError("posture exception identity is invalid")
    validate_graph_time(payload["expires_at"])


def validate_posture_revoke(payload: Mapping[str, Any]) -> None:
    if set(payload) != {"reason"}:
        raise ValueError("posture exception revocation fields are invalid")
    reason = payload["reason"]
    if not isinstance(reason, str) or not 3 <= len(reason.strip()) <= 512:
        raise ValueError("posture exception revocation reason is invalid")


def validate_content_id(content_id: str) -> None:
    if CONTENT_ID_PATTERN.fullmatch(content_id) is None:
        raise ValueError("invalid detection content ID")


def validate_content_definition(payload: Mapping[str, Any]) -> None:
    if set(payload) != {"definition"} or not isinstance(payload["definition"], dict):
        raise ValueError("detection content definition fields are invalid")


def _content_preset_events(payload: Mapping[str, Any], *, validation: bool) -> Dict[str, Any]:
    allowed = {"presets", "expected_alert_presets", "name"} if validation else {"presets"}
    if set(payload) - allowed or "presets" not in payload:
        raise ValueError("detection content evaluation fields are invalid")
    presets = payload["presets"]
    if (
        not isinstance(presets, list)
        or not 1 <= len(presets) <= 100
        or any(not isinstance(item, str) or item not in PRESETS for item in presets)
    ):
        raise ValueError("detection content presets are invalid")
    events = [make_event(item) for item in presets]
    if not validation:
        return {"events": events}
    expected = payload.get("expected_alert_presets", [])
    if (
        not isinstance(expected, list)
        or len(expected) > len(presets)
        or any(not isinstance(item, str) or item not in PRESETS for item in expected)
    ):
        raise ValueError("expected alert presets are invalid")
    remaining = list(expected)
    expected_ids: List[str] = []
    for preset, event in zip(presets, events):
        if preset in remaining:
            expected_ids.append(str(event["event_id"]))
            remaining.remove(preset)
    if remaining:
        raise ValueError("expected alert presets must be included in presets")
    name = payload.get("name", "Rule Studio deterministic preset suite")
    if not isinstance(name, str) or not 3 <= len(name.strip()) <= 256:
        raise ValueError("detection content suite name is invalid")
    return {
        "suite": {
            "name": name.strip(),
            "events": events,
            "expected_alert_event_ids": expected_ids,
        }
    }


def normalize_content_action(action: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
    if action not in CONTENT_ACTIONS:
        raise ValueError("unknown detection content action")
    if action == "validate":
        return _content_preset_events(payload, validation=True)
    if action in {"backtest", "shadow-evaluate"}:
        return _content_preset_events(payload, validation=False)
    if action in {"submit", "shadow"}:
        if payload:
            raise ValueError("detection content action accepts no fields")
        return {}
    if action == "review":
        if (
            set(payload) != {"decision", "comment"}
            or payload.get("decision") not in {"approve", "reject"}
            or not isinstance(payload.get("comment"), str)
            or not 3 <= len(str(payload["comment"]).strip()) <= 1024
        ):
            raise ValueError("detection content review is invalid")
        return dict(payload)
    if action == "publish":
        digest = payload.get("expected_definition_sha256")
        if set(payload) != {"expected_definition_sha256"} or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("detection content publication acknowledgement is invalid")
        return dict(payload)
    if (
        set(payload) != {"new_version", "reason"}
        or not isinstance(payload.get("new_version"), str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", str(payload["new_version"])) is None
        or not isinstance(payload.get("reason"), str)
        or not 10 <= len(str(payload["reason"]).strip()) <= 1024
    ):
        raise ValueError("detection content rollback is invalid")
    return dict(payload)


def validate_content_pack_export(payload: Mapping[str, Any]) -> None:
    if set(payload) != {"content_ids", "name", "description", "version"}:
        raise ValueError("detection content pack export fields are invalid")
    content_ids = payload["content_ids"]
    if (
        not isinstance(content_ids, list)
        or not 1 <= len(content_ids) <= 100
        or len(set(content_ids)) != len(content_ids)
        or any(not isinstance(item, str) or CONTENT_ID_PATTERN.fullmatch(item) is None for item in content_ids)
    ):
        raise ValueError("detection content pack selection is invalid")
    for field, minimum, maximum in (("name", 3, 256), ("description", 3, 1024)):
        value = payload[field]
        if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum:
            raise ValueError("detection content pack metadata is invalid")
    version = payload["version"]
    if not isinstance(version, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", version) is None:
        raise ValueError("detection content pack version is invalid")


def validate_content_pack_import(payload: Mapping[str, Any]) -> None:
    if set(payload) != {"pack"} or not isinstance(payload["pack"], dict):
        raise ValueError("detection content pack import fields are invalid")


def validate_behavior_tuning(payload: Mapping[str, Any]) -> None:
    if set(payload) != {"config", "reason"} or not isinstance(payload["config"], dict):
        raise ValueError("behavior tuning fields are invalid")
    if set(payload["config"]) != BEHAVIOR_TUNING_FIELDS:
        raise ValueError("behavior tuning config fields are invalid")
    reason = payload["reason"]
    if not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 1024:
        raise ValueError("behavior tuning reason is invalid")


def validate_correlation_transition(payload: Mapping[str, Any]) -> None:
    if (
        set(payload) != {"status", "reason"}
        or payload.get("status") not in {"open", "investigating", "contained", "closed"}
        or not isinstance(payload.get("reason"), str)
        or not 3 <= len(str(payload["reason"]).strip()) <= 512
    ):
        raise ValueError("correlation transition is invalid")


def validate_correlation_merge(payload: Mapping[str, Any]) -> None:
    ids = payload.get("incident_ids")
    if (
        set(payload) != {"incident_ids", "reason"}
        or not isinstance(ids, list)
        or not 2 <= len(ids) <= 20
        or len(set(ids)) != len(ids)
        or any(not isinstance(item, str) or CORRELATED_INCIDENT_PATTERN.fullmatch(item) is None for item in ids)
        or not isinstance(payload.get("reason"), str)
        or not 10 <= len(str(payload["reason"]).strip()) <= 512
    ):
        raise ValueError("correlation merge is invalid")


def validate_correlation_split(payload: Mapping[str, Any]) -> None:
    ids = payload.get("finding_ids")
    if (
        set(payload) != {"finding_ids", "reason"}
        or not isinstance(ids, list)
        or not 1 <= len(ids) <= 499
        or len(set(ids)) != len(ids)
        or any(not isinstance(item, str) or FINDING_ID_PATTERN.fullmatch(item) is None for item in ids)
        or not isinstance(payload.get("reason"), str)
        or not 10 <= len(str(payload["reason"]).strip()) <= 512
    ):
        raise ValueError("correlation split is invalid")


def make_event(preset_name: str) -> Dict[str, Any]:
    if preset_name not in PRESETS:
        raise ValueError("unknown forge preset")
    suffix = uuid4().hex
    preset = PRESETS[preset_name]
    return {
        "schema_version": "1.0.0",
        "event_id": "evt_live_%s" % suffix,
        "occurred_at": utc_now(),
        "tenant_id": "tenant-lab",
        "flow_id": "flow-live-%s" % suffix[:16],
        "agent_id": "response-agent",
        "operation": preset["operation"],
        "resource": preset["resource"],
        "destination": preset.get("destination"),
        "source_type": preset["source_type"],
        "source_id": preset["source_id"],
        "source_trust": preset["source_trust"],
        "data_classes": preset.get("data_classes", []),
        "authority_operations": preset.get("authority_operations", []),
        "indicators": preset.get("indicators", []),
        "approval_present": False,
        "is_effectful": preset.get("is_effectful", True),
        "tool_name": preset.get("tool_name"),
        "declared_tool_schema_digest": preset.get("declared_tool_schema_digest"),
        "observed_tool_schema_digest": preset.get("observed_tool_schema_digest"),
        "attributes": {"live_ui_preset": preset_name},
    }


def validate_simulation_mutation(payload: Mapping[str, Any]) -> None:
    name = payload.get("name")
    if (
        set(payload) != {"base_scenario_id", "base_version", "variant", "name"}
        or not isinstance(payload.get("base_scenario_id"), str)
        or SIMULATION_SCENARIO_ID_PATTERN.fullmatch(str(payload["base_scenario_id"])) is None
        or not isinstance(payload.get("base_version"), str)
        or SIMULATION_VERSION_PATTERN.fullmatch(str(payload["base_version"])) is None
        or payload.get("variant") not in SIMULATION_VARIANTS
        or (name is not None and (not isinstance(name, str) or not 3 <= len(name) <= 256))
    ):
        raise ValueError("simulation mutation request is invalid")


def validate_simulation_run(payload: Mapping[str, Any]) -> None:
    if (
        set(payload) != {"request_id", "scenario_id", "version", "mode"}
        or not isinstance(payload.get("request_id"), str)
        or SIMULATION_REQUEST_ID_PATTERN.fullmatch(str(payload["request_id"])) is None
        or not isinstance(payload.get("scenario_id"), str)
        or SIMULATION_SCENARIO_ID_PATTERN.fullmatch(str(payload["scenario_id"])) is None
        or not isinstance(payload.get("version"), str)
        or SIMULATION_VERSION_PATTERN.fullmatch(str(payload["version"])) is None
        or payload.get("mode") not in SIMULATION_RUN_MODES
    ):
        raise ValueError("simulation run request is invalid")


def validate_simulation_replay(payload: Mapping[str, Any]) -> None:
    if (
        set(payload) != {"request_id"}
        or not isinstance(payload.get("request_id"), str)
        or SIMULATION_REQUEST_ID_PATTERN.fullmatch(str(payload["request_id"])) is None
    ):
        raise ValueError("simulation replay request is invalid")


def _remote_command(script: str, payload: Mapping[str, Any]) -> str:
    payload_b64 = base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    script_b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return (
        "printf '%%s' '%s' | base64 -d | "
        "docker exec -i agentsec python - '%s'" % (script_b64, payload_b64)
    )


def build_remote_command(event: Mapping[str, Any]) -> str:
    return _remote_command(REMOTE_AUTHORIZE_SCRIPT, event)


def build_incident_command(finding_id: str) -> str:
    validate_finding_id(finding_id)
    return _remote_command(REMOTE_INCIDENT_SCRIPT, {"finding_id": finding_id})


def build_transition_command(
    finding_id: str, action: str, actor: str, reason: str
) -> str:
    validate_finding_id(finding_id)
    payload = {"action": action, "actor": actor, "reason": reason}
    validate_transition(payload)
    return _remote_command(
        REMOTE_TRANSITION_SCRIPT, {"finding_id": finding_id, **payload}
    )


def decode_json_output(output: str) -> Optional[Dict[str, Any]]:
    try:
        payload = json.loads(output.strip())
    except (json.JSONDecodeError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def authorization_from_output(
    output: str,
) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], List[Dict[str, Any]]]]:
    payload = decode_json_output(output)
    if payload is None:
        return None
    if payload.get("agentsec_live_ui") in {"1", "2"}:
        authorization = payload.get("authorization")
        event = payload.get("event")
        if not isinstance(authorization, dict) or not isinstance(event, dict):
            return None
    else:
        required = {
            "event_id",
            "overall_action",
            "effect_allowed",
            "alerts",
            "ledger_verified",
        }
        if not required.issubset(payload) or not isinstance(payload.get("alerts"), list):
            return None
        authorization = payload
        event = {}
    raw_details = authorization.get("incidents", [])
    details = (
        [item for item in raw_details if isinstance(item, dict)]
        if isinstance(raw_details, list)
        else []
    )
    return authorization, event, details


def normalize_decision(value: object) -> str:
    decision = str(value or "unknown").lower()
    if decision == "require_approval":
        return "REQUIRE APPROVAL"
    if decision.startswith("allow"):
        return "ALLOW"
    if decision == "deny":
        return "DENY"
    return "UNKNOWN"


def normalize_time(value: object) -> str:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(DISPLAY_TIMEZONE).strftime("%H:%M:%S")
    except ValueError:
        return "--:--:--"


def _detail_for_summary(
    details: Sequence[Mapping[str, Any]], summary: Mapping[str, Any]
) -> Optional[Dict[str, Any]]:
    finding_id = str(summary.get("finding_id", ""))
    for item in details:
        incident_id = item.get("incident_id")
        nested_summary = item.get("summary")
        nested_finding_id = (
            nested_summary.get("finding_id")
            if isinstance(nested_summary, dict)
            else None
        )
        if finding_id and finding_id in {str(incident_id), str(nested_finding_id)}:
            return dict(item)
    return None


def _safe_display_alert(
    summary: Mapping[str, Any],
    authorization: Mapping[str, Any],
    event: Mapping[str, Any],
    detail: Optional[Dict[str, Any]],
    *,
    command_id: str,
    requested_at: object,
) -> Dict[str, Any]:
    incident_summary = detail.get("summary", {}) if detail else {}
    if not isinstance(incident_summary, dict):
        incident_summary = {}
    detection = detail.get("detection", {}) if detail else {}
    if not isinstance(detection, dict):
        detection = {}
    event_context = detail.get("event_context", {}) if detail else {}
    if not isinstance(event_context, dict):
        event_context = {}
    triage = detail.get("triage", {}) if detail else {}
    if not isinstance(triage, dict):
        triage = {}
    judgment = detail.get("judgment", {}) if detail else {}
    if not isinstance(judgment, dict):
        judgment = {}

    detail_availability = (
        str(detail.get("detail_availability"))
        if detail and detail.get("detail_availability") in {"complete", "summary_only"}
        else "summary_only"
    )
    alert_type = str(summary.get("alert_type", "unknown_alert"))
    resource_class = event_context.get("resource_class")
    resource_ref = event_context.get("resource_ref")
    destination_class = event_context.get("destination_class")
    destination_ref = event_context.get("destination_ref")
    source_type = event_context.get("source_type")
    source_ref = event_context.get("source_ref")
    model_verdict = judgment.get("model_verdict")
    ai_review = None
    if isinstance(model_verdict, dict):
        ai_review = model_verdict.get("label")
    elif judgment.get("model_status"):
        ai_review = str(judgment.get("model_status"))

    return {
        "id": str(
            summary.get("alert_id")
            or detection.get("alert_id")
            or summary.get("finding_id")
            or ""
        ),
        "title": str(detection.get("title") or incident_summary.get("title") or alert_type),
        "type": alert_type,
        "severity": str(incident_summary.get("severity") or summary.get("severity") or "unknown"),
        "decision": normalize_decision(
            incident_summary.get("decision") or summary.get("decision")
        ),
        "state": str(incident_summary.get("status") or "unknown"),
        "time": normalize_time(
            detection.get("detected_at")
            or incident_summary.get("created_at")
            or event.get("occurred_at")
            or requested_at
        ),
        "occurredAt": detection.get("detected_at")
        or incident_summary.get("created_at")
        or event.get("occurred_at"),
        "agent": incident_summary.get("agent_id") or event_context.get("agent_id") or event.get("agent_id"),
        "operation": event_context.get("operation") or event.get("operation"),
        "resource": " · ".join(str(item) for item in (resource_class, resource_ref) if item) or None,
        "source": " · ".join(str(item) for item in (source_type, source_ref) if item) or None,
        "sourceTrust": event_context.get("source_trust") or event.get("source_trust"),
        "destination": " · ".join(str(item) for item in (destination_class, destination_ref) if item) or None,
        "reason": triage.get("narrative"),
        "finding": str(summary.get("finding_id", "")),
        "policy": judgment.get("policy_version"),
        "risk": triage.get("risk_score"),
        "aiReview": ai_review,
        "evidence": list(detection.get("reason_codes", []))
        if isinstance(detection.get("reason_codes"), list)
        else [],
        "eventId": str(authorization.get("event_id", "")),
        "commandId": command_id,
        "detailAvailability": detail_availability,
        "detail": detail,
    }


def alerts_from_authorization(
    authorization: Mapping[str, Any],
    event: Mapping[str, Any],
    details: Sequence[Mapping[str, Any]],
    *,
    command_id: str,
    requested_at: object,
) -> List[Dict[str, Any]]:
    """Build display rows only from allowlisted authoritative service output."""

    rows: List[Dict[str, Any]] = []
    raw_summaries = authorization.get("alerts", [])
    if not isinstance(raw_summaries, list):
        return rows
    for summary in raw_summaries:
        if not isinstance(summary, dict):
            continue
        detail = _detail_for_summary(details, summary)
        row = _safe_display_alert(
            summary,
            authorization,
            event,
            detail,
            command_id=command_id,
            requested_at=requested_at,
        )
        if row["id"]:
            rows.append(row)
    return rows


def alerts_from_invocations(
    invocations: Sequence[Mapping[str, Any]],
) -> Tuple[List[Dict[str, Any]], Optional[bool]]:
    live_alerts: List[Dict[str, Any]] = []
    ledger_values: List[bool] = []
    seen: set[str] = set()
    for invocation in invocations:
        command_id = str(invocation.get("CommandId", "unknown"))
        requested_at = invocation.get("RequestedDateTime", "")
        plugins = invocation.get("CommandPlugins", [])
        if not isinstance(plugins, list):
            continue
        for plugin in plugins:
            if not isinstance(plugin, dict):
                continue
            parsed = authorization_from_output(str(plugin.get("Output", "")))
            if parsed is None:
                continue
            authorization, event, details = parsed
            if isinstance(authorization.get("ledger_verified"), bool):
                ledger_values.append(bool(authorization["ledger_verified"]))
            raw_summaries = authorization.get("alerts", [])
            if not isinstance(raw_summaries, list):
                continue
            for summary in raw_summaries:
                if not isinstance(summary, dict):
                    continue
                alert_id = str(summary.get("alert_id", ""))
                if not alert_id or alert_id in seen:
                    continue
                seen.add(alert_id)
                detail = _detail_for_summary(details, summary)
                live_alerts.append(
                    _safe_display_alert(
                        summary,
                        authorization,
                        event,
                        detail,
                        command_id=command_id,
                        requested_at=requested_at,
                    )
                )
    ledger_verified = all(ledger_values) if ledger_values else None
    return live_alerts[:100], ledger_verified


class LocalServiceClient:
    """Token-owning client for a local AgentSec service; browser never sees it."""

    source = "local-service"

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        opener: Callable[..., Any] = urlopen,
    ) -> None:
        self.base_url = validate_local_service_url(base_url)
        self.token = validate_service_token(token)
        self.opener = opener

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        data = None
        headers = {"Authorization": "Bearer " + self.token}
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(
            self.base_url + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with self.opener(request, timeout=10) as response:
                encoded = response.read(MAX_UPSTREAM_BODY_BYTES + 1)
                if len(encoded) > MAX_UPSTREAM_BODY_BYTES:
                    raise RuntimeError("Local AgentSec service response was too large")
                result = json.loads(encoded.decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Local AgentSec service request failed") from exc
        if not isinstance(result, dict):
            raise RuntimeError("Local AgentSec service returned an invalid response")
        return result

    def telemetry_sources(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/telemetry/sources")

    def telemetry_queue(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/telemetry/queue")

    def detection_health(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/detection/health")

    def enrichment_health(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/enrichment/health")

    def analyst_health(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/analyst/health")

    def list_alerts(self) -> Dict[str, Any]:
        payload = self._request("GET", "/v1/incidents")
        raw_summaries = payload.get("incidents", [])
        if not isinstance(raw_summaries, list):
            raise RuntimeError("Local incident list was invalid")
        alerts: List[Dict[str, Any]] = []
        ledger_values: List[bool] = []
        for raw_summary in raw_summaries[:100]:
            if not isinstance(raw_summary, dict):
                continue
            finding_id = raw_summary.get("finding_id")
            detail: Optional[Dict[str, Any]] = None
            if isinstance(finding_id, str):
                try:
                    detail = self.get_incident(finding_id)
                except RuntimeError:
                    detail = None
            validation = detail.get("validation", {}) if detail else {}
            if isinstance(validation, dict) and isinstance(
                validation.get("ledger_verified"), bool
            ):
                ledger_values.append(bool(validation["ledger_verified"]))
            row = _safe_display_alert(
                raw_summary,
                {"event_id": raw_summary.get("event_id")},
                {},
                detail,
                command_id="local-service",
                requested_at=raw_summary.get("created_at", ""),
            )
            if row["id"]:
                alerts.append(row)
        return {
            "source": self.source,
            "region": "local",
            "alerts": alerts,
            "ledger_verified": all(ledger_values) if ledger_values else None,
            "checked_at": utc_now(),
        }

    def forge(self, preset_name: str) -> Dict[str, Any]:
        event = make_event(preset_name)
        authorization = self._request("POST", "/v1/authorize", event)
        raw_details = authorization.get("incidents", [])
        details = (
            [item for item in raw_details if isinstance(item, dict)]
            if isinstance(raw_details, list)
            else []
        )
        alerts = alerts_from_authorization(
            authorization,
            event,
            details,
            command_id="local-service",
            requested_at=event["occurred_at"],
        )
        ledger = authorization.get("ledger_verified")
        return {
            "preset": preset_name,
            "event_id": authorization.get("event_id"),
            "overall_action": authorization.get("overall_action"),
            "effect_allowed": authorization.get("effect_allowed"),
            "ledger_verified": ledger if isinstance(ledger, bool) else None,
            "alerts": alerts,
            "completed_at": utc_now(),
        }

    def simulation_catalog(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/simulation/catalog")

    def simulation_health(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/simulation/health")

    def administration_snapshot(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/administration")

    def administration_health(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/administration/health")

    def simulation_scenario(self, scenario_id: str, version: str) -> Dict[str, Any]:
        if (
            SIMULATION_SCENARIO_ID_PATTERN.fullmatch(scenario_id) is None
            or SIMULATION_VERSION_PATTERN.fullmatch(version) is None
        ):
            raise ValueError("simulation scenario ID is invalid")
        return self._request(
            "GET", "/v1/simulation/scenarios/%s/versions/%s" % (scenario_id, version)
        )

    def simulation_mutate(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_simulation_mutation(payload)
        return self._request("POST", "/v1/simulation/mutations", payload)

    def simulation_run(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_simulation_run(payload)
        return self._request("POST", "/v1/simulation/runs", payload)

    def simulation_runs(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/simulation/runs?limit=100&offset=0")

    def simulation_run_detail(self, run_id: str) -> Dict[str, Any]:
        if SIMULATION_RUN_ID_PATTERN.fullmatch(run_id) is None:
            raise ValueError("simulation run ID is invalid")
        return self._request("GET", "/v1/simulation/runs/" + run_id)

    def simulation_replay(self, run_id: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        if SIMULATION_RUN_ID_PATTERN.fullmatch(run_id) is None:
            raise ValueError("simulation run ID is invalid")
        validate_simulation_replay(payload)
        return self._request("POST", "/v1/simulation/runs/%s/replay" % run_id, payload)

    def get_incident(self, finding_id: str) -> Dict[str, Any]:
        validate_finding_id(finding_id)
        return self._request("GET", "/v1/incidents/" + finding_id)

    def transition(
        self, finding_id: str, *, action: str, actor: str, reason: str
    ) -> Dict[str, Any]:
        validate_finding_id(finding_id)
        payload = {"action": action, "actor": actor, "reason": reason}
        validate_transition(payload)
        return self._request(
            "POST", "/v1/incidents/" + finding_id + "/transition", payload
        )

    def cases(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/cases?limit=200&offset=0")

    def case_health(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/cases/health")

    def case_teams(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/case-teams")

    def case_detail(self, case_id: str) -> Dict[str, Any]:
        validate_case_id(case_id)
        return self._request("GET", "/v1/cases/%s" % case_id)

    def case_action(
        self, case_id: str, action: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        validate_case_id(case_id)
        validate_case_action(action, payload)
        return self._request(
            "POST", "/v1/cases/%s/%s" % (case_id, action), payload
        )

    def case_task_transition(
        self, case_id: str, task_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        validate_case_id(case_id)
        if CASE_TASK_ID_PATTERN.fullmatch(task_id) is None:
            raise ValueError("invalid case task ID")
        validate_case_task_transition(payload)
        return self._request(
            "POST",
            "/v1/cases/%s/tasks/%s/transition" % (case_id, task_id),
            payload,
        )

    def case_attachment_scan(
        self, case_id: str, attachment_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        validate_case_id(case_id)
        if CASE_ATTACHMENT_ID_PATTERN.fullmatch(attachment_id) is None:
            raise ValueError("invalid case attachment ID")
        validate_case_attachment_scan(payload)
        return self._request(
            "POST",
            "/v1/cases/%s/attachments/%s/scan" % (case_id, attachment_id),
            payload,
        )

    def case_team_create(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_case_team(payload)
        return self._request("POST", "/v1/case-teams", payload)

    def notifications(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/notifications?limit=200&offset=0")

    def notification_health(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/notifications/health")

    def notification_destinations(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/notification-destinations")

    def notification_detail(self, notification_id: str) -> Dict[str, Any]:
        if NOTIFICATION_ID_PATTERN.fullmatch(notification_id) is None:
            raise ValueError("invalid notification ID")
        return self._request("GET", "/v1/notifications/%s" % notification_id)

    def notification_process(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_notification_process(payload)
        return self._request("POST", "/v1/notifications/process", payload)

    def notification_acknowledge(
        self, notification_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        if NOTIFICATION_ID_PATTERN.fullmatch(notification_id) is None:
            raise ValueError("invalid notification ID")
        validate_notification_acknowledgment(payload)
        return self._request(
            "POST", "/v1/notifications/%s/acknowledge" % notification_id, payload
        )

    def notification_provider_acknowledge(
        self, delivery_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        if NOTIFICATION_DELIVERY_ID_PATTERN.fullmatch(delivery_id) is None:
            raise ValueError("invalid notification delivery ID")
        validate_provider_acknowledgment(payload)
        return self._request(
            "POST",
            "/v1/notification-deliveries/%s/provider-acknowledge" % delivery_id,
            payload,
        )

    def notification_redrive(
        self, delivery_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        if NOTIFICATION_DELIVERY_ID_PATTERN.fullmatch(delivery_id) is None:
            raise ValueError("invalid notification delivery ID")
        validate_notification_redrive(payload)
        return self._request(
            "POST",
            "/v1/notification-deliveries/%s/redrive" % delivery_id,
            payload,
        )

    def response_executions(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/response/executions?limit=200&offset=0")

    def response_health(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/response/health")

    def response_connectors(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/response/connectors")

    def response_control(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/response/control")

    def response_playbooks(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/response/playbooks?limit=200&offset=0")

    def response_detail(self, execution_id: str) -> Dict[str, Any]:
        if RESPONSE_EXECUTION_ID_PATTERN.fullmatch(execution_id) is None:
            raise ValueError("invalid response execution ID")
        return self._request("GET", "/v1/response/executions/%s" % execution_id)

    def response_action(
        self, execution_id: str, action: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        if RESPONSE_EXECUTION_ID_PATTERN.fullmatch(execution_id) is None:
            raise ValueError("invalid response execution ID")
        if action in {"request-live", "request-rollback"}:
            validate_response_mutation(payload)
        elif action in {"approve", "approve-rollback"}:
            validate_response_approval(payload)
        elif action in {"execute", "rollback"}:
            validate_response_empty(payload)
        else:
            raise ValueError("invalid response execution action")
        return self._request(
            "POST", "/v1/response/executions/%s/%s" % (execution_id, action), payload
        )

    def response_kill_switch(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_response_kill_switch(payload)
        return self._request("POST", "/v1/response/control", payload)

    def response_playbook_create(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_response_playbook_create(payload)
        return self._request("POST", "/v1/response/playbooks", payload)

    def response_playbook_action(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_response_playbook_action(payload)
        return self._request("POST", "/v1/response/playbooks/action", payload)

    def search(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_search_request(payload)
        return self._request("POST", "/v1/search", payload)

    def aggregate(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_aggregation_request(payload)
        return self._request("POST", "/v1/search/aggregate", payload)

    def list_hunts(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/hunts")

    def save_hunt(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_saved_hunt(payload)
        return self._request("POST", "/v1/hunts", payload)

    def evidence_pivot(self, evidence_id: str) -> Dict[str, Any]:
        if EVIDENCE_ID_PATTERN.fullmatch(evidence_id) is None:
            raise ValueError("invalid evidence ID")
        return self._request("GET", "/v1/evidence/%s/pivot" % evidence_id)

    def inventory(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/inventory?limit=200")

    def inventory_summary(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/inventory/summary")

    def inventory_detail(self, component_id: str) -> Dict[str, Any]:
        if COMPONENT_ID_PATTERN.fullmatch(component_id) is None:
            raise ValueError("invalid inventory component ID")
        return self._request("GET", "/v1/inventory/%s" % component_id)

    def model_gateway_status(self) -> Dict[str, Any]:
        """Return only the governed, sanitized model-control-plane views."""

        health = self._request("GET", "/v1/model-gateway/health")
        routes = self._request("GET", "/v1/model-gateway/routes")
        prompts = self._request("GET", "/v1/model-gateway/prompts")
        qualifications = self._request("GET", "/v1/model-gateway/qualifications")
        calls = self._request("GET", "/v1/model-gateway/calls?limit=100&offset=0")
        return {
            "schema_version": "1.0.0",
            "health": health,
            "routes": routes.get("routes", []),
            "prompts": prompts.get("prompts", []),
            "qualifications": qualifications.get("qualifications", []),
            "calls": calls.get("calls", []),
            "checked_at": utc_now(),
        }

    def graph(self, as_of: Optional[str] = None) -> Dict[str, Any]:
        suffix = ""
        if as_of is not None:
            suffix = "?" + urlencode({"as_of": validate_graph_time(as_of)})
        return self._request("GET", "/v1/graph" + suffix)

    def graph_summary(self, as_of: Optional[str] = None) -> Dict[str, Any]:
        suffix = ""
        if as_of is not None:
            suffix = "?" + urlencode({"as_of": validate_graph_time(as_of)})
        return self._request("GET", "/v1/graph/summary" + suffix)

    def graph_analysis(self, path: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        bridge_path = "/api" + path.removeprefix("/v1")
        validate_graph_analysis(bridge_path, payload)
        return self._request("POST", path, payload)

    def posture_summary(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/posture/summary")

    def posture_checks(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/posture/checks")

    def posture_findings(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/posture/findings?limit=200")

    def posture_trends(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/posture/trends?limit=30")

    def posture_detail(self, finding_id: str) -> Dict[str, Any]:
        if POSTURE_FINDING_ID_PATTERN.fullmatch(finding_id) is None:
            raise ValueError("invalid posture finding ID")
        return self._request("GET", "/v1/posture/findings/%s" % finding_id)

    def posture_scan(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_posture_scan(payload)
        return self._request("POST", "/v1/posture/scans", payload)

    def posture_exception(self, finding_id: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        if POSTURE_FINDING_ID_PATTERN.fullmatch(finding_id) is None:
            raise ValueError("invalid posture finding ID")
        validate_posture_exception(payload)
        return self._request("POST", "/v1/posture/findings/%s/exceptions" % finding_id, payload)

    def posture_revoke_exception(self, exception_id: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        if POSTURE_EXCEPTION_ID_PATTERN.fullmatch(exception_id) is None:
            raise ValueError("invalid posture exception ID")
        validate_posture_revoke(payload)
        return self._request("POST", "/v1/posture/exceptions/%s/revoke" % exception_id, payload)

    def content_list(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/detection/content?limit=200&offset=0")

    def content_health(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/detection/content/health")

    def content_packs(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/detection/content/packs")

    def content_detail(self, content_id: str) -> Dict[str, Any]:
        validate_content_id(content_id)
        return self._request("GET", "/v1/detection/content/%s" % content_id)

    def content_history(self, content_id: str) -> Dict[str, Any]:
        validate_content_id(content_id)
        return self._request("GET", "/v1/detection/content/%s/history" % content_id)

    def content_create(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_content_definition(payload)
        return self._request("POST", "/v1/detection/content", payload)

    def content_update(self, content_id: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_content_id(content_id)
        validate_content_definition(payload)
        return self._request("PUT", "/v1/detection/content/%s" % content_id, payload)

    def content_action(
        self, content_id: str, action: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        validate_content_id(content_id)
        normalized = normalize_content_action(action, payload)
        return self._request(
            "POST", "/v1/detection/content/%s/%s" % (content_id, action), normalized
        )

    def content_export_pack(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_content_pack_export(payload)
        return self._request("POST", "/v1/detection/content/packs/export", payload)

    def content_import_pack(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_content_pack_import(payload)
        return self._request("POST", "/v1/detection/content/packs/import", payload)

    def model_gateway_health(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/model-gateway/health")

    def model_gateway_routes(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/model-gateway/routes")

    def model_gateway_qualifications(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/model-gateway/qualifications")

    def model_gateway_calls(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/model-gateway/calls?limit=50&offset=0")

    def model_gateway_secrets(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/model-gateway/secrets")

    def behavior_baselines(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/behavior/baselines?limit=200&offset=0")

    def behavior_assessments(self, *, anomalies_only: bool = False) -> Dict[str, Any]:
        return self._request(
            "GET",
            "/v1/behavior/assessments?%s"
            % urlencode(
                {
                    "anomalies_only": "true" if anomalies_only else "false",
                    "limit": "200",
                    "offset": "0",
                }
            ),
        )

    def behavior_assessment(self, assessment_id: str) -> Dict[str, Any]:
        if re.fullmatch(r"bhas_[A-Za-z0-9]+", assessment_id) is None:
            raise ValueError("invalid behavior assessment ID")
        return self._request("GET", "/v1/behavior/assessments/%s" % assessment_id)

    def behavior_health(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/behavior/health")

    def behavior_config(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/behavior/config")

    def behavior_drift(self, entity_ref: Optional[str] = None) -> Dict[str, Any]:
        suffix = ""
        if entity_ref is not None:
            if BEHAVIOR_ENTITY_PATTERN.fullmatch(entity_ref) is None:
                raise ValueError("invalid behavior entity reference")
            suffix = "?" + urlencode({"entity_ref": entity_ref})
        return self._request("GET", "/v1/behavior/drift" + suffix)

    def behavior_tune(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_behavior_tuning(payload)
        return self._request("POST", "/v1/behavior/config", payload)

    def correlation_incidents(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/correlation/incidents?limit=200&offset=0")

    def correlation_incident(self, incident_id: str) -> Dict[str, Any]:
        if CORRELATED_INCIDENT_PATTERN.fullmatch(incident_id) is None:
            raise ValueError("invalid correlated incident ID")
        return self._request("GET", "/v1/correlation/incidents/%s" % incident_id)

    def correlation_health(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/correlation/health")

    def correlation_decisions(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/correlation/decisions?limit=200")

    def correlation_transition(self, incident_id: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        if CORRELATED_INCIDENT_PATTERN.fullmatch(incident_id) is None:
            raise ValueError("invalid correlated incident ID")
        validate_correlation_transition(payload)
        return self._request("POST", "/v1/correlation/incidents/%s/transition" % incident_id, payload)

    def correlation_merge(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_correlation_merge(payload)
        return self._request("POST", "/v1/correlation/incidents/merge", payload)

    def correlation_split(self, incident_id: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        if CORRELATED_INCIDENT_PATTERN.fullmatch(incident_id) is None:
            raise ValueError("invalid correlated incident ID")
        validate_correlation_split(payload)
        return self._request("POST", "/v1/correlation/incidents/%s/split" % incident_id, payload)


class AwsSsmClient:
    source = "aws-ssm"

    def __init__(
        self,
        *,
        profile: str,
        region: str,
        instance_id: str,
        runner: Runner = subprocess.run,
    ) -> None:
        validate_config(profile, region, instance_id)
        self.profile = profile
        self.region = region
        self.instance_id = instance_id
        self.runner = runner

    def _run(self, args: Sequence[str], timeout: int = 30) -> str:
        completed = self.runner(
            list(args),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            shell=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("AWS CLI request failed")
        return completed.stdout

    def _base(self, operation: str) -> List[str]:
        return [
            "aws",
            "ssm",
            operation,
            "--region",
            self.region,
            "--profile",
            self.profile,
        ]

    def _send_and_wait(
        self, remote_command: str, *, comment: str, requested_at: str
    ) -> Dict[str, Any]:
        parameters = json.dumps({"commands": [remote_command]}, separators=(",", ":"))
        send_args = self._base("send-command") + [
            "--instance-ids",
            self.instance_id,
            "--document-name",
            "AWS-RunShellScript",
            "--comment",
            comment,
            "--parameters",
            parameters,
            "--query",
            "Command.CommandId",
            "--output",
            "text",
            "--no-cli-pager",
        ]
        command_id = self._run(send_args, timeout=30).strip()
        if not re.fullmatch(r"[0-9a-f-]{36}", command_id):
            raise RuntimeError("AWS CLI returned an invalid command ID")
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            get_args = self._base("get-command-invocation") + [
                "--command-id",
                command_id,
                "--instance-id",
                self.instance_id,
                "--output",
                "json",
                "--no-cli-pager",
            ]
            candidate = json.loads(self._run(get_args, timeout=20))
            status = candidate.get("Status")
            if status == "Success":
                return {
                    "CommandId": command_id,
                    "RequestedDateTime": requested_at,
                    "CommandPlugins": [
                        {"Output": candidate.get("StandardOutputContent", "")}
                    ],
                }
            if status in {"Cancelled", "Cancelling", "Failed", "TimedOut"}:
                raise RuntimeError("Remote AgentSec command ended with status %s" % status)
            time.sleep(1)
        raise RuntimeError("Remote AgentSec command did not finish within 45 seconds")

    def list_alerts(self) -> Dict[str, Any]:
        args = self._base("list-command-invocations") + [
            "--instance-id",
            self.instance_id,
            "--details",
            "--max-results",
            "25",
            "--output",
            "json",
            "--no-cli-pager",
        ]
        payload = json.loads(self._run(args, timeout=35))
        invocations = payload.get("CommandInvocations", [])
        alerts, ledger_verified = alerts_from_invocations(invocations)
        return {
            "source": "aws-ssm",
            "region": self.region,
            "alerts": alerts,
            "ledger_verified": ledger_verified,
            "checked_at": utc_now(),
        }

    def forge(self, preset_name: str) -> Dict[str, Any]:
        event = make_event(preset_name)
        invocation = self._send_and_wait(
            build_remote_command(event),
            comment="AgentSec local live UI forge: %s" % preset_name,
            requested_at=event["occurred_at"],
        )
        alerts, ledger_verified = alerts_from_invocations([invocation])
        parsed = authorization_from_output(invocation["CommandPlugins"][0]["Output"])
        if parsed is None:
            raise RuntimeError("Remote AgentSec command returned an invalid response")
        authorization, _event, _details = parsed
        return {
            "preset": preset_name,
            "event_id": authorization.get("event_id"),
            "overall_action": authorization.get("overall_action"),
            "effect_allowed": authorization.get("effect_allowed"),
            "ledger_verified": ledger_verified,
            "alerts": alerts,
            "completed_at": utc_now(),
        }

    def get_incident(self, finding_id: str) -> Dict[str, Any]:
        invocation = self._send_and_wait(
            build_incident_command(finding_id),
            comment="AgentSec local UI incident detail",
            requested_at=utc_now(),
        )
        payload = decode_json_output(invocation["CommandPlugins"][0]["Output"])
        incident = payload.get("incident") if payload else None
        if not payload or payload.get("agentsec_live_incident") != "1" or not isinstance(incident, dict):
            raise RuntimeError("Remote AgentSec incident response was invalid")
        return incident

    def transition(
        self, finding_id: str, *, action: str, actor: str, reason: str
    ) -> Dict[str, Any]:
        invocation = self._send_and_wait(
            build_transition_command(finding_id, action, actor, reason),
            comment="AgentSec local UI incident transition",
            requested_at=utc_now(),
        )
        payload = decode_json_output(invocation["CommandPlugins"][0]["Output"])
        incident = payload.get("incident") if payload else None
        if not payload or payload.get("agentsec_live_transition") != "1" or not isinstance(incident, dict):
            raise RuntimeError("Remote AgentSec transition response was invalid")
        return incident


class LiveBridge:
    def __init__(self, client: Any, cache_seconds: float = 4.0) -> None:
        self.client = client
        self.source = str(getattr(client, "source", "configured-service"))
        self.cache_seconds = cache_seconds
        self._cache: Optional[Dict[str, Any]] = None
        self._cache_at = 0.0
        self._lock = threading.Lock()
        self._recent_alerts: Dict[str, Dict[str, Any]] = {}

    def _merge_recent(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        remote_alerts = payload.get("alerts", [])
        remote_ids = {
            str(item.get("id"))
            for item in remote_alerts
            if isinstance(item, dict) and item.get("id")
        }
        recent = [
            item
            for alert_id, item in self._recent_alerts.items()
            if alert_id not in remote_ids
        ]
        return {**payload, "alerts": recent + remote_alerts}

    def alerts(self) -> Dict[str, Any]:
        with self._lock:
            if (
                self._cache is not None
                and time.monotonic() - self._cache_at < self.cache_seconds
            ):
                return self._cache
        payload = self.client.list_alerts()
        with self._lock:
            payload = self._merge_recent(payload)
            self._cache = payload
            self._cache_at = time.monotonic()
        return payload

    def forge(self, preset_name: str) -> Dict[str, Any]:
        result = self.client.forge(preset_name)
        with self._lock:
            for alert in result.get("alerts", []):
                if isinstance(alert, dict) and alert.get("id"):
                    self._recent_alerts[str(alert["id"])] = alert
            self._cache = None
            self._cache_at = 0.0
        return result

    def simulation_catalog(self) -> Dict[str, Any]:
        if not hasattr(self.client, "simulation_catalog"):
            raise RuntimeError("simulation lab is unavailable")
        return self.client.simulation_catalog()

    def simulation_health(self) -> Dict[str, Any]:
        if not hasattr(self.client, "simulation_health"):
            raise RuntimeError("simulation lab is unavailable")
        return self.client.simulation_health()

    def administration_snapshot(self) -> Dict[str, Any]:
        if not hasattr(self.client, "administration_snapshot"):
            raise RuntimeError("administration plane is unavailable")
        return self.client.administration_snapshot()

    def administration_health(self) -> Dict[str, Any]:
        if not hasattr(self.client, "administration_health"):
            raise RuntimeError("administration plane is unavailable")
        return self.client.administration_health()

    def simulation_scenario(self, scenario_id: str, version: str) -> Dict[str, Any]:
        if (
            SIMULATION_SCENARIO_ID_PATTERN.fullmatch(scenario_id) is None
            or SIMULATION_VERSION_PATTERN.fullmatch(version) is None
        ):
            raise ValueError("simulation scenario ID is invalid")
        if not hasattr(self.client, "simulation_scenario"):
            raise RuntimeError("simulation lab is unavailable")
        return self.client.simulation_scenario(scenario_id, version)

    def simulation_mutate(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_simulation_mutation(payload)
        if not hasattr(self.client, "simulation_mutate"):
            raise RuntimeError("simulation lab is unavailable")
        return self.client.simulation_mutate(payload)

    def simulation_run(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_simulation_run(payload)
        if not hasattr(self.client, "simulation_run"):
            raise RuntimeError("simulation lab is unavailable")
        return self.client.simulation_run(payload)

    def simulation_runs(self) -> Dict[str, Any]:
        if not hasattr(self.client, "simulation_runs"):
            raise RuntimeError("simulation lab is unavailable")
        return self.client.simulation_runs()

    def simulation_run_detail(self, run_id: str) -> Dict[str, Any]:
        if SIMULATION_RUN_ID_PATTERN.fullmatch(run_id) is None:
            raise ValueError("simulation run ID is invalid")
        if not hasattr(self.client, "simulation_run_detail"):
            raise RuntimeError("simulation lab is unavailable")
        return self.client.simulation_run_detail(run_id)

    def simulation_replay(self, run_id: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        if SIMULATION_RUN_ID_PATTERN.fullmatch(run_id) is None:
            raise ValueError("simulation run ID is invalid")
        validate_simulation_replay(payload)
        if not hasattr(self.client, "simulation_replay"):
            raise RuntimeError("simulation lab is unavailable")
        return self.client.simulation_replay(run_id, payload)

    def detail(self, finding_id: str) -> Dict[str, Any]:
        validate_finding_id(finding_id)
        payload = self.alerts()
        for alert in payload.get("alerts", []):
            if not isinstance(alert, dict) or alert.get("finding") != finding_id:
                continue
            detail = alert.get("detail")
            if isinstance(detail, dict) and detail.get("detail_availability") == "complete":
                return {"detail_availability": "complete", "incident": detail}
            try:
                incident = self.client.get_incident(finding_id)
            except RuntimeError:
                return {
                    "detail_availability": "summary_only",
                    "finding_id": finding_id,
                    "incident": detail if isinstance(detail, dict) else None,
                }
            return {
                "detail_availability": str(
                    incident.get("detail_availability", "summary_only")
                ),
                "incident": incident,
            }
        raise KeyError(finding_id)

    def transition(
        self, finding_id: str, *, action: str, actor: str, reason: str
    ) -> Dict[str, Any]:
        validate_finding_id(finding_id)
        validate_transition({"action": action, "actor": actor, "reason": reason})
        incident = self.client.transition(
            finding_id, action=action, actor=actor, reason=reason
        )
        with self._lock:
            for alert in self._recent_alerts.values():
                if alert.get("finding") == finding_id:
                    alert["detail"] = incident
                    alert["detailAvailability"] = incident.get(
                        "detail_availability", "summary_only"
                    )
                    summary = incident.get("summary", {})
                    if isinstance(summary, dict):
                        alert["state"] = summary.get("status", alert.get("state"))
            self._cache = None
            self._cache_at = 0.0
        return {
            "finding_id": finding_id,
            "detail_availability": incident.get(
                "detail_availability", "summary_only"
            ),
            "incident": incident,
        }

    def telemetry_sources(self) -> Dict[str, Any]:
        if not hasattr(self.client, "telemetry_sources"):
            raise RuntimeError("configured source does not support telemetry health")
        return self.client.telemetry_sources()

    def telemetry_queue(self) -> Dict[str, Any]:
        if not hasattr(self.client, "telemetry_queue"):
            raise RuntimeError("configured source does not support telemetry queue health")
        return self.client.telemetry_queue()

    def detection_health(self) -> Dict[str, Any]:
        if not hasattr(self.client, "detection_health"):
            raise RuntimeError("configured source does not support detection health")
        return self.client.detection_health()

    def enrichment_health(self) -> Dict[str, Any]:
        if not hasattr(self.client, "enrichment_health"):
            raise RuntimeError("configured source does not support enrichment health")
        return self.client.enrichment_health()

    def analyst_health(self) -> Dict[str, Any]:
        if not hasattr(self.client, "analyst_health"):
            raise RuntimeError("configured source does not support analyst health")
        return self.client.analyst_health()

    def platform_snapshot(self) -> Dict[str, Any]:
        """Aggregate fixed health reads and committed reports for the UI shell."""

        probes: List[Tuple[str, str, Callable[[], Dict[str, Any]]]] = [
            ("incidents", "Incident decision plane", self.alerts),
            ("telemetry_sources", "Telemetry source intake", self.telemetry_sources),
            ("telemetry_queue", "Telemetry durable queue", self.telemetry_queue),
            ("inventory", "AI asset inventory", self.inventory_summary),
            ("security_graph", "AI security graph", lambda: self.graph_summary(None)),
            ("posture", "AI security posture", self.posture_summary),
            ("detection", "Detection engine", self.detection_health),
            ("content", "Detection content", self.content_health),
            ("behavior", "Behavioral risk", self.behavior_health),
            ("correlation", "Incident correlation", self.correlation_health),
            ("cases", "Case management", self.case_health),
            ("notifications", "Escalation delivery", self.notification_health),
            ("response", "Guarded response", self.response_health),
            ("enrichment", "Context enrichment", self.enrichment_health),
            ("analyst", "AI analyst", self.analyst_health),
            ("model_gateway", "Model gateway", self.model_gateway_health),
            ("simulation", "Simulation validation lab", self.simulation_health),
            ("administration", "Administration assurance", self.administration_health),
        ]
        services: List[Dict[str, Any]] = []
        for service_id, name, probe in probes:
            try:
                payload = probe()
                if not isinstance(payload, dict):
                    raise RuntimeError("platform health contract is invalid")
                services.append(
                    {
                        "service_id": service_id,
                        "name": name,
                        "state": "available",
                        "metrics": _platform_metrics(payload),
                    }
                )
            except (KeyError, RuntimeError, ValueError):
                services.append(
                    {
                        "service_id": service_id,
                        "name": name,
                        "state": "unavailable",
                        "metrics": {},
                        "error_code": "service_not_configured_or_unavailable",
                    }
                )

        reports: Dict[str, Any] = {}
        try:
            release, release_sha = _load_fixed_platform_report("release")
            criteria = release.get("criteria", [])
            reports["release"] = {
                "state": "available",
                "sha256": release_sha,
                "schema_version": release.get("schema_version"),
                "scope": release.get("scope"),
                "dataset_version": release.get("dataset_version"),
                "all_passed": release.get("all_passed") is True,
                "production_ready": release.get("production_ready") is True,
                "discovered_tests": int(release.get("discovered_tests", 0)),
                "criteria": [
                    {"id": item.get("id"), "passed": item.get("passed") is True}
                    for item in criteria
                    if isinstance(item, dict)
                    and isinstance(item.get("id"), str)
                ][:64],
                "production_deferred": [
                    str(item)[:256]
                    for item in release.get("production_deferred", [])
                    if isinstance(item, str)
                ][:32],
            }
        except (OSError, RuntimeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            reports["release"] = {"state": "unavailable"}

        try:
            evaluation, evaluation_sha = _load_fixed_platform_report("evaluation")
            manifest_entries = {
                str(item.get("path")): item
                for item in evaluation.get("artifacts", [])
                if isinstance(item, dict) and isinstance(item.get("path"), str)
            }
            modes: List[Dict[str, Any]] = []
            for filename in EVALUATION_MODE_FILES:
                relative_path = "reports/evaluation/%s" % filename
                manifest_entry = manifest_entries.get(relative_path)
                if not isinstance(manifest_entry, dict):
                    raise RuntimeError("evaluation manifest is incomplete")
                expected_sha256 = manifest_entry.get("sha256")
                if not isinstance(expected_sha256, str):
                    raise RuntimeError("evaluation manifest digest is invalid")
                record, _record_sha256 = _load_fixed_evaluation_record(
                    filename, expected_sha256
                )
                metrics = record.get("metrics")
                if not isinstance(metrics, dict) or not isinstance(
                    record.get("mode"), str
                ):
                    raise RuntimeError("evaluation mode record is invalid")
                metric_names = (
                    "attack_scenarios",
                    "benign_scenarios",
                    "benign_task_completion_rate",
                    "detector_recall",
                    "false_block_rate",
                    "forbidden_effect_attack_success_rate",
                )
                if any(
                    isinstance(metrics.get(metric), bool)
                    or not isinstance(metrics.get(metric), (int, float))
                    for metric in metric_names
                ):
                    raise RuntimeError("evaluation mode metrics are invalid")
                modes.append(
                    {
                        "mode": record["mode"],
                        **{metric: metrics[metric] for metric in metric_names},
                        "record_digest": record.get("record_digest"),
                        "sha256": expected_sha256,
                    }
                )

            ablation_entry = manifest_entries.get(
                "reports/evaluation/ablation.json"
            )
            if not isinstance(ablation_entry, dict) or not isinstance(
                ablation_entry.get("sha256"), str
            ):
                raise RuntimeError("evaluation ablation manifest is incomplete")
            ablation_record, _ablation_sha256 = _load_fixed_evaluation_record(
                "ablation.json", ablation_entry["sha256"]
            )
            ablation_results = ablation_record.get("results")
            if not isinstance(ablation_results, list):
                raise RuntimeError("evaluation ablation record is invalid")
            continuous_records: Dict[str, Dict[str, Any]] = {}
            continuous_metric_names = (
                "cases",
                "attack_cases",
                "benign_cases",
                "alert_precision",
                "detector_recall",
                "forbidden_effect_attack_success_rate",
                "benign_task_completion_rate",
                "severity_exact_agreement_rate",
                "evidence_validity_rate",
                "safe_action_agreement_rate",
                "abstention_rate",
                "brier_score",
                "expected_calibration_error",
                "schema_validity_rate",
            )
            for label, filename in (
                ("baseline", "continuous-baseline.json"),
                ("candidate", "continuous.json"),
            ):
                entry = manifest_entries.get("reports/evaluation/" + filename)
                if not isinstance(entry, dict) or not isinstance(
                    entry.get("sha256"), str
                ):
                    raise RuntimeError("continuous evaluation manifest is incomplete")
                record, _continuous_sha256 = _load_fixed_evaluation_record(
                    filename, entry["sha256"]
                )
                dataset = record.get("dataset")
                candidate = record.get("candidate")
                metrics = record.get("metrics")
                gate = record.get("gate")
                use_case_metrics = record.get("use_case_metrics")
                if not all(
                    isinstance(item, dict)
                    for item in (dataset, candidate, metrics, gate, use_case_metrics)
                ):
                    raise RuntimeError("continuous evaluation record is invalid")
                splits = dataset.get("splits")
                if (
                    not isinstance(splits, dict)
                    or isinstance(dataset.get("case_count"), bool)
                    or not isinstance(dataset.get("case_count"), int)
                    or isinstance(dataset.get("use_case_count"), bool)
                    or not isinstance(dataset.get("use_case_count"), int)
                ):
                    raise RuntimeError("continuous evaluation dataset is invalid")
                if any(
                    isinstance(metrics.get(metric), bool)
                    or not isinstance(metrics.get(metric), (int, float))
                    for metric in continuous_metric_names
                ):
                    raise RuntimeError("continuous evaluation metrics are invalid")
                checks = gate.get("checks")
                if not isinstance(checks, list) or gate.get("state") not in {
                    "pass", "block", "hold"
                }:
                    raise RuntimeError("continuous evaluation gate is invalid")
                drift = gate.get("drift")
                if drift is not None and not isinstance(drift, dict):
                    raise RuntimeError("continuous evaluation drift is invalid")
                continuous_records[label] = {
                    "dataset_version": dataset.get("dataset_version"),
                    "dataset_sha256": dataset.get("dataset_sha256"),
                    "case_count": dataset.get("case_count"),
                    "use_case_count": dataset.get("use_case_count"),
                    "splits": {
                        str(split)[:32]: count
                        for split, count in sorted(splits.items())
                        if isinstance(count, int) and not isinstance(count, bool)
                    },
                    "blind_execution": dataset.get("blind_execution") is True,
                    "candidate_id": candidate.get("candidate_id"),
                    "candidate_kind": candidate.get("kind"),
                    "provider": candidate.get("provider"),
                    "exact_model_id": candidate.get("exact_model_id"),
                    "qualified": candidate.get("qualified") is True,
                    "live_provider_calls": candidate.get("live_provider_calls") is True,
                    "route_sha256": candidate.get("route_sha256"),
                    "gate_state": gate.get("state"),
                    "failed_checks": sum(
                        item.get("passed") is not True
                        for item in checks
                        if isinstance(item, dict)
                    ),
                    "drift_passed": (
                        drift.get("passed") is True if isinstance(drift, dict) else None
                    ),
                    "metrics": {
                        metric: metrics[metric] for metric in continuous_metric_names
                    },
                    "use_cases": [
                        {
                            "use_case": str(use_case)[:64],
                            "cases": values.get("cases"),
                            "detector_recall": values.get("detector_recall"),
                            "safe_action_agreement_rate": values.get(
                                "safe_action_agreement_rate"
                            ),
                            "evidence_validity_rate": values.get(
                                "evidence_validity_rate"
                            ),
                            "severity_exact_agreement_rate": values.get(
                                "severity_exact_agreement_rate"
                            ),
                        }
                        for use_case, values in sorted(use_case_metrics.items())
                        if isinstance(values, dict)
                    ][:16],
                    "record_digest": record.get("record_digest"),
                    "sha256": entry["sha256"],
                }
            reports["evaluation"] = {
                "state": "available",
                "sha256": evaluation_sha,
                "schema_version": evaluation.get("schema_version"),
                "dataset_version": evaluation.get("dataset_version"),
                "manifest_digest": evaluation.get("manifest_digest"),
                "artifacts": [
                    {
                        "path": item.get("path"),
                        "record_digest": item.get("record_digest"),
                        "sha256": item.get("sha256"),
                    }
                    for item in evaluation.get("artifacts", [])
                    if isinstance(item, dict)
                    and isinstance(item.get("path"), str)
                ][:32],
                "modes": modes,
                "ablation": {
                    "full_system_attack_success_rate": ablation_record.get(
                        "full_system_attack_success_rate"
                    ),
                    "record_digest": ablation_record.get("record_digest"),
                    "sha256": ablation_entry["sha256"],
                    "results": [
                        {
                            "component": item.get("component"),
                            "attack_scenarios": item.get("attack_scenarios"),
                            "forbidden_effect_attack_success_rate": item.get(
                                "forbidden_effect_attack_success_rate"
                            ),
                            "affected_scenarios_count": len(
                                item.get("affected_scenarios", [])
                            )
                            if isinstance(item.get("affected_scenarios"), list)
                            else 0,
                        }
                        for item in ablation_results
                        if isinstance(item, dict)
                    ][:16],
                },
                "continuous": continuous_records,
            }
        except (OSError, RuntimeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            reports["evaluation"] = {"state": "unavailable"}

        modules: List[Dict[str, Any]] = []
        module_scope = "unavailable"
        try:
            catalog, _catalog_sha = _load_fixed_platform_report("modules")
            module_scope = str(catalog.get("scope", "unknown"))[:256]
            modules = [
                {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "status": item.get("status"),
                    "acceptance_record": item.get("acceptance_record"),
                }
                for item in catalog.get("modules", [])
                if isinstance(item, dict)
                and item.get("status")
                in {"not_started", "in_progress", "implemented", "verified"}
            ][:24]
        except (OSError, RuntimeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            pass

        administration: Dict[str, Any] = {"state": "unavailable"}
        try:
            raw_administration = self.administration_snapshot()
            tenant = raw_administration.get("tenant")
            health = raw_administration.get("health")
            identities = raw_administration.get("identities")
            workloads = raw_administration.get("workloads")
            keys = raw_administration.get("keys")
            reviews = raw_administration.get("access_reviews")
            slos = raw_administration.get("slo_measurements")
            drills = raw_administration.get("recovery_drills")
            attestations = raw_administration.get("supply_chain_attestations")
            checkpoint = raw_administration.get("latest_audit_checkpoint")
            if not (
                isinstance(tenant, dict)
                and isinstance(health, dict)
                and all(
                    isinstance(item, list)
                    for item in (identities, workloads, keys, reviews, slos, drills, attestations)
                )
                and (checkpoint is None or isinstance(checkpoint, dict))
            ):
                raise RuntimeError("administration snapshot contract is invalid")
            role_counts: Dict[str, int] = {}
            for identity in identities[:200]:
                if not isinstance(identity, dict):
                    continue
                for role in identity.get("roles", []):
                    if isinstance(role, str) and re.fullmatch(r"[a-z_]{2,64}", role):
                        role_counts[role] = role_counts.get(role, 0) + 1
            latest_slo = slos[0] if slos and isinstance(slos[0], dict) else None
            latest_drill = drills[0] if drills and isinstance(drills[0], dict) else None
            latest_attestation = (
                attestations[0]
                if attestations and isinstance(attestations[0], dict)
                else None
            )
            administration = {
                "state": "available",
                "tenant": {
                    "tenant_id": str(tenant.get("tenant_id", ""))[:128],
                    "display_name": str(tenant.get("display_name", ""))[:128],
                    "status": str(tenant.get("status", ""))[:32],
                    "residency_region": str(tenant.get("residency_region", ""))[:64],
                    "allowed_processing_regions": [
                        str(item)[:64]
                        for item in tenant.get("allowed_processing_regions", [])
                        if isinstance(item, str)
                    ][:16],
                    "retention_days": tenant.get("retention_days"),
                    "evidence_retention_days": tenant.get("evidence_retention_days"),
                    "legal_hold": tenant.get("legal_hold") is True,
                    "encryption_required": tenant.get("encryption_required") is True,
                    "policy_version": tenant.get("policy_version"),
                    "record_sha256": tenant.get("record_sha256"),
                },
                "identity": {
                    "configured": len(identities),
                    "enabled": sum(
                        item.get("enabled") is True
                        for item in identities
                        if isinstance(item, dict)
                    ),
                    "role_counts": role_counts,
                    "access_reviews": len(reviews),
                    "local_adapter": health.get("local_identity_adapter") is True,
                    "external_idp_federated": health.get("external_idp_federated") is True,
                },
                "workload_identity": {
                    "configured": len(workloads),
                    "revoked": sum(
                        item.get("revoked_at") is not None
                        for item in workloads
                        if isinstance(item, dict)
                    ),
                },
                "keys": {
                    "configured": len(keys),
                    "active": sum(
                        item.get("state") == "active"
                        for item in keys
                        if isinstance(item, dict)
                    ),
                    "external_custody_verified": health.get(
                        "external_key_custody_verified"
                    ) is True,
                },
                "assurance": {
                    "audit_entries": health.get("audit_entries"),
                    "audit_valid": health.get("audit_valid") is True,
                    "latest_slos_passed": health.get("latest_slos_passed") is True,
                    "latest_recovery_drill_passed": health.get(
                        "latest_recovery_drill_passed"
                    ) is True,
                    "latest_supply_chain_attestation_passed": health.get(
                        "latest_supply_chain_attestation_passed"
                    ) is True,
                    "geographic_residency_verified": health.get(
                        "geographic_residency_verified"
                    ) is True,
                    "distributed_ha_verified": health.get("distributed_ha_verified") is True,
                    "production_ready": health.get("production_ready") is True,
                    "boundaries": [
                        str(item)[:256]
                        for item in health.get("boundaries", [])
                        if isinstance(item, str)
                    ][:16],
                },
                "latest_slo": {
                    "name": latest_slo.get("objective", {}).get("name"),
                    "observed": latest_slo.get("observed"),
                    "passed": latest_slo.get("passed") is True,
                    "error_budget_remaining": latest_slo.get("error_budget_remaining"),
                } if latest_slo else None,
                "latest_recovery": {
                    "passed": latest_drill.get("passed") is True,
                    "observed_rpo_minutes": latest_drill.get("observed_rpo_minutes"),
                    "observed_rto_minutes": latest_drill.get("observed_rto_minutes"),
                    "integrity_verified": latest_drill.get("integrity_verified") is True,
                    "record_sha256": latest_drill.get("record_sha256"),
                } if latest_drill else None,
                "latest_supply_chain": {
                    "release_id": latest_attestation.get("release_id"),
                    "passed": latest_attestation.get("passed") is True,
                    "signature_verified": latest_attestation.get("signature_verified") is True,
                    "artifact_sha256": latest_attestation.get("artifact_sha256"),
                    "sbom_sha256": latest_attestation.get("sbom_sha256"),
                    "provenance_sha256": latest_attestation.get("provenance_sha256"),
                } if latest_attestation else None,
                "audit_checkpoint": {
                    "sequence": checkpoint.get("sequence"),
                    "current_sha256": checkpoint.get("current_sha256"),
                    "signature_algorithm": checkpoint.get("signature_algorithm"),
                } if checkpoint else None,
            }
        except (KeyError, RuntimeError, TypeError, ValueError):
            pass

        return {
            "schema_version": "1.0.0",
            "source": self.source,
            "bff": {
                "upstream_authenticated": True,
                "upstream_authentication": "server_held_bearer",
                "browser_service_auth_exposed": False,
                "network_scope": "loopback_origin_allowlist",
                "human_identity_verified": False,
                "human_identity_boundary": "module_24_sso_rbac_required",
            },
            "services": services,
            "administration": administration,
            "reports": reports,
            "module_scope": module_scope,
            "modules": modules,
            "checked_at": utc_now(),
        }

    def cases(self) -> Dict[str, Any]:
        if not hasattr(self.client, "cases"):
            raise RuntimeError("configured source does not support case management")
        return self.client.cases()

    def case_health(self) -> Dict[str, Any]:
        if not hasattr(self.client, "case_health"):
            raise RuntimeError("configured source does not support case management")
        return self.client.case_health()

    def case_teams(self) -> Dict[str, Any]:
        if not hasattr(self.client, "case_teams"):
            raise RuntimeError("configured source does not support case management")
        return self.client.case_teams()

    def case_detail(self, case_id: str) -> Dict[str, Any]:
        validate_case_id(case_id)
        if not hasattr(self.client, "case_detail"):
            raise RuntimeError("configured source does not support case management")
        return self.client.case_detail(case_id)

    def case_action(
        self, case_id: str, action: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        validate_case_id(case_id)
        validate_case_action(action, payload)
        if not hasattr(self.client, "case_action"):
            raise RuntimeError("configured source does not support case management")
        return self.client.case_action(case_id, action, payload)

    def case_task_transition(
        self, case_id: str, task_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        validate_case_id(case_id)
        if CASE_TASK_ID_PATTERN.fullmatch(task_id) is None:
            raise ValueError("invalid case task ID")
        validate_case_task_transition(payload)
        if not hasattr(self.client, "case_task_transition"):
            raise RuntimeError("configured source does not support case management")
        return self.client.case_task_transition(case_id, task_id, payload)

    def case_attachment_scan(
        self, case_id: str, attachment_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        validate_case_id(case_id)
        if CASE_ATTACHMENT_ID_PATTERN.fullmatch(attachment_id) is None:
            raise ValueError("invalid case attachment ID")
        validate_case_attachment_scan(payload)
        if not hasattr(self.client, "case_attachment_scan"):
            raise RuntimeError("configured source does not support case management")
        return self.client.case_attachment_scan(case_id, attachment_id, payload)

    def case_team_create(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_case_team(payload)
        if not hasattr(self.client, "case_team_create"):
            raise RuntimeError("configured source does not support case management")
        return self.client.case_team_create(payload)

    def notifications(self) -> Dict[str, Any]:
        if not hasattr(self.client, "notifications"):
            raise RuntimeError("configured source does not support notifications")
        return self.client.notifications()

    def notification_health(self) -> Dict[str, Any]:
        if not hasattr(self.client, "notification_health"):
            raise RuntimeError("configured source does not support notifications")
        return self.client.notification_health()

    def notification_destinations(self) -> Dict[str, Any]:
        if not hasattr(self.client, "notification_destinations"):
            raise RuntimeError("configured source does not support notifications")
        return self.client.notification_destinations()

    def notification_detail(self, notification_id: str) -> Dict[str, Any]:
        if NOTIFICATION_ID_PATTERN.fullmatch(notification_id) is None:
            raise ValueError("invalid notification ID")
        if not hasattr(self.client, "notification_detail"):
            raise RuntimeError("configured source does not support notifications")
        return self.client.notification_detail(notification_id)

    def notification_process(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_notification_process(payload)
        if not hasattr(self.client, "notification_process"):
            raise RuntimeError("configured source does not support notifications")
        return self.client.notification_process(payload)

    def notification_acknowledge(
        self, notification_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        if NOTIFICATION_ID_PATTERN.fullmatch(notification_id) is None:
            raise ValueError("invalid notification ID")
        validate_notification_acknowledgment(payload)
        if not hasattr(self.client, "notification_acknowledge"):
            raise RuntimeError("configured source does not support notifications")
        return self.client.notification_acknowledge(notification_id, payload)

    def notification_provider_acknowledge(
        self, delivery_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        if NOTIFICATION_DELIVERY_ID_PATTERN.fullmatch(delivery_id) is None:
            raise ValueError("invalid notification delivery ID")
        validate_provider_acknowledgment(payload)
        if not hasattr(self.client, "notification_provider_acknowledge"):
            raise RuntimeError("configured source does not support notifications")
        return self.client.notification_provider_acknowledge(delivery_id, payload)

    def notification_redrive(
        self, delivery_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        if NOTIFICATION_DELIVERY_ID_PATTERN.fullmatch(delivery_id) is None:
            raise ValueError("invalid notification delivery ID")
        validate_notification_redrive(payload)
        if not hasattr(self.client, "notification_redrive"):
            raise RuntimeError("configured source does not support notifications")
        return self.client.notification_redrive(delivery_id, payload)

    def response_executions(self) -> Dict[str, Any]:
        if not hasattr(self.client, "response_executions"):
            raise RuntimeError("configured source does not support response automation")
        return self.client.response_executions()

    def response_health(self) -> Dict[str, Any]:
        if not hasattr(self.client, "response_health"):
            raise RuntimeError("configured source does not support response automation")
        return self.client.response_health()

    def response_connectors(self) -> Dict[str, Any]:
        if not hasattr(self.client, "response_connectors"):
            raise RuntimeError("configured source does not support response automation")
        return self.client.response_connectors()

    def response_control(self) -> Dict[str, Any]:
        if not hasattr(self.client, "response_control"):
            raise RuntimeError("configured source does not support response automation")
        return self.client.response_control()

    def response_playbooks(self) -> Dict[str, Any]:
        if not hasattr(self.client, "response_playbooks"):
            raise RuntimeError("configured source does not support response automation")
        return self.client.response_playbooks()

    def response_detail(self, execution_id: str) -> Dict[str, Any]:
        if RESPONSE_EXECUTION_ID_PATTERN.fullmatch(execution_id) is None:
            raise ValueError("invalid response execution ID")
        if not hasattr(self.client, "response_detail"):
            raise RuntimeError("configured source does not support response automation")
        return self.client.response_detail(execution_id)

    def response_action(
        self, execution_id: str, action: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        if RESPONSE_EXECUTION_ID_PATTERN.fullmatch(execution_id) is None:
            raise ValueError("invalid response execution ID")
        if action in {"request-live", "request-rollback"}:
            validate_response_mutation(payload)
        elif action in {"approve", "approve-rollback"}:
            validate_response_approval(payload)
        elif action in {"execute", "rollback"}:
            validate_response_empty(payload)
        else:
            raise ValueError("invalid response execution action")
        if not hasattr(self.client, "response_action"):
            raise RuntimeError("configured source does not support response automation")
        return self.client.response_action(execution_id, action, payload)

    def response_kill_switch(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_response_kill_switch(payload)
        if not hasattr(self.client, "response_kill_switch"):
            raise RuntimeError("configured source does not support response automation")
        return self.client.response_kill_switch(payload)

    def response_playbook_create(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_response_playbook_create(payload)
        if not hasattr(self.client, "response_playbook_create"):
            raise RuntimeError("configured source does not support response automation")
        return self.client.response_playbook_create(payload)

    def response_playbook_action(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_response_playbook_action(payload)
        if not hasattr(self.client, "response_playbook_action"):
            raise RuntimeError("configured source does not support response automation")
        return self.client.response_playbook_action(payload)

    def search(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_search_request(payload)
        if not hasattr(self.client, "search"):
            raise RuntimeError("configured source does not support indexed search")
        return self.client.search(payload)

    def aggregate(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_aggregation_request(payload)
        if not hasattr(self.client, "aggregate"):
            raise RuntimeError("configured source does not support aggregation")
        return self.client.aggregate(payload)

    def list_hunts(self) -> Dict[str, Any]:
        if not hasattr(self.client, "list_hunts"):
            raise RuntimeError("configured source does not support saved hunts")
        return self.client.list_hunts()

    def save_hunt(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_saved_hunt(payload)
        if not hasattr(self.client, "save_hunt"):
            raise RuntimeError("configured source does not support saved hunts")
        return self.client.save_hunt(payload)

    def evidence_pivot(self, evidence_id: str) -> Dict[str, Any]:
        if EVIDENCE_ID_PATTERN.fullmatch(evidence_id) is None:
            raise ValueError("invalid evidence ID")
        if not hasattr(self.client, "evidence_pivot"):
            raise RuntimeError("configured source does not support evidence pivots")
        return self.client.evidence_pivot(evidence_id)

    def inventory(self) -> Dict[str, Any]:
        if not hasattr(self.client, "inventory"):
            raise RuntimeError("configured source does not support inventory")
        return self.client.inventory()

    def inventory_summary(self) -> Dict[str, Any]:
        if not hasattr(self.client, "inventory_summary"):
            raise RuntimeError("configured source does not support inventory")
        return self.client.inventory_summary()

    def inventory_detail(self, component_id: str) -> Dict[str, Any]:
        if COMPONENT_ID_PATTERN.fullmatch(component_id) is None:
            raise ValueError("invalid inventory component ID")
        if not hasattr(self.client, "inventory_detail"):
            raise RuntimeError("configured source does not support inventory")
        return self.client.inventory_detail(component_id)

    def model_gateway_status(self) -> Dict[str, Any]:
        if not hasattr(self.client, "model_gateway_status"):
            raise RuntimeError("configured source does not support model governance")
        return self.client.model_gateway_status()

    def graph(self, as_of: Optional[str] = None) -> Dict[str, Any]:
        if as_of is not None:
            validate_graph_time(as_of)
        if not hasattr(self.client, "graph"):
            raise RuntimeError("configured source does not support security graph")
        return self.client.graph(as_of)

    def graph_summary(self, as_of: Optional[str] = None) -> Dict[str, Any]:
        if as_of is not None:
            validate_graph_time(as_of)
        if not hasattr(self.client, "graph_summary"):
            raise RuntimeError("configured source does not support security graph")
        return self.client.graph_summary(as_of)

    def graph_analysis(self, path: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_graph_analysis(path, payload)
        if not hasattr(self.client, "graph_analysis"):
            raise RuntimeError("configured source does not support security graph")
        upstream_path = "/v1" + path.removeprefix("/api")
        return self.client.graph_analysis(upstream_path, payload)

    def posture_summary(self) -> Dict[str, Any]:
        if not hasattr(self.client, "posture_summary"):
            raise RuntimeError("configured source does not support posture")
        return self.client.posture_summary()

    def posture_checks(self) -> Dict[str, Any]:
        if not hasattr(self.client, "posture_checks"):
            raise RuntimeError("configured source does not support posture")
        return self.client.posture_checks()

    def posture_findings(self) -> Dict[str, Any]:
        if not hasattr(self.client, "posture_findings"):
            raise RuntimeError("configured source does not support posture")
        return self.client.posture_findings()

    def posture_trends(self) -> Dict[str, Any]:
        if not hasattr(self.client, "posture_trends"):
            raise RuntimeError("configured source does not support posture")
        return self.client.posture_trends()

    def posture_detail(self, finding_id: str) -> Dict[str, Any]:
        if POSTURE_FINDING_ID_PATTERN.fullmatch(finding_id) is None:
            raise ValueError("invalid posture finding ID")
        if not hasattr(self.client, "posture_detail"):
            raise RuntimeError("configured source does not support posture")
        return self.client.posture_detail(finding_id)

    def posture_scan(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_posture_scan(payload)
        if not hasattr(self.client, "posture_scan"):
            raise RuntimeError("configured source does not support posture")
        return self.client.posture_scan(payload)

    def posture_exception(self, finding_id: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        if POSTURE_FINDING_ID_PATTERN.fullmatch(finding_id) is None:
            raise ValueError("invalid posture finding ID")
        validate_posture_exception(payload)
        if not hasattr(self.client, "posture_exception"):
            raise RuntimeError("configured source does not support posture")
        return self.client.posture_exception(finding_id, payload)

    def posture_revoke_exception(self, exception_id: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        if POSTURE_EXCEPTION_ID_PATTERN.fullmatch(exception_id) is None:
            raise ValueError("invalid posture exception ID")
        validate_posture_revoke(payload)
        if not hasattr(self.client, "posture_revoke_exception"):
            raise RuntimeError("configured source does not support posture")
        return self.client.posture_revoke_exception(exception_id, payload)

    def content_list(self) -> Dict[str, Any]:
        if not hasattr(self.client, "content_list"):
            raise RuntimeError("configured source does not support detection content")
        return self.client.content_list()

    def content_health(self) -> Dict[str, Any]:
        if not hasattr(self.client, "content_health"):
            raise RuntimeError("configured source does not support detection content")
        return self.client.content_health()

    def content_packs(self) -> Dict[str, Any]:
        if not hasattr(self.client, "content_packs"):
            raise RuntimeError("configured source does not support detection content")
        return self.client.content_packs()

    def content_detail(self, content_id: str) -> Dict[str, Any]:
        validate_content_id(content_id)
        if not hasattr(self.client, "content_detail"):
            raise RuntimeError("configured source does not support detection content")
        return self.client.content_detail(content_id)

    def content_history(self, content_id: str) -> Dict[str, Any]:
        validate_content_id(content_id)
        if not hasattr(self.client, "content_history"):
            raise RuntimeError("configured source does not support detection content")
        return self.client.content_history(content_id)

    def content_create(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_content_definition(payload)
        if not hasattr(self.client, "content_create"):
            raise RuntimeError("configured source does not support detection content")
        return self.client.content_create(payload)

    def content_update(self, content_id: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_content_id(content_id)
        validate_content_definition(payload)
        if not hasattr(self.client, "content_update"):
            raise RuntimeError("configured source does not support detection content")
        return self.client.content_update(content_id, payload)

    def content_action(
        self, content_id: str, action: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        validate_content_id(content_id)
        normalize_content_action(action, payload)
        if not hasattr(self.client, "content_action"):
            raise RuntimeError("configured source does not support detection content")
        return self.client.content_action(content_id, action, payload)

    def content_export_pack(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_content_pack_export(payload)
        if not hasattr(self.client, "content_export_pack"):
            raise RuntimeError("configured source does not support detection content")
        return self.client.content_export_pack(payload)

    def content_import_pack(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_content_pack_import(payload)
        if not hasattr(self.client, "content_import_pack"):
            raise RuntimeError("configured source does not support detection content")
        return self.client.content_import_pack(payload)

    def model_gateway_health(self) -> Dict[str, Any]:
        if not hasattr(self.client, "model_gateway_health"):
            raise RuntimeError("configured source does not support the model gateway")
        return self.client.model_gateway_health()

    def model_gateway_routes(self) -> Dict[str, Any]:
        if not hasattr(self.client, "model_gateway_routes"):
            raise RuntimeError("configured source does not support the model gateway")
        return self.client.model_gateway_routes()

    def model_gateway_qualifications(self) -> Dict[str, Any]:
        if not hasattr(self.client, "model_gateway_qualifications"):
            raise RuntimeError("configured source does not support the model gateway")
        return self.client.model_gateway_qualifications()

    def model_gateway_calls(self) -> Dict[str, Any]:
        if not hasattr(self.client, "model_gateway_calls"):
            raise RuntimeError("configured source does not support the model gateway")
        return self.client.model_gateway_calls()

    def model_gateway_secrets(self) -> Dict[str, Any]:
        if not hasattr(self.client, "model_gateway_secrets"):
            raise RuntimeError("configured source does not support the model gateway")
        return self.client.model_gateway_secrets()

    def behavior_baselines(self) -> Dict[str, Any]:
        if not hasattr(self.client, "behavior_baselines"):
            raise RuntimeError("configured source does not support behavioral analytics")
        return self.client.behavior_baselines()

    def behavior_assessments(self, *, anomalies_only: bool = False) -> Dict[str, Any]:
        if not hasattr(self.client, "behavior_assessments"):
            raise RuntimeError("configured source does not support behavioral analytics")
        return self.client.behavior_assessments(anomalies_only=anomalies_only)

    def behavior_assessment(self, assessment_id: str) -> Dict[str, Any]:
        if re.fullmatch(r"bhas_[A-Za-z0-9]+", assessment_id) is None:
            raise ValueError("invalid behavior assessment ID")
        if not hasattr(self.client, "behavior_assessment"):
            raise RuntimeError("configured source does not support behavioral analytics")
        return self.client.behavior_assessment(assessment_id)

    def behavior_health(self) -> Dict[str, Any]:
        if not hasattr(self.client, "behavior_health"):
            raise RuntimeError("configured source does not support behavioral analytics")
        return self.client.behavior_health()

    def behavior_config(self) -> Dict[str, Any]:
        if not hasattr(self.client, "behavior_config"):
            raise RuntimeError("configured source does not support behavioral analytics")
        return self.client.behavior_config()

    def behavior_drift(self, entity_ref: Optional[str] = None) -> Dict[str, Any]:
        if entity_ref is not None and BEHAVIOR_ENTITY_PATTERN.fullmatch(entity_ref) is None:
            raise ValueError("invalid behavior entity reference")
        if not hasattr(self.client, "behavior_drift"):
            raise RuntimeError("configured source does not support behavioral analytics")
        return self.client.behavior_drift(entity_ref)

    def behavior_tune(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_behavior_tuning(payload)
        if not hasattr(self.client, "behavior_tune"):
            raise RuntimeError("configured source does not support behavioral analytics")
        return self.client.behavior_tune(payload)

    def correlation_incidents(self) -> Dict[str, Any]:
        if not hasattr(self.client, "correlation_incidents"):
            raise RuntimeError("configured source does not support incident correlation")
        return self.client.correlation_incidents()

    def correlation_incident(self, incident_id: str) -> Dict[str, Any]:
        if CORRELATED_INCIDENT_PATTERN.fullmatch(incident_id) is None:
            raise ValueError("invalid correlated incident ID")
        if not hasattr(self.client, "correlation_incident"):
            raise RuntimeError("configured source does not support incident correlation")
        return self.client.correlation_incident(incident_id)

    def correlation_health(self) -> Dict[str, Any]:
        if not hasattr(self.client, "correlation_health"):
            raise RuntimeError("configured source does not support incident correlation")
        return self.client.correlation_health()

    def correlation_decisions(self) -> Dict[str, Any]:
        if not hasattr(self.client, "correlation_decisions"):
            raise RuntimeError("configured source does not support incident correlation")
        return self.client.correlation_decisions()

    def correlation_transition(self, incident_id: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_correlation_transition(payload)
        if not hasattr(self.client, "correlation_transition"):
            raise RuntimeError("configured source does not support incident correlation")
        return self.client.correlation_transition(incident_id, payload)

    def correlation_merge(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_correlation_merge(payload)
        if not hasattr(self.client, "correlation_merge"):
            raise RuntimeError("configured source does not support incident correlation")
        return self.client.correlation_merge(payload)

    def correlation_split(self, incident_id: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        validate_correlation_split(payload)
        if not hasattr(self.client, "correlation_split"):
            raise RuntimeError("configured source does not support incident correlation")
        return self.client.correlation_split(incident_id, payload)


def make_handler(bridge: LiveBridge, port: int) -> Type[BaseHTTPRequestHandler]:
    class LiveBridgeHandler(BaseHTTPRequestHandler):
        server_version = "agentsec-live-bridge/0.2"

        def _origin_allowed(self) -> bool:
            origin = self.headers.get("Origin")
            return origin is None or origin in ALLOWED_ORIGINS

        def _request_allowed(self) -> bool:
            active_port = getattr(self.server, "server_port", port)
            allowed_hosts = {
                "127.0.0.1:%d" % active_port,
                "localhost:%d" % active_port,
            }
            return self.headers.get("Host") in allowed_hosts and self._origin_allowed()

        def _json(self, status: HTTPStatus, payload: Mapping[str, Any]) -> None:
            encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status.value)
            origin = self.headers.get("Origin")
            if origin in ALLOWED_ORIGINS:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'")
            self.end_headers()
            self.wfile.write(encoded)

        def _read_json(self) -> Dict[str, Any]:
            if self.headers.get_content_type() != "application/json":
                raise TypeError("json_required")
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise OverflowError("invalid_size") from exc
            if size <= 0 or size > MAX_BODY_BYTES:
                raise OverflowError("invalid_size")
            payload = json.loads(self.rfile.read(size).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("object_required")
            return payload

        def do_OPTIONS(self) -> None:
            path = urlsplit(self.path).path
            writable = path in {
                "/api/forge", "/api/search", "/api/search/aggregate", "/api/hunts",
                "/api/simulation/mutations", "/api/simulation/runs",
                "/api/posture/scans", "/api/detection/content",
                "/api/detection/content/packs/export", "/api/detection/content/packs/import",
                "/api/behavior/config",
                "/api/correlation/incidents/merge",
                "/api/case-teams",
            } or path in GRAPH_ANALYSIS_PATHS or re.fullmatch(
                r"/api/alerts/fnd_[A-Za-z0-9]+/transition", path
            ) or re.fullmatch(
                r"/api/posture/findings/pstf_[0-9a-f]{32}/exceptions", path
            ) or re.fullmatch(
                r"/api/posture/exceptions/pste_[A-Za-z0-9]+/revoke", path
            ) or re.fullmatch(
                r"/api/detection/content/drc_[A-Za-z0-9]+", path
            ) or re.fullmatch(
                r"/api/detection/content/drc_[A-Za-z0-9]+/(?:validate|backtest|submit|review|shadow|shadow-evaluate|publish|rollback)", path
            ) or re.fullmatch(
                r"/api/correlation/incidents/inc_[A-Za-z0-9]+/(?:transition|split)", path
            ) or re.fullmatch(
                r"/api/cases/case_[0-9a-f]{32}/(?:assign|acknowledge|comments|tasks|attachments|relationships|start|request-review|review|close)", path
            ) or re.fullmatch(
                r"/api/cases/case_[0-9a-f]{32}/tasks/ctk_[0-9a-f]{32}/transition", path
            ) or re.fullmatch(
                r"/api/cases/case_[0-9a-f]{32}/attachments/cat_[0-9a-f]{32}/scan", path
            ) or re.fullmatch(
                r"/api/simulation/runs/simrun_[0-9a-f]{32}/replay", path
            )
            if not self._request_allowed() or not writable:
                self._json(HTTPStatus.FORBIDDEN, {"error": "request_not_allowed"})
                return
            self.send_response(HTTPStatus.NO_CONTENT.value)
            origin = self.headers.get("Origin")
            if origin in ALLOWED_ORIGINS:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "POST, PUT, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Max-Age", "600")
            self.end_headers()

        def do_GET(self) -> None:
            if not self._request_allowed():
                self._json(HTTPStatus.FORBIDDEN, {"error": "request_not_allowed"})
                return
            parsed = urlsplit(self.path)
            path = parsed.path
            if path == "/health":
                self._json(
                    HTTPStatus.OK,
                    {
                        "status": "ok",
                        "service": "agentsec-live-bridge",
                        "source": bridge.source,
                    },
                )
                return
            try:
                if path == "/api/simulation/catalog":
                    if parsed.query:
                        raise ValueError("simulation catalog filters are not supported")
                    response = bridge.simulation_catalog()
                elif re.fullmatch(
                    r"/api/simulation/scenarios/sim_[a-z0-9_]{3,96}/versions/[0-9]+\.[0-9]+\.[0-9]+",
                    path,
                ):
                    if parsed.query:
                        raise ValueError("simulation scenario filters are not supported")
                    parts = path.split("/")
                    response = bridge.simulation_scenario(parts[4], parts[6])
                elif path == "/api/simulation/runs":
                    if parsed.query:
                        raise ValueError("simulation run filters are not supported")
                    response = bridge.simulation_runs()
                elif re.fullmatch(r"/api/simulation/runs/simrun_[0-9a-f]{32}", path):
                    if parsed.query:
                        raise ValueError("simulation run filters are not supported")
                    response = bridge.simulation_run_detail(path.split("/")[4])
                elif path == "/api/platform":
                    if parsed.query:
                        raise ValueError("platform filters are not supported")
                    response = bridge.platform_snapshot()
                elif path == "/api/alerts":
                    response = bridge.alerts()
                elif path == "/api/response/executions":
                    if parsed.query:
                        raise ValueError("response filters are not supported")
                    response = bridge.response_executions()
                elif path == "/api/response/health":
                    if parsed.query:
                        raise ValueError("response health filters are not supported")
                    response = bridge.response_health()
                elif path == "/api/response/connectors":
                    if parsed.query:
                        raise ValueError("response connector filters are not supported")
                    response = bridge.response_connectors()
                elif path == "/api/response/control":
                    if parsed.query:
                        raise ValueError("response control filters are not supported")
                    response = bridge.response_control()
                elif path == "/api/response/playbooks":
                    if parsed.query:
                        raise ValueError("response playbook filters are not supported")
                    response = bridge.response_playbooks()
                elif re.fullmatch(r"/api/response/executions/rex_[0-9a-f]{32}", path):
                    if parsed.query:
                        raise ValueError("response detail filters are not supported")
                    response = bridge.response_detail(path.split("/")[4])
                elif path == "/api/notifications":
                    if parsed.query:
                        raise ValueError("notification filters are not supported")
                    response = bridge.notifications()
                elif path == "/api/notifications/health":
                    if parsed.query:
                        raise ValueError("notification health filters are not supported")
                    response = bridge.notification_health()
                elif path == "/api/notification-destinations":
                    if parsed.query:
                        raise ValueError("notification destination filters are not supported")
                    response = bridge.notification_destinations()
                elif re.fullmatch(r"/api/notifications/ntf_[0-9a-f]{32}", path):
                    if parsed.query:
                        raise ValueError("notification detail filters are not supported")
                    response = bridge.notification_detail(path.split("/")[3])
                elif path == "/api/cases":
                    if parsed.query:
                        raise ValueError("case filters are not supported by the bridge")
                    response = bridge.cases()
                elif path == "/api/cases/health":
                    if parsed.query:
                        raise ValueError("case health filters are not supported")
                    response = bridge.case_health()
                elif path == "/api/case-teams":
                    if parsed.query:
                        raise ValueError("case team filters are not supported")
                    response = bridge.case_teams()
                elif re.fullmatch(r"/api/cases/case_[0-9a-f]{32}", path):
                    if parsed.query:
                        raise ValueError("case detail filters are not supported")
                    response = bridge.case_detail(path.split("/")[3])
                elif path == "/api/correlation/incidents":
                    if parsed.query:
                        raise ValueError("correlation incident filters are not supported")
                    response = bridge.correlation_incidents()
                elif path == "/api/correlation/health":
                    if parsed.query:
                        raise ValueError("correlation health filters are not supported")
                    response = bridge.correlation_health()
                elif path == "/api/correlation/decisions":
                    if parsed.query:
                        raise ValueError("correlation decision filters are not supported")
                    response = bridge.correlation_decisions()
                elif re.fullmatch(r"/api/correlation/incidents/inc_[A-Za-z0-9]+", path):
                    if parsed.query:
                        raise ValueError("correlation incident filters are not supported")
                    response = bridge.correlation_incident(path.split("/")[4])
                elif path == "/api/behavior/baselines":
                    if parsed.query:
                        raise ValueError("behavior baseline filters are not supported")
                    response = bridge.behavior_baselines()
                elif path in {"/api/behavior/assessments", "/api/behavior/anomalies"}:
                    if parsed.query:
                        raise ValueError("behavior assessment filters are not supported")
                    response = bridge.behavior_assessments(
                        anomalies_only=path.endswith("/anomalies")
                    )
                elif path == "/api/behavior/health":
                    if parsed.query:
                        raise ValueError("behavior health filters are not supported")
                    response = bridge.behavior_health()
                elif path == "/api/behavior/config":
                    if parsed.query:
                        raise ValueError("behavior config filters are not supported")
                    response = bridge.behavior_config()
                elif path == "/api/behavior/drift":
                    filters = parse_qs(parsed.query, keep_blank_values=False)
                    if set(filters) - {"entity_ref"} or any(
                        len(values) != 1 for values in filters.values()
                    ):
                        raise ValueError("behavior drift filters are invalid")
                    entity_ref = (filters.get("entity_ref") or [None])[0]
                    response = bridge.behavior_drift(entity_ref)
                elif re.fullmatch(r"/api/behavior/assessments/bhas_[A-Za-z0-9]+", path):
                    if parsed.query:
                        raise ValueError("behavior assessment filters are not supported")
                    response = bridge.behavior_assessment(path.split("/")[4])
                elif path == "/api/detection/content":
                    if parsed.query:
                        raise ValueError("detection content filters are not supported")
                    response = bridge.content_list()
                elif path == "/api/detection/content/health":
                    if parsed.query:
                        raise ValueError("detection content health filters are not supported")
                    response = bridge.content_health()
                elif path == "/api/detection/content/packs":
                    if parsed.query:
                        raise ValueError("detection content pack filters are not supported")
                    response = bridge.content_packs()
                elif re.fullmatch(r"/api/detection/content/drc_[A-Za-z0-9]+/history", path):
                    response = bridge.content_history(path.split("/")[4])
                elif re.fullmatch(r"/api/detection/content/drc_[A-Za-z0-9]+", path):
                    response = bridge.content_detail(path.split("/")[4])
                elif path == "/api/posture/summary":
                    response = bridge.posture_summary()
                elif path == "/api/posture/checks":
                    response = bridge.posture_checks()
                elif path == "/api/posture/findings":
                    response = bridge.posture_findings()
                elif path == "/api/posture/trends":
                    response = bridge.posture_trends()
                elif re.fullmatch(r"/api/posture/findings/pstf_[0-9a-f]{32}", path):
                    response = bridge.posture_detail(path.split("/")[4])
                elif path in {"/api/graph", "/api/graph/summary"}:
                    filters = parse_qs(parsed.query, keep_blank_values=False)
                    if set(filters) - {"as_of"} or any(
                        len(values) != 1 for values in filters.values()
                    ):
                        raise ValueError("graph filters are invalid")
                    as_of = (filters.get("as_of") or [None])[0]
                    if as_of is not None:
                        validate_graph_time(as_of)
                    response = (
                        bridge.graph_summary(as_of)
                        if path.endswith("/summary")
                        else bridge.graph(as_of)
                    )
                elif path == "/api/inventory":
                    response = bridge.inventory()
                elif path == "/api/inventory/summary":
                    response = bridge.inventory_summary()
                elif re.fullmatch(r"/api/inventory/cmp_[A-Za-z0-9]+", path):
                    response = bridge.inventory_detail(path.split("/")[3])
                elif path == "/api/model-gateway":
                    if parsed.query:
                        raise ValueError("model gateway filters are not supported")
                    response = bridge.model_gateway_status()
                elif path == "/api/hunts":
                    response = bridge.list_hunts()
                elif re.fullmatch(r"/api/evidence/evd_[A-Za-z0-9]+/pivot", path):
                    response = bridge.evidence_pivot(path.split("/")[3])
                else:
                    match = re.fullmatch(r"/api/alerts/(fnd_[A-Za-z0-9]+)", path)
                    if match is None:
                        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                        return
                    response = bridge.detail(match.group(1))
                self._json(HTTPStatus.OK, response)
            except KeyError:
                self._json(HTTPStatus.NOT_FOUND, {"error": "incident_not_found"})
            except ValueError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            except (RuntimeError, json.JSONDecodeError, subprocess.TimeoutExpired):
                self._json(HTTPStatus.BAD_GATEWAY, {"error": "upstream_unavailable"})

        def do_POST(self) -> None:
            if (
                not self._request_allowed()
                or self.headers.get("Origin") not in ALLOWED_ORIGINS
            ):
                self._json(HTTPStatus.FORBIDDEN, {"error": "request_not_allowed"})
                return
            path = urlsplit(self.path).path
            try:
                payload = self._read_json()
                if path == "/api/forge":
                    if set(payload) != {"preset"}:
                        raise ValueError("preset_only")
                    preset = payload.get("preset")
                    if not isinstance(preset, str) or preset not in PRESETS:
                        raise ValueError("unknown_preset")
                    response = bridge.forge(preset)
                elif path == "/api/simulation/mutations":
                    validate_simulation_mutation(payload)
                    response = bridge.simulation_mutate(payload)
                elif path == "/api/simulation/runs":
                    validate_simulation_run(payload)
                    response = bridge.simulation_run(payload)
                elif re.fullmatch(
                    r"/api/simulation/runs/simrun_[0-9a-f]{32}/replay", path
                ):
                    validate_simulation_replay(payload)
                    response = bridge.simulation_replay(path.split("/")[4], payload)
                elif re.fullmatch(
                    r"/api/response/executions/rex_[0-9a-f]{32}/(?:request-live|approve|execute|request-rollback|approve-rollback|rollback)",
                    path,
                ):
                    parts = path.split("/")
                    response = bridge.response_action(parts[4], parts[5], payload)
                elif path == "/api/response/control":
                    validate_response_kill_switch(payload)
                    response = bridge.response_kill_switch(payload)
                elif path == "/api/response/playbooks":
                    validate_response_playbook_create(payload)
                    response = bridge.response_playbook_create(payload)
                elif path == "/api/response/playbooks/action":
                    validate_response_playbook_action(payload)
                    response = bridge.response_playbook_action(payload)
                elif path == "/api/notifications/process":
                    validate_notification_process(payload)
                    response = bridge.notification_process(payload)
                elif re.fullmatch(
                    r"/api/notifications/ntf_[0-9a-f]{32}/acknowledge", path
                ):
                    validate_notification_acknowledgment(payload)
                    response = bridge.notification_acknowledge(
                        path.split("/")[3], payload
                    )
                elif re.fullmatch(
                    r"/api/notification-deliveries/ndv_[0-9a-f]{32}/provider-acknowledge",
                    path,
                ):
                    validate_provider_acknowledgment(payload)
                    response = bridge.notification_provider_acknowledge(
                        path.split("/")[3], payload
                    )
                elif re.fullmatch(
                    r"/api/notification-deliveries/ndv_[0-9a-f]{32}/redrive",
                    path,
                ):
                    validate_notification_redrive(payload)
                    response = bridge.notification_redrive(
                        path.split("/")[3], payload
                    )
                elif path == "/api/case-teams":
                    validate_case_team(payload)
                    response = bridge.case_team_create(payload)
                elif re.fullmatch(
                    r"/api/cases/case_[0-9a-f]{32}/(?:assign|acknowledge|comments|tasks|attachments|relationships|start|request-review|review|close)",
                    path,
                ):
                    parts = path.split("/")
                    response = bridge.case_action(parts[3], parts[4], payload)
                elif re.fullmatch(
                    r"/api/cases/case_[0-9a-f]{32}/tasks/ctk_[0-9a-f]{32}/transition",
                    path,
                ):
                    parts = path.split("/")
                    response = bridge.case_task_transition(parts[3], parts[5], payload)
                elif re.fullmatch(
                    r"/api/cases/case_[0-9a-f]{32}/attachments/cat_[0-9a-f]{32}/scan",
                    path,
                ):
                    parts = path.split("/")
                    response = bridge.case_attachment_scan(parts[3], parts[5], payload)
                elif path == "/api/correlation/incidents/merge":
                    response = bridge.correlation_merge(payload)
                elif re.fullmatch(r"/api/correlation/incidents/inc_[A-Za-z0-9]+/transition", path):
                    response = bridge.correlation_transition(path.split("/")[4], payload)
                elif re.fullmatch(r"/api/correlation/incidents/inc_[A-Za-z0-9]+/split", path):
                    response = bridge.correlation_split(path.split("/")[4], payload)
                elif path == "/api/behavior/config":
                    validate_behavior_tuning(payload)
                    response = bridge.behavior_tune(payload)
                elif path == "/api/detection/content":
                    validate_content_definition(payload)
                    response = bridge.content_create(payload)
                elif path == "/api/detection/content/packs/export":
                    response = bridge.content_export_pack(payload)
                elif path == "/api/detection/content/packs/import":
                    response = bridge.content_import_pack(payload)
                elif re.fullmatch(
                    r"/api/detection/content/drc_[A-Za-z0-9]+/(?:validate|backtest|submit|review|shadow|shadow-evaluate|publish|rollback)",
                    path,
                ):
                    parts = path.split("/")
                    response = bridge.content_action(parts[4], parts[5], payload)
                elif path == "/api/posture/scans":
                    validate_posture_scan(payload)
                    response = bridge.posture_scan(payload)
                elif re.fullmatch(r"/api/posture/findings/pstf_[0-9a-f]{32}/exceptions", path):
                    validate_posture_exception(payload)
                    response = bridge.posture_exception(path.split("/")[4], payload)
                elif re.fullmatch(r"/api/posture/exceptions/pste_[A-Za-z0-9]+/revoke", path):
                    validate_posture_revoke(payload)
                    response = bridge.posture_revoke_exception(path.split("/")[4], payload)
                elif path == "/api/search":
                    validate_search_request(payload)
                    response = bridge.search(payload)
                elif path == "/api/search/aggregate":
                    validate_aggregation_request(payload)
                    response = bridge.aggregate(payload)
                elif path == "/api/hunts":
                    validate_saved_hunt(payload)
                    response = bridge.save_hunt(payload)
                elif path in GRAPH_ANALYSIS_PATHS:
                    validate_graph_analysis(path, payload)
                    response = bridge.graph_analysis(path, payload)
                else:
                    match = re.fullmatch(
                        r"/api/alerts/(fnd_[A-Za-z0-9]+)/transition", path
                    )
                    if match is None:
                        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                        return
                    validate_transition(payload)
                    response = bridge.transition(
                        match.group(1),
                        action=str(payload["action"]),
                        actor=str(payload["actor"]),
                        reason=str(payload["reason"]),
                    )
                self._json(HTTPStatus.OK, response)
            except TypeError:
                self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "json_required"})
            except OverflowError:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "invalid_size"})
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            except KeyError:
                self._json(HTTPStatus.NOT_FOUND, {"error": "incident_not_found"})
            except (RuntimeError, subprocess.TimeoutExpired):
                self._json(
                    HTTPStatus.BAD_GATEWAY, {"error": "remote_authorization_failed"}
                )

        def do_PUT(self) -> None:
            if (
                not self._request_allowed()
                or self.headers.get("Origin") not in ALLOWED_ORIGINS
            ):
                self._json(HTTPStatus.FORBIDDEN, {"error": "request_not_allowed"})
                return
            path = urlsplit(self.path).path
            match = re.fullmatch(r"/api/detection/content/(drc_[A-Za-z0-9]+)", path)
            if match is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            try:
                payload = self._read_json()
                validate_content_definition(payload)
                response = bridge.content_update(match.group(1), payload)
                self._json(HTTPStatus.OK, response)
            except TypeError:
                self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "json_required"})
            except OverflowError:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "invalid_size"})
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            except KeyError:
                self._json(HTTPStatus.NOT_FOUND, {"error": "content_not_found"})
            except (RuntimeError, subprocess.TimeoutExpired):
                self._json(HTTPStatus.BAD_GATEWAY, {"error": "upstream_unavailable"})

        def log_message(self, format: str, *args: object) -> None:
            return

    return LiveBridgeHandler


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the loopback-only AgentSec live UI bridge"
    )
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--region", default=DEFAULT_REGION)
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--instance-id",
        help="Use the service on this separately approved EC2 instance through SSM",
    )
    source.add_argument(
        "--local-service-url",
        help=(
            "Use a local loopback service origin; defaults to %s when no instance "
            "ID is supplied" % DEFAULT_LOCAL_SERVICE_URL
        ),
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.port < 1024 or args.port > 65535:
        raise ValueError("port must be between 1024 and 65535")
    if args.instance_id:
        client: Any = AwsSsmClient(
            profile=args.profile,
            region=args.region,
            instance_id=args.instance_id,
        )
    else:
        token = os.environ.get("AGENTSEC_INGEST_TOKEN", "")
        client = LocalServiceClient(
            base_url=args.local_service_url or DEFAULT_LOCAL_SERVICE_URL,
            token=token,
        )
    server = ThreadingHTTPServer(
        ("127.0.0.1", args.port), make_handler(LiveBridge(client), args.port)
    )
    print(
        "AgentSec live UI bridge (%s): http://127.0.0.1:%d"
        % (client.source, args.port)
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
