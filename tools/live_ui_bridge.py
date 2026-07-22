#!/usr/bin/env python3
"""Loopback-only bridge between the local AgentSec UI and the private EC2 service.

The browser never receives AWS credentials or the service ingestion token. The
bridge executes only two fixed AWS SSM operations: read recent sanitized command
outputs, and submit one of the allowlisted synthetic AgentEvent presets.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Type
from urllib.parse import urlsplit
from uuid import uuid4


DEFAULT_PROFILE = "agentsec-deploy"
DEFAULT_REGION = "ap-northeast-1"
DEFAULT_INSTANCE_ID = "i-082370aa89a20ff93"
DEFAULT_PORT = 8765
MAX_BODY_BYTES = 4096
ALLOWED_ORIGINS = {"http://localhost:3000", "http://127.0.0.1:3000"}
DISPLAY_TIMEZONE = timezone(timedelta(hours=9), name="JST")


ALERT_CATALOG: Dict[str, Dict[str, Any]] = {
    "indirect_prompt_injection": {
        "title": "Untrusted content influenced an effectful agent action",
        "reason": "Untrusted instructions reached a proposed agent effect and were denied.",
        "policy": "deterministic-v1",
        "evidence": ["Untrusted instruction", "Source-to-effect path"],
    },
    "secret_egress": {
        "title": "Secret data proposed for external egress",
        "reason": "Secret-class data intersected an external sink and was denied.",
        "policy": "deterministic-v1",
        "evidence": ["Secret data class", "External destination"],
    },
    "authority_violation": {
        "title": "Agent requested an operation outside delegated authority",
        "reason": "The requested operation was outside the agent's effective grant.",
        "policy": "authority-v1",
        "evidence": ["Authority intersection", "Operation outside grant"],
    },
    "persistent_memory_poisoning": {
        "title": "Persisted untrusted memory influenced a later effect",
        "reason": "Adversarial provenance survived into a cross-session effect proposal.",
        "policy": "provenance-v1",
        "evidence": ["Cross-session lineage", "Adversarial trust label"],
    },
    "mcp_schema_drift": {
        "title": "Observed MCP tool schema differs from approved manifest",
        "reason": "The observed tool contract drifted from the approved ABOM manifest.",
        "policy": "abom-drift-v1",
        "evidence": ["Declared schema digest", "Observed schema digest mismatch"],
    },
    "destructive_action_without_approval": {
        "title": "Destructive action lacks exact-action approval",
        "reason": "A high-impact operation was proposed without a bound approval token.",
        "policy": "approval-v1",
        "evidence": ["Destructive operation", "Approval absent"],
    },
}


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


REMOTE_SCRIPT = r"""import base64
import json
import os
import sys
import urllib.request
from urllib.parse import urlparse

from agentsec.contracts import AgentEvent
from agentsec.runtime import build_pipeline_from_environment

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
        "occurred_at", "agent_id", "operation", "resource", "destination",
        "source_type", "source_id", "source_trust", "data_classes",
        "authority_operations", "indicators", "tool_name",
        "declared_tool_schema_digest", "observed_tool_schema_digest"
    )
}

authoritative_details = authorization.get("incidents", [])
if not isinstance(authoritative_details, list):
    authoritative_details = []
authoritative_details = [item for item in authoritative_details if isinstance(item, dict)]
incident_details = []
trace_status = "unavailable"
try:
    normalized = AgentEvent.model_validate(event)
    replay = build_pipeline_from_environment().process(normalized)
    service_types = sorted(item["alert_type"] for item in authorization["alerts"])
    replay_types = sorted(item.alert.alert_type for item in replay.alerts)
    if service_types != replay_types or authorization["overall_action"] != replay.overall_action.value:
        raise ValueError("authorization and replay did not match")

    parsed_destination = urlparse(normalized.destination or "")
    destination_class = (
        "external-network"
        if parsed_destination.scheme in {"http", "https"}
        else (parsed_destination.scheme or "none")
    )
    resource_class = normalized.resource.split("://", 1)[0] if "://" in normalized.resource else "opaque"
    authority_match = normalized.operation in normalized.authority_operations
    enrichment = [
        {
            "kind": "Source provenance",
            "status": "risk" if normalized.source_trust.value in {"external-untrusted", "suspected-adversarial"} else "verified",
            "value": "%s · %s" % (normalized.source_type, normalized.source_trust.value),
            "evidence": normalized.source_id,
            "source": "AgentEvent provenance metadata",
            "impact": "Untrusted provenance retained" if normalized.source_trust.value in {"external-untrusted", "suspected-adversarial"} else "Authenticated or internal source",
        },
        {
            "kind": "Authority intersection",
            "status": "verified" if authority_match else "risk",
            "value": "requested %s · allowed %s" % (normalized.operation, sorted(normalized.authority_operations)),
            "evidence": normalized.event_id,
            "source": "Effective authority metadata",
            "impact": "Operation inside effective grant" if authority_match else "Operation exceeds effective grant",
        },
        {
            "kind": "Data classification",
            "status": "risk" if "secret" in normalized.data_classes else "verified",
            "value": "%s · %s" % (resource_class, sorted(normalized.data_classes) or ["unclassified"]),
            "evidence": normalized.resource,
            "source": "Resource and data-class labels",
            "impact": "Secret-class material present" if "secret" in normalized.data_classes else "No secret label observed",
        },
        {
            "kind": "Destination analysis",
            "status": "risk" if destination_class == "external-network" else "verified",
            "value": destination_class,
            "evidence": normalized.destination or "no destination",
            "source": "Destination classifier",
            "impact": "External network sink" if destination_class == "external-network" else "No external network sink",
        },
        {
            "kind": "Tool contract",
            "status": "risk" if normalized.declared_tool_schema_digest and normalized.declared_tool_schema_digest != normalized.observed_tool_schema_digest else "verified",
            "value": normalized.tool_name or "no tool declared",
            "evidence": "declared=%s · observed=%s" % (normalized.declared_tool_schema_digest or "none", normalized.observed_tool_schema_digest or "none"),
            "source": "ABOM event observation",
            "impact": "Schema digest drift observed" if normalized.declared_tool_schema_digest and normalized.declared_tool_schema_digest != normalized.observed_tool_schema_digest else "No schema drift observed",
        },
        {
            "kind": "Memory persistence",
            "status": "risk" if normalized.source_type == "memory" and "memory_poisoning" in normalized.indicators else "verified",
            "value": "cross-session" if normalized.source_type == "memory" else "not memory sourced",
            "evidence": ", ".join(sorted(normalized.indicators)) or "no persistence indicators",
            "source": "Memory and indicator metadata",
            "impact": "Persisted adversarial influence" if normalized.source_type == "memory" and "memory_poisoning" in normalized.indicators else "No memory-poisoning path",
        },
    ]
    base_scores = {"info": 10, "low": 25, "medium": 50, "high": 75, "critical": 95}
    for item in replay.alerts:
        contributions = [
            {
                "label": "Base %s severity" % item.alert.severity.value,
                "delta": base_scores[item.alert.severity.value],
                "evidence": item.alert.detector_id,
            }
        ]
        if item.alert.confidence >= 0.95:
            contributions.append({"label": "High-confidence detection", "delta": 3, "evidence": "confidence %.2f" % item.alert.confidence})
        if item.alert.source_trust.value in {"external-untrusted", "suspected-adversarial"}:
            contributions.append({"label": "Untrusted provenance", "delta": 2, "evidence": item.alert.source_trust.value})
        incident_details.append(
            {
                "trace_mode": "deterministic_replay",
                "alert_type": item.alert.alert_type,
                "alert": item.alert.model_dump(mode="json"),
                "ingestion": item.ingestion.model_dump(mode="json"),
                "triage": item.triage.model_dump(mode="json"),
                "risk_contributions": contributions,
                "judgment": item.judgment.model_dump(mode="json"),
                "escalation": item.escalation.model_dump(mode="json"),
                "response": item.response.model_dump(mode="json"),
                "finding": item.finding.model_dump(mode="json"),
                "timeline": [entry.model_dump(mode="json") for entry in item.timeline],
                "enrichment": enrichment,
            }
        )
    trace_status = "complete"
except Exception:
    incident_details = []
    trace_status = "unavailable"

if authoritative_details:
    incident_details = authoritative_details
    trace_status = "authoritative"

print(json.dumps({
    "agentsec_live_ui": "1",
    "preset": event.get("attributes", {}).get("live_ui_preset", "unknown"),
    "event": safe_event,
    "authorization": authorization,
    "incident_details": incident_details,
    "trace_status": trace_status,
}, sort_keys=True))
"""


Runner = Callable[..., subprocess.CompletedProcess[str]]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def validate_config(profile: str, region: str, instance_id: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", profile):
        raise ValueError("invalid AWS profile name")
    if not re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-\d", region):
        raise ValueError("invalid AWS region")
    if not re.fullmatch(r"i-[0-9a-f]{8,17}", instance_id):
        raise ValueError("invalid EC2 instance ID")


def make_event(preset_name: str) -> Dict[str, Any]:
    if preset_name not in PRESETS:
        raise ValueError("unknown forge preset")
    suffix = uuid4().hex
    preset = PRESETS[preset_name]
    event: Dict[str, Any] = {
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
    return event


def build_remote_command(event: Mapping[str, Any]) -> str:
    event_b64 = base64.b64encode(
        json.dumps(event, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    script_b64 = base64.b64encode(REMOTE_SCRIPT.encode("utf-8")).decode("ascii")
    return (
        "printf '%%s' '%s' | base64 -d | "
        "docker exec -i agentsec python - '%s'" % (script_b64, event_b64)
    )


def decode_json_output(output: str) -> Optional[Dict[str, Any]]:
    try:
        payload = json.loads(output.strip())
    except (json.JSONDecodeError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def authorization_from_output(output: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], List[Dict[str, Any]]]]:
    payload = decode_json_output(output)
    if payload is None:
        return None
    if payload.get("agentsec_live_ui") == "1":
        authorization = payload.get("authorization")
        event = payload.get("event")
        if isinstance(authorization, dict) and isinstance(event, dict):
            details = payload.get("incident_details", [])
            safe_details = [item for item in details if isinstance(item, dict)] if isinstance(details, list) else []
            return authorization, event, safe_details
        return None
    required = {"event_id", "overall_action", "effect_allowed", "alerts", "ledger_verified"}
    if required.issubset(payload) and isinstance(payload.get("alerts"), list):
        return payload, {}, []
    return None


def normalize_decision(value: object) -> str:
    decision = str(value or "deny").lower()
    if decision == "require_approval":
        return "REQUIRE APPROVAL"
    if decision.startswith("allow"):
        return "ALLOW"
    return "DENY"


def normalize_time(value: object) -> str:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(DISPLAY_TIMEZONE).strftime("%H:%M:%S")
    except ValueError:
        return "--:--:--"


def alerts_from_invocations(invocations: Sequence[Mapping[str, Any]]) -> Tuple[List[Dict[str, Any]], Optional[bool]]:
    live_alerts: List[Dict[str, Any]] = []
    ledger_values: List[bool] = []
    seen: set[str] = set()
    risk_by_severity = {"critical": 100, "high": 90, "medium": 60, "low": 35, "info": 5}

    for invocation in invocations:
        command_id = str(invocation.get("CommandId", "unknown"))
        requested_at = invocation.get("RequestedDateTime", "")
        for plugin in invocation.get("CommandPlugins", []):
            parsed = authorization_from_output(str(plugin.get("Output", "")))
            if parsed is None:
                continue
            authorization, event, incident_details = parsed
            detail_by_type = {
                str(item.get("alert_type")): item
                for item in incident_details
                if item.get("alert_type")
            }
            if isinstance(authorization.get("ledger_verified"), bool):
                ledger_values.append(authorization["ledger_verified"])
            for summary in authorization.get("alerts", []):
                if not isinstance(summary, dict):
                    continue
                alert_id = str(summary.get("alert_id", ""))
                if not alert_id or alert_id in seen:
                    continue
                seen.add(alert_id)
                alert_type = str(summary.get("alert_type", "unknown_alert"))
                incident_detail = detail_by_type.get(alert_type)
                catalog = ALERT_CATALOG.get(
                    alert_type,
                    {
                        "title": alert_type.replace("_", " ").title(),
                        "reason": "The live authorization service produced this finding.",
                        "policy": "deterministic-v1",
                        "evidence": ["Sanitized authorization response"],
                    },
                )
                actual_alert = incident_detail.get("alert", {}) if incident_detail else {}
                actual_triage = incident_detail.get("triage", {}) if incident_detail else {}
                actual_judgment = incident_detail.get("judgment", {}) if incident_detail else {}
                model_verdict = actual_judgment.get("model_verdict") if isinstance(actual_judgment, dict) else None
                ai_review = "Codex recorded shadow · deterministic decision unchanged"
                if isinstance(model_verdict, dict):
                    ai_review = "Codex shadow %s · %d%% confidence" % (
                        str(model_verdict.get("action", "reviewed")).upper(),
                        round(float(model_verdict.get("confidence", 0)) * 100),
                    )
                severity = str(summary.get("severity", "medium")).lower()
                if severity not in {"critical", "high", "medium", "info"}:
                    severity = "info" if severity == "low" else "medium"
                decision = normalize_decision(summary.get("decision"))
                event_id = str(authorization.get("event_id", "unknown"))
                evidence = list(catalog["evidence"])
                evidence.extend(
                    [
                        "AWS SSM command %s" % command_id[:8],
                        "Escalation: %s" % summary.get("escalation", "none"),
                    ]
                )
                trace_mode = (
                    str(incident_detail.get("trace_mode", ""))
                    if incident_detail
                    else ""
                )
                detail_availability = (
                    "authoritative"
                    if trace_mode == "authoritative"
                    else "mvp_replay"
                    if incident_detail
                    else "summary_only"
                )
                live_alerts.append(
                    {
                        "id": alert_id,
                        "title": str(actual_alert.get("title") or catalog["title"]),
                        "type": alert_type,
                        "severity": severity,
                        "decision": decision,
                        "state": "Contained" if decision == "DENY" else "Awaiting review",
                        "time": normalize_time(event.get("occurred_at") or requested_at),
                        "agent": str(event.get("agent_id") or "response-agent"),
                        "operation": str(event.get("operation") or "authorization.request"),
                        "resource": str(event.get("resource") or "event://%s" % event_id),
                        "source": str(event.get("source_id") or "aws-ssm://command/%s" % command_id),
                        "sourceTrust": str(event.get("source_trust") or "live SSM observation"),
                        "destination": str(event.get("destination") or "private EC2 loopback service"),
                        "reason": catalog["reason"],
                        "finding": str(summary.get("finding_id", "No finding ID")),
                        "policy": catalog["policy"],
                        "risk": int(actual_triage.get("risk_score", risk_by_severity[severity])),
                        "aiReview": ai_review,
                        "evidence": list(actual_alert.get("reason_codes") or evidence),
                        "eventId": event_id,
                        "commandId": command_id,
                        "detailAvailability": detail_availability,
                        "detail": incident_detail,
                    }
                )
    ledger_verified = all(ledger_values) if ledger_values else None
    return live_alerts[:100], ledger_verified


class AwsSsmClient:
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
            "aws", "ssm", operation,
            "--region", self.region,
            "--profile", self.profile,
        ]

    def list_alerts(self) -> Dict[str, Any]:
        args = self._base("list-command-invocations") + [
            "--instance-id", self.instance_id,
            "--details",
            "--max-results", "25",
            "--output", "json",
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
        remote_command = build_remote_command(event)
        parameters = json.dumps({"commands": [remote_command]}, separators=(",", ":"))
        send_args = self._base("send-command") + [
            "--instance-ids", self.instance_id,
            "--document-name", "AWS-RunShellScript",
            "--comment", "AgentSec local live UI forge: %s" % preset_name,
            "--parameters", parameters,
            "--query", "Command.CommandId",
            "--output", "text",
            "--no-cli-pager",
        ]
        command_id = self._run(send_args, timeout=30).strip()
        if not re.fullmatch(r"[0-9a-f-]{36}", command_id):
            raise RuntimeError("AWS CLI returned an invalid command ID")

        invocation: Optional[Dict[str, Any]] = None
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            get_args = self._base("get-command-invocation") + [
                "--command-id", command_id,
                "--instance-id", self.instance_id,
                "--output", "json",
                "--no-cli-pager",
            ]
            candidate = json.loads(self._run(get_args, timeout=20))
            status = candidate.get("Status")
            if status == "Success":
                invocation = {
                    "CommandId": command_id,
                    "RequestedDateTime": event["occurred_at"],
                    "CommandPlugins": [{"Output": candidate.get("StandardOutputContent", "")}],
                }
                break
            if status in {"Cancelled", "Cancelling", "Failed", "TimedOut"}:
                raise RuntimeError("Remote AgentSec command ended with status %s" % status)
            time.sleep(1)
        if invocation is None:
            raise RuntimeError("Remote AgentSec command did not finish within 45 seconds")

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


class LiveBridge:
    def __init__(self, client: AwsSsmClient, cache_seconds: float = 4.0) -> None:
        self.client = client
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
        recent = [item for alert_id, item in self._recent_alerts.items() if alert_id not in remote_ids]
        recent.sort(key=lambda item: int(item.get("risk", 0)), reverse=True)
        return {**payload, "alerts": recent + remote_alerts}

    def alerts(self) -> Dict[str, Any]:
        with self._lock:
            if self._cache is not None and time.monotonic() - self._cache_at < self.cache_seconds:
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


def make_handler(bridge: LiveBridge, port: int) -> Type[BaseHTTPRequestHandler]:
    allowed_hosts = {"127.0.0.1:%d" % port, "localhost:%d" % port}

    class LiveBridgeHandler(BaseHTTPRequestHandler):
        server_version = "agentsec-live-bridge/0.1"

        def _origin_allowed(self) -> bool:
            origin = self.headers.get("Origin")
            return origin is None or origin in ALLOWED_ORIGINS

        def _request_allowed(self) -> bool:
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

        def do_OPTIONS(self) -> None:
            if not self._request_allowed() or self.path != "/api/forge":
                self._json(HTTPStatus.FORBIDDEN, {"error": "request_not_allowed"})
                return
            self.send_response(HTTPStatus.NO_CONTENT.value)
            origin = self.headers.get("Origin")
            if origin in ALLOWED_ORIGINS:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Max-Age", "600")
            self.end_headers()

        def do_GET(self) -> None:
            if not self._request_allowed():
                self._json(HTTPStatus.FORBIDDEN, {"error": "request_not_allowed"})
                return
            path = urlsplit(self.path).path
            if path == "/health":
                self._json(
                    HTTPStatus.OK,
                    {"status": "ok", "service": "agentsec-live-bridge", "source": "aws-ssm"},
                )
                return
            if path != "/api/alerts":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            try:
                self._json(HTTPStatus.OK, bridge.alerts())
            except (RuntimeError, json.JSONDecodeError, subprocess.TimeoutExpired):
                self._json(HTTPStatus.BAD_GATEWAY, {"error": "aws_ssm_unavailable"})

        def do_POST(self) -> None:
            if not self._request_allowed() or self.headers.get("Origin") not in ALLOWED_ORIGINS:
                self._json(HTTPStatus.FORBIDDEN, {"error": "request_not_allowed"})
                return
            if urlsplit(self.path).path != "/api/forge":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            if self.headers.get_content_type() != "application/json":
                self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "json_required"})
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                size = 0
            if size <= 0 or size > MAX_BODY_BYTES:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "invalid_size"})
                return
            try:
                payload = json.loads(self.rfile.read(size).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
                return
            if not isinstance(payload, dict) or set(payload) != {"preset"}:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "preset_only"})
                return
            preset_name = payload.get("preset")
            if not isinstance(preset_name, str) or preset_name not in PRESETS:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "unknown_preset"})
                return
            try:
                self._json(HTTPStatus.OK, bridge.forge(preset_name))
            except (RuntimeError, json.JSONDecodeError, subprocess.TimeoutExpired):
                self._json(HTTPStatus.BAD_GATEWAY, {"error": "remote_authorization_failed"})

        def log_message(self, format: str, *args: object) -> None:
            return

    return LiveBridgeHandler


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the loopback-only AgentSec live UI bridge")
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument("--instance-id", default=DEFAULT_INSTANCE_ID)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.port < 1024 or args.port > 65535:
        raise ValueError("port must be between 1024 and 65535")
    client = AwsSsmClient(
        profile=args.profile,
        region=args.region,
        instance_id=args.instance_id,
    )
    bridge = LiveBridge(client)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(bridge, args.port))
    print("AgentSec live bridge listening on http://127.0.0.1:%d" % args.port, flush=True)
    print("Reading sanitized alerts via AWS SSM; public network binding is disabled.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
