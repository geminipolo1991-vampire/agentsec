"""Authenticated, metadata-only HTTP authorization service for EC2 deployment."""

from __future__ import annotations

import hmac
import json
import os
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple, Type

from pydantic import Field, ValidationError

from .contracts import AgentEvent, StrictModel
from .incidents import IncidentDetail, build_incident_detail
from .pipeline import SecurityPipeline
from .runtime import build_pipeline_from_environment


MAX_REQUEST_BYTES = 1024 * 1024


def health_payload() -> Dict[str, str]:
    return {"status": "ok", "service": "agentsec-authorization"}


def bearer_is_valid(supplied_header: str, bearer_token: str) -> bool:
    return hmac.compare_digest(supplied_header, "Bearer %s" % bearer_token)


class AuthorizationAlertSummary(StrictModel):
    alert_id: str
    finding_id: str
    alert_type: str
    severity: str
    decision: str
    escalation: str


class AuthorizationResponse(StrictModel):
    schema_version: str = "1.1.0"
    event_id: str
    overall_action: str
    effect_allowed: bool
    alerts: List[AuthorizationAlertSummary] = Field(default_factory=list)
    incidents: List[IncidentDetail] = Field(default_factory=list)
    ledger_verified: bool


class AuthorizationApplication:
    """Serializes access to the in-memory PoC stores and returns an allowlist view."""

    def __init__(self, pipeline: Optional[SecurityPipeline] = None) -> None:
        self.pipeline = pipeline or SecurityPipeline()
        self._lock = threading.Lock()

    def authorize(self, payload: Dict[str, Any]) -> AuthorizationResponse:
        event = AgentEvent.model_validate(payload)
        with self._lock:
            result = self.pipeline.process(event)
            ledger_verified = self.pipeline.ledger.verify()
        return AuthorizationResponse(
            event_id=event.event_id,
            overall_action=result.overall_action.value,
            effect_allowed=result.effect_allowed,
            alerts=[
                AuthorizationAlertSummary(
                    alert_id=item.alert.alert_id,
                    finding_id=item.finding.finding_id,
                    alert_type=item.alert.alert_type,
                    severity=item.alert.severity.value,
                    decision=item.judgment.action.value,
                    escalation=item.escalation.level.value,
                )
                for item in result.alerts
            ],
            incidents=[build_incident_detail(item) for item in result.alerts],
            ledger_verified=ledger_verified,
        )


def make_handler(
    application: AuthorizationApplication, bearer_token: str
) -> Type[BaseHTTPRequestHandler]:
    if len(bearer_token) < 32:
        raise ValueError("ingestion bearer token must contain at least 32 characters")

    class AuthorizationHandler(BaseHTTPRequestHandler):
        server_version = "agentsec/0.1"

        def _json(self, status: HTTPStatus, payload: Dict[str, Any]) -> None:
            encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status.value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(encoded)

        def _authenticated(self) -> bool:
            return bearer_is_valid(self.headers.get("Authorization", ""), bearer_token)

        def do_GET(self) -> None:
            if self.path != "/healthz":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            self._json(
                HTTPStatus.OK,
                health_payload(),
            )

        def do_POST(self) -> None:
            if self.path != "/v1/authorize":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            if not self._authenticated():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            if self.headers.get_content_type() != "application/json":
                self._json(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    {"error": "content_type_must_be_application_json"},
                )
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                size = 0
            if size <= 0 or size > MAX_REQUEST_BYTES:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "invalid_size"})
                return
            try:
                raw = self.rfile.read(size)
                payload = json.loads(raw.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("request body must be an object")
                response = application.authorize(payload)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError, ValidationError):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
                return
            self._json(HTTPStatus.OK, response.model_dump(mode="json"))

        def log_message(self, format: str, *args: object) -> None:
            # Avoid default request logging because event IDs and paths can be sensitive.
            return

    return AuthorizationHandler


def serve(
    *, host: str, port: int, bearer_token: str, application: Optional[AuthorizationApplication] = None
) -> None:
    app = application or AuthorizationApplication()
    server = ThreadingHTTPServer((host, port), make_handler(app, bearer_token))
    server.serve_forever()


def main() -> int:
    bearer_token = os.environ.get("AGENTSEC_INGEST_TOKEN", "")
    host = os.environ.get("AGENTSEC_BIND_HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("AGENTSEC_PORT", "8080"))
    except ValueError as exc:
        raise ValueError("AGENTSEC_PORT must be an integer") from exc
    pipeline = build_pipeline_from_environment()
    serve(
        host=host,
        port=port,
        bearer_token=bearer_token,
        application=AuthorizationApplication(pipeline),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
