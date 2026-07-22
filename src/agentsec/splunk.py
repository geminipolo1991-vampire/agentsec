"""Allowlist-only Splunk HEC delivery with idempotency and dead letters."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional, Protocol, Set
from urllib.parse import urlparse

from pydantic import Field

from .contracts import StrictModel, utc_now
from .privacy import SocFindingExport


class HecTransport(Protocol):
    def post(
        self,
        *,
        url: str,
        headers: Dict[str, str],
        payload: Dict[str, Any],
        timeout_seconds: float,
    ) -> Dict[str, Any]:
        ...


class UrllibHecTransport:
    def post(
        self,
        *,
        url: str,
        headers: Dict[str, str],
        payload: Dict[str, Any],
        timeout_seconds: float,
    ) -> Dict[str, Any]:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raise RuntimeError("Splunk HEC returned HTTP %d" % exc.code) from None
        except (urllib.error.URLError, socket.timeout, TimeoutError):
            raise RuntimeError("Splunk HEC transport unavailable") from None
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError("Splunk HEC returned invalid JSON") from None
        if not isinstance(result, dict):
            raise RuntimeError("Splunk HEC response must be an object")
        return result


def validate_hec_endpoint(endpoint: str, allowed_hosts: Set[str]) -> str:
    parsed = urlparse(endpoint)
    if parsed.scheme != "https":
        raise ValueError("Splunk HEC endpoint must use HTTPS")
    if parsed.hostname not in allowed_hosts:
        raise ValueError("Splunk HEC host is not allowlisted")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Splunk HEC endpoint contains prohibited URL components")
    if parsed.path.rstrip("/") != "/services/collector/event":
        raise ValueError("Splunk HEC endpoint path must be /services/collector/event")
    return endpoint


class SplunkExportReceipt(StrictModel):
    event_id: str
    status: str
    response_code: Optional[int] = None
    response_text: Optional[str] = None
    exported_at: datetime = Field(default_factory=utc_now)


class SplunkDeadLetter(StrictModel):
    event_id: str
    export: SocFindingExport
    error_category: str
    attempts: int = Field(ge=1)


class SplunkHecClient:
    def __init__(
        self,
        *,
        endpoint: str,
        token: str,
        allowed_hosts: Set[str],
        index: str,
        sourcetype: str = "agentsec:finding",
        transport: Optional[HecTransport] = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not token:
            raise ValueError("Splunk HEC token is required")
        self.endpoint = validate_hec_endpoint(endpoint, allowed_hosts)
        self._token = token
        self.index = index
        self.sourcetype = sourcetype
        self.transport = transport or UrllibHecTransport()
        self.timeout_seconds = timeout_seconds
        self._sent: Set[str] = set()
        self.dead_letters: List[SplunkDeadLetter] = []

    def export(self, finding: SocFindingExport) -> SplunkExportReceipt:
        event_id = finding.finding_id
        if event_id in self._sent:
            return SplunkExportReceipt(event_id=event_id, status="duplicate")
        payload = {
            "event": finding.model_dump(mode="json"),
            "sourcetype": self.sourcetype,
            "source": "agentsec",
            "index": self.index,
            "fields": {"event_id": event_id},
        }
        try:
            response = self.transport.post(
                url=self.endpoint,
                headers={
                    "Authorization": "Splunk %s" % self._token,
                    "Content-Type": "application/json",
                },
                payload=payload,
                timeout_seconds=self.timeout_seconds,
            )
            code = response.get("code")
            if code not in {0, "0"}:
                raise RuntimeError("Splunk HEC rejected event")
        except RuntimeError as exc:
            self.dead_letters.append(
                SplunkDeadLetter(
                    event_id=event_id,
                    export=finding,
                    error_category=str(exc),
                    attempts=1,
                )
            )
            return SplunkExportReceipt(event_id=event_id, status="dead_letter")
        self._sent.add(event_id)
        return SplunkExportReceipt(
            event_id=event_id,
            status="sent",
            response_code=int(code),
            response_text=str(response.get("text", "")),
        )
