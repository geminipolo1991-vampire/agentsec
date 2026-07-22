"""Fail-closed recursive redaction for model and SOC metadata exports."""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Set

from pydantic import Field

from .contracts import StrictModel


REDACTED = "[REDACTED]"
SENSITIVE_FIELD = re.compile(
    r"(^|_)(authorization|password|passwd|secret|token|api_key|access_key|private_key)($|_)",
    re.IGNORECASE,
)
VALUE_PATTERNS = [
    re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)[^\s,;]{8,}"),
    re.compile(r"(?i)(password\s*[=:]\s*)[^\s,;]{4,}"),
]


class RedactionResult(StrictModel):
    value: Any
    redaction_count: int = Field(ge=0)
    rule_version: str = "redaction-2026-07-22.1"


class Redactor:
    def __init__(self, canaries: Iterable[str] = ()) -> None:
        self._canaries: Set[str] = {item for item in canaries if item}

    def _redact_string(self, value: str) -> tuple:
        result = value
        count = 0
        for canary in self._canaries:
            occurrences = result.count(canary)
            if occurrences:
                result = result.replace(canary, REDACTED)
                count += occurrences
        for pattern in VALUE_PATTERNS:
            result, replacements = pattern.subn(REDACTED, result)
            count += replacements
        return result, count

    def _walk(self, value: Any, depth: int) -> tuple:
        if depth > 20:
            raise ValueError("redaction depth limit exceeded")
        if isinstance(value, str):
            return self._redact_string(value)
        if isinstance(value, dict):
            output: Dict[str, Any] = {}
            count = 0
            for key, item in value.items():
                if SENSITIVE_FIELD.search(str(key)):
                    output[str(key)] = REDACTED
                    count += 1
                else:
                    output[str(key)], item_count = self._walk(item, depth + 1)
                    count += item_count
            return output, count
        if isinstance(value, (list, tuple, set)):
            output: List[Any] = []
            count = 0
            for item in value:
                transformed, item_count = self._walk(item, depth + 1)
                output.append(transformed)
                count += item_count
            return output, count
        if value is None or isinstance(value, (bool, int, float)):
            return value, 0
        raise TypeError("unsupported export value type: %s" % type(value).__name__)

    def redact(self, value: Any) -> RedactionResult:
        transformed, count = self._walk(value, 0)
        return RedactionResult(value=transformed, redaction_count=count)

