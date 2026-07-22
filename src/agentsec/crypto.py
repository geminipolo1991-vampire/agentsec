"""Canonical signing helpers for local PoC integrity controls.

HMAC is intentionally scoped to the single-process research harness. Production
deployment must replace this implementation with Ed25519 and managed KMS/HSM keys.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Dict


def canonical_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode(
        "utf-8"
    )


class PocHmacSigner:
    algorithm = "hmac-sha256-poc"

    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("PoC signing key must contain at least 32 bytes")
        self._key = key

    def sign(self, payload: Dict[str, Any]) -> str:
        return hmac.new(self._key, canonical_bytes(payload), hashlib.sha256).hexdigest()

    def verify(self, payload: Dict[str, Any], signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)

