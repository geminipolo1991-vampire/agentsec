#!/usr/bin/env python3
"""Fail CI on common credential material committed to the PoC tree."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {
    ".git",
    ".venv",
    ".vinext",
    ".wrangler",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
}
PATTERNS = {
    "OpenAI-style API key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "Anthropic API key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}


def main() -> int:
    findings = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or SKIP_PARTS.intersection(path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for label, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append("%s:%d: %s" % (path.relative_to(ROOT), line, label))
    if findings:
        print("potential committed secrets detected:")
        for finding in findings:
            print("- %s" % finding)
        return 1
    print("secret scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
