#!/usr/bin/env bash
set -euo pipefail

base_url=${1:-http://127.0.0.1:8000}
origin=${2:-http://127.0.0.1:8000}

curl -fsS --max-time 10 "${base_url}/health"
curl -fsS --max-time 15 "${base_url}/api/platform" >/dev/null
curl -fsS --max-time 30 \
  -H "Origin: ${origin}" \
  -H 'Content-Type: application/json' \
  -X POST \
  --data '{"preset":"indirect_injection_secret_egress"}' \
  "${base_url}/api/forge"
