#!/usr/bin/env bash
set -euo pipefail

# This probe is intended to run on the AgentSec-owned EC2 instance through
# AWS Systems Manager Run Command. It never reads or prints the host env file;
# the bearer token is consumed only inside the already-running container.

systemctl is-active --quiet agentsec.service

container_status=$(docker inspect --format '{{.State.Status}}' agentsec)
container_health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' agentsec)
published_port=$(docker port agentsec 8080/tcp)
image_reference=$(docker inspect --format '{{.Config.Image}}' agentsec)

test "$container_status" = "running"
test "$container_health" = "healthy"
test "$published_port" = "127.0.0.1:8080"

case "$image_reference" in
  *@sha256:*) ;;
  *)
    echo '{"error":"container_image_is_not_digest_pinned"}' >&2
    exit 1
    ;;
esac

docker exec -i agentsec python - <<'PY'
import json
import os
import urllib.request

from agentsec.scenarios import forge_scenarios


runtime = {
    "ai_mode": os.environ.get("AGENTSEC_AI_MODE"),
    "model_profile": os.environ.get("AGENTSEC_MODEL_PROFILE"),
    "live_provider_keys_present": any(
        bool(os.environ.get(name))
        for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY")
    ),
}
if runtime != {
    "ai_mode": "shadow",
    "model_profile": "codex-recorded-shadow",
    "live_provider_keys_present": False,
}:
    raise SystemExit('{"error":"unexpected_runtime_provider_configuration"}')

expected = {
    "benign_inventory_read": {
        "action": "allow",
        "effect_allowed": True,
        "alerts": [],
        "ledger_verified": True,
    },
    "indirect_injection_secret_egress": {
        "action": "deny",
        "effect_allowed": False,
        "alerts": ["indirect_prompt_injection", "secret_egress"],
        "ledger_verified": True,
    },
}

events = forge_scenarios()
events["indirect_injection_secret_egress"] = events[
    "indirect_injection_secret_egress"
].model_copy(update={"attributes": {"raw_prompt": "REMOTE_CANARY_MUST_NOT_ECHO"}})

results = []
for name in expected:
    request = urllib.request.Request(
        "http://127.0.0.1:8080/v1/authorize",
        data=events[name].model_dump_json().encode("utf-8"),
        headers={
            "Authorization": "Bearer " + os.environ["AGENTSEC_INGEST_TOKEN"],
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        encoded = response.read().decode("utf-8")
    if "REMOTE_CANARY_MUST_NOT_ECHO" in encoded:
        raise SystemExit('{"error":"raw_event_echoed"}')
    payload = json.loads(encoded)
    observed = {
        "action": payload["overall_action"],
        "effect_allowed": payload["effect_allowed"],
        "alerts": sorted(item["alert_type"] for item in payload["alerts"]),
        "ledger_verified": payload["ledger_verified"],
    }
    if observed != expected[name]:
        raise SystemExit(
            json.dumps(
                {"error": "unexpected_authorization_result", "scenario": name},
                sort_keys=True,
            )
        )
    results.append({"scenario": name, **observed})

print(
    json.dumps(
        {
            "container": "healthy",
            "runtime": runtime,
            "scenarios": results,
            "status": "passed",
        },
        sort_keys=True,
    )
)
PY
