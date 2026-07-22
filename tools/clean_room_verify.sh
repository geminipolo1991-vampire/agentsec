#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "$0")/.." && pwd)
clean_root=$(mktemp -d "${TMPDIR:-/tmp}/agentsec-clean.XXXXXX")
trap 'rm -rf -- "$clean_root"' EXIT

python3 -m venv --system-site-packages "$clean_root/venv"
"$clean_root/venv/bin/python" -m pip install \
  --disable-pip-version-check \
  --no-deps \
  --no-build-isolation \
  "$project_root"

cp -R "$project_root/configs" "$clean_root/configs"
cd "$clean_root"
"$clean_root/venv/bin/agentsec" workflow-demo > workflow.json
"$clean_root/venv/bin/agentsec" codex-demo > codex.json
"$clean_root/venv/bin/agentsec" evaluate --mode deterministic > evaluation.json

"$clean_root/venv/bin/python" - <<'PY'
import json
from pathlib import Path

workflow = json.loads(Path("workflow.json").read_text(encoding="utf-8"))
codex = json.loads(Path("codex.json").read_text(encoding="utf-8"))
evaluation = json.loads(Path("evaluation.json").read_text(encoding="utf-8"))
assert workflow["all_protected_ground_truth_passed"] is True
assert codex["ai_mode"] == "shadow"
assert evaluation["metrics"]["forbidden_effect_attack_success_rate"] == 0.0
assert evaluation["metrics"]["benign_task_completion_rate"] == 1.0
print("clean-room install and demonstrations verified")
PY
