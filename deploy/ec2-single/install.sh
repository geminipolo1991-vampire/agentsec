#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "run this installer with sudo" >&2
  exit 1
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
release_dir=$(cd "${script_dir}/../.." && pwd)

case "${release_dir}" in
  /opt/agentsec/releases/*) ;;
  *)
    echo "release must be staged below /opt/agentsec/releases" >&2
    exit 1
    ;;
esac

dnf install -y \
  nginx \
  nodejs22 \
  nodejs22-npm \
  openssl \
  python3.12 \
  python3.12-pip

if ! getent group agentsec >/dev/null; then
  groupadd --system agentsec
fi
if ! id agentsec >/dev/null 2>&1; then
  useradd --system --gid agentsec --home-dir /var/lib/agentsec --shell /sbin/nologin agentsec
fi

install -d -m 0750 -o root -g agentsec /etc/agentsec
install -d -m 0750 -o agentsec -g agentsec /var/lib/agentsec
install -d -m 0750 -o agentsec -g agentsec /var/lib/agentsec-ui

python3.12 -m venv "${release_dir}/.venv"
"${release_dir}/.venv/bin/python" -m pip install --no-cache-dir -r "${release_dir}/requirements.lock"
"${release_dir}/.venv/bin/python" -m pip install --no-cache-dir --no-deps "${release_dir}"

node_path=$(command -v node-22 || command -v node)
npm_path=$(command -v npm-22 || command -v npm)
"${node_path}" -e 'const major=Number(process.versions.node.split(".")[0]); if (major < 22) process.exit(1)'
ln -sfn "${node_path}" /usr/local/bin/agentsec-node
ln -sfn "${npm_path}" /usr/local/bin/agentsec-npm

pushd "${release_dir}/ui" >/dev/null
/usr/local/bin/agentsec-npm ci --no-audit --fund=false
/usr/local/bin/agentsec-npm run build
popd >/dev/null

if [[ ! -f /etc/agentsec/runtime.env ]]; then
  ingest_token=$(openssl rand -hex 32)
  search_cursor_secret=$(openssl rand -hex 32)
  content_signing_key=$(openssl rand -hex 32)
  integration_cursor_secret=$(openssl rand -hex 32)
  admin_assertion_key=$(openssl rand -hex 32)
  admin_checkpoint_key=$(openssl rand -hex 32)
  runtime_tmp=$(mktemp /etc/agentsec/runtime.env.XXXXXX)
  {
    printf 'AGENTSEC_INGEST_TOKEN=%s\n' "${ingest_token}"
    printf 'AGENTSEC_AI_MODE=shadow\n'
    printf 'AGENTSEC_MODEL_PROFILE=codex-recorded-shadow\n'
    printf 'AGENTSEC_CANONICAL_DB=/var/lib/agentsec/canonical.sqlite3\n'
    printf 'AGENTSEC_SEARCH_DB=/var/lib/agentsec/search.sqlite3\n'
    printf 'AGENTSEC_SEARCH_TENANT=tenant-lab\n'
    printf 'AGENTSEC_SEARCH_CURSOR_SECRET=%s\n' "${search_cursor_secret}"
    printf 'AGENTSEC_INVENTORY_DB=/var/lib/agentsec/inventory.sqlite3\n'
    printf 'AGENTSEC_INVENTORY_TENANT=tenant-lab\n'
    printf 'AGENTSEC_INVENTORY_APPLICATION_ID=authorization-service\n'
    printf 'AGENTSEC_GRAPH_DB=/var/lib/agentsec/graph.sqlite3\n'
    printf 'AGENTSEC_GRAPH_TENANT=tenant-lab\n'
    printf 'AGENTSEC_POSTURE_DB=/var/lib/agentsec/posture.sqlite3\n'
    printf 'AGENTSEC_POSTURE_TENANT=tenant-lab\n'
    printf 'AGENTSEC_DETECTION_DB=/var/lib/agentsec/detection.sqlite3\n'
    printf 'AGENTSEC_DETECTION_TENANT=tenant-lab\n'
    printf 'AGENTSEC_CONTENT_DB=/var/lib/agentsec/content.sqlite3\n'
    printf 'AGENTSEC_CONTENT_SIGNING_KEY=%s\n' "${content_signing_key}"
    printf 'AGENTSEC_BEHAVIOR_DB=/var/lib/agentsec/behavior.sqlite3\n'
    printf 'AGENTSEC_BEHAVIOR_TENANT=tenant-lab\n'
    printf 'AGENTSEC_CORRELATION_DB=/var/lib/agentsec/correlation.sqlite3\n'
    printf 'AGENTSEC_CORRELATION_TENANT=tenant-lab\n'
    printf 'AGENTSEC_ENRICHMENT_DB=/var/lib/agentsec/enrichment.sqlite3\n'
    printf 'AGENTSEC_ENRICHMENT_CONFIG=/opt/agentsec/current/configs/enrichment-connectors.example.json\n'
    printf 'AGENTSEC_ENRICHMENT_TENANT=tenant-lab\n'
    printf 'AGENTSEC_ANALYST_DB=/var/lib/agentsec/analyst.sqlite3\n'
    printf 'AGENTSEC_ANALYST_RECORDING=/opt/agentsec/current/configs/codex-analyst-evaluation.json\n'
    printf 'AGENTSEC_ANALYST_TENANT=tenant-lab\n'
    printf 'AGENTSEC_CASE_DB=/var/lib/agentsec/cases.sqlite3\n'
    printf 'AGENTSEC_CASE_TENANT=tenant-lab\n'
    printf 'AGENTSEC_NOTIFICATION_DB=/var/lib/agentsec/notifications.sqlite3\n'
    printf 'AGENTSEC_NOTIFICATION_CONFIG=/opt/agentsec/current/configs/notification-policy.example.json\n'
    printf 'AGENTSEC_NOTIFICATION_TENANT=tenant-lab\n'
    printf 'AGENTSEC_RESPONSE_DB=/var/lib/agentsec/response.sqlite3\n'
    printf 'AGENTSEC_RESPONSE_CONFIG=/opt/agentsec/current/configs/response-playbooks.example.json\n'
    printf 'AGENTSEC_RESPONSE_TENANT=tenant-lab\n'
    printf 'AGENTSEC_INTEGRATION_DB=/var/lib/agentsec/integrations.sqlite3\n'
    printf 'AGENTSEC_INTEGRATION_CONFIG=/opt/agentsec/current/configs/external-integrations.example.json\n'
    printf 'AGENTSEC_INTEGRATION_TENANT=tenant-lab\n'
    printf 'AGENTSEC_INTEGRATION_CURSOR_SECRET=%s\n' "${integration_cursor_secret}"
    printf 'AGENTSEC_SIMULATION_DB=/var/lib/agentsec/simulation.sqlite3\n'
    printf 'AGENTSEC_SIMULATION_TENANT=tenant-lab\n'
    printf 'AGENTSEC_EVALUATION_DB=/var/lib/agentsec/evaluation.sqlite3\n'
    printf 'AGENTSEC_EVALUATION_TENANT=tenant-lab\n'
    printf 'AGENTSEC_EVALUATION_POLICY=/opt/agentsec/current/configs/continuous-evaluation-policy.json\n'
    printf 'AGENTSEC_EVALUATION_RECORDING=/opt/agentsec/current/configs/codex-evaluation.json\n'
    printf 'AGENTSEC_ADMIN_DB=/var/lib/agentsec/administration.sqlite3\n'
    printf 'AGENTSEC_ADMIN_TENANT=tenant-lab\n'
    printf 'AGENTSEC_ADMIN_CONFIG=/opt/agentsec/current/configs/administration.example.json\n'
    printf 'AGENTSEC_ADMIN_ASSERTION_KEY=%s\n' "${admin_assertion_key}"
    printf 'AGENTSEC_ADMIN_CHECKPOINT_KEY=%s\n' "${admin_checkpoint_key}"
  } >"${runtime_tmp}"
  chown root:agentsec "${runtime_tmp}"
  chmod 0640 "${runtime_tmp}"
  mv "${runtime_tmp}" /etc/agentsec/runtime.env
fi

append_generated_secret() {
  local key=$1
  if ! grep -q "^${key}=" /etc/agentsec/runtime.env; then
    printf '%s=%s\n' "${key}" "$(openssl rand -hex 32)" >>/etc/agentsec/runtime.env
  fi
}

append_generated_secret AGENTSEC_INVENTORY_CONNECTOR_TOKEN
append_generated_secret AGENTSEC_REPUTATION_CONNECTOR_TOKEN
chown root:agentsec /etc/agentsec/runtime.env
chmod 0640 /etc/agentsec/runtime.env

if grep -Eq '^(OPENAI_API_KEY|ANTHROPIC_API_KEY)=.+' /etc/agentsec/runtime.env; then
  echo "live provider keys are present, but this deployment was approved without them" >&2
  exit 1
fi

chown -R root:agentsec "${release_dir}"
chmod -R g+rX,o-rwx "${release_dir}"
install -d -m 0770 -o agentsec -g agentsec "${release_dir}/ui/.wrangler"

ln -sfn "${release_dir}" /opt/agentsec/current.next
mv -Tf /opt/agentsec/current.next /opt/agentsec/current

install -m 0644 "${script_dir}/agentsec-backend.service" /etc/systemd/system/agentsec-backend.service
install -m 0644 "${script_dir}/agentsec-bridge.service" /etc/systemd/system/agentsec-bridge.service
install -m 0644 "${script_dir}/agentsec-ui.service" /etc/systemd/system/agentsec-ui.service
install -m 0644 "${script_dir}/nginx-agentsec.conf" /etc/nginx/conf.d/agentsec.conf

if command -v getenforce >/dev/null && [[ $(getenforce) == Enforcing ]]; then
  setsebool -P httpd_can_network_connect 1
fi

systemctl daemon-reload
systemctl enable agentsec-backend.service agentsec-bridge.service agentsec-ui.service nginx.service
systemctl restart agentsec-backend.service

for _ in {1..30}; do
  if curl -fsS --max-time 2 http://127.0.0.1:8080/healthz >/dev/null; then
    break
  fi
  sleep 1
done
curl -fsS --max-time 5 http://127.0.0.1:8080/healthz >/dev/null

systemctl restart agentsec-bridge.service
for _ in {1..30}; do
  if curl -fsS --max-time 2 -H 'Host: 127.0.0.1:8765' http://127.0.0.1:8765/health >/dev/null; then
    break
  fi
  sleep 1
done
curl -fsS --max-time 5 -H 'Host: 127.0.0.1:8765' http://127.0.0.1:8765/health >/dev/null

systemctl restart agentsec-ui.service
for _ in {1..60}; do
  if curl -fsS --max-time 2 http://127.0.0.1:3000/ >/dev/null; then
    break
  fi
  sleep 1
done
curl -fsS --max-time 5 http://127.0.0.1:3000/ >/dev/null

nginx -t
systemctl restart nginx.service
curl -fsS --max-time 5 http://127.0.0.1:8000/health >/dev/null
curl -fsS --max-time 10 http://127.0.0.1:8000/api/platform >/dev/null

echo "AgentSec deployment completed successfully on port 8000"
