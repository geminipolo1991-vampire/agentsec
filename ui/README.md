# AgentSec Control Room UI

Responsive analyst interface for the AI-Agent Security research PoC. The alert
queue reads sanitized live authorization decisions from the private Tokyo EC2
service through AWS Systems Manager. It does not use fixed alert fixtures.

Views:

- Overview and incident decision queue
- Six-stage authorization trace
- Deterministic policy catalog
- Eight-mode evaluation comparison
- Provider, Splunk, and EC2 Tokyo readiness
- Allowlisted live POC event forge

Run locally with the live bridge. From the repository root, start the bridge in
the first terminal:

```bash
python3 tools/live_ui_bridge.py \
  --profile agentsec-deploy \
  --region ap-northeast-1 \
  --instance-id i-082370aa89a20ff93
```

Then start the UI in a second terminal:

```bash
cd ui
npm run dev
```

Open <http://localhost:3000>. The UI polls the bridge every eight seconds.
Choose an allowlisted scenario and select **Forge live event** to submit a new
metadata-only event to the running EC2 container. The resulting sanitized SSM
response appears in the alert queue.

The bridge binds only to `127.0.0.1:8765`, accepts browser writes only from the
local UI origins, and never sends AWS credentials or `AGENTSEC_INGEST_TOKEN` to
the browser. The token is consumed only inside the EC2 container. Arbitrary
shell commands and arbitrary event payloads are not accepted.

Build and test:

```bash
npm run build
npm test
```

The model provider remains `codex-recorded-shadow`; deterministic policy makes
the enforcement decision. Public UI hosting remains disabled for this POC.

## Tonight's investigation MVP

New events forged while the bridge is running include a presentation-oriented
investigation trace. Select an alert marked **AUTHORITATIVE** or **MVP TRACE**,
then walk through:

1. **Overview** — policy proof, detector confidence, evidence, lineage, and the “Why this alert is valid” record
2. **Triage** — actual risk score, priority, contribution breakdown, and ledger receipt
3. **Enrichment** — six metadata context checks with evidence, source, and impact
4. **Decision** — deterministic result, recorded Codex shadow verdict, and final combiner action
5. **Response** — escalation, containment actions, and finding audit trail

The current source implements an **AUTHORITATIVE TRACE** derived from the exact
pipeline result used for enforcement. The currently deployed EC2 image has not
been changed: until a separate service deployment is approved, the bridge shows
its detailed records as **MVP REPLAY**, performed inside the same container and
checked against the service alert types and final action. Neither mode is a
durable production incident store. Older SSM results remain **SUMMARY ONLY**.
