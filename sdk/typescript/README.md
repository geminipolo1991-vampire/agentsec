# AgentSec TypeScript telemetry SDK

Dependency-free server-side telemetry client for the AgentSec canonical
`TelemetryInput` 1.0.0 contract. Content collection is disabled by default. Set
`includeContent: true` only when the receiving collector has an approved
redacted or encrypted collection policy.

```js
import {
  AgentSecTelemetryClient,
  SignedHttpTelemetryTransport,
  TelemetryEventKind,
  createTelemetryEvent,
} from "@agentsec/telemetry";

const transport = new SignedHttpTelemetryTransport({
  endpoint: "https://agentsec.example.internal",
  credentialId: process.env.AGENTSEC_TELEMETRY_KEY_ID,
  secret: process.env.AGENTSEC_TELEMETRY_SECRET,
});
const client = new AgentSecTelemetryClient({ transport });

await client.emit(createTelemetryEvent({
  context: {
    tenant_id: "tenant-a",
    application_id: "support-app",
    agent_id: "triage-agent",
    session_id: "session-1",
    trace_id: "trace-1",
    source_id: "sdk://typescript/support-app",
    source_type: "typescript-sdk",
    collector_id: "collector-1",
  },
  kind: TelemetryEventKind.TOOL_CALL_REQUEST,
  operation: "ticket.read",
  resource: "ticket://123",
  tool_name: "ticket_reader",
}));
```

The signed transport binds the method, path, body digest, timestamp, and unique
nonce with HMAC-SHA256. The Module 2 gateway resolves tenant and source from the
credential and rejects replays. A custom transport can be injected for tests,
queues, or an embedded collector.

The package also includes the scoped external API client used by SIEM, SOAR,
and security data-platform consumers. Its bearer is sent only in the
`Authorization` header, routes are fixed under `/api/v1`, and paging inputs are
bounded before a request is issued:

```js
import { AgentSecExternalApiClient } from "@agentsec/telemetry";

const api = new AgentSecExternalApiClient({
  endpoint: "https://agentsec.example.internal",
  token: process.env.AGENTSEC_EXTERNAL_API_TOKEN,
});

const events = await api.streamEvents({ limit: 100, eventTypes: ["finding"] });
const findings = await api.listFindings();
const integrations = await api.integrations();
```

Use a different scoped client credential for read-only events, search, and
integration operation. This client is not a telemetry workload credential and
cannot call the private administrative `/v1` API.
