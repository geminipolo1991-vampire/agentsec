import assert from "node:assert/strict";
import test from "node:test";

import {
  AgentSecExternalApiClient,
  AgentSecTelemetryClient,
  HttpTelemetryTransport,
  SignedHttpTelemetryTransport,
  TelemetryEventKind,
  createTelemetryEvent,
} from "../index.mjs";

const CANARY = "TYPESCRIPT-RAW-CONTENT-CANARY";

function event(overrides = {}) {
  return createTelemetryEvent({
    event_id: "tel_typescript_001",
    occurred_at: "2026-07-23T00:00:00Z",
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
    kind: TelemetryEventKind.MODEL_REQUEST,
    operation: "model.generate",
    resource: "model://test/model",
    content: { input: CANARY },
    ...overrides,
  });
}

class RecordingTransport {
  calls = [];
  async send(value) {
    this.calls.push(["one", value]);
    return { status: "accepted" };
  }
  async sendBatch(values) {
    this.calls.push(["batch", values]);
    return { accepted: values.length };
  }
}

test("content is excluded from transport unless explicitly enabled", async () => {
  const transport = new RecordingTransport();
  const client = new AgentSecTelemetryClient({ transport });

  await client.emit(event());

  assert.deepEqual(transport.calls[0][1].content, {});
  assert.doesNotMatch(JSON.stringify(transport.calls), new RegExp(CANARY));
});

test("approved content collection is explicit and batch bounded", async () => {
  const transport = new RecordingTransport();
  const client = new AgentSecTelemetryClient({ transport, includeContent: true });

  await client.emitBatch([event(), event({ event_id: "tel_typescript_002" })]);

  assert.equal(transport.calls[0][0], "batch");
  assert.equal(transport.calls[0][1].length, 2);
  assert.equal(transport.calls[0][1][0].content.input, CANARY);
  assert.throws(() => client.emitBatch([]), /1 to 1000/);
});

test("event and context validation fail before delivery", () => {
  assert.throws(() => event({ kind: "unknown" }), /supported telemetry event kind/);
  assert.throws(
    () => event({ occurred_at: "2026-07-23 00:00:00" }),
    /timezone-aware/,
  );
  assert.throws(
    () => event({ context: { tenant_id: "tenant-a" } }),
    /application_id/,
  );
  assert.throws(
    () => event({ attributes: { nested: { untrusted: true } } }),
    /bounded JSON scalars/,
  );
  assert.throws(
    () => event({ attributes: { non_finite: Number.POSITIVE_INFINITY } }),
    /bounded JSON scalars/,
  );
});

test("HTTP transport rejects unsafe endpoints and keeps credentials in headers", async () => {
  assert.throws(
    () => new HttpTelemetryTransport({ endpoint: "http://agentsec.example.test", token: "x" }),
    /HTTPS/,
  );
  assert.throws(
    () => new HttpTelemetryTransport({ endpoint: "https://user:pass@agentsec.example.test", token: "x" }),
    /credentials/,
  );
  const calls = [];
  const transport = new HttpTelemetryTransport({
    endpoint: "http://127.0.0.1:8080",
    token: "test-telemetry-token",
    allowLoopbackHttp: true,
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return { ok: true, status: 200, json: async () => ({ status: "accepted" }) };
    },
  });

  await transport.send(event({ content: {} }));

  assert.equal(calls[0].url, "http://127.0.0.1:8080/v1/telemetry");
  assert.equal(calls[0].options.headers.Authorization, "Bearer test-telemetry-token");
  assert.doesNotMatch(calls[0].options.body, /test-telemetry-token/);
});

test("signed HTTP transport binds the request without exposing its secret", async () => {
  const calls = [];
  const secret = "typescript-signed-secret-at-least-thirty-two-characters";
  const transport = new SignedHttpTelemetryTransport({
    endpoint: "http://localhost:8080",
    credentialId: "typescript-sdk-test",
    secret,
    allowLoopbackHttp: true,
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return { ok: true, status: 202, json: async () => ({ status: "accepted" }) };
    },
  });

  await transport.send(event({ content: {} }));

  assert.equal(calls[0].url, "http://localhost:8080/v1/telemetry");
  assert.equal(calls[0].options.headers["X-AgentSec-Key-Id"], "typescript-sdk-test");
  assert.match(calls[0].options.headers["X-AgentSec-Nonce"], /^[A-Za-z0-9_-]{16,128}$/);
  assert.match(calls[0].options.headers["X-AgentSec-Signature"], /^v1=[0-9a-f]{64}$/);
  assert.doesNotMatch(JSON.stringify(calls), new RegExp(secret));
});

test("external API client uses fixed routes and keeps its bearer header-only", async () => {
  const calls = [];
  const token = "typescript-external-api-token-at-least-32-bytes";
  const client = new AgentSecExternalApiClient({
    endpoint: "http://127.0.0.1:8080",
    token,
    allowLoopbackHttp: true,
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return { ok: true, status: 200, json: async () => ({ schema_version: "1.0.0" }) };
    },
  });

  await client.capabilities();
  await client.streamEvents({ limit: 25, eventTypes: ["finding"] });
  await client.search({ query: { term: { field: "record_type", value: "finding" } } });
  await client.listEntities({ limit: 25, offset: 0 });
  await client.listRules();
  await client.listFindings({ limit: 25, offset: 0 });
  await client.listIncidents({ limit: 25, offset: 0 });
  await client.getEntity("cmp_entity1");
  await client.getFinding("fnd_finding1");
  await client.getIncident("inc_incident1");
  await client.integrations();
  await client.deliveries({ state: "dead_letter", limit: 25 });
  await client.processIntegrations({ limit: 10 });
  await client.redriveDelivery(
    `idl_${"a".repeat(32)}`,
    "operator reviewed failed delivery",
  );

  assert.equal(calls.length, 14);
  assert.equal(calls[0].url, "http://127.0.0.1:8080/api/v1/capabilities");
  assert.match(calls[1].url, /\/api\/v1\/events\/stream\?limit=25&event_types=finding$/);
  for (const call of calls) {
    assert.equal(call.options.headers.Authorization, `Bearer ${token}`);
    assert.doesNotMatch(call.options.body ?? "", new RegExp(token));
  }
  assert.throws(
    () => client.streamEvents({ eventTypes: ["unsupported"] }),
    /unsupported external event type/,
  );
  assert.throws(
    () => client.deliveries({ destinationId: "https://not-an-integration" }),
    /destinationId is invalid/,
  );
  assert.throws(
    () => client.redriveDelivery(`idl_${"a".repeat(32)}`, "x"),
    /reason is too short/,
  );
});
