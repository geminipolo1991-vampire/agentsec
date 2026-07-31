const SCHEMA_VERSION = "1.0.0";

export const TelemetryEventKind = Object.freeze({
  MODEL_REQUEST: "model_request",
  MODEL_RESPONSE: "model_response",
  MODEL_CALL: "model_call",
  TOOL_CALL_REQUEST: "tool_call_request",
  TOOL_CALL_RESULT: "tool_call_result",
  AGENT_MESSAGE: "agent_message",
  RAG_RETRIEVAL: "rag_retrieval",
  MEMORY_READ: "memory_read",
  MEMORY_WRITE: "memory_write",
  GUARDRAIL_DECISION: "guardrail_decision",
  ERROR: "error",
  HEARTBEAT: "heartbeat",
});

const eventKinds = new Set(Object.values(TelemetryEventKind));

function boundedString(value, name, maximum, optional = false) {
  if (optional && (value === undefined || value === null)) return undefined;
  if (typeof value !== "string" || value.length < 1 || value.length > maximum) {
    throw new TypeError(`${name} must contain 1 to ${maximum} characters`);
  }
  return value;
}

function boundedObject(value, name, maximum) {
  if (value === undefined) return {};
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object`);
  }
  if (Object.keys(value).length > maximum) throw new RangeError(`${name} has too many fields`);
  return structuredClone(value);
}

function boundedAttributes(value) {
  const attributes = boundedObject(value, "attributes", 64);
  for (const [key, attribute] of Object.entries(attributes)) {
    boundedString(key, "attribute key", 128);
    const scalar = typeof attribute;
    if (
      attribute === null ||
      !["string", "number", "boolean"].includes(scalar) ||
      (scalar === "string" && attribute.length > 2048) ||
      (scalar === "number" && !Number.isFinite(attribute))
    ) {
      throw new TypeError("attribute values must be bounded JSON scalars");
    }
  }
  return attributes;
}

export function createTelemetryContext(input) {
  const required = {
    tenant_id: 128,
    application_id: 128,
    agent_id: 128,
    session_id: 128,
    trace_id: 128,
    source_id: 256,
    source_type: 64,
    collector_id: 128,
  };
  const context = {};
  for (const [name, maximum] of Object.entries(required)) {
    context[name] = boundedString(input?.[name], name, maximum);
  }
  context.environment = boundedString(input.environment ?? "unknown", "environment", 64);
  const provider = boundedString(input.provider, "provider", 64, true);
  const modelId = boundedString(input.model_id, "model_id", 256, true);
  if (provider !== undefined) context.provider = provider;
  if (modelId !== undefined) context.model_id = modelId;
  return Object.freeze(context);
}

export function createTelemetryEvent(input) {
  if (!eventKinds.has(input?.kind)) throw new TypeError("kind is not a supported telemetry event kind");
  const occurredAt = input.occurred_at ?? new Date().toISOString();
  const parsedTime = new Date(occurredAt);
  if (
    Number.isNaN(parsedTime.getTime()) ||
    (!String(occurredAt).endsWith("Z") && !/[+-]\d\d:\d\d$/.test(String(occurredAt)))
  ) {
    throw new TypeError("occurred_at must be a timezone-aware timestamp");
  }
  const event = {
    schema_version: SCHEMA_VERSION,
    event_id: boundedString(input.event_id ?? `tel_${crypto.randomUUID().replaceAll("-", "")}`, "event_id", 128),
    occurred_at: parsedTime.toISOString(),
    context: createTelemetryContext(input.context),
    kind: input.kind,
    attributes: boundedAttributes(input.attributes),
    content: boundedObject(input.content, "content", 16),
    data_classes: [...new Set(input.data_classes ?? [])],
    indicators: [...new Set(input.indicators ?? [])],
  };
  const optionalStrings = {
    span_id: 128,
    parent_span_id: 128,
    operation: 128,
    resource: 512,
    destination: 512,
    tool_name: 128,
    error_code: 128,
  };
  for (const [name, maximum] of Object.entries(optionalStrings)) {
    const value = boundedString(input[name], name, maximum, true);
    if (value !== undefined) event[name] = value;
  }
  for (const name of ["sequence", "duration_ms", "input_tokens", "output_tokens"]) {
    const value = input[name];
    if (value !== undefined) {
      if (!Number.isSafeInteger(value) || value < (name === "sequence" ? 1 : 0)) {
        throw new TypeError(`${name} must be a non-negative safe integer`);
      }
      event[name] = value;
    }
  }
  if (input.success !== undefined) {
    if (typeof input.success !== "boolean") throw new TypeError("success must be boolean");
    event.success = input.success;
  }
  JSON.stringify(event); // Reject cyclic or non-serializable input now, not during delivery.
  return Object.freeze(event);
}

function validateBaseEndpoint(value, allowLoopbackHttp) {
  const parsed = new URL(value);
  const loopback = ["127.0.0.1", "::1", "localhost"].includes(parsed.hostname);
  if (parsed.protocol !== "https:" && !(allowLoopbackHttp && loopback && parsed.protocol === "http:")) {
    throw new TypeError("telemetry endpoint must use HTTPS (or explicit loopback HTTP)");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new TypeError("telemetry endpoint cannot contain credentials, query, or fragment");
  }
  parsed.pathname = parsed.pathname.replace(/\/$/, "");
  return parsed.toString().replace(/\/$/, "");
}

function hex(bytes) {
  return [...new Uint8Array(bytes)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(value) {
  return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}

export class HttpTelemetryTransport {
  #baseEndpoint;
  #token;
  #fetch;

  constructor({ endpoint, token, fetchImpl = globalThis.fetch, allowLoopbackHttp = false }) {
    this.#baseEndpoint = validateBaseEndpoint(endpoint, allowLoopbackHttp);
    this.#token = boundedString(token, "token", 4096);
    if (typeof fetchImpl !== "function") throw new TypeError("fetchImpl must be a function");
    this.#fetch = fetchImpl;
  }

  async #post(path, payload) {
    const response = await this.#fetch(`${this.#baseEndpoint}${path}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.#token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error(`AgentSec telemetry delivery failed with HTTP ${response.status}`);
    return response.json();
  }

  send(event) {
    return this.#post("/v1/telemetry", event);
  }

  sendBatch(events) {
    return this.#post("/v1/telemetry/batch", { events });
  }
}

export class SignedHttpTelemetryTransport {
  #baseEndpoint;
  #credentialId;
  #secret;
  #fetch;

  constructor({ endpoint, credentialId, secret, fetchImpl = globalThis.fetch, allowLoopbackHttp = false }) {
    this.#baseEndpoint = validateBaseEndpoint(endpoint, allowLoopbackHttp);
    this.#credentialId = boundedString(credentialId, "credentialId", 128);
    if (!/^[A-Za-z0-9._:-]{3,128}$/.test(this.#credentialId)) {
      throw new TypeError("credentialId has an invalid format");
    }
    const encodedSecret = new TextEncoder().encode(boundedString(secret, "secret", 4096));
    if (encodedSecret.byteLength < 32) throw new TypeError("secret must contain at least 32 bytes");
    this.#secret = encodedSecret;
    if (typeof fetchImpl !== "function") throw new TypeError("fetchImpl must be a function");
    this.#fetch = fetchImpl;
  }

  async #post(path, payload) {
    const body = JSON.stringify(payload);
    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonce = crypto.randomUUID().replaceAll("-", "");
    const canonical = `POST\n${path}\n${timestamp}\n${nonce}\n${await sha256Hex(body)}`;
    const key = await crypto.subtle.importKey(
      "raw",
      this.#secret,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const signature = hex(
      await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(canonical)),
    );
    const response = await this.#fetch(`${this.#baseEndpoint}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-AgentSec-Key-Id": this.#credentialId,
        "X-AgentSec-Timestamp": timestamp,
        "X-AgentSec-Nonce": nonce,
        "X-AgentSec-Signature": `v1=${signature}`,
      },
      body,
    });
    if (!response.ok) throw new Error(`AgentSec telemetry delivery failed with HTTP ${response.status}`);
    return response.json();
  }

  send(event) {
    return this.#post("/v1/telemetry", event);
  }

  sendBatch(events) {
    return this.#post("/v1/telemetry/batch", { events });
  }
}

export class AgentSecTelemetryClient {
  #transport;
  #includeContent;

  constructor({ transport, includeContent = false }) {
    if (!transport || typeof transport.send !== "function" || typeof transport.sendBatch !== "function") {
      throw new TypeError("transport must implement send and sendBatch");
    }
    this.#transport = transport;
    this.#includeContent = includeContent === true;
  }

  #project(event) {
    const validated = createTelemetryEvent(event);
    if (this.#includeContent) return validated;
    return Object.freeze({ ...validated, content: {} });
  }

  emit(event) {
    return this.#transport.send(this.#project(event));
  }

  emitBatch(events) {
    if (!Array.isArray(events) || events.length < 1 || events.length > 1000) {
      throw new RangeError("events must contain 1 to 1000 telemetry records");
    }
    return this.#transport.sendBatch(events.map((event) => this.#project(event)));
  }
}

export class AgentSecExternalApiClient {
  #baseEndpoint;
  #token;
  #fetch;

  constructor({ endpoint, token, fetchImpl = globalThis.fetch, allowLoopbackHttp = false }) {
    this.#baseEndpoint = validateBaseEndpoint(endpoint, allowLoopbackHttp);
    this.#token = boundedString(token, "token", 4096);
    if (new TextEncoder().encode(this.#token).byteLength < 32) {
      throw new TypeError("external API token must contain at least 32 bytes");
    }
    if (typeof fetchImpl !== "function") throw new TypeError("fetchImpl must be a function");
    this.#fetch = fetchImpl;
  }

  async #request(method, path, { query, payload } = {}) {
    const suffix = query ? `?${new URLSearchParams(query).toString()}` : "";
    const options = {
      method,
      headers: { Authorization: `Bearer ${this.#token}` },
    };
    if (payload !== undefined) {
      if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
        throw new TypeError("external API payload must be an object");
      }
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(payload);
    }
    const response = await this.#fetch(`${this.#baseEndpoint}${path}${suffix}`, options);
    if (!response.ok) throw new Error(`AgentSec external API failed with HTTP ${response.status}`);
    const decoded = await response.json();
    if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) {
      throw new TypeError("AgentSec external API response must be an object");
    }
    return decoded;
  }

  capabilities() {
    return this.#request("GET", "/api/v1/capabilities");
  }

  streamEvents({ limit = 100, cursor, eventTypes } = {}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200) {
      throw new RangeError("external event limit must contain 1 to 200 records");
    }
    const query = { limit: String(limit) };
    if (cursor !== undefined) query.cursor = boundedString(cursor, "cursor", 4096);
    if (eventTypes !== undefined) {
      if (
        !Array.isArray(eventTypes) || eventTypes.length < 1 || eventTypes.length > 4 ||
        eventTypes.some((item) => !["finding", "incident", "alert", "audit"].includes(item))
      ) {
        throw new TypeError("eventTypes contains an unsupported external event type");
      }
      query.event_types = [...new Set(eventTypes)].sort().join(",");
    }
    return this.#request("GET", "/api/v1/events/stream", { query });
  }

  search(request) {
    return this.#request("POST", "/api/v1/search", { payload: request });
  }

  listEntities({ limit = 100, offset = 0 } = {}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200) {
      throw new RangeError("entity limit must contain 1 to 200 records");
    }
    if (!Number.isSafeInteger(offset) || offset < 0) {
      throw new RangeError("entity offset must be a non-negative safe integer");
    }
    if (offset > 1_000_000) throw new RangeError("entity offset is too large");
    return this.#request("GET", "/api/v1/entities", {
      query: { limit: String(limit), offset: String(offset) },
    });
  }

  listRules() {
    return this.#request("GET", "/api/v1/rules");
  }

  listFindings({ limit = 100, offset = 0 } = {}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200) {
      throw new RangeError("finding limit must contain 1 to 200 records");
    }
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > 1_000_000) {
      throw new RangeError("finding offset must contain 0 to 1000000 records");
    }
    return this.#request("GET", "/api/v1/findings", {
      query: { limit: String(limit), offset: String(offset) },
    });
  }

  listIncidents({ limit = 100, offset = 0 } = {}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200) {
      throw new RangeError("incident limit must contain 1 to 200 records");
    }
    if (!Number.isSafeInteger(offset) || offset < 0) {
      throw new RangeError("incident offset must be a non-negative safe integer");
    }
    if (offset > 1_000_000) throw new RangeError("incident offset is too large");
    return this.#request("GET", "/api/v1/incidents", {
      query: { limit: String(limit), offset: String(offset) },
    });
  }

  getEntity(entityId) {
    const value = boundedString(entityId, "entityId", 128);
    if (!/^cmp_[A-Za-z0-9]+$/.test(value)) throw new TypeError("entityId is invalid");
    return this.#request("GET", `/api/v1/entities/${value}`);
  }

  getFinding(findingId) {
    const value = boundedString(findingId, "findingId", 128);
    if (!/^fnd_[A-Za-z0-9]+$/.test(value)) throw new TypeError("findingId is invalid");
    return this.#request("GET", `/api/v1/findings/${value}`);
  }

  getIncident(incidentId) {
    const value = boundedString(incidentId, "incidentId", 128);
    if (!/^inc_[A-Za-z0-9]+$/.test(value)) throw new TypeError("incidentId is invalid");
    return this.#request("GET", `/api/v1/incidents/${value}`);
  }

  integrations() {
    return this.#request("GET", "/api/v1/integrations");
  }

  deliveries({ state, destinationId, limit = 100, offset = 0 } = {}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200) {
      throw new RangeError("delivery limit must contain 1 to 200 records");
    }
    if (!Number.isSafeInteger(offset) || offset < 0) {
      throw new RangeError("delivery offset must be a non-negative safe integer");
    }
    if (offset > 1_000_000) throw new RangeError("delivery offset is too large");
    const query = { limit: String(limit), offset: String(offset) };
    if (state !== undefined) {
      if (!["queued", "retry", "ack_pending", "delivered", "dead_letter"].includes(state)) {
        throw new TypeError("delivery state is invalid");
      }
      query.state = state;
    }
    if (destinationId !== undefined) {
      const value = boundedString(destinationId, "destinationId", 256);
      if (!/^integration:\/\/[A-Za-z0-9_.@/-]+$/.test(value)) {
        throw new TypeError("destinationId is invalid");
      }
      query.destination_id = value;
    }
    return this.#request("GET", "/api/v1/integrations/deliveries", { query });
  }

  processIntegrations({ limit = 25 } = {}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new RangeError("integration process limit must contain 1 to 100 records");
    }
    return this.#request("POST", "/api/v1/integrations/process", {
      payload: { limit },
    });
  }

  redriveDelivery(deliveryId, reason) {
    const value = boundedString(deliveryId, "deliveryId", 128);
    if (!/^idl_[0-9a-f]{32}$/.test(value)) throw new TypeError("deliveryId is invalid");
    const boundedReason = boundedString(reason, "reason", 512);
    if (boundedReason.length < 3) throw new TypeError("reason is too short");
    return this.#request("POST", `/api/v1/integrations/deliveries/${value}/redrive`, {
      payload: { reason: boundedReason },
    });
  }
}

export { SCHEMA_VERSION as TELEMETRY_SCHEMA_VERSION };
