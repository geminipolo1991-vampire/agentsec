export type TelemetryEventKindValue =
  | "model_request" | "model_response" | "model_call"
  | "tool_call_request" | "tool_call_result" | "agent_message"
  | "rag_retrieval" | "memory_read" | "memory_write"
  | "guardrail_decision" | "error" | "heartbeat";

export const TELEMETRY_SCHEMA_VERSION: "1.0.0";
export const TelemetryEventKind: Readonly<Record<string, TelemetryEventKindValue>>;

export interface TelemetryContext {
  tenant_id: string;
  application_id: string;
  agent_id: string;
  session_id: string;
  trace_id: string;
  source_id: string;
  source_type: string;
  collector_id: string;
  environment?: string;
  provider?: string;
  model_id?: string;
}

export interface TelemetryEventInput {
  schema_version?: "1.0.0";
  event_id?: string;
  occurred_at?: string;
  context: TelemetryContext;
  kind: TelemetryEventKindValue;
  span_id?: string;
  parent_span_id?: string;
  sequence?: number;
  operation?: string;
  resource?: string;
  destination?: string;
  tool_name?: string;
  data_classes?: string[];
  indicators?: string[];
  attributes?: Record<string, string | number | boolean>;
  content?: Record<string, unknown>;
  duration_ms?: number;
  input_tokens?: number;
  output_tokens?: number;
  success?: boolean;
  error_code?: string;
}

export function createTelemetryContext(input: TelemetryContext): Readonly<TelemetryContext>;
export function createTelemetryEvent(input: TelemetryEventInput): Readonly<TelemetryEventInput>;

export interface TelemetryTransport {
  send(event: TelemetryEventInput): Promise<unknown>;
  sendBatch(events: TelemetryEventInput[]): Promise<unknown>;
}

export class HttpTelemetryTransport implements TelemetryTransport {
  constructor(options: {
    endpoint: string;
    token: string;
    fetchImpl?: typeof fetch;
    allowLoopbackHttp?: boolean;
  });
  send(event: TelemetryEventInput): Promise<unknown>;
  sendBatch(events: TelemetryEventInput[]): Promise<unknown>;
}

export class SignedHttpTelemetryTransport implements TelemetryTransport {
  constructor(options: {
    endpoint: string;
    credentialId: string;
    secret: string;
    fetchImpl?: typeof fetch;
    allowLoopbackHttp?: boolean;
  });
  send(event: TelemetryEventInput): Promise<unknown>;
  sendBatch(events: TelemetryEventInput[]): Promise<unknown>;
}

export class AgentSecTelemetryClient {
  constructor(options: { transport: TelemetryTransport; includeContent?: boolean });
  emit(event: TelemetryEventInput): Promise<unknown>;
  emitBatch(events: TelemetryEventInput[]): Promise<unknown>;
}

export interface AgentSecExternalApiClientOptions {
  endpoint: string;
  token: string;
  fetchImpl?: typeof fetch;
  allowLoopbackHttp?: boolean;
}

export class AgentSecExternalApiClient {
  constructor(options: AgentSecExternalApiClientOptions);
  capabilities(): Promise<Record<string, unknown>>;
  streamEvents(options?: {
    limit?: number;
    cursor?: string;
    eventTypes?: Array<"finding" | "incident" | "alert" | "audit">;
  }): Promise<Record<string, unknown>>;
  search(request: Record<string, unknown>): Promise<Record<string, unknown>>;
  listEntities(options?: { limit?: number; offset?: number }): Promise<Record<string, unknown>>;
  getEntity(entityId: string): Promise<Record<string, unknown>>;
  listRules(): Promise<Record<string, unknown>>;
  listFindings(options?: { limit?: number; offset?: number }): Promise<Record<string, unknown>>;
  getFinding(findingId: string): Promise<Record<string, unknown>>;
  listIncidents(options?: { limit?: number; offset?: number }): Promise<Record<string, unknown>>;
  getIncident(incidentId: string): Promise<Record<string, unknown>>;
  integrations(): Promise<Record<string, unknown>>;
  deliveries(options?: {
    state?: "queued" | "retry" | "ack_pending" | "delivered" | "dead_letter";
    destinationId?: string;
    limit?: number;
    offset?: number;
  }): Promise<Record<string, unknown>>;
  processIntegrations(options?: { limit?: number }): Promise<Record<string, unknown>>;
  redriveDelivery(deliveryId: string, reason: string): Promise<Record<string, unknown>>;
}
