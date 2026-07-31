# Splunk HEC integration

Module 21 supersedes the earlier process-memory helper with the durable common
integration plane in `src/agentsec/integrations.py`. The legacy helper remains
as a compatibility reference; it is not the delivery path described here.

The connector constructs a new `ExternalSecurityEvent` only from the
allowlisted `SocFindingExport`. It cannot access raw prompts, model or memory
content, tool arguments/results, evidence bodies, arbitrary event attributes,
credentials, or authorization headers. HEC authentication uses
`Authorization: Splunk <runtime token>` and the exact HTTPS
`/services/collector/event` path.

Each finding and destination produces one stable durable delivery. When
`indexer_ack` is enabled, the event request carries a stable
`X-Splunk-Request-Channel`; an HTTP success without a valid `ackId` is rejected.
The delivery then remains `ack_pending` until a bounded
`/services/collector/ack` poll confirms that exact ID. Missing acknowledgment,
transport errors, or rejection retry with bounded exponential backoff and end
in an explicit dead letter. Governed redrive preserves the attempt history.

The raw acknowledgment ID is private connector state. APIs expose only its
SHA-256 commitment, the response-receipt commitment, attempt operation, safe
error code, and timestamps. The token is resolved from the policy-named
environment variable and is never stored in SQLite or returned by an API.

The checked-in Splunk destination is disabled and uses a reserved `.invalid`
host. Tests use an injected transport and therefore do not certify a Splunk
deployment. Even a positive indexer acknowledgment is evidence for the
configured Splunk HEC contract, not proof of retention policy, searchability,
alert generation, or an end-to-end SOC workflow.

References:

- [Splunk HEC event format](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.4/get-data-with-http-event-collector/format-events-for-http-event-collector)
- [Splunk HEC indexer acknowledgment](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.4/get-data-with-http-event-collector/about-http-event-collector-indexer-acknowledgment)
