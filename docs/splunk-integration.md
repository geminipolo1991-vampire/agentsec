# Splunk HEC integration

The HEC client constructs a new event only from `SocFindingExport`. It cannot
access raw prompts, tool results, memory content, credentials, or full sensitive
arguments. Authentication uses `Authorization: Splunk <token>` and JSON events
use `/services/collector/event` over HTTPS.

Delivery is idempotent by finding ID. Provider/transport failures create a local
dead letter containing only the already-allowlisted export object. Production
must persist and encrypt dead letters and, when indexer acknowledgment is
enabled, implement channel and acknowledgment polling before treating delivery as
durable.

Reference: https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.2/get-data-with-http-event-collector/format-events-for-http-event-collector

