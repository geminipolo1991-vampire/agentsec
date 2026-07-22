# Data handling

The first slice records metadata only. Raw prompts, model responses, tool results,
memory content, credentials, authorization headers, and secrets are prohibited in
general alert attributes.

Allowed model-review fields are alert/finding IDs, normalized operation and
resource classes, destination class, trust labels, data-classification labels,
policy/manifest versions, reason codes, and redacted evidence references.

Allowed external SOC fields are the same metadata subset plus severity, status,
owner reference, case ID, and a restricted evidence pivot. Export construction
must begin from this allowlist; it must not serialize raw evidence and remove
fields afterward.

Recursive redaction, model-bundle, and SOC-export tests use canary values to prove
that configured secrets and raw content are absent. The Splunk client receives
only `SocFindingExport`, and its dead letter contains that same allowlisted object.
Provider requests set storage off where the API supports it, but deploying a live
profile still requires a separate privacy, residency, retention, and contractual
review. Redaction is defense in depth; the preferred control remains never
placing raw content in the model/export contract.
