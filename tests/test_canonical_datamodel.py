from __future__ import annotations

import json
import unittest

from pydantic import ValidationError

from agentsec.contracts import DecisionAction
from agentsec.datamodel import (
    ActionRecord,
    ActionStatus,
    CANONICAL_SCHEMA_VERSION,
    CanonicalBundle,
    CanonicalMigrator,
    CanonicalRecordEnvelope,
    EventRecord,
    InvestigationRecord,
    InvestigationStatus,
    JudgmentRecord,
    RecordType,
    canonical_bundle_from_pipeline,
    event_record_from_telemetry,
)
from agentsec.pipeline import SecurityPipeline
from agentsec.scenarios import forge_scenarios
from agentsec.telemetry import (
    TelemetryCollector,
    TelemetryContext,
    TelemetryEventKind,
    TelemetryInput,
)


CANARY = "CANONICAL-DATA-MODEL-RAW-CONTENT-CANARY"
ID_FIELDS = {
    RecordType.EVENT: "event_id",
    RecordType.EVIDENCE: "evidence_id",
    RecordType.ENTITY: "entity_id",
    RecordType.ALERT: "alert_id",
    RecordType.FINDING: "finding_id",
    RecordType.INCIDENT: "incident_id",
    RecordType.INVESTIGATION: "investigation_id",
    RecordType.JUDGMENT: "judgment_id",
    RecordType.ACTION: "action_id",
}


class CanonicalDataModelTests(unittest.TestCase):
    def pipeline_bundle(self) -> CanonicalBundle:
        event = forge_scenarios()["indirect_injection_secret_egress"].model_copy(
            update={"attributes": {"raw_prompt": CANARY}}
        )
        result = SecurityPipeline().process(event).alerts[0]
        return canonical_bundle_from_pipeline(result)

    def complete_bundle(self) -> CanonicalBundle:
        bundle = self.pipeline_bundle()
        incident = next(
            record for record in bundle.records if record.record_type == RecordType.INCIDENT
        )
        evidence = next(
            record for record in bundle.records if record.record_type == RecordType.EVIDENCE
        )
        investigation = InvestigationRecord(
            tenant_id=bundle.tenant_id,
            investigation_id="inv_canonical_test",
            incident_id=incident.incident_id,
            status=InvestigationStatus.RUNNING,
            hypothesis="The observed effect proposal is an indirect prompt-injection chain.",
            evidence_ids=[evidence.evidence_id],
        )
        return CanonicalBundle(
            tenant_id=bundle.tenant_id,
            records=[*bundle.records, investigation],
        )

    def test_pipeline_projection_produces_all_reference_valid_first_class_records(self) -> None:
        bundle = self.complete_bundle()
        record_types = {record.record_type for record in bundle.records}
        self.assertEqual(record_types, set(RecordType))
        encoded = bundle.model_dump_json()
        self.assertNotIn(CANARY, encoded)
        self.assertIn("content_sha256", encoded)

    def test_bundle_rejects_cross_tenant_and_unresolved_references(self) -> None:
        bundle = self.pipeline_bundle()
        first = bundle.records[0].model_copy(update={"tenant_id": "tenant-other"})
        with self.assertRaisesRegex(ValidationError, "cannot cross tenants"):
            CanonicalBundle(
                tenant_id=bundle.tenant_id,
                records=[first, *bundle.records[1:]],
            )

        event_index = next(
            index
            for index, record in enumerate(bundle.records)
            if isinstance(record, EventRecord)
        )
        broken_event = bundle.records[event_index].model_copy(
            update={"evidence_ids": ["evd_missing"]}
        )
        records = list(bundle.records)
        records[event_index] = broken_event
        with self.assertRaisesRegex(ValidationError, "unresolved evidence"):
            CanonicalBundle(tenant_id=bundle.tenant_id, records=records)

    def test_judgment_and_action_lifecycle_invariants_fail_closed(self) -> None:
        bundle = self.pipeline_bundle()
        judgment = next(
            record for record in bundle.records if isinstance(record, JudgmentRecord)
        )
        with self.assertRaisesRegex(ValidationError, "cannot weaken"):
            JudgmentRecord.model_validate(
                judgment.model_dump(
                    mode="json",
                    exclude={"action", "deterministic_action"},
                )
                | {
                    "action": DecisionAction.ALLOW,
                    "deterministic_action": DecisionAction.DENY,
                }
            )
        action = next(record for record in bundle.records if isinstance(record, ActionRecord))
        with self.assertRaisesRegex(ValidationError, "completed_at"):
            ActionRecord.model_validate(
                action.model_dump(mode="json", exclude={"status", "completed_at"})
                | {"status": ActionStatus.SUCCEEDED}
            )

    def test_envelope_digest_detects_mutation(self) -> None:
        record = self.pipeline_bundle().records[0]
        envelope = CanonicalRecordEnvelope.wrap(
            record, source_schema_version=CANONICAL_SCHEMA_VERSION
        )
        self.assertEqual(len(envelope.record_sha256), 64)
        payload = envelope.model_dump(mode="json")
        payload["record_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValidationError, "digest mismatch"):
            CanonicalRecordEnvelope.model_validate(payload)

    def test_every_record_type_migrates_from_documented_beta_shape(self) -> None:
        bundle = self.complete_bundle()
        for record in bundle.records:
            legacy = record.model_dump(mode="json")
            legacy["schema_version"] = "0.9.0"
            legacy["tenant"] = legacy.pop("tenant_id")
            legacy["id"] = legacy.pop(ID_FIELDS[record.record_type])
            legacy["timestamp"] = legacy.pop("created_at")

            migrated = CanonicalMigrator.migrate(legacy)

            self.assertEqual(migrated.record, record)
            self.assertEqual(migrated.source_schema_version, "0.9.0")
            self.assertEqual(
                migrated.migrations_applied,
                ["%s:0.9.0->1.0.0" % record.record_type.value],
            )

    def test_current_record_is_identity_migration_and_future_version_is_rejected(self) -> None:
        record = self.pipeline_bundle().records[0]
        current = CanonicalMigrator.migrate(record.model_dump(mode="json"))
        self.assertEqual(current.record, record)
        self.assertEqual(current.migrations_applied, [])

        future = record.model_dump(mode="json")
        future["schema_version"] = "99.0.0"
        with self.assertRaisesRegex(ValueError, "unsupported canonical schema version"):
            CanonicalMigrator.migrate(future)

    def test_telemetry_adapter_preserves_metadata_and_excludes_raw_content(self) -> None:
        telemetry = TelemetryInput(
            event_id="tel_canonical_001",
            context=TelemetryContext(
                tenant_id="tenant-a",
                application_id="app-a",
                agent_id="agent-a",
                session_id="session-a",
                trace_id="trace-a",
                source_id="sdk://python/app-a",
                source_type="python-sdk",
                collector_id="collector-a",
            ),
            kind=TelemetryEventKind.MODEL_REQUEST,
            operation="model.generate",
            content={"input": CANARY},
        )
        capture = TelemetryCollector().capture(telemetry)
        assert capture.event is not None

        canonical = event_record_from_telemetry(capture.event)

        self.assertEqual(canonical.event_kind, "model_request")
        self.assertEqual(canonical.session_id, "session-a")
        self.assertNotIn(CANARY, json.dumps(canonical.model_dump(mode="json")))


if __name__ == "__main__":
    unittest.main()
