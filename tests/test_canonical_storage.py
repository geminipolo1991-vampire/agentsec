from __future__ import annotations

import hashlib
from datetime import timedelta
from pathlib import Path
import tempfile
import threading
import unittest

from agentsec.crypto import PocHmacSigner
from agentsec.datamodel import (
    EntityRecord,
    EventRecord,
    EvidenceRecord,
    IncidentRecord,
    RecordType,
    canonical_bundle_from_pipeline,
)
from agentsec.pipeline import SecurityPipeline
from agentsec.scenarios import forge_scenarios
from agentsec.storage import (
    BackupManifest,
    CanonicalRepository,
    ProtectedEvidenceBlob,
    RetentionPolicy,
)


CHECKPOINT_KEY = b"canonical-storage-checkpoint-test-key-at-least-32-bytes"
RAW_CANARY = "CANONICAL-STORAGE-RAW-EVIDENCE-CANARY"


def pipeline_bundle():
    event = forge_scenarios()["indirect_injection_secret_egress"].model_copy(
        update={"attributes": {"raw_prompt": RAW_CANARY}}
    )
    return canonical_bundle_from_pipeline(SecurityPipeline().process(event).alerts[0])


class CanonicalStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp.name) / "canonical.sqlite3")
        self.repository = CanonicalRepository(self.database)

    def tearDown(self) -> None:
        self.repository.close()
        self.temp.cleanup()

    def test_atomic_bundle_is_durable_idempotent_tenant_scoped_and_revisioned(self) -> None:
        bundle = pipeline_bundle()
        unresolved_event = next(
            record for record in bundle.records if isinstance(record, EventRecord)
        )
        with self.assertRaisesRegex(ValueError, "reference is unresolved"):
            self.repository.commit(unresolved_event)
        receipts = self.repository.commit_bundle(bundle)
        self.assertTrue(all(not receipt.duplicate for receipt in receipts))
        self.assertTrue(self.repository.verify(bundle.tenant_id).valid)
        self.assertNotIn(RAW_CANARY.encode("utf-8"), Path(self.database).read_bytes())
        incident = next(record for record in bundle.records if isinstance(record, IncidentRecord))

        duplicates = self.repository.commit_bundle(bundle)
        self.assertTrue(all(receipt.duplicate for receipt in duplicates))
        self.repository.close()
        self.repository = CanonicalRepository(self.database)
        restored = self.repository.get(
            bundle.tenant_id, RecordType.INCIDENT, incident.incident_id
        )
        self.assertEqual(restored, incident)
        with self.assertRaises(KeyError):
            self.repository.get("tenant-other", RecordType.INCIDENT, incident.incident_id)

        revised_score = incident.risk_score - 1 if incident.risk_score else 1
        revised = incident.model_copy(update={"risk_score": revised_score})
        receipt = self.repository.commit(revised)
        self.assertEqual(receipt.revision, 2)
        self.assertEqual(
            len(
                self.repository.history(
                    bundle.tenant_id, RecordType.INCIDENT, incident.incident_id
                )
            ),
            2,
        )

        event = next(record for record in bundle.records if isinstance(record, EventRecord))
        with self.assertRaisesRegex(ValueError, "immutable"):
            self.repository.commit(event.model_copy(update={"outcome": "changed"}))

    def test_concurrent_same_record_commits_once(self) -> None:
        event = next(record for record in pipeline_bundle().records if isinstance(record, EntityRecord))
        receipts = []
        receipt_lock = threading.Lock()

        def commit() -> None:
            receipt = self.repository.commit(event)
            with receipt_lock:
                receipts.append(receipt)

        threads = [threading.Thread(target=commit) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(not item.duplicate for item in receipts), 1)
        self.assertEqual(sum(item.duplicate for item in receipts), 11)
        self.assertEqual(self.repository.latest_head(event.tenant_id)[0], 1)

    def test_record_and_ledger_tamper_reports_first_broken_entry(self) -> None:
        bundle = pipeline_bundle()
        self.repository.commit_bundle(bundle)
        event = next(record for record in bundle.records if isinstance(record, EventRecord))
        self.repository._connection.execute(
            "UPDATE canonical_records SET record_json = ? WHERE tenant_id = ? "
            "AND record_type = 'event' AND record_id = ?",
            ('{"tampered":true}', bundle.tenant_id, event.event_id),
        )

        result = self.repository.verify(bundle.tenant_id)

        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "record_payload_mismatch")
        self.assertGreaterEqual(result.first_broken_sequence, 1)

    def test_protected_evidence_is_ciphertext_only_and_integrity_checked(self) -> None:
        bundle = pipeline_bundle()
        self.repository.commit_bundle(bundle)
        evidence = next(
            record for record in bundle.records if isinstance(record, EvidenceRecord)
        )
        ciphertext = "test-ciphertext-envelope-001"
        blob = ProtectedEvidenceBlob(
            evidence_id=evidence.evidence_id,
            ciphertext=ciphertext,
            key_reference="test-key://evidence/001",
            algorithm="TEST-AUTHENTICATED-PROTECTOR",
            plaintext_sha256=evidence.content_sha256,
            ciphertext_sha256=hashlib.sha256(ciphertext.encode("utf-8")).hexdigest(),
        )
        self.repository.put_protected_evidence(bundle.tenant_id, blob)

        self.assertEqual(
            self.repository.get_protected_evidence(bundle.tenant_id, evidence.evidence_id),
            blob,
        )
        self.assertNotIn(RAW_CANARY.encode("utf-8"), Path(self.database).read_bytes())
        mismatched = blob.model_copy(update={"plaintext_sha256": "0" * 64})
        with self.assertRaisesRegex(ValueError, "plaintext receipt"):
            self.repository.put_protected_evidence(bundle.tenant_id, mismatched)

        self.repository._connection.execute(
            "UPDATE protected_evidence_blobs SET ciphertext = 'tampered' "
            "WHERE tenant_id = ? AND evidence_id = ?",
            (bundle.tenant_id, evidence.evidence_id),
        )
        result = self.repository.verify(bundle.tenant_id)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "protected_evidence_mismatch")

    def test_signed_checkpoint_survives_restart_and_detects_mutation(self) -> None:
        bundle = pipeline_bundle()
        self.repository.commit_bundle(bundle)
        signer = PocHmacSigner(CHECKPOINT_KEY)
        checkpoint = self.repository.create_checkpoint(bundle.tenant_id, signer)
        self.repository.close()
        self.repository = CanonicalRepository(self.database)

        durable = self.repository.get_checkpoint(checkpoint.checkpoint_id)
        self.assertTrue(self.repository.verify_checkpoint(durable, signer).valid)
        tampered = durable.model_copy(update={"current_hash": "0" * 64})
        result = self.repository.verify_checkpoint(tampered, signer)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "checkpoint_signature_invalid")

    def test_retention_erases_payload_and_blob_but_preserves_chain_and_holds(self) -> None:
        bundle = pipeline_bundle()
        self.repository.commit_bundle(bundle)
        evidence = next(
            record for record in bundle.records if isinstance(record, EvidenceRecord)
        )
        ciphertext = "test-ciphertext-envelope-retention"
        self.repository.put_protected_evidence(
            bundle.tenant_id,
            ProtectedEvidenceBlob(
                evidence_id=evidence.evidence_id,
                ciphertext=ciphertext,
                key_reference="test-key://evidence/retention",
                algorithm="TEST-AUTHENTICATED-PROTECTOR",
                plaintext_sha256=evidence.content_sha256,
                ciphertext_sha256=hashlib.sha256(ciphertext.encode("utf-8")).hexdigest(),
            ),
        )
        self.repository.place_hold(
            bundle.tenant_id,
            RecordType.EVIDENCE,
            evidence.evidence_id,
            reason="active_security_investigation",
        )
        policy = RetentionPolicy(
            policy_id="one-day-test",
            retention_days={record_type: 1 for record_type in RecordType},
        )
        evaluated_at = max(receipt.committed_at for receipt in self.repository.commit_bundle(bundle))
        first = self.repository.apply_retention(
            policy,
            evaluated_at=evaluated_at.replace(microsecond=0) + timedelta(days=2),
        )
        self.assertGreater(first.expired_payloads, 0)
        self.assertGreaterEqual(first.held_payloads, 1)
        self.assertIsInstance(
            self.repository.get(bundle.tenant_id, RecordType.EVIDENCE, evidence.evidence_id),
            EvidenceRecord,
        )

        self.repository.release_hold(
            bundle.tenant_id, RecordType.EVIDENCE, evidence.evidence_id
        )
        second = self.repository.apply_retention(
            policy,
            evaluated_at=evaluated_at.replace(microsecond=0) + timedelta(days=3),
        )
        self.assertEqual(second.expired_blobs, 1)
        with self.assertRaises(KeyError):
            self.repository.get(bundle.tenant_id, RecordType.EVIDENCE, evidence.evidence_id)
        with self.assertRaises(KeyError):
            self.repository.get_protected_evidence(bundle.tenant_id, evidence.evidence_id)
        verification = self.repository.verify(bundle.tenant_id)
        self.assertTrue(verification.valid)
        self.assertGreater(verification.expired_payloads, 0)

    def test_verified_backup_restore_and_manifest_tamper(self) -> None:
        bundle = pipeline_bundle()
        self.repository.commit_bundle(bundle)
        backup_path = Path(self.temp.name) / "backup.sqlite3"
        manifest = self.repository.create_backup(backup_path)
        restore_path = Path(self.temp.name) / "restored.sqlite3"

        restored = CanonicalRepository.restore_backup(manifest, restore_path)
        try:
            self.assertTrue(restored.verify(bundle.tenant_id).valid)
            self.assertEqual(
                restored.latest_head(bundle.tenant_id),
                self.repository.latest_head(bundle.tenant_id),
            )
        finally:
            restored.close()

        invalid = BackupManifest.model_validate(
            manifest.model_dump(mode="json") | {"sha256": "0" * 64}
        )
        with self.assertRaisesRegex(ValueError, "manifest digest mismatch"):
            CanonicalRepository.restore_backup(
                invalid, Path(self.temp.name) / "invalid-restore.sqlite3"
            )


if __name__ == "__main__":
    unittest.main()
