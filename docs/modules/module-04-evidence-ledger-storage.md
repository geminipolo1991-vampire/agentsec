# Module 4 — Evidence ledger and storage

Status: verified on 2026-07-23  
Storage contracts: 1.0.0

## Comparison baseline

Before this loop, the alert ledger, finding/incident stores, provenance,
checkpoints, approval use, and most workflow records lived in Python process
memory. Module 2 added a durable SQLite intake spool, but that spool was not the
canonical evidence system of record. Restart-safe canonical revisions,
tenant-specific integrity chains, protected evidence blobs, retention, legal
hold, and backup/restore were missing.

## Implemented remediation

- Transactional SQLite repository for all nine Module 3 canonical record types.
- Atomic `CanonicalBundle` commits with database-enforced transaction rollback.
- Tenant, type, record ID, and revision keys on every canonical payload.
- Durable current heads plus revision history for mutable records.
- Immutable Event, Evidence, Alert, Judgment, and Action identity: changed
  content under the same ID fails closed.
- Idempotent duplicate commits return the original receipt and do not extend the
  ledger.
- Repository-level reference checks prevent single-record writes from bypassing
  Module 3 bundle referential integrity.
- Append-only, monotonically sequenced hash chain per tenant. Every entry binds
  tenant, sequence, type, ID, revision, payload digest, and previous hash.
- Detailed verification checks sequence, previous/current hashes, record
  receipts, active payload digests, retention tombstones, and protected evidence
  ciphertext receipts.
- Ciphertext-only evidence blob API. It accepts an externally protected envelope
  only after its plaintext receipt matches the canonical `EvidenceRecord`; no
  raw-content storage method exists.
- Signed checkpoints are stored durably and verify after restart against any
  later intact ledger head.
- Versioned retention policy covers every canonical record type.
- Legal hold requires a fixed machine-readable reason and prevents payload/blob
  expiry.
- Retention cryptographically erases payload/ciphertext while retaining hashes,
  ledger continuity, and policy-bound tombstones.
- Online SQLite backup is allowed only after every tenant verifies.
- Backup manifest binds path, size, SHA-256, time, and pre-backup tenant
  verification results.
- Restore refuses overwrite, verifies the backup manifest before copying, and
  verifies every restored tenant before returning the repository.
- WAL, full synchronization, foreign keys, busy timeout, and transaction locks
  support restart and concurrent local operation.

## Security invariants

1. Every primary identity and ledger chain is tenant-scoped.
2. Single-record persistence cannot introduce an unresolved security reference.
3. Immutable evidence/events cannot be rewritten under an existing identity.
4. Duplicate commits are stable; changed immutable content is a conflict.
5. Active payload bytes must match their committed digest.
6. Expired payloads must be absent and have an exact retention tombstone.
7. Protected evidence must be ciphertext with matching plaintext and ciphertext
   receipts; raw content has no persistence API.
8. Checkpoint mutation invalidates its signature.
9. Invalid storage cannot be backed up; invalid restore cannot be opened as a
   successful repository.
10. Backup and restore never overwrite an existing destination.

## Verification evidence

- `tests/test_canonical_storage.py`
  - atomic durable bundle, restart, idempotency, tenant isolation, and revision;
  - unresolved reference and immutable rewrite rejection;
  - concurrent duplicate commit accepts once;
  - payload/ledger tamper location;
  - ciphertext-only evidence receipt and tamper detection;
  - durable signed checkpoint and signature mutation;
  - retention, legal hold, cryptographic erasure, tombstone, and intact chain;
  - verified backup/restore and manifest-tamper rejection.
- Eight generated schemas cover commit, verification, protected blob,
  checkpoint, retention, and backup contracts.

## Deferred dependencies, not Module 4 completion shortcuts

- SQLite is the fully verified local reference adapter; a clustered PostgreSQL
  adapter and distributed immutable checkpoint archive are production
  deployment concerns, not an AWS task in this goal.
- Module 5 supplies indexed search rather than scanning repository revisions.
- Module 20 supplies authorized storage/retention operations in the UI.
- Module 24 supplies whole-database encryption, KMS/HSM key custody, platform
  RBAC, multi-region DR policy, and operational SLOs.

## Acceptance closure

Module 4 passed seven focused durability, concurrency, tamper, protected
evidence, checkpoint, retention, and recovery tests plus the complete repository
regression gate:

- 171 total Python tests and 5 TypeScript SDK tests;
- 2 analyst UI production build/render contract tests;
- 66 generated schema checks and 10 deterministic report checks;
- clean-package install reproduction, Python 3.9 compilation, secret scan,
  dependency check, release audit, workflow/Codex demos, all evaluation modes,
  and component ablation.

The local durable storage boundary is complete. Clustered production adapters,
whole-database key custody, and platform DR/SLO operation remain explicitly
assigned to deployment adapters and Module 24.
