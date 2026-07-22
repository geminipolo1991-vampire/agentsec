# Ledger-integrity runbook

1. Freeze effectful execution and preserve the ledger, receipts, and separately
   held checkpoint. Do not repair data in place.
2. Run detailed verification and record the first broken sequence and reason.
3. Verify the checkpoint signature before comparing its sequence/hash with the
   ledger. A valid chain without an independently trusted checkpoint is
   insufficient after possible producer compromise.
4. Correlate the affected interval with gateway effect observations, findings,
   approvals, authority use, ABOM changes, and downstream SOC receipts.
5. Rebuild state only from independently retained canonical records and document
   every excluded or reconstructed entry.
6. Re-run the immutable corpus and obtain human approval before resuming. Treat a
   signer or checkpoint-store compromise as a separate incident.
