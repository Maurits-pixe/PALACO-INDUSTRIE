# ∆ GO-031 — PERSISTENT EXECUTION LEDGER & REVOCATION AUDIT

**Status:** DRAFT / implementation branch

## Purpose

GO-031 gives Office automation a durable-friendly, append-only execution history.

The ledger records lifecycle transitions without replacing the constitutional authorization model.

## Ledger states

`PENDING → EXECUTING → COMPLETED`

Failure and cancellation are explicit alternatives:

- `FAILED`
- `CANCELLED`
- `REVOKED`
- `EXPIRED`

**REVOKED ≠ EXPIRED ≠ FAILED ≠ CANCELLED**

## Implemented

`ExecutionLedgerEntry` preserves:

- sequence
- execution ID
- event ID
- trace ID
- idempotency key
- authorization reference
- lifecycle state

`ExecutionLedger` provides:

- append-only transition recording
- explicit revocation recording
- immutable history access
- JSON serialization for durable storage
- JSON restoration for replay/audit
- latest-state revocation detection

The ledger does not grant authority and does not execute work.

## Constitutional properties

1. **PROVENANCE PRESERVED** — event, trace and authorization lineage remain attached.
2. **REVOKE IS FIRST-CLASS** — revocation is an explicit ledger state.
3. **HISTORY IS NOT ERASED** — revocation appends a transition rather than rewriting prior history.
4. **REPLAY IS OBSERVABLE** — serialized snapshots can be restored for audit.
5. **AUTHORIZATION ≠ EXECUTION** — the ledger records both but does not conflate them.
6. **SIGNATURE ≠ AUTHORIZATION** — cryptographic proof remains separate.

## Verification

A regression test records pending work, appends REVOKED, serializes the complete ledger, restores it, and verifies that both historical states remain present.

No live Microsoft Graph credentials or external writes are introduced.

Local Cargo tests have not been run through the GitHub connector and must be verified by CI/local engineering before merge.
