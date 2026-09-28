# ∆ GO-037 — Atomic Idempotency + Initial Lifecycle

## Purpose

Close the crash window between a durable idempotency claim and creation of the initial execution lifecycle.

## Canonical transaction

`BEGIN → CLAIM IDEMPOTENCY → CREATE PENDING → PROJECT CURRENT → EMIT OUTBOX → COMMIT`

All five durable effects belong to one PostgreSQL transaction.

### Duplicate path

When the idempotency key already exists:

1. do not create a second lifecycle;
2. do not emit a second initial outbox signal;
3. return the existing execution identity;
4. preserve the original provenance and history.

### Failure semantics

Any failure before commit rolls back the idempotency claim, lifecycle record, current projection, and outbox signal together.

This removes the GO-034 crash window in which idempotency could be claimed without an initial lifecycle record.

## Constitutional boundaries

`IDEMPOTENCY ≠ AUTHORIZATION`

`PENDING ≠ EXECUTING`

`OUTBOX ≠ EXECUTION`

`DATABASE ACCESS ≠ AUTHORIZATION`

The transaction establishes durable state only. It does not grant authority and does not perform an external side effect.

## Verification status

The migration and transaction contract were added to the repository.

No live PostgreSQL integration run is claimed.
