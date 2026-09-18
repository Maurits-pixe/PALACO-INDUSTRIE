# ∆ GO-033 — Transactional Outbox & Durable Idempotency

GO-033 closes a persistence correctness gap discovered during hardening of GO-032.

## Critical correction

A lifecycle ledger is append-only and may contain multiple transitions for the same execution. Therefore **idempotency claims cannot be uniquely constrained on the lifecycle table's idempotency_key**.

GO-033 separates:

- `palaco_execution_ledger` — immutable lifecycle history;
- `palaco_execution_idempotency` — one durable claim per idempotency key;
- `palaco_execution_current` — current-state projection;
- `palaco_execution_outbox` — transactional propagation facts.

This preserves exactly-once claim semantics without preventing legitimate lifecycle history.

## Transaction boundary

For every state-changing operation:

`LOCK → RE-READ → VALIDATE → APPEND → PROJECT → OUTBOX → COMMIT`

A worker must not rely on a previously observed state.

## Revocation

`REVOKE` performs the same locked transaction and writes both:

1. the immutable `REVOKED` lifecycle fact;
2. a `REVOKED` outbox signal.

Failure to dispatch the outbox never removes or weakens the durable revocation.

## Outbox semantics

The outbox is a propagation mechanism, not an execution queue.

An outbox dispatcher may deliver a lifecycle signal to another subsystem, but:

- dispatch does not grant authorization;
- dispatch does not authorize execution;
- dispatch failure does not roll back a committed revocation;
- external side effects remain outside the database transaction.

## Constitutional boundary

`IDEMPOTENCY ≠ AUTHORIZATION`

`OUTBOX ≠ EXECUTION`

`DATABASE ACCESS ≠ AUTHORIZATION`

`REVOCATION ≠ EXPIRATION`

`AUTHORIZATION ≠ EXECUTION`

## Verification status

The contracts and migration were written to GitHub. No live PostgreSQL instance was available through the GitHub connector, so PostgreSQL integration execution is **not claimed**.
