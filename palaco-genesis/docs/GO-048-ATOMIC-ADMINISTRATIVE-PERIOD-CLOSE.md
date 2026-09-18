# ∆ GO-048 — Atomic Administrative Period Close

## Boundary

GO-048 turns the GO-047 closing gate from a durable evidence contract into an
atomic PostgreSQL state transition.

Canonical transaction:

`LOCK → RE-READ → VERIFY → PERSIST GATE → CLOSE → COMMIT`

The transaction:

1. locks the target administrative period with `FOR UPDATE`;
2. re-reads its current state;
3. re-reads reconciliation observations bound to that period;
4. compares the durable mismatch/unknown counts with the caller-provided
   closing evidence;
5. fails closed if evidence is missing, stale, or unresolved;
6. persists the closing gate evidence;
7. transitions the period to `CLOSED`;
8. commits both durable changes together.

A concurrent closer cannot independently pass the same state boundary because
the period row is serialized by the row lock. PostgreSQL holds a `FOR UPDATE`
row lock until the transaction ends.

## Constitutional rules

- `LOCK ≠ AUTHORIZATION`
- `RE-READ ≠ TRUST`
- `EVIDENCE ≠ AUTHORIZATION`
- `GATE ≠ EXECUTION`
- `CLOSING ≠ DELETION`
- `CLOSED ≠ MUTABLE`
- `REPORTING ≠ AUTHORIZATION`

No ledger row is updated, deleted, or rewritten. No payment, bank, tax filing,
or other financial side effect is executed.

## Fail-closed conditions

The transaction rejects:

- an unknown period;
- a period already `CLOSED`;
- a period outside `OPEN` / `CLOSING`;
- missing/invalid closing evidence;
- a reconciliation snapshot whose durable counts differ from the submitted
  evidence;
- any unresolved mismatch;
- any unresolved unknown.

The gate evidence and `CLOSED` state are written in one transaction. If any
step fails, PostgreSQL rolls the transaction back, leaving neither a partial
gate nor a partial close.

## Database binding

GO-048 adds `period_id` to reconciliation observations. Existing observations
without a period binding remain historical evidence and are not silently
assigned to a period.

## Scope

This is an administrative control-plane transition only. It does not grant
authority and does not perform financial execution.
