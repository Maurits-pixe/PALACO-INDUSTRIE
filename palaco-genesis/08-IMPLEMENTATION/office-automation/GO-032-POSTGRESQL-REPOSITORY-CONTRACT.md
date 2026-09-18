# ∆ GO-032 — PostgreSQL Repository Contract

## Repository operations

The persistence adapter exposes these conceptual operations:
- append_transition
- claim_idempotency
- get_current_state
- revoke
- append_outbox_signal

All state-changing operations are transactional.

## Revocation

revoke(execution_id) must acquire the execution row lock, inspect current state, append REVOKED, update palaco_execution_current, append a REVOKED outbox signal, and commit as one transaction.

If the execution is already terminal, the repository must not silently convert its historical state. The caller receives a deterministic conflict/error.

## Worker claim

A worker must acquire the same execution lock before transitioning PENDING → EXECUTING. After the lock is acquired, the worker re-reads current state. If it is REVOKED, the claim fails closed.

This prevents a stale worker read from bypassing a committed revocation.

## Idempotency

The unique database index on idempotency_key is authoritative for durable duplicate prevention. A uniqueness conflict is not interpreted as permission to retry the external side effect.

## Outbox

The outbox propagates lifecycle facts. It is not an authorization mechanism. A dispatcher may publish REVOKED, but publication does not create authority and failure to publish does not erase durable revocation state.

## Side-effect boundary

The transaction ends before Microsoft Graph I/O.

DATABASE COMMIT ≠ EXTERNAL SIDE EFFECT

The production execution adapter must perform its final revocation check after loading durable state and immediately before transport.
