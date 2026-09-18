# ∆ GO-032 — PostgreSQL Execution Ledger

## Purpose

GO-032 promotes the execution ledger from a serialization-friendly in-memory model to a durable PostgreSQL persistence contract.

Constitutional boundary: **REVOKE IS FIRST-CLASS. NO CONTINUED EXECUTION AFTER REVOCATION.**

The database is an audit/state substrate. It does not grant authority, approve work, or perform external side effects.

## Transactional model

A lifecycle transition is written as an append-only ledger row inside one PostgreSQL transaction.

The transition transaction must:
1. lock the execution identity;
2. read the current state;
3. reject illegal terminal transitions;
4. append the new state;
5. update the current-state projection;
6. commit atomically.

REVOKED is terminal for queued execution. A revocation transaction therefore prevents a later worker from legitimately claiming the same execution after the revocation commit.

External Microsoft Graph I/O is not performed inside the database transaction.

## Idempotency

idempotency_key is unique at the database boundary. Duplicate claims return a conflict instead of authorizing a second side effect.

## Audit invariants

- history is append-only;
- execution identity is stable;
- trace identity is preserved;
- authorization reference is preserved;
- REVOKED remains distinguishable from EXPIRED;
- authorization is not inferred from ledger state;
- database access is not authorization;
- the outbox records propagation intent only.

## Canonical serialization

The existing JSON method is intentionally scoped as storage serialization. Cryptographic request signing continues to use the exact canonical byte contract from GO-028/PVB-011.

The database representation must never become an alternate signing representation.

## Failure behavior

If the transaction cannot establish the required lock, state, uniqueness constraint, or append operation, the operation fails closed and no external side effect is authorized.

## Migration

Migration: palaco-genesis/migrations/032_execution_ledger.sql

Creates palaco_execution_ledger, palaco_execution_current, and palaco_execution_outbox.

The outbox is an immutable propagation record for lifecycle signals such as REVOKED; it is not an execution queue and carries no authority.

## Constitutional separation

CONSENT ≠ AUTHORIZATION
AUTHORIZATION ≠ EXECUTION
ACCESS ≠ AUTHORIZATION
SIGNATURE ≠ AUTHORIZATION
PROVENANCE ≠ AUTHORIZATION
REVOCATION ≠ EXPIRATION

ExecutionLedger remains the domain model; PostgreSQL is its durable persistence boundary.
