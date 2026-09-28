# ∆ GO-038 — Durable Authorization Binding

## Purpose

Bind an execution durably to the authorization reference that permitted it, while preserving the constitutional distinction between authorization and execution.

## Binding

The durable record contains:

- execution identity;
- opaque authorization reference;
- authorization state;
- provenance reference;
- binding timestamp.

The binding is evidence of which authorization fact an execution references. It is **not** itself a grant.

## Fail-closed rules

- missing execution identity → reject;
- missing authorization reference → reject;
- missing provenance → reject;
- only `GRANTED` permits the authorization boundary;
- `REVOKED` and `EXPIRED` do not permit execution;
- conflicting authorization references for the same execution must be rejected;
- revocation and expiration remain distinct terminal conditions.

## Transaction boundary

`LOCK → RE-READ → REQUIRE GRANTED → BIND → COMMIT`

Later revocation/expiration propagates through an explicit lifecycle operation.

## Constitutional separation

`AUTHORIZATION ≠ EXECUTION`

`PROVENANCE ≠ AUTHORIZATION`

`BINDING ≠ GRANT`

`ACCESS ≠ AUTHORIZATION`

No external side effect is performed by this crate.

## Verification status

Contract, migration, and crate were added.

No live PostgreSQL integration run is claimed.
