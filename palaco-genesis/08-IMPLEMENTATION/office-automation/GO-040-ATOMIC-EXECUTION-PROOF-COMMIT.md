# ∆ GO-040 — Atomic Execution Proof Commit

## Purpose

Close the boundary between a verified signed execution proof and the durable transition from `PENDING` to `EXECUTING`.

## Atomic sequence

`LOCK AUTHORIZATION → RE-READ → REQUIRE GRANTED → LOCK EXECUTION → REQUIRE PENDING → VERIFY PROOF → APPEND → PROJECT → OUTBOX → COMMIT`

The proof, authorization state, execution state, projection, and propagation signal are committed as one durable unit.

## Why this matters

A worker must not reach `EXECUTING` with a proof that was verified against stale authorization state. The authorization row and execution row are therefore re-read under lock inside the commit boundary.

If any validation fails, the transaction does not commit.

## External side effects

The database commit happens before the external side-effect boundary:

`DURABLE COMMIT → FINAL REVOCATION CHECK → EXTERNAL SIDE EFFECT`

No Microsoft Graph call is made by this transaction.

## Constitutional separation

`PROOF ≠ AUTHORIZATION`

`AUTHORIZATION ≠ EXECUTION`

`COMMIT ≠ SIDE EFFECT`

`OUTBOX ≠ EXECUTION`

## Verification status

Added the PostgreSQL migration and Rust contract.

No live PostgreSQL integration run is claimed.
