# ∆ GO-039 — Signed Authorization Execution Proof

## Purpose

Close the proof boundary between:

1. durable authorization binding;
2. the exact canonical signed request;
3. cryptographic provenance;
4. the execution identity.

## Canonical chain

`EXECUTION → AUTHORIZATION REFERENCE → PROVENANCE → CANONICAL REQUEST SHA-256 → SIGNATURE → EXECUTION PROOF`

The proof verifies that these references agree. It does not manufacture authority.

## Verification

The proof is rejected when any required reference is absent or differs:

- execution identity;
- authorization reference;
- provenance reference;
- canonical signed-request digest;
- signature reference.

## Constitutional separation

`SIGNATURE ≠ AUTHORIZATION`

`PROVENANCE ≠ AUTHORIZATION`

`BINDING ≠ GRANT`

`EXECUTION PROOF ≠ EXECUTION AUTHORIZATION`

The actual authorization state must already be `GRANTED` at the constitutional boundary.

## Transaction

`LOCK AUTHORIZATION → RE-READ → REQUIRE GRANTED → LOCK EXECUTION → BIND PROOF → COMMIT`

External side effects remain outside the transaction.

## Verification status

Contract, migration, and Rust crate were added.

No live PostgreSQL integration run is claimed.
