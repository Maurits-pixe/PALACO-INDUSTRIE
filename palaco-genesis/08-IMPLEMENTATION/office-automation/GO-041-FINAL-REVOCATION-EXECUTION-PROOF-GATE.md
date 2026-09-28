# ∆ GO-041 — Final Revocation + Execution Proof Gate

## Purpose

Establish the final fail-closed boundary immediately before an external side-effect.

## Final sequence

`DURABLE COMMIT → FINAL AUTHORIZATION RE-READ → REQUIRE EXECUTING → VERIFY PROOF → EXTERNAL SIDE EFFECT`

The final gate requires:

- authorization still `GRANTED`;
- execution still `EXECUTING`;
- exact authorization reference;
- exact provenance reference;
- exact canonical signed-request SHA-256;
- exact signature reference.

Any mismatch blocks the side-effect.

## Revocation race

The durable gate is deliberately followed by the external adapter boundary. The adapter must perform the freshest available revocation check immediately before the network operation.

If revocation is observed, execution stops and no new external operation is initiated.

A revocation after an external system has already accepted the operation cannot be retroactively undone by this gate; the resulting external reference must therefore be retained in the execution receipt for audit/reconciliation.

## Constitutional separation

`REVOCATION ≠ EXPIRATION`

`FINAL GATE ≠ AUTHORIZATION GRANT`

`PROOF ≠ AUTHORIZATION`

`OUTBOX ≠ EXECUTION`

`COMMIT ≠ SIDE EFFECT`

## Verification status

Added migration, Rust contract, and implementation documentation.

No live PostgreSQL integration run is claimed.
