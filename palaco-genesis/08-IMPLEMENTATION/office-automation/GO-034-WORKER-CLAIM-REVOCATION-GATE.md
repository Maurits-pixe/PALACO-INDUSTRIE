# ∆ GO-034 — Worker Claim & Final Revocation Gate

GO-034 closes the worker-side race boundary introduced by asynchronous execution.

## Worker claim

A worker cannot claim execution from a stale read.

The durable sequence is:

LOCK → RE-READ CURRENT STATE → TRANSITION CHECK → APPEND → PROJECT → OUTBOX → COMMIT

Only PENDING → EXECUTING is permitted for a worker claim.

REVOKED, EXPIRED, COMPLETED, FAILED, and CANCELLED are fail-closed for a worker claim.

## Final revocation gate

A queue delay, retry, or worker hand-off may occur after authorization and signing. Therefore a durable state check is required immediately before the external side-effect boundary.

The final sequence is:

DURABLE REVOCATION CHECK → AUTHORIZATION CHECK → SIGNATURE/PROVENANCE CHECK → IDEMPOTENCY CHECK → TRANSPORT

The checks remain distinct. A non-revoked state does not itself grant authorization.

## Outbox concurrency

The outbox claim contract uses FOR UPDATE SKIP LOCKED so concurrent dispatchers do not select the same pending signal.

The outbox is a propagation mechanism only.

## Transition policy

The Rust repository boundary now exposes a deterministic permits_transition policy. Unknown or terminal transitions return false.

This is intentionally fail-closed.

## Constitutional invariants

- REVOKE IS FIRST-CLASS
- NO CONTINUED EXECUTION AFTER REVOCATION
- AUTHORIZATION ≠ EXECUTION
- ACCESS ≠ AUTHORIZATION
- SIGNATURE ≠ AUTHORIZATION
- PROVENANCE ≠ AUTHORIZATION
- OUTBOX ≠ EXECUTION
- REVOCATION ≠ EXPIRATION

## Verification

The SQL/Rust contracts and unit-level contract assertions were committed to GitHub.

No live PostgreSQL integration run is claimed because the available GitHub connector does not provide a PostgreSQL runtime.
