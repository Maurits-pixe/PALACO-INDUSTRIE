# ∆ GO-034 — PostgreSQL Worker Runtime Adapter

## Implemented

- Added the concrete `PostgresExecutionLedger` adapter using the PostgreSQL client boundary.
- Added durable state decoding and fail-closed transition validation.
- Implemented transactional lifecycle append: lock → validate → append → project → outbox → commit.
- Implemented durable idempotency claims bound to an execution identity.
- Implemented transactional first-class revocation with immutable lifecycle history and outbox propagation.
- Implemented locked outbox selection with `FOR UPDATE SKIP LOCKED`.

## Important boundary

This adapter does **not** claim that an outbox item has been externally published merely because it was selected. Delivery leasing/acknowledgement remains a separate concern and must be made crash-safe before production dispatch is enabled.

Likewise, durable idempotency claiming and lifecycle creation are separate repository operations at this stage. The production consequential boundary must compose them atomically so a crash cannot leave an idempotency claim without its corresponding lifecycle record.

## Constitutional safety

The adapter never grants authorization. Database access is persistence infrastructure only.

`DATABASE ACCESS ≠ AUTHORIZATION`

`IDEMPOTENCY ≠ AUTHORIZATION`

`OUTBOX ≠ EXECUTION`

`REVOCATION ≠ EXPIRATION`

No live PostgreSQL integration run is claimed in this GO.
