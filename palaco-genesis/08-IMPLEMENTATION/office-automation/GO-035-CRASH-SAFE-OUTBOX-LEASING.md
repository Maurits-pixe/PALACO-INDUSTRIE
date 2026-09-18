# ∆ GO-035 — CRASH-SAFE OUTBOX LEASING

GO-035 hardens the transactional outbox against the failure mode where a dispatcher claims a signal and the process crashes before successful publication.

## Contract

Claim:

LOCK → SELECT PENDING/EXPIRED LEASE → ASSIGN LEASE → COMMIT

Publication:

LEASED SIGNAL → EXTERNAL PUBLICATION

Acknowledgement:

VERIFY LEASE OWNER → MARK DISPATCHED → CLEAR LEASE

A claim is **not** an acknowledgement.

## Lease semantics

The outbox now has:

- `leased_by`
- `lease_until`

A signal with an expired lease becomes eligible for another dispatcher.

The lifecycle fact remains immutable. Only delivery metadata changes.

## Constitutional boundary

The outbox dispatcher:

- does not grant authorization;
- does not alter authorization;
- does not execute the external action;
- only propagates durable state signals.

Therefore:

**OUTBOX ≠ EXECUTION**

**DISPATCH ≠ AUTHORIZATION**

**DELIVERY ≠ EXECUTION**

## Failure behavior

If a dispatcher crashes after lease acquisition:

1. no lifecycle state is fabricated;
2. no authorization is created;
3. the outbox fact remains;
4. after lease expiry, another dispatcher may reclaim it;
5. acknowledgement occurs only after successful publication.

## Production boundary

This GO adds the database migration and formal contract. The concrete adapter must consume the lease atomically and expose an explicit acknowledgement operation before production dispatch is enabled.

No live PostgreSQL integration run is claimed.
