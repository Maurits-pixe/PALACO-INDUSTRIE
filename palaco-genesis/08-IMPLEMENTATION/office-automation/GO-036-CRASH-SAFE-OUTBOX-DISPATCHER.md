# ∆ GO-036 — Crash-Safe Outbox Dispatcher Adapter

Implemented a concrete PostgreSQL dispatcher for the GO-035 lease contract.

## Runtime flow

LEASE → COMMIT → PUBLISH → ACK

A dispatcher crash after lease acquisition does not mark the signal delivered. Once the lease expires, another worker can reclaim it.

## Safety properties

- `FOR UPDATE SKIP LOCKED` prevents concurrent selection of the same available row.
- Lease ownership is stored durably.
- Acknowledgement requires the same worker identity that acquired the lease.
- Acknowledgement is only possible while `dispatched_at` is still null.
- The underlying office action is not executed by the dispatcher.
- Empty worker identity and invalid lease duration fail closed.

## Boundary

The dispatcher is propagation infrastructure. It does not create authorization and does not execute Microsoft Graph actions.

`OUTBOX ≠ EXECUTION`

`DISPATCH ≠ AUTHORIZATION`

`DELIVERY ≠ EXECUTION`

No live PostgreSQL integration run is claimed.
