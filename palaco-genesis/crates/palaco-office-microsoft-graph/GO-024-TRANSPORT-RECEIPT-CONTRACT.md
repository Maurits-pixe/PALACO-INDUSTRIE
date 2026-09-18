# GO-024 — Microsoft Graph Transport & Receipt Contract

## Purpose

GO-024 hardens the Microsoft Graph boundary without introducing credentials,
implicit authority, or a live network client.

## Contract

`GraphTransport` is the only external I/O boundary.

The adapter performs, in order:

1. event validation
2. authorization reference validation
3. execution-state validation
4. bounded action/path validation
5. idempotency claim
6. transport dispatch
7. HTTP success validation
8. external execution receipt

## Fail-closed rules

- authorization other than `Granted` blocks execution
- missing authorization reference blocks execution
- execution other than `Started` blocks execution
- unsupported action blocks execution
- duplicate idempotency key blocks execution
- non-2xx Graph response is a rejection, not a success receipt
- no task payload is invented because the current canonical event contract does not yet define one
- credentials and network clients remain outside this crate

## Constitutional chain

`AUTHORIZATION → EXECUTION COMMIT → SAFETY RE-CHECK → IDEMPOTENCY CLAIM → GRAPH ADAPTER → EXTERNAL EFFECT → TRACE`

## Deliberate boundary

GO-024 does **not** execute a real Microsoft Graph operation. A concrete authenticated
transport requires an explicit credential/connection design and an explicit external
write workflow. This GO establishes the contract that such a transport must satisfy.
