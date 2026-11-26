# PALACO INDUSTRIE — Uncooperative Transport Permit Retention v2.3 (DRAFT / HOLD)

v2.3 hardens `distribution/prefetched-signed-challenge-registry.js` against transports that ignore the `AbortSignal` after the v1.9 `fetchTimeoutMs` deadline.

## Change

The caller still receives a fail-closed rejection at the configured deadline. However, when the underlying fetch Promise is not settled at timeout, its local `maxInFlight` and optional shared `sharedAdmission` permits remain reserved until that underlying Promise resolves or rejects. A late signed floor never triggers a challenge operation after the timeout. Releasing capacity after a late rejection is handled without propagating an unhandled rejection. All external authority calls still occur before SQLite `BEGIN IMMEDIATE`.

The new tests verify that two registry instances sharing one admission controller cannot exceed the budget while an aborted fetch remains unresolved. They also verify release after late resolution or rejection and that late signed responses cannot create challenges.

## Security / availability tradeoff

This is deliberately fail-closed: an authority transport that never settles may hold a permit for the remainder of the process lifetime. The admission controller does not forcibly cancel asynchronous I/O. Operators MUST supply an abort-aware transport with reliable resource reclamation, independent timeouts at the network layer, circuit breakers, process-level watchdogs and quotas. No guarantee is made for synchronous JavaScript blocking the event loop, or for separate processes/hosts unless they share an independent distributed admission system.

No production authority, key provisioning, release, install, merge or deployment is authorized; all outcomes retain `authorization=DENY`, `go13=HOLD` and publication restrictions.

Test with `npm test`; GitHub Actions must confirm the exact final commit.
