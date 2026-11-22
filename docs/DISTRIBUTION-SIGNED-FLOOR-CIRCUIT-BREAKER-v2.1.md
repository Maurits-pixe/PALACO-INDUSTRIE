# PALACO INDUSTRIE — Signed-Floor Circuit Breaker v2.1 (DRAFT / HOLD)

The v2.0 prefetched signed-floor registry now includes a per-instance fail-closed circuit breaker.

- `failureThreshold`: consecutive signed-floor preparation failures before opening the circuit (default 3, allowed 1..100).
- `cooldownMs`: duration before one half-open recovery probe may attempt a new signed-floor request (default 30000, allowed 1..300000).
- In the OPEN state, issue returns `{issued:false, reason:'AUTHORITY_CIRCUIT_OPEN'}` and consume returns a frozen blocked assessment with the same finding. No external request or database mutation occurs.
- After cooldown, one HALF-OPEN probe is admitted. Competing calls remain blocked until it finishes. Valid signed proof closes the circuit; another preparation failure reopens it for a fresh cooldown.
- Circuit state uses `process.hrtime.bigint()` (or an injected monotonic test clock) and is independent for each registry instance. Fail-closed if the monotonic clock becomes unavailable.
- The existing `maxInFlight` capacity gate and `fetchTimeoutMs` deadline remain active, and the external fetch still occurs before SQLite BEGIN IMMEDIATE.

Only signed-floor preparation failures contribute to the breaker. A SQLite audit failure does not misclassify the external signer as broken. This circuit is local, non-durable, and not suitable as a cross-process or distributed admission controller. A stale or malicious signer with a valid key may still sign an unsound floor; independent roots, minimum epoch and rollback-resistant state remain mandatory. Underlying transports must honor AbortSignal and system-level quotas must be enforced separately.

All operations remain authorization DENY / GO-13 HOLD. No recovery, installation, publication, rotation, merge or deployment permission is created.

Regression tests were added to `tests/distribution-prefetched-signed-challenge-registry.test.js` for repeated failures, recovery, exclusive half-open probing, renewed cooldown, consume safety, and configuration validation. Run `npm test` and independently verify GitHub Actions before release review.
