# PALACO INDUSTRIE — Shared Authority Admission v2.2 (DRAFT / HOLD)

**Purpose.** Prevent multiple signed-floor registry instances within one Node.js process from independently using their full request budgets against a shared authority. This is an optional, explicitly shared **in-process** budget, not distributed admission control.

## Contract

- `createSharedAuthorityAdmission({maxInFlight:32})` from `distribution/shared-authority-admission.js` produces a branded, frozen controller.
- Supply the same controller as `sharedAdmission` to `createPrefetchedSignedChallengeRegistry(db, options)` in each related instance. Construction rejects arbitrary forged controllers and unsafe capacity values.
- Capacity is acquired synchronously before the remote floor fetch. The controller returns a one-use release function. A `finally` releases the permit on proof success, verification failure, timeout, or SQLite audit failure.
- Excess `issue` requests return `issued:false,reason:SHARED_AUTHORITY_CAPACITY_REACHED`. Excess `consume` requests return a frozen `BLOCKED` assessment with that finding; the persisted challenge is untouched.
- If the local circuit breaker has reached the half-open recovery phase but the shared budget is full, the half-open probe reservation is cleared so a later probe remains possible.
- `snapshot()` returns a frozen, read-only view of active, capacity and available counts for diagnostics; this is not authentication or authority.

## Boundaries

This mechanism coordinates only code that explicitly shares the same object **in one Node.js process**. Separate processes, tenants or hosts require a different, independently secured distributed admission policy. It does not enforce resource reclamation for transports that ignore `AbortSignal`; do not confuse a returned permit with a terminated underlying network connection. The previous per-instance `maxInFlight`, `failureThreshold`, `cooldownMs`, signed Ed25519 floor verification, cryptographic challenge, SQLite transactional auditing and DENY / GO-13 HOLD remain unchanged.

Tests: `node --test tests/distribution-shared-authority-admission.test.js tests/distribution-prefetched-signed-challenge-registry.test.js`; full suite `npm test`. PR stays Draft, without merge, installation, deployment or release permission.
