# PALACO INDUSTRIE — Authority Fetch Admission Control v2.0 (DRAFT / HOLD)

The v1.9 prefetch adapter now supports `maxInFlight` (default 16, integer from 1 through 1024), limiting the number of concurrent signed-floor preparations started through a single `createPrefetchedSignedChallengeRegistry` instance.

Admission happens synchronously before any await, preventing concurrent callers of the **same registry instance** from surpassing this cap. Excess `issue` calls return `{issued:false,reason:'AUTHORITY_CAPACITY_REACHED'}`. Excess `consume` calls return a frozen blocked assessment with `AUTHORITY_CAPACITY_REACHED`; the challenge remains unconsumed. Each admitted operation releases its slot in `finally` whether it succeeds, fails signature verification, times out, or raises an exception.

These limits complement `fetchTimeoutMs` and `AbortSignal` (v1.9), and they do not change the v1.8 rule that the external authority fetch occurs before SQLite `BEGIN IMMEDIATE`. The v1.5 audit still validates the stored clock against an independently authenticated signed floor under the lock.

## Security and operational boundaries

- This is **per-instance in-memory admission control**. It does not bound requests across multiple registries, server processes, hosts, or a compromised/abandoned transport that ignores AbortSignal.
- A timed-out callback that ignores cancellation may keep underlying resources alive after its slot is released. Real production protection needs abort-aware transport, per-host rate limits, circuit breakers and system-level resource quotas.
- Capacity limits are not permission checks: every result remains authorization DENY, GO-13 HOLD, with no release/installation/publication authority.
- No independent signer, hardware rollback-resistant store, transport integration, deployment or merge is included.

Regression tests added: competing requests are capped, rejected consume calls preserve pending tokens, invalid configuration fails closed, and a failed fetch frees the slot. Run `node --test tests/distribution-prefetched-signed-challenge-registry.test.js` and the complete `npm test` suite. GitHub CI must verify the final commit.
