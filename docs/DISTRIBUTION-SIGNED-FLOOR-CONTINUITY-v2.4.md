# PALACO INDUSTRIE — Signed Floor Continuity v2.4 (DRAFT / HOLD)

The v2.3 prefetched signed-floor registry now rejects an independently signed but regressed clock-floor value or signer epoch already superseded within the active process.

## Design

`distribution/signed-floor-continuity.js` supplies `createSignedFloorContinuity()` and `isSignedFloorContinuity()`. A fresh registry creates its own monitor by default. To protect multiple registries inside the **same process**, pass an explicitly shared monitor as `signedFloorContinuity` to each `createPrefetchedSignedChallengeRegistry` instance. Arbitrary forged monitor objects are rejected at construction.

Only a valid Ed25519 floor proof that passes nonce binding, independently pinned signer, minimum epoch and monotonic proof-age checks can be observed. `observe(epoch, minimumLastSeenMs)` requires both fields be non-decreasing relative to all previously accepted proofs; an otherwise valid signed response with lower epoch or lower floor is blocked before any SQLite writer transaction or challenge operation. The monitor advances synchronously in the JS isolate, and its immutable `snapshot()` is diagnostic only.

## Trust and availability limitations

This monitor is **in-memory**, not independent, durable, or cryptographically protected state. Restart, another server, separate Node.js process or restored instance can lose the high watermark. It cannot prove signer honesty, replace the independently protected minimum epoch, or prevent jointly rolled-back durable data. An authenticated signed proof may advance the in-memory floor even if the subsequent SQLite operation is rejected; this is intentionally conservative and may require new independent evidence before later operations.

All responses remain authorization DENY and GO-13 HOLD. No merge, deployment, installation, recovery grant, publication grant or trust-root rotation is included.

Tests: five module tests in `tests/distribution-signed-floor-continuity.test.js`, four integration tests added to `tests/distribution-prefetched-signed-challenge-registry.test.js`, and the full `npm test` workflow.
