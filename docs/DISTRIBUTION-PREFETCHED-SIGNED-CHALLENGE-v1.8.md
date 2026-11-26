# PALACO INDUSTRIE — Prefetched Signed Challenge Registry v1.8 (DRAFT / HOLD)

Module: `distribution/prefetched-signed-challenge-registry.js`.

The new `createPrefetchedSignedChallengeRegistry(db, {floorAuthority,clock,ttlMs,maxPending,maxRows,maxProofAgeMs,monotonicNow})` exports async `issue` and `consume` methods. Its chief objective is to keep external authority callbacks **outside** the SQLite `BEGIN IMMEDIATE` writer lock.

## Execution sequence

1. Generate a fresh cryptographically random 256-bit challenge for the external floor authority.
2. Await `floorAuthority.fetchSignedFloor(challenge)` BEFORE any SQLite transaction starts. No network transport is bundled.
3. Verify the Ed25519 response with v1.6 using independently pinned roots, an independently held minimum epoch, exact challenge binding and strict schema validation.
4. Reject a response if the proof preparation exceeds `maxProofAgeMs` on `process.hrtime.bigint()` (default 5000 ms). The transport itself requires a separate timeout and abort mechanism; this post-hoc age check cannot interrupt a hung request.
5. Pass a **single-use** signed-floor result to the v1.5 guarded SQLite factory. Inside `BEGIN IMMEDIATE`, the callback again checks monotonic proof age, then the registry compares the pre-update stored clock to the bound, audits existing records, and performs exactly one issue/consume operation. A callback cannot reuse the floor a second time.

## Important security boundaries

- The callback is an externally supplied async implementation. This code does not perform HTTPS, TLS pinning, transport authentication, deadline cancellation, remote consensus, or signed durable consumption receipts.
- A signed proof only authenticates an independently pinned key's response; a compromised authority could return a stale value for a fresh nonce. A separate rollback-resistant minimum epoch and a trusted monotonic floor source remain mandatory.
- A clock-floor retrieval failure during `consume` does **not** consume the outstanding challenge. Retrying within its TTL is possible after a successful new floor check. A completed consume still burns the token before receipt verification.
- The proof age check is local to one process and cannot establish wall-clock freshness or hardware monotonicity. Time elapsing during the SQLite audit is not bounded by the age callback; keep audits efficient and use operational timeouts.
- The legacy synchronous v1.7 and older factories remain available for compatibility; using v1.8 is an explicit choice. A real distributed deployment needs a transactional shared replay store and protected, rollback-resistant database state.

All operations retain `authorization=DENY`, `go13=HOLD`, `mayAdvance=false`, `mayRestore=false`, `mayRotate=false`, `mayInstall=false`, `mayPublish=false`. No merge, production rollout, credentials, deployment or issuer authority.

Regression command: `node --test tests/distribution-prefetched-signed-challenge-registry.test.js`. Nine tests added, with independent CI review required.
