# PALACO INDUSTRIE — Bounded Signed-Floor Fetch v1.9 (DRAFT / HOLD)

The v1.8 prefetch adapter now enforces a configurable fetch deadline. Its `createPrefetchedSignedChallengeRegistry` options include `fetchTimeoutMs` (default 3000, integer 1..maxProofAgeMs). The previous monotonic proof-age limit (default 5000 ms) still applies.

The asynchronous fetch starts **outside** SQLite `BEGIN IMMEDIATE`. `Promise.race` enforces the deadline and an `AbortController` signals abort to `floorAuthority.fetchSignedFloor(challenge, signal)`. Timers are cleared on completion. A late or abandoned reply can never cause an issue/consume operation by that timed-out call. Any preparation error results in a DENY / GO-13 HOLD assessment.

IMPORTANT: an abort signal is cooperative. The transport implementation MUST handle it to cancel network I/O and release resources. An implementation that ignores abort may continue running after the API returns, though it cannot commit a challenge transaction. JavaScript running synchronously and blocking the event loop cannot be forcibly interrupted by timers. Do not perform synchronous network I/O or CPU-intensive verification in the fetch callback. This is not a remote signer, hardware trust anchor, or independently rollback-proof checkpoint store.

Tests added to `tests/distribution-prefetched-signed-challenge-registry.test.js`: hanging fetch, delayed valid response, and invalid timeout configuration. The full GitHub test suite must remain green before considering this version validated.

All security and release flags remain DENY, GO-13 HOLD; no merge or deployment.
