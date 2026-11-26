# PALACO INDUSTRIE — Signed Clock Floor v1.6 (DRAFT / HOLD)

The module `distribution/signed-clock-floor.js` adds an independent Ed25519 verification contract for the external minimum clock bound consumed by the v1.5 audited SQLite challenge registry.

## API

- `clockFloorPayload(floor)` canonicalizes the versioned UTF-8 signature payload, with domain separation and a final newline.
- `verifySignedClockFloor(namespace,floor,endorsement,pinnedRoots,expectedChallenge,minimumEpoch)` checks namespace, challenge, pinned active Ed25519 signer, minimum independently held epoch, and signature.
- `createSignedClockFloorProvider({namespace,fetchSignedFloor,pinnedRoots,minimumEpoch})` generates a cryptographically random 256-bit challenge for each call, synchronously fetches a proof with that exact challenge, verifies it, and returns the authenticated `minimumLastSeenMs` number. Invalid replies throw and the caller's transaction must roll back.

### Optional integration with v1.5

```js
const { createSignedClockFloorProvider } = require('./distribution/signed-clock-floor');
const { createAuditedDurableChallengeRegistry } = require('./distribution/durable-challenge-registry');
const minimumLastSeenMs = createSignedClockFloorProvider({
  namespace: 'palaco.registry', fetchSignedFloor, pinnedRoots, minimumEpoch
});
const registry = createAuditedDurableChallengeRegistry(db, { minimumLastSeenMs });
```

The placeholder names `fetchSignedFloor`, `pinnedRoots`, and `minimumEpoch` MUST be supplied by an independently trusted integration. No real signing service, public key, network transport, key provisioning, or external authority is shipped.

## Security boundaries

1. The callback is **synchronous** and runs under SQLite `BEGIN IMMEDIATE` in the v1.5 integration. Never perform unbounded remote network I/O while holding a database write lock; deployment should use a bounded, independently verified local authority bridge or redesign the transaction protocol. This module does not supply such a bridge.
2. A valid signature establishes authorship under a pinned key, not that the signer has up-to-date state or truly rollback-resistant durable storage. `minimumEpoch` must be independently maintained and rollback-resistant; the code cannot authenticate the caller's floor or pinned-root provisioning.
3. A signer that signs a stale floor with a fresh challenge can still cause an incorrect acceptance unless separately protected monotonic state and policy prevent it. Challenge freshness alone does not establish clock freshness.
4. The older v1.5 factory remains accessible and is not implicitly upgraded. Callers must explicitly pass this verified provider to use the new signature gate.

Every verification result remains `authorization: DENY`, `go13: HOLD`, `mayInstall: false`, `mayPublish: false`, `mayRestore: false`, and `mayRotate: false`. Nothing is merged, deployed, installed, issued, or approved.

Run `node --test tests/distribution-signed-clock-floor.test.js`. The new local module passed 10/10 tests on Node.js 22.16.0; independent GitHub CI and integration review remain required.
