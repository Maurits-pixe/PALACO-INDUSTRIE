'use strict';

const { createSignedClockFloorProvider } = require('./signed-clock-floor');
const { createAuditedDurableChallengeRegistry } = require('./durable-challenge-registry');

/**
 * Explicit strict integration: authenticated floor -> guarded SQLite transaction.
 * NEVER falls back to a caller-supplied unsigned clock number on proof failure.
 * The synchronous floor provider is invoked under SQLite's write transaction;
 * only use bounded, local, trusted proof sources until an async protocol exists.
 */
function createSignedAuditedChallengeRegistry(db, {
  floorAuthority, clock = Date.now, ttlMs = 60_000,
  maxPending = 128, maxRows = 100000
} = {}) {
  if (!floorAuthority || typeof floorAuthority !== 'object' ||
      Array.isArray(floorAuthority)) {
    throw new TypeError('Signed floor authority configuration required');
  }
  const floor = createSignedClockFloorProvider({
    namespace: floorAuthority.namespace,
    fetchSignedFloor: floorAuthority.fetchSignedFloor,
    pinnedRoots: floorAuthority.pinnedRoots,
    minimumEpoch: floorAuthority.minimumEpoch
  });
  const registry = createAuditedDurableChallengeRegistry(db, {
    minimumLastSeenMs: floor, maxRows, clock, ttlMs, maxPending
  });
  return Object.freeze({
    issue: namespace => registry.issue(namespace),
    consume: (namespace, challenge, state, endorsement, roots, minimumSequence) =>
      registry.consume(namespace, challenge, state, endorsement, roots, minimumSequence)
  });
}

module.exports = { createSignedAuditedChallengeRegistry };
