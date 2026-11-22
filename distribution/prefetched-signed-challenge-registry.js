'use strict';

const { randomBytes } = require('node:crypto');
const { verifySignedClockFloor } = require('./signed-clock-floor');
const { createAuditedDurableChallengeRegistry } = require('./durable-challenge-registry');

const NS = /^[a-z][a-z0-9._-]{2,79}$/;

function deny(reason) {
  return Object.freeze({
    schemaVersion: 'palaco.distribution.prefetched-floor-assessment.v1',
    readiness: 'BLOCKED', authorization: 'DENY', go13: 'HOLD',
    mayAdvance: false, mayRestore: false, mayRotate: false,
    mayInstall: false, mayPublish: false,
    findings: Object.freeze([reason])
  });
}

/**
 * Network / external proof retrieval happens BEFORE SQLite's BEGIN IMMEDIATE.
 * An authenticated floor is held only in a one-use closure, checked for age
 * *inside* the subsequent transaction. No fallback to unauthenticated floors.
 *
 * The request deadline is enforced outside the SQLite transaction. The caller
 * must honor AbortSignal to cancel the underlying transport. No rollback-proof storage.
 */
function createPrefetchedSignedChallengeRegistry(db, {
  floorAuthority, clock = Date.now, ttlMs = 60_000, maxPending = 128,
  maxRows = 100000, maxProofAgeMs = 5000, fetchTimeoutMs = 3000,
  monotonicNow = () => process.hrtime.bigint()
} = {}) {
  if (!floorAuthority || typeof floorAuthority !== 'object' ||
      Array.isArray(floorAuthority) ||
      typeof floorAuthority.namespace !== 'string' ||
      !NS.test(floorAuthority.namespace) ||
      typeof floorAuthority.fetchSignedFloor !== 'function' ||
      !Array.isArray(floorAuthority.pinnedRoots) ||
      floorAuthority.pinnedRoots.length < 1 ||
      !Number.isSafeInteger(floorAuthority.minimumEpoch) ||
      floorAuthority.minimumEpoch < 0 ||
      !Number.isSafeInteger(maxProofAgeMs) ||
      maxProofAgeMs < 1 || maxProofAgeMs > 30_000 ||
      !Number.isSafeInteger(fetchTimeoutMs) || fetchTimeoutMs < 1 ||
      fetchTimeoutMs > maxProofAgeMs ||
      typeof monotonicNow !== 'function') {
    throw new TypeError('Independent signed-floor configuration required');
  }
  const maxAgeNs = BigInt(maxProofAgeMs) * 1000000n;

  async function prepareFloor() {
    const challenge = randomBytes(32).toString('hex');
    const start = monotonicNow();
    if (typeof start !== 'bigint') throw new Error('MONOTONIC_CLOCK_UNAVAILABLE');
    // An abort signal requests transport cancellation; Promise.race bounds the
    // caller's wait even if the remote implementation ignores that signal.
    // This entire operation runs before BEGIN IMMEDIATE.
    const controller = new AbortController();
    let timeout;
    let expired = false;
    const timer = new Promise((_, reject) => {
      timeout = setTimeout(() => {
        expired = true;
        controller.abort();
        reject(new Error('SIGNED_FLOOR_FETCH_TIMEOUT'));
      }, fetchTimeoutMs);
    });
    let reply;
    try {
      reply = await Promise.race([
        Promise.resolve().then(() => floorAuthority.fetchSignedFloor(challenge, controller.signal)),
        timer
      ]);
      if (expired) throw new Error('SIGNED_FLOOR_FETCH_TIMEOUT');
    } finally {
      clearTimeout(timeout);
    }
    const verified = verifySignedClockFloor(
      floorAuthority.namespace, reply && reply.floor,
      reply && reply.endorsement, floorAuthority.pinnedRoots,
      challenge, floorAuthority.minimumEpoch
    );
    if (verified.readiness !== 'SIGNED_CLOCK_FLOOR_MATCH') {
      throw new Error('SIGNED_FLOOR_VERIFICATION_FAILED');
    }
    const end = monotonicNow();
    if (typeof end !== 'bigint' || end < start || end - start > maxAgeNs) {
      throw new Error('SIGNED_FLOOR_EXPIRED');
    }
    let used = false;
    return () => {
      // The closure is consumed even when the DB transaction later rolls back.
      if (used) throw new Error('FLOOR_REUSED');
      used = true;
      const at = monotonicNow();
      if (typeof at !== 'bigint' || at < start || at - start > maxAgeNs) {
        throw new Error('SIGNED_FLOOR_EXPIRED');
      }
      return verified.minimumLastSeenMs;
    };
  }

  async function guarded(operation, args, isIssue) {
    try {
      const floor = await prepareFloor();
      const registry = createAuditedDurableChallengeRegistry(db, {
        minimumLastSeenMs: floor, maxRows, clock, ttlMs, maxPending
      });
      return registry[operation](...args);
    } catch (_) {
      return isIssue
        ? Object.freeze({ issued: false, reason: 'SIGNED_FLOOR_PREPARATION_FAILED' })
        : deny('SIGNED_FLOOR_PREPARATION_FAILED');
    }
  }

  return Object.freeze({
    issue: namespace => guarded('issue', [namespace], true),
    consume: (namespace, challenge, state, endorsement, roots, minimumSequence) =>
      guarded('consume', [namespace, challenge, state, endorsement, roots, minimumSequence], false)
  });
}

module.exports = { createPrefetchedSignedChallengeRegistry };
