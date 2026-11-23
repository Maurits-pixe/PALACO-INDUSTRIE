'use strict';

const { randomBytes } = require('node:crypto');
const { verifySignedClockFloor } = require('./signed-clock-floor');
const { createAuditedDurableChallengeRegistry } = require('./durable-challenge-registry');
const { isSharedAuthorityAdmission } = require('./shared-authority-admission');
const { createSignedFloorContinuity, isSignedFloorContinuity } = require('./signed-floor-continuity');
const { isIndependentContinuityAuthority } = require('./independent-continuity-authority');
const { isCheckpointExecutionGate } = require('./checkpoint-execution-gate');

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
  maxInFlight = 16, failureThreshold = 3, cooldownMs = 30_000,
  sharedAdmission = null, signedFloorContinuity = null,
  independentContinuity = null, checkpointGate = null,
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
      !Number.isSafeInteger(maxInFlight) || maxInFlight < 1 ||
      maxInFlight > 1024 ||
      !Number.isSafeInteger(failureThreshold) || failureThreshold < 1 ||
      failureThreshold > 100 ||
      !Number.isSafeInteger(cooldownMs) || cooldownMs < 1 ||
      cooldownMs > 300_000 ||
      (sharedAdmission !== null && !isSharedAuthorityAdmission(sharedAdmission)) ||
      (signedFloorContinuity !== null && !isSignedFloorContinuity(signedFloorContinuity)) ||
      (independentContinuity !== null &&
       (!isIndependentContinuityAuthority(independentContinuity) ||
        independentContinuity.namespace !== floorAuthority.namespace)) ||
      (checkpointGate !== null &&
       (!isCheckpointExecutionGate(checkpointGate) ||
        checkpointGate.namespace !== floorAuthority.namespace)) ||
      typeof monotonicNow !== 'function') {
    throw new TypeError('Independent signed-floor configuration required');
  }
  const maxAgeNs = BigInt(maxProofAgeMs) * 1000000n;
  // Local-process admission control; no global/distributed resource guarantee.
  let inFlight = 0;
  const cooldownNs = BigInt(cooldownMs) * 1000000n;
  let consecutiveFailures = 0;
  let blockedUntil = null;
  let probeInProgress = false;
  const continuity = signedFloorContinuity || createSignedFloorContinuity();

  async function prepareFloor(onAbandoned) {
    const challenge = randomBytes(32).toString('hex');
    const start = monotonicNow();
    if (typeof start !== 'bigint') throw new Error('MONOTONIC_CLOCK_UNAVAILABLE');
    // An abort signal requests transport cancellation; Promise.race bounds the
    // caller's wait even if the remote implementation ignores that signal.
    // This entire operation runs before BEGIN IMMEDIATE.
    const controller = new AbortController();
    let timeout;
    let expired = false;
    let transportSettled = false;
    const transport = Promise.resolve().then(() =>
      floorAuthority.fetchSignedFloor(challenge, controller.signal));
    // Observe rejection without changing the original fetch outcome.
    transport.then(() => { transportSettled = true; },
      () => { transportSettled = true; });
    const timer = new Promise((_, reject) => {
      timeout = setTimeout(() => {
        expired = true;
        // If abort is ignored, keep both local and shared permits reserved
        // until the underlying asynchronous transport actually settles.
        if (!transportSettled) onAbandoned(transport);
        controller.abort();
        reject(new Error('SIGNED_FLOOR_FETCH_TIMEOUT'));
      }, fetchTimeoutMs);
    });
    let reply;
    try {
      reply = await Promise.race([
        transport,
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
    // Mandatory in createCheckpointGuardedChallengeRegistry: verify the
    // UNMODIFIED PostgreSQL row before independent compare-and-advance.
    // Otherwise an UPDATE could conceal a restored high-watermark.
    // External operations always run before SQLite BEGIN IMMEDIATE.
    if (checkpointGate !== null) {
      const controller = new AbortController();
      let settled = false;
      const request = Promise.resolve().then(() =>
        checkpointGate.verify(reply.floor.epoch,
          verified.minimumLastSeenMs, controller.signal));
      request.then(() => { settled = true; }, () => { settled = true; });
      let deadline;
      let timedOut = false;
      const timer = new Promise((_, reject) => {
        deadline = setTimeout(() => {
          timedOut = true;
          if (!settled) onAbandoned(request);
          controller.abort();
          reject(new Error('CHECKPOINT_GATE_TIMEOUT'));
        }, fetchTimeoutMs);
      });
      let accepted;
      try {
        accepted = await Promise.race([request, timer]);
      } finally {
        clearTimeout(deadline);
      }
      const checkedAt = monotonicNow();
      if (timedOut || accepted !== true ||
          typeof checkedAt !== 'bigint' || checkedAt < start ||
          checkedAt - start > maxAgeNs)
        throw new Error('CHECKPOINT_GATE_REJECTED');
    }
    // A configured independent store must atomically compare-and-advance
    // before the local continuity monitor and SQLite transaction. It must be
    // rollback-resistant itself; this code does not supply such storage.
    if (independentContinuity !== null) {
      const controller = new AbortController();
      let settled = false;
      const request = Promise.resolve().then(() =>
        independentContinuity.advance(reply.floor.epoch,
          verified.minimumLastSeenMs, controller.signal));
      request.then(() => { settled = true; }, () => { settled = true; });
      let deadline;
      let timedOut = false;
      const timer = new Promise((_, reject) => {
        deadline = setTimeout(() => {
          timedOut = true;
          if (!settled) onAbandoned(request);
          controller.abort();
          reject(new Error('INDEPENDENT_CONTINUITY_TIMEOUT'));
        }, fetchTimeoutMs);
      });
      let accepted;
      try {
        accepted = await Promise.race([request, timer]);
      } finally {
        clearTimeout(deadline);
      }
      const checkedAt = monotonicNow();
      if (timedOut || accepted !== true ||
          typeof checkedAt !== 'bigint' || checkedAt < start ||
          checkedAt - start > maxAgeNs) {
        throw new Error('INDEPENDENT_CONTINUITY_REJECTED');
      }
    }
    // Only authenticated, sufficiently fresh signed proofs can advance this
    // process-local high-watermark. Regression is rejected before SQLite writes.
    if (!continuity.observe(reply.floor.epoch, verified.minimumLastSeenMs)) {
      throw new Error('SIGNED_FLOOR_CONTINUITY_ROLLBACK');
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
    // Admission is synchronous, before the first await, so competing calls
    // cannot oversubscribe this registry instance's authority fetch budget.
    if (inFlight >= maxInFlight) {
      return isIssue
        ? Object.freeze({ issued: false, reason: 'AUTHORITY_CAPACITY_REACHED' })
        : deny('AUTHORITY_CAPACITY_REACHED');
    }
    // Only one half-open probe is admitted after the cooldown. This local
    // breaker counts signed-floor preparation failures, not SQLite failures.
    let isProbe = false;
    try {
      const now = monotonicNow();
      if (typeof now !== 'bigint' || now < 0n) throw new Error('MONOTONIC_CLOCK_UNAVAILABLE');
      if (blockedUntil !== null) {
        if (now < blockedUntil || probeInProgress) {
          return isIssue
            ? Object.freeze({ issued: false, reason: 'AUTHORITY_CIRCUIT_OPEN' })
            : deny('AUTHORITY_CIRCUIT_OPEN');
        }
        probeInProgress = true;
        isProbe = true;
      }
    } catch (_) {
      return isIssue
        ? Object.freeze({ issued: false, reason: 'AUTHORITY_CLOCK_UNAVAILABLE' })
        : deny('AUTHORITY_CLOCK_UNAVAILABLE');
    }
    // Shared per-process admission is acquired only after local circuit and
    // capacity checks. A rejected half-open probe must release its probe lock.
    const releaseShared = sharedAdmission === null
      ? () => {} : sharedAdmission.acquire();
    if (releaseShared === null) {
      if (isProbe) probeInProgress = false;
      return isIssue
        ? Object.freeze({ issued: false, reason: 'SHARED_AUTHORITY_CAPACITY_REACHED' })
        : deny('SHARED_AUTHORITY_CAPACITY_REACHED');
    }
    inFlight += 1;
    let abandonedTransport = null;
    try {
      let floor;
      try {
        floor = await prepareFloor(transport => { abandonedTransport = transport; });
        consecutiveFailures = 0;
        blockedUntil = null;
      } catch (_) {
        consecutiveFailures += 1;
        if (isProbe || consecutiveFailures >= failureThreshold) {
          // A broken monotonic clock must not accidentally reopen the circuit.
          let now;
          try { now = monotonicNow(); } catch (_) {}
          blockedUntil = typeof now === 'bigint' && now >= 0n
            ? now + cooldownNs : (1n << 120n);
        }
        throw new Error('SIGNED_FLOOR_PREPARATION_FAILED');
      }
      const registry = createAuditedDurableChallengeRegistry(db, {
        minimumLastSeenMs: floor, maxRows, clock, ttlMs, maxPending
      });
      return registry[operation](...args);
    } catch (_) {
      return isIssue
        ? Object.freeze({ issued: false, reason: 'SIGNED_FLOOR_PREPARATION_FAILED' })
        : deny('SIGNED_FLOOR_PREPARATION_FAILED');
    } finally {
      const releaseCapacity = () => {
        if (isProbe) probeInProgress = false;
        inFlight -= 1;
        releaseShared();
      };
      if (abandonedTransport !== null) {
        // Keep capacity reserved on an uncooperative transport: capacity
        // exhaustion is safer than claiming resources were reclaimed.
        abandonedTransport.then(releaseCapacity, releaseCapacity);
      } else {
        releaseCapacity();
      }
    }
  }

  return Object.freeze({
    issue: namespace => guarded('issue', [namespace], true),
    consume: (namespace, challenge, state, endorsement, roots, minimumSequence) =>
      guarded('consume', [namespace, challenge, state, endorsement, roots, minimumSequence], false)
  });
}

/** Explicit strict mode: refuse construction without an independent authority. */
function createIndependentlyGuardedChallengeRegistry(db, options = {}) {
  if (!options || !isIndependentContinuityAuthority(options.independentContinuity) ||
      !options.floorAuthority ||
      options.independentContinuity.namespace !== options.floorAuthority.namespace) {
    throw new TypeError('Independent continuity authority required');
  }
  return createPrefetchedSignedChallengeRegistry(db, options);
}
/** v3.1 strict route: independent monotone authority AND checkpoint required. */
function createCheckpointGuardedChallengeRegistry(db, options = {}) {
  if (!options || !isIndependentContinuityAuthority(options.independentContinuity) ||
      !isCheckpointExecutionGate(options.checkpointGate) ||
      !options.floorAuthority ||
      options.independentContinuity.namespace !== options.floorAuthority.namespace ||
      options.checkpointGate.namespace !== options.floorAuthority.namespace) {
    throw new TypeError('Independent checkpoint and continuity gate required');
  }
  return createPrefetchedSignedChallengeRegistry(db, options);
}
module.exports = {
  createPrefetchedSignedChallengeRegistry,
  createIndependentlyGuardedChallengeRegistry,
  createCheckpointGuardedChallengeRegistry
};
