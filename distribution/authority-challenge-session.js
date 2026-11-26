'use strict';

const { randomBytes } = require('node:crypto');
const { verifyAuthorityReceipt } = require('./authority-receipt');

function blocked(reason) {
  return Object.freeze({
    schemaVersion: 'palaco.distribution.challenge-session-assessment.v1',
    readiness: 'BLOCKED', authorization: 'DENY', go13: 'HOLD',
    mayAdvance: false, mayRestore: false, mayRotate: false,
    mayInstall: false, mayPublish: false,
    findings: Object.freeze([reason])
  });
}

/** In-process challenge manager. Never use as durable or distributed replay store. */
function createAuthorityChallengeSession({ ttlMs = 60_000, maxPending = 128 } = {}) {
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > 300_000 ||
      !Number.isSafeInteger(maxPending) || maxPending < 1 || maxPending > 4096) {
    throw new RangeError('Invalid challenge-session limits');
  }
  const pending = new Map();
  const monotonicNow = () => process.hrtime.bigint();
  const ttlNs = BigInt(ttlMs) * 1_000_000n;

  function issue(namespace) {
    if (typeof namespace !== 'string' || !/^[a-z][a-z0-9._-]{2,79}$/.test(namespace)) {
      return Object.freeze({ issued: false, reason: 'INVALID_NAMESPACE' });
    }
    const now = monotonicNow();
    for (const [token, entry] of pending) {
      if (now >= entry.expiresAt) pending.delete(token);
    }
    if (pending.size >= maxPending) {
      return Object.freeze({ issued: false, reason: 'CHALLENGE_CAPACITY_REACHED' });
    }
    const challenge = randomBytes(32).toString('hex');
    pending.set(challenge, { namespace, expiresAt: now + ttlNs });
    return Object.freeze({ issued: true, challenge });
  }

  function consume(namespace, challenge, state, endorsement, pinnedRoots, minimumSequence) {
    if (typeof challenge !== 'string' || !/^[a-f0-9]{64}$/.test(challenge)) {
      return blocked('INVALID_CHALLENGE');
    }
    const entry = pending.get(challenge);
    pending.delete(challenge);
    if (!entry) return blocked('UNKNOWN_OR_REPLAYED_CHALLENGE');
    if (monotonicNow() >= entry.expiresAt) return blocked('CHALLENGE_EXPIRED');
    if (entry.namespace !== namespace) return blocked('CHALLENGE_NAMESPACE_MISMATCH');
    return verifyAuthorityReceipt(namespace, state, endorsement, pinnedRoots, challenge, minimumSequence);
  }
  function close() { pending.clear(); }
  return Object.freeze({ issue, consume, close });
}

module.exports = { createAuthorityChallengeSession };
