'use strict';

// Contract wrapper only. This module DOES NOT provide secure persistence.
// The trusted service MUST atomically compare-and-advance independently from
// the SQLite challenge database, across restarts and all participating hosts.
const NS = /^[a-z][a-z0-9._-]{2,79}$/;
const registered = new WeakSet();

function createIndependentContinuityAuthority({namespace, compareAndAdvance} = {}) {
  if (typeof namespace !== 'string' || !NS.test(namespace) ||
      typeof compareAndAdvance !== 'function') {
    throw new TypeError('Independent continuity authority required');
  }
  const api = Object.freeze({
    async advance(epoch, minimumLastSeenMs, signal) {
      if (!Number.isSafeInteger(epoch) || epoch < 0 ||
          !Number.isSafeInteger(minimumLastSeenMs) || minimumLastSeenMs < 0 ||
          !signal || typeof signal.aborted !== 'boolean' || signal.aborted)
        return false;
      // Never accept truthy objects or a vague success response.
      const result = await compareAndAdvance(namespace, epoch, minimumLastSeenMs, signal);
      return result === true && !signal.aborted;
    },
    namespace
  });
  registered.add(api);
  return api;
}
function isIndependentContinuityAuthority(value) {
  return value !== null && typeof value === 'object' && registered.has(value);
}
module.exports = {createIndependentContinuityAuthority,isIndependentContinuityAuthority};
