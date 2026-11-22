'use strict';

// Explicit per-process shared authority fetch budget. No network or storage I/O.
// Instances using the same object share a synchronous admission limit.
const trusted = new WeakSet();

function createSharedAuthorityAdmission({ maxInFlight = 32 } = {}) {
  if (!Number.isSafeInteger(maxInFlight) || maxInFlight < 1 ||
      maxInFlight > 4096) throw new RangeError('Invalid shared admission limit');
  let active = 0;
  const api = Object.freeze({
    acquire() {
      if (active >= maxInFlight) return null;
      active += 1;
      let released = false;
      return () => {
        if (released) return false;
        released = true;
        active -= 1;
        return true;
      };
    },
    snapshot() {
      return Object.freeze({ active, capacity: maxInFlight, available: maxInFlight - active });
    }
  });
  trusted.add(api);
  return api;
}
function isSharedAuthorityAdmission(value) {
  return value !== null && typeof value === 'object' && trusted.has(value);
}

module.exports = { createSharedAuthorityAdmission, isSharedAuthorityAdmission };
