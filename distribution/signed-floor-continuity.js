'use strict';

// In-memory, fail-closed high-watermark for signed clock floors.
// This is NOT independent persistent anti-rollback storage.
const created = new WeakSet();
function createSignedFloorContinuity() {
  let epoch = null;
  let minimumLastSeenMs = null;
  const monitor = Object.freeze({
    observe(nextEpoch, nextFloor) {
      if (!Number.isSafeInteger(nextEpoch) || nextEpoch < 0 ||
          !Number.isSafeInteger(nextFloor) || nextFloor < 0) return false;
      if (epoch !== null &&
          (nextEpoch < epoch || nextFloor < minimumLastSeenMs)) return false;
      // Synchronous compare-and-update: concurrent promise resolutions within
      // one JavaScript isolate cannot interleave in the middle of this method.
      epoch = nextEpoch;
      minimumLastSeenMs = nextFloor;
      return true;
    },
    snapshot() {
      return Object.freeze({epoch, minimumLastSeenMs});
    }
  });
  created.add(monitor);
  return monitor;
}
function isSignedFloorContinuity(value) {
  return value !== null && typeof value === 'object' && created.has(value);
}
module.exports = {createSignedFloorContinuity,isSignedFloorContinuity};
