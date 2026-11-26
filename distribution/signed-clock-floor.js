'use strict';
const { createPublicKey, verify, randomBytes } = require('node:crypto');
const NS = /^[a-z][a-z0-9._-]{2,79}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const NONCE = /^[a-f0-9]{64}$/;
const SIG = /^[A-Za-z0-9+/]{86}==$/;

function clockFloorPayload(floor) {
  if (!floor || typeof floor !== 'object' || Array.isArray(floor) ||
      floor.schemaVersion !== 'palaco.distribution.signed-clock-floor.v1' ||
      typeof floor.namespace !== 'string' || !NS.test(floor.namespace) ||
      !Number.isSafeInteger(floor.epoch) || floor.epoch < 0 ||
      !Number.isSafeInteger(floor.minimumLastSeenMs) || floor.minimumLastSeenMs < 0 ||
      typeof floor.challenge !== 'string' || !NONCE.test(floor.challenge)) return null;
  return Buffer.from([
    'PALACO-INDUSTRIE-SIGNED-CLOCK-FLOOR-V1', floor.schemaVersion,
    floor.namespace, String(floor.epoch), String(floor.minimumLastSeenMs),
    floor.challenge, ''
  ].join('\n'), 'utf8');
}
function blocked(findings) {
  return Object.freeze({
    schemaVersion: 'palaco.distribution.clock-floor-proof-assessment.v1',
    readiness: 'BLOCKED', authorization: 'DENY', go13: 'HOLD',
    mayAdvance: false, mayRestore: false, mayRotate: false,
    mayInstall: false, mayPublish: false,
    findings: Object.freeze(findings)
  });
}
function verifySignedClockFloor(namespace, floor, endorsement, roots, expectedChallenge, minimumEpoch) {
  const findings = [];
  const payload = clockFloorPayload(floor);
  if (!payload || floor.namespace !== namespace) findings.push('INVALID_CLOCK_FLOOR');
  if (typeof expectedChallenge !== 'string' || !NONCE.test(expectedChallenge) ||
      !payload || floor.challenge !== expectedChallenge) findings.push('CLOCK_FLOOR_CHALLENGE_MISMATCH');
  if (!Number.isSafeInteger(minimumEpoch) || minimumEpoch < 0)
    findings.push('INDEPENDENT_EPOCH_UNAVAILABLE');
  if (!endorsement || typeof endorsement !== 'object' || Array.isArray(endorsement) ||
      endorsement.algorithm !== 'Ed25519' || typeof endorsement.keyId !== 'string' ||
      !ID.test(endorsement.keyId) || typeof endorsement.signature !== 'string' ||
      !SIG.test(endorsement.signature) ||
      Buffer.from(endorsement.signature || '', 'base64').toString('base64') !== endorsement.signature)
    findings.push('INVALID_FLOOR_ENDORSEMENT');
  if (!Array.isArray(roots) || roots.length < 1 || roots.length > 32)
    findings.push('PINNED_FLOOR_ROOTS_UNAVAILABLE');
  if (!findings.length) {
    if (floor.epoch < minimumEpoch) findings.push('CLOCK_FLOOR_EPOCH_ROLLBACK');
    const matching = roots.filter(root => root && root.keyId === endorsement.keyId);
    if (matching.length !== 1 || matching[0].enabled !== true || matching[0].revoked !== false ||
        typeof matching[0].publicKeyPem !== 'string' || matching[0].publicKeyPem.length > 4096) {
      findings.push('CLOCK_FLOOR_ROOT_UNTRUSTED');
    } else {
      try {
        const key = createPublicKey(matching[0].publicKeyPem);
        if (key.asymmetricKeyType !== 'ed25519' ||
            !verify(null, payload, key, Buffer.from(endorsement.signature, 'base64')))
          findings.push('CLOCK_FLOOR_SIGNATURE_INVALID');
      } catch (_) { findings.push('CLOCK_FLOOR_SIGNATURE_INVALID'); }
    }
  }
  if (findings.length) return blocked(findings);
  return Object.freeze({
    schemaVersion: 'palaco.distribution.clock-floor-proof-assessment.v1',
    readiness: 'SIGNED_CLOCK_FLOOR_MATCH', authorization: 'DENY', go13: 'HOLD',
    minimumLastSeenMs: floor.minimumLastSeenMs,
    mayAdvance: false, mayRestore: false, mayRotate: false,
    mayInstall: false, mayPublish: false, findings: Object.freeze([])
  });
}
/** Synchronous adapter for v1.5 transaction audits. */
function createSignedClockFloorProvider({ namespace = 'palaco.registry', fetchSignedFloor,
  pinnedRoots, minimumEpoch } = {}) {
  if (typeof namespace !== 'string' || !NS.test(namespace) ||
      typeof fetchSignedFloor !== 'function' || !Number.isSafeInteger(minimumEpoch) ||
      minimumEpoch < 0 || !Array.isArray(pinnedRoots) || !pinnedRoots.length)
    throw new TypeError('Authenticated clock-floor provider configuration required');
  return () => {
    const challenge = randomBytes(32).toString('hex');
    const envelope = fetchSignedFloor(challenge);
    const result = verifySignedClockFloor(namespace, envelope && envelope.floor,
      envelope && envelope.endorsement, pinnedRoots, challenge, minimumEpoch);
    if (result.readiness !== 'SIGNED_CLOCK_FLOOR_MATCH')
      throw new Error('SIGNED_CLOCK_FLOOR_REJECTED');
    return result.minimumLastSeenMs;
  };
}
module.exports = { clockFloorPayload, verifySignedClockFloor, createSignedClockFloorProvider };
