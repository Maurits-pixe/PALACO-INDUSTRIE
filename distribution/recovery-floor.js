'use strict';
const { createPublicKey, verify, timingSafeEqual } = require('node:crypto');
const HEX = /^[a-f0-9]{64}$/;
const NAMESPACE = /^[a-z][a-z0-9._-]{2,79}$/;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const SIG = /^[A-Za-z0-9+/]{86}==$/;

function validState(value) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Number.isSafeInteger(value.sequence) && value.sequence >= 0 &&
    typeof value.digest === 'string' && HEX.test(value.digest);
}

function floorPayload(floor) {
  if (!floor || typeof floor !== 'object' || Array.isArray(floor) ||
      floor.schemaVersion !== 'palaco.distribution.recovery-floor.v1' ||
      typeof floor.namespace !== 'string' || !NAMESPACE.test(floor.namespace) ||
      !validState(floor)) return null;
  return Buffer.from([
    'PALACO-INDUSTRIE-RECOVERY-FLOOR-V1', floor.schemaVersion,
    floor.namespace, String(floor.sequence), floor.digest, ''
  ].join('\n'), 'utf8');
}

function verifyFloorEndorsement(floor, endorsement, roots) {
  const payload = floorPayload(floor);
  if (!payload || !endorsement || typeof endorsement !== 'object' || Array.isArray(endorsement) ||
      endorsement.algorithm !== 'Ed25519' || typeof endorsement.keyId !== 'string' ||
      !KEY_ID.test(endorsement.keyId) || typeof endorsement.signature !== 'string' ||
      !SIG.test(endorsement.signature) || !Array.isArray(roots) ||
      roots.length < 1 || roots.length > 32) return false;
  const sig = Buffer.from(endorsement.signature, 'base64');
  if (sig.length !== 64 || sig.toString('base64') !== endorsement.signature) return false;
  const matches = roots.filter(root => root && root.keyId === endorsement.keyId);
  if (matches.length !== 1 || matches[0].enabled !== true ||
      matches[0].revoked !== false || typeof matches[0].publicKeyPem !== 'string') return false;
  try {
    const key = createPublicKey(matches[0].publicKeyPem);
    return key.asymmetricKeyType === 'ed25519' && verify(null, payload, key, sig);
  } catch (_) { return false; }
}

/**
 * Read-only check against an independently pinned, signed high-watermark.
 * This module never restores data, advances the floor or approves execution.
 * An operator must guarantee that the floor source itself cannot be rolled back.
 */
function assessRecoveryFloor(namespace, restoredAnchor, floor, endorsement, independentlyPinnedRoots) {
  const findings = [];
  if (typeof namespace !== 'string' || !NAMESPACE.test(namespace))
    findings.push('INVALID_NAMESPACE');
  if (!validState(restoredAnchor)) findings.push('INVALID_RESTORED_ANCHOR');
  if (!floorPayload(floor) || floor.namespace !== namespace)
    findings.push('INVALID_RECOVERY_FLOOR');
  if (!verifyFloorEndorsement(floor, endorsement, independentlyPinnedRoots))
    findings.push('FLOOR_AUTHENTICATION_FAILED');
  if (findings.length === 0) {
    if (restoredAnchor.sequence < floor.sequence) findings.push('RECOVERY_BELOW_TRUSTED_FLOOR');
    else if (restoredAnchor.sequence > floor.sequence) findings.push('FLOOR_STALE');
    else if (!timingSafeEqual(Buffer.from(restoredAnchor.digest, 'hex'),
                              Buffer.from(floor.digest, 'hex')))
      findings.push('FLOOR_DIGEST_CONFLICT');
  }
  return Object.freeze({
    schemaVersion: 'palaco.distribution.recovery-floor-assessment.v1',
    readiness: findings.length === 0 ? 'FLOOR_MATCH' : 'BLOCKED',
    authorization: 'DENY', go13: 'HOLD', mayRestore: false,
    mayRotate: false, mayInstall: false, mayPublish: false,
    findings: Object.freeze(findings)
  });
}
module.exports = { floorPayload, assessRecoveryFloor };
