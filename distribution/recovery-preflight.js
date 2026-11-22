'use strict';
const { createPublicKey, verify, timingSafeEqual } = require('node:crypto');
const HEX = /^[a-f0-9]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const B64 = /^[A-Za-z0-9+/]{86}==$/;

function witnessPayload(witness) {
  if (!witness || typeof witness !== 'object' || Array.isArray(witness) ||
      witness.schemaVersion !== 'palaco.distribution.recovery-witness.v1' ||
      typeof witness.namespace !== 'string' ||
      !/^[a-z][a-z0-9._-]{2,79}$/.test(witness.namespace) ||
      !Number.isSafeInteger(witness.sequence) || witness.sequence < 0 ||
      typeof witness.digest !== 'string' || !HEX.test(witness.digest)) return null;
  return Buffer.from([
    'PALACO-INDUSTRIE-RECOVERY-WITNESS-V1', witness.schemaVersion,
    witness.namespace, String(witness.sequence), witness.digest, ''
  ].join('\n'), 'utf8');
}

function assessRecoveryPreflight(namespace, restoredAnchor, witness, endorsement, independentRoots) {
  const findings = [];
  const payload = witnessPayload(witness);
  if (!payload || witness.namespace !== namespace) findings.push('INVALID_RECOVERY_WITNESS');
  if (!restoredAnchor || typeof restoredAnchor !== 'object' || Array.isArray(restoredAnchor) ||
      !Number.isSafeInteger(restoredAnchor.sequence) || restoredAnchor.sequence < 0 ||
      typeof restoredAnchor.digest !== 'string' || !HEX.test(restoredAnchor.digest)) {
    findings.push('INVALID_RESTORED_ANCHOR');
  }
  if (!endorsement || typeof endorsement !== 'object' || Array.isArray(endorsement) ||
      endorsement.algorithm !== 'Ed25519' || typeof endorsement.keyId !== 'string' ||
      !ID.test(endorsement.keyId) || typeof endorsement.signature !== 'string' ||
      !B64.test(endorsement.signature) ||
      Buffer.from(endorsement.signature || '', 'base64').toString('base64') !== endorsement.signature) {
    findings.push('INVALID_WITNESS_ENDORSEMENT');
  }
  if (!Array.isArray(independentRoots) || independentRoots.length < 1 || independentRoots.length > 32) {
    findings.push('INDEPENDENT_ROOTS_UNAVAILABLE');
  }
  if (findings.length === 0) {
    const roots = independentRoots.filter(x => x && x.keyId === endorsement.keyId);
    if (roots.length !== 1 || roots[0].enabled !== true || roots[0].revoked !== false ||
        typeof roots[0].publicKeyPem !== 'string') {
      findings.push('UNTRUSTED_WITNESS_ROOT');
    } else {
      try {
        const pub = createPublicKey(roots[0].publicKeyPem);
        if (pub.asymmetricKeyType !== 'ed25519' ||
            !verify(null, payload, pub, Buffer.from(endorsement.signature, 'base64'))) {
          findings.push('INVALID_WITNESS_SIGNATURE');
        }
      } catch (_) { findings.push('INVALID_WITNESS_SIGNATURE'); }
    }
    // Exact agreement prevents both old restored anchors and stale witnesses.
    if (restoredAnchor.sequence < witness.sequence) findings.push('RESTORED_ANCHOR_ROLLBACK');
    else if (restoredAnchor.sequence > witness.sequence) findings.push('WITNESS_BEHIND_ANCHOR');
    else if (!timingSafeEqual(Buffer.from(restoredAnchor.digest, 'hex'),
                              Buffer.from(witness.digest, 'hex'))) {
      findings.push('RECOVERY_DIGEST_MISMATCH');
    }
  }
  return Object.freeze({
    schemaVersion: 'palaco.distribution.recovery-preflight-assessment.v1',
    readiness: findings.length ? 'BLOCKED' : 'RECOVERY_WITNESS_MATCH',
    authorization: 'DENY', go13: 'HOLD',
    mayRestore: false, mayRotate: false, mayInstall: false, mayPublish: false,
    findings: Object.freeze(findings)
  });
}

module.exports = { witnessPayload, assessRecoveryPreflight };
