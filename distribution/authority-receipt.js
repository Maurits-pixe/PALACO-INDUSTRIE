'use strict';

const { createPublicKey, verify, timingSafeEqual } = require('node:crypto');
const NS = /^[a-z][a-z0-9._-]{2,79}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const HEX = /^[a-f0-9]{64}$/;
const NONCE = /^[a-f0-9]{32,64}$/;
const B64 = /^[A-Za-z0-9+/]{86}==$/;

function validState(state) {
  return state && typeof state === 'object' && !Array.isArray(state) &&
    state.schemaVersion === 'palaco.distribution.authority-state.v1' &&
    typeof state.namespace === 'string' && NS.test(state.namespace) &&
    Number.isSafeInteger(state.sequence) && state.sequence >= 0 &&
    typeof state.digest === 'string' && HEX.test(state.digest) &&
    typeof state.challenge === 'string' && NONCE.test(state.challenge);
}
function authorityReceiptPayload(state) {
  if (!validState(state)) return null;
  return Buffer.from([
    'PALACO-INDUSTRIE-AUTHORITY-STATE-V1', state.schemaVersion,
    state.namespace, String(state.sequence), state.digest, state.challenge, ''
  ].join('\n'), 'utf8');
}
function response(readiness, findings) {
  return Object.freeze({
    schemaVersion: 'palaco.distribution.authority-receipt-assessment.v1',
    readiness, authorization: 'DENY', go13: 'HOLD',
    mayAdvance: false, mayRestore: false, mayRotate: false,
    mayPublish: false, mayInstall: false,
    findings: Object.freeze(findings)
  });
}
/** Caller MUST supply an independently pinned root, verifier-generated
 * unpredictable challenge and rollback-protected minimumSequence.
 * No I/O, authority state mutations or release actions occur here.
 */
function verifyAuthorityReceipt(namespace, state, endorsement, pinnedRoots, challenge, minimumSequence) {
  const findings = [];
  const payload = authorityReceiptPayload(state);
  if (typeof namespace !== 'string' || !NS.test(namespace) || !payload || state.namespace !== namespace)
    findings.push('INVALID_AUTHORITY_STATE');
  if (typeof challenge !== 'string' || !NONCE.test(challenge) ||
      !payload || state.challenge !== challenge)
    findings.push('CHALLENGE_MISMATCH');
  if (!Number.isSafeInteger(minimumSequence) || minimumSequence < 0)
    findings.push('TRUSTED_FLOOR_UNAVAILABLE');
  if (!endorsement || typeof endorsement !== 'object' || Array.isArray(endorsement) ||
      endorsement.algorithm !== 'Ed25519' || typeof endorsement.keyId !== 'string' ||
      !ID.test(endorsement.keyId) || typeof endorsement.signature !== 'string' ||
      !B64.test(endorsement.signature) ||
      Buffer.from(endorsement.signature || '', 'base64').toString('base64') !== endorsement.signature)
    findings.push('INVALID_RECEIPT_ENDORSEMENT');
  if (!Array.isArray(pinnedRoots) || pinnedRoots.length < 1 || pinnedRoots.length > 32)
    findings.push('PINNED_AUTHORITY_ROOTS_UNAVAILABLE');
  if (findings.length === 0) {
    if (state.sequence < minimumSequence) findings.push('AUTHORITY_STATE_BELOW_FLOOR');
    const matching = pinnedRoots.filter(root => root && root.keyId === endorsement.keyId);
    if (matching.length !== 1 || matching[0].enabled !== true || matching[0].revoked !== false ||
        typeof matching[0].publicKeyPem !== 'string' || matching[0].publicKeyPem.length > 4096) {
      findings.push('UNTRUSTED_AUTHORITY_ROOT');
    } else {
      try {
        const pub = createPublicKey(matching[0].publicKeyPem);
        const signature = Buffer.from(endorsement.signature, 'base64');
        if (pub.asymmetricKeyType !== 'ed25519' || signature.length !== 64 ||
            !verify(null, payload, pub, signature)) findings.push('AUTHORITY_SIGNATURE_INVALID');
      } catch (_) { findings.push('AUTHORITY_SIGNATURE_INVALID'); }
    }
  }
  return response(findings.length ? 'BLOCKED' : 'AUTHORITY_RECEIPT_VALID', findings);
}
function assessAuthenticatedRecovery(namespace, restored, state, endorsement, roots, challenge, minimumSequence) {
  const proof = verifyAuthorityReceipt(namespace, state, endorsement, roots, challenge, minimumSequence);
  const findings = [...proof.findings];
  if (!restored || typeof restored !== 'object' || Array.isArray(restored) ||
      restored.namespace !== namespace || !Number.isSafeInteger(restored.sequence) ||
      restored.sequence < 0 || typeof restored.digest !== 'string' || !HEX.test(restored.digest)) {
    findings.push('INVALID_RESTORED_ANCHOR');
  } else if (!findings.length) {
    if (restored.sequence < state.sequence) findings.push('RESTORED_ANCHOR_ROLLBACK');
    else if (restored.sequence > state.sequence) findings.push('AUTHORITY_RECEIPT_STALE');
    else if (!timingSafeEqual(Buffer.from(restored.digest, 'hex'), Buffer.from(state.digest, 'hex')))
      findings.push('RESTORED_ANCHOR_FORK');
  }
  return response(findings.length ? 'BLOCKED' : 'AUTHENTICATED_RECOVERY_MATCH', findings);
}
module.exports = { authorityReceiptPayload, verifyAuthorityReceipt, assessAuthenticatedRecovery };
