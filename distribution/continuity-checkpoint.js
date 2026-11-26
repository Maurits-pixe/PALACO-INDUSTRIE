'use strict';

const { createPublicKey, verify, createHash } = require('node:crypto');

const NS = /^[a-z][a-z0-9._-]{2,79}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const NONCE = /^[0-9a-f]{64}$/;
const HEX = /^[0-9a-f]{64}$/;
const SIG = /^[A-Za-z0-9+/]{86}==$/;
const VERSION = 'palaco.distribution.continuity-checkpoint.v1';

function checkpointPayload(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      value.schemaVersion !== VERSION ||
      typeof value.namespace !== 'string' || !NS.test(value.namespace) ||
      !Number.isSafeInteger(value.epoch) || value.epoch < 0 ||
      !Number.isSafeInteger(value.minimumLastSeenMs) || value.minimumLastSeenMs < 0 ||
      !Number.isSafeInteger(value.sequence) || value.sequence < 1 ||
      typeof value.challenge !== 'string' || !NONCE.test(value.challenge) ||
      typeof value.previousDigest !== 'string' || !HEX.test(value.previousDigest))
    return null;
  return Buffer.from([
    'PALACO-INDUSTRIE-CONTINUITY-CHECKPOINT-V1',
    VERSION, value.namespace, String(value.sequence), String(value.epoch),
    String(value.minimumLastSeenMs), value.previousDigest, value.challenge, ''
  ].join('\n'),'utf8');
}

function checkpointDigest(checkpoint) {
  const payload=checkpointPayload(checkpoint);
  return payload ? createHash('sha256').update(payload).digest('hex') : null;
}

function assessment(reason) {
  return Object.freeze({
    readiness:'BLOCKED', authorization:'DENY', go13:'HOLD',
    mayAdvance:false, mayRestore:false, mayPublish:false, mayInstall:false,
    findings:Object.freeze([reason])
  });
}

/**
 * Pinned Ed25519 root + fresh nonce + externally anchored sequence/digest.
 * The required anchor MUST be persisted outside any backup/restore domain of
 * the checkpoint issuer. This verifier does not persist or sign anything.
 */
function verifyContinuityCheckpoint(checkpoint, endorsement, {
  namespace, challenge, pinnedRoots, minimumSequence, priorDigest,
  minimumEpoch, minimumLastSeenMs
} = {}) {
  const payload=checkpointPayload(checkpoint);
  if (!payload || checkpoint.namespace !== namespace ||
      checkpoint.challenge !== challenge || !NONCE.test(challenge || ''))
    return assessment('CHECKPOINT_CONTEXT_INVALID');
  if (!Number.isSafeInteger(minimumSequence) || minimumSequence < 1 ||
      !HEX.test(priorDigest || '') ||
      !Number.isSafeInteger(minimumEpoch) || minimumEpoch < 0 ||
      !Number.isSafeInteger(minimumLastSeenMs) || minimumLastSeenMs < 0)
    return assessment('CHECKPOINT_ANCHOR_MISSING');
  if (checkpoint.sequence !== minimumSequence ||
      checkpoint.previousDigest !== priorDigest ||
      checkpoint.epoch < minimumEpoch ||
      checkpoint.minimumLastSeenMs < minimumLastSeenMs)
    return assessment('CHECKPOINT_ROLLBACK_OR_CHAIN_MISMATCH');
  if (!endorsement || endorsement.algorithm !== 'Ed25519' ||
      typeof endorsement.keyId !== 'string' || !ID.test(endorsement.keyId) ||
      typeof endorsement.signature !== 'string' || !SIG.test(endorsement.signature) ||
      Buffer.from(endorsement.signature,'base64').toString('base64') !== endorsement.signature ||
      !Array.isArray(pinnedRoots) || pinnedRoots.length < 1 || pinnedRoots.length > 32)
    return assessment('CHECKPOINT_SIGNATURE_INVALID');
  const matches=pinnedRoots.filter(root=>root && root.keyId===endorsement.keyId);
  if (matches.length!==1 || matches[0].enabled!==true || matches[0].revoked!==false ||
      typeof matches[0].publicKeyPem!=='string' || matches[0].publicKeyPem.length>4096)
    return assessment('CHECKPOINT_ROOT_UNTRUSTED');
  try {
    const key=createPublicKey(matches[0].publicKeyPem);
    if (key.asymmetricKeyType!=='ed25519' ||
        !verify(null,payload,key,Buffer.from(endorsement.signature,'base64')))
      return assessment('CHECKPOINT_SIGNATURE_INVALID');
  } catch (_) { return assessment('CHECKPOINT_SIGNATURE_INVALID'); }
  return Object.freeze({
    readiness:'CHECKPOINT_VERIFIED',authorization:'DENY',go13:'HOLD',
    digest:checkpointDigest(checkpoint),
    sequence:checkpoint.sequence,epoch:checkpoint.epoch,
    minimumLastSeenMs:checkpoint.minimumLastSeenMs,
    mayAdvance:false,mayRestore:false,mayPublish:false,mayInstall:false,
    findings:Object.freeze([])
  });
}

module.exports={VERSION,checkpointPayload,checkpointDigest,verifyContinuityCheckpoint};
