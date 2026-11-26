'use strict';

const { createHash, createPublicKey, verify } = require('node:crypto');
const { verifyCheckpointAuthority } = require('./authenticated-checkpoint');

const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const HEX = /^[a-f0-9]{64}$/;
const BASE64 = /^[A-Za-z0-9+/]{86}==$/;

function readRoots(roots) {
  if (!Array.isArray(roots) || roots.length < 1 || roots.length > 32) return null;
  const keys = [];
  const ids = new Set();
  for (const entry of roots) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
        typeof entry.keyId !== 'string' || !KEY_ID.test(entry.keyId) ||
        ids.has(entry.keyId) || entry.enabled !== true || entry.revoked !== false ||
        typeof entry.publicKeyPem !== 'string' || entry.publicKeyPem.length > 4096) return null;
    try {
      const key = createPublicKey(entry.publicKeyPem);
      if (key.asymmetricKeyType !== 'ed25519') return null;
      const fingerprint = createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
      ids.add(entry.keyId);
      keys.push({ keyId: entry.keyId, fingerprint, key });
    } catch (_) { return null; }
  }
  keys.sort((a, b) => a.keyId.localeCompare(b.keyId, 'en'));
  return keys;
}

function rotationPayload(proposal, oldRoots, newRoots) {
  if (!proposal || typeof proposal !== 'object' || Array.isArray(proposal) ||
      proposal.schemaVersion !== 'palaco.distribution.root-rotation.v1' ||
      !Number.isSafeInteger(proposal.sequence) || proposal.sequence < 1 ||
      typeof proposal.previousDigest !== 'string' || !HEX.test(proposal.previousDigest) ||
      typeof proposal.checkpointDigest !== 'string' || !HEX.test(proposal.checkpointDigest)) return null;
  const oldKeys = readRoots(oldRoots);
  const newKeys = readRoots(newRoots);
  if (!oldKeys || !newKeys) return null;
  const oldIds = new Set(oldKeys.map(x => x.keyId));
  // Require a genuinely new root; disallow reusing an existing ID with a changed key.
  if (newKeys.some(x => oldIds.has(x.keyId))) return null;
  const oldHash = createHash('sha256').update(JSON.stringify(oldKeys.map(x => [x.keyId, x.fingerprint]))).digest('hex');
  const newHash = createHash('sha256').update(JSON.stringify(newKeys.map(x => [x.keyId, x.fingerprint]))).digest('hex');
  const lines = [
    'PALACO-INDUSTRIE-ROOT-ROTATION-V1',
    proposal.schemaVersion, String(proposal.sequence), proposal.previousDigest,
    proposal.checkpointDigest, oldHash, newHash, ''
  ];
  return Buffer.from(lines.join('\n'), 'utf8');
}

function validEndorsement(endorsement, roots, payload) {
  if (!endorsement || typeof endorsement !== 'object' || Array.isArray(endorsement) ||
      endorsement.algorithm !== 'Ed25519' || typeof endorsement.keyId !== 'string' ||
      !KEY_ID.test(endorsement.keyId) || typeof endorsement.signature !== 'string' ||
      !BASE64.test(endorsement.signature)) return false;
  const signature = Buffer.from(endorsement.signature, 'base64');
  if (signature.length !== 64 || signature.toString('base64') !== endorsement.signature) return false;
  const matching = roots.filter(x => x.keyId === endorsement.keyId);
  return matching.length === 1 && verify(null, payload, matching[0].key, signature);
}

/**
 * Dual-consent rotation assessment:
 * 1) old pinned root signs checkpoint + transition;
 * 2) new proposed root proves possession of its own private key;
 * 3) one root cannot impersonate both sets.
 * No root installation, durable state mutation, or release authority.
 */
function assessRootRotation(proposal, checkpoint, oldRoots, newRoots, oldCheckpointEndorsement,
                            oldRotationEndorsement, newRotationEndorsement) {
  const findings = [];
  const old = readRoots(oldRoots), next = readRoots(newRoots);
  const payload = rotationPayload(proposal, oldRoots, newRoots);
  if (!payload || !old || !next) findings.push('INVALID_ROOT_ROTATION_PROPOSAL');
  if (!checkpoint || typeof checkpoint !== 'object' || Array.isArray(checkpoint) ||
      !proposal || proposal.sequence !== checkpoint.sequence ||
      proposal.previousDigest !== checkpoint.previousDigest ||
      proposal.checkpointDigest !== checkpoint.digest) {
    findings.push('ROTATION_CHECKPOINT_MISMATCH');
  }
  const checkpointResult = verifyCheckpointAuthority(checkpoint, oldCheckpointEndorsement, oldRoots);
  if (checkpointResult.readiness !== 'CHECKPOINT_SIGNATURE_VALID') {
    findings.push('OLD_CHECKPOINT_AUTHORITY_INVALID');
  }
  if (payload && old && !validEndorsement(oldRotationEndorsement, old, payload)) {
    findings.push('OLD_ROOT_CONSENT_INVALID');
  }
  if (payload && next && !validEndorsement(newRotationEndorsement, next, payload)) {
    findings.push('NEW_ROOT_PROOF_INVALID');
  }
  return Object.freeze({
    schemaVersion: 'palaco.distribution.root-rotation-assessment.v1',
    readiness: findings.length === 0 ? 'DUAL_ROOT_PROOF_VALID' : 'BLOCKED',
    authorization: 'DENY', go13: 'HOLD',
    mayPublish: false, mayInstall: false, mayRotate: false,
    findings: Object.freeze(findings)
  });
}

module.exports = { rotationPayload, assessRootRotation };
