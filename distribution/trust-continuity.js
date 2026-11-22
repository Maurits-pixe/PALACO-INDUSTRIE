'use strict';

const { createHash, timingSafeEqual } = require('node:crypto');
const { verifySignedDistribution } = require('./signed-verifier');

const HASH = /^[a-f0-9]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const MAX_KEYS = 1000;

function digestSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot) ||
      snapshot.schemaVersion !== 'palaco.distribution.trust.v1' ||
      snapshot.complete !== true || snapshot.revocationsChecked !== true ||
      !Array.isArray(snapshot.keys) || snapshot.keys.length > MAX_KEYS) return null;
  const normalized = [];
  const seen = new Set();
  for (const entry of snapshot.keys) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
        typeof entry.keyId !== 'string' || !ID.test(entry.keyId) ||
        typeof entry.publicKeyPem !== 'string' || entry.publicKeyPem.length > 4096 ||
        (entry.enabled !== true && entry.enabled !== false) ||
        (entry.revoked !== true && entry.revoked !== false) ||
        seen.has(entry.keyId)) return null;
    seen.add(entry.keyId);
    normalized.push([entry.keyId, entry.publicKeyPem, entry.enabled, entry.revoked]);
  }
  normalized.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
  const serialized = JSON.stringify(['PALACO-TRUST-SNAPSHOT-V1', normalized]);
  return createHash('sha256').update(serialized, 'utf8').digest('hex');
}

function sameHash(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || !HASH.test(a) || !HASH.test(b)) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

/**
 * Compare a candidate trust snapshot with a previously authenticated, durable
 * caller-held anchor. This does NOT authenticate the new checkpoint; callers
 * must verify checkpoint authority through an independent trusted channel.
 */
function assessTrustContinuity(snapshot, checkpoint, anchor) {
  const findings = [];
  const digest = digestSnapshot(snapshot);
  if (!digest) findings.push('INVALID_TRUST_SNAPSHOT');
  if (!anchor || typeof anchor !== 'object' || Array.isArray(anchor) ||
      !Number.isSafeInteger(anchor.sequence) || anchor.sequence < 0 ||
      typeof anchor.digest !== 'string' || !HASH.test(anchor.digest)) {
    findings.push('TRUST_ANCHOR_UNAVAILABLE');
  }
  if (!checkpoint || typeof checkpoint !== 'object' || Array.isArray(checkpoint) ||
      checkpoint.schemaVersion !== 'palaco.distribution.checkpoint.v1' ||
      !Number.isSafeInteger(checkpoint.sequence) || checkpoint.sequence < 1 ||
      typeof checkpoint.digest !== 'string' || !HASH.test(checkpoint.digest) ||
      typeof checkpoint.previousDigest !== 'string' || !HASH.test(checkpoint.previousDigest)) {
    findings.push('INVALID_TRUST_CHECKPOINT');
  }
  if (findings.length === 0) {
    if (checkpoint.sequence !== anchor.sequence + 1) findings.push('NON_SEQUENTIAL_TRUST_UPDATE');
    if (!sameHash(checkpoint.previousDigest, anchor.digest)) findings.push('TRUST_CHAIN_MISMATCH');
    if (!sameHash(checkpoint.digest, digest)) findings.push('TRUST_SNAPSHOT_DIGEST_MISMATCH');
  }
  return Object.freeze({
    schemaVersion: 'palaco.distribution.continuity-assessment.v1',
    readiness: findings.length === 0 ? 'CONTINUITY_MATCH' : 'BLOCKED',
    authorization: 'DENY',
    go13: 'HOLD',
    mayPublish: false,
    mayInstall: false,
    findings: Object.freeze(findings)
  });
}

function verifyDistributionWithContinuity(manifest, bytes, envelope, snapshot, checkpoint, anchor) {
  const signed = verifySignedDistribution(manifest, bytes, envelope, snapshot);
  const continuity = assessTrustContinuity(snapshot, checkpoint, anchor);
  const findings = [...signed.findings, ...continuity.findings];
  return Object.freeze({
    schemaVersion: 'palaco.distribution.continuous-signed-assessment.v1',
    readiness: findings.length === 0 ? 'SIGNED_BYTES_AND_CONTINUITY_MATCH' : 'BLOCKED',
    authorization: 'DENY',
    go13: 'HOLD',
    mayPublish: false,
    mayInstall: false,
    findings: Object.freeze(findings)
  });
}

module.exports = { digestSnapshot, assessTrustContinuity, verifyDistributionWithContinuity };
