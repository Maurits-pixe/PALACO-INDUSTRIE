'use strict';

const { createPublicKey, verify } = require('node:crypto');
const { assessTrustContinuity, verifyDistributionWithContinuity } = require('./trust-continuity');

const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const SIG = /^[A-Za-z0-9+/]{86}==$/;

/**
 * Deterministic, domain-separated checkpoint signing payload.
 * Only call after checkpoint schema validation by assessTrustContinuity.
 */
function checkpointSigningPayload(checkpoint) {
  return Buffer.from([
    'PALACO-INDUSTRIE-TRUST-CHECKPOINT-V1',
    checkpoint.schemaVersion,
    String(checkpoint.sequence),
    checkpoint.previousDigest,
    checkpoint.digest,
    ''
  ].join('\n'), 'utf8');
}

/**
 * Independently authenticate a checkpoint with caller-pinned root keys.
 * The pinned root set must come from the application's independently trusted
 * configuration, NOT from the candidate snapshot or downloaded package.
 */
function verifyCheckpointAuthority(checkpoint, endorsement, pinnedRoots) {
  const findings = [];
  if (!checkpoint || typeof checkpoint !== 'object' || Array.isArray(checkpoint) ||
      checkpoint.schemaVersion !== 'palaco.distribution.checkpoint.v1' ||
      !Number.isSafeInteger(checkpoint.sequence) || checkpoint.sequence < 1 ||
      !/^[a-f0-9]{64}$/.test(checkpoint.digest ?? '') ||
      !/^[a-f0-9]{64}$/.test(checkpoint.previousDigest ?? '')) {
    findings.push('INVALID_CHECKPOINT');
  }
  if (!endorsement || typeof endorsement !== 'object' || Array.isArray(endorsement) ||
      endorsement.algorithm !== 'Ed25519' ||
      typeof endorsement.keyId !== 'string' || !KEY_ID.test(endorsement.keyId) ||
      typeof endorsement.signature !== 'string' || !SIG.test(endorsement.signature) ||
      Buffer.from(endorsement.signature ?? '', 'base64').toString('base64') !== endorsement.signature) {
    findings.push('INVALID_CHECKPOINT_ENDORSEMENT');
  }
  if (!Array.isArray(pinnedRoots) || pinnedRoots.length < 1 || pinnedRoots.length > 32) {
    findings.push('PINNED_ROOTS_UNAVAILABLE');
  }

  if (findings.length === 0) {
    const matching = pinnedRoots.filter(root => root && root.keyId === endorsement.keyId);
    if (matching.length !== 1) {
      findings.push('UNKNOWN_OR_DUPLICATE_ROOT');
    } else {
      const root = matching[0];
      if (root.enabled !== true || root.revoked !== false || typeof root.publicKeyPem !== 'string') {
        findings.push('ROOT_NOT_TRUSTED');
      } else {
        try {
          const pub = createPublicKey(root.publicKeyPem);
          if (pub.asymmetricKeyType !== 'ed25519' ||
              !verify(null, checkpointSigningPayload(checkpoint), pub,
                Buffer.from(endorsement.signature, 'base64'))) {
            findings.push('CHECKPOINT_SIGNATURE_INVALID');
          }
        } catch (_) {
          findings.push('CHECKPOINT_SIGNATURE_INVALID');
        }
      }
    }
  }
  return Object.freeze({
    schemaVersion: 'palaco.distribution.checkpoint-authority-assessment.v1',
    readiness: findings.length ? 'BLOCKED' : 'CHECKPOINT_SIGNATURE_VALID',
    authorization: 'DENY',
    go13: 'HOLD',
    mayPublish: false,
    mayInstall: false,
    findings: Object.freeze(findings)
  });
}

function verifyAuthenticatedDistribution(manifest, bytes, artifactSignature, snapshot,
                                         checkpoint, anchor, endorsement, pinnedRoots) {
  const continuity = assessTrustContinuity(snapshot, checkpoint, anchor);
  const authority = verifyCheckpointAuthority(checkpoint, endorsement, pinnedRoots);
  const distribution = verifyDistributionWithContinuity(manifest, bytes, artifactSignature,
                                                        snapshot, checkpoint, anchor);
  const findings = [...distribution.findings, ...authority.findings];
  return Object.freeze({
    schemaVersion: 'palaco.distribution.authenticated-assessment.v1',
    readiness: !findings.length && continuity.readiness === 'CONTINUITY_MATCH'
      ? 'AUTHENTICATED_CHECKPOINT_AND_ARTIFACT_MATCH' : 'BLOCKED',
    authorization: 'DENY',
    go13: 'HOLD',
    mayPublish: false,
    mayInstall: false,
    findings: Object.freeze(findings)
  });
}

module.exports = { checkpointSigningPayload, verifyCheckpointAuthority,
                   verifyAuthenticatedDistribution };
