'use strict';

const { createHash, timingSafeEqual } = require('node:crypto');
const { assessDistributionManifest } = require('./manifest-gate');

/**
 * Verify supplied bytes against draft metadata. Does not read files, fetch URLs,
 * authenticate origin, verify signatures, install, or authorize publishing.
 * The caller is responsible for obtaining trusted bytes and protecting them
 * against changes after this assessment.
 */
function verifyDistributionBytes(manifest, bytes) {
  const assessment = assessDistributionManifest(manifest);
  const findings = [...assessment.findings];

  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0) {
    findings.push('INVALID_ARTIFACT_BYTES');
  } else if (assessment.readiness === 'MANIFEST_VALID') {
    if (bytes.byteLength !== manifest.sizeBytes) {
      findings.push('ARTIFACT_SIZE_MISMATCH');
    }
    const digest = createHash('sha256').update(bytes).digest();
    const expected = Buffer.from(manifest.sha256, 'hex');
    if (!timingSafeEqual(digest, expected)) {
      findings.push('ARTIFACT_HASH_MISMATCH');
    }
  }

  return Object.freeze({
    schemaVersion: 'palaco.distribution.byte-assessment.v1',
    readiness: findings.length === 0 ? 'BYTES_MATCH_MANIFEST' : 'BLOCKED',
    authorization: 'DENY',
    go13: 'HOLD',
    mayPublish: false,
    mayInstall: false,
    findings: Object.freeze(findings)
  });
}

module.exports = { verifyDistributionBytes };
