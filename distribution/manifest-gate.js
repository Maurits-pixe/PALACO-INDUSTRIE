'use strict';

/**
 * PALACO INDUSTRIE — read-only distribution manifest assessment.
 * A valid manifest is NOT publication authorization.
 * No filesystem, network, signing, or installation side effects.
 */
const HEX64 = /^[a-f0-9]{64}$/;
const IDENTIFIER = /^[a-z][a-z0-9.-]{2,79}$/;
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/;
const ARTIFACT = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,199}\.(?:zip|tar\.gz|msi|exe|apk)$/;

function assessDistributionManifest(manifest) {
  const findings = [];
  const reject = (code) => findings.push(code);

  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    reject('INVALID_MANIFEST');
  } else {
    if (manifest.schemaVersion !== 'palaco.distribution.v1') reject('UNSUPPORTED_SCHEMA');
    if (typeof manifest.appId !== 'string' || !IDENTIFIER.test(manifest.appId)) reject('INVALID_APP_ID');
    if (typeof manifest.version !== 'string' || !VERSION.test(manifest.version)) reject('INVALID_VERSION');
    if (typeof manifest.artifact !== 'string' || !ARTIFACT.test(manifest.artifact)) reject('INVALID_ARTIFACT');
    if (typeof manifest.sha256 !== 'string' || !HEX64.test(manifest.sha256)) reject('INVALID_SHA256');
    if (!Number.isSafeInteger(manifest.sizeBytes) || manifest.sizeBytes <= 0) reject('INVALID_SIZE');
    if (manifest.channel !== 'draft') reject('NON_DRAFT_CHANNEL');
    if (manifest.authorization !== 'DENY') reject('AUTHORIZATION_MUST_BE_DENY');
    if (manifest.go13 !== 'HOLD') reject('GO13_MUST_BE_HOLD');
  }
  const valid = findings.length === 0;
  return Object.freeze({
    schemaVersion: 'palaco.distribution.assessment.v1',
    readiness: valid ? 'MANIFEST_VALID' : 'BLOCKED',
    authorization: 'DENY',
    go13: 'HOLD',
    mayPublish: false,
    mayInstall: false,
    findings: Object.freeze(findings)
  });
}

module.exports = { assessDistributionManifest };
