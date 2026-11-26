'use strict';

const { createPublicKey, verify } = require('node:crypto');
const { verifyDistributionBytes } = require('./byte-verifier');

const KEY_ID = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/;
const B64_SIGNATURE = /^[A-Za-z0-9+/]{86}==$/;

// Signing representation is versioned, UTF-8 and uses a fixed field order.
// Values are prevalidated by the manifest gate before encoding.
function signedManifestPayload(manifest) {
  return Buffer.from([
    'PALACO-INDUSTRIE-DISTRIBUTION-V1',
    manifest.schemaVersion,
    manifest.appId,
    manifest.version,
    manifest.artifact,
    manifest.sha256,
    String(manifest.sizeBytes),
    manifest.channel,
    manifest.authorization,
    manifest.go13,
    ''
  ].join('\n'), 'utf8');
}

/**
 * Verify metadata, actual artifact bytes, and a signature over the canonical
 * manifest payload against a caller-provided, explicitly trusted key snapshot.
 * Trust snapshots must be authenticated, current, and revocation-complete.
 * No networking, trust discovery, filesystem access or side effects.
 */
function verifySignedDistribution(manifest, bytes, envelope, trust) {
  const byteAssessment = verifyDistributionBytes(manifest, bytes);
  const findings = [...byteAssessment.findings];

  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope) ||
      envelope.algorithm !== 'Ed25519' || !KEY_ID.test(envelope.keyId ?? '') ||
      typeof envelope.signature !== 'string' ||
      !B64_SIGNATURE.test(envelope.signature) ||
      Buffer.from(envelope.signature, 'base64').length !== 64 ||
      Buffer.from(envelope.signature, 'base64').toString('base64') !== envelope.signature) {
    findings.push('INVALID_SIGNATURE_ENVELOPE');
  }

  if (!trust || typeof trust !== 'object' || Array.isArray(trust) ||
      trust.schemaVersion !== 'palaco.distribution.trust.v1' ||
      trust.complete !== true || trust.revocationsChecked !== true ||
      !Array.isArray(trust.keys)) {
    findings.push('TRUST_SNAPSHOT_UNAVAILABLE');
  }

  if (findings.length === 0) {
    const matching = trust.keys.filter(key => key && key.keyId === envelope.keyId);
    if (matching.length !== 1) {
      findings.push('UNKNOWN_OR_DUPLICATE_SIGNING_KEY');
    } else {
      const entry = matching[0];
      if (entry.revoked !== false || entry.enabled !== true ||
          typeof entry.publicKeyPem !== 'string') {
        findings.push('SIGNING_KEY_NOT_TRUSTED');
      } else {
        try {
          const key = createPublicKey(entry.publicKeyPem);
          if (key.asymmetricKeyType !== 'ed25519' ||
              !verify(null, signedManifestPayload(manifest), key,
                Buffer.from(envelope.signature, 'base64'))) {
            findings.push('SIGNATURE_VERIFICATION_FAILED');
          }
        } catch (_) {
          findings.push('SIGNATURE_VERIFICATION_FAILED');
        }
      }
    }
  }

  return Object.freeze({
    schemaVersion: 'palaco.distribution.signed-assessment.v1',
    readiness: findings.length === 0 ? 'SIGNED_BYTES_MATCH' : 'BLOCKED',
    authorization: 'DENY',
    go13: 'HOLD',
    mayPublish: false,
    mayInstall: false,
    findings: Object.freeze(findings)
  });
}

module.exports = { signedManifestPayload, verifySignedDistribution };
