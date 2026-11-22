'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, generateKeyPairSync, sign } = require('node:crypto');
const { signedManifestPayload } = require('../distribution/signed-verifier');
const { digestSnapshot } = require('../distribution/trust-continuity');
const { checkpointSigningPayload, verifyCheckpointAuthority,
        verifyAuthenticatedDistribution } = require('../distribution/authenticated-checkpoint');

const artifactKey = generateKeyPairSync('ed25519');
const rootKey = generateKeyPairSync('ed25519');
const bytes = Buffer.from('PALACO v0.5 draft specimen');
const manifest = {
  schemaVersion: 'palaco.distribution.v1', appId: 'palaco.one',
  version: '0.5.0', artifact: 'palaco-one.zip',
  sha256: createHash('sha256').update(bytes).digest('hex'),
  sizeBytes: bytes.length, channel: 'draft', authorization: 'DENY', go13: 'HOLD'
};
const artifactSignature = {
  algorithm: 'Ed25519', keyId: 'artifact-key',
  signature: sign(null, signedManifestPayload(manifest), artifactKey.privateKey).toString('base64')
};
const snapshot = {
  schemaVersion: 'palaco.distribution.trust.v1', complete: true, revocationsChecked: true,
  keys: [{ keyId: 'artifact-key', enabled: true, revoked: false,
    publicKeyPem: artifactKey.publicKey.export({ type: 'spki', format: 'pem' }) }]
};
const anchor = { sequence: 10, digest: 'a'.repeat(64) };
const checkpoint = {
  schemaVersion: 'palaco.distribution.checkpoint.v1',
  sequence: 11, previousDigest: anchor.digest, digest: digestSnapshot(snapshot)
};
const endorsement = cp => ({
  algorithm: 'Ed25519', keyId: 'offline-root-test',
  signature: sign(null, checkpointSigningPayload(cp), rootKey.privateKey).toString('base64')
});
const roots = () => [{
  keyId: 'offline-root-test', enabled: true, revoked: false,
  publicKeyPem: rootKey.publicKey.export({ type: 'spki', format: 'pem' })
}];

test('independently signed checkpoint verifies without granting deployment rights', () => {
  const result = verifyAuthenticatedDistribution(manifest, bytes, artifactSignature, snapshot,
    checkpoint, anchor, endorsement(checkpoint), roots());
  assert.equal(result.readiness, 'AUTHENTICATED_CHECKPOINT_AND_ARTIFACT_MATCH');
  assert.equal(result.authorization, 'DENY');
  assert.equal(result.go13, 'HOLD');
  assert.equal(result.mayPublish, false);
  assert.equal(result.mayInstall, false);
});

test('unsigned and unknown-root checkpoints are blocked', () => {
  assert.equal(verifyCheckpointAuthority(checkpoint, null, roots()).readiness, 'BLOCKED');
  assert.equal(verifyCheckpointAuthority(checkpoint, endorsement(checkpoint), []).readiness, 'BLOCKED');
  assert.equal(verifyCheckpointAuthority(checkpoint, endorsement(checkpoint), [
    { ...roots()[0], keyId: 'different' }]).readiness, 'BLOCKED');
});

test('tampered checkpoint fields cannot reuse a signature', () => {
  for (const cp of [
    { ...checkpoint, digest: 'b'.repeat(64) },
    { ...checkpoint, previousDigest: 'c'.repeat(64) },
    { ...checkpoint, sequence: 12 }
  ]) {
    assert.equal(verifyCheckpointAuthority(cp, endorsement(checkpoint), roots()).readiness, 'BLOCKED');
  }
});

test('revoked, disabled or duplicated authority roots are blocked', () => {
  const e = endorsement(checkpoint), r = roots()[0];
  for (const set of [[{ ...r, revoked: true }], [{ ...r, enabled: false }], [r, r]]) {
    assert.equal(verifyCheckpointAuthority(checkpoint, e, set).readiness, 'BLOCKED');
  }
});

test('wrong checkpoint signing key is rejected', () => {
  const other = generateKeyPairSync('ed25519');
  const fake = { ...endorsement(checkpoint),
    signature: sign(null, checkpointSigningPayload(checkpoint), other.privateKey).toString('base64') };
  assert.equal(verifyCheckpointAuthority(checkpoint, fake, roots()).readiness, 'BLOCKED');
});

test('authenticated checkpoint cannot bypass a broken continuity chain', () => {
  const wrongAnchor = { ...anchor, sequence: 9 };
  assert.equal(verifyAuthenticatedDistribution(manifest, bytes, artifactSignature, snapshot,
    checkpoint, wrongAnchor, endorsement(checkpoint), roots()).readiness, 'BLOCKED');
});

test('authenticated checkpoint cannot bypass tampered package', () => {
  const mutated = Buffer.from(bytes); mutated[0] ^= 1;
  assert.equal(verifyAuthenticatedDistribution(manifest, mutated, artifactSignature, snapshot,
    checkpoint, anchor, endorsement(checkpoint), roots()).readiness, 'BLOCKED');
});
