'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync, createHash, sign } = require('node:crypto');
const { signedManifestPayload } = require('../distribution/signed-verifier');
const { digestSnapshot, assessTrustContinuity, verifyDistributionWithContinuity } = require('../distribution/trust-continuity');

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const bytes = Buffer.from('PALACO continuity test');
const manifest = {
  schemaVersion: 'palaco.distribution.v1', appId: 'palaco.one',
  version: '0.4.0', artifact: 'palaco-one.zip',
  sha256: createHash('sha256').update(bytes).digest('hex'), sizeBytes: bytes.length,
  channel: 'draft', authorization: 'DENY', go13: 'HOLD'
};
const envelope = {
  algorithm: 'Ed25519', keyId: 'test-key',
  signature: sign(null, signedManifestPayload(manifest), privateKey).toString('base64')
};
const snapshot = () => ({
  schemaVersion: 'palaco.distribution.trust.v1',
  complete: true, revocationsChecked: true,
  keys: [{ keyId: 'test-key', enabled: true, revoked: false,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) }]
});
const anchor = { sequence: 4, digest: 'b'.repeat(64) };
const checkpoint = s => ({
  schemaVersion: 'palaco.distribution.checkpoint.v1',
  sequence: 5, previousDigest: anchor.digest, digest: digestSnapshot(s)
});

test('sequential digest-linked checkpoint validates without granting authority', () => {
  const s = snapshot(), result = verifyDistributionWithContinuity(manifest, bytes, envelope, s, checkpoint(s), anchor);
  assert.equal(result.readiness, 'SIGNED_BYTES_AND_CONTINUITY_MATCH');
  assert.equal(result.mayInstall, false);
  assert.equal(result.mayPublish, false);
  assert.equal(result.authorization, 'DENY');
  assert.equal(result.go13, 'HOLD');
});

test('older, repeated, skipped or non-integer sequence is denied', () => {
  const s = snapshot(), cp = checkpoint(s);
  for (const sequence of [3, 4, 6, 5.5, -1]) {
    assert.equal(assessTrustContinuity(s, { ...cp, sequence }, anchor).readiness, 'BLOCKED');
  }
});

test('checkpoint cannot change snapshot or previous digest undetected', () => {
  const s = snapshot(), cp = checkpoint(s);
  assert.equal(assessTrustContinuity(s, { ...cp, previousDigest: 'c'.repeat(64) }, anchor).readiness, 'BLOCKED');
  assert.equal(assessTrustContinuity({ ...s, keys: [] }, cp, anchor).readiness, 'BLOCKED');
  assert.equal(assessTrustContinuity(s, { ...cp, digest: '0'.repeat(64) }, anchor).readiness, 'BLOCKED');
});

test('unknown anchor and malformed trust state fail closed', () => {
  const s = snapshot(), cp = checkpoint(s);
  assert.equal(assessTrustContinuity(s, cp, null).readiness, 'BLOCKED');
  assert.equal(assessTrustContinuity(s, cp, { sequence: 4, digest: 'no' }).readiness, 'BLOCKED');
  assert.equal(assessTrustContinuity(null, cp, anchor).readiness, 'BLOCKED');
  assert.equal(assessTrustContinuity({ ...s, complete: false }, cp, anchor).readiness, 'BLOCKED');
  assert.equal(assessTrustContinuity(s, null, anchor).readiness, 'BLOCKED');
});

test('duplicate key ids and malformed key state are blocked', () => {
  const s = snapshot();
  assert.equal(digestSnapshot({ ...s, keys: [s.keys[0], s.keys[0]] }), null);
  assert.equal(digestSnapshot({ ...s, keys: [{ ...s.keys[0], revoked: 'false' }] }), null);
});

test('key order does not change digest', () => {
  const s = snapshot();
  const extra = { ...s.keys[0], keyId: 'other-key', revoked: true };
  assert.equal(digestSnapshot({ ...s, keys: [s.keys[0], extra] }),
    digestSnapshot({ ...s, keys: [extra, s.keys[0]] }));
});

test('revoked signing key blocks the composed verifier even if checkpoint matches', () => {
  const s = snapshot(); s.keys[0].revoked = true;
  assert.equal(verifyDistributionWithContinuity(manifest, bytes, envelope, s, checkpoint(s), anchor).readiness, 'BLOCKED');
});
