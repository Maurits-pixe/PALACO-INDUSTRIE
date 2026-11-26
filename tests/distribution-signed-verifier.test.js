'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, generateKeyPairSync, sign } = require('node:crypto');
const { signedManifestPayload, verifySignedDistribution } = require('../distribution/signed-verifier');

const payload = Buffer.from('PALACO signed test draft package');
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const keyId = 'palaco-draft-test-key';
const manifest = () => ({
  schemaVersion: 'palaco.distribution.v1',
  appId: 'palaco.one',
  version: '0.2.0',
  artifact: 'palaco-one.zip',
  sha256: createHash('sha256').update(payload).digest('hex'),
  sizeBytes: payload.length,
  channel: 'draft',
  authorization: 'DENY',
  go13: 'HOLD'
});
const envelope = m => ({
  algorithm: 'Ed25519',
  keyId,
  signature: sign(null, signedManifestPayload(m), privateKey).toString('base64')
});
const trust = () => ({
  schemaVersion: 'palaco.distribution.trust.v1',
  complete: true,
  revocationsChecked: true,
  keys: [{
    keyId,
    enabled: true,
    revoked: false,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' })
  }]
});

test('signed matching bytes verify but remain denied for release', () => {
  const m = manifest();
  const result = verifySignedDistribution(m, payload, envelope(m), trust());
  assert.equal(result.readiness, 'SIGNED_BYTES_MATCH');
  assert.equal(result.mayPublish, false);
  assert.equal(result.mayInstall, false);
  assert.equal(result.authorization, 'DENY');
  assert.equal(result.go13, 'HOLD');
  assert.ok(Object.isFrozen(result));
});

test('tampered package or manifest is blocked', () => {
  const m = manifest(), sig = envelope(m), t = trust();
  const changed = Buffer.from(payload);
  changed[0] ^= 1;
  assert.equal(verifySignedDistribution(m, changed, sig, t).readiness, 'BLOCKED');
  assert.equal(verifySignedDistribution({ ...m, version: '0.3.0' }, payload, sig, t).readiness, 'BLOCKED');
});

test('revoked, disabled, missing and duplicate keys are blocked', () => {
  const m = manifest(), sig = envelope(m), t = trust();
  for (const keys of [
    [{ ...t.keys[0], revoked: true }],
    [{ ...t.keys[0], enabled: false }],
    [],
    [t.keys[0], t.keys[0]]
  ]) {
    assert.equal(verifySignedDistribution(m, payload, sig, { ...t, keys }).readiness, 'BLOCKED');
  }
});

test('missing revocation completeness blocks even a valid signature', () => {
  const m = manifest(), sig = envelope(m), t = trust();
  for (const change of [{ complete: false }, { revocationsChecked: false }, { keys: null }]) {
    assert.equal(verifySignedDistribution(m, payload, sig, { ...t, ...change }).readiness, 'BLOCKED');
  }
  assert.equal(verifySignedDistribution(m, payload, sig, null).readiness, 'BLOCKED');
});

test('invalid signature and wrong algorithm are blocked', () => {
  const m = manifest(), sig = envelope(m);
  const corrupt = Buffer.from(sig.signature, 'base64'); corrupt[0] ^= 1;
  assert.equal(verifySignedDistribution(m, payload, { ...sig, signature: corrupt.toString('base64') }, trust()).readiness, 'BLOCKED');
  assert.equal(verifySignedDistribution(m, payload, { ...sig, algorithm: 'RSA' }, trust()).readiness, 'BLOCKED');
  assert.equal(verifySignedDistribution(m, payload, null, trust()).readiness, 'BLOCKED');
});

test('untrusted or incorrect public key cannot validate a signature', () => {
  const m = manifest();
  const other = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
  const t = trust(); t.keys[0].publicKeyPem = other;
  assert.equal(verifySignedDistribution(m, payload, envelope(m), t).readiness, 'BLOCKED');
});
