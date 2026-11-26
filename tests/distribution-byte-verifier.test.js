'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { verifyDistributionBytes } = require('../distribution/byte-verifier');

const bytes = Buffer.from('palaco-draft-payload-v1', 'utf8');
const manifest = () => ({
  schemaVersion: 'palaco.distribution.v1',
  appId: 'palaco.one',
  version: '0.1.0',
  artifact: 'palaco-one.zip',
  sha256: createHash('sha256').update(bytes).digest('hex'),
  sizeBytes: bytes.byteLength,
  channel: 'draft',
  authorization: 'DENY',
  go13: 'HOLD'
});

test('matching bytes validate without granting authority', () => {
  const result = verifyDistributionBytes(manifest(), bytes);
  assert.equal(result.readiness, 'BYTES_MATCH_MANIFEST');
  assert.equal(result.mayPublish, false);
  assert.equal(result.mayInstall, false);
  assert.equal(result.authorization, 'DENY');
  assert.equal(result.go13, 'HOLD');
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.findings));
});

test('altered bytes are rejected even if the byte length matches', () => {
  const modified = Buffer.from(bytes);
  modified[0] ^= 1;
  assert.ok(verifyDistributionBytes(manifest(), modified).findings.includes('ARTIFACT_HASH_MISMATCH'));
});

test('truncated package is rejected', () => {
  assert.ok(verifyDistributionBytes(manifest(), bytes.subarray(0, -1)).findings.includes('ARTIFACT_SIZE_MISMATCH'));
});

test('no bytes and invalid inputs are rejected', () => {
  for (const input of [null, undefined, '', [], new Uint8Array(0)]) {
    assert.equal(verifyDistributionBytes(manifest(), input).readiness, 'BLOCKED');
  }
});

test('a Uint8Array view only hashes its selected range', () => {
  const wrapped = Buffer.concat([Buffer.from('prefix'), bytes, Buffer.from('suffix')]);
  const view = new Uint8Array(wrapped.buffer, wrapped.byteOffset + 6, bytes.length);
  assert.equal(verifyDistributionBytes(manifest(), view).readiness, 'BYTES_MATCH_MANIFEST');
});

test('metadata failures and authorization escalation remain blocked', () => {
  assert.equal(verifyDistributionBytes({ ...manifest(), authorization: 'ALLOW' }, bytes).readiness, 'BLOCKED');
  assert.equal(verifyDistributionBytes({ ...manifest(), sha256: 'invalid' }, bytes).readiness, 'BLOCKED');
  assert.equal(verifyDistributionBytes(null, bytes).readiness, 'BLOCKED');
});
