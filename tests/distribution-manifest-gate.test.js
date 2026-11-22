'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { assessDistributionManifest } = require('../distribution/manifest-gate');

const sample = () => ({
  schemaVersion: 'palaco.distribution.v1',
  appId: 'palaco.one',
  version: '0.1.0',
  artifact: 'palaco-one.zip',
  sha256: 'a'.repeat(64),
  sizeBytes: 1024,
  channel: 'draft',
  authorization: 'DENY',
  go13: 'HOLD'
});

test('valid draft metadata is read-only and never authorizes publication', () => {
  const outcome = assessDistributionManifest(sample());
  assert.equal(outcome.readiness, 'MANIFEST_VALID');
  assert.equal(outcome.authorization, 'DENY');
  assert.equal(outcome.mayPublish, false);
  assert.equal(outcome.mayInstall, false);
  assert.equal(Object.isFrozen(outcome), true);
});

test('invalid, absent, and array inputs fail closed', () => {
  for (const value of [null, undefined, [], 'x']) {
    assert.equal(assessDistributionManifest(value).readiness, 'BLOCKED');
  }
});

test('paths and URL-like artifact names are rejected', () => {
  for (const artifact of ['../payload.zip', '/tmp/file.zip', 'https://host/app.zip', 'dir\\file.zip']) {
    assert.ok(assessDistributionManifest({ ...sample(), artifact }).findings.includes('INVALID_ARTIFACT'));
  }
});

test('release or authorization escalation is rejected', () => {
  for (const change of [
    { channel: 'production' }, { authorization: 'ALLOW' }, { go13: 'GO' }
  ]) {
    const outcome = assessDistributionManifest({ ...sample(), ...change });
    assert.equal(outcome.readiness, 'BLOCKED');
    assert.equal(outcome.authorization, 'DENY');
    assert.equal(outcome.mayPublish, false);
  }
});

test('missing or malformed artifact integrity metadata is rejected', () => {
  for (const change of [
    { sha256: 'f'.repeat(63) }, { sizeBytes: 0 }, { version: 'latest' }, { appId: '../escape' }
  ]) {
    assert.equal(assessDistributionManifest({ ...sample(), ...change }).readiness, 'BLOCKED');
  }
});
