'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync, sign } = require('node:crypto');
const { checkpointSigningPayload } = require('../distribution/authenticated-checkpoint');
const { rotationPayload, assessRootRotation } = require('../distribution/root-rotation');

const former = generateKeyPairSync('ed25519');
const incoming = generateKeyPairSync('ed25519');
const root = (keyId, pair) => ({ keyId, enabled: true, revoked: false,
  publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }) });
const oldRoots = [root('old-root', former)];
const newRoots = [root('new-root', incoming)];
const checkpoint = { schemaVersion: 'palaco.distribution.checkpoint.v1',
  sequence: 6, previousDigest: 'a'.repeat(64), digest: 'b'.repeat(64) };
const proposal = { schemaVersion: 'palaco.distribution.root-rotation.v1',
  sequence: checkpoint.sequence, previousDigest: checkpoint.previousDigest,
  checkpointDigest: checkpoint.digest };
const signature = (keyId, pair, data) => ({
  algorithm: 'Ed25519', keyId,
  signature: sign(null, data, pair.privateKey).toString('base64')
});
const endorsement = signature('old-root', former, checkpointSigningPayload(checkpoint));
const approvals = p => [
  signature('old-root', former, p),
  signature('new-root', incoming, p)
];
const run = (options = {}) => {
  const p = options.proposal ?? proposal;
  const cp = options.checkpoint ?? checkpoint;
  const old = options.oldRoots ?? oldRoots;
  const next = options.newRoots ?? newRoots;
  const payload = rotationPayload(proposal, oldRoots, newRoots);
  const [a, b] = approvals(payload);
  return assessRootRotation(p, cp, old, next, options.checkpointEndorsement ?? endorsement,
    options.oldApproval ?? a, options.newApproval ?? b);
};

test('two independent signatures match without enabling rotation or release', () => {
  const r = run();
  assert.equal(r.readiness, 'DUAL_ROOT_PROOF_VALID');
  assert.equal(r.mayRotate, false);
  assert.equal(r.mayPublish, false);
  assert.equal(r.mayInstall, false);
  assert.equal(r.authorization, 'DENY');
  assert.equal(r.go13, 'HOLD');
});
test('missing either signature is denied', () => {
  assert.equal(run({ oldApproval: null }).readiness, 'BLOCKED');
  assert.equal(run({ newApproval: null }).readiness, 'BLOCKED');
  assert.equal(run({ checkpointEndorsement: null }).readiness, 'BLOCKED');
});
test('mismatched checkpoint or proposal cannot reuse approvals', () => {
  assert.equal(run({ checkpoint: { ...checkpoint, digest: 'c'.repeat(64) } }).readiness, 'BLOCKED');
  assert.equal(run({ proposal: { ...proposal, sequence: 7 } }).readiness, 'BLOCKED');
});
test('new root cannot be substituted without a new signature', () => {
  const attacker = generateKeyPairSync('ed25519');
  assert.equal(run({ newRoots: [root('new-root', attacker)] }).readiness, 'BLOCKED');
});
test('duplicate, disabled or revoked roots fail closed', () => {
  assert.equal(run({ oldRoots: [...oldRoots, ...oldRoots] }).readiness, 'BLOCKED');
  assert.equal(run({ newRoots: [{ ...newRoots[0], revoked: true }] }).readiness, 'BLOCKED');
  assert.equal(run({ oldRoots: [{ ...oldRoots[0], enabled: false }] }).readiness, 'BLOCKED');
});
test('reuse of root id and malformed proposals fail closed', () => {
  assert.equal(run({ newRoots: [root('old-root', incoming)] }).readiness, 'BLOCKED');
  assert.equal(run({ proposal: { ...proposal, previousDigest: 'bogus' } }).readiness, 'BLOCKED');
});
