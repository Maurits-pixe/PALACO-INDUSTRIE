'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync, sign } = require('node:crypto');
const { floorPayload, assessRecoveryFloor } = require('../distribution/recovery-floor');
const pair = generateKeyPairSync('ed25519');
const root = { keyId: 'recovery-floor-root', enabled: true, revoked: false,
  publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }) };
const floor = { schemaVersion: 'palaco.distribution.recovery-floor.v1',
  namespace: 'palaco.one', sequence: 25, digest: 'a'.repeat(64) };
const anchor = { sequence: 25, digest: 'a'.repeat(64) };
const endorsement = f => ({ algorithm: 'Ed25519', keyId: root.keyId,
  signature: sign(null, floorPayload(f), pair.privateKey).toString('base64') });
const evaluate = (a=anchor, f=floor, e=endorsement(floor), roots=[root], name='palaco.one') =>
  assessRecoveryFloor(name, a, f, e, roots);

test('matching signed floor is diagnostic only', () => {
  const r = evaluate();
  assert.equal(r.readiness, 'FLOOR_MATCH');
  assert.equal(r.authorization, 'DENY');
  assert.equal(r.go13, 'HOLD');
  assert.equal(r.mayRestore, false);
  assert.equal(r.mayPublish, false);
  assert.ok(Object.isFrozen(r));
});
test('restored version below independent floor is blocked', () => {
  assert.ok(evaluate({ ...anchor, sequence: 24 }).findings.includes('RECOVERY_BELOW_TRUSTED_FLOOR'));
});
test('stale floor cannot validate a newer restored state', () => {
  assert.ok(evaluate({ ...anchor, sequence: 26 }).findings.includes('FLOOR_STALE'));
});
test('same sequence with conflicting digest is blocked', () => {
  assert.ok(evaluate({ ...anchor, digest: 'b'.repeat(64) }).findings.includes('FLOOR_DIGEST_CONFLICT'));
});
test('missing signature or independent roots fail closed', () => {
  assert.equal(evaluate(anchor, floor, null).readiness, 'BLOCKED');
  assert.equal(evaluate(anchor, floor, endorsement(floor), []).readiness, 'BLOCKED');
});
test('tampered floor and namespace changes invalidate the proof', () => {
  assert.equal(evaluate(anchor, { ...floor, sequence: 24 }).readiness, 'BLOCKED');
  assert.equal(evaluate(anchor, floor, endorsement(floor), [root], 'another.space').readiness, 'BLOCKED');
});
test('revoked and duplicate roots are rejected', () => {
  assert.equal(evaluate(anchor, floor, endorsement(floor), [{ ...root, revoked: true }]).readiness, 'BLOCKED');
  assert.equal(evaluate(anchor, floor, endorsement(floor), [root, root]).readiness, 'BLOCKED');
});
test('invalid signatures, anchors and formats fail closed', () => {
  const wrong = generateKeyPairSync('ed25519');
  const fake = { ...endorsement(floor),
    signature: sign(null, floorPayload(floor), wrong.privateKey).toString('base64') };
  assert.equal(evaluate(anchor, floor, fake).readiness, 'BLOCKED');
  assert.equal(evaluate(null).readiness, 'BLOCKED');
  assert.equal(evaluate(anchor, { ...floor, digest: 'wrong' }).readiness, 'BLOCKED');
  assert.equal(evaluate(anchor, floor, endorsement(floor), [root], '../bad').readiness, 'BLOCKED');
});
