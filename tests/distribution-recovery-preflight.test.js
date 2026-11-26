'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync, sign } = require('node:crypto');
const { witnessPayload, assessRecoveryPreflight } = require('../distribution/recovery-preflight');
const pair = generateKeyPairSync('ed25519');
const roots = [{keyId:'independent-recovery', enabled:true, revoked:false,
  publicKeyPem:pair.publicKey.export({type:'spki',format:'pem'})}];
const witness = {schemaVersion:'palaco.distribution.recovery-witness.v1',
  namespace:'palaco.one', sequence:8, digest:'a'.repeat(64)};
const anchor = {sequence:8, digest:'a'.repeat(64)};
const endorsement = w => ({algorithm:'Ed25519', keyId:'independent-recovery',
  signature:sign(null,witnessPayload(w),pair.privateKey).toString('base64')});
const check = (a=anchor,w=witness,e=endorsement(witness),r=roots,namespace='palaco.one') =>
  assessRecoveryPreflight(namespace,a,w,e,r);

test('matching independently signed recovery witness is read-only', () => {
 const r=check();
 assert.equal(r.readiness,'RECOVERY_WITNESS_MATCH');
 assert.equal(r.authorization,'DENY');
 assert.equal(r.go13,'HOLD');
 assert.equal(r.mayRestore,false);
 assert.equal(r.mayPublish,false);
 assert.ok(Object.isFrozen(r.findings));
});
test('older restored state is rejected', () => {
 assert.ok(check({...anchor,sequence:7}).findings.includes('RESTORED_ANCHOR_ROLLBACK'));
});
test('newer state needs a fresh witness', () => {
 assert.ok(check({...anchor,sequence:9}).findings.includes('WITNESS_BEHIND_ANCHOR'));
});
test('equal sequences with mismatched digests are rejected', () => {
 assert.ok(check({...anchor,digest:'b'.repeat(64)}).findings.includes('RECOVERY_DIGEST_MISMATCH'));
});
test('missing independent witness or root is blocked', () => {
 assert.equal(check(anchor,witness,null).readiness,'BLOCKED');
 assert.equal(check(anchor,witness,endorsement(witness),[]).readiness,'BLOCKED');
 assert.equal(check(null).readiness,'BLOCKED');
});
test('tampering with signed witness is detected', () => {
 assert.equal(check(anchor,{...witness,sequence:9},endorsement(witness)).readiness,'BLOCKED');
 assert.equal(check(anchor,{...witness,namespace:'other.space'},endorsement(witness)).readiness,'BLOCKED');
});
test('revoked and duplicated roots are blocked', () => {
 assert.equal(check(anchor,witness,endorsement(witness),[{...roots[0],revoked:true}]).readiness,'BLOCKED');
 assert.equal(check(anchor,witness,endorsement(witness),[...roots,...roots]).readiness,'BLOCKED');
});
test('foreign signing key cannot attest recovery', () => {
 const attacker=generateKeyPairSync('ed25519');
 const e={...endorsement(witness),signature:sign(null,witnessPayload(witness),attacker.privateKey).toString('base64')};
 assert.equal(check(anchor,witness,e).readiness,'BLOCKED');
});
