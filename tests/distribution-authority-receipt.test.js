'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync, sign } = require('node:crypto');
const { authorityReceiptPayload, verifyAuthorityReceipt, assessAuthenticatedRecovery } = require('../distribution/authority-receipt');
const kp = generateKeyPairSync('ed25519');
const challenge = 'a'.repeat(32);
const state = () => ({ schemaVersion:'palaco.distribution.authority-state.v1', namespace:'palaco.one', sequence:10, digest:'b'.repeat(64), challenge });
const roots = () => [{keyId:'independent-authority',enabled:true,revoked:false,publicKeyPem:kp.publicKey.export({type:'spki',format:'pem'})}];
const endorsement = s => ({algorithm:'Ed25519',keyId:'independent-authority',signature:sign(null,authorityReceiptPayload(s),kp.privateKey).toString('base64')});
const evaluate = (s=state(), e=endorsement(state()),r=roots(),ch=challenge,floor=10) => verifyAuthorityReceipt('palaco.one',s,e,r,ch,floor);
test('verified receipt never grants permissions', () => {
 const r=evaluate(); assert.equal(r.readiness,'AUTHORITY_RECEIPT_VALID'); assert.equal(r.authorization,'DENY');
 assert.equal(r.go13,'HOLD'); assert.equal(r.mayRestore,false); assert.equal(r.mayPublish,false); assert.ok(Object.isFrozen(r.findings));
});
test('replayed response with new verifier challenge is denied', () => {
 assert.ok(evaluate(state(),endorsement(state()),roots(),'c'.repeat(32)).findings.includes('CHALLENGE_MISMATCH'));
});
test('authority state below independent floor is rejected', () => {
 assert.ok(evaluate(state(),endorsement(state()),roots(),challenge,11).findings.includes('AUTHORITY_STATE_BELOW_FLOOR'));
});
test('unavailable floor blocks despite valid signature', () => {
 assert.ok(evaluate(state(),endorsement(state()),roots(),challenge,null).findings.includes('TRUSTED_FLOOR_UNAVAILABLE'));
});
test('tampering sequence, digest and namespace blocks signature reuse', () => {
 for(const change of [{sequence:11},{digest:'c'.repeat(64)},{namespace:'other.ns'}]) assert.equal(evaluate({...state(),...change}).readiness,'BLOCKED');
});
test('missing, revoked and duplicate roots are rejected', () => {
 assert.equal(evaluate(state(),endorsement(state()),[]).readiness,'BLOCKED');
 assert.equal(evaluate(state(),endorsement(state()),[{...roots()[0],revoked:true}]).readiness,'BLOCKED');
 assert.equal(evaluate(state(),endorsement(state()),[...roots(),...roots()]).readiness,'BLOCKED');
});
test('foreign signer and malformed signature are rejected', () => {
 const other=generateKeyPairSync('ed25519'); const e=endorsement(state());
 assert.equal(evaluate(state(),{...e,signature:sign(null,authorityReceiptPayload(state()),other.privateKey).toString('base64')}).readiness,'BLOCKED');
 assert.equal(evaluate(state(),{...e,signature:'invalid'}).readiness,'BLOCKED');
});
test('authenticated recovery detects older, newer, and forked anchors', () => {
 const s=state(),e=endorsement(s),r=roots();
 const restored={namespace:'palaco.one',sequence:10,digest:'b'.repeat(64)};
 const check=a=>assessAuthenticatedRecovery('palaco.one',a,s,e,r,challenge,10);
 assert.equal(check(restored).readiness,'AUTHENTICATED_RECOVERY_MATCH');
 assert.equal(check({...restored,sequence:9}).readiness,'BLOCKED');
 assert.equal(check({...restored,sequence:11}).readiness,'BLOCKED');
 assert.equal(check({...restored,digest:'c'.repeat(64)}).readiness,'BLOCKED');
});
