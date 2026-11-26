'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync, sign } = require('node:crypto');
const { createAuthorityChallengeSession } = require('../distribution/authority-challenge-session');
const { authorityReceiptPayload } = require('../distribution/authority-receipt');

const keys = generateKeyPairSync('ed25519');
const roots = [{keyId:'authority-root',enabled:true,revoked:false,
  publicKeyPem:keys.publicKey.export({format:'pem',type:'spki'})}];
const stateFor = challenge => ({schemaVersion:'palaco.distribution.authority-state.v1',
  namespace:'palaco.one',sequence:42,digest:'a'.repeat(64),challenge});
const signature = state => ({algorithm:'Ed25519',keyId:'authority-root',
  signature:sign(null,authorityReceiptPayload(state),keys.privateKey).toString('base64')});
const issue = session => { const v=session.issue('palaco.one'); assert.equal(v.issued,true); return v.challenge; };
const consume = (s, challenge, state=stateFor(challenge), endorsement=signature(state), floor=42) =>
  s.consume('palaco.one',challenge,state,endorsement,roots,floor);

test('fresh challenge validates signed response without allowing execution', () => {
  const s=createAuthorityChallengeSession();
  const c=issue(s);
  assert.match(c,/^[a-f0-9]{64}$/);
  const r=consume(s,c);
  assert.equal(r.readiness,'AUTHORITY_RECEIPT_VALID');
  assert.equal(r.authorization,'DENY');
  assert.equal(r.mayPublish,false);
  s.close();
});
test('a verified response cannot be replayed', () => {
  const s=createAuthorityChallengeSession(); const c=issue(s);
  assert.equal(consume(s,c).readiness,'AUTHORITY_RECEIPT_VALID');
  assert.equal(consume(s,c).readiness,'BLOCKED'); s.close();
});
test('failed proof burns token and cannot be retried', () => {
  const s=createAuthorityChallengeSession(); const c=issue(s);
  assert.equal(consume(s,c,stateFor(c),{...signature(stateFor(c)),signature:'bad'}).readiness,'BLOCKED');
  assert.equal(consume(s,c).readiness,'BLOCKED'); s.close();
});
test('challenge is namespace scoped and mismatch burns it', () => {
  const s=createAuthorityChallengeSession(); const c=issue(s); const state=stateFor(c);
  assert.equal(s.consume('other.ns',c,state,signature(state),roots,42).readiness,'BLOCKED');
  assert.equal(consume(s,c).readiness,'BLOCKED'); s.close();
});
test('capacity limit fails closed without discarding an active token', () => {
  const s=createAuthorityChallengeSession({maxPending:1}); const c=issue(s);
  assert.equal(s.issue('palaco.one').reason,'CHALLENGE_CAPACITY_REACHED');
  assert.equal(consume(s,c).readiness,'AUTHORITY_RECEIPT_VALID'); s.close();
});
test('independently issued challenges are unique', () => {
  const s=createAuthorityChallengeSession(); const a=issue(s), b=issue(s);
  assert.notEqual(a,b); s.close();
});
test('missing trusted minimum blocks and consumes token', () => {
  const s=createAuthorityChallengeSession();const c=issue(s);
  assert.equal(consume(s,c,stateFor(c),signature(stateFor(c)),null).readiness,'BLOCKED');
  assert.equal(consume(s,c).readiness,'BLOCKED'); s.close();
});
test('close clears outstanding challenges and invalid configuration throws', () => {
  const s=createAuthorityChallengeSession(); const c=issue(s); s.close();
  assert.equal(consume(s,c).readiness,'BLOCKED');
  assert.throws(()=>createAuthorityChallengeSession({ttlMs:0}),RangeError);
  assert.throws(()=>createAuthorityChallengeSession({maxPending:0}),RangeError);
});
