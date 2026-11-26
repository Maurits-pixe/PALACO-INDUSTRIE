'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync, sign } = require('node:crypto');
const { clockFloorPayload, verifySignedClockFloor, createSignedClockFloorProvider } =
  require('../distribution/signed-clock-floor');
const rootKey = generateKeyPairSync('ed25519');
const challenge = 'c'.repeat(64);
const roots = [{keyId:'floor-root',enabled:true,revoked:false,
  publicKeyPem:rootKey.publicKey.export({type:'spki',format:'pem'})}];
const floor = (nonce=challenge) => ({schemaVersion:'palaco.distribution.signed-clock-floor.v1',
  namespace:'palaco.registry',epoch:8,minimumLastSeenMs:1700,challenge:nonce});
const signed = f => ({algorithm:'Ed25519',keyId:'floor-root',
  signature:sign(null,clockFloorPayload(f),rootKey.privateKey).toString('base64')});
const check=(f=floor(),e=signed(floor()),r=roots,c=challenge,epoch=8)=>
  verifySignedClockFloor('palaco.registry',f,e,r,c,epoch);

test('independently signed floor supplies bound but grants no rights',()=>{
 const result=check();
 assert.equal(result.readiness,'SIGNED_CLOCK_FLOOR_MATCH');
 assert.equal(result.minimumLastSeenMs,1700);
 assert.equal(result.authorization,'DENY');assert.equal(result.go13,'HOLD');
 assert.equal(result.mayInstall,false);assert.equal(result.mayPublish,false);
});
test('missing or malformed proof blocks',()=>{
 assert.equal(check(null).readiness,'BLOCKED');
 assert.equal(check(floor(),null).readiness,'BLOCKED');
 assert.equal(check({...floor(),minimumLastSeenMs:-1}).readiness,'BLOCKED');
});
test('old signed proof cannot satisfy a new challenge',()=>{
 assert.ok(check(floor(),signed(floor()),roots,'d'.repeat(64)).findings.includes('CLOCK_FLOOR_CHALLENGE_MISMATCH'));
});
test('minimum independently held epoch blocks earlier state',()=>{
 assert.ok(check(floor(),signed(floor()),roots,challenge,9).findings.includes('CLOCK_FLOOR_EPOCH_ROLLBACK'));
 assert.ok(check(floor(),signed(floor()),roots,challenge,null).findings.includes('INDEPENDENT_EPOCH_UNAVAILABLE'));
});
test('tampered clock, epoch or namespace cannot reuse signature',()=>{
 for (const patch of [{epoch:9},{minimumLastSeenMs:1701},{namespace:'other.registry'}])
  assert.equal(check({...floor(),...patch}).readiness,'BLOCKED');
});
test('revoked, disabled and duplicate roots block',()=>{
 for(const r of [[{...roots[0],revoked:true}],[{...roots[0],enabled:false}],[...roots,...roots]])
  assert.equal(check(floor(),signed(floor()),r).readiness,'BLOCKED');
});
test('different signer cannot forge independent floor',()=>{
 const outsider=generateKeyPairSync('ed25519');
 const forged={...signed(floor()),signature:sign(null,clockFloorPayload(floor()),outsider.privateKey).toString('base64')};
 assert.equal(check(floor(),forged).readiness,'BLOCKED');
});
test('provider produces a fresh challenge on every call and verifies it',()=>{
 const observed=[];
 const provider=createSignedClockFloorProvider({pinnedRoots:roots,minimumEpoch:8,
   fetchSignedFloor: nonce => {observed.push(nonce);const f=floor(nonce);return {floor:f,endorsement:signed(f)};}});
 assert.equal(provider(),1700);assert.equal(provider(),1700);
 assert.match(observed[0],/^[a-f0-9]{64}$/);assert.notEqual(observed[0],observed[1]);
});
test('provider fails closed when signer replays a prior response',()=>{
 let cached;
 const provider=createSignedClockFloorProvider({pinnedRoots:roots,minimumEpoch:8,
  fetchSignedFloor: nonce => cached ??= {floor:floor(nonce),endorsement:signed(floor(nonce))}});
 assert.equal(provider(),1700);
 assert.throws(()=>provider(),/SIGNED_CLOCK_FLOOR_REJECTED/);
});
test('provider cannot run with missing trust configuration',()=>{
 assert.throws(()=>createSignedClockFloorProvider({fetchSignedFloor:()=>null}),TypeError);
});
