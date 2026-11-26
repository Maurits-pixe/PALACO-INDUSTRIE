'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { DatabaseSync } = require('node:sqlite');
const { generateKeyPairSync, sign } = require('node:crypto');
const { initializeDurableChallengeSchema, createDurableChallengeRegistry } =
  require('../distribution/durable-challenge-registry');
const { createSignedAuditedChallengeRegistry } =
  require('../distribution/signed-audited-challenge-registry');
const { clockFloorPayload } = require('../distribution/signed-clock-floor');
const { authorityReceiptPayload } = require('../distribution/authority-receipt');

const floorKeys = generateKeyPairSync('ed25519');
const receiptKeys = generateKeyPairSync('ed25519');
const floorRoots = [{ keyId:'clock-root',enabled:true,revoked:false,
  publicKeyPem:floorKeys.publicKey.export({format:'pem',type:'spki'}) }];
const receiptRoots = [{ keyId:'receipt-root',enabled:true,revoked:false,
  publicKeyPem:receiptKeys.publicKey.export({format:'pem',type:'spki'}) }];

function fixture() {
  const db = new DatabaseSync(':memory:');
  initializeDurableChallengeSchema(db);
  let now = 1000;
  const clock = () => now;
  const bootstrap = createDurableChallengeRegistry(db, { clock });
  assert.equal(bootstrap.issue('palaco.one').issued, true);
  return {db,clock,setTime:value=>{now=value;}};
}
function authority({epoch=5,minimumLastSeenMs=1000,modify=proof=>proof}={}) {
  return {
    namespace:'palaco.registry', pinnedRoots:floorRoots, minimumEpoch:5,
    fetchSignedFloor:challenge=>{
      const floor={schemaVersion:'palaco.distribution.signed-clock-floor.v1',
        namespace:'palaco.registry',epoch,minimumLastSeenMs,challenge};
      const endorsement={algorithm:'Ed25519',keyId:'clock-root',
        signature:sign(null,clockFloorPayload(floor),floorKeys.privateKey).toString('base64')};
      return modify({floor,endorsement});
    }
  };
}
function make(f,config=authority()) {
  return createSignedAuditedChallengeRegistry(f.db,{
    floorAuthority:config,clock:f.clock
  });
}
function proof(challenge) {
 const state={schemaVersion:'palaco.distribution.authority-state.v1',
   namespace:'palaco.one',sequence:8,digest:'a'.repeat(64),challenge};
 const endorsement={algorithm:'Ed25519',keyId:'receipt-root',
   signature:sign(null,authorityReceiptPayload(state),receiptKeys.privateKey).toString('base64')};
 return {state,endorsement};
}
test('valid signed floor allows issue but never grants a release',()=>{
 const f=fixture();try{
  const r=make(f),token=r.issue('palaco.one');
  assert.equal(token.issued,true);
  const {state,endorsement}=proof(token.challenge);
  const result=r.consume('palaco.one',token.challenge,state,endorsement,receiptRoots,8);
  assert.equal(result.readiness,'AUTHORITY_RECEIPT_VALID');
  assert.equal(result.authorization,'DENY');
  assert.equal(result.mayPublish,false);
  assert.equal(r.consume('palaco.one',token.challenge,state,endorsement,receiptRoots,8).readiness,'BLOCKED');
 }finally{f.db.close();}
});
test('unsigned and malformed floors block without mutating clock',()=>{
 const f=fixture();try{
  f.setTime(2000);
  const r=make(f,authority({modify:({floor})=>({floor,endorsement:null})}));
  assert.equal(r.issue('palaco.one').issued,false);
  assert.equal(f.db.prepare('SELECT last_seen_ms FROM distribution_challenge_clock').get().last_seen_ms,1000);
 }finally{f.db.close();}
});
test('stale floor epoch blocks the transaction',()=>{
 const f=fixture();try{
  const r=make(f,authority({epoch:4}));
  assert.equal(r.issue('palaco.one').issued,false);
 }finally{f.db.close();}
});
test('restored database clock lower than a signed floor is rejected',()=>{
 const f=fixture();try{
  f.setTime(2000);
  const r=make(f,authority({minimumLastSeenMs:1500}));
  assert.equal(r.issue('palaco.one').issued,false);
  assert.equal(f.db.prepare('SELECT last_seen_ms FROM distribution_challenge_clock').get().last_seen_ms,1000);
 }finally{f.db.close();}
});
test('replayed signed floor cannot bypass fresh challenge',()=>{
 const f=fixture();try{
  let cached;
  const config=authority({modify:proof=>cached??=proof});
  const r=make(f,config);
  assert.equal(r.issue('palaco.one').issued,true);
  assert.equal(r.issue('palaco.one').issued,false);
 }finally{f.db.close();}
});
test('untrusted root and absent floor service fail closed',()=>{
 const f=fixture();try{
  assert.throws(()=>make(f,{namespace:'palaco.registry',minimumEpoch:5,pinnedRoots:[]}),TypeError);
  const config=authority();
  config.pinnedRoots=[{...floorRoots[0],revoked:true}];
  assert.equal(make(f,config).issue('palaco.one').issued,false);
 }finally{f.db.close();}
});
test('corrupt registry metadata blocks even a correctly signed clock floor',()=>{
 const f=fixture();try{
  f.db.exec("UPDATE distribution_challenges SET namespace='***'");
  assert.equal(make(f).issue('palaco.one').issued,false);
 }finally{f.db.close();}
});
test('signed floor failure on consume does not mark token consumed',()=>{
 const f=fixture();try{
  const r=make(f),token=r.issue('palaco.one').challenge;
  const broken=make(f,authority({minimumLastSeenMs:2000}));
  const {state,endorsement}=proof(token);
  assert.equal(broken.consume('palaco.one',token,state,endorsement,receiptRoots,8).readiness,'BLOCKED');
  assert.equal(f.db.prepare('SELECT status FROM distribution_challenges WHERE status=?').get('pending').status,'pending');
  assert.equal(r.consume('palaco.one',token,state,endorsement,receiptRoots,8).readiness,'AUTHORITY_RECEIPT_VALID');
 }finally{f.db.close();}
});
