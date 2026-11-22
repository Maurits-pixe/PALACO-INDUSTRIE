'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const { DatabaseSync }=require('node:sqlite');
const { mkdtempSync,rmSync }=require('node:fs');
const { tmpdir }=require('node:os');
const { join }=require('node:path');
const { generateKeyPairSync,sign }=require('node:crypto');
const { authorityReceiptPayload }=require('../distribution/authority-receipt');
const { initializeDurableChallengeSchema,createDurableChallengeRegistry }=require('../distribution/durable-challenge-registry');
const keys=generateKeyPairSync('ed25519');
const roots=[{keyId:'test-root',enabled:true,revoked:false,publicKeyPem:keys.publicKey.export({type:'spki',format:'pem'})}];
function proof(challenge) {
 const state={schemaVersion:'palaco.distribution.authority-state.v1',namespace:'palaco.one',sequence:7,digest:'a'.repeat(64),challenge};
 return {state,endorsement:{algorithm:'Ed25519',keyId:'test-root',signature:sign(null,authorityReceiptPayload(state),keys.privateKey).toString('base64')}};
}
function fixture(t) {
 const dir=mkdtempSync(join(tmpdir(),'palaco-durable-'));const path=join(dir,'registry.sqlite');const opened=[];
 t.after(()=>{for(const db of opened){try{db.close();}catch(_){}}rmSync(dir,{recursive:true,force:true});});
 return {open(){const db=new DatabaseSync(path);initializeDurableChallengeSchema(db);opened.push(db);return db;}};
}
const consume=(r,token,minimum=7)=>{const {state,endorsement}=proof(token);return r.consume('palaco.one',token,state,endorsement,roots,minimum);};
test('valid response is diagnostic only and cannot replay',t=>{
 const r=createDurableChallengeRegistry(fixture(t).open()),challenge=r.issue('palaco.one').challenge;
 assert.match(challenge,/^[a-f0-9]{64}$/);
 const result=consume(r,challenge);
 assert.equal(result.readiness,'AUTHORITY_RECEIPT_VALID');
 assert.equal(result.authorization,'DENY');assert.equal(result.mayPublish,false);
 assert.equal(consume(r,challenge).readiness,'BLOCKED');
});
test('pending challenge survives closing and reopening the database',t=>{
 const f=fixture(t),a=f.open(),token=createDurableChallengeRegistry(a).issue('palaco.one').challenge;
 a.close();const b=f.open();
 assert.equal(consume(createDurableChallengeRegistry(b),token).readiness,'AUTHORITY_RECEIPT_VALID');
});
test('consumed challenge is still rejected after restart',t=>{
 const f=fixture(t),a=f.open(),r=createDurableChallengeRegistry(a),token=r.issue('palaco.one').challenge;
 consume(r,token);a.close();
 assert.equal(consume(createDurableChallengeRegistry(f.open()),token).readiness,'BLOCKED');
});
test('invalid proof burns challenge',t=>{
 const r=createDurableChallengeRegistry(fixture(t).open()),token=r.issue('palaco.one').challenge;
 assert.equal(consume(r,token,8).readiness,'BLOCKED');
 assert.equal(consume(r,token).readiness,'BLOCKED');
});
test('namespace mismatch consumes token',t=>{
 const r=createDurableChallengeRegistry(fixture(t).open()),token=r.issue('palaco.one').challenge,{state,endorsement}=proof(token);
 assert.equal(r.consume('another.ns',token,state,endorsement,roots,7).readiness,'BLOCKED');
 assert.equal(consume(r,token).readiness,'BLOCKED');
});
test('expired token cannot validate later',t=>{
 let now=1000;
 const r=createDurableChallengeRegistry(fixture(t).open(),{ttlMs:10,clock:()=>now}),token=r.issue('palaco.one').challenge;
 now=1010;assert.ok(consume(r,token).findings.includes('CHALLENGE_EXPIRED'));
 assert.equal(consume(r,token).readiness,'BLOCKED');
});
test('wall clock rollback blocks without consuming challenge',t=>{
 let now=100;
 const r=createDurableChallengeRegistry(fixture(t).open(),{clock:()=>now}),token=r.issue('palaco.one').challenge;
 now=99;assert.ok(consume(r,token).findings.includes('CHALLENGE_STORAGE_UNAVAILABLE'));
 now=101;assert.equal(consume(r,token).readiness,'AUTHORITY_RECEIPT_VALID');
});
test('bounded capacity across SQLite connections',t=>{
 const f=fixture(t),r1=createDurableChallengeRegistry(f.open(),{maxPending:1}),r2=createDurableChallengeRegistry(f.open(),{maxPending:1});
 const token=r1.issue('palaco.one').challenge;
 assert.equal(r2.issue('palaco.one').reason,'CHALLENGE_CAPACITY_REACHED');
 assert.equal(consume(r2,token).readiness,'AUTHORITY_RECEIPT_VALID');
});
test('closed storage and invalid namespace fail closed',t=>{
 const db=fixture(t).open(),r=createDurableChallengeRegistry(db);
 assert.equal(r.issue('../bad').issued,false);
 db.close();assert.equal(r.issue('palaco.one').issued,false);
 assert.equal(r.consume('palaco.one','a'.repeat(64),null,null,null,0).readiness,'BLOCKED');
});
