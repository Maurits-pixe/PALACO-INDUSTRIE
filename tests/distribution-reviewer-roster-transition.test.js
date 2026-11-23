'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {rosterPayload,rosterDigest,verifyReviewerRosterTransition}=
  require('../distribution/reviewer-roster-transition');

const trust=generateKeyPairSync('ed25519');
const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519'),
  generateKeyPairSync('ed25519')];
const pem=key=>key.publicKey.export({type:'spki',format:'pem'});
function sample(){
 const previous={
  schemaVersion:'palaco.distribution.reviewer-roster.v1',
  namespace:'palaco.registry',revision:9,previousDigest:'a'.repeat(64),
  reviewers:[
   {reviewerId:'alice',keyId:'k-alice',status:'active',publicKeyPem:pem(keys[0])},
   {reviewerId:'bob',keyId:'k-bob',status:'revoked',publicKeyPem:pem(keys[1])}
  ]
 };
 const next={
  ...previous,revision:10,previousDigest:rosterDigest(previous),
  reviewers:previous.reviewers.map(r=>({...r}))
 };
 const roots=[{keyId:'roster-root',enabled:true,revoked:false,publicKeyPem:pem(trust)}];
 const options={namespace:'palaco.registry',pinnedRoots:roots,
  minimumRevision:9,previousDigest:rosterDigest(previous)};
 const endorse=(value=next)=>({
  algorithm:'Ed25519',keyId:'roster-root',
  signature:sign(null,rosterPayload(value),trust.privateKey).toString('base64')
 });
 return {previous,next,roots,options,endorse};
}
function result(f){return verifyReviewerRosterTransition(f.previous,f.next,f.endorse(f.next),f.options);}
test('valid signed monotonic transition is evidence only and excludes revoked roots',()=>{
 const f=sample();const r=result(f);
 assert.equal(r.readiness,'ROSTER_TRANSITION_VERIFIED_NON_AUTHORIZING');
 assert.equal(r.authorization,'DENY');assert.equal(r.go13,'HOLD');
 assert.equal(r.mayPublish,false);assert.equal(r.revision,10);
 assert.equal(r.digest,rosterDigest(f.next));
 assert.deepEqual(r.reviewRoots.map(x=>x.reviewerId),['alice']);
 assert.ok(Object.isFrozen(r.reviewRoots));
});
test('a validly signed change cannot restore a revoked reviewer',()=>{
 const f=sample();f.next.reviewers[1].status='active';
 assert.deepEqual(result(f).findings,['ROSTER_REVOCATION_ROLLBACK']);
});
test('a validly signed transition cannot substitute an existing reviewer key',()=>{
 for(const change of [
  r=>{r.keyId='k-alice-new';},
  r=>{r.publicKeyPem=pem(keys[2]);}
 ]){const f=sample();change(f.next.reviewers[0]);
  assert.deepEqual(result(f).findings,['ROSTER_KEY_SUBSTITUTION']);}
});
test('an existing reviewer identity cannot disappear',()=>{
 const f=sample();f.next.reviewers.splice(1,1);
 // At least two reviewers is required structurally.
 assert.equal(result(f).readiness,'BLOCKED');
 const g=sample();g.next.reviewers.push({
  reviewerId:'charlie',keyId:'k-charlie',status:'active',publicKeyPem:pem(keys[2])});
 g.next.reviewers.splice(1,1);
 assert.deepEqual(result(g).findings,['ROSTER_IDENTITY_REMOVED']);
});
test('fresh reviewers are accepted only in sorted canonical order',()=>{
 const f=sample();f.next.reviewers.push({
  reviewerId:'charlie',keyId:'k-charlie',status:'active',publicKeyPem:pem(keys[2])});
 const r=result(f);
 assert.equal(r.readiness,'ROSTER_TRANSITION_VERIFIED_NON_AUTHORIZING');
 assert.deepEqual(r.reviewRoots.map(x=>x.reviewerId),['alice','charlie']);
 f.next.reviewers.reverse();
 assert.equal(rosterPayload(f.next),null);
 assert.deepEqual(result(f).findings,['ROSTER_FORMAT_INVALID']);
});
test('old revision, skipped revision or predecessor digest rollback denies',()=>{
 for(const change of [
  r=>{r.revision=9;},r=>{r.revision=11;},
  r=>{r.previousDigest='f'.repeat(64);}
 ]){const f=sample();change(f.next);
  assert.deepEqual(result(f).findings,['ROSTER_CHAIN_MISMATCH']);}
});
test('external independent anchor mismatch denies even a signed candidate',()=>{
 const f=sample();f.options.previousDigest='f'.repeat(64);
 assert.deepEqual(result(f).findings,['ROSTER_CHAIN_MISMATCH']);
 const g=sample();delete g.options.minimumRevision;
 assert.deepEqual(result(g).findings,['ROSTER_ANCHOR_UNAVAILABLE']);
});
test('mutating signed content after endorsement invalidates the signature',()=>{
 const f=sample();const signed=f.endorse();
 f.next.reviewers[0].status='revoked';
 assert.deepEqual(verifyReviewerRosterTransition(f.previous,f.next,signed,f.options).findings,
  ['ROSTER_SIGNATURE_INVALID']);
});
test('untrusted, revoked, duplicate or absent roster authority is denied',()=>{
 for(const mode of ['revoked','duplicate','absent','wrong-key']){
  const f=sample();
  if(mode==='revoked')f.roots[0].revoked=true;
  if(mode==='duplicate')f.roots.push({...f.roots[0]});
  if(mode==='absent')f.options.pinnedRoots=[];
  const endorsement=f.endorse();
  if(mode==='wrong-key'){
   endorsement.signature=sign(null,rosterPayload(f.next),keys[0].privateKey).toString('base64');
  }
  assert.deepEqual(verifyReviewerRosterTransition(f.previous,f.next,endorsement,f.options).findings,
   ['ROSTER_SIGNATURE_INVALID']);
 }
});
test('duplicated reviewer, key or invalid public key causes malformed registry',()=>{
 for(const mode of ['duplicate-reviewer','duplicate-key','wrong-key']){
  const f=sample();
  if(mode==='duplicate-reviewer')f.next.reviewers[1].reviewerId='alice';
  if(mode==='duplicate-key')f.next.reviewers[1].keyId='k-alice';
  if(mode==='wrong-key')f.next.reviewers[0].publicKeyPem='not-a-key';
  assert.equal(rosterPayload(f.next),null);
  assert.deepEqual(result(f).findings,['ROSTER_FORMAT_INVALID']);
 }
});
