'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {authorityDigest,authorityPayload,rotationPayload,
  verifyRosterAuthorityRotation}=require('../distribution/roster-authority-rotation');

const keys=[0,1,2,3,4].map(()=>generateKeyPairSync('ed25519'));
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
function fixture(){
 const previous={schemaVersion:'palaco.distribution.roster-authority.v1',
  namespace:'palaco.registry',revision:10,previousDigest:'0'.repeat(64),
  keys:[{keyId:'auth-a',status:'active',publicKeyPem:pem(keys[0])}]};
 const next={...previous,revision:11,previousDigest:authorityDigest(previous),keys:[
  {keyId:'auth-a',status:'revoked',publicKeyPem:pem(keys[0])},
  {keyId:'auth-z',status:'active',publicKeyPem:pem(keys[1])}
 ]};
 const record={schemaVersion:'palaco.distribution.roster-authority-rotation.v1',
  namespace:'palaco.registry',revision:11,previousDigest:authorityDigest(previous),
  nextDigest:authorityDigest(next),oldKeyId:'auth-a',newKeyId:'auth-z'};
 const approve=(key,keyId,body=record)=>({algorithm:'Ed25519',keyId,
  signature:sign(null,rotationPayload(body),key.privateKey).toString('base64')});
 const endorsements={oldAuthority:approve(keys[0],'auth-a'),
  newAuthority:approve(keys[1],'auth-z'),
  reviewers:[approve(keys[2],'review-a'),approve(keys[3],'review-b')]};
 const options={namespace:'palaco.registry',minimumRevision:10,
  previousDigest:authorityDigest(previous),pinnedReviewers:[
   {keyId:'review-a',reviewerId:'alice',enabled:true,revoked:false,publicKeyPem:pem(keys[2])},
   {keyId:'review-b',reviewerId:'bob',enabled:true,revoked:false,publicKeyPem:pem(keys[3])}
  ]};
 return {previous,next,record,endorsements,options,approve};
}
const check=f=>verifyRosterAuthorityRotation(f.previous,f.next,f.record,f.endorsements,f.options);
test('four independent Ed25519 signatures verify diagnostic-only rotation',()=>{
 const f=fixture(),r=check(f);
 assert.equal(r.readiness,'AUTHORITY_ROTATION_VERIFIED_NON_AUTHORIZING');
 assert.equal(r.digest,authorityDigest(f.next));
 assert.equal(r.proposedAuthority.keyId,'auth-z');
 assert.equal(r.authorization,'DENY');assert.equal(r.go13,'HOLD');
 assert.equal(r.mayRotate,false);assert.equal(r.mayPublish,false);
 assert.ok(Object.isFrozen(r));
});
test('old or new authority signature is mandatory',()=>{
 for(const who of ['oldAuthority','newAuthority']){
  const f=fixture();delete f.endorsements[who];
  assert.deepEqual(check(f).findings,['AUTHORITY_ROTATION_DUAL_SIGNATURE_INVALID']);
 }
});
test('reviewer signatures must be two distinct humans and keys',()=>{
 for(const mode of ['one','same-person','same-key']){
  const f=fixture();
  if(mode==='one')f.endorsements.reviewers.pop();
  if(mode==='same-person')f.options.pinnedReviewers[1].reviewerId='alice';
  if(mode==='same-key')f.options.pinnedReviewers[1].publicKeyPem=pem(keys[2]);
  assert.equal(check(f).readiness,'BLOCKED');
 }
});
test('reviewer may not reuse old or new authority private key',()=>{
 const f=fixture();
 f.options.pinnedReviewers[0].publicKeyPem=pem(keys[0]);
 f.endorsements.reviewers[0]=f.approve(keys[0],'review-a');
 assert.deepEqual(check(f).findings,['AUTHORITY_ROTATION_REVIEW_UNTRUSTED']);
});
test('revoked reviewer or duplicated pinned identity fails closed',()=>{
 for(const mode of ['revoked','duplicate']){
  const f=fixture();
  if(mode==='revoked')f.options.pinnedReviewers[0].revoked=true;
  else f.options.pinnedReviewers.push({...f.options.pinnedReviewers[0]});
  assert.deepEqual(check(f).findings,['AUTHORITY_ROTATION_REVIEW_UNTRUSTED']);
 }
});
test('previous active authority must be revoked; cannot retain two active roots',()=>{
 const f=fixture();
 f.next.keys[0].status='active';
 assert.equal(authorityPayload(f.next),null);
 assert.deepEqual(check(f).findings,['AUTHORITY_ROTATION_FORMAT_INVALID']);
});
test('old revoked key cannot be removed or silently substituted',()=>{
 const f=fixture();
 f.next.keys[0].publicKeyPem=pem(keys[4]);
 assert.deepEqual(check(f).findings,['AUTHORITY_ROTATION_CHAIN_MISMATCH']);
 const g=fixture();g.next.keys.shift();
 assert.deepEqual(check(g).findings,['AUTHORITY_ROTATION_CHAIN_MISMATCH']);
});
test('new key ID must not be reused from previous history',()=>{
 const f=fixture();
 f.next.keys=[{keyId:'auth-a',status:'active',publicKeyPem:pem(keys[1])}];
 assert.equal(check(f).readiness,'BLOCKED');
});
test('anchored revision and predecessor digest block rollback or skips',()=>{
 for(const mutate of [
  f=>{f.options.minimumRevision=9;},
  f=>{f.options.previousDigest='f'.repeat(64);},
  f=>{f.next.revision=12;},
  f=>{f.record.revision=12;}
 ]){const f=fixture();mutate(f);
  assert.equal(check(f).readiness,'BLOCKED');}
});
test('tampered rotation intent cannot reuse four valid signatures',()=>{
 const f=fixture();
 f.record.newKeyId='auth-q';
 assert.deepEqual(check(f).findings,['AUTHORITY_ROTATION_DUAL_SIGNATURE_INVALID']);
});
test('untrusted old anchor cannot be inferred from signed proposal',()=>{
 const f=fixture();delete f.options.previousDigest;
 assert.deepEqual(check(f).findings,['AUTHORITY_ANCHOR_UNAVAILABLE']);
});
test('malformed Ed25519 state, duplicate IDs and unsorted history are blocked',()=>{
 for(const changes of [
  f=>{f.next.keys[1].publicKeyPem='not a key';},
  f=>{f.next.keys[1].keyId='auth-a';},
  f=>{f.next.keys.reverse();}
 ]){const f=fixture();changes(f);
  assert.equal(authorityPayload(f.next),null);
  assert.deepEqual(check(f).findings,['AUTHORITY_ROTATION_FORMAT_INVALID']);}
});
