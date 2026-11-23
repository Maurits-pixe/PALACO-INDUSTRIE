'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {rosterPayload,rosterDigest}=
  require('../distribution/reviewer-roster-transition');
const {dossierPayload,verifyRosterBoundBootstrapDossier}=
  require('../distribution/bootstrap-review-dossier');
const {createDistributionStartupInterlock}=
  require('../distribution/distribution-startup-interlock');

function fixture(){
 const alice=generateKeyPairSync('ed25519');
 const bob=generateKeyPairSync('ed25519');
 const authority=generateKeyPairSync('ed25519');
 const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
 const original={
  schemaVersion:'palaco.distribution.reviewer-roster.v1',
  namespace:'palaco.registry',revision:7,previousDigest:'0'.repeat(64),
  reviewers:[
   {reviewerId:'alice',keyId:'key-a',status:'active',publicKeyPem:pem(alice)},
   {reviewerId:'bob',keyId:'key-b',status:'active',publicKeyPem:pem(bob)}
  ]
 };
 const next={...original,revision:8,previousDigest:rosterDigest(original),
  reviewers:original.reviewers.map(r=>({...r}))};
 const endorsement={algorithm:'Ed25519',keyId:'registry-root',
  signature:sign(null,rosterPayload(next),authority.privateKey).toString('base64')};
 const anchor={namespace:'palaco.registry',minimumRevision:7,
  previousDigest:rosterDigest(original),
  pinnedRoots:[{keyId:'registry-root',enabled:true,revoked:false,
    publicKeyPem:pem(authority)}]};
 const dossier={
  schemaVersion:'palaco.distribution.bootstrap-dossier.v1',
  namespace:'palaco.registry',sequence:16,
  issuedAtMs:1000,expiresAtMs:6000,
  sourceDigest:'a'.repeat(64),checkpointDigest:'b'.repeat(64),
  anchorDigest:'c'.repeat(64),postgresSchemaDigest:'d'.repeat(64),
  pinnedRootsDigest:rosterDigest(next),authorization:'DENY',go13:'HOLD'
 };
 const endorsements=[
  {algorithm:'Ed25519',keyId:'key-a',
   signature:sign(null,dossierPayload(dossier),alice.privateKey).toString('base64')},
  {algorithm:'Ed25519',keyId:'key-b',
   signature:sign(null,dossierPayload(dossier),bob.privateKey).toString('base64')}
 ];
 const policy={namespace:'palaco.registry',minimumSequence:16,nowMs:3000,
  // Deliberately malicious unverified roots: strict variant must ignore these.
  pinnedReviewRoots:[{keyId:'fake',reviewerId:'fake',enabled:true,revoked:false,
    publicKeyPem:pem(authority)}]
 };
 const rosterEvidence={previous:original,next,endorsement,anchor};
 return {dossier,endorsements,policy,rosterEvidence,alice,bob,authority};
}
const verify=f=>verifyRosterBoundBootstrapDossier(
 f.dossier,f.endorsements,f.policy,f.rosterEvidence);
test('roster-bound bootstrap verifies signer lineage but never release authority',()=>{
 const f=fixture();const v=verify(f);
 assert.deepEqual(v.findings,['BOOTSTRAP_EVIDENCE_VERIFIED_NO_RELEASE_AUTHORITY']);
 assert.equal(v.authorization,'DENY');assert.equal(v.go13,'HOLD');
 const startup=createDistributionStartupInterlock({},{
  dossier:f.dossier,endorsements:f.endorsements,
  reviewPolicy:f.policy,rosterEvidence:f.rosterEvidence});
 assert.equal(startup.report.evidenceStatus,'VERIFIED_NON_AUTHORIZING');
 assert.equal(startup.report.ingressEnabled,false);
 assert.equal(startup.ingress,null);
});
test('missing provenance roster must not silently use caller-provided roots',()=>{
 const f=fixture();
 assert.deepEqual(verifyRosterBoundBootstrapDossier(
  f.dossier,f.endorsements,f.policy,null).findings,
  ['BOOTSTRAP_ROSTER_EVIDENCE_MISSING']);
});
test('reviewer identity removal, key rotation and revoked resurrection block dossier',()=>{
 for(const mode of ['removed','key-change','resurrection']){
  const f=fixture(), next=f.rosterEvidence.next;
  if(mode==='removed'){
   next.reviewers.splice(1,1);
  }else if(mode==='key-change'){
   next.reviewers[1].keyId='replacement';
  }else{
   f.rosterEvidence.previous.reviewers[1].status='revoked';
   f.rosterEvidence.anchor.previousDigest=rosterDigest(f.rosterEvidence.previous);
   next.previousDigest=rosterDigest(f.rosterEvidence.previous);
  }
  // A malicious signed roster that violates continuity must still fail.
  if(rosterPayload(next)){
   f.rosterEvidence.endorsement.signature=sign(null,rosterPayload(next),
    f.authority.privateKey).toString('base64');
  }
  assert.deepEqual(verify(f).findings,['BOOTSTRAP_ROSTER_TRANSITION_REJECTED']);
 }
});
test('bootstrapping with wrong signed roster digest fails independently of signature',()=>{
 const f=fixture();
 f.dossier.pinnedRootsDigest='f'.repeat(64);
 assert.deepEqual(verify(f).findings,['BOOTSTRAP_ROSTER_DIGEST_MISMATCH']);
});
test('revoked roster authority or stale independent anchor blocks bootstrap',()=>{
 for(const mode of ['authority-revoked','stale-anchor','signature-tamper']){
  const f=fixture();
  if(mode==='authority-revoked')f.rosterEvidence.anchor.pinnedRoots[0].revoked=true;
  if(mode==='stale-anchor')f.rosterEvidence.anchor.minimumRevision=6;
  if(mode==='signature-tamper')f.rosterEvidence.endorsement.signature='A'.repeat(86)+'==';
  assert.deepEqual(verify(f).findings,['BOOTSTRAP_ROSTER_TRANSITION_REJECTED']);
  const state=createDistributionStartupInterlock({},{
   dossier:f.dossier,endorsements:f.endorsements,reviewPolicy:f.policy,
   rosterEvidence:f.rosterEvidence});
  assert.equal(state.ingress,null);
  assert.equal(state.report.authorization,'DENY');
  assert.equal(state.report.go13,'HOLD');
 }
});
test('a revoked reviewer is excluded from the quorum even with a historical signature',()=>{
 const f=fixture();
 f.rosterEvidence.next.reviewers[1].status='revoked';
 f.rosterEvidence.endorsement.signature=sign(null,
  rosterPayload(f.rosterEvidence.next),f.authority.privateKey).toString('base64');
 f.dossier.pinnedRootsDigest=rosterDigest(f.rosterEvidence.next);
 f.endorsements=[
  {algorithm:'Ed25519',keyId:'key-a',
    signature:sign(null,dossierPayload(f.dossier),f.alice.privateKey).toString('base64')},
  {algorithm:'Ed25519',keyId:'key-b',
    signature:sign(null,dossierPayload(f.dossier),f.bob.privateKey).toString('base64')}
 ];
 assert.deepEqual(verify(f).findings,['BOOTSTRAP_REVIEW_QUORUM_MISSING']);
});
test('scope mismatch cannot reuse signed roster in another namespace',()=>{
 const f=fixture();f.policy.namespace='other.registry';
 assert.deepEqual(verify(f).findings,['BOOTSTRAP_ROSTER_SCOPE_MISMATCH']);
});
