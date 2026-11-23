'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {dossierPayload,verifyBootstrapDossier}=
  require('../distribution/bootstrap-review-dossier');

const reviewers=[
  {id:'review-a',person:'reviewer-a',key:generateKeyPairSync('ed25519')},
  {id:'review-b',person:'reviewer-b',key:generateKeyPairSync('ed25519')}
];
function context() {
 const dossier={
  schemaVersion:'palaco.distribution.bootstrap-dossier.v1',
  namespace:'palaco.registry',sequence:10,issuedAtMs:1000,expiresAtMs:5000,
  sourceDigest:'a'.repeat(64),checkpointDigest:'b'.repeat(64),
  anchorDigest:'c'.repeat(64),postgresSchemaDigest:'d'.repeat(64),
  pinnedRootsDigest:'e'.repeat(64),authorization:'DENY',go13:'HOLD'
 };
 const roots=reviewers.map(r=>({
  keyId:r.id,reviewerId:r.person,enabled:true,revoked:false,
  publicKeyPem:r.key.publicKey.export({type:'spki',format:'pem'})
 }));
 const signDossier=(d=dossier,who=reviewers)=>who.map(r=>({
  algorithm:'Ed25519',keyId:r.id,
  signature:sign(null,dossierPayload(d),r.key.privateKey).toString('base64')
 }));
 const options={namespace:'palaco.registry',pinnedReviewRoots:roots,
  minimumSequence:10,nowMs:2000};
 return {dossier,endorsements:signDossier(),options,signDossier};
}
test('valid two-reviewer signatures are evidence only, never authority',()=>{
 const f=context();
 const result=verifyBootstrapDossier(f.dossier,f.endorsements,f.options);
 assert.deepEqual(result.findings,['BOOTSTRAP_EVIDENCE_VERIFIED_NO_RELEASE_AUTHORITY']);
 assert.equal(result.readiness,'BLOCKED');
 assert.equal(result.authorization,'DENY');
 assert.equal(result.go13,'HOLD');
 assert.equal(result.ingressEnabled,false);
 assert.equal(result.mayPublish,false);
 assert.equal(result.mayInstall,false);
 assert.match(result.dossierDigest,/^[a-f0-9]{64}$/);
 assert.ok(Object.isFrozen(result));
});
test('missing or single signature fails closed',()=>{
 const f=context();
 for(const endorsements of [[],[f.endorsements[0]],null])
  assert.deepEqual(verifyBootstrapDossier(f.dossier,endorsements,f.options).findings,
    ['BOOTSTRAP_REVIEW_QUORUM_MISSING']);
});
test('same signer or same human reviewer cannot count twice',()=>{
 const f=context();
 const duplicate=[f.endorsements[0],f.endorsements[0]];
 assert.equal(verifyBootstrapDossier(f.dossier,duplicate,f.options).readiness,'BLOCKED');
 f.options.pinnedReviewRoots[1].reviewerId='reviewer-a';
 assert.deepEqual(verifyBootstrapDossier(f.dossier,f.endorsements,f.options).findings,
  ['BOOTSTRAP_REVIEW_ROOT_UNTRUSTED']);
});
test('signature cannot be reused after source, checkpoint or anchor is changed',()=>{
 for(const field of ['sourceDigest','checkpointDigest','anchorDigest',
  'postgresSchemaDigest','pinnedRootsDigest']){
  const f=context();
  f.dossier[field]='f'.repeat(64);
  assert.deepEqual(verifyBootstrapDossier(f.dossier,f.endorsements,f.options).findings,
   ['BOOTSTRAP_REVIEW_SIGNATURE_INVALID']);
 }
});
test('expired, future or rolled-back dossier sequence fails before signatures',()=>{
 for(const changes of [{sequence:9},{expiresAtMs:2000},{issuedAtMs:2001}]){
  const f=context();
  Object.assign(f.dossier,changes);
  assert.deepEqual(verifyBootstrapDossier(f.dossier,f.endorsements,f.options).findings,
    ['BOOTSTRAP_DOSSIER_STALE']);
 }
});
test('disabled or revoked review root is refused',()=>{
 for(const changes of [{enabled:false},{revoked:true}]){
  const f=context();
  Object.assign(f.options.pinnedReviewRoots[0],changes);
  assert.deepEqual(verifyBootstrapDossier(f.dossier,f.endorsements,f.options).findings,
    ['BOOTSTRAP_REVIEW_ROOT_UNTRUSTED']);
 }
});
test('unknown anchor, malformed payload and release assertions are blocked',()=>{
 const f=context();
 delete f.options.minimumSequence;
 assert.deepEqual(verifyBootstrapDossier(f.dossier,f.endorsements,f.options).findings,
  ['BOOTSTRAP_ANCHOR_UNAVAILABLE']);
 const release=context();
 release.dossier.authorization='ALLOW';
 assert.equal(dossierPayload(release.dossier),null);
 assert.deepEqual(verifyBootstrapDossier(release.dossier,release.endorsements,release.options).findings,
  ['BOOTSTRAP_DOSSIER_MALFORMED']);
});
test('unsupported lifetime and bad review-root configuration refuse approval',()=>{
 const f=context();
 f.options.maximumLifetimeMs=86400001;
 assert.deepEqual(verifyBootstrapDossier(f.dossier,f.endorsements,f.options).findings,
  ['BOOTSTRAP_ANCHOR_UNAVAILABLE']);
 const bad=context();
 bad.options.pinnedReviewRoots=[bad.options.pinnedReviewRoots[0]];
 assert.deepEqual(verifyBootstrapDossier(bad.dossier,bad.endorsements,bad.options).findings,
  ['BOOTSTRAP_REVIEW_QUORUM_MISSING']);
});
