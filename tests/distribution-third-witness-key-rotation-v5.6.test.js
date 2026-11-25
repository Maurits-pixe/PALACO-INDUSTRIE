'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {manifestDigest}=require('../distribution/third-witness-key-history-v5.5');
const {VERSION,transitionBytes,verifyThirdWitnessKeyRotation}=
 require('../distribution/third-witness-key-rotation-v5.6');
function fixture(){
 const [oldKey,newKey,reviewer]=Array.from({length:3},
  ()=>generateKeyPairSync('ed25519'));
 const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
 const namespace='palaco.v56ci';
 const oldEpoch={observerId:'custodian',keyId:'old-ed25519',
  validFromMs:1000,validUntilMs:3000,enabled:true,revoked:false,
  publicKeyPem:pem(oldKey)};
 const newEpoch={observerId:'custodian',keyId:'new-ed25519',
  validFromMs:3000,validUntilMs:9000,enabled:true,revoked:false,
  publicKeyPem:pem(newKey)};
 const previousManifest={
  schemaVersion:'palaco.distribution.third-witness-key-history.v1',
  namespace,floorSequence:12,floorDigest:'a'.repeat(64),
  epochs:[oldEpoch]
 };
 const nextManifest={...previousManifest,
  floorSequence:13,floorDigest:'b'.repeat(64),
  epochs:[oldEpoch,newEpoch]};
 const transition={
  schemaVersion:VERSION,namespace,rotationNumber:1,
  previousManifestDigest:manifestDigest(previousManifest),
  nextManifestDigest:manifestDigest(nextManifest),
  retiringKeyId:oldEpoch.keyId,successorKeyId:newEpoch.keyId,
  rotatedAtMs:2999,authorization:'DENY',go13:'HOLD',
  purpose:'TRUST_KEY_ROTATION_NO_RELEASE'
 };
 const signature=(key,id)=>({algorithm:'Ed25519',keyId:id,
  signature:sign(null,transitionBytes(transition),key.privateKey).toString('base64')});
 const args={
  previousManifest,nextManifest,transition,
  retiringSignature:signature(oldKey,oldEpoch.keyId),
  successorSignature:signature(newKey,newEpoch.keyId),
  reviewSignature:signature(reviewer,'reviewer'),
  pinnedPreviousDigest:manifestDigest(previousManifest),
  trustedRotationNumber:0,
  reviewRoot:{keyId:'reviewer',enabled:true,revoked:false,
   publicKeyPem:pem(reviewer)}
 };
 return {args,oldKey,newKey,reviewer};
}
const check=args=>verifyThirdWitnessKeyRotation(args);
test('old, new and independent reviewer signatures preserve HOLD',()=>{
 const f=fixture(),r=check(f.args);
 assert.equal(r.readiness,'THIRD_WITNESS_KEY_ROTATION_VERIFIED_NON_AUTHORIZING');
 assert.equal(r.verifiedSignatures,3);
 assert.equal(r.authorization,'DENY');assert.equal(r.go13,'HOLD');
 assert.equal(r.mayAdvance,false);assert.equal(r.mayInstall,false);
});
test('malicious replacement or rollback of pinned predecessor is rejected',()=>{
 for(const change of [
  a=>{a.pinnedPreviousDigest='f'.repeat(64);},
  a=>{a.transition.previousManifestDigest='f'.repeat(64);},
  a=>{a.trustedRotationNumber=1;},
  a=>{a.nextManifest.floorSequence=11;},
  a=>{a.nextManifest.floorDigest='f'.repeat(64);
   a.nextManifest.floorSequence=12;}
 ]){
  const a=fixture().args;change(a);
  assert.equal(check(a).readiness,'BLOCKED');
 }
});
test('older key epochs cannot be deleted, modified or reordered',()=>{
 for(const change of [
  a=>{a.nextManifest.epochs=[a.nextManifest.epochs[1]];},
  a=>{a.nextManifest.epochs[0].validUntilMs=2000;},
  a=>{a.nextManifest.epochs.reverse();},
  a=>{a.nextManifest.epochs[0].keyId='changed';}
 ]){
  const a=structuredClone(fixture().args);change(a);
  assert.equal(check(a).readiness,'BLOCKED');
 }
});
test('forged old, new and reviewer signatures are rejected independently',()=>{
 for(const field of [
  'retiringSignature','successorSignature','reviewSignature'
 ]){
  const a=fixture().args;
  a[field]={...a[field],signature:'A'.repeat(86)+'=='};
  assert.equal(check(a).readiness,'BLOCKED');
 }
 const a=fixture().args;a.reviewRoot.revoked=true;
 assert.equal(check(a).readiness,'BLOCKED');
});
test('epoch gaps, overlapping keys and invalid rotation ceremony fail',()=>{
 for(const change of [
  a=>{a.nextManifest.epochs[1].validFromMs=2999;},
  a=>{a.transition.rotatedAtMs=3000;},
  a=>{a.transition.rotatedAtMs=999;},
  a=>{a.nextManifest.epochs[1].observerId='intruder';},
  a=>{a.nextManifest.epochs[1].publicKeyPem=a.nextManifest.epochs[0].publicKeyPem;},
  a=>{a.transition.purpose='RELEASE';}
 ]){
  const a=fixture().args;change(a);
  assert.equal(check(a).readiness,'BLOCKED');
 }
});
test('no writes, malformed roots and bogus keys can confer authority',()=>{
 assert.equal(transitionBytes({...fixture().args.transition,
  authorization:'ALLOW'}),null);
 for(const change of [
  a=>{a.reviewRoot.publicKeyPem='bad-key';},
  a=>{a.reviewRoot.keyId=a.transition.retiringKeyId;},
  a=>{a.reviewRoot.publicKeyPem=a.previousManifest.epochs[0].publicKeyPem;},
  a=>{a.previousManifest.epochs=[];}
 ]){
  const a=fixture().args;change(a);
  assert.equal(check(a).readiness,'BLOCKED');
 }
 const out=check(fixture().args);
 assert.equal(out.mayPublish,false);
 assert.equal(typeof out.commit,'undefined');
});
