'use strict';
// v5.6 non-authorizing, multi-signer witness key-manifest succession.
// Requires independently pinned predecessor digest and independent review key.
const {createPublicKey,verify}=require('node:crypto');
const {manifestDigest,manifestBytes}=require('./third-witness-key-history-v5.5');
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const HEX=/^[a-f0-9]{64}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const VERSION='palaco.distribution.third-witness-key-rotation.v1';
function denied(reason){
 return Object.freeze({readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
  mayAdvance:false,mayRestore:false,mayReconcile:false,maySynchronize:false,
  mayInstall:false,mayPublish:false,findings:Object.freeze([reason])});
}
function transitionBytes(t){
 if(!t||typeof t!=='object'||Array.isArray(t)||
  t.schemaVersion!==VERSION||!NS.test(t.namespace||'')||
  !Number.isSafeInteger(t.rotationNumber)||t.rotationNumber<1||
  !HEX.test(t.previousManifestDigest||'')||
  !HEX.test(t.nextManifestDigest||'')||
  t.previousManifestDigest===t.nextManifestDigest||
  !ID.test(t.retiringKeyId||'')||!ID.test(t.successorKeyId||'')||
  t.retiringKeyId===t.successorKeyId||
  !Number.isSafeInteger(t.rotatedAtMs)||t.rotatedAtMs<0||
  t.authorization!=='DENY'||t.go13!=='HOLD'||
  t.purpose!=='TRUST_KEY_ROTATION_NO_RELEASE')return null;
 return Buffer.from(['PALACO-INDUSTRIE-THIRD-WITNESS-KEY-ROTATION-V1',
  VERSION,t.namespace,String(t.rotationNumber),
  t.previousManifestDigest,t.nextManifestDigest,
  t.retiringKeyId,t.successorKeyId,String(t.rotatedAtMs),
  t.authorization,t.go13,t.purpose,''].join('\n'));
}
function validSig(bytes,signature,root){
 if(!bytes||!root||!signature||signature.algorithm!=='Ed25519'||
  !ID.test(signature.keyId||'')||signature.keyId!==root.keyId||
  root.enabled!==true||root.revoked!==false||
  typeof root.publicKeyPem!=='string'||root.publicKeyPem.length>4096||
  !SIG.test(signature.signature||'')||
  Buffer.from(signature.signature,'base64').toString('base64')!==
   signature.signature)return false;
 try{
  const key=createPublicKey(root.publicKeyPem);
  return key.asymmetricKeyType==='ed25519'&&
   verify(null,bytes,key,Buffer.from(signature.signature,'base64'));
 }catch(_){return false;}
}
function verifyThirdWitnessKeyRotation({
 previousManifest,nextManifest,transition,retiringSignature,
 successorSignature,reviewSignature,pinnedPreviousDigest,
 trustedRotationNumber,reviewRoot
}={}){
 const prev=manifestDigest(previousManifest);
 const next=manifestDigest(nextManifest);
 const bytes=transitionBytes(transition);
 if(!bytes||!prev||!next||!manifestBytes(previousManifest)||
  !manifestBytes(nextManifest)||
  !HEX.test(pinnedPreviousDigest||'')||
  !Number.isSafeInteger(trustedRotationNumber)||trustedRotationNumber<0)
  return denied('THIRD_ROTATION_MANIFEST_OR_PIN_INVALID');
 if(prev!==pinnedPreviousDigest||
  transition.previousManifestDigest!==prev||
  transition.nextManifestDigest!==next||
  previousManifest.namespace!==transition.namespace||
  nextManifest.namespace!==transition.namespace||
  transition.rotationNumber!==trustedRotationNumber+1)
  return denied('THIRD_ROTATION_REPLAY_OR_PIN_MISMATCH');
 if(nextManifest.floorSequence<previousManifest.floorSequence||
  (nextManifest.floorSequence===previousManifest.floorSequence&&
   nextManifest.floorDigest!==previousManifest.floorDigest))
  return denied('THIRD_ROTATION_FLOOR_REGRESSION');
 const p=previousManifest.epochs,n=nextManifest.epochs;
 if(n.length!==p.length+1)
  return denied('THIRD_ROTATION_EPOCHS_NOT_APPEND_ONLY');
 // Existing epoch identities, key material and validity windows are immutable.
 for(let i=0;i<p.length;i++){
  if(JSON.stringify(p[i])!==JSON.stringify(n[i]))
   return denied('THIRD_ROTATION_PRIOR_EPOCH_MUTATED');
 }
 const retiring=p.at(-1),successor=n.at(-1);
 if(retiring.keyId!==transition.retiringKeyId||
  successor.keyId!==transition.successorKeyId||
  successor.observerId!==retiring.observerId||
  successor.validFromMs!==retiring.validUntilMs||
  transition.rotatedAtMs<retiring.validFromMs||
  transition.rotatedAtMs>=retiring.validUntilMs||
  transition.rotatedAtMs>successor.validFromMs||
  successor.publicKeyPem===retiring.publicKeyPem)
  return denied('THIRD_ROTATION_INVALID_EPOCH_BOUNDARY');
 if(!reviewRoot||!ID.test(reviewRoot.keyId||'')||
  reviewRoot.keyId===retiring.keyId||
  reviewRoot.keyId===successor.keyId||
  reviewRoot.publicKeyPem===retiring.publicKeyPem||
  reviewRoot.publicKeyPem===successor.publicKeyPem)
  return denied('THIRD_ROTATION_INDEPENDENT_REVIEW_MISSING');
 if(!validSig(bytes,retiringSignature,retiring))
  return denied('THIRD_ROTATION_OLD_SIGNATURE_INVALID');
 if(!validSig(bytes,successorSignature,successor))
  return denied('THIRD_ROTATION_NEW_SIGNATURE_INVALID');
 if(!validSig(bytes,reviewSignature,reviewRoot))
  return denied('THIRD_ROTATION_REVIEW_SIGNATURE_INVALID');
 return Object.freeze({
  readiness:'THIRD_WITNESS_KEY_ROTATION_VERIFIED_NON_AUTHORIZING',
  authorization:'DENY',go13:'HOLD',rotationNumber:transition.rotationNumber,
  previousManifestDigest:prev,nextManifestDigest:next,
  verifiedSignatures:3,mayAdvance:false,mayRestore:false,
  mayReconcile:false,maySynchronize:false,mayInstall:false,
  mayPublish:false,findings:Object.freeze([])
 });
}
module.exports={VERSION,transitionBytes,verifyThirdWitnessKeyRotation};
