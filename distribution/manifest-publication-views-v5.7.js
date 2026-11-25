'use strict';
// v5.7: read-only comparison of independently signed manifest publication views.
// Two independently pinned observer identities must attest the SAME digest.
const {createPublicKey,verify}=require('node:crypto');
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const HEX=/^[a-f0-9]{64}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const VERSION='palaco.distribution.manifest-publication-view.v1';
const SELECT=[
 'SELECT namespace,rotation_number,manifest_digest,previous_manifest_digest,',
 'observer_id,key_id,observed_at_ms,signature',
 'FROM palaco_manifest_publication.views',
 'WHERE namespace=$1 AND rotation_number=$2'
].join('\n');
function publicationBytes(p){
 if(!p||typeof p!=='object'||Array.isArray(p)||
  p.schemaVersion!==VERSION||!NS.test(p.namespace||'')||
  !Number.isSafeInteger(p.rotationNumber)||p.rotationNumber<1||
  !HEX.test(p.manifestDigest||'')||!HEX.test(p.previousManifestDigest||'')||
  p.manifestDigest===p.previousManifestDigest||
  !ID.test(p.observerId||'')||
  !Number.isSafeInteger(p.observedAtMs)||p.observedAtMs<0||
  p.authorization!=='DENY'||p.go13!=='HOLD'||
  p.purpose!=='MANIFEST_VIEW_OBSERVATION_NO_RELEASE')return null;
 return Buffer.from([
  'PALACO-INDUSTRIE-MANIFEST-PUBLICATION-VIEW-V1',VERSION,
  p.namespace,String(p.rotationNumber),p.manifestDigest,
  p.previousManifestDigest,p.observerId,String(p.observedAtMs),
  p.authorization,p.go13,p.purpose,''
 ].join('\n'),'utf8');
}
function denied(reason){
 return Object.freeze({readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
  mayAdvance:false,mayRestore:false,mayReconcile:false,
  maySynchronize:false,mayInstall:false,mayPublish:false,
  findings:Object.freeze([reason])});
}
function verifyView(row,root,expected){
 const observedAtMs=Number(row?.observed_at_ms);
 const p={
  schemaVersion:VERSION,namespace:row?.namespace,
  rotationNumber:Number(row?.rotation_number),
  manifestDigest:row?.manifest_digest,
  previousManifestDigest:row?.previous_manifest_digest,
  observerId:row?.observer_id,observedAtMs,
  authorization:'DENY',go13:'HOLD',
  purpose:'MANIFEST_VIEW_OBSERVATION_NO_RELEASE'
 };
 const bytes=publicationBytes(p);
 if(!bytes||row.namespace!==expected.namespace||
  p.rotationNumber!==expected.rotationNumber||
  !/^[1-9][0-9]*$/.test(String(row.rotation_number))||
  !/^(0|[1-9][0-9]*)$/.test(String(row.observed_at_ms))||
  !SIG.test(row.signature||'')||
  Buffer.from(row.signature,'base64').toString('base64')!==row.signature||
  !root||root.enabled!==true||root.revoked!==false||
  root.observerId!==p.observerId||root.keyId!==row.key_id||
  !ID.test(root.keyId||'')||
  typeof root.publicKeyPem!=='string'||root.publicKeyPem.length>4096)return false;
 try{
  const key=createPublicKey(root.publicKeyPem);
  return key.asymmetricKeyType==='ed25519'&&
   verify(null,bytes,key,Buffer.from(row.signature,'base64'));
 }catch(_){return false;}
}
function createManifestPublicationViewVerifier({
 namespace,rotationNumber,pinnedPreviousDigest,pinnedNextDigest,
 firstQuery,secondQuery,rootProvider
}={}){
 if(!NS.test(namespace||'')||!Number.isSafeInteger(rotationNumber)||
  rotationNumber<1||!HEX.test(pinnedPreviousDigest||'')||
  !HEX.test(pinnedNextDigest||'')||
  pinnedPreviousDigest===pinnedNextDigest||
  typeof firstQuery!=='function'||typeof secondQuery!=='function'||
  firstQuery===secondQuery||typeof rootProvider!=='function')
  throw new TypeError('Independent publication sources, pinned digests and roots required');
 return Object.freeze({namespace,
  async verify(signal){
   if(signal?.aborted)return denied('PUBLICATION_VIEW_ABORTED');
   let a,b;
   try{
    [a,b]=await Promise.all([
     firstQuery({text:SELECT,values:[namespace,rotationNumber],signal}),
     secondQuery({text:SELECT,values:[namespace,rotationNumber],signal})
    ]);
   }catch(_){return denied('PUBLICATION_VIEW_SOURCE_UNAVAILABLE');}
   if(signal?.aborted)return denied('PUBLICATION_VIEW_ABORTED');
   const rowA=a?.rowCount===1&&a.rows?.length===1?a.rows[0]:null;
   const rowB=b?.rowCount===1&&b.rows?.length===1?b.rows[0]:null;
   if(!rowA||!rowB)return denied('PUBLICATION_VIEW_MISSING_OR_AMBIGUOUS');
   // Conflict is identified independently of signature validity, but never
   // accepted as an authenticated split-view until both signatures pass.
   let rootA,rootB;
   try{
    [rootA,rootB]=await Promise.all([
     rootProvider(namespace,rowA.observer_id,rowA.key_id,signal),
     rootProvider(namespace,rowB.observer_id,rowB.key_id,signal)
    ]);
   }catch(_){return denied('PUBLICATION_VIEW_ROOTS_UNAVAILABLE');}
   if(signal?.aborted||!rootA||!rootB||
    rootA.observerId===rootB.observerId||
    rootA.keyId===rootB.keyId||
    rootA.publicKeyPem===rootB.publicKeyPem)
    return denied('PUBLICATION_VIEW_INDEPENDENCE_UNPROVEN');
   const expected={namespace,rotationNumber};
   if(!verifyView(rowA,rootA,expected)||!verifyView(rowB,rootB,expected))
    return denied('PUBLICATION_VIEW_SIGNATURE_INVALID');
   if(rowA.manifest_digest!==rowB.manifest_digest||
    rowA.previous_manifest_digest!==rowB.previous_manifest_digest)
    return denied('PUBLICATION_VIEW_SIGNED_SPLIT_VIEW_DETECTED');
   if(rowA.manifest_digest!==pinnedNextDigest||
    rowA.previous_manifest_digest!==pinnedPreviousDigest)
    return denied('PUBLICATION_VIEW_PIN_MISMATCH');
   return Object.freeze({
    readiness:'TWO_PUBLICATION_VIEWS_MATCH_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',rotationNumber,
    manifestDigest:pinnedNextDigest,
    mayAdvance:false,mayRestore:false,mayReconcile:false,
    maySynchronize:false,mayInstall:false,mayPublish:false,
    findings:Object.freeze([])
   });
  }
 });
}
module.exports={VERSION,SELECT,publicationBytes,
 createManifestPublicationViewVerifier};
