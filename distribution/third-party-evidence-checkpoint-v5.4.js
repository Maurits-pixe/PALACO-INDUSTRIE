'use strict';
// v5.4 third-party signed observation. This verifier NEVER signs, advances
// source archives, reconciles, repairs, publishes or issues authority.
const {createPublicKey,verify}=require('node:crypto');
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const HEX=/^[a-f0-9]{64}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const VERSION='palaco.distribution.third-party-evidence-checkpoint.v1';
const LATEST=[
 'SELECT sequence,chain_digest FROM palaco_signed_evidence_anchor.latest',
 'WHERE namespace=$1'
].join('\n');
const THIRD=[
 'SELECT namespace,sequence,chain_digest,observed_at_ms,observer_id,',
 'key_id,signature FROM palaco_third_witness.checkpoints',
 'WHERE namespace=$1 ORDER BY sequence DESC LIMIT 1'
].join('\n');
function payload(v){
 if(!v||typeof v!=='object'||Array.isArray(v)||
  v.schemaVersion!==VERSION||!NS.test(v.namespace||'')||
  !Number.isSafeInteger(v.sequence)||v.sequence<2||
  !HEX.test(v.chainDigest||'')||!ID.test(v.observerId||'')||
  !Number.isSafeInteger(v.observedAtMs)||v.observedAtMs<0||
  v.authorization!=='DENY'||v.go13!=='HOLD'||
  v.purpose!=='INDEPENDENT_OBSERVATION_NO_AUTHORITY')return null;
 return Buffer.from(['PALACO-INDUSTRIE-THIRD-PARTY-EVIDENCE-CHECKPOINT-V1',
  VERSION,v.namespace,String(v.sequence),v.chainDigest,
  v.observerId,String(v.observedAtMs),
  v.authorization,v.go13,v.purpose,''].join('\n'));
}
function denied(reason){
 return Object.freeze({
  readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
  mayAdvance:false,mayRestore:false,mayReconcile:false,
  maySynchronize:false,mayInstall:false,mayPublish:false,
  findings:Object.freeze([reason])
 });
}
function decodeHead(response){
 if(response?.rowCount!==1||response.rows?.length!==1)return null;
 const row=response.rows[0],n=Number(row?.sequence);
 if(!/^[1-9][0-9]*$/.test(String(row?.sequence))||
  !Number.isSafeInteger(n)||n<2||!HEX.test(row.chain_digest||''))return null;
 return {sequence:n,digest:row.chain_digest};
}
function decodeThird(response,namespace){
 if(response?.rowCount!==1||response.rows?.length!==1)return null;
 const row=response.rows[0];
 const sequence=Number(row?.sequence),observedAtMs=Number(row?.observed_at_ms);
 if(row?.namespace!==namespace||
  !/^[1-9][0-9]*$/.test(String(row?.sequence))||
  !/^(0|[1-9][0-9]*)$/.test(String(row?.observed_at_ms))||
  !Number.isSafeInteger(sequence)||!Number.isSafeInteger(observedAtMs)||
  !ID.test(row?.observer_id||'')||!ID.test(row?.key_id||'')||
  !SIG.test(row?.signature||'')||
  Buffer.from(row.signature,'base64').toString('base64')!==row.signature)
  return null;
 return {checkpoint:{
   schemaVersion:VERSION,namespace,sequence,
   chainDigest:row.chain_digest,observedAtMs,observerId:row.observer_id,
   authorization:'DENY',go13:'HOLD',
   purpose:'INDEPENDENT_OBSERVATION_NO_AUTHORITY'
  },keyId:row.key_id,signature:row.signature};
}
function createThirdPartyEvidenceCheckpointVerifier({
 namespace,anchorQuery,thirdPartyQuery,trustRootProvider
}={}){
 if(!NS.test(namespace||'')||typeof anchorQuery!=='function'||
  typeof thirdPartyQuery!=='function'||anchorQuery===thirdPartyQuery||
  typeof trustRootProvider!=='function')
  throw new TypeError('Separate external anchor and trusted third-party witness required');
 return Object.freeze({namespace,
  async verify(signal){
   if(signal?.aborted)return denied('THIRD_CHECKPOINT_ABORTED');
   let primary,third;
   try{
    [primary,third]=await Promise.all([
     anchorQuery({text:LATEST,values:[namespace],signal}),
     thirdPartyQuery({text:THIRD,values:[namespace],signal})
    ]);
   }catch(_){return denied('THIRD_CHECKPOINT_SOURCE_UNAVAILABLE');}
   if(signal?.aborted)return denied('THIRD_CHECKPOINT_ABORTED');
   const current=decodeHead(primary);
   const witness=decodeThird(third,namespace);
   if(!current||!witness)return denied('THIRD_CHECKPOINT_MISSING_OR_MALFORMED');
   let root;
   try{
    root=await trustRootProvider(namespace,witness.keyId,signal);
   }catch(_){return denied('THIRD_CHECKPOINT_TRUST_UNAVAILABLE');}
   if(signal?.aborted||!root||root.enabled!==true||root.revoked!==false||
    root.keyId!==witness.keyId||
    root.observerId!==witness.checkpoint.observerId||
    typeof root.publicKeyPem!=='string'||root.publicKeyPem.length>4096)
    return denied('THIRD_CHECKPOINT_TRUST_UNAVAILABLE');
   const bytes=payload(witness.checkpoint);
   if(!bytes)return denied('THIRD_CHECKPOINT_FORMAT_INVALID');
   let signatureValid=false;
   try{
    const key=createPublicKey(root.publicKeyPem);
    signatureValid=key.asymmetricKeyType==='ed25519'&&
     verify(null,bytes,key,Buffer.from(witness.signature,'base64'));
   }catch(_){return denied('THIRD_CHECKPOINT_SIGNATURE_INVALID');}
   if(!signatureValid)return denied('THIRD_CHECKPOINT_SIGNATURE_INVALID');
   if(current.sequence!==witness.checkpoint.sequence||
      current.digest!==witness.checkpoint.chainDigest)
    return denied('THIRD_CHECKPOINT_ROOT_ROLLBACK_OR_FORK');
   return Object.freeze({
    readiness:'THIRD_PARTY_CHECKPOINT_MATCHED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',
    sequence:current.sequence,digest:current.digest,
    observerId:witness.checkpoint.observerId,
    mayAdvance:false,mayRestore:false,mayReconcile:false,
    maySynchronize:false,mayInstall:false,mayPublish:false,
    findings:Object.freeze([])
   });
  }
 });
}
module.exports={VERSION,LATEST,THIRD,payload,
 createThirdPartyEvidenceCheckpointVerifier};
