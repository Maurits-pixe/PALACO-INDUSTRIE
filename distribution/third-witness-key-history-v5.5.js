'use strict';
// v5.5: third-witness anti-rollback floor and key-history manifest pinned
// OUTSIDE all three databases. Read-only; no release or repair authority.
const {createHash,createPublicKey}=require('node:crypto');
const {createThirdPartyEvidenceCheckpointVerifier}=
 require('./third-party-evidence-checkpoint-v5.4');
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const HEX=/^[a-f0-9]{64}$/;
const LATEST=[
 'SELECT namespace,sequence,chain_digest,observed_at_ms,observer_id,',
 'key_id,signature FROM palaco_third_witness.checkpoints',
 'WHERE namespace=$1 ORDER BY sequence DESC LIMIT 1'
].join('\n');
function denied(reason){
 return Object.freeze({readiness:'BLOCKED',authorization:'DENY',
  go13:'HOLD',mayAdvance:false,mayRestore:false,
  mayReconcile:false,maySynchronize:false,mayInstall:false,
  mayPublish:false,findings:Object.freeze([reason])});
}
// One strict, deterministic canonical encoding of the externally governed
// immutable history. No JSON order ambiguity or supplemental policy fields.
function manifestBytes(manifest){
 if(!manifest||typeof manifest!=='object'||Array.isArray(manifest)||
  manifest.schemaVersion!=='palaco.distribution.third-witness-key-history.v1'||
  !NS.test(manifest.namespace||'')||
  !Number.isSafeInteger(manifest.floorSequence)||manifest.floorSequence<2||
  !HEX.test(manifest.floorDigest||'')||
  !Array.isArray(manifest.epochs)||!manifest.epochs.length||
  manifest.epochs.length>256)return null;
 const chunks=['PALACO-THIRD-WITNESS-KEY-HISTORY-V1',
  manifest.schemaVersion,manifest.namespace,
  String(manifest.floorSequence),manifest.floorDigest];
 const seen=new Set();
 for(const epoch of manifest.epochs){
  if(!epoch||typeof epoch!=='object'||Array.isArray(epoch)||
   !ID.test(epoch.observerId||'')||!ID.test(epoch.keyId||'')||
   seen.has(epoch.keyId)||!Number.isSafeInteger(epoch.validFromMs)||
   epoch.validFromMs<0||!Number.isSafeInteger(epoch.validUntilMs)||
   epoch.validUntilMs<=epoch.validFromMs||
   epoch.enabled!==true||epoch.revoked!==false||
   typeof epoch.publicKeyPem!=='string'||
   epoch.publicKeyPem.length>4096)return null;
  let key;
  try{key=createPublicKey(epoch.publicKeyPem);}
  catch(_){return null;}
  if(key.asymmetricKeyType!=='ed25519')return null;
  seen.add(epoch.keyId);
  const spki=key.export({type:'spki',format:'der'});
  chunks.push(epoch.observerId,epoch.keyId,
   String(epoch.validFromMs),String(epoch.validUntilMs),
   createHash('sha256').update(spki).digest('hex'));
 }
 return Buffer.from([...chunks,''].join('\n'),'utf8');
}
function manifestDigest(manifest){
 const bytes=manifestBytes(manifest);
 return bytes?createHash('sha256').update(bytes).digest('hex'):null;
}
function createThirdWitnessKeyHistoryVerifier({
 namespace,anchorQuery,thirdPartyQuery,historyProvider,pinnedManifestDigest
}={}){
 if(!NS.test(namespace||'')||typeof anchorQuery!=='function'||
  typeof thirdPartyQuery!=='function'||anchorQuery===thirdPartyQuery||
  typeof historyProvider!=='function'||!HEX.test(pinnedManifestDigest||''))
  throw new TypeError('Independent pinned manifest, third witness and anchor required');
 return Object.freeze({namespace,
  async verify(signal){
   if(signal?.aborted)return denied('THIRD_HISTORY_ABORTED');
   let history,third;
   try{
    [history,third]=await Promise.all([
     historyProvider(namespace,signal),
     thirdPartyQuery({text:LATEST,values:[namespace],signal})
    ]);
   }catch(_){return denied('THIRD_HISTORY_SOURCE_UNAVAILABLE');}
   if(signal?.aborted)return denied('THIRD_HISTORY_ABORTED');
   const digest=manifestDigest(history);
   if(!digest||digest!==pinnedManifestDigest||
     history.namespace!==namespace)
    return denied('THIRD_HISTORY_PIN_MISMATCH');
   const row=third?.rowCount===1&&third.rows?.length===1?
    third.rows[0]:null;
   const seq=Number(row?.sequence),at=Number(row?.observed_at_ms);
   if(!row||row.namespace!==namespace||
    !/^[1-9][0-9]*$/.test(String(row.sequence))||
    !/^(0|[1-9][0-9]*)$/.test(String(row.observed_at_ms))||
    !Number.isSafeInteger(seq)||!Number.isSafeInteger(at)||
    !HEX.test(row.chain_digest||'')||
    !ID.test(row.observer_id||'')||!ID.test(row.key_id||''))
    return denied('THIRD_HISTORY_CHECKPOINT_MISSING');
   // A pinned independent high-watermark detects rollback of the third DB
   // even when the primary and external DBs are rolled back together.
   if(seq<history.floorSequence||
      (seq===history.floorSequence&&row.chain_digest!==history.floorDigest))
    return denied('THIRD_HISTORY_HIGH_WATER_ROLLBACK');
   const epoch=history.epochs.find(x=>x.keyId===row.key_id);
   if(!epoch||epoch.observerId!==row.observer_id||
    at<epoch.validFromMs||at>=epoch.validUntilMs)
    return denied('THIRD_HISTORY_KEY_EPOCH_INVALID');
   const verified=createThirdPartyEvidenceCheckpointVerifier({
    namespace,anchorQuery,thirdPartyQuery,
    trustRootProvider:async(ns,keyId)=>keyId===epoch.keyId?{
     observerId:epoch.observerId,keyId:epoch.keyId,
     enabled:epoch.enabled,revoked:epoch.revoked,
     publicKeyPem:epoch.publicKeyPem
    }:null
   });
   const proof=await verified.verify(signal);
   if(proof.readiness!=='THIRD_PARTY_CHECKPOINT_MATCHED_NON_AUTHORIZING')
    return denied(proof.findings?.[0]||'THIRD_HISTORY_CROSS_CHECK_REJECTED');
   return Object.freeze({
    readiness:'THIRD_WITNESS_KEY_HISTORY_VERIFIED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',sequence:proof.sequence,
    digest:proof.digest,keyId:epoch.keyId,manifestDigest:digest,
    mayAdvance:false,mayRestore:false,mayReconcile:false,
    maySynchronize:false,mayInstall:false,mayPublish:false,
    findings:Object.freeze([])
   });
  }
 });
}
module.exports={LATEST,manifestBytes,manifestDigest,
 createThirdWitnessKeyHistoryVerifier};
