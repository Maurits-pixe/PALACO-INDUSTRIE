'use strict';
// v5.8 — complete signed manifest observation chain, externally pinned head.
const {createHash,createPublicKey,verify}=require('node:crypto');
const {publicationBytes}=require('./manifest-publication-views-v5.7');
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const HEX=/^[a-f0-9]{64}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const ZERO='0'.repeat(64);
const CHECKPOINT_VERSION='palaco.distribution.manifest-transparency-checkpoint.v1';
const EVENTS=[
 'SELECT namespace,entry_sequence,previous_entry_digest,entry_digest,',
 'rotation_number,manifest_digest,previous_manifest_digest,',
 'observer_id,key_id,observed_at_ms,signature',
 'FROM palaco_manifest_transparency.entries',
 'WHERE namespace=$1 ORDER BY entry_sequence ASC'
].join('\n');
const CHECKPOINT=[
 'SELECT namespace,entry_sequence,entry_digest,observer_id,key_id,',
 'observed_at_ms,signature FROM palaco_manifest_transparency_anchor.latest',
 'WHERE namespace=$1'
].join('\n');
function deny(reason){return Object.freeze({readiness:'BLOCKED',
 authorization:'DENY',go13:'HOLD',mayRestore:false,mayAdvance:false,
 mayReconcile:false,maySynchronize:false,mayInstall:false,mayPublish:false,
 findings:Object.freeze([reason])});}
function number(value,min){
 const n=Number(value);
 return /^(0|[1-9][0-9]*)$/.test(String(value))&&
  Number.isSafeInteger(n)&&n>=min?n:null;
}
function signatureValid(bytes,signature,keyId,root,observerId){
 if(!bytes||!root||root.enabled!==true||root.revoked!==false||
  root.observerId!==observerId||root.keyId!==keyId||
  !ID.test(keyId||'')||!SIG.test(signature||'')||
  Buffer.from(signature,'base64').toString('base64')!==signature||
  typeof root.publicKeyPem!=='string'||root.publicKeyPem.length>4096)return false;
 try{
  const key=createPublicKey(root.publicKeyPem);
  return key.asymmetricKeyType==='ed25519'&&
   verify(null,bytes,key,Buffer.from(signature,'base64'));
 }catch(_){return false;}
}
function viewBytes(row){
 const rotation=number(row?.rotation_number,1),time=number(row?.observed_at_ms,0);
 if(rotation===null||time===null)return null;
 return publicationBytes({
  schemaVersion:'palaco.distribution.manifest-publication-view.v1',
  namespace:row.namespace,rotationNumber:rotation,
  manifestDigest:row.manifest_digest,
  previousManifestDigest:row.previous_manifest_digest,
  observerId:row.observer_id,observedAtMs:time,
  authorization:'DENY',go13:'HOLD',
  purpose:'MANIFEST_VIEW_OBSERVATION_NO_RELEASE'
 });
}
function entryDigest(row,previousDigest){
 const seq=number(row?.entry_sequence,1),bytes=viewBytes(row);
 if(seq===null||!bytes||!HEX.test(previousDigest||'')||
  !ID.test(row.key_id||'')||!SIG.test(row.signature||'')||
  Buffer.from(row.signature,'base64').toString('base64')!==row.signature)
  return null;
 return createHash('sha256').update(Buffer.concat([
  Buffer.from('PALACO-MANIFEST-TRANSPARENCY-ENTRY-V1\n'),
  Buffer.from(String(seq)+'\n'+previousDigest+'\n'+row.key_id+'\n'+row.signature+'\n'),
  bytes
 ])).digest('hex');
}
function checkpointBytes(v){
 if(!v||v.schemaVersion!==CHECKPOINT_VERSION||
  !NS.test(v.namespace||'')||
  !Number.isSafeInteger(v.entrySequence)||v.entrySequence<1||
  !HEX.test(v.entryDigest||'')||!ID.test(v.observerId||'')||
  !Number.isSafeInteger(v.observedAtMs)||v.observedAtMs<0||
  v.authorization!=='DENY'||v.go13!=='HOLD'||
  v.purpose!=='MANIFEST_TRANSPARENCY_OBSERVATION_NO_AUTHORITY')return null;
 return Buffer.from(['PALACO-MANIFEST-TRANSPARENCY-CHECKPOINT-V1',
  CHECKPOINT_VERSION,v.namespace,String(v.entrySequence),v.entryDigest,
  v.observerId,String(v.observedAtMs),v.authorization,v.go13,v.purpose,
  ''].join('\n'));
}
function createManifestTransparencyVerifier({
 namespace,logQuery,checkpointQuery,observationRootProvider,
 checkpointRootProvider,pinnedCheckpointSequence,pinnedCheckpointDigest
}={}){
 if(!NS.test(namespace||'')||typeof logQuery!=='function'||
  typeof checkpointQuery!=='function'||logQuery===checkpointQuery||
  typeof observationRootProvider!=='function'||
  typeof checkpointRootProvider!=='function'||
  !Number.isSafeInteger(pinnedCheckpointSequence)||
  pinnedCheckpointSequence<1||!HEX.test(pinnedCheckpointDigest||''))
  throw new TypeError('Independent log, signing roots and pinned checkpoint required');
 return Object.freeze({namespace,async verify(signal){
  if(signal?.aborted)return deny('TRANSPARENCY_ABORTED');
  let log,head;
  try{
   [log,head]=await Promise.all([
    logQuery({text:EVENTS,values:[namespace],signal}),
    checkpointQuery({text:CHECKPOINT,values:[namespace],signal})
   ]);
  }catch(_){return deny('TRANSPARENCY_SOURCE_UNAVAILABLE');}
  if(signal?.aborted)return deny('TRANSPARENCY_ABORTED');
  if(!log||!Array.isArray(log.rows)||log.rowCount!==log.rows.length||
   !log.rows.length||log.rows.length>10000)
   return deny('TRANSPARENCY_LOG_MISSING_OR_OVERSIZED');
  const row=head?.rowCount===1&&head.rows?.length===1?head.rows[0]:null;
  const anchorSeq=number(row?.entry_sequence,1),time=number(row?.observed_at_ms,0);
  if(!row||row.namespace!==namespace||anchorSeq===null||time===null||
   !HEX.test(row.entry_digest||'')||!ID.test(row.observer_id||''))
   return deny('TRANSPARENCY_CHECKPOINT_MISSING');
  const checkpoint={schemaVersion:CHECKPOINT_VERSION,namespace,
   entrySequence:anchorSeq,entryDigest:row.entry_digest,
   observerId:row.observer_id,observedAtMs:time,
   authorization:'DENY',go13:'HOLD',
   purpose:'MANIFEST_TRANSPARENCY_OBSERVATION_NO_AUTHORITY'};
  let root;
  try{root=await checkpointRootProvider(namespace,row.observer_id,
   row.key_id,signal);}
  catch(_){return deny('TRANSPARENCY_CHECKPOINT_TRUST_UNAVAILABLE');}
  if(signal?.aborted||!signatureValid(checkpointBytes(checkpoint),
   row.signature,row.key_id,root,row.observer_id))
   return deny('TRANSPARENCY_CHECKPOINT_SIGNATURE_INVALID');
  if(anchorSeq<pinnedCheckpointSequence||
   (anchorSeq===pinnedCheckpointSequence&&
    row.entry_digest!==pinnedCheckpointDigest))
   return deny('TRANSPARENCY_PINNED_ROLLBACK');
  let previous=ZERO,sequence=0,priorRotation=0,priorManifest=null,
   priorPredecessorManifest=null;
  const seen=new Set();let pinnedAt=null;
  for(const e of log.rows){
   if(signal?.aborted)return deny('TRANSPARENCY_ABORTED');
   const n=number(e?.entry_sequence,1),rotation=number(e?.rotation_number,1);
   const observedAt=number(e?.observed_at_ms,0);
   if(e?.namespace!==namespace||n!==sequence+1||
    rotation===null||observedAt===null||
    e.previous_entry_digest!==previous)
    return deny('TRANSPARENCY_SEQUENCE_OR_PREDECESSOR_INVALID');
   const digest=entryDigest(e,previous);
   if(!digest||digest!==e.entry_digest)
    return deny('TRANSPARENCY_EVENT_DIGEST_INVALID');
   if(seen.has(rotation+':'+e.observer_id))
    return deny('TRANSPARENCY_DUPLICATE_OBSERVATION');
   seen.add(rotation+':'+e.observer_id);
   if(rotation<priorRotation||rotation>priorRotation+1||
    (rotation===priorRotation+1&&priorRotation!==0&&
     e.previous_manifest_digest!==priorManifest))
    return deny('TRANSPARENCY_MANIFEST_ORDER_INVALID');
   let observerRoot;
   try{observerRoot=await observationRootProvider(namespace,
    e.observer_id,e.key_id,observedAt,signal);}
   catch(_){return deny('TRANSPARENCY_OBSERVER_TRUST_UNAVAILABLE');}
   if(!signatureValid(viewBytes(e),e.signature,e.key_id,
    observerRoot,e.observer_id))
    return deny('TRANSPARENCY_OBSERVATION_SIGNATURE_INVALID');
   if(rotation===priorRotation&&
    (e.manifest_digest!==priorManifest||
     e.previous_manifest_digest!==priorPredecessorManifest))
    return deny('TRANSPARENCY_AUTHENTIC_SPLIT_VIEW');
   if(rotation!==priorRotation){
    priorManifest=e.manifest_digest;
    priorPredecessorManifest=e.previous_manifest_digest;
   }
   priorRotation=rotation;sequence=n;previous=digest;
   if(n===pinnedCheckpointSequence)pinnedAt=previous;
  }
  if(sequence!==anchorSeq||previous!==row.entry_digest)
   return deny('TRANSPARENCY_CHECKPOINT_HEAD_MISMATCH');
  if(!pinnedAt||pinnedAt!==pinnedCheckpointDigest)
   return deny('TRANSPARENCY_PINNED_HISTORY_MISMATCH');
  return Object.freeze({
   readiness:'MANIFEST_TRANSPARENCY_VERIFIED_NON_AUTHORIZING',
   authorization:'DENY',go13:'HOLD',sequence,digest:previous,
   verifiedObservations:sequence,mayAdvance:false,mayRestore:false,
   mayReconcile:false,maySynchronize:false,mayInstall:false,
   mayPublish:false,findings:Object.freeze([])
  });
 }});
}
module.exports={ZERO,CHECKPOINT_VERSION,EVENTS,CHECKPOINT,
 entryDigest,checkpointBytes,createManifestTransparencyVerifier};
