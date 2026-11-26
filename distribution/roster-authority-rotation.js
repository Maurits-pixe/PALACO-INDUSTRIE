'use strict';

// Read-only v3.8 authority-key rollover evidence. This never changes the
// configured trust roots, issues secrets or grants distribution authority.
const {createPublicKey,createHash,verify}=require('node:crypto');
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const HEX=/^[a-f0-9]{64}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const VERSION='palaco.distribution.roster-authority.v1';
const ROTATION='palaco.distribution.roster-authority-rotation.v1';

function publicBytes(value){
  if(typeof value!=='string'||value.length>4096||value.length<48)return null;
  try{
    const key=createPublicKey(value);
    return key.asymmetricKeyType==='ed25519'
      ? key.export({type:'spki',format:'der'}):null;
  }catch(_){return null;}
}
function publicDigest(value){
  const bytes=publicBytes(value);
  return bytes?createHash('sha256').update(bytes).digest('hex'):null;
}
function authorityPayload(state){
  if(!state||typeof state!=='object'||Array.isArray(state)||
    state.schemaVersion!==VERSION||!NS.test(state.namespace||'')||
    !Number.isSafeInteger(state.revision)||state.revision<1||
    !HEX.test(state.previousDigest||'')||
    !Array.isArray(state.keys)||state.keys.length<1||state.keys.length>32)
    return null;
  const lines=[],seenIds=new Set(),seenKeys=new Set();
  let last='',active=0;
  for(const entry of state.keys){
    if(!entry||typeof entry!=='object'||Array.isArray(entry)||
      !ID.test(entry.keyId||'')||entry.keyId<=last||
      !['active','revoked'].includes(entry.status)||
      seenIds.has(entry.keyId))return null;
    const digest=publicDigest(entry.publicKeyPem);
    if(!digest||seenKeys.has(digest))return null;
    seenIds.add(entry.keyId);seenKeys.add(digest);
    if(entry.status==='active')active++;
    last=entry.keyId;
    lines.push([entry.keyId,entry.status,digest].join('\n'));
  }
  if(active!==1)return null;
  return Buffer.from(['PALACO-INDUSTRIE-ROSTER-AUTHORITY-V1',VERSION,
    state.namespace,String(state.revision),state.previousDigest,...lines,''
  ].join('\n'),'utf8');
}
function authorityDigest(state){
  const payload=authorityPayload(state);
  return payload?createHash('sha256').update(payload).digest('hex'):null;
}
function rotationPayload(record){
  if(!record||typeof record!=='object'||Array.isArray(record)||
    record.schemaVersion!==ROTATION||!NS.test(record.namespace||'')||
    !Number.isSafeInteger(record.revision)||record.revision<2||
    !HEX.test(record.previousDigest||'')||!HEX.test(record.nextDigest||'')||
    !ID.test(record.oldKeyId||'')||!ID.test(record.newKeyId||'')||
    record.oldKeyId===record.newKeyId)
    return null;
  return Buffer.from(['PALACO-INDUSTRIE-AUTHORITY-ROTATION-V1',ROTATION,
    record.namespace,String(record.revision),record.previousDigest,
    record.nextDigest,record.oldKeyId,record.newKeyId,''].join('\n'),'utf8');
}
function denied(reason){
  return Object.freeze({readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
    mayAdvance:false,mayRotate:false,mayRestore:false,mayInstall:false,
    mayPublish:false,findings:Object.freeze([reason])});
}
function signatureMatches(payload,endorsement,root){
  if(!endorsement||endorsement.algorithm!=='Ed25519'||
    !ID.test(endorsement.keyId||'')||!SIG.test(endorsement.signature||'')||
    Buffer.from(endorsement.signature,'base64').toString('base64')!==endorsement.signature||
    !root||root.keyId!==endorsement.keyId)return false;
  const bytes=publicBytes(root.publicKeyPem);
  try{return !!bytes&&verify(null,payload,createPublicKey(root.publicKeyPem),
    Buffer.from(endorsement.signature,'base64'));}catch(_){return false;}
}

/**
 * The external anchor must originate outside the authority's signing and
 * restore domain. Both old and proposed new authorities must sign identical
 * bytes; two distinct non-authority reviewers must also sign.
 */
function verifyRosterAuthorityRotation(previous,next,record,endorsements,
  {namespace,minimumRevision,previousDigest,pinnedReviewers}={}) {
  if(!NS.test(namespace||'')||!Number.isSafeInteger(minimumRevision)||
    minimumRevision<1||!HEX.test(previousDigest||''))
    return denied('AUTHORITY_ANCHOR_UNAVAILABLE');
  const oldDigest=authorityDigest(previous),newDigest=authorityDigest(next);
  const payload=rotationPayload(record);
  if(!oldDigest||!newDigest||!payload||
    previous.namespace!==namespace||next.namespace!==namespace||
    record.namespace!==namespace)return denied('AUTHORITY_ROTATION_FORMAT_INVALID');
  if(previous.revision!==minimumRevision||oldDigest!==previousDigest||
    next.revision!==previous.revision+1||
    next.previousDigest!==oldDigest||
    record.revision!==next.revision||
    record.previousDigest!==oldDigest||record.nextDigest!==newDigest)
    return denied('AUTHORITY_ROTATION_CHAIN_MISMATCH');
  const oldActive=previous.keys.filter(k=>k.status==='active');
  const newActive=next.keys.filter(k=>k.status==='active');
  const previousById=new Map(previous.keys.map(k=>[k.keyId,k]));
  const nextById=new Map(next.keys.map(k=>[k.keyId,k]));
  if(oldActive.length!==1||newActive.length!==1||
    oldActive[0].keyId!==record.oldKeyId||
    newActive[0].keyId!==record.newKeyId||
    previousById.has(record.newKeyId)||
    next.keys.length!==previous.keys.length+1)
    return denied('AUTHORITY_ROTATION_STATE_INVALID');
  for(const entry of previous.keys){
    const after=nextById.get(entry.keyId);
    if(!after||after.status!=='revoked'||
       publicDigest(after.publicKeyPem)!==publicDigest(entry.publicKeyPem))
      return denied('AUTHORITY_ROTATION_HISTORY_INVALID');
  }
  const proposed=nextById.get(record.newKeyId);
  if(!proposed||proposed.status!=='active')
    return denied('AUTHORITY_ROTATION_STATE_INVALID');
  if(!endorsements||typeof endorsements!=='object'||Array.isArray(endorsements)||
    !signatureMatches(payload,endorsements.oldAuthority,oldActive[0])||
    !signatureMatches(payload,endorsements.newAuthority,proposed))
    return denied('AUTHORITY_ROTATION_DUAL_SIGNATURE_INVALID');
  if(!Array.isArray(pinnedReviewers)||pinnedReviewers.length<2||
    pinnedReviewers.length>32||
    !Array.isArray(endorsements.reviewers)||endorsements.reviewers.length!==2)
    return denied('AUTHORITY_ROTATION_REVIEW_QUORUM_MISSING');
  const ids=new Set(),people=new Set(),usedKeys=new Set([
    publicDigest(oldActive[0].publicKeyPem),publicDigest(proposed.publicKeyPem)]);
  for(const approval of endorsements.reviewers){
    const roots=pinnedReviewers.filter(r=>r&&r.keyId===approval?.keyId);
    if(roots.length!==1)return denied('AUTHORITY_ROTATION_REVIEW_UNTRUSTED');
    const root=roots[0];
    const digest=publicDigest(root.publicKeyPem);
    if(root.enabled!==true||root.revoked!==false||
      !ID.test(root.reviewerId||'')||!digest||
      ids.has(root.keyId)||people.has(root.reviewerId)||usedKeys.has(digest))
      return denied('AUTHORITY_ROTATION_REVIEW_UNTRUSTED');
    if(!signatureMatches(payload,approval,root))
      return denied('AUTHORITY_ROTATION_REVIEW_SIGNATURE_INVALID');
    ids.add(root.keyId);people.add(root.reviewerId);usedKeys.add(digest);
  }
  return Object.freeze({
    readiness:'AUTHORITY_ROTATION_VERIFIED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',mayAdvance:false,mayRotate:false,
    mayRestore:false,mayInstall:false,mayPublish:false,
    revision:next.revision,digest:newDigest,
    proposedAuthority:Object.freeze({keyId:proposed.keyId,
      publicKeyPem:proposed.publicKeyPem}),
    findings:Object.freeze([])
  });
}
module.exports={VERSION,ROTATION,authorityPayload,authorityDigest,
  rotationPayload,verifyRosterAuthorityRotation};
