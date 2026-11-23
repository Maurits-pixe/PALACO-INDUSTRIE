'use strict';

const {createPublicKey,verify,createHash}=require('node:crypto');
const {verifyRosterAuthorityRotation}=require('./roster-authority-rotation');

const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const HEX=/^[0-9a-f]{64}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const VERSION='palaco.distribution.reviewer-roster.v1';

function rosterPayload(roster) {
  if(!roster||typeof roster!=='object'||Array.isArray(roster)||
     roster.schemaVersion!==VERSION||!NS.test(roster.namespace||'')||
     !Number.isSafeInteger(roster.revision)||roster.revision<1||
     !HEX.test(roster.previousDigest||'')||
     !Array.isArray(roster.reviewers)||roster.reviewers.length<2||
     roster.reviewers.length>32) return null;
  const identities=new Set(),keys=new Set();
  let previous='';
  const lines=[];
  for(const r of roster.reviewers) {
    if(!r||typeof r!=='object'||Array.isArray(r)||
       !ID.test(r.reviewerId||'')||!ID.test(r.keyId||'')||
       !['active','revoked'].includes(r.status)||
       typeof r.publicKeyPem!=='string'||r.publicKeyPem.length>4096||
       r.publicKeyPem.length<48||
       identities.has(r.reviewerId)||keys.has(r.keyId)||
       (previous!==''&&r.reviewerId<=previous)) return null;
    try {
      if(createPublicKey(r.publicKeyPem).asymmetricKeyType!=='ed25519')return null;
    }catch(_){return null;}
    identities.add(r.reviewerId);keys.add(r.keyId);previous=r.reviewerId;
    const keyHash=createHash('sha256').update(
      createPublicKey(r.publicKeyPem).export({type:'spki',format:'der'})
    ).digest('hex');
    lines.push([r.reviewerId,r.keyId,r.status,keyHash].join('\n'));
  }
  return Buffer.from([
    'PALACO-INDUSTRIE-REVIEWER-ROSTER-V1',VERSION,roster.namespace,
    String(roster.revision),roster.previousDigest,...lines,''
  ].join('\n'),'utf8');
}
function rosterDigest(roster){
  const payload=rosterPayload(roster);
  return payload?createHash('sha256').update(payload).digest('hex'):null;
}
function deny(reason){
  return Object.freeze({
    readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
    mayAdvance:false,mayRestore:false,mayInstall:false,mayPublish:false,
    findings:Object.freeze([reason])
  });
}
function verifyRosterSignature(roster,endorsement,pinnedRoots){
  const payload=rosterPayload(roster);
  if(!payload)return false;
  if(!endorsement||endorsement.algorithm!=='Ed25519'||
     !ID.test(endorsement.keyId||'')||!SIG.test(endorsement.signature||'')||
     Buffer.from(endorsement.signature,'base64').toString('base64')!==endorsement.signature||
     !Array.isArray(pinnedRoots)||pinnedRoots.length<1||pinnedRoots.length>32) return false;
  const roots=pinnedRoots.filter(r=>r&&r.keyId===endorsement.keyId);
  if(roots.length!==1||roots[0].enabled!==true||roots[0].revoked!==false||
     typeof roots[0].publicKeyPem!=='string'||roots[0].publicKeyPem.length>4096)
    return false;
  try{
    const key=createPublicKey(roots[0].publicKeyPem);
    return key.asymmetricKeyType==='ed25519'&&
      verify(null,payload,key,Buffer.from(endorsement.signature,'base64'));
  }catch(_){return false;}
}

/**
 * Every transition must be signed by an independently pinned roster authority.
 * Pinned last revision/digest MUST be held outside this roster's trust domain.
 * Fail closed on removal, key substitution or reactivation of revoked people.
 */
function verifyReviewerRosterTransition(previous,next,endorsement,options={}) {
  if(!options||typeof options!=='object'||Array.isArray(options))
    return deny('ROSTER_ANCHOR_UNAVAILABLE');
  const {namespace,pinnedRoots,minimumRevision,previousDigest}=options;
  if(!NS.test(namespace||'')||!Number.isSafeInteger(minimumRevision)||
     minimumRevision<1||!HEX.test(previousDigest||''))
    return deny('ROSTER_ANCHOR_UNAVAILABLE');
  const oldDigest=rosterDigest(previous),newDigest=rosterDigest(next);
  if(!oldDigest||!newDigest||previous.namespace!==namespace||
     next.namespace!==namespace)return deny('ROSTER_FORMAT_INVALID');
  if(previous.revision!==minimumRevision||oldDigest!==previousDigest||
     next.revision!==previous.revision+1||
     next.previousDigest!==oldDigest) return deny('ROSTER_CHAIN_MISMATCH');
  if(!verifyRosterSignature(next,endorsement,pinnedRoots))
    return deny('ROSTER_SIGNATURE_INVALID');
  const nextById=new Map(next.reviewers.map(r=>[r.reviewerId,r]));
  for(const prior of previous.reviewers) {
    const current=nextById.get(prior.reviewerId);
    if(!current)return deny('ROSTER_IDENTITY_REMOVED');
    if(current.keyId!==prior.keyId||current.publicKeyPem!==prior.publicKeyPem)
      return deny('ROSTER_KEY_SUBSTITUTION');
    if(prior.status==='revoked'&&current.status!=='revoked')
      return deny('ROSTER_REVOCATION_ROLLBACK');
  }
  const roots=Object.freeze(next.reviewers.filter(r=>r.status==='active')
    .map(r=>Object.freeze({reviewerId:r.reviewerId,keyId:r.keyId,
      publicKeyPem:r.publicKeyPem,enabled:true,revoked:false})));
  return Object.freeze({
    readiness:'ROSTER_TRANSITION_VERIFIED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',mayAdvance:false,mayRestore:false,
    mayInstall:false,mayPublish:false,
    revision:next.revision,digest:newDigest,reviewRoots:roots,
    findings:Object.freeze([])
  });
}
/**
 * Explicit stronger mode: reviewer roster's authority key is taken only
 * from a verified old/new authority rotation (never untrusted pinnedRoots
 * from the caller's options). The independent rotation anchor stays required.
 */
function verifyRotationBoundReviewerRosterTransition(previous,next,endorsement,
  options,rotationEvidence){
  if(!rotationEvidence||typeof rotationEvidence!=='object'||
     Array.isArray(rotationEvidence))return deny('AUTHORITY_ROTATION_EVIDENCE_MISSING');
  const proof=verifyRosterAuthorityRotation(
    rotationEvidence.previous,rotationEvidence.next,rotationEvidence.record,
    rotationEvidence.endorsements,rotationEvidence.anchor);
  if(proof.readiness!=='AUTHORITY_ROTATION_VERIFIED_NON_AUTHORIZING')
    return deny('AUTHORITY_ROTATION_EVIDENCE_REJECTED');
  if(!options||typeof options!=='object'||Array.isArray(options)||
     options.namespace!==rotationEvidence.anchor.namespace||
     options.namespace!==rotationEvidence.next.namespace)
    return deny('AUTHORITY_ROTATION_NAMESPACE_MISMATCH');
  // The only accepted signer is the verified proposed authority.
  return verifyReviewerRosterTransition(previous,next,endorsement,{
    ...options,pinnedRoots:[{...proof.proposedAuthority,
      enabled:true,revoked:false}]
  });
}
module.exports={VERSION,rosterPayload,rosterDigest,verifyReviewerRosterTransition,
  verifyRotationBoundReviewerRosterTransition};
