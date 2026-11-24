'use strict';

// PALACO INDUSTRIE v4.2 — forensic incident review, NEVER a repair command.
// This module does not mutate any witness or produce operational authorization.
const {createHash,createPublicKey,verify}=require('node:crypto');
const VERSION='palaco.distribution.witness-incident.v1';
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const HEX=/^[a-f0-9]{64}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;

function headValid(head){
 return head&&typeof head==='object'&&!Array.isArray(head)&&
  Number.isSafeInteger(head.revision)&&head.revision>=1&&
  typeof head.digest==='string'&&HEX.test(head.digest);
}
function incidentPayload(value){
 if(!value||typeof value!=='object'||Array.isArray(value)||
  value.schemaVersion!==VERSION||!NS.test(value.namespace||'')||
  !ID.test(value.incidentId||'')||
  !Number.isSafeInteger(value.sequence)||value.sequence<1||
  !HEX.test(value.priorIncidentDigest||'')||
  !Number.isSafeInteger(value.observedAtMs)||value.observedAtMs<0||
  !Number.isSafeInteger(value.expiresAtMs)||
  value.expiresAtMs<=value.observedAtMs||
  !headValid(value.primary)||!headValid(value.secondary)||
  value.primary.revision===value.secondary.revision&&
    value.primary.digest===value.secondary.digest||
  value.authorization!=='DENY'||value.go13!=='HOLD'||
  value.recommendedAction!=='QUARANTINE_NO_SYNC')
  return null;
 return Buffer.from([
  'PALACO-INDUSTRIE-WITNESS-INCIDENT-V1',VERSION,value.namespace,
  value.incidentId,String(value.sequence),value.priorIncidentDigest,
  String(value.observedAtMs),String(value.expiresAtMs),
  String(value.primary.revision),value.primary.digest,
  String(value.secondary.revision),value.secondary.digest,
  value.authorization,value.go13,value.recommendedAction,''
 ].join('\n'),'utf8');
}
function incidentDigest(value){
 const bytes=incidentPayload(value);
 return bytes?createHash('sha256').update(bytes).digest('hex'):null;
}
function blocked(reason,digest=null){
 return Object.freeze({
  readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
  mayAdvance:false,mayRotate:false,mayRestore:false,
  mayReconcile:false,maySynchronize:false,mayInstall:false,mayPublish:false,
  incidentDigest:digest,findings:Object.freeze([reason])
 });
}
function validateSignature(payload,endorsement,roots,usedKeys,usedPeople){
 if(!endorsement||endorsement.algorithm!=='Ed25519'||
   !ID.test(endorsement.keyId||'')||!SIG.test(endorsement.signature||'')||
   Buffer.from(endorsement.signature,'base64').toString('base64')!==endorsement.signature||
   usedKeys.has(endorsement.keyId)) return 'INCIDENT_REVIEW_SIGNATURE_INVALID';
 const found=roots.filter(root=>root&&root.keyId===endorsement.keyId);
 if(found.length!==1)return 'INCIDENT_REVIEW_ROOT_UNTRUSTED';
 const root=found[0];
 if(root.enabled!==true||root.revoked!==false||
  !ID.test(root.reviewerId||'')||usedPeople.has(root.reviewerId)||
  typeof root.publicKeyPem!=='string'||root.publicKeyPem.length>4096)
  return 'INCIDENT_REVIEW_ROOT_UNTRUSTED';
 try{
  const key=createPublicKey(root.publicKeyPem);
  if(key.asymmetricKeyType!=='ed25519'||
    !verify(null,payload,key,Buffer.from(endorsement.signature,'base64')))
    return 'INCIDENT_REVIEW_SIGNATURE_INVALID';
 }catch(_){return 'INCIDENT_REVIEW_SIGNATURE_INVALID';}
 usedKeys.add(endorsement.keyId);usedPeople.add(root.reviewerId);
 return null;
}
/**
 * A verified incident is evidence that two reviewers signed an observation.
 * It is NOT proof that the alleged witness observations were authentic; a
 * separate read-only live check is required, and this can NEVER authorize sync.
 * A trusted durable incident chain head must be supplied out of band.
 */
function verifyWitnessIncident(incident,endorsements,{
 namespace,minimumSequence,priorIncidentDigest,nowMs,
 pinnedReviewRoots,maximumLifetimeMs=86400000
}={}){
 const payload=incidentPayload(incident);
 if(!payload||incident.namespace!==namespace)return blocked('INCIDENT_FORMAT_INVALID');
 const digest=createHash('sha256').update(payload).digest('hex');
 if(!Number.isSafeInteger(minimumSequence)||minimumSequence<1||
    !HEX.test(priorIncidentDigest||'')||
    !Number.isSafeInteger(nowMs)||nowMs<0||
    !Number.isSafeInteger(maximumLifetimeMs)||maximumLifetimeMs<1||
    maximumLifetimeMs>86400000)
  return blocked('INCIDENT_INDEPENDENT_ANCHOR_UNAVAILABLE',digest);
 if(incident.sequence!==minimumSequence||
    incident.priorIncidentDigest!==priorIncidentDigest)
  return blocked('INCIDENT_REPLAY_OR_CHAIN_MISMATCH',digest);
 if(nowMs<incident.observedAtMs||nowMs>=incident.expiresAtMs||
    incident.expiresAtMs-incident.observedAtMs>maximumLifetimeMs)
  return blocked('INCIDENT_STALE',digest);
 if(!Array.isArray(pinnedReviewRoots)||pinnedReviewRoots.length<2||
    pinnedReviewRoots.length>32||!Array.isArray(endorsements)||
    endorsements.length!==2)
  return blocked('INCIDENT_REVIEW_QUORUM_MISSING',digest);
 const usedKeys=new Set(),usedPeople=new Set();
 for(const endorsement of endorsements){
  const error=validateSignature(payload,endorsement,pinnedReviewRoots,usedKeys,usedPeople);
  if(error)return blocked(error,digest);
 }
 return Object.freeze({
  readiness:'INCIDENT_REVIEW_VERIFIED_NON_AUTHORIZING',
  authorization:'DENY',go13:'HOLD',incidentDigest:digest,
  mayAdvance:false,mayRotate:false,mayRestore:false,mayReconcile:false,
  maySynchronize:false,mayInstall:false,mayPublish:false,
  findings:Object.freeze(['INCIDENT_REQUIRES_INDEPENDENT_RECONCILIATION'])
 });
}
/**
 * Bind signed observations to two CURRENT independent read-only witnesses.
 * A stale or healed incident must not be misreported as a live divergence.
 * Neither this path nor verified signatures can issue a repair instruction.
 */
async function verifyLiveWitnessIncident(incident,endorsements,policy,
  {primary,secondary}={},signal){
 const assessment=verifyWitnessIncident(incident,endorsements,policy);
 if(assessment.readiness!=='INCIDENT_REVIEW_VERIFIED_NON_AUTHORIZING')
  return assessment;
 if(!primary||!secondary||primary===secondary||
  primary.namespace!==incident.namespace||
  secondary.namespace!==incident.namespace||
  typeof primary.latest!=='function'||typeof secondary.latest!=='function'||
  signal?.aborted)
  return blocked('INCIDENT_LIVE_WITNESS_UNAVAILABLE',assessment.incidentDigest);
 let first,second;
 try{
  [first,second]=await Promise.all([
    primary.latest(signal),secondary.latest(signal)
  ]);
 }catch(_){return blocked('INCIDENT_LIVE_WITNESS_UNAVAILABLE',assessment.incidentDigest);}
 if(signal?.aborted||!headValid(first)||!headValid(second))
  return blocked('INCIDENT_LIVE_WITNESS_UNAVAILABLE',assessment.incidentDigest);
 if(first.revision!==incident.primary.revision||
    first.digest!==incident.primary.digest||
    second.revision!==incident.secondary.revision||
    second.digest!==incident.secondary.digest)
  return blocked('INCIDENT_LIVE_SNAPSHOT_MISMATCH',assessment.incidentDigest);
 return Object.freeze({
  ...assessment,readiness:'INCIDENT_LIVE_DIVERGENCE_VERIFIED_NON_AUTHORIZING'
 });
}
module.exports={VERSION,incidentPayload,incidentDigest,verifyWitnessIncident,
 verifyLiveWitnessIncident};
