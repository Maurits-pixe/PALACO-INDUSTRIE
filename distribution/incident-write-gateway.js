'use strict';

// Trusted process-only forensic gateway. Never expose the writer connection,
// reviewer roots or incident policy to an HTTP client. No distribution ingress.
const {verifyLiveWitnessIncident}=require('./witness-incident-review');
const {createIncidentArchive}=require('./incident-append-only-archive');
const instances=new WeakSet();

function denied(reason){
 return Object.freeze({
  readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
  mayAdvance:false,mayReconcile:false,maySynchronize:false,
  mayRestore:false,mayInstall:false,mayPublish:false,
  findings:Object.freeze([reason])
 });
}
function createIncidentWriteGateway({
 namespace,query,reviewPolicyProvider,primaryWitness,secondaryWitness
}={}){
 if(typeof namespace!=='string'||!/^[a-z][a-z0-9._-]{2,79}$/.test(namespace)||
   typeof query!=='function'||typeof reviewPolicyProvider!=='function'||
   !primaryWitness||!secondaryWitness||primaryWitness===secondaryWitness||
   primaryWitness.namespace!==namespace||secondaryWitness.namespace!==namespace||
   typeof primaryWitness.latest!=='function'||
   typeof secondaryWitness.latest!=='function')
   throw new TypeError('Isolated writer, policy provider and two witnesses required');
 const archive=createIncidentArchive({namespace,query});
 const gateway=Object.freeze({
  namespace,
  async submit(incident,endorsements,signal){
   if(signal?.aborted||!incident||incident.namespace!==namespace)
    return denied('INCIDENT_GATEWAY_INPUT_REJECTED');
   // Review policy comes only from protected operator-owned state. Never
   // accept a caller-provided reviewer root, clock or replay floor.
   let policy;
   try {policy=await reviewPolicyProvider(namespace,signal);}
   catch(_){return denied('INCIDENT_GATEWAY_POLICY_UNAVAILABLE');}
   if(signal?.aborted||!policy||typeof policy!=='object'||
     Array.isArray(policy)||!Number.isSafeInteger(policy.nowMs)||
     !Array.isArray(policy.pinnedReviewRoots))
    return denied('INCIDENT_GATEWAY_POLICY_UNAVAILABLE');
   const head=await archive.latest(signal);
   if(signal?.aborted||head?.unavailable)
    return denied('INCIDENT_GATEWAY_ARCHIVE_UNAVAILABLE');
   const expectedSequence=head?head.sequence+1:1;
   const expectedPrior=head?head.digest:'0'.repeat(64);
   if(!Number.isSafeInteger(expectedSequence)||
      incident.sequence!==expectedSequence||
      incident.priorIncidentDigest!==expectedPrior)
    return denied('INCIDENT_GATEWAY_HEAD_MISMATCH');
   const assessment=await verifyLiveWitnessIncident(
    incident,endorsements,{
     namespace,minimumSequence:expectedSequence,
     priorIncidentDigest:expectedPrior,
     nowMs:policy.nowMs,pinnedReviewRoots:policy.pinnedReviewRoots,
     maximumLifetimeMs:policy.maximumLifetimeMs
    },{primary:primaryWitness,secondary:secondaryWitness},signal);
   if(assessment.readiness!=='INCIDENT_LIVE_DIVERGENCE_VERIFIED_NON_AUTHORIZING')
    return denied('INCIDENT_GATEWAY_LIVE_REVIEW_REJECTED');
   if(signal?.aborted)return denied('INCIDENT_GATEWAY_ABORTED');
   // Archive adapter repeats cryptographic checks and reads current head
   // again. PostgreSQL uniqueness resolves concurrent competing writers.
   const result=await archive.appendReviewed(incident,endorsements,{
    nowMs:policy.nowMs,pinnedReviewRoots:policy.pinnedReviewRoots,
    maximumLifetimeMs:policy.maximumLifetimeMs
   },signal);
   if(result.readiness!=='INCIDENT_ARCHIVED_NON_AUTHORIZING')
    return denied('INCIDENT_GATEWAY_ARCHIVE_REJECTED');
   return Object.freeze({
    readiness:'INCIDENT_GATEWAY_ARCHIVED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',incidentDigest:result.incidentDigest,
    sequence:result.sequence,mayAdvance:false,mayReconcile:false,
    maySynchronize:false,mayRestore:false,mayInstall:false,
    mayPublish:false,findings:Object.freeze([])
   });
  }
 });
 instances.add(gateway);
 return gateway;
}
function isIncidentWriteGateway(value){
 return !!value&&typeof value==='object'&&instances.has(value);
}
module.exports={createIncidentWriteGateway,isIncidentWriteGateway};
