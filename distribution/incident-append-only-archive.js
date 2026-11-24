'use strict';

// PALACO INDUSTRIE v4.3: append-only forensic archive. No repair, authority,
// unlock, production credentials, schema bootstrap or release action.
const {verifyWitnessIncident,incidentDigest}=
  require('./witness-incident-review');

const HEAD_SQL=[
 'SELECT sequence, incident_digest',
 'FROM palaco_incident_archive.entries',
 'WHERE namespace=$1 ORDER BY sequence DESC LIMIT 1'
].join('\n');
const INSERT_SQL=[
 'INSERT INTO palaco_incident_archive.entries',
 '(namespace,sequence,incident_id,prior_digest,incident_digest,',
 ' observed_at_ms,dossier,endorsements)',
 'VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb)',
 'RETURNING sequence, incident_digest'
].join('\n');
const ZERO='0'.repeat(64);
function denied(code){
 return Object.freeze({readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
  mayAdvance:false,mayReconcile:false,maySynchronize:false,mayRestore:false,
  mayPublish:false,mayInstall:false,
  findings:Object.freeze([code])});
}
function headFrom(reply){
 if(!reply||reply.rowCount!==1||!Array.isArray(reply.rows)||
   reply.rows.length!==1)return null;
 const row=reply.rows[0];
 const seq=Number(row?.sequence);
 if(!Number.isSafeInteger(seq)||seq<1||
  typeof row.incident_digest!=='string'||!/^[a-f0-9]{64}$/.test(row.incident_digest))
  return null;
 return {sequence:seq,digest:row.incident_digest};
}
function createIncidentArchive({namespace,query}={}){
 if(typeof namespace!=='string'||!/^[a-z][a-z0-9._-]{2,79}$/.test(namespace)||
    typeof query!=='function')
  throw new TypeError('Named trusted incident archive query required');
 async function latest(signal){
  if(signal?.aborted)return {unavailable:true};
  try{
   const result=await query({text:HEAD_SQL,values:[namespace],signal});
   if(signal?.aborted||!result||!Array.isArray(result.rows))
    return {unavailable:true};
   if(result.rowCount===0&&result.rows.length===0)return null;
   return headFrom(result)||{unavailable:true};
  }catch(_){return {unavailable:true};}
 }
 async function appendReviewed(incident,endorsements,reviewPolicy,signal){
  const head=await latest(signal);
  if(signal?.aborted||head?.unavailable)
   return denied('INCIDENT_ARCHIVE_UNAVAILABLE');
  if(!incident||incident.namespace!==namespace)
   return denied('INCIDENT_ARCHIVE_SCOPE_INVALID');
  const sequence=head?head.sequence+1:1;
  const prior=head?head.digest:ZERO;
  if(!Number.isSafeInteger(sequence))
   return denied('INCIDENT_ARCHIVE_SEQUENCE_EXHAUSTED');
  if(incident.sequence!==sequence||incident.priorIncidentDigest!==prior)
   return denied('INCIDENT_ARCHIVE_HEAD_MISMATCH');
  // Review roots, clock and the external authorization to append come
  // from trusted application code, never from the dossier itself.
  const proof=verifyWitnessIncident(incident,endorsements,{
   ...reviewPolicy,namespace,minimumSequence:sequence,priorIncidentDigest:prior
  });
  if(proof.readiness!=='INCIDENT_REVIEW_VERIFIED_NON_AUTHORIZING')
   return denied('INCIDENT_ARCHIVE_REVIEW_REJECTED');
  if(signal?.aborted)return denied('INCIDENT_ARCHIVE_UNAVAILABLE');
  try{
   const result=await query({text:INSERT_SQL,values:[
    namespace,sequence,incident.incidentId,prior,incidentDigest(incident),
    incident.observedAtMs,JSON.stringify(incident),JSON.stringify(endorsements)
   ],signal});
   const actual=headFrom(result);
   if(signal?.aborted||!actual||actual.sequence!==sequence||
      actual.digest!==proof.incidentDigest)
    return denied('INCIDENT_ARCHIVE_WRITE_UNCONFIRMED');
  }catch(_){
   return denied('INCIDENT_ARCHIVE_APPEND_REJECTED');
  }
  return Object.freeze({
   readiness:'INCIDENT_ARCHIVED_NON_AUTHORIZING',
   authorization:'DENY',go13:'HOLD',sequence,
   incidentDigest:proof.incidentDigest,mayAdvance:false,
   mayReconcile:false,maySynchronize:false,mayRestore:false,
   mayInstall:false,mayPublish:false,findings:Object.freeze([])
  });
 }
 return Object.freeze({namespace,latest,appendReviewed});
}
module.exports={HEAD_SQL,INSERT_SQL,createIncidentArchive};
