'use strict';
// v4.6: two independently provisioned read-only heads, no automatic repair.
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const HEX=/^[a-f0-9]{64}$/;
const SQL=[
 'SELECT sequence,incident_digest FROM palaco_incident_witness.heads',
 'WHERE namespace=$1'
].join('\n');
function denied(reason){
 return Object.freeze({readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
  mayAdvance:false,mayRestore:false,mayReconcile:false,
  maySynchronize:false,mayInstall:false,mayPublish:false,
  findings:Object.freeze([reason])});
}
function decode(reply){
 if(!reply||reply.rowCount!==1||!Array.isArray(reply.rows)||
  reply.rows.length!==1)return null;
 const row=reply.rows[0];
 if(!row||!/^[1-9][0-9]*$/.test(String(row.sequence))||
  !HEX.test(row.incident_digest||''))return null;
 const sequence=Number(row.sequence);
 return Number.isSafeInteger(sequence)?{
  sequence,digest:row.incident_digest}:null;
}
function createIncidentExternalWitness({namespace,query}={}){
 if(!NS.test(namespace||'')||typeof query!=='function')
  throw new TypeError('Independent incident witness query adapter required');
 return Object.freeze({namespace,
  async latest(signal){
   if(signal?.aborted)return null;
   try{
    const result=await query({text:SQL,values:[namespace],signal});
    return signal?.aborted?null:decode(result);
   }catch(_){return null;}
  }
 });
}
async function verifyIncidentArchiveWitness(archive,witness,signal){
 if(!archive||!witness||archive===witness||
  !NS.test(archive.namespace||'')||
  archive.namespace!==witness.namespace||
  typeof archive.latest!=='function'||typeof witness.latest!=='function'||
  signal?.aborted)return denied('INCIDENT_WITNESS_UNAVAILABLE');
 let local,external;
 try{
  [local,external]=await Promise.all([
   archive.latest(signal),witness.latest(signal)]);
 }catch(_){return denied('INCIDENT_WITNESS_UNAVAILABLE');}
 if(signal?.aborted||!local||!external||local.unavailable||
  !Number.isSafeInteger(local.sequence)||local.sequence<1||
  !HEX.test(local.digest||'')||
  !Number.isSafeInteger(external.sequence)||external.sequence<1||
  !HEX.test(external.digest||''))
  return denied('INCIDENT_WITNESS_UNAVAILABLE');
 if(local.sequence!==external.sequence||local.digest!==external.digest)
  return denied('INCIDENT_WITNESS_HEAD_MISMATCH');
 return Object.freeze({
  readiness:'INCIDENT_ARCHIVE_HEAD_VERIFIED_NON_AUTHORIZING',
  authorization:'DENY',go13:'HOLD',sequence:local.sequence,digest:local.digest,
  mayAdvance:false,mayRestore:false,mayReconcile:false,
  maySynchronize:false,mayInstall:false,mayPublish:false,
  findings:Object.freeze([])
 });
}
module.exports={SQL,createIncidentExternalWitness,verifyIncidentArchiveWitness};
