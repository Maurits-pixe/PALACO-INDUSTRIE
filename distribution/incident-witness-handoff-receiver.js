'use strict';
// v4.7 trusted adapter: verify signed handoff and recipient receipt first,
// then perform one atomic PostgreSQL CAS + immutable nonce insertion.
const {verifyIncidentWitnessHandoff}=
 require('./incident-witness-handoff');
const {createIncidentExternalWitness}=
 require('./incident-external-witness');
const SQL=[
 'WITH advanced AS (',
 ' UPDATE palaco_incident_witness.heads',
 ' SET sequence=$4,incident_digest=$5',
 ' WHERE namespace=$1 AND sequence=$2 AND incident_digest=$3',
 '   AND sequence+1=$4 AND incident_digest<>$5',
 ' RETURNING namespace,sequence,incident_digest',
 '), recorded AS (',
 ' INSERT INTO palaco_incident_witness.receipts',
 ' (namespace,nonce,handoff_digest,recipient_id,sequence)',
 ' SELECT namespace,$6,$7,$8,sequence FROM advanced',
 ' RETURNING namespace,nonce,sequence',
 ') SELECT a.sequence,a.incident_digest,r.nonce',
 ' FROM advanced a INNER JOIN recorded r',
 ' ON a.namespace=r.namespace AND a.sequence=r.sequence'
].join('\n');
function denied(reason){
 return Object.freeze({readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
  mayAdvance:false,mayRestore:false,mayPublish:false,
  mayReconcile:false,maySynchronize:false,mayInstall:false,
  findings:Object.freeze([reason])});
}
function createIncidentWitnessHandoffReceiver({
 namespace,query,trustPolicyProvider
}={}){
 if(typeof trustPolicyProvider!=='function')
  throw new TypeError('Trusted handoff policy provider required');
 const witness=createIncidentExternalWitness({namespace,query});
 return Object.freeze({
  namespace,
  async receive(handoff,senderSignature,receipt,receiptSignature,signal){
   if(signal?.aborted)return denied('WITNESS_RECEIVER_ABORTED');
   let policy;
   try{policy=await trustPolicyProvider(namespace,signal);}
   catch(_){return denied('WITNESS_RECEIVER_POLICY_UNAVAILABLE');}
   if(signal?.aborted||!policy||typeof policy!=='object'||
      Array.isArray(policy)||!Number.isSafeInteger(policy.nowMs))
    return denied('WITNESS_RECEIVER_POLICY_UNAVAILABLE');
   const previous=await witness.latest(signal);
   if(!previous||signal?.aborted)
    return denied('WITNESS_RECEIVER_HEAD_UNAVAILABLE');
   const proof=verifyIncidentWitnessHandoff(handoff,senderSignature,
    receipt,receiptSignature,{
     ...policy,namespace,previousSequence:previous.sequence,
     previousDigest:previous.digest
    });
   if(proof.readiness!=='WITNESS_HANDOFF_RECEIPT_VERIFIED_NON_AUTHORIZING')
    return denied('WITNESS_RECEIVER_PROOF_REJECTED');
   try{
    const result=await query({text:SQL,values:[
     namespace,previous.sequence,previous.digest,
     proof.sequence,proof.digest,proof.nonce,proof.handoffDigest,
     handoff.recipientId
    ],signal});
    if(signal?.aborted||!result||result.rowCount!==1||
       !Array.isArray(result.rows)||result.rows.length!==1||
       String(result.rows[0].sequence)!==String(proof.sequence)||
       result.rows[0].incident_digest!==proof.digest||
       result.rows[0].nonce!==proof.nonce)
      return denied('WITNESS_RECEIVER_WRITE_UNCONFIRMED');
   }catch(_){return denied('WITNESS_RECEIVER_CAS_OR_REPLAY_REJECTED');}
   return Object.freeze({
    readiness:'WITNESS_RECEIPT_RECORDED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',sequence:proof.sequence,
    digest:proof.digest,handoffDigest:proof.handoffDigest,
    mayAdvance:false,mayRestore:false,mayPublish:false,
    mayReconcile:false,maySynchronize:false,mayInstall:false,
    findings:Object.freeze([])
   });
  }
 });
}
module.exports={SQL,createIncidentWitnessHandoffReceiver};
