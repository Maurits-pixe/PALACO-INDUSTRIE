'use strict';
// Opt-in v5.0 receiver: one PostgreSQL statement advances witness, registers
// nonce, stores both signatures and commits complete evidence SHA-256 digest.
// Existing v4.7 receiver remains untouched. No HTTP integration.
const {verifyIncidentWitnessHandoff}=
 require('./incident-witness-handoff');
const {createIncidentExternalWitness}=
 require('./incident-external-witness');
const {evidenceDigest}=require('./signed-evidence-v5');
const SQL=[
 'WITH advanced AS (',
 ' UPDATE palaco_incident_witness.heads',
 ' SET sequence=$4,incident_digest=$5',
 ' WHERE namespace=$1 AND sequence=$2 AND incident_digest=$3',
 ' AND sequence+1=$4 AND incident_digest<>$5',
 ' RETURNING namespace,sequence,incident_digest',
 '), received AS (',
 ' INSERT INTO palaco_incident_witness.receipts',
 ' (namespace,sequence,nonce,handoff_digest,recipient_id)',
 ' SELECT namespace,sequence,$6,$7,$8 FROM advanced',
 ' RETURNING namespace,sequence,nonce,handoff_digest,recipient_id',
 '), evidence AS (',
 ' INSERT INTO palaco_incident_witness.receipt_evidence',
 ' (namespace,sequence,nonce,handoff_digest,recipient_id,',
 ' handoff,sender_signature,receipt,receipt_signature)',
 ' SELECT namespace,sequence,nonce,handoff_digest,recipient_id,',
 ' $9::jsonb,$10::jsonb,$11::jsonb,$12::jsonb FROM received',
 ' RETURNING namespace,sequence',
 '), committed AS (',
 ' INSERT INTO palaco_incident_witness.evidence_commitments',
 ' (namespace,sequence,evidence_digest)',
 ' SELECT namespace,sequence,$13 FROM evidence',
 ' RETURNING namespace,sequence,evidence_digest',
 ') SELECT a.sequence,a.incident_digest,r.nonce,c.evidence_digest',
 ' FROM advanced a JOIN received r ON a.namespace=r.namespace',
 ' AND a.sequence=r.sequence',
 ' JOIN committed c ON a.namespace=c.namespace AND a.sequence=c.sequence'
].join('\n');
function deny(code){return Object.freeze({
 readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
 mayAdvance:false,mayRestore:false,mayReconcile:false,
 maySynchronize:false,mayInstall:false,mayPublish:false,
 findings:Object.freeze([code])
});}
function createAtomicSignedEvidenceReceiver({namespace,query,trustPolicyProvider}={}){
 if(typeof trustPolicyProvider!=='function')
  throw new TypeError('Trusted recipient identity policy required');
 const witness=createIncidentExternalWitness({namespace,query});
 return Object.freeze({namespace,
  async receive(handoff,senderSignature,receipt,receiptSignature,signal){
   if(signal?.aborted)return deny('ATOMIC_RECEIPT_ABORTED');
   let policy;
   try{policy=await trustPolicyProvider(namespace,signal);}
   catch(_){return deny('ATOMIC_RECEIPT_POLICY_UNAVAILABLE');}
   if(signal?.aborted||!policy||!Number.isSafeInteger(policy.nowMs)||
     !policy.senderRoot||!policy.recipientRoot)
    return deny('ATOMIC_RECEIPT_POLICY_UNAVAILABLE');
   const previous=await witness.latest(signal);
   if(!previous||signal?.aborted)
    return deny('ATOMIC_RECEIPT_WITNESS_UNAVAILABLE');
   const proof=verifyIncidentWitnessHandoff(
    handoff,senderSignature,receipt,receiptSignature,{
     ...policy,namespace,previousSequence:previous.sequence,
     previousDigest:previous.digest
    });
   const full=evidenceDigest(handoff,senderSignature,receipt,receiptSignature);
   if(!full||
    proof.readiness!=='WITNESS_HANDOFF_RECEIPT_VERIFIED_NON_AUTHORIZING')
    return deny('ATOMIC_RECEIPT_PROOF_REJECTED');
   if(signal?.aborted)return deny('ATOMIC_RECEIPT_ABORTED');
   let result;
   try{
    result=await query({text:SQL,values:[
     namespace,previous.sequence,previous.digest,proof.sequence,
     proof.digest,proof.nonce,proof.handoffDigest,handoff.recipientId,
     JSON.stringify(handoff),JSON.stringify(senderSignature),
     JSON.stringify(receipt),JSON.stringify(receiptSignature),full
    ],signal});
   }catch(_){return deny('ATOMIC_RECEIPT_CAS_OR_STORAGE_REJECTED');}
   if(signal?.aborted||result?.rowCount!==1||
     !Array.isArray(result.rows)||result.rows.length!==1||
     String(result.rows[0].sequence)!==String(proof.sequence)||
     result.rows[0].incident_digest!==proof.digest||
     result.rows[0].nonce!==proof.nonce||
     result.rows[0].evidence_digest!==full)
    return deny('ATOMIC_RECEIPT_WRITE_UNCONFIRMED');
   return Object.freeze({
    readiness:'ATOMIC_SIGNED_RECEIPT_RECORDED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',sequence:proof.sequence,
    digest:proof.digest,evidenceDigest:full,mayAdvance:false,
    mayRestore:false,mayReconcile:false,maySynchronize:false,
    mayInstall:false,mayPublish:false,findings:Object.freeze([])
   });
  }
 });
}
module.exports={SQL,createAtomicSignedEvidenceReceiver};
