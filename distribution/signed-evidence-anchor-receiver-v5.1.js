'use strict';
// v5.3 opt-in extension: verify primary full signed-evidence chain before independently
// recording a recipient-signed external root acknowledgement.
// This is a trusted process adapter, not a public service or release gate.
const {signedEvidenceChain,evidenceDigest,SELECT}=require('./signed-evidence-v5');
const {verifyIncidentWitnessHandoff,handoffDigest}=require('./incident-witness-handoff');
const {verifySignedEvidenceAnchorTransfer}=
 require('./signed-evidence-anchor-handoff-v5.1');
const HEX=/^[a-f0-9]{64}$/;
const HEAD=[
 'SELECT sequence,chain_digest FROM palaco_signed_evidence_anchor.latest',
 'WHERE namespace=$1'
].join('\n');
const CAS=[
 'WITH advanced AS (',
 ' UPDATE palaco_signed_evidence_anchor.latest',
 ' SET sequence=$4,chain_digest=$5',
 ' WHERE namespace=$1 AND sequence=$2 AND chain_digest=$3',
 ' AND sequence+1=$4 AND chain_digest<>$5',
 ' RETURNING namespace,sequence,chain_digest',
 '), recorded AS (',
 ' INSERT INTO palaco_signed_evidence_anchor.transfer_receipts',
 ' (namespace,sequence,nonce,handoff_digest,recipient_id,',
 ' sender_signature,receipt_signature)',
 ' SELECT namespace,sequence,$6,$7,$8,$9::jsonb,$10::jsonb',
 ' FROM advanced RETURNING namespace,sequence,nonce',
 '), dossier AS (',
 ' INSERT INTO palaco_signed_evidence_anchor.transfer_dossiers',
 ' (namespace,sequence,nonce,handoff_digest,handoff,recipient_receipt)',
 ' SELECT r.namespace,r.sequence,r.nonce,$7,$11::jsonb,$12::jsonb',
 ' FROM recorded r',
 ' RETURNING namespace,sequence',
 ') SELECT a.sequence,a.chain_digest,r.nonce',
 ' FROM advanced a JOIN recorded r',
 ' ON a.namespace=r.namespace AND a.sequence=r.sequence',
 ' JOIN dossier d ON a.namespace=d.namespace AND a.sequence=d.sequence'
].join('\n');
function denied(reason){return Object.freeze({
 readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
 mayAdvance:false,mayRestore:false,mayReconcile:false,
 maySynchronize:false,mayInstall:false,mayPublish:false,
 findings:Object.freeze([reason])
});}
function parseHead(reply){
 if(!reply||reply.rowCount!==1||reply.rows?.length!==1)return null;
 const row=reply.rows[0],sequence=Number(row.sequence);
 if(!/^[1-9][0-9]*$/.test(String(row.sequence))||
  !Number.isSafeInteger(sequence)||sequence<2||
  !HEX.test(row.chain_digest||''))return null;
 return {sequence,digest:row.chain_digest};
}
function createSignedEvidenceAnchorReceiver({
 namespace,firstSequence,evidenceQuery,anchorQuery,trustPolicyProvider,
 historicalRootsProvider
}={}){
 if(typeof namespace!=='string'||!/^[a-z][a-z0-9._-]{2,79}$/.test(namespace)||
 !Number.isSafeInteger(firstSequence)||firstSequence<2||
 typeof evidenceQuery!=='function'||typeof anchorQuery!=='function'||
 evidenceQuery===anchorQuery||typeof trustPolicyProvider!=='function'||
 typeof historicalRootsProvider!=='function')
 throw new TypeError('Separate evidence store, witness and protected trust policy required');
 return Object.freeze({namespace,
  async receive(h,sig,r,ack,signal){
   if(signal?.aborted)return denied('EVIDENCE_ANCHOR_ABORTED');
   let policy,head,stored;
   try{
    [policy,head,stored]=await Promise.all([
     trustPolicyProvider(namespace,signal),
     anchorQuery({text:HEAD,values:[namespace],signal}),
     evidenceQuery({text:SELECT,values:[namespace],signal})
    ]);
   }catch(_){return denied('EVIDENCE_ANCHOR_SOURCE_UNAVAILABLE');}
   if(signal?.aborted||!policy||!Number.isSafeInteger(policy.nowMs))
    return denied('EVIDENCE_ANCHOR_POLICY_UNAVAILABLE');
   const previous=parseHead(head);
   if(!previous)return denied('EVIDENCE_ANCHOR_HEAD_UNAVAILABLE');
   if(!stored||!Array.isArray(stored.rows)||
     stored.rowCount!==stored.rows.length)
    return denied('EVIDENCE_ANCHOR_ARCHIVE_UNAVAILABLE');
   const full=signedEvidenceChain(stored.rows,{namespace,firstSequence});
   if(!full)return denied('EVIDENCE_ANCHOR_ARCHIVE_INVALID');
   let predecessor=null;
   for(const row of stored.rows){
    if(signal?.aborted)return denied('EVIDENCE_ANCHOR_ABORTED');
    const signed=row.handoff,received=row.receipt;
    if(!signed||!received||signed.namespace!==namespace||
       signed.nextSequence!==Number(row.sequence)||
       signed.nonce!==row.nonce||signed.recipientId!==row.recipient_id||
       handoffDigest(signed)!==row.handoff_digest||
       received.handoffDigest!==row.handoff_digest||
       (predecessor&&(signed.previousSequence!==predecessor.nextSequence||
         signed.previousDigest!==predecessor.nextDigest)))
      return denied('EVIDENCE_ANCHOR_SIGNED_HISTORY_INVALID');
    const bytes=evidenceDigest(signed,row.sender_signature,received,
       row.receipt_signature);
    if(!bytes||bytes!==row.evidence_digest)
      return denied('EVIDENCE_ANCHOR_SIGNED_HISTORY_INVALID');
    let roots;
    try{
     roots=await historicalRootsProvider(namespace,Number(row.sequence),signal);
    }catch(_){return denied('EVIDENCE_ANCHOR_HISTORIC_ROOTS_UNAVAILABLE');}
    if(signal?.aborted||!roots)
      return denied('EVIDENCE_ANCHOR_HISTORIC_ROOTS_UNAVAILABLE');
    const verified=verifyIncidentWitnessHandoff(signed,
      row.sender_signature,received,row.receipt_signature,{
       namespace,previousSequence:signed.previousSequence,
       previousDigest:signed.previousDigest,nowMs:received.acceptedAtMs,
       senderRoot:roots.senderRoot,recipientRoot:roots.recipientRoot
      });
    if(verified.readiness!=='WITNESS_HANDOFF_RECEIPT_VERIFIED_NON_AUTHORIZING')
     return denied('EVIDENCE_ANCHOR_HISTORIC_SIGNATURE_INVALID');
    predecessor=signed;
   }
   if(!h||full.sequence!==h.nextSequence||full.digest!==h.nextDigest)
    return denied('EVIDENCE_ANCHOR_ARCHIVE_MISMATCH');
   const proof=verifySignedEvidenceAnchorTransfer(h,sig,r,ack,{
    ...policy,namespace,previousSequence:previous.sequence,
    previousDigest:previous.digest
   });
   if(proof.readiness!=='EVIDENCE_ANCHOR_TRANSFER_VERIFIED_NON_AUTHORIZING')
    return denied('EVIDENCE_ANCHOR_TRANSFER_REJECTED');
   if(signal?.aborted)return denied('EVIDENCE_ANCHOR_ABORTED');
   let result;
   try{
    result=await anchorQuery({text:CAS,values:[
     namespace,previous.sequence,previous.digest,
     proof.sequence,proof.digest,proof.nonce,proof.handoffDigest,
     h.recipientId,JSON.stringify(sig),JSON.stringify(ack),
     JSON.stringify(h),JSON.stringify(r)
    ],signal});
   }catch(_){return denied('EVIDENCE_ANCHOR_CAS_OR_REPLAY_REJECTED');}
   if(signal?.aborted||result?.rowCount!==1||result.rows?.length!==1||
    String(result.rows[0].sequence)!==String(proof.sequence)||
    result.rows[0].chain_digest!==proof.digest||
    result.rows[0].nonce!==proof.nonce)
    return denied('EVIDENCE_ANCHOR_WRITE_UNCONFIRMED');
   return Object.freeze({
    readiness:'EVIDENCE_ANCHOR_RECEIPT_RECORDED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',sequence:proof.sequence,
    digest:proof.digest,handoffDigest:proof.handoffDigest,
    mayAdvance:false,mayRestore:false,mayReconcile:false,
    maySynchronize:false,mayInstall:false,mayPublish:false,
    findings:Object.freeze([])
   });
  }
 });
}
module.exports={HEAD,CAS,createSignedEvidenceAnchorReceiver};
