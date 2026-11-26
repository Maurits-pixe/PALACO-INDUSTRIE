'use strict';
// PALACO INDUSTRIE v5.2. Read-only cross-database incident classification.
// Observation never grants repair, synchronization or a transfer capability.
const {signedEvidenceChain,evidenceDigest,SELECT}=require('./signed-evidence-v5');
const {verifyIncidentWitnessHandoff,handoffDigest}=require('./incident-witness-handoff');
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const HEX=/^[a-f0-9]{64}$/;
const HEAD=[
 'SELECT sequence,chain_digest FROM palaco_signed_evidence_anchor.latest',
 'WHERE namespace=$1'
].join('\n');
const RECEIPT=[
 'SELECT sequence,nonce,handoff_digest,recipient_id',
 'FROM palaco_signed_evidence_anchor.transfer_receipts',
 'WHERE namespace=$1 AND sequence=$2'
].join('\n');
function result(state,reason,details={}){
 return Object.freeze({
  readiness:state,authorization:'DENY',go13:'HOLD',
  mayAdvance:false,mayRestore:false,mayReconcile:false,
  maySynchronize:false,mayInstall:false,mayPublish:false,
  findings:Object.freeze([reason]),...details
 });
}
function sequence(value,min=2){
 const n=Number(value);
 return /^[1-9][0-9]*$/.test(String(value))&&
  Number.isSafeInteger(n)&&n>=min?n:null;
}
function head(reply){
 if(!reply||reply.rowCount!==1||!Array.isArray(reply.rows)||
  reply.rows.length!==1)return null;
 const row=reply.rows[0],n=sequence(row?.sequence);
 return n&&HEX.test(row?.chain_digest||'')?
  {sequence:n,digest:row.chain_digest}:null;
}
function createEvidenceTransferReconciliationObserver({
 namespace,firstSequence,evidenceQuery,anchorQuery,historicalRootsProvider
}={}){
 if(!NS.test(namespace||'')||!Number.isSafeInteger(firstSequence)||
  firstSequence<2||typeof evidenceQuery!=='function'||
  typeof anchorQuery!=='function'||anchorQuery===evidenceQuery||
  typeof historicalRootsProvider!=='function')
  throw new TypeError('Independent read-only sources and historical trust roots required');
 return Object.freeze({namespace,
  async inspect(signal){
   if(signal?.aborted)return result('BLOCKED','TRANSFER_INSPECTION_ABORTED');
   let archive,anchor;
   try{
    [archive,anchor]=await Promise.all([
     evidenceQuery({text:SELECT,values:[namespace],signal}),
     anchorQuery({text:HEAD,values:[namespace],signal})
    ]);
   }catch(_){return result('BLOCKED','TRANSFER_SOURCE_UNAVAILABLE');}
   if(signal?.aborted)return result('BLOCKED','TRANSFER_INSPECTION_ABORTED');
   if(!archive||!Array.isArray(archive.rows)||
    archive.rowCount!==archive.rows.length)
    return result('BLOCKED','TRANSFER_SOURCE_UNAVAILABLE');
   const external=head(anchor);
   if(!external)return result('BLOCKED','TRANSFER_ANCHOR_UNAVAILABLE');
   const whole=signedEvidenceChain(archive.rows,{namespace,firstSequence});
   if(!whole)return result('BLOCKED','TRANSFER_ARCHIVE_INVALID');
   let previous=null;
   for(const row of archive.rows){
    if(signal?.aborted)return result('BLOCKED','TRANSFER_INSPECTION_ABORTED');
    const h=row.handoff,r=row.receipt;
    if(!h||!r||h.namespace!==namespace||
     h.nextSequence!==sequence(row.sequence,firstSequence)||
     h.nonce!==row.nonce||h.recipientId!==row.recipient_id||
     handoffDigest(h)!==row.handoff_digest||
     r.handoffDigest!==row.handoff_digest||
     previous&&(h.previousSequence!==previous.nextSequence||
      h.previousDigest!==previous.nextDigest))
     return result('BLOCKED','TRANSFER_SIGNED_LINEAGE_INVALID');
    const digest=evidenceDigest(h,row.sender_signature,r,row.receipt_signature);
    if(!digest||digest!==row.evidence_digest)
     return result('BLOCKED','TRANSFER_EVIDENCE_DIGEST_INVALID');
    let roots;
    try{roots=await historicalRootsProvider(namespace,Number(row.sequence),signal);}
    catch(_){return result('BLOCKED','TRANSFER_HISTORIC_TRUST_UNAVAILABLE');}
    if(signal?.aborted||!roots)
     return result('BLOCKED','TRANSFER_HISTORIC_TRUST_UNAVAILABLE');
    const proof=verifyIncidentWitnessHandoff(h,row.sender_signature,
     r,row.receipt_signature,{
      namespace,previousSequence:h.previousSequence,
      previousDigest:h.previousDigest,nowMs:r.acceptedAtMs,
      senderRoot:roots.senderRoot,recipientRoot:roots.recipientRoot
     });
    if(proof.readiness!=='WITNESS_HANDOFF_RECEIPT_VERIFIED_NON_AUTHORIZING')
     return result('BLOCKED','TRANSFER_HISTORIC_SIGNATURE_INVALID');
    previous=h;
   }
   if(external.sequence<firstSequence)
    return result('BLOCKED','TRANSFER_ANCHOR_BEFORE_PINNED_GENESIS');
   const prefix=archive.rows.slice(0,external.sequence-firstSequence+1);
   const proven=signedEvidenceChain(prefix,{namespace,firstSequence});
   if(!proven||external.digest!==proven.digest)
    return result('BLOCKED',external.sequence>whole.sequence?
     'TRANSFER_EXTERNAL_AHEAD_OR_ARCHIVE_RESTORED':'TRANSFER_ANCHOR_FORK_OR_CORRUPTION');
   // A head with no receipt indicates an unconfirmed external anchor,
   // regardless of matching data. The initial genesis root has no handoff.
   if(external.sequence>firstSequence){
    let ack;
    try{ack=await anchorQuery({text:RECEIPT,
      values:[namespace,external.sequence],signal});}
    catch(_){return result('BLOCKED','TRANSFER_RECEIPT_SOURCE_UNAVAILABLE');}
    if(signal?.aborted)return result('BLOCKED','TRANSFER_INSPECTION_ABORTED');
    const row=ack?.rowCount===1&&ack.rows?.length===1?ack.rows[0]:null;
    if(!row||sequence(row.sequence)!==external.sequence||
      typeof row.nonce!=='string'||!/(?:^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$)/.test(row.nonce)||
      !HEX.test(row.handoff_digest||'')||
      typeof row.recipient_id!=='string'||row.recipient_id.length<1)
     return result('BLOCKED','TRANSFER_RECEIPT_MISSING_OR_INVALID');
   }
   if(whole.sequence===external.sequence)
    return result('MATCHED_NON_AUTHORIZING','TRANSFER_CONFIRMED_READ_ONLY',
     {sequence:external.sequence,chainDigest:external.digest});
   if(whole.sequence===external.sequence+1)
    return result('SOURCE_AHEAD_HOLD','TRANSFER_PARTIAL_SOURCE_COMMITTED',
     {sourceSequence:whole.sequence,anchorSequence:external.sequence,
      sourceDigest:whole.digest,anchorDigest:external.digest});
   return result('BLOCKED','TRANSFER_MULTIPLE_UNANCHORED_STEPS');
  }
 });
}
module.exports={HEAD,RECEIPT,createEvidenceTransferReconciliationObserver};
