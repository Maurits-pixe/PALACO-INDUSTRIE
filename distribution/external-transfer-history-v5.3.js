'use strict';
// v5.3: independent read-only re-verification of complete signed external
// transfer dossiers; no synchronization, recovery or release capability.
const {verifySignedEvidenceAnchorTransfer,handoffDigest}=
 require('./signed-evidence-anchor-handoff-v5.1');
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const HEX=/^[a-f0-9]{64}$/;
const SELECT=[
 'SELECT r.sequence,r.nonce,r.handoff_digest,r.recipient_id,',
 'r.sender_signature,r.receipt_signature,',
 'd.handoff,d.recipient_receipt',
 'FROM palaco_signed_evidence_anchor.transfer_receipts r',
 'LEFT JOIN palaco_signed_evidence_anchor.transfer_dossiers d',
 ' ON d.namespace=r.namespace AND d.sequence=r.sequence',
 'WHERE r.namespace=$1 ORDER BY r.sequence ASC'
].join('\n');
const HEAD=[
 'SELECT sequence,chain_digest FROM palaco_signed_evidence_anchor.latest',
 'WHERE namespace=$1'
].join('\n');
function blocked(reason){return Object.freeze({
 readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
 mayAdvance:false,mayRestore:false,mayReconcile:false,
 maySynchronize:false,mayInstall:false,mayPublish:false,
 findings:Object.freeze([reason])
});}
function parseHead(reply){
 if(!reply||reply.rowCount!==1||reply.rows?.length!==1)return null;
 const r=reply.rows[0],n=Number(r.sequence);
 return /^[1-9][0-9]*$/.test(String(r.sequence))&&
 Number.isSafeInteger(n)&&n>=2&&HEX.test(r.chain_digest||'')?
 {sequence:n,digest:r.chain_digest}:null;
}
function createExternalTransferHistoryVerifier({
 namespace,genesisSequence,genesisDigest,anchorQuery,
 historicalRootsProvider,maxAgeMs=86400000
}={}){
 if(!NS.test(namespace||'')||!Number.isSafeInteger(genesisSequence)||
 genesisSequence<2||!HEX.test(genesisDigest||'')||
 typeof anchorQuery!=='function'||typeof historicalRootsProvider!=='function'||
 !Number.isSafeInteger(maxAgeMs)||maxAgeMs<1||maxAgeMs>86400000)
 throw new TypeError('Pinned genesis, trusted historical roots and external reader required');
 return Object.freeze({namespace,
  async verify(signal){
   if(signal?.aborted)return blocked('EXTERNAL_HISTORY_ABORTED');
   let records,anchor;
   try{
    [records,anchor]=await Promise.all([
     anchorQuery({text:SELECT,values:[namespace],signal}),
     anchorQuery({text:HEAD,values:[namespace],signal})
    ]);
   }catch(_){return blocked('EXTERNAL_HISTORY_SOURCE_UNAVAILABLE');}
   if(signal?.aborted)return blocked('EXTERNAL_HISTORY_ABORTED');
   if(!records||!Array.isArray(records.rows)||
    records.rowCount!==records.rows.length||
    records.rows.length<1||records.rows.length>10000)
    return blocked('EXTERNAL_HISTORY_MISSING_OR_OVERSIZED');
   const root=parseHead(anchor);
   if(!root)return blocked('EXTERNAL_HISTORY_ANCHOR_UNAVAILABLE');
   let priorSeq=genesisSequence,priorDigest=genesisDigest;
   const nonces=new Set(),handoffs=new Set();
   for(const row of records.rows){
    if(signal?.aborted)return blocked('EXTERNAL_HISTORY_ABORTED');
    const h=row.handoff,r=row.recipient_receipt;
    const next=Number(row.sequence);
    if(!h||!r||!/^[1-9][0-9]*$/.test(String(row.sequence))||
      !Number.isSafeInteger(next)||next!==priorSeq+1||
      h.nextSequence!==next||h.previousSequence!==priorSeq||
      h.previousDigest!==priorDigest||
      h.namespace!==namespace||r.namespace!==namespace||
      h.nonce!==row.nonce||h.recipientId!==row.recipient_id||
      r.nonce!==row.nonce||r.recipientId!==row.recipient_id||
      !HEX.test(row.handoff_digest||'')||
      handoffDigest(h)!==row.handoff_digest||
      r.handoffDigest!==row.handoff_digest||
      nonces.has(row.nonce)||handoffs.has(row.handoff_digest))
      return blocked('EXTERNAL_HISTORY_LINEAGE_OR_BINDING_INVALID');
    let roots;
    try{roots=await historicalRootsProvider(namespace,next,signal);}
    catch(_){return blocked('EXTERNAL_HISTORY_ROOTS_UNAVAILABLE');}
    if(signal?.aborted||!roots)
      return blocked('EXTERNAL_HISTORY_ROOTS_UNAVAILABLE');
    const proof=verifySignedEvidenceAnchorTransfer(
     h,row.sender_signature,r,row.receipt_signature,{
      namespace,previousSequence:priorSeq,previousDigest:priorDigest,
      // Reverify based on originally signed recipient time, not wall clock.
      nowMs:r.acceptedAtMs,senderRoot:roots.senderRoot,
      recipientRoot:roots.recipientRoot,maxAgeMs
     });
    if(proof.readiness!=='EVIDENCE_ANCHOR_TRANSFER_VERIFIED_NON_AUTHORIZING')
      return blocked('EXTERNAL_HISTORY_SIGNATURE_INVALID');
    nonces.add(row.nonce);handoffs.add(row.handoff_digest);
    priorSeq=next;priorDigest=h.nextDigest;
   }
   if(root.sequence!==priorSeq||root.digest!==priorDigest)
    return blocked('EXTERNAL_HISTORY_ANCHOR_ROLLBACK_OR_FORK');
   return Object.freeze({
    readiness:'EXTERNAL_TRANSFER_HISTORY_VERIFIED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',sequence:priorSeq,
    digest:priorDigest,verifiedSignatures:records.rows.length*2,
    count:records.rows.length,mayAdvance:false,mayRestore:false,
    mayReconcile:false,maySynchronize:false,
    mayInstall:false,mayPublish:false,findings:Object.freeze([])
   });
  }
 });
}
module.exports={SELECT,HEAD,createExternalTransferHistoryVerifier};
