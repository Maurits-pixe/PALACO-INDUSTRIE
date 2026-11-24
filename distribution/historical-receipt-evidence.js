'use strict';
// v4.9: full historical cryptographic re-verification against anchored
// receipt metadata. Evidence only; no authority, repair or distribution.
const {verifyIncidentWitnessHandoff,handoffDigest}=
 require('./incident-witness-handoff');
const {receiptChain}=require('./receipt-succession-verifier');

const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const HEX=/^[a-f0-9]{64}$/;
const SELECT=[
 'SELECT r.sequence,r.nonce,r.handoff_digest,r.recipient_id,',
 'e.handoff,e.sender_signature,e.receipt,e.receipt_signature',
 'FROM palaco_incident_witness.receipts r',
 'LEFT JOIN palaco_incident_witness.receipt_evidence e',
 ' ON e.namespace=r.namespace AND e.sequence=r.sequence',
 'WHERE r.namespace=$1 ORDER BY r.sequence ASC'
].join('\n');
const ROOT=[
 'SELECT sequence,chain_digest FROM palaco_receipt_anchor.latest',
 'WHERE namespace=$1'
].join('\n');
const INSERT=[
 'INSERT INTO palaco_incident_witness.receipt_evidence',
 '(namespace,sequence,nonce,handoff_digest,recipient_id,',
 ' handoff,sender_signature,receipt,receipt_signature)',
 'SELECT r.namespace,r.sequence,r.nonce,r.handoff_digest,r.recipient_id,',
 '$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb',
 'FROM palaco_incident_witness.receipts r',
 'WHERE r.namespace=$1 AND r.sequence=$2 AND r.nonce=$3',
 ' AND r.handoff_digest=$4 AND r.recipient_id=$5',
 'RETURNING sequence,handoff_digest'
].join('\n');
function deny(reason){
 return Object.freeze({readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
  mayAdvance:false,mayRestore:false,mayReconcile:false,
  maySynchronize:false,mayInstall:false,mayPublish:false,
  findings:Object.freeze([reason])});
}
function validAnchor(result){
 if(!result||result.rowCount!==1||!Array.isArray(result.rows)||
   result.rows.length!==1)return null;
 const r=result.rows[0],sequence=Number(r?.sequence);
 return /^[1-9][0-9]*$/.test(String(r?.sequence))&&
  Number.isSafeInteger(sequence)&&sequence>=2&&HEX.test(r.chain_digest||'')?
  {sequence,digest:r.chain_digest}:null;
}
function validateRecord(r,namespace,roots,maximumLifetimeMs){
 if(!r||!r.handoff||!r.receipt||!r.sender_signature||!r.receipt_signature||
    !roots||typeof roots!=='object'||Array.isArray(roots))return false;
 const h=r.handoff,receipt=r.receipt,sequence=Number(r.sequence);
 if(!Number.isSafeInteger(sequence)||h.namespace!==namespace||
    h.nextSequence!==sequence||h.nonce!==r.nonce||
    h.recipientId!==r.recipient_id||
    handoffDigest(h)!==r.handoff_digest||
    receipt.handoffDigest!==r.handoff_digest)return false;
 const proof=verifyIncidentWitnessHandoff(
  h,r.sender_signature,receipt,r.receipt_signature,{
   namespace,previousSequence:h.previousSequence,
   previousDigest:h.previousDigest,
   // Archival validity is checked at signed receipt time, not today's date.
   nowMs:receipt.acceptedAtMs,maximumLifetimeMs,
   senderRoot:roots.senderRoot,recipientRoot:roots.recipientRoot
  });
 return proof.readiness==='WITNESS_HANDOFF_RECEIPT_VERIFIED_NON_AUTHORIZING';
}
function createHistoricalReceiptVerifier({
 namespace,firstSequence,receiptQuery,anchorQuery,
 historicalRootsProvider,maximumLifetimeMs=86400000
}={}){
 if(!NS.test(namespace||'')||!Number.isSafeInteger(firstSequence)||
   firstSequence<2||typeof receiptQuery!=='function'||
   typeof anchorQuery!=='function'||receiptQuery===anchorQuery||
   typeof historicalRootsProvider!=='function'||
   !Number.isSafeInteger(maximumLifetimeMs)||maximumLifetimeMs<1||
   maximumLifetimeMs>86400000)
  throw new TypeError('Independent historical roots and anchored queries required');
 return Object.freeze({namespace,
  async verify(signal){
   if(signal?.aborted)return deny('HISTORICAL_RECEIPTS_ABORTED');
   let evidence,anchor;
   try{
    [evidence,anchor]=await Promise.all([
     receiptQuery({text:SELECT,values:[namespace],signal}),
     anchorQuery({text:ROOT,values:[namespace],signal})
    ]);
   }catch(_){return deny('HISTORICAL_RECEIPTS_SOURCE_UNAVAILABLE');}
   if(signal?.aborted||!evidence||!Array.isArray(evidence.rows)||
     evidence.rowCount!==evidence.rows.length)
    return deny('HISTORICAL_RECEIPTS_SOURCE_UNAVAILABLE');
   const chain=receiptChain(evidence.rows,{namespace,firstSequence});
   if(!chain)return deny('HISTORICAL_RECEIPTS_CHAIN_INVALID');
   const root=validAnchor(anchor);
   if(!root)return deny('HISTORICAL_RECEIPTS_ANCHOR_UNAVAILABLE');
   if(root.sequence!==chain.sequence||root.digest!==chain.digest)
    return deny('HISTORICAL_RECEIPTS_ANCHOR_MISMATCH');
   for(const row of evidence.rows){
    if(signal?.aborted)return deny('HISTORICAL_RECEIPTS_ABORTED');
    let roots;
    try{
     roots=await historicalRootsProvider(namespace,Number(row.sequence),signal);
    }catch(_){return deny('HISTORICAL_RECEIPTS_ROOTS_UNAVAILABLE');}
    if(signal?.aborted||!roots)
     return deny('HISTORICAL_RECEIPTS_ROOTS_UNAVAILABLE');
    if(!validateRecord(row,namespace,roots,maximumLifetimeMs))
     return deny('HISTORICAL_RECEIPTS_SIGNATURE_OR_BINDING_INVALID');
   }
   return Object.freeze({
    readiness:'HISTORICAL_RECEIPTS_VERIFIED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',
    sequence:chain.sequence,chainDigest:chain.digest,
    verifiedSignatures:chain.count*2,count:chain.count,
    mayAdvance:false,mayRestore:false,mayReconcile:false,
    maySynchronize:false,mayInstall:false,mayPublish:false,
    findings:Object.freeze([])
   });
  }
 });
}
/**
 * Trusted backfill only. Signatures verified BEFORE any write; immutable
 * INSERT..SELECT binds evidence to the existing nonce/sequence/digest.
 */
function createHistoricalReceiptArchiver({
 namespace,query,historicalRootsProvider,maximumLifetimeMs=86400000
}={}){
 if(!NS.test(namespace||'')||typeof query!=='function'||
    typeof historicalRootsProvider!=='function')
  throw new TypeError('Trusted historical receipt archive required');
 return Object.freeze({namespace,
  async archive(handoff,senderSignature,receipt,receiptSignature,signal){
   if(signal?.aborted||!handoff||handoff.namespace!==namespace)
    return deny('HISTORICAL_ARCHIVE_INVALID_INPUT');
   const sequence=handoff.nextSequence,digest=handoffDigest(handoff);
   if(!digest||!receipt||!Number.isSafeInteger(sequence))
    return deny('HISTORICAL_ARCHIVE_INVALID_INPUT');
   let roots;
   try{roots=await historicalRootsProvider(namespace,sequence,signal);}
   catch(_){return deny('HISTORICAL_ARCHIVE_ROOTS_UNAVAILABLE');}
   if(signal?.aborted||!roots)return deny('HISTORICAL_ARCHIVE_ROOTS_UNAVAILABLE');
   const row={sequence,nonce:handoff.nonce,handoff_digest:digest,
    recipient_id:handoff.recipientId,handoff,sender_signature:senderSignature,
    receipt,receipt_signature:receiptSignature};
   if(!validateRecord(row,namespace,roots,maximumLifetimeMs))
    return deny('HISTORICAL_ARCHIVE_SIGNATURE_INVALID');
   let reply;
   try{
    reply=await query({text:INSERT,values:[
     namespace,sequence,handoff.nonce,digest,handoff.recipientId,
     JSON.stringify(handoff),JSON.stringify(senderSignature),
     JSON.stringify(receipt),JSON.stringify(receiptSignature)
    ],signal});
   }catch(_){return deny('HISTORICAL_ARCHIVE_INSERT_REJECTED');}
   if(signal?.aborted||reply?.rowCount!==1||!Array.isArray(reply.rows)||
    reply.rows.length!==1||
    String(reply.rows[0].sequence)!==String(sequence)||
    reply.rows[0].handoff_digest!==digest)
    return deny('HISTORICAL_ARCHIVE_WRITE_UNCONFIRMED');
   return Object.freeze({
    readiness:'HISTORICAL_RECEIPT_ARCHIVED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',sequence,digest,
    mayAdvance:false,mayRestore:false,mayReconcile:false,
    maySynchronize:false,mayInstall:false,mayPublish:false,
    findings:Object.freeze([])
   });
  }
 });
}
module.exports={SELECT,ROOT,INSERT,createHistoricalReceiptVerifier,
 createHistoricalReceiptArchiver};
