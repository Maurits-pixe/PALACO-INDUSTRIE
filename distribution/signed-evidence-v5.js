'use strict';
// v5.0: hash the COMPLETE signed handoff and receipt, not metadata alone.
const {createHash}=require('node:crypto');
const {handoffPayload,receiptPayload,handoffDigest,
 verifyIncidentWitnessHandoff}=require('./incident-witness-handoff');
const {receiptChain}=require('./receipt-succession-verifier');
const HEX=/^[a-f0-9]{64}$/;
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const ZERO='0'.repeat(64);
function evidenceDigest(handoff,senderSignature,receipt,receiptSignature){
 const a=handoffPayload(handoff),b=receiptPayload(receipt);
 if(!a||!b)return null;
 const signatures=[senderSignature,receiptSignature];
 for(const s of signatures){
  if(!s||s.algorithm!=='Ed25519'||typeof s.keyId!=='string'||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(s.keyId)||
    typeof s.signature!=='string'||
    !/^[A-Za-z0-9+/]{86}==$/.test(s.signature)||
    Buffer.from(s.signature,'base64').toString('base64')!==s.signature)
   return null;
 }
 return createHash('sha256').update(Buffer.concat([
  Buffer.from('PALACO-INDUSTRIE-SIGNED-RECEIPT-EVIDENCE-V5\n'),
  a,Buffer.from('\n'),b,Buffer.from('\n'),
  Buffer.from(signatures.map(s=>s.keyId+'\n'+s.signature+'\n').join(''))
 ])).digest('hex');
}
function signedEvidenceChain(rows,{namespace,firstSequence}={}){
 if(!NS.test(namespace||'')||!Array.isArray(rows)||rows.length<1||
   rows.length>10000||!Number.isSafeInteger(firstSequence)||
   firstSequence<2||!receiptChain(rows,{namespace,firstSequence}))return null;
 let previous=ZERO;
 for(const r of rows){
  if(!HEX.test(r.evidence_digest||''))return null;
  previous=createHash('sha256').update([
   'PALACO-INDUSTRIE-SIGNED-EVIDENCE-SUCCESSION-V5',
   namespace,String(r.sequence),r.handoff_digest,r.evidence_digest,
   previous,''
  ].join('\n')).digest('hex');
 }
 return Object.freeze({sequence:Number(rows.at(-1).sequence),
  digest:previous,count:rows.length});
}
function denied(reason){return Object.freeze({
 readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
 mayAdvance:false,mayRestore:false,mayReconcile:false,
 maySynchronize:false,mayInstall:false,mayPublish:false,
 findings:Object.freeze([reason])
});}
const SELECT=[
 'SELECT r.sequence,r.nonce,r.handoff_digest,r.recipient_id,',
 'e.handoff,e.sender_signature,e.receipt,e.receipt_signature,',
 'c.evidence_digest',
 'FROM palaco_incident_witness.receipts r',
 'LEFT JOIN palaco_incident_witness.receipt_evidence e',
 ' ON e.namespace=r.namespace AND e.sequence=r.sequence',
 'LEFT JOIN palaco_incident_witness.evidence_commitments c',
 ' ON c.namespace=r.namespace AND c.sequence=r.sequence',
 'WHERE r.namespace=$1 ORDER BY r.sequence ASC'
].join('\n');
const ROOT=[
 'SELECT sequence,chain_digest FROM palaco_signed_evidence_anchor.latest',
 'WHERE namespace=$1'
].join('\n');
function createSignedEvidenceVerifier({
 namespace,firstSequence,evidenceQuery,anchorQuery,historicalRootsProvider
}={}){
 if(!NS.test(namespace||'')||!Number.isSafeInteger(firstSequence)||
   firstSequence<2||typeof evidenceQuery!=='function'||
   typeof anchorQuery!=='function'||evidenceQuery===anchorQuery||
   typeof historicalRootsProvider!=='function')
   throw new TypeError('Separate signed evidence root and historical trust roots required');
 return Object.freeze({namespace,
  async verify(signal){
   if(signal?.aborted)return denied('SIGNED_EVIDENCE_ABORTED');
   let records,root;
   try{[records,root]=await Promise.all([
    evidenceQuery({text:SELECT,values:[namespace],signal}),
    anchorQuery({text:ROOT,values:[namespace],signal})
   ]);}catch(_){return denied('SIGNED_EVIDENCE_SOURCE_UNAVAILABLE');}
   if(signal?.aborted||!records||!Array.isArray(records.rows)||
     records.rowCount!==records.rows.length)
    return denied('SIGNED_EVIDENCE_SOURCE_UNAVAILABLE');
   const chain=signedEvidenceChain(records.rows,{namespace,firstSequence});
   if(!chain)return denied('SIGNED_EVIDENCE_CHAIN_INVALID');
   const anchor=root?.rowCount===1&&root.rows?.length===1?root.rows[0]:null;
   if(!anchor||String(anchor.sequence)!==String(chain.sequence)||
     !HEX.test(anchor.chain_digest||'')||anchor.chain_digest!==chain.digest)
    return denied('SIGNED_EVIDENCE_ANCHOR_MISMATCH');
   let previous=null;
   for(const r of records.rows){
    if(signal?.aborted)return denied('SIGNED_EVIDENCE_ABORTED');
    const h=r.handoff,t=r.receipt;
    if(!h||!t||h.namespace!==namespace||
      h.nextSequence!==Number(r.sequence)||
      h.recipientId!==r.recipient_id||h.nonce!==r.nonce||
      handoffDigest(h)!==r.handoff_digest||
      t.handoffDigest!==r.handoff_digest||
      (previous&&(h.previousSequence!==previous.nextSequence||
        h.previousDigest!==previous.nextDigest)))
      return denied('SIGNED_EVIDENCE_LINEAGE_INVALID');
    const digest=evidenceDigest(h,r.sender_signature,t,r.receipt_signature);
    if(!digest||digest!==r.evidence_digest)
      return denied('SIGNED_EVIDENCE_DIGEST_MISMATCH');
    let roots;
    try{roots=await historicalRootsProvider(namespace,Number(r.sequence),signal);}
    catch(_){return denied('SIGNED_EVIDENCE_ROOTS_UNAVAILABLE');}
    if(signal?.aborted||!roots)
      return denied('SIGNED_EVIDENCE_ROOTS_UNAVAILABLE');
    const result=verifyIncidentWitnessHandoff(h,r.sender_signature,t,r.receipt_signature,{
     namespace,previousSequence:h.previousSequence,previousDigest:h.previousDigest,
     nowMs:t.acceptedAtMs,senderRoot:roots.senderRoot,
     recipientRoot:roots.recipientRoot
    });
    if(result.readiness!=='WITNESS_HANDOFF_RECEIPT_VERIFIED_NON_AUTHORIZING')
      return denied('SIGNED_EVIDENCE_SIGNATURE_INVALID');
    previous=h;
   }
   return Object.freeze({readiness:'SIGNED_EVIDENCE_HISTORY_VERIFIED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',sequence:chain.sequence,
    chainDigest:chain.digest,count:chain.count,
    verifiedSignatures:chain.count*2,mayAdvance:false,
    mayRestore:false,mayReconcile:false,maySynchronize:false,
    mayInstall:false,mayPublish:false,findings:Object.freeze([])
   });
  }
 });
}
module.exports={evidenceDigest,signedEvidenceChain,SELECT,ROOT,
 createSignedEvidenceVerifier};
