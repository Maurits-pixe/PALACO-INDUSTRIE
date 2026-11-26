'use strict';
// v4.8 — Verify the entire ordered receipt history against a separately
// pinned monotonic root. Read-only, not an ingestion or recovery capability.
const {createHash}=require('node:crypto');
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const HEX=/^[a-f0-9]{64}$/;
const ZERO='0'.repeat(64);
const SELECT_RECEIPTS=[
 'SELECT sequence,nonce,handoff_digest,recipient_id',
 'FROM palaco_incident_witness.receipts',
 'WHERE namespace=$1 ORDER BY sequence ASC'
].join('\n');
const SELECT_ROOT=[
 'SELECT sequence,chain_digest FROM palaco_receipt_anchor.latest',
 'WHERE namespace=$1'
].join('\n');
function denied(code){
 return Object.freeze({readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
  mayRestore:false,mayAdvance:false,mayReconcile:false,maySynchronize:false,
  mayInstall:false,mayPublish:false,findings:Object.freeze([code])});
}
function receiptChain(entries,{namespace,firstSequence}={}){
 if(!NS.test(namespace||'')||!Number.isSafeInteger(firstSequence)||
  firstSequence<2||!Array.isArray(entries)||entries.length===0||
  entries.length>10000)return null;
 let previous=ZERO,sequence=firstSequence-1;
 const nonces=new Set(),handoffs=new Set(),ids=new Set();
 for(const row of entries){
  if(!row||typeof row!=='object'||Array.isArray(row)||
     !/^[1-9][0-9]*$/.test(String(row.sequence))||
     !ID.test(row.nonce||'')||!ID.test(row.recipient_id||'')||
     !HEX.test(row.handoff_digest||''))return null;
  const next=Number(row.sequence);
  if(!Number.isSafeInteger(next)||next!==sequence+1||
   nonces.has(row.nonce)||handoffs.has(row.handoff_digest))return null;
  nonces.add(row.nonce);handoffs.add(row.handoff_digest);ids.add(row.recipient_id);
  const payload=Buffer.from([
   'PALACO-INDUSTRIE-RECEIPT-SUCCESSION-V1',namespace,
   String(next),row.nonce,row.handoff_digest,row.recipient_id,
   previous,''
  ].join('\n'),'utf8');
  previous=createHash('sha256').update(payload).digest('hex');
  sequence=next;
 }
 return Object.freeze({sequence,digest:previous,count:entries.length});
}
function decodeRoot(result){
 if(!result||result.rowCount!==1||!Array.isArray(result.rows)||
  result.rows.length!==1)return null;
 const row=result.rows[0],seq=Number(row?.sequence);
 return /^[1-9][0-9]*$/.test(String(row?.sequence))&&
  Number.isSafeInteger(seq)&&seq>=2&&HEX.test(row?.chain_digest||'')?
  {sequence:seq,digest:row.chain_digest}:null;
}
function createReceiptSuccessionVerifier({
 namespace,archiveQuery,anchorQuery,firstSequence
}={}){
 if(!NS.test(namespace||'')||typeof archiveQuery!=='function'||
  typeof anchorQuery!=='function'||archiveQuery===anchorQuery||
  !Number.isSafeInteger(firstSequence)||firstSequence<2)
  throw new TypeError('Distinct receipt and anchored-root providers required');
 const verifier={
  namespace,
  async verify(signal){
   if(signal?.aborted)return denied('RECEIPT_CHAIN_ABORTED');
   let receipts,anchor;
   try{
    [receipts,anchor]=await Promise.all([
     archiveQuery({text:SELECT_RECEIPTS,values:[namespace],signal}),
     anchorQuery({text:SELECT_ROOT,values:[namespace],signal})
    ]);
   }catch(_){return denied('RECEIPT_CHAIN_SOURCE_UNAVAILABLE');}
   if(signal?.aborted||!receipts||!Array.isArray(receipts.rows)||
    !Number.isSafeInteger(receipts.rowCount)||
    receipts.rowCount!==receipts.rows.length)
    return denied('RECEIPT_CHAIN_SOURCE_UNAVAILABLE');
   const chain=receiptChain(receipts.rows,{namespace,firstSequence});
   if(!chain)return denied('RECEIPT_CHAIN_INVALID');
   const root=decodeRoot(anchor);
   if(!root)return denied('RECEIPT_ANCHOR_UNAVAILABLE');
   if(chain.sequence!==root.sequence||chain.digest!==root.digest)
    return denied('RECEIPT_CHAIN_ANCHOR_MISMATCH');
   return Object.freeze({
    readiness:'RECEIPT_SUCCESSION_VERIFIED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',sequence:chain.sequence,
    chainDigest:chain.digest,count:chain.count,
    mayRestore:false,mayAdvance:false,mayReconcile:false,
    maySynchronize:false,mayInstall:false,mayPublish:false,
    findings:Object.freeze([])
   });
  }
 };
 return Object.freeze(verifier);
}
module.exports={ZERO,SELECT_RECEIPTS,SELECT_ROOT,receiptChain,
 createReceiptSuccessionVerifier};
