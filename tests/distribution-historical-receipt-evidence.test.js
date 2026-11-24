'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {handoffPayload,handoffDigest,receiptPayload}=
 require('../distribution/incident-witness-handoff');
const {receiptChain}=require('../distribution/receipt-succession-verifier');
const {createHistoricalReceiptVerifier,createHistoricalReceiptArchiver}=
 require('../distribution/historical-receipt-evidence');
const namespace='palaco.registry';
function fixture(){
 const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
 const roots={
  senderRoot:{identityId:'sender',keyId:'sender-key',enabled:true,
   revoked:false,publicKeyPem:keys[0].publicKey.export({type:'spki',format:'pem'})},
  recipientRoot:{identityId:'receiver',keyId:'receiver-key',enabled:true,
   revoked:false,publicKeyPem:keys[1].publicKey.export({type:'spki',format:'pem'})}
 };
 function make(sequence,oldHash,newHash){
  const handoff={schemaVersion:'palaco.distribution.incident-witness-handoff.v1',
   namespace,senderId:'sender',recipientId:'receiver',nonce:'nonce-'+sequence,
   previousSequence:sequence-1,previousDigest:oldHash,nextSequence:sequence,
   nextDigest:newHash,issuedAtMs:1000,expiresAtMs:2000,
   authorization:'DENY',go13:'HOLD',purpose:'EVIDENCE_ONLY_NO_RELEASE'};
  const receipt={schemaVersion:'palaco.distribution.incident-witness-receipt.v1',
   namespace,recipientId:'receiver',nonce:handoff.nonce,
   handoffDigest:handoffDigest(handoff),acceptedAtMs:1200,
   acknowledgement:'EVIDENCE_RECEIVED_NO_AUTHORITY'};
  const signature=(payload,index,keyId)=>({
   algorithm:'Ed25519',keyId,
   signature:sign(null,payload,keys[index].privateKey).toString('base64')
  });
  return {sequence,nonce:handoff.nonce,handoff_digest:handoffDigest(handoff),
   recipient_id:'receiver',handoff,
   sender_signature:signature(handoffPayload(handoff),0,'sender-key'),
   receipt,receipt_signature:signature(receiptPayload(receipt),1,'receiver-key')};
 }
 const rows=[make(11,'a'.repeat(64),'b'.repeat(64)),
  make(12,'b'.repeat(64),'c'.repeat(64))];
 const head=receiptChain(rows,{namespace,firstSequence:11});
 const provider=async()=>roots;
 const verifier=(records=rows,root=head,extra={})=>
  createHistoricalReceiptVerifier({
   namespace,firstSequence:11,
   receiptQuery:async()=>({rowCount:records.length,rows:records}),
   anchorQuery:async()=>({rowCount:1,rows:[{
    sequence:String(root.sequence),chain_digest:root.digest
   }]}),historicalRootsProvider:provider,...extra
  });
 return {rows,roots,provider,head,verifier};
}
test('valid historical signatures reverify at receipt time, not current time',async()=>{
 const f=fixture();
 const r=await f.verifier().verify();
 assert.equal(r.readiness,'HISTORICAL_RECEIPTS_VERIFIED_NON_AUTHORIZING');
 assert.equal(r.verifiedSignatures,4);assert.equal(r.count,2);
 assert.equal(r.authorization,'DENY');assert.equal(r.go13,'HOLD');
 assert.equal(r.mayPublish,false);assert.equal(r.mayRestore,false);
});
test('missing evidence or forged historic Ed25519 signature blocks despite anchored metadata',async()=>{
 const f=fixture();
 for(const mutate of [
  row=>{row.handoff=null;},
  row=>{row.sender_signature.signature='A'.repeat(86)+'==';},
  row=>{row.receipt_signature.signature='A'.repeat(86)+'==';},
  row=>{row.receipt.acceptedAtMs=3000;},
  row=>{row.handoff.nextDigest='f'.repeat(64);},
  row=>{row.receipt.recipientId='intruder';}
 ]){
  const rows=structuredClone(f.rows);
  mutate(rows[1]);
  const result=await f.verifier(rows).verify();
  assert.deepEqual(result.findings,
   ['HISTORICAL_RECEIPTS_SIGNATURE_OR_BINDING_INVALID']);
 }
});
test('truncated archive and forged metadata blocked by external root',async()=>{
 const f=fixture();
 const truncated=await f.verifier([f.rows[0]]).verify();
 assert.deepEqual(truncated.findings,['HISTORICAL_RECEIPTS_ANCHOR_MISMATCH']);
 const rows=structuredClone(f.rows);rows[1].nonce='different-nonce';
 assert.deepEqual((await f.verifier(rows).verify()).findings,
  ['HISTORICAL_RECEIPTS_ANCHOR_MISMATCH']);
});
test('revoked/missing historical roots and failed provider block verification',async()=>{
 const f=fixture();
 const revoked=await f.verifier(f.rows,f.head,{
  historicalRootsProvider:async()=>({...f.roots,
   senderRoot:{...f.roots.senderRoot,revoked:true}})
 }).verify();
 assert.deepEqual(revoked.findings,
  ['HISTORICAL_RECEIPTS_SIGNATURE_OR_BINDING_INVALID']);
 const offline=await f.verifier(f.rows,f.head,{
  historicalRootsProvider:async()=>{throw Error('offline');}
 }).verify();
 assert.deepEqual(offline.findings,['HISTORICAL_RECEIPTS_ROOTS_UNAVAILABLE']);
});
test('trusted evidence archiver verifies and never exposes arbitrary UPDATE or delete',async()=>{
 const f=fixture(),rows=[],queries=[];
 const query=async request=>{
  queries.push(request);
  if(!request.text.startsWith('INSERT'))throw Error('not permitted');
  const [scope,seq,nonce,digest,recipient,h,sig,r,ack]=request.values;
  rows.push({scope,seq,nonce,digest,recipient,h,sig,r,ack});
  return {rowCount:1,rows:[{sequence:String(seq),handoff_digest:digest}]};
 };
 const archiver=createHistoricalReceiptArchiver({
  namespace,query,historicalRootsProvider:f.provider
 });
 const e=f.rows[0];
 const result=await archiver.archive(
  e.handoff,e.sender_signature,e.receipt,e.receipt_signature);
 assert.equal(result.readiness,'HISTORICAL_RECEIPT_ARCHIVED_NON_AUTHORIZING');
 assert.equal(result.authorization,'DENY');assert.equal(result.mayAdvance,false);
 assert.equal(rows.length,1);
 assert.equal(archiver.query,undefined);assert.equal(archiver.update,undefined);
 const altered=structuredClone(f.rows[1]);
 altered.receipt_signature.signature='A'.repeat(86)+'==';
 assert.equal((await archiver.archive(altered.handoff,altered.sender_signature,
  altered.receipt,altered.receipt_signature)).readiness,'BLOCKED');
 assert.equal(rows.length,1);
});
test('archive loss, abort and ambiguous insertion reject without privilege',async()=>{
 const f=fixture(),e=f.rows[0];
 for(const query of [
  async()=>{throw Error('offline');},
  async()=>({rowCount:0,rows:[]})
 ]){
  const archiver=createHistoricalReceiptArchiver({
   namespace,query,historicalRootsProvider:f.provider
  });
  const r=await archiver.archive(
   e.handoff,e.sender_signature,e.receipt,e.receipt_signature);
  assert.equal(r.readiness,'BLOCKED');assert.equal(r.authorization,'DENY');
 }
 const controller=new AbortController();controller.abort();
 assert.equal((await f.verifier().verify(controller.signal)).readiness,'BLOCKED');
});
