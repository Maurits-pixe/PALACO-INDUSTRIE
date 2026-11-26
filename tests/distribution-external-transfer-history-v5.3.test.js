'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {handoffBytes,handoffDigest,receiptBytes}=
 require('../distribution/signed-evidence-anchor-handoff-v5.1');
const {createExternalTransferHistoryVerifier}=
 require('../distribution/external-transfer-history-v5.3');
const namespace='palaco.registry',genesis='a'.repeat(64);
function fixture(){
 const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
 const roots={
  senderRoot:{identityId:'issuer',keyId:'issuer-key',enabled:true,revoked:false,
   publicKeyPem:keys[0].publicKey.export({type:'spki',format:'pem'})},
  recipientRoot:{identityId:'custodian',keyId:'custodian-key',enabled:true,revoked:false,
   publicKeyPem:keys[1].publicKey.export({type:'spki',format:'pem'})}
 };
 const record=(sequence,previousDigest,nextDigest)=>{
  const h={schemaVersion:'palaco.distribution.signed-evidence-anchor-handoff.v1',
   namespace,senderId:'issuer',recipientId:'custodian',nonce:'handoff-'+sequence,
   previousSequence:sequence-1,previousDigest,nextSequence:sequence,nextDigest,
   issuedAtMs:1000,expiresAtMs:5000,authorization:'DENY',go13:'HOLD',
   purpose:'SIGNED_EVIDENCE_ANCHOR_ONLY'};
  const r={schemaVersion:'palaco.distribution.signed-evidence-anchor-receipt.v1',
   namespace,recipientId:'custodian',nonce:h.nonce,
   handoffDigest:handoffDigest(h),acceptedAtMs:1500,
   acknowledgement:'ANCHOR_RECEIVED_NO_AUTHORITY'};
  const signed=(bytes,i,keyId)=>({algorithm:'Ed25519',keyId,
   signature:sign(null,bytes,keys[i].privateKey).toString('base64')});
  return {sequence:String(sequence),nonce:h.nonce,
   handoff_digest:handoffDigest(h),recipient_id:'custodian',
   handoff:h,recipient_receipt:r,
   sender_signature:signed(handoffBytes(h),0,'issuer-key'),
   receipt_signature:signed(receiptBytes(r),1,'custodian-key')};
 };
 const rows=[record(12,genesis,'b'.repeat(64)),
  record(13,'b'.repeat(64),'c'.repeat(64))];
 const build=(items=rows,head={sequence:'13',chain_digest:'c'.repeat(64)},
  historicalRootsProvider=async()=>roots,override={})=>
  createExternalTransferHistoryVerifier({
   namespace,genesisSequence:11,genesisDigest:genesis,
   anchorQuery:async request=>request.text.includes('transfer_receipts')?
    {rowCount:items.length,rows:items}:
    {rowCount:1,rows:[head]},
   historicalRootsProvider,...override
  });
 return {roots,rows,build};
}
test('every original issuer and recipient signature is reverified, never authorizing',async()=>{
 const f=fixture(),r=await f.build().verify();
 assert.equal(r.readiness,'EXTERNAL_TRANSFER_HISTORY_VERIFIED_NON_AUTHORIZING');
 assert.equal(r.count,2);assert.equal(r.verifiedSignatures,4);
 assert.equal(r.authorization,'DENY');assert.equal(r.go13,'HOLD');
 assert.equal(r.mayRestore,false);assert.equal(r.mayAdvance,false);
});
test('missing dossier or corrupted signature fails closed even if final head matches',async()=>{
 const f=fixture();
 for(const change of [
  row=>{row.handoff=null;},
  row=>{row.recipient_receipt=null;},
  row=>{row.sender_signature.signature='A'.repeat(86)+'==';},
  row=>{row.receipt_signature.signature='A'.repeat(86)+'==';},
  row=>{row.recipient_receipt.acceptedAtMs=6000;},
  row=>{row.recipient_id='other-custodian';}
 ]){
  const rows=structuredClone(f.rows);
  change(rows[1]);
  assert.equal((await f.build(rows).verify()).readiness,'BLOCKED');
 }
});
test('skipped sequence, changed predecessor or replayed nonce is blocked',async()=>{
 const f=fixture();
 for(const change of [
  rows=>rows.splice(0,1),
  rows=>{rows[1].sequence='14';},
  rows=>{rows[1].handoff.previousDigest='f'.repeat(64);},
  rows=>{rows[1].nonce=rows[0].nonce;}
 ]){
  const rows=structuredClone(f.rows);change(rows);
  assert.equal((await f.build(rows).verify()).readiness,'BLOCKED');
 }
});
test('external root rollback or digest fork is blocked',async()=>{
 const f=fixture();
 for(const head of [
  {sequence:'12',chain_digest:'b'.repeat(64)},
  {sequence:'13',chain_digest:'f'.repeat(64)},
  {sequence:'14',chain_digest:'d'.repeat(64)}
 ]){
  const r=await f.build(f.rows,head).verify();
  assert.deepEqual(r.findings,['EXTERNAL_HISTORY_ANCHOR_ROLLBACK_OR_FORK']);
 }
});
test('unavailable source, invalid historical keys, abort and no write methods',async()=>{
 const f=fixture();
 const offline=f.build(f.rows,undefined,async()=>{throw Error('historical keys offline');});
 assert.deepEqual((await offline.verify()).findings,['EXTERNAL_HISTORY_ROOTS_UNAVAILABLE']);
 const revoked=f.build(f.rows,undefined,async()=>({
  senderRoot:{...f.roots.senderRoot,revoked:true},
  recipientRoot:f.roots.recipientRoot
 }));
 assert.equal((await revoked.verify()).readiness,'BLOCKED');
 const source=f.build(f.rows,undefined,undefined,{
  anchorQuery:async()=>{throw Error('database offline');}
 });
 assert.deepEqual((await source.verify()).findings,['EXTERNAL_HISTORY_SOURCE_UNAVAILABLE']);
 const abort=new AbortController();abort.abort();
 assert.equal((await f.build().verify(abort.signal)).readiness,'BLOCKED');
 assert.equal(f.build().repair,undefined);
 assert.equal(f.build().query,undefined);
});
test('invalid independent genesis and missing trust adapter rejected',()=>{
 assert.throws(()=>createExternalTransferHistoryVerifier({
  namespace,genesisSequence:11,genesisDigest:'invalid',
  anchorQuery:async()=>({}),historicalRootsProvider:async()=>({})
 }),TypeError);
 assert.throws(()=>createExternalTransferHistoryVerifier({
  namespace,genesisSequence:11,genesisDigest:genesis,
  anchorQuery:async()=>({})
 }),TypeError);
});
