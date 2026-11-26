'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {handoffPayload,receiptPayload,handoffDigest}=
 require('../distribution/incident-witness-handoff');
const {evidenceDigest,signedEvidenceChain}=
 require('../distribution/signed-evidence-v5');
const {createEvidenceTransferReconciliationObserver}=
 require('../distribution/evidence-transfer-reconciliation-v5.2');
function fixture(){
 const namespace='palaco.v52ci';
 const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
 const roots={
  senderRoot:{identityId:'issuer',keyId:'issuer-k',enabled:true,revoked:false,
   publicKeyPem:keys[0].publicKey.export({type:'spki',format:'pem'})},
  recipientRoot:{identityId:'custodian',keyId:'custodian-k',enabled:true,
   revoked:false,publicKeyPem:keys[1].publicKey.export({type:'spki',format:'pem'})}
 };
 function record(seq,prior,next){
  const h={schemaVersion:'palaco.distribution.incident-witness-handoff.v1',
   namespace,senderId:'issuer',recipientId:'custodian',
   nonce:'nonce-'+seq,previousSequence:seq-1,previousDigest:prior,
   nextSequence:seq,nextDigest:next,issuedAtMs:1000,expiresAtMs:5000,
   authorization:'DENY',go13:'HOLD',purpose:'EVIDENCE_ONLY_NO_RELEASE'};
  const r={schemaVersion:'palaco.distribution.incident-witness-receipt.v1',
   namespace,recipientId:'custodian',nonce:h.nonce,
   handoffDigest:handoffDigest(h),acceptedAtMs:2000,
   acknowledgement:'EVIDENCE_RECEIVED_NO_AUTHORITY'};
  const signed=(bytes,index,keyId)=>({algorithm:'Ed25519',keyId,
   signature:sign(null,bytes,keys[index].privateKey).toString('base64')});
  const sender_signature=signed(handoffPayload(h),0,'issuer-k');
  const receipt_signature=signed(receiptPayload(r),1,'custodian-k');
  return {sequence:String(seq),nonce:h.nonce,
   handoff_digest:handoffDigest(h),recipient_id:'custodian',
   evidence_digest:evidenceDigest(h,sender_signature,r,receipt_signature),
   handoff:h,receipt:r,sender_signature,receipt_signature};
 }
 const rows=[record(11,'a'.repeat(64),'b'.repeat(64)),
  record(12,'b'.repeat(64),'c'.repeat(64)),
  record(13,'c'.repeat(64),'d'.repeat(64))];
 const rootAt=n=>signedEvidenceChain(rows.slice(0,n-10),{
  namespace,firstSequence:11});
 const ctx=(n=12,archive=rows.slice(0,2),options={})=>
  createEvidenceTransferReconciliationObserver({
   namespace,firstSequence:11,
   evidenceQuery:async()=>({rowCount:archive.length,rows:archive}),
   anchorQuery:async request=>request.text.includes('transfer_receipts')?
    {rowCount:1,rows:[{sequence:String(n),nonce:'anchor-'+n,
     handoff_digest:'e'.repeat(64),recipient_id:'custodian'}]}:
    {rowCount:1,rows:[{sequence:String(n),chain_digest:rootAt(n).digest}]},
   historicalRootsProvider:async()=>roots,...options
  });
 return {rows,roots,rootAt,ctx,namespace};
}
test('matched verified archive and signed external receipt remains DENY HOLD',async()=>{
 const f=fixture(),out=await f.ctx().inspect();
 assert.equal(out.readiness,'MATCHED_NON_AUTHORIZING');
 assert.equal(out.authorization,'DENY');assert.equal(out.go13,'HOLD');
 assert.equal(out.mayReconcile,false);assert.equal(out.mayRestore,false);
});
test('source ahead one is classified as partial transfer, never auto-resumed',async()=>{
 const f=fixture(),out=await f.ctx(12,f.rows).inspect();
 assert.equal(out.readiness,'SOURCE_AHEAD_HOLD');
 assert.equal(out.findings[0],'TRANSFER_PARTIAL_SOURCE_COMMITTED');
 assert.equal(out.mayAdvance,false);assert.equal(out.maySynchronize,false);
});
test('restored primary, forked anchor and two missing steps remain blocked',async()=>{
 const f=fixture();
 const restored=await f.ctx(13,f.rows.slice(0,2)).inspect();
 assert.equal(restored.readiness,'BLOCKED');
 assert.equal(restored.findings[0],'TRANSFER_EXTERNAL_AHEAD_OR_ARCHIVE_RESTORED');
 const fork=await f.ctx(12,f.rows.slice(0,2),{
  anchorQuery:async()=>({rowCount:1,rows:[{
   sequence:'12',chain_digest:'f'.repeat(64)}]})
 }).inspect();
 assert.equal(fork.findings[0],'TRANSFER_ANCHOR_FORK_OR_CORRUPTION');
 const two=await f.ctx(11,f.rows).inspect();
 assert.equal(two.findings[0],'TRANSFER_MULTIPLE_UNANCHORED_STEPS');
});
test('missing external receipt and unavailable sources block even when heads match',async()=>{
 const f=fixture();
 for(const override of [
  {anchorQuery:async req=>req.text.includes('transfer_receipts')?
   {rowCount:0,rows:[]}:{rowCount:1,rows:[{
    sequence:'12',chain_digest:f.rootAt(12).digest}]}},
  {anchorQuery:async()=>{throw Error('offline');}},
  {evidenceQuery:async()=>{throw Error('offline');}},
  {historicalRootsProvider:async()=>{throw Error('no keys');}}
 ]){
  const out=await f.ctx(12,f.rows.slice(0,2),override).inspect();
  assert.equal(out.readiness,'BLOCKED');
 }
});
test('damaged historical signatures and changed signed history cannot be treated as partial',async()=>{
 const f=fixture();
 const broken=structuredClone(f.rows);
 broken[2].receipt_signature.signature='A'.repeat(86)+'==';
 assert.equal((await f.ctx(12,broken).inspect()).readiness,'BLOCKED');
 const changed=structuredClone(f.rows);
 changed[2].handoff.previousDigest='f'.repeat(64);
 assert.equal((await f.ctx(12,changed).inspect()).readiness,'BLOCKED');
});
test('abort and indistinct query providers cannot create a recovery privilege',async()=>{
 const f=fixture(),a=new AbortController();a.abort();
 assert.equal((await f.ctx().inspect(a.signal)).readiness,'BLOCKED');
 const query=async()=>({});
 assert.throws(()=>createEvidenceTransferReconciliationObserver({
  namespace:f.namespace,firstSequence:11,evidenceQuery:query,
  anchorQuery:query,historicalRootsProvider:async()=>f.roots
 }),TypeError);
 assert.equal(typeof f.ctx().reconcile,'undefined');
});
