'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {handoffBytes,handoffDigest,receiptBytes,
 verifySignedEvidenceAnchorTransfer}=
 require('../distribution/signed-evidence-anchor-handoff-v5.1');
const {signedEvidenceChain}=require('../distribution/signed-evidence-v5');
const {createSignedEvidenceAnchorReceiver}=
 require('../distribution/signed-evidence-anchor-receiver-v5.1');
function fixture(){
 const namespace='palaco.registry';
 const rows=[
  {sequence:'11',nonce:'nonce11',handoff_digest:'a'.repeat(64),
   recipient_id:'custodian',evidence_digest:'c'.repeat(64)},
  {sequence:'12',nonce:'nonce12',handoff_digest:'b'.repeat(64),
   recipient_id:'custodian',evidence_digest:'d'.repeat(64)}
 ];
 const prev=signedEvidenceChain(rows.slice(0,1),{namespace,firstSequence:11});
 const next=signedEvidenceChain(rows,{namespace,firstSequence:11});
 const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
 const roots={
  senderRoot:{identityId:'issuer',keyId:'issuer-key',enabled:true,
   revoked:false,publicKeyPem:keys[0].publicKey.export({type:'spki',format:'pem'})},
  recipientRoot:{identityId:'custodian',keyId:'custodian-key',enabled:true,
   revoked:false,publicKeyPem:keys[1].publicKey.export({type:'spki',format:'pem'})}
 };
 const h={schemaVersion:'palaco.distribution.signed-evidence-anchor-handoff.v1',
  namespace,senderId:'issuer',recipientId:'custodian',nonce:'transfer-12',
  previousSequence:11,previousDigest:prev.digest,
  nextSequence:12,nextDigest:next.digest,issuedAtMs:1000,
  expiresAtMs:5000,authorization:'DENY',go13:'HOLD',
  purpose:'SIGNED_EVIDENCE_ANCHOR_ONLY'};
 const r={schemaVersion:'palaco.distribution.signed-evidence-anchor-receipt.v1',
  namespace,recipientId:'custodian',nonce:h.nonce,handoffDigest:handoffDigest(h),
  acceptedAtMs:1500,acknowledgement:'ANCHOR_RECEIVED_NO_AUTHORITY'};
 const sig=(payload,i,keyId)=>({algorithm:'Ed25519',keyId,
  signature:sign(null,payload,keys[i].privateKey).toString('base64')});
 const s=sig(handoffBytes(h),0,'issuer-key');
 const ack=sig(receiptBytes(r),1,'custodian-key');
 const policy={namespace,previousSequence:11,previousDigest:prev.digest,
  nowMs:2000,...roots};
 return {namespace,rows,prev,next,roots,h,r,s,ack,policy};
}
test('two signatures verify a bound full-evidence anchor receipt without release',()=>{
 const f=fixture();
 const result=verifySignedEvidenceAnchorTransfer(f.h,f.s,f.r,f.ack,f.policy);
 assert.equal(result.readiness,'EVIDENCE_ANCHOR_TRANSFER_VERIFIED_NON_AUTHORIZING');
 assert.equal(result.authorization,'DENY');assert.equal(result.go13,'HOLD');
 assert.equal(result.mayAdvance,false);assert.equal(result.mayPublish,false);
});
test('tampering, swapped custodian, replay and expiry always block',()=>{
 const mutations=[
  f=>{f.h.nextDigest='e'.repeat(64);},
  f=>{f.r.nonce='other';},
  f=>{f.r.handoffDigest='f'.repeat(64);},
  f=>{f.r.recipientId='other';},
  f=>{f.policy.previousSequence=10;},
  f=>{f.policy.nowMs=5000;},
  f=>{f.policy.recipientRoot.revoked=true;},
  f=>{f.ack.signature=f.s.signature;},
  f=>{f.h.purpose='AUTHORIZE_RELEASE';}
 ];
 for(const mutate of mutations){
  const f=fixture();mutate(f);
  const result=verifySignedEvidenceAnchorTransfer(f.h,f.s,f.r,f.ack,f.policy);
  assert.equal(result.readiness,'BLOCKED');assert.equal(result.authorization,'DENY');
 }
});
test('receiver only writes after signed full-evidence chain matches and receipt is genuine',async()=>{
 const f=fixture();let head={sequence:11,digest:f.prev.digest},writes=0;
 const source=async()=>({rowCount:f.rows.length,rows:f.rows});
 const anchor=async req=>{
  if(req.text.startsWith('SELECT'))return {rowCount:1,rows:[{
   sequence:String(head.sequence),chain_digest:head.digest
  }]};
  writes++;
  if(head.sequence!==req.values[1]||head.digest!==req.values[2])
   return {rowCount:0,rows:[]};
  head={sequence:req.values[3],digest:req.values[4]};
  return {rowCount:1,rows:[{
   sequence:String(head.sequence),chain_digest:head.digest,nonce:req.values[5]
  }]};
 };
 const receiver=createSignedEvidenceAnchorReceiver({
  namespace:f.namespace,firstSequence:11,evidenceQuery:source,anchorQuery:anchor,
  trustPolicyProvider:async()=>f.policy
 });
 assert.equal(typeof receiver.query,'undefined');
 const one=await receiver.receive(f.h,f.s,f.r,f.ack);
 assert.equal(one.readiness,'EVIDENCE_ANCHOR_RECEIPT_RECORDED_NON_AUTHORIZING');
 assert.equal(one.mayAdvance,false);assert.equal(writes,1);
 const repeat=await receiver.receive(f.h,f.s,f.r,f.ack);
 assert.equal(repeat.readiness,'BLOCKED');assert.equal(writes,1);
});
test('unavailable external anchor, missing archive and stale primary block without write',async()=>{
 const f=fixture();
 for(const option of [
  {anchorQuery:async()=>{throw Error('offline');}},
  {evidenceQuery:async()=>{throw Error('offline');}},
  {evidenceQuery:async()=>({rowCount:1,rows:f.rows.slice(0,1)})},
  {anchorQuery:async()=>({rowCount:0,rows:[]})}
 ]){
  let writes=0;
  const receiver=createSignedEvidenceAnchorReceiver({
   namespace:f.namespace,firstSequence:11,
   evidenceQuery:async()=>({rowCount:2,rows:f.rows}),
   anchorQuery:async req=>{
    if(!req.text.startsWith('SELECT'))writes++;
    return {rowCount:1,rows:[{sequence:'11',chain_digest:f.prev.digest}]};
   },
   trustPolicyProvider:async()=>f.policy,...option
  });
  assert.equal((await receiver.receive(f.h,f.s,f.r,f.ack)).readiness,'BLOCKED');
  assert.equal(writes,0);
 }
});
test('external database conflict or unconfirmed atomic write never returns success',async()=>{
 const f=fixture();
 for(const response of [
  null,{rowCount:0,rows:[]},
  {rowCount:1,rows:[{sequence:'12',chain_digest:'f'.repeat(64),nonce:f.h.nonce}]}
 ]){
  const receiver=createSignedEvidenceAnchorReceiver({
   namespace:f.namespace,firstSequence:11,
   evidenceQuery:async()=>({rowCount:2,rows:f.rows}),
   anchorQuery:async req=>req.text.startsWith('SELECT')?
    {rowCount:1,rows:[{sequence:'11',chain_digest:f.prev.digest}]}:response,
   trustPolicyProvider:async()=>f.policy
  });
  assert.equal((await receiver.receive(f.h,f.s,f.r,f.ack)).readiness,'BLOCKED');
 }
});
