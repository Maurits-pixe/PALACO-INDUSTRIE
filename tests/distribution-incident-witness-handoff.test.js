'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {handoffPayload,handoffDigest,receiptPayload,
 verifyIncidentWitnessHandoff}=
 require('../distribution/incident-witness-handoff');
const {createIncidentWitnessHandoffReceiver}=
 require('../distribution/incident-witness-handoff-receiver');
function fixture(){
 const sender=generateKeyPairSync('ed25519');
 const recipient=generateKeyPairSync('ed25519');
 const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
 const handoff={
  schemaVersion:'palaco.distribution.incident-witness-handoff.v1',
  namespace:'palaco.registry',senderId:'issuer',recipientId:'witness',
  nonce:'unique-nonce-1',previousSequence:10,previousDigest:'a'.repeat(64),
  nextSequence:11,nextDigest:'b'.repeat(64),
  issuedAtMs:1000,expiresAtMs:5000,authorization:'DENY',go13:'HOLD',
  purpose:'EVIDENCE_ONLY_NO_RELEASE'
 };
 const receipt={
  schemaVersion:'palaco.distribution.incident-witness-receipt.v1',
  namespace:'palaco.registry',recipientId:'witness',
  nonce:handoff.nonce,handoffDigest:handoffDigest(handoff),
  acceptedAtMs:1200,acknowledgement:'EVIDENCE_RECEIVED_NO_AUTHORITY'
 };
 const signature=(payload,keys,id)=>({algorithm:'Ed25519',keyId:id,
  signature:sign(null,payload,keys.privateKey).toString('base64')});
 const senderSignature=signature(handoffPayload(handoff),sender,'sender-key');
 const receiptSignature=signature(receiptPayload(receipt),recipient,'recipient-key');
 const policy={namespace:'palaco.registry',
  previousSequence:10,previousDigest:'a'.repeat(64),nowMs:1300,
  senderRoot:{identityId:'issuer',keyId:'sender-key',enabled:true,revoked:false,
   publicKeyPem:pem(sender)},
  recipientRoot:{identityId:'witness',keyId:'recipient-key',enabled:true,revoked:false,
   publicKeyPem:pem(recipient)}
 };
 return {handoff,receipt,senderSignature,receiptSignature,policy,sender,recipient};
}
const verify=f=>verifyIncidentWitnessHandoff(
 f.handoff,f.senderSignature,f.receipt,f.receiptSignature,f.policy);
test('issuer and recipient signatures attest receipt without authority',()=>{
 const f=fixture(),r=verify(f);
 assert.equal(r.readiness,'WITNESS_HANDOFF_RECEIPT_VERIFIED_NON_AUTHORIZING');
 assert.equal(r.authorization,'DENY');assert.equal(r.go13,'HOLD');
 assert.equal(r.mayAdvance,false);assert.equal(r.mayPublish,false);
 assert.equal(r.handoffDigest,handoffDigest(f.handoff));
});
test('modified handoff, receiver, nonce and receipt are rejected',()=>{
 for(const mutate of [
  f=>{f.handoff.nextDigest='c'.repeat(64);},
  f=>{f.handoff.nonce='replay-other';},
  f=>{f.receipt.recipientId='wrong';},
  f=>{f.receipt.nonce='mismatched';},
  f=>{f.receipt.handoffDigest='f'.repeat(64);},
  f=>{f.receipt.acceptedAtMs=1500;},
  f=>{f.handoff.purpose='RELEASE';}
 ]){
  const f=fixture();mutate(f);
  assert.equal(verify(f).readiness,'BLOCKED');
 }
});
test('key mismatch, revoked root, missing second signature and forged receipt fail',()=>{
 for(const mutate of [
  f=>{f.policy.recipientRoot.revoked=true;},
  f=>{f.policy.recipientRoot.publicKeyPem=f.policy.senderRoot.publicKeyPem;},
  f=>{f.policy.recipientRoot.identityId='other';},
  f=>{f.receiptSignature.signature=f.senderSignature.signature;},
  f=>{f.senderSignature=null;},
  f=>{f.policy.senderRoot.enabled=false;}
 ]){
  const f=fixture();mutate(f);
  assert.equal(verify(f).readiness,'BLOCKED');
 }
});
test('old anchor, expired signature and impossible lifetime are denied',()=>{
 for(const mutate of [
  f=>{f.policy.previousSequence=9;},
  f=>{f.policy.previousDigest='f'.repeat(64);},
  f=>{f.policy.nowMs=5000;},
  f=>{f.policy.nowMs=999;},
  f=>{f.policy.maximumLifetimeMs=20;}
 ]){
  const f=fixture();mutate(f);
  assert.equal(verify(f).readiness,'BLOCKED');
 }
});
test('receiver does not expose raw SQL and denies replay or missing policy',async()=>{
 const f=fixture();
 const state={sequence:10,digest:'a'.repeat(64)},nonces=new Set();
 const calls=[];
 const query=async({text,values})=>{
  calls.push(text);
  if(text.startsWith('SELECT'))return {rowCount:1,
   rows:[{sequence:String(state.sequence),incident_digest:state.digest}]};
  if(!text.startsWith('WITH advanced'))throw Error('unauthorized query');
  const [namespace,prevSeq,prevHash,nextSeq,nextHash,nonce]=values;
  if(nonces.has(nonce)||state.sequence!==prevSeq||state.digest!==prevHash)
   return {rowCount:0,rows:[]};
  state.sequence=nextSeq;state.digest=nextHash;nonces.add(nonce);
  return {rowCount:1,rows:[{sequence:String(nextSeq),incident_digest:nextHash,nonce}]};
 };
 const receiver=createIncidentWitnessHandoffReceiver({
  namespace:'palaco.registry',query,trustPolicyProvider:async()=>f.policy
 });
 assert.equal(typeof receiver.query,'undefined');
 assert.equal(typeof receiver.advance,'undefined');
 const args=[f.handoff,f.senderSignature,f.receipt,f.receiptSignature];
 const accepted=await receiver.receive(...args);
 assert.equal(accepted.readiness,'WITNESS_RECEIPT_RECORDED_NON_AUTHORIZING');
 assert.equal(accepted.mayAdvance,false);assert.equal(accepted.go13,'HOLD');
 assert.equal(state.sequence,11);
 const replay=await receiver.receive(...args);
 assert.deepEqual(replay.findings,['WITNESS_RECEIVER_PROOF_REJECTED']);
 assert.equal(nonces.size,1);
 assert.equal(calls.filter(x=>x.startsWith('WITH advanced')).length,1);
 const absent=createIncidentWitnessHandoffReceiver({
  namespace:'palaco.registry',query,trustPolicyProvider:async()=>null
 });
 assert.deepEqual((await absent.receive(...args)).findings,
  ['WITNESS_RECEIVER_POLICY_UNAVAILABLE']);
});
