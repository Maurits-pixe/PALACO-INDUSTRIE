'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {handoffPayload,handoffDigest,receiptPayload}=
 require('../distribution/incident-witness-handoff');
const {evidenceDigest,signedEvidenceChain,createSignedEvidenceVerifier}=
 require('../distribution/signed-evidence-v5');
const {createAtomicSignedEvidenceReceiver}=
 require('../distribution/atomic-signed-evidence-receiver-v5');
function fixture(){
 const namespace='palaco.registry';
 const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
 const pem=i=>keys[i].publicKey.export({type:'spki',format:'pem'});
 const roots={
  senderRoot:{identityId:'sender',keyId:'issuer-key',enabled:true,
   revoked:false,publicKeyPem:pem(0)},
  recipientRoot:{identityId:'receiver',keyId:'receiver-key',enabled:true,
   revoked:false,publicKeyPem:pem(1)}
 };
 const handoff={schemaVersion:'palaco.distribution.incident-witness-handoff.v1',
  namespace,senderId:'sender',recipientId:'receiver',nonce:'nonce-11',
  previousSequence:10,previousDigest:'a'.repeat(64),
  nextSequence:11,nextDigest:'b'.repeat(64),
  issuedAtMs:1000,expiresAtMs:5000,
  authorization:'DENY',go13:'HOLD',purpose:'EVIDENCE_ONLY_NO_RELEASE'};
 const receipt={schemaVersion:'palaco.distribution.incident-witness-receipt.v1',
  namespace,recipientId:'receiver',nonce:handoff.nonce,
  handoffDigest:handoffDigest(handoff),acceptedAtMs:1500,
  acknowledgement:'EVIDENCE_RECEIVED_NO_AUTHORITY'};
 const sig=(bytes,i,keyId)=>({algorithm:'Ed25519',keyId,
  signature:sign(null,bytes,keys[i].privateKey).toString('base64')});
 const sender=sig(handoffPayload(handoff),0,'issuer-key');
 const recipient=sig(receiptPayload(receipt),1,'receiver-key');
 const digest=evidenceDigest(handoff,sender,receipt,recipient);
 const row={sequence:'11',nonce:handoff.nonce,
  handoff_digest:handoffDigest(handoff),recipient_id:'receiver',
  evidence_digest:digest,handoff,receipt,
  sender_signature:sender,receipt_signature:recipient};
 const chain=signedEvidenceChain([row],{namespace,firstSequence:11});
 return {namespace,keys,roots,handoff,receipt,sender,recipient,digest,row,chain};
}
test('full evidence hash commits both signature bytes not only receipt metadata',()=>{
 const f=fixture();
 assert.match(f.digest,/^[a-f0-9]{64}$/);
 const other={...f.recipient,signature:'A'.repeat(86)+'=='};
 assert.notEqual(evidenceDigest(f.handoff,f.sender,f.receipt,other),f.digest);
 assert.equal(evidenceDigest({...f.handoff,authorization:'ALLOW'},
  f.sender,f.receipt,f.recipient),null);
});
test('historical full evidence verification never unlocks action',async()=>{
 const f=fixture();
 const verify=createSignedEvidenceVerifier({namespace:f.namespace,firstSequence:11,
  evidenceQuery:async()=>({rowCount:1,rows:[f.row]}),
  anchorQuery:async()=>({rowCount:1,rows:[{
   sequence:'11',chain_digest:f.chain.digest}]}),
  historicalRootsProvider:async()=>f.roots});
 const outcome=await verify.verify();
 assert.equal(outcome.readiness,'SIGNED_EVIDENCE_HISTORY_VERIFIED_NON_AUTHORIZING');
 assert.equal(outcome.verifiedSignatures,2);assert.equal(outcome.authorization,'DENY');
 assert.equal(outcome.go13,'HOLD');assert.equal(outcome.mayRestore,false);
});
test('forged signature and absent evidence fail even with anchored head',async()=>{
 const f=fixture();
 for(const mutated of [
  {...f.row,receipt_signature:{...f.recipient,signature:'A'.repeat(86)+'=='}},
  {...f.row,receipt:null},
  {...f.row,evidence_digest:'f'.repeat(64)}
 ]){
  const verify=createSignedEvidenceVerifier({namespace:f.namespace,
   firstSequence:11,evidenceQuery:async()=>({rowCount:1,rows:[mutated]}),
   anchorQuery:async()=>({rowCount:1,rows:[{
    sequence:'11',chain_digest:f.chain.digest}]}),
   historicalRootsProvider:async()=>f.roots});
  assert.equal((await verify.verify()).readiness,'BLOCKED');
 }
});
test('backed-up partial receipt history is denied by immutable external head',async()=>{
 const f=fixture();
 const verify=createSignedEvidenceVerifier({namespace:f.namespace,
  firstSequence:11,evidenceQuery:async()=>({rowCount:0,rows:[]}),
  anchorQuery:async()=>({rowCount:1,rows:[{
   sequence:'11',chain_digest:f.chain.digest}]}),
  historicalRootsProvider:async()=>f.roots});
 assert.equal((await verify.verify()).readiness,'BLOCKED');
});
test('atomic receiver does not expose arbitrary raw writer functions',async()=>{
 const f=fixture();let advanced=0;
 const query=async({text,values})=>{
  if(text.startsWith('SELECT'))return {rowCount:1,
   rows:[{sequence:'10',incident_digest:'a'.repeat(64)}]};
  assert.ok(text.startsWith('WITH advanced'));
  assert.equal(values.length,13);advanced++;
  return {rowCount:1,rows:[{sequence:'11',incident_digest:'b'.repeat(64),
   nonce:'nonce-11',evidence_digest:f.digest}]};
 };
 const recv=createAtomicSignedEvidenceReceiver({
  namespace:f.namespace,query,
  trustPolicyProvider:async()=>({nowMs:2000,...f.roots})
 });
 assert.equal(typeof recv.query,'undefined');
 assert.equal(typeof recv.update,'undefined');
 const result=await recv.receive(f.handoff,f.sender,f.receipt,f.recipient);
 assert.equal(result.readiness,'ATOMIC_SIGNED_RECEIPT_RECORDED_NON_AUTHORIZING');
 assert.equal(result.evidenceDigest,f.digest);assert.equal(advanced,1);
 assert.equal(result.authorization,'DENY');
});
test('rejected signature or storage conflict never confirms receipt',async()=>{
 const f=fixture();
 let writes=0;
 const query=async({text})=>{
  if(text.startsWith('SELECT'))return {rowCount:1,
   rows:[{sequence:'10',incident_digest:'a'.repeat(64)}]};
  writes++;throw Error('unique or invalid FK');
 };
 const recv=createAtomicSignedEvidenceReceiver({namespace:f.namespace,
  query,trustPolicyProvider:async()=>({nowMs:2000,...f.roots})});
 assert.equal((await recv.receive(f.handoff,f.sender,f.receipt,
  {...f.recipient,signature:'A'.repeat(86)+'=='})).readiness,'BLOCKED');
 assert.equal(writes,0);
 assert.deepEqual((await recv.receive(f.handoff,f.sender,
  f.receipt,f.recipient)).findings,['ATOMIC_RECEIPT_CAS_OR_STORAGE_REJECTED']);
 assert.equal(writes,1);
});
