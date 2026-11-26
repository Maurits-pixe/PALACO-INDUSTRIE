'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {VERSION,merkleRoot,checkpointBytes}=
 require('../distribution/manifest-merkle-proofs-v5.9');
const {createManifestProofIssuer}=
 require('../distribution/manifest-proof-issuer-v6.0');
const {createIndependentManifestProofService}=
 require('../distribution/manifest-proof-verification-service-v6.0');
function fixture(){
 const namespace='palaco.v60ci',keys=generateKeyPairSync('ed25519');
 const root={observerId:'independent-reviewer',keyId:'root-key',
  enabled:true,revoked:false,
  publicKeyPem:keys.publicKey.export({type:'spki',format:'pem'})};
 const leaves=Array.from({length:11},(_,i)=>(i+1).toString(16).padStart(64,'0'));
 const checkpoint=size=>{
  const cp={schemaVersion:VERSION,namespace,treeSize:size,
   merkleRoot:merkleRoot(leaves.slice(0,size)),
   observerId:root.observerId,observedAtMs:2000+size,
   authorization:'DENY',go13:'HOLD',
   purpose:'MERKLE_PROOF_ROOT_NO_AUTHORITY'};
  return {namespace,tree_size:String(size),merkle_root:cp.merkleRoot,
   observer_id:cp.observerId,key_id:root.keyId,
   observed_at_ms:String(cp.observedAtMs),
   signature:sign(null,checkpointBytes(cp),keys.privateKey).toString('base64')};
 };
 const log=async({values})=>({rowCount:values[1],
  rows:leaves.slice(0,values[1]).map((entry_digest,i)=>({
   entry_sequence:String(i+1),entry_digest
  }))});
 const issuer=createManifestProofIssuer({namespace,logQuery:log});
 const verify=(overrides={})=>createIndependentManifestProofService({
  namespace,checkpointQuery:async({values})=>({
   rowCount:1,rows:[checkpoint(values[1])]}),
  trustRootProvider:async()=>root,
  pinnedRootProvider:async(ns,size)=>merkleRoot(leaves.slice(0,size)),
  ...overrides
 });
 return {namespace,leaves,log,root,checkpoint,issuer,verify};
}
test('read-only issuer and independently pinned verifier accept valid inclusion',async()=>{
 const f=fixture(),envelope=await f.issuer.issueInclusion({treeSize:11,index:8});
 assert.equal(envelope.readiness,'COMPACT_INCLUSION_PROOF_ISSUED_NON_AUTHORIZING');
 const result=await f.verify().verifyInclusion(envelope);
 assert.equal(result.readiness,'INDEPENDENT_INCLUSION_VERIFIED_NON_AUTHORIZING');
 assert.equal(result.authorization,'DENY');assert.equal(result.go13,'HOLD');
 assert.equal(result.mayPublish,false);
 assert.equal(typeof f.issuer.write,'undefined');
 assert.equal(typeof f.verify().publish,'undefined');
});
test('independent source verifies signed compact consistency proof',async()=>{
 const f=fixture();
 for(let oldSize=1;oldSize<11;oldSize++){
  const envelope=await f.issuer.issueConsistency({oldSize,newSize:11});
  assert.equal(envelope.readiness,'COMPACT_CONSISTENCY_PROOF_ISSUED_NON_AUTHORIZING');
  const outcome=await f.verify().verifyConsistency(envelope);
  assert.equal(outcome.readiness,'INDEPENDENT_CONSISTENCY_VERIFIED_NON_AUTHORIZING');
  assert.equal(outcome.mayAdvance,false);
 }
});
test('issuer rejects oversized, absent, gapped or tampered rowsets',async()=>{
 const f=fixture();
 for(const request of [
  {treeSize:0,index:0},{treeSize:10001,index:0},
  {treeSize:11,index:11},{treeSize:11,index:-1},
  {treeSize:1.2,index:0}
 ])assert.equal((await f.issuer.issueInclusion(request)).readiness,'BLOCKED');
 for(const opts of [
  {oldSize:11,newSize:11},{oldSize:0,newSize:11},
  {oldSize:1,newSize:10001}
 ])assert.equal((await f.issuer.issueConsistency(opts)).readiness,'BLOCKED');
 const corrupt=createManifestProofIssuer({
  namespace:f.namespace,logQuery:async()=>({
   rowCount:2,rows:[{entry_sequence:'1',entry_digest:f.leaves[0]},
    {entry_sequence:'3',entry_digest:f.leaves[1]}]})
 });
 assert.equal((await corrupt.issueInclusion({treeSize:2,index:1})).readiness,'BLOCKED');
});
test('same-size conflicting root is rejected by independent pin',async()=>{
 const f=fixture(),envelope=await f.issuer.issueInclusion({treeSize:11,index:5});
 const altered=f.verify({pinnedRootProvider:async()=>('f'.repeat(64))});
 assert.deepEqual((await altered.verifyInclusion(envelope)).findings,
  ['PROOF_SIGNED_SPLIT_VIEW_OR_ROLLBACK']);
 const full=await f.issuer.issueConsistency({oldSize:3,newSize:11});
 assert.deepEqual((await altered.verifyConsistency(full)).findings,
  ['PROOF_SIGNED_SPLIT_VIEW_OR_ROLLBACK']);
});
test('compromised checkpoint, offline independent root or tampered paths deny',async()=>{
 const f=fixture(),valid=await f.issuer.issueInclusion({treeSize:11,index:2});
 for(const override of [
  {trustRootProvider:async()=>({...f.root,revoked:true})},
  {checkpointQuery:async()=>{throw Error('offline');}},
  {pinnedRootProvider:async()=>{throw Error('offline');}},
  {checkpointQuery:async({values})=>({rowCount:1,rows:[{
   ...f.checkpoint(values[1]),signature:'A'.repeat(86)+'=='
  }]})}
 ]){
  assert.equal((await f.verify(override).verifyInclusion(valid)).readiness,'BLOCKED');
 }
 const forged={...valid,proof:{...valid.proof,
  siblings:['f'.repeat(64),...valid.proof.siblings.slice(1)]}};
 assert.equal((await f.verify().verifyInclusion(forged)).readiness,'BLOCKED');
});
test('oversized envelope, cross namespace, conflicting metadata and abort deny',async()=>{
 const f=fixture(),envelope=await f.issuer.issueInclusion({treeSize:11,index:0});
 for(const candidate of [
  {...envelope,namespace:'palaco.other'},
  {...envelope,merkleRoot:'f'.repeat(64)},
  {...envelope,authorization:'ALLOW'},
  {...envelope,padding:'x'.repeat(5000)}
 ])assert.equal((await f.verify().verifyInclusion(candidate)).readiness,'BLOCKED');
 const abort=new AbortController();abort.abort();
 assert.equal((await f.verify().verifyInclusion(envelope,abort.signal)).readiness,'BLOCKED');
});
