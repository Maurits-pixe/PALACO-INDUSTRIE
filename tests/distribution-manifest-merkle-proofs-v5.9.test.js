'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {VERSION,merkleRoot,inclusionProof,reconstructInclusion,
 consistencyProof,reconstructConsistency,checkpointBytes,
 createRootVerifier}=require('../distribution/manifest-merkle-proofs-v5.9');
function fixture(){
 const namespace='palaco.v59ci',keys=generateKeyPairSync('ed25519');
 const root={observerId:'merkle-auditor',keyId:'merkle-key',
  enabled:true,revoked:false,
  publicKeyPem:keys.publicKey.export({type:'spki',format:'pem'})};
 const leaves=Array.from({length:37},(_,i)=>(i+1).toString(16).padStart(64,'0'));
 const checkpoint=size=>{
  const obj={schemaVersion:VERSION,namespace,treeSize:size,
   merkleRoot:merkleRoot(leaves.slice(0,size)),
   observerId:root.observerId,observedAtMs:2000+size,
   authorization:'DENY',go13:'HOLD',
   purpose:'MERKLE_PROOF_ROOT_NO_AUTHORITY'};
  return {namespace,tree_size:String(size),merkle_root:obj.merkleRoot,
   observer_id:obj.observerId,key_id:root.keyId,
   observed_at_ms:String(obj.observedAtMs),
   signature:sign(null,checkpointBytes(obj),keys.privateKey).toString('base64')};
 };
 const create=(mods={})=>createRootVerifier({
  namespace,
  checkpointQuery:async({values})=>({rowCount:1,
   rows:[checkpoint(values[1])]}),
  trustRootProvider:async()=>root,...mods
 });
 return {leaves,checkpoint,root,create,namespace};
}
test('all indices in trees 1..37 have inclusion proof matching signed root',async()=>{
 const f=fixture(),verifier=f.create();
 for(let size=1;size<=37;size++){
  for(let index=0;index<size;index++){
   const proof=inclusionProof(f.leaves.slice(0,size),index);
   assert.equal(reconstructInclusion(proof),merkleRoot(f.leaves.slice(0,size)));
   const result=await verifier.verifyInclusion(proof);
   assert.equal(result.readiness,'MERKLE_INCLUSION_VERIFIED_NON_AUTHORIZING');
   assert.equal(result.authorization,'DENY');assert.equal(result.go13,'HOLD');
   assert.equal(result.mayPublish,false);assert.equal(result.mayRestore,false);
  }
 }
});
test('all old and new tree sizes 1..37 verify compact prefix consistency',async()=>{
 const f=fixture(),verifier=f.create();
 for(let newSize=2;newSize<=37;newSize++){
  for(let oldSize=1;oldSize<newSize;oldSize++){
   const proof=consistencyProof(f.leaves.slice(0,newSize),oldSize);
   const roots=reconstructConsistency(proof);
   assert.deepEqual(roots,{
    oldRoot:merkleRoot(f.leaves.slice(0,oldSize)),
    newRoot:merkleRoot(f.leaves.slice(0,newSize))
   });
   assert.equal((await verifier.verifyConsistency(proof)).readiness,
    'MERKLE_APPEND_ONLY_CONSISTENCY_VERIFIED_NON_AUTHORIZING');
  }
 }
});
test('tampered, omitted, swapped, extra or malformed audit nodes deny',async()=>{
 const f=fixture(),v=f.create(),base=inclusionProof(f.leaves,8);
 for(const proof of [
  {...base,entryDigest:'f'.repeat(64)},
  {...base,siblings:base.siblings.slice(1)},
  {...base,siblings:[...base.siblings].reverse()},
  {...base,siblings:[...base.siblings,'a'.repeat(64)]},
  {...base,index:37}, {...base,treeSize:10001}
 ])assert.equal((await v.verifyInclusion(proof)).readiness,'BLOCKED');
});
test('forked old prefix, changed extension, wrong length and injected nodes deny',async()=>{
 const f=fixture(),v=f.create(),base=consistencyProof(f.leaves,13);
 for(const proof of [
  {...base,previous:['f'.repeat(64),...base.previous.slice(1)]},
  {...base,extension:['f'.repeat(64),...base.extension.slice(1)]},
  {...base,previous:base.previous.slice(1)},
  {...base,extension:[...base.extension,'a'.repeat(64)]},
  {...base,newSize:13},{...base,oldSize:0}
 ])assert.equal((await v.verifyConsistency(proof)).readiness,'BLOCKED');
});
test('forged checkpoint, revoked auditor or unavailable root denies both proofs',async()=>{
 const f=fixture(),proof=inclusionProof(f.leaves,4);
 const consistency=consistencyProof(f.leaves,20);
 for(const mods of [
  {checkpointQuery:async()=>({rowCount:0,rows:[]})},
  {checkpointQuery:async()=>{throw Error('offline');}},
  {trustRootProvider:async()=>({...f.root,revoked:true})},
  {checkpointQuery:async({values})=>({rowCount:1,rows:[{
   ...f.checkpoint(values[1]),signature:'A'.repeat(86)+'=='
  }]})}
 ]){
  const v=f.create(mods);
  assert.equal((await v.verifyInclusion(proof)).readiness,'BLOCKED');
  assert.equal((await v.verifyConsistency(consistency)).readiness,'BLOCKED');
 }
});
test('invalid hashes, abort and no raw writes cannot confer authority',async()=>{
 const f=fixture(),v=f.create(),abort=new AbortController();abort.abort();
 assert.equal(inclusionProof(['f'],0),null);
 assert.equal(consistencyProof(f.leaves,0),null);
 assert.equal((await v.verifyInclusion(inclusionProof(f.leaves,0),abort.signal)).readiness,
  'BLOCKED');
 assert.equal((await v.verifyConsistency(consistencyProof(f.leaves,1),
  abort.signal)).readiness,'BLOCKED');
 assert.equal(typeof v.publish,'undefined');
 assert.equal(typeof v.insert,'undefined');
 assert.ok(Object.isFrozen(v));
});
