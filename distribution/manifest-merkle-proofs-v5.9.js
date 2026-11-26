'use strict';
// v5.9 — domain-separated append-only Merkle proofs over v5.8 entry digests.
// Proofs are compact; verification uses only signed roots and proof nodes.
const {createHash,createPublicKey,verify}=require('node:crypto');
const {entryDigest}=require('./manifest-transparency-v5.8');
const HEX=/^[a-f0-9]{64}$/;
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const VERSION='palaco.distribution.manifest-merkle-checkpoint.v1';
const ROOT_QUERY=[
 'SELECT namespace,tree_size,merkle_root,observer_id,key_id,',
 'observed_at_ms,signature FROM palaco_manifest_merkle_anchor.checkpoints',
 'WHERE namespace=$1 AND tree_size=$2'
].join('\n');
const sha=b=>createHash('sha256').update(b).digest('hex');
const leaf=d=>HEX.test(d||'')?sha(Buffer.concat([
 Buffer.from([0]),Buffer.from(d,'hex')])):null;
const branch=(a,b)=>HEX.test(a||'')&&HEX.test(b||'')?
 sha(Buffer.concat([Buffer.from([1]),Buffer.from(a,'hex'),Buffer.from(b,'hex')])):null;
function largestPowerBelow(n){let p=1;while(p*2<n)p*=2;return p;}
function validLeaves(values){
 return Array.isArray(values)&&values.length>0&&values.length<=10000&&
  values.every(v=>HEX.test(v||''));
}
function rootRange(leaves,start,end){
 if(end-start===1)return leaf(leaves[start]);
 const k=largestPowerBelow(end-start);
 return branch(rootRange(leaves,start,start+k),
  rootRange(leaves,start+k,end));
}
function merkleRoot(leaves){
 return validLeaves(leaves)?rootRange(leaves,0,leaves.length):null;
}
function inclusionProof(leaves,index){
 if(!validLeaves(leaves)||!Number.isSafeInteger(index)||
  index<0||index>=leaves.length)return null;
 const siblings=[];
 function walk(start,end,i){
  if(end-start===1)return;
  const k=largestPowerBelow(end-start);
  if(i<start+k){
   walk(start,start+k,i);siblings.push(rootRange(leaves,start+k,end));
  }else{
   walk(start+k,end,i);siblings.push(rootRange(leaves,start,start+k));
  }
 }
 walk(0,leaves.length,index);
 return Object.freeze({index,treeSize:leaves.length,
  entryDigest:leaves[index],siblings:Object.freeze(siblings)});
}
function reconstructInclusion(proof){
 if(!proof||!Number.isSafeInteger(proof.treeSize)||proof.treeSize<1||
  proof.treeSize>10000||!Number.isSafeInteger(proof.index)||
  proof.index<0||proof.index>=proof.treeSize||
  !HEX.test(proof.entryDigest||'')||!Array.isArray(proof.siblings)||
  proof.siblings.length>20||
  !proof.siblings.every(x=>HEX.test(x||'')))return null;
 let pos=0;
 function walk(start,end){
  if(end-start===1)return leaf(proof.entryDigest);
  const k=largestPowerBelow(end-start);
  if(proof.index<start+k){
   const left=walk(start,start+k);
   if(pos>=proof.siblings.length)return null;
   return branch(left,proof.siblings[pos++]);
  }
  const right=walk(start+k,end);
  if(pos>=proof.siblings.length)return null;
  return branch(proof.siblings[pos++],right);
 }
 const result=walk(0,proof.treeSize);
 return pos===proof.siblings.length?result:null;
}
// Canonical aligned perfect-subtree forest: old prefix + new suffix.
// It commits to the same prefix in both signed roots; O(log n) nodes.
function cover(start,end){
 const ranges=[];
 while(start<end){
  let length=1;
  while(length*2<=end-start&&start%(length*2)===0)length*=2;
  ranges.push({start,length});start+=length;
 }
 return ranges;
}
function foldForest(chunks){
 const stack=[];
 for(const c of chunks){
  let current={length:c.length,digest:c.digest};
  while(stack.length&&stack.at(-1).length===current.length){
   const left=stack.pop();
   current={length:current.length*2,
    digest:branch(left.digest,current.digest)};
  }
  stack.push(current);
 }
 let root=stack.pop()?.digest||null;
 while(stack.length)root=branch(stack.pop().digest,root);
 return root;
}
function consistencyProof(leaves,oldSize){
 if(!validLeaves(leaves)||!Number.isSafeInteger(oldSize)||
  oldSize<1||oldSize>=leaves.length)return null;
 const previous=cover(0,oldSize).map(c=>rootRange(leaves,
  c.start,c.start+c.length));
 const extension=cover(oldSize,leaves.length).map(c=>rootRange(leaves,
  c.start,c.start+c.length));
 return Object.freeze({oldSize,newSize:leaves.length,
  previous:Object.freeze(previous),extension:Object.freeze(extension)});
}
function reconstructConsistency(proof){
 if(!proof||!Number.isSafeInteger(proof.oldSize)||
  !Number.isSafeInteger(proof.newSize)||proof.oldSize<1||
  proof.newSize<=proof.oldSize||proof.newSize>10000||
  !Array.isArray(proof.previous)||!Array.isArray(proof.extension))
  return null;
 const a=cover(0,proof.oldSize),b=cover(proof.oldSize,proof.newSize);
 if(proof.previous.length!==a.length||proof.extension.length!==b.length||
  ![...proof.previous,...proof.extension].every(x=>HEX.test(x||'')))
  return null;
 const first=a.map((c,i)=>({...c,digest:proof.previous[i]}));
 const rest=b.map((c,i)=>({...c,digest:proof.extension[i]}));
 return {oldRoot:foldForest(first),newRoot:foldForest([...first,...rest])};
}
function checkpointBytes(v){
 if(!v||v.schemaVersion!==VERSION||!NS.test(v.namespace||'')||
  !Number.isSafeInteger(v.treeSize)||v.treeSize<1||
  !HEX.test(v.merkleRoot||'')||!ID.test(v.observerId||'')||
  !Number.isSafeInteger(v.observedAtMs)||v.observedAtMs<0||
  v.authorization!=='DENY'||v.go13!=='HOLD'||
  v.purpose!=='MERKLE_PROOF_ROOT_NO_AUTHORITY')return null;
 return Buffer.from(['PALACO-MANIFEST-MERKLE-ROOT-V1',VERSION,
  v.namespace,String(v.treeSize),v.merkleRoot,v.observerId,
  String(v.observedAtMs),v.authorization,v.go13,v.purpose,''].join('\n'));
}
function denial(reason){return Object.freeze({
 readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
 mayAdvance:false,mayRestore:false,mayReconcile:false,
 maySynchronize:false,mayInstall:false,mayPublish:false,
 findings:Object.freeze([reason])
});}
async function createRootVerifier({
 namespace,checkpointQuery,trustRootProvider
}={}){
 if(!NS.test(namespace||'')||typeof checkpointQuery!=='function'||
  typeof trustRootProvider!=='function')
  throw new TypeError('Independent signed roots required');
 async function check(treeSize,signal){
  if(signal?.aborted)return null;
  let response;
  try{response=await checkpointQuery({text:ROOT_QUERY,values:[
   namespace,treeSize],signal});}catch(_){return null;}
  if(signal?.aborted||response?.rowCount!==1||
   response.rows?.length!==1)return null;
  const row=response.rows[0];
  if(row.namespace!==namespace||String(row.tree_size)!==String(treeSize)||
   !HEX.test(row.merkle_root||'')||!ID.test(row.observer_id||'')||
   !ID.test(row.key_id||'')||!SIG.test(row.signature||'')||
   Buffer.from(row.signature,'base64').toString('base64')!==row.signature||
   !/^(0|[1-9][0-9]*)$/.test(String(row.observed_at_ms)))
   return null;
  const observedAtMs=Number(row.observed_at_ms);
  if(!Number.isSafeInteger(observedAtMs))return null;
  const checkpoint={schemaVersion:VERSION,namespace,treeSize,
   merkleRoot:row.merkle_root,observerId:row.observer_id,
   observedAtMs,authorization:'DENY',go13:'HOLD',
   purpose:'MERKLE_PROOF_ROOT_NO_AUTHORITY'};
  let root;
  try{root=await trustRootProvider(namespace,row.observer_id,
   row.key_id,signal);}catch(_){return null;}
  if(signal?.aborted||!root||root.enabled!==true||root.revoked!==false||
   root.observerId!==row.observer_id||root.keyId!==row.key_id||
   typeof root.publicKeyPem!=='string'||root.publicKeyPem.length>4096)
   return null;
  try{
   const key=createPublicKey(root.publicKeyPem);
   if(key.asymmetricKeyType!=='ed25519'||!verify(null,checkpointBytes(checkpoint),
    key,Buffer.from(row.signature,'base64')))return null;
  }catch(_){return null;}
  return row.merkle_root;
 }
 return Object.freeze({namespace,
  async verifyInclusion(proof,signal){
   if(!proof||signal?.aborted)return denial('MERKLE_INCLUSION_INVALID');
   const computed=reconstructInclusion(proof);
   if(!computed)return denial('MERKLE_INCLUSION_INVALID');
   const expected=await check(proof.treeSize,signal);
   if(!expected)return denial('MERKLE_CHECKPOINT_UNTRUSTED');
   if(computed!==expected)return denial('MERKLE_INCLUSION_ROOT_MISMATCH');
   return Object.freeze({readiness:'MERKLE_INCLUSION_VERIFIED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',index:proof.index,treeSize:proof.treeSize,
    mayAdvance:false,mayRestore:false,mayReconcile:false,
    maySynchronize:false,mayInstall:false,mayPublish:false,
    findings:Object.freeze([])});
  },
  async verifyConsistency(proof,signal){
   if(!proof||signal?.aborted)return denial('MERKLE_CONSISTENCY_INVALID');
   const roots=reconstructConsistency(proof);
   if(!roots)return denial('MERKLE_CONSISTENCY_INVALID');
   const [oldRoot,newRoot]=await Promise.all([
    check(proof.oldSize,signal),check(proof.newSize,signal)
   ]);
   if(!oldRoot||!newRoot)return denial('MERKLE_CHECKPOINT_UNTRUSTED');
   if(oldRoot!==roots.oldRoot||newRoot!==roots.newRoot)
    return denial('MERKLE_CONSISTENCY_ROOT_MISMATCH');
   return Object.freeze({
    readiness:'MERKLE_APPEND_ONLY_CONSISTENCY_VERIFIED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',oldSize:proof.oldSize,
    newSize:proof.newSize,mayAdvance:false,mayRestore:false,
    mayReconcile:false,maySynchronize:false,
    mayInstall:false,mayPublish:false,findings:Object.freeze([])
   });
  }
 });
}
module.exports={VERSION,ROOT_QUERY,leaf,branch,merkleRoot,
 inclusionProof,reconstructInclusion,consistencyProof,
 reconstructConsistency,checkpointBytes,createRootVerifier};
