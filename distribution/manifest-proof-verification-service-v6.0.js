'use strict';
// v6.0 independently rooted verification adapter. Issuer and verifier
// MUST be different processes/credentials in production, not shared memory.
const {createRootVerifier,reconstructInclusion,reconstructConsistency}=
 require('./manifest-merkle-proofs-v5.9');
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const HEX=/^[a-f0-9]{64}$/;
const MAX_ENVELOPE_BYTES=4096,MAX_ENTRIES=10000;
function denied(reason){return Object.freeze({
 readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
 mayAdvance:false,mayRestore:false,mayReconcile:false,
 maySynchronize:false,mayInstall:false,mayPublish:false,
 findings:Object.freeze([reason])
});}
function bounded(x){
 if(!x||typeof x!=='object'||Array.isArray(x))return false;
 try{return Buffer.byteLength(JSON.stringify(x),'utf8')<=MAX_ENVELOPE_BYTES;}
 catch(_){return false;}
}
function createIndependentManifestProofService({
 namespace,checkpointQuery,trustRootProvider,pinnedRootProvider
}={}){
 if(!NS.test(namespace||'')||typeof checkpointQuery!=='function'||
  typeof trustRootProvider!=='function'||
  typeof pinnedRootProvider!=='function')
  throw new TypeError('Independent checkpoint, Ed25519 root and out-of-band pin required');
 const verifier=createRootVerifier({namespace,checkpointQuery,trustRootProvider});
 async function pinned(size,signal){
  if(signal?.aborted)return null;
  let result;
  try{result=await pinnedRootProvider(namespace,size,signal);}
  catch(_){return null;}
  return !signal?.aborted&&HEX.test(result||'')?result:null;
 }
 return Object.freeze({namespace,
  async verifyInclusion(envelope,signal){
   if(signal?.aborted||!bounded(envelope)||envelope.namespace!==namespace||
    envelope.readiness!=='COMPACT_INCLUSION_PROOF_ISSUED_NON_AUTHORIZING'||
    envelope.authorization!=='DENY'||envelope.go13!=='HOLD'||
    !envelope.proof||!Number.isSafeInteger(envelope.proof.treeSize)||
    envelope.proof.treeSize<1||envelope.proof.treeSize>MAX_ENTRIES)
    return denied('PROOF_ENVELOPE_INVALID');
   const reconstructed=reconstructInclusion(envelope.proof);
   if(!reconstructed||envelope.merkleRoot!==reconstructed)
    return denied('PROOF_ENVELOPE_INCLUSION_MISMATCH');
   const root=await pinned(envelope.proof.treeSize,signal);
   if(!root)return denied('PROOF_INDEPENDENT_PIN_UNAVAILABLE');
   if(root!==reconstructed)
    return denied('PROOF_SIGNED_SPLIT_VIEW_OR_ROLLBACK');
   const verified=await verifier.verifyInclusion(envelope.proof,signal);
   if(verified.readiness!=='MERKLE_INCLUSION_VERIFIED_NON_AUTHORIZING')
    return denied('PROOF_SIGNED_ROOT_INVALID');
   return Object.freeze({
    readiness:'INDEPENDENT_INCLUSION_VERIFIED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',index:envelope.proof.index,
    treeSize:envelope.proof.treeSize,
    mayAdvance:false,mayRestore:false,mayReconcile:false,
    maySynchronize:false,mayInstall:false,mayPublish:false,
    findings:Object.freeze([])
   });
  },
  async verifyConsistency(envelope,signal){
   if(signal?.aborted||!bounded(envelope)||envelope.namespace!==namespace||
    envelope.readiness!=='COMPACT_CONSISTENCY_PROOF_ISSUED_NON_AUTHORIZING'||
    envelope.authorization!=='DENY'||envelope.go13!=='HOLD'||
    !envelope.proof||!Number.isSafeInteger(envelope.proof.oldSize)||
    !Number.isSafeInteger(envelope.proof.newSize)||
    envelope.proof.oldSize<1||envelope.proof.oldSize>=envelope.proof.newSize||
    envelope.proof.newSize>MAX_ENTRIES)
    return denied('PROOF_ENVELOPE_INVALID');
   const reconstructed=reconstructConsistency(envelope.proof);
   if(!reconstructed)return denied('PROOF_ENVELOPE_CONSISTENCY_INVALID');
   const [oldPin,newPin]=await Promise.all([
    pinned(envelope.proof.oldSize,signal),
    pinned(envelope.proof.newSize,signal)
   ]);
   if(!oldPin||!newPin)return denied('PROOF_INDEPENDENT_PIN_UNAVAILABLE');
   if(reconstructed.oldRoot!==oldPin||reconstructed.newRoot!==newPin)
    return denied('PROOF_SIGNED_SPLIT_VIEW_OR_ROLLBACK');
   const verified=await verifier.verifyConsistency(envelope.proof,signal);
   if(verified.readiness!=='MERKLE_APPEND_ONLY_CONSISTENCY_VERIFIED_NON_AUTHORIZING')
    return denied('PROOF_SIGNED_ROOT_INVALID');
   return Object.freeze({
    readiness:'INDEPENDENT_CONSISTENCY_VERIFIED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',
    oldSize:envelope.proof.oldSize,newSize:envelope.proof.newSize,
    mayAdvance:false,mayRestore:false,mayReconcile:false,
    maySynchronize:false,mayInstall:false,mayPublish:false,
    findings:Object.freeze([])
   });
  }
 });
}
module.exports={MAX_ENVELOPE_BYTES,MAX_ENTRIES,
 createIndependentManifestProofService};
