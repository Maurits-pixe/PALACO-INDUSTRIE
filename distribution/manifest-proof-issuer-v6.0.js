'use strict';
// v6.0: process-local read-only proof issuer. NOT a public HTTP server.
// No signing, checkpoint mutation or release authority.
const {inclusionProof,consistencyProof,merkleRoot}=
 require('./manifest-merkle-proofs-v5.9');
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const HEX=/^[a-f0-9]{64}$/;
const LIMIT=10000;
const SELECT=[
 'SELECT entry_sequence,entry_digest',
 'FROM palaco_manifest_transparency.entries',
 'WHERE namespace=$1 AND entry_sequence<=$2',
 'ORDER BY entry_sequence ASC LIMIT 10001'
].join('\n');
function blocked(reason){return Object.freeze({
 readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
 mayAdvance:false,mayRestore:false,mayReconcile:false,
 maySynchronize:false,mayInstall:false,mayPublish:false,
 findings:Object.freeze([reason])
});}
function validSize(n){return Number.isSafeInteger(n)&&n>=1&&n<=LIMIT;}
function createManifestProofIssuer({namespace,logQuery}={}){
 if(!NS.test(namespace||'')||typeof logQuery!=='function')
  throw new TypeError('Read-only log query and scoped namespace required');
 async function load(size,signal){
  if(!validSize(size)||signal?.aborted)return null;
  let result;
  try{result=await logQuery({text:SELECT,values:[namespace,size],signal});}
  catch(_){return null;}
  if(signal?.aborted||!result||!Array.isArray(result.rows)||
   result.rowCount!==result.rows.length||result.rows.length!==size)
   return null;
  const leaves=[];
  for(let i=0;i<size;i++){
   const row=result.rows[i];
   if(String(row?.entry_sequence)!==String(i+1)||
    !HEX.test(row?.entry_digest||''))return null;
   leaves.push(row.entry_digest);
  }
  return leaves;
 }
 return Object.freeze({namespace,
  async issueInclusion({treeSize,index}={},signal){
   if(!validSize(treeSize)||!Number.isSafeInteger(index)||
    index<0||index>=treeSize)return blocked('PROOF_ISSUE_BAD_REQUEST');
   const leaves=await load(treeSize,signal);
   if(!leaves)return blocked('PROOF_ISSUE_LOG_UNAVAILABLE_OR_GAPPED');
   const proof=inclusionProof(leaves,index);
   if(!proof||proof.siblings.length>20)
    return blocked('PROOF_ISSUE_COMPUTATION_INVALID');
   return Object.freeze({readiness:'COMPACT_INCLUSION_PROOF_ISSUED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',namespace,
    merkleRoot:merkleRoot(leaves),proof,
    mayAdvance:false,mayRestore:false,mayReconcile:false,
    maySynchronize:false,mayInstall:false,mayPublish:false,
    findings:Object.freeze([])});
  },
  async issueConsistency({oldSize,newSize}={},signal){
   if(!validSize(oldSize)||!validSize(newSize)||oldSize>=newSize)
    return blocked('PROOF_ISSUE_BAD_REQUEST');
   const leaves=await load(newSize,signal);
   if(!leaves)return blocked('PROOF_ISSUE_LOG_UNAVAILABLE_OR_GAPPED');
   const proof=consistencyProof(leaves,oldSize);
   if(!proof||proof.previous.length+proof.extension.length>40)
    return blocked('PROOF_ISSUE_COMPUTATION_INVALID');
   return Object.freeze({readiness:'COMPACT_CONSISTENCY_PROOF_ISSUED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',namespace,proof,
    mayAdvance:false,mayRestore:false,mayReconcile:false,
    maySynchronize:false,mayInstall:false,mayPublish:false,
    findings:Object.freeze([])});
  }
 });
}
module.exports={LIMIT,SELECT,createManifestProofIssuer};
