'use strict';

// v4.1 independent second witness. Read-only comparison, never a key
// rotation, repair command, bypass or distribution activation.
const {authorityDigest,verifyRosterAuthorityRotation}=
  require('./roster-authority-rotation');

function denied(reason) {
 return Object.freeze({readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
  mayAdvance:false,mayRotate:false,mayRestore:false,mayInstall:false,
  mayPublish:false,findings:Object.freeze([reason])});
}

/**
 * Require two separately provisioned anchor stores (different trust/restore
 * domains outside CI). Both must attest the exact SAME predecessor state.
 * This detects a restored primary against an independently advanced witness.
 * Never use either store's data as a fallback when the other fails.
 */
function createDualAuthorityWitness({primary,secondary}={}) {
 if(!primary||!secondary||primary===secondary||
    typeof primary.namespace!=='string'||primary.namespace!==secondary.namespace||
    typeof primary.latest!=='function'||typeof secondary.latest!=='function')
  throw new TypeError('Two distinct authority anchor stores required');
 const namespace=primary.namespace;
 const witness=Object.freeze({
  namespace,
  async verifyHead(expectedRevision,expectedDigest,signal){
   if(signal?.aborted||!Number.isSafeInteger(expectedRevision)||
      expectedRevision<1||typeof expectedDigest!=='string'||
      !/^[a-f0-9]{64}$/.test(expectedDigest))
    return denied('DUAL_AUTHORITY_EXPECTATION_INVALID');
   let first,second;
   try{
    [first,second]=await Promise.all([
      primary.latest(signal),secondary.latest(signal)]);
   }catch(_){return denied('DUAL_AUTHORITY_WITNESS_UNAVAILABLE');}
   if(signal?.aborted||!first||!second)
    return denied('DUAL_AUTHORITY_WITNESS_UNAVAILABLE');
   if(first.revision!==second.revision||first.digest!==second.digest)
    return denied('DUAL_AUTHORITY_WITNESS_DIVERGENCE');
   if(first.revision!==expectedRevision||first.digest!==expectedDigest)
    return denied('DUAL_AUTHORITY_HEAD_MISMATCH');
   return Object.freeze({
    readiness:'DUAL_AUTHORITY_HEAD_VERIFIED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',revision:expectedRevision,
    digest:expectedDigest,mayAdvance:false,mayRotate:false,
    mayRestore:false,mayInstall:false,mayPublish:false,
    findings:Object.freeze([])
   });
  },
  async verifyRotation(previous,next,record,endorsements,reviewerRoots,signal) {
   const oldDigest=authorityDigest(previous);
   const head=await witness.verifyHead(previous?.revision,oldDigest,signal);
   if(head.readiness!=='DUAL_AUTHORITY_HEAD_VERIFIED_NON_AUTHORIZING')
    return head;
   const proof=verifyRosterAuthorityRotation(previous,next,record,endorsements,{
    namespace,minimumRevision:head.revision,previousDigest:head.digest,
    pinnedReviewers:reviewerRoots
   });
   if(proof.readiness!=='AUTHORITY_ROTATION_VERIFIED_NON_AUTHORIZING')
    return denied('DUAL_AUTHORITY_ROTATION_REJECTED');
   if(signal?.aborted)return denied('DUAL_AUTHORITY_WITNESS_UNAVAILABLE');
   return Object.freeze({
    readiness:'DUAL_AUTHORITY_ROTATION_VERIFIED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',revision:proof.revision,
    digest:proof.digest,mayAdvance:false,mayRotate:false,
    mayRestore:false,mayInstall:false,mayPublish:false,
    findings:Object.freeze([])
   });
  }
 });
 return witness;
}
module.exports={createDualAuthorityWitness};
