'use strict';
// v5.6 trusted reviewer-only append adapter. No network endpoint or key issuing.
const {verifyThirdWitnessKeyRotation}=
 require('./third-witness-key-rotation-v5.6');
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const INSERT=[
 'INSERT INTO palaco_third_witness_rotation.attestations',
 '(namespace,rotation_number,previous_manifest_digest,',
 'next_manifest_digest,transition,retiring_signature,successor_signature,review_signature)',
 'SELECT $1,$2::bigint,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb,$8::jsonb',
 'WHERE (',
 ' ($2::bigint=1 AND NOT EXISTS (',
 ' SELECT 1 FROM palaco_third_witness_rotation.attestations WHERE namespace=$1))',
 ' OR ($2::bigint>1 AND EXISTS (',
 ' SELECT 1 FROM palaco_third_witness_rotation.attestations',
 ' WHERE namespace=$1 AND rotation_number=$2::bigint-1 AND next_manifest_digest=$3)',
 ' AND NOT EXISTS (',
 ' SELECT 1 FROM palaco_third_witness_rotation.attestations',
 ' WHERE namespace=$1 AND rotation_number>=$2::bigint))',
 ') RETURNING rotation_number,next_manifest_digest'
].join('\n');
function deny(code){return Object.freeze({readiness:'BLOCKED',
 authorization:'DENY',go13:'HOLD',mayAdvance:false,mayRestore:false,
 mayReconcile:false,maySynchronize:false,mayInstall:false,
 mayPublish:false,findings:Object.freeze([code])});}
function createThirdWitnessRotationAttestor({namespace,query,policyProvider}={}){
 if(!NS.test(namespace||'')||typeof query!=='function'||
   typeof policyProvider!=='function')
  throw new TypeError('Trusted rotation reviewer and restricted INSERT connection required');
 return Object.freeze({namespace,
  async record(previousManifest,nextManifest,transition,
   retiringSignature,successorSignature,reviewSignature,signal){
   if(signal?.aborted)return deny('THIRD_ROTATION_ABORTED');
   let policy;
   try{policy=await policyProvider(namespace,signal);}
   catch(_){return deny('THIRD_ROTATION_POLICY_UNAVAILABLE');}
   if(signal?.aborted||!policy)
    return deny('THIRD_ROTATION_POLICY_UNAVAILABLE');
   const proof=verifyThirdWitnessKeyRotation({
    previousManifest,nextManifest,transition,retiringSignature,
    successorSignature,reviewSignature,...policy
   });
   if(proof.readiness!=='THIRD_WITNESS_KEY_ROTATION_VERIFIED_NON_AUTHORIZING')
    return deny('THIRD_ROTATION_PROOF_REJECTED');
   if(signal?.aborted)return deny('THIRD_ROTATION_ABORTED');
   let response;
   try{
    response=await query({text:INSERT,values:[
     namespace,proof.rotationNumber,proof.previousManifestDigest,
     proof.nextManifestDigest,JSON.stringify(transition),
     JSON.stringify(retiringSignature),JSON.stringify(successorSignature),
     JSON.stringify(reviewSignature)
    ],signal});
   }catch(_){return deny('THIRD_ROTATION_INSERT_OR_REPLAY_REJECTED');}
   if(signal?.aborted||response?.rowCount!==1||
    response.rows?.length!==1||
    String(response.rows[0].rotation_number)!==String(proof.rotationNumber)||
    response.rows[0].next_manifest_digest!==proof.nextManifestDigest)
    return deny('THIRD_ROTATION_WRITE_UNCONFIRMED');
   return Object.freeze({
    readiness:'THIRD_ROTATION_ATTESTED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',rotationNumber:proof.rotationNumber,
    nextManifestDigest:proof.nextManifestDigest,
    mayAdvance:false,mayRestore:false,mayReconcile:false,
    maySynchronize:false,mayInstall:false,mayPublish:false,
    findings:Object.freeze([])
   });
  }
 });
}
module.exports={INSERT,createThirdWitnessRotationAttestor};
