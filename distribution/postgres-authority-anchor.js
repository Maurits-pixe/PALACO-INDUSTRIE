'use strict';

// Separate trusted PostgreSQL service; not the authority issuer database.
// No credential provisioning, schema migration or admin bootstrap here.
const {verifyRosterAuthorityRotation,authorityDigest}=
  require('./roster-authority-rotation');

const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const HEX=/^[a-f0-9]{64}$/;
const READ_SQL=[
 'SELECT revision, state_digest',
 'FROM palaco_authority_anchor.latest',
 'WHERE namespace=$1'
].join('\n');
const ADVANCE_SQL=[
 'UPDATE palaco_authority_anchor.latest',
 'SET revision=$3, state_digest=$4',
 'WHERE namespace=$1 AND revision=$2 AND state_digest=$5',
 'AND revision + 1 = $3 AND state_digest <> $4',
 'RETURNING revision, state_digest'
].join('\n');

function denied(reason){
 return Object.freeze({readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
   mayAdvance:false,mayRotate:false,mayRestore:false,mayInstall:false,
   mayPublish:false,findings:Object.freeze([reason])});
}
function decodeRow(reply){
 if(!reply||reply.rowCount!==1||!Array.isArray(reply.rows)||
    reply.rows.length!==1)return null;
 const row=reply.rows[0];
 if(!row||!/^[1-9][0-9]*$/.test(String(row.revision))||
    !HEX.test(row.state_digest||''))return null;
 const revision=Number(row.revision);
 if(!Number.isSafeInteger(revision))return null;
 return {revision,digest:row.state_digest};
}
/**
 * An independent anchor is trusted only if the query runs against a
 * separately administered store. This is a read-only preflight and DOES
 * NOT grant or perform a rollover.
 */
function createAuthorityAnchorStore({namespace,query}={}){
 if(typeof namespace!=='string'||!NS.test(namespace)||
    typeof query!=='function')
   throw new TypeError('Independent authority anchor adapter required');
 async function latest(signal){
   if(signal?.aborted)return null;
   try{
    const r=await query({text:READ_SQL,values:[namespace],signal});
    return signal?.aborted?null:decodeRow(r);
   }catch(_){return null;}
 }
 async function compareAndAdvance(previousRevision,previousDigest,
   nextRevision,nextDigest,signal){
   if(signal?.aborted||!Number.isSafeInteger(previousRevision)||
      previousRevision<1||nextRevision!==previousRevision+1||
      !HEX.test(previousDigest||'')||!HEX.test(nextDigest||'')||
      nextDigest===previousDigest)return false;
   try{
     const r=await query({text:ADVANCE_SQL,
       values:[namespace,previousRevision,nextRevision,nextDigest,previousDigest],
       signal});
     const row=decodeRow(r);
     return !signal?.aborted&&!!row&&row.revision===nextRevision&&
       row.digest===nextDigest;
   }catch(_){return false;}
 }
 return Object.freeze({namespace,latest,compareAndAdvance});
}

async function verifyAnchoredAuthorityRotation(store,previous,next,record,
  endorsements,reviewerRoots,signal){
 if(!store||typeof store.latest!=='function'||
    !NS.test(store.namespace||'')||signal?.aborted)
   return denied('AUTHORITY_ANCHOR_STORE_UNAVAILABLE');
 const head=await store.latest(signal);
 if(!head)return denied('AUTHORITY_ANCHOR_STORE_UNAVAILABLE');
 const previousDigest=authorityDigest(previous);
 if(!previousDigest||head.revision!==previous.revision||
    head.digest!==previousDigest)
   return denied('AUTHORITY_INDEPENDENT_HEAD_MISMATCH');
 const proof=verifyRosterAuthorityRotation(previous,next,record,endorsements,{
   namespace:store.namespace,minimumRevision:head.revision,
   previousDigest:head.digest,pinnedReviewers:reviewerRoots
 });
 if(proof.readiness!=='AUTHORITY_ROTATION_VERIFIED_NON_AUTHORIZING')
   return denied('AUTHORITY_ROTATION_EVIDENCE_REJECTED');
 if(signal?.aborted)return denied('AUTHORITY_ANCHOR_STORE_UNAVAILABLE');
 return Object.freeze({
   readiness:'ANCHOR_MATCH_VERIFIED_NON_AUTHORIZING',
   authorization:'DENY',go13:'HOLD',
   revision:proof.revision,digest:proof.digest,
   mayAdvance:false,mayRotate:false,mayRestore:false,
   mayInstall:false,mayPublish:false,findings:Object.freeze([])
 });
}
module.exports={READ_SQL,ADVANCE_SQL,createAuthorityAnchorStore,
  verifyAnchoredAuthorityRotation};
