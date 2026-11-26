'use strict';
// v6.1 opt-in, process-local verification gateway. No HTTP listener,
// database writer, private key, release handler, or proof issuer attached.
const {createHash}=require('node:crypto');
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const HEX=/^[a-f0-9]{64}$/;
const MAX_REQUEST_BYTES=4096;
const MAX_REQUESTS_PER_WINDOW=20;
const WINDOW_MS=60000;
const VERSION='palaco.distribution.proof-verification-request.v1';
function blocked(code,requestId=null){
 return Object.freeze({schemaVersion:'palaco.distribution.proof-verification-response.v1',
  requestId,readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
  mayAdvance:false,mayRestore:false,mayReconcile:false,
  maySynchronize:false,mayInstall:false,mayPublish:false,
  findings:Object.freeze([code])});
}
function plain(x){return x!==null&&typeof x==='object'&&
 !Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;}
function exact(x,keys){return plain(x)&&Object.keys(x).length===keys.length&&
 keys.every(k=>Object.hasOwn(x,k));}
function validate(request,namespace){
 if(!exact(request,['schemaVersion','requestId','namespace','kind','envelope'])||
  request.schemaVersion!==VERSION||
  !/^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$/.test(request.requestId||'')||
  request.namespace!==namespace||
  !['inclusion','consistency'].includes(request.kind)||
  !plain(request.envelope))return false;
 try{return Buffer.byteLength(JSON.stringify(request),'utf8')<=MAX_REQUEST_BYTES;}
 catch(_){return false;}
}
function digest(x){return createHash('sha256').update(
 JSON.stringify(x)).digest('hex');}
function createProofVerificationGateway({
 namespace,verifier,clock,auditAppend,principalId,
 maxPerWindow=MAX_REQUESTS_PER_WINDOW
}={}){
 if(!NS.test(namespace||'')||!verifier||
  typeof verifier.verifyInclusion!=='function'||
  typeof verifier.verifyConsistency!=='function'||
  verifier.namespace!==namespace||
  typeof clock!=='function'||typeof auditAppend!=='function'||
  !/^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$/.test(principalId||'')||
  !Number.isSafeInteger(maxPerWindow)||maxPerWindow<1||
  maxPerWindow>100)throw new TypeError('Trusted verifier, clock and durable audit required');
 let windowStart=null,count=0,pending=0,previousTime=null;
 const accepted=new Set();
 // One request at a time; concurrent requests fail closed and remain
 // rate-limited. Requests are never internally queued/retried.
 return Object.freeze({namespace,
  async handle(request,signal){
   const valid=validate(request,namespace),requestId=valid?request.requestId:null;
   const candidateDigest=valid?digest(request):null;
   if(pending)return blocked('PROOF_GATEWAY_BUSY',requestId);
   pending=1;
   let outcome=blocked('PROOF_GATEWAY_UNAVAILABLE',requestId),now;
   try{
    now=clock();
    if(!Number.isSafeInteger(now)||now<0||
     (previousTime!==null&&now<previousTime)){
     outcome=blocked('PROOF_GATEWAY_CLOCK_INVALID',requestId);
    }else{
     previousTime=now;
     if(windowStart===null||now-windowStart>=WINDOW_MS){
      windowStart=now;count=0;
     }
     count++;
     if(count>maxPerWindow){
      outcome=blocked('PROOF_GATEWAY_RATE_LIMIT',requestId);
     }else if(!valid){
      outcome=blocked('PROOF_GATEWAY_REQUEST_INVALID',null);
     }else if(accepted.has(requestId)){
      outcome=blocked('PROOF_GATEWAY_REPLAY',requestId);
     }else if(signal?.aborted){
      outcome=blocked('PROOF_GATEWAY_ABORTED',requestId);
     }else{
      // Prevent the caller from resubmitting this id within this process.
      accepted.add(requestId);
      try{
       const method=request.kind==='inclusion'?'verifyInclusion':'verifyConsistency';
       const checked=await verifier[method](request.envelope,signal);
       if(!signal?.aborted&&
        ['INDEPENDENT_INCLUSION_VERIFIED_NON_AUTHORIZING',
         'INDEPENDENT_CONSISTENCY_VERIFIED_NON_AUTHORIZING'].includes(
          checked?.readiness)&&checked.authorization==='DENY'&&
          checked.go13==='HOLD'&&checked.mayPublish===false){
        outcome=Object.freeze({
         schemaVersion:'palaco.distribution.proof-verification-response.v1',
         requestId,readiness:'PROOF_GATEWAY_VERIFIED_NON_AUTHORIZING',
         authorization:'DENY',go13:'HOLD',
         mayAdvance:false,mayRestore:false,mayReconcile:false,
         maySynchronize:false,mayInstall:false,mayPublish:false,
         findings:Object.freeze([])
        });
       }else{
        outcome=blocked('PROOF_GATEWAY_PROOF_REJECTED',requestId);
       }
      }catch(_){outcome=blocked('PROOF_GATEWAY_VERIFIER_UNAVAILABLE',requestId);}
     }
    }
   }catch(_){outcome=blocked('PROOF_GATEWAY_CLOCK_INVALID',requestId);}
   // Persist an audit receipt even for denied requests; never store the
   // full proof, cryptographic private keys, or the complete request.
   // Audit writer must ensure durable uniqueness/append-only behavior.
   try{
    const event=Object.freeze({
     schemaVersion:'palaco.distribution.proof-verification-audit.v1',
     namespace,principalId,requestId,requestDigest:candidateDigest,
     timestampMs:now,readiness:outcome.readiness,
     finding:outcome.findings[0]||null,
     authorization:'DENY',go13:'HOLD'
    });
    if(!Number.isSafeInteger(now)||now<0||
     await auditAppend(event,signal)!==true){
     return blocked('PROOF_GATEWAY_AUDIT_UNAVAILABLE',requestId);
    }
    return outcome;
   }catch(_){
    return blocked('PROOF_GATEWAY_AUDIT_UNAVAILABLE',requestId);
   }finally{pending=0;}
  }
 });
}
module.exports={VERSION,MAX_REQUEST_BYTES,MAX_REQUESTS_PER_WINDOW,
 WINDOW_MS,validate,createProofVerificationGateway};
