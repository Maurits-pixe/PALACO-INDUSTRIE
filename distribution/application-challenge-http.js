'use strict';

const { isApplicationChallengeIngress } = require('./application-challenge-ingress');

const BASE = '/api/distribution/';
const ALLOWED = new Set([
  '/api/distribution/challenges/issue',
  '/api/distribution/challenges/consume'
]);

function denied(code,status) {
  return Object.freeze({
    status,
    payload:Object.freeze({
      readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
      mayAdvance:false,mayRestore:false,mayInstall:false,mayPublish:false,
      error:code
    })
  });
}

/**
 * HTTP boundary: NEVER construct trust from request data.
 * Requires existing authenticated session + CSRF verification.
 * Missing branded ingress is 503; no fallback to legacy registries.
 * Does not read request body until authorization checks pass.
 */
async function dispatchDistributionHttp({
  method,path,authenticated,csrfValid,ingress,readBody
}={}) {
  if(typeof path!=='string'||!path.startsWith(BASE)) return denied('NOT_DISTRIBUTION_ROUTE',404);
  if(!ALLOWED.has(path)) return denied('DISTRIBUTION_ROUTE_DENIED',404);
  if(method!=='POST') return denied('DISTRIBUTION_METHOD_DENIED',405);
  if(authenticated!==true) return denied('AUTHENTICATION_REQUIRED',401);
  if(csrfValid!==true) return denied('CSRF_REQUIRED',403);
  if(!isApplicationChallengeIngress(ingress))
    return denied('DISTRIBUTION_TRUST_NOT_CONFIGURED',503);
  if(typeof readBody!=='function') return denied('DISTRIBUTION_BODY_READER_UNAVAILABLE',503);
  try {
    const body=await readBody();
    const result=await ingress.dispatch({method,path,body});
    if(!result||result.authorization!=='DENY'||result.go13!=='HOLD')
      return denied('DISTRIBUTION_INVALID_ASSESSMENT',503);
    return Object.freeze({
      status: result.issued===true ? 201 : 403,
      payload:Object.freeze({...result,authorization:'DENY',go13:'HOLD',
        mayAdvance:false,mayRestore:false,mayInstall:false,mayPublish:false})
    });
  } catch (_) {
    return denied('DISTRIBUTION_REQUEST_REJECTED',400);
  }
}
module.exports={dispatchDistributionHttp};
