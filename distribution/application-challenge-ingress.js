'use strict';

const { createCheckpointGuardedChallengeRegistry } =
  require('./prefetched-signed-challenge-registry');

const ACTIONS = Object.freeze(['issue','consume']);
const ROUTES = Object.freeze({
  '/api/distribution/challenges/issue':'issue',
  '/api/distribution/challenges/consume':'consume'
});
const registered = new WeakSet();

function blocked(reason) {
  return Object.freeze({
    readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
    mayAdvance:false,mayRestore:false,mayRotate:false,
    mayInstall:false,mayPublish:false,
    findings:Object.freeze([reason])
  });
}

/**
 * Single explicitly strict adapter for a future application route.
 * No implicit legacy fallback, no key provisioning, no server binding.
 * A verifier can validate a challenge; it never grants release authority.
 */
function createApplicationChallengeIngress(db, options) {
  if (!options || !Array.isArray(options.pinnedReceiptRoots) ||
      options.pinnedReceiptRoots.length < 1 ||
      !Number.isSafeInteger(options.minimumReceiptSequence) ||
      options.minimumReceiptSequence < 0)
    throw new TypeError('Pinned receipt roots and sequence required');
  const pinnedReceiptRoots = Object.freeze(options.pinnedReceiptRoots.map(root =>
    Object.freeze({...root})));
  const minimumReceiptSequence = options.minimumReceiptSequence;
  if (!db || typeof db.exec!=='function' || typeof db.prepare!=='function')
    throw new TypeError('SQLite challenge database required');
  const strict = createCheckpointGuardedChallengeRegistry(db,options);
  let closed=false;
  const ingress=Object.freeze({
    async dispatch({method,path,body}={}) {
      if (closed) return blocked('CHALLENGE_INGRESS_CLOSED');
      if (method!=='POST' || typeof path!=='string' ||
          !Object.hasOwn(ROUTES,path) ||
          !body || typeof body!=='object' || Array.isArray(body))
        return blocked('CHALLENGE_ROUTE_DENIED');
      const action=ROUTES[path];
      if(!ACTIONS.includes(action)) return blocked('CHALLENGE_ROUTE_DENIED');
      try {
        if(action==='issue') {
          // Exact keys only. Never accept an alternate registry, callback,
          // role, authorization token, or request-controlled trust settings.
          if(Object.keys(body).length!==1 ||
             !Object.hasOwn(body,'namespace')) return blocked('CHALLENGE_BODY_INVALID');
          const result=await strict.issue(body.namespace);
          return result.issued===true ?
            Object.freeze({issued:true,challenge:result.challenge,
              authorization:'DENY',go13:'HOLD',mayPublish:false,mayInstall:false}) :
            blocked('CHALLENGE_ISSUE_BLOCKED');
        }
        const allowed=['namespace','challenge','state','endorsement'];
        if(Object.keys(body).length!==allowed.length ||
           allowed.some(key=>!Object.hasOwn(body,key)))
          return blocked('CHALLENGE_BODY_INVALID');
        const result=await strict.consume(body.namespace,body.challenge,
          body.state,body.endorsement,pinnedReceiptRoots,minimumReceiptSequence);
        return Object.freeze({...result,authorization:'DENY',go13:'HOLD',
          mayAdvance:false,mayRestore:false,mayRotate:false,
          mayInstall:false,mayPublish:false});
      }catch(_) { return blocked('CHALLENGE_GATE_UNAVAILABLE'); }
    },
    close() {closed=true;},
    routes:Object.freeze(Object.keys(ROUTES))
  });
  registered.add(ingress);
  return ingress;
}
function isApplicationChallengeIngress(value) {
  return !!value && typeof value==='object' && registered.has(value);
}

module.exports={createApplicationChallengeIngress,isApplicationChallengeIngress};
