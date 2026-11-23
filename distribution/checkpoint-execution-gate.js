'use strict';

const { randomBytes } = require('node:crypto');
const { verifyPostgresCheckpoint } = require('./postgres-checkpoint-verifier');

const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const trusted=new WeakSet();

/**
 * Attested preflight. Caller-provided anchor provider MUST be independent
 * of PostgreSQL and the checkpoint issuer's rollback/trust domain.
 * This module does not create the external witness or its trust.
 */
function createCheckpointExecutionGate({
  namespace, fetchCheckpoint, fetchIndependentAnchor, query
}={}) {
  if(typeof namespace!=='string'||!NS.test(namespace)||
     typeof fetchCheckpoint!=='function'||
     typeof fetchIndependentAnchor!=='function'||typeof query!=='function')
    throw new TypeError('Independent checkpoint execution gate required');
  const gate=Object.freeze({
    namespace,
    async verify(expectedEpoch,expectedFloor,signal) {
      if (!Number.isSafeInteger(expectedEpoch)||expectedEpoch<0||
          !Number.isSafeInteger(expectedFloor)||expectedFloor<0||
          !signal||typeof signal.aborted!=='boolean'||signal.aborted) return false;
      const challenge=randomBytes(32).toString('hex');
      // Independently provided anchor is queried each time: no stale cache
      // may silently downgrade the verifier's externally held chain head.
      const [evidence,anchor]=await Promise.all([
        fetchCheckpoint(challenge,signal),
        fetchIndependentAnchor(challenge,signal)
      ]);
      if(signal.aborted||!evidence||!evidence.checkpoint||!anchor) return false;
      const cp=evidence.checkpoint;
      if(cp.namespace!==namespace || cp.challenge!==challenge ||
         cp.epoch!==expectedEpoch ||
         cp.minimumLastSeenMs!==expectedFloor ||
         anchor.namespace!==namespace || anchor.challenge!==challenge)
        return false;
      const verified=await verifyPostgresCheckpoint(query,cp,evidence.endorsement,anchor);
      return verified.readiness==='CHECKPOINT_VERIFIED'&&!signal.aborted;
    }
  });
  trusted.add(gate);
  return gate;
}
function isCheckpointExecutionGate(value) {
  return value!==null&&typeof value==='object'&&trusted.has(value);
}
module.exports={createCheckpointExecutionGate,isCheckpointExecutionGate};
