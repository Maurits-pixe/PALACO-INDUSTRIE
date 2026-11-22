'use strict';
const { randomBytes, createHash } = require('node:crypto');
const { verifyAuthorityReceipt } = require('./authority-receipt');
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const CHALLENGE=/^[a-f0-9]{64}$/;
function blocked(reason) {
 return Object.freeze({schemaVersion:'palaco.distribution.durable-challenge-assessment.v1',
 readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
 mayAdvance:false,mayRestore:false,mayRotate:false,mayInstall:false,mayPublish:false,
 findings:Object.freeze([reason])});
}
function initializeDurableChallengeSchema(db) {
 db.exec("CREATE TABLE IF NOT EXISTS distribution_challenge_clock (singleton INTEGER PRIMARY KEY CHECK(singleton=1),last_seen_ms INTEGER NOT NULL) STRICT");
 db.exec("CREATE TABLE IF NOT EXISTS distribution_challenges (challenge_hash TEXT PRIMARY KEY,namespace TEXT NOT NULL,expires_at_ms INTEGER NOT NULL,status TEXT NOT NULL CHECK(status IN ('pending','consumed'))) STRICT");
 db.exec("CREATE INDEX IF NOT EXISTS distribution_challenges_pending ON distribution_challenges(status,expires_at_ms)");
}
function createDurableChallengeRegistry(db,{ttlMs=60000,maxPending=128,clock=Date.now}={}) {
 if(!Number.isSafeInteger(ttlMs)||ttlMs<1||ttlMs>300000||
    !Number.isSafeInteger(maxPending)||maxPending<1||maxPending>4096||
    typeof clock!=='function') throw new RangeError('Invalid challenge registry configuration');
 const digest=token=>createHash('sha256').update('PALACO-INDUSTRIE-CHALLENGE-V1\n').update(token,'ascii').digest('hex');
 function transaction(action) {
  let active=false;
  try {
   db.exec('BEGIN IMMEDIATE'); active=true;
   const now=clock();
   if(!Number.isSafeInteger(now)||now<0||now>Number.MAX_SAFE_INTEGER-ttlMs) throw new Error('INVALID_TIME');
   const previous=db.prepare('SELECT last_seen_ms FROM distribution_challenge_clock WHERE singleton=1').get();
   if(previous&&(!Number.isSafeInteger(previous.last_seen_ms)||now<previous.last_seen_ms)) throw new Error('CLOCK_ROLLBACK');
   db.prepare('INSERT INTO distribution_challenge_clock(singleton,last_seen_ms) VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET last_seen_ms=excluded.last_seen_ms').run(now);
   const result=action(now);
   db.exec('COMMIT'); active=false;
   return result;
  } catch (_) {
   if(active) { try {db.exec('ROLLBACK');} catch (_) {} }
   return null;
  }
 }
 function issue(namespace) {
  if(typeof namespace!=='string'||!NS.test(namespace)) return Object.freeze({issued:false,reason:'INVALID_NAMESPACE'});
  const result=transaction(now=>{
   const count=db.prepare("SELECT COUNT(*) AS n FROM distribution_challenges WHERE status='pending' AND expires_at_ms>?").get(now).n;
   if(count>=maxPending) return {issued:false,reason:'CHALLENGE_CAPACITY_REACHED'};
   const challenge=randomBytes(32).toString('hex');
   db.prepare("INSERT INTO distribution_challenges(challenge_hash,namespace,expires_at_ms,status) VALUES(?,?,?,'pending')").run(digest(challenge),namespace,now+ttlMs);
   return {issued:true,challenge};
  });
  return Object.freeze(result||{issued:false,reason:'CHALLENGE_STORAGE_UNAVAILABLE'});
 }
 function consume(namespace,challenge,state,endorsement,pinnedRoots,minimumSequence) {
  if(typeof challenge!=='string'||!CHALLENGE.test(challenge)) return blocked('INVALID_CHALLENGE');
  const status=transaction(now=>{
   const key=digest(challenge);
   const row=db.prepare('SELECT namespace,expires_at_ms,status FROM distribution_challenges WHERE challenge_hash=?').get(key);
   if(!row||row.status!=='pending') return 'UNKNOWN_OR_REPLAYED_CHALLENGE';
   const updated=db.prepare("UPDATE distribution_challenges SET status='consumed' WHERE challenge_hash=? AND status='pending'").run(key);
   if(updated.changes!==1) return 'CHALLENGE_CONFLICT';
   if(now>=row.expires_at_ms) return 'CHALLENGE_EXPIRED';
   if(row.namespace!==namespace) return 'CHALLENGE_NAMESPACE_MISMATCH';
   return 'OK';
  });
  if(status===null) return blocked('CHALLENGE_STORAGE_UNAVAILABLE');
  if(status!=='OK') return blocked(status);
  try { return verifyAuthorityReceipt(namespace,state,endorsement,pinnedRoots,challenge,minimumSequence); }
  catch (_) { return blocked('AUTHORITY_VERIFICATION_FAILED'); }
 }
 return Object.freeze({issue,consume});
}
module.exports={initializeDurableChallengeSchema,createDurableChallengeRegistry};
