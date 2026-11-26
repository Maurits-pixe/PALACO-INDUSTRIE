'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {incidentPayload,incidentDigest,verifyWitnessIncident,
 verifyLiveWitnessIncident}=require('../distribution/witness-incident-review');
const a=generateKeyPairSync('ed25519'),b=generateKeyPairSync('ed25519');
const pem=keys=>keys.publicKey.export({type:'spki',format:'pem'});
function fixture(){
 const incident={
  schemaVersion:'palaco.distribution.witness-incident.v1',
  namespace:'palaco.registry',incidentId:'incident-0001',
  sequence:12,priorIncidentDigest:'0'.repeat(64),
  observedAtMs:1000,expiresAtMs:5000,
  primary:{revision:10,digest:'a'.repeat(64)},
  secondary:{revision:11,digest:'b'.repeat(64)},
  authorization:'DENY',go13:'HOLD',recommendedAction:'QUARANTINE_NO_SYNC'
 };
 const signAs=(id,keys)=>({algorithm:'Ed25519',keyId:id,
   signature:sign(null,incidentPayload(incident),keys.privateKey).toString('base64')});
 const endorsements=[signAs('k-alice',a),signAs('k-bob',b)];
 const policy={namespace:'palaco.registry',minimumSequence:12,
  priorIncidentDigest:'0'.repeat(64),nowMs:2000,
  pinnedReviewRoots:[
   {keyId:'k-alice',reviewerId:'alice',enabled:true,revoked:false,publicKeyPem:pem(a)},
   {keyId:'k-bob',reviewerId:'bob',enabled:true,revoked:false,publicKeyPem:pem(b)}
  ]};
 const store=(state)=>({namespace:'palaco.registry',latest:async()=>({...state})});
 const witnesses={primary:store(incident.primary),secondary:store(incident.secondary)};
 return {incident,endorsements,policy,witnesses,signAs};
}
const verify=f=>verifyWitnessIncident(f.incident,f.endorsements,f.policy);
const live=f=>verifyLiveWitnessIncident(f.incident,f.endorsements,f.policy,f.witnesses);
test('two independent signed reviewers only attest HOLD incident, never synchronization',()=>{
 const f=fixture(),r=verify(f);
 assert.equal(r.readiness,'INCIDENT_REVIEW_VERIFIED_NON_AUTHORIZING');
 assert.equal(r.authorization,'DENY');assert.equal(r.go13,'HOLD');
 assert.equal(r.maySynchronize,false);assert.equal(r.mayReconcile,false);
 assert.equal(r.mayRestore,false);assert.match(r.incidentDigest,/^[a-f0-9]{64}$/);
 assert.ok(Object.isFrozen(r));
});
test('live witness verification matches both exact observed heads',async()=>{
 const f=fixture();
 const r=await live(f);
 assert.equal(r.readiness,'INCIDENT_LIVE_DIVERGENCE_VERIFIED_NON_AUTHORIZING');
 assert.equal(r.maySynchronize,false);assert.equal(r.authorization,'DENY');
});
test('forged snapshot, reordered witnesses, healed witness or stale observation is denied',async()=>{
 for(const mutate of [
  f=>{f.witnesses.primary.latest=async()=>({...f.incident.secondary});},
  f=>{f.witnesses.secondary.latest=async()=>({...f.incident.primary});},
  f=>{f.witnesses.secondary.latest=async()=>({...f.incident.primary,
    revision:12,digest:'c'.repeat(64)});},
  f=>{f.witnesses.secondary.latest=async()=>null;},
  f=>{f.witnesses.secondary.latest=async()=>{throw Error('down');}}
 ]){
  const f=fixture();mutate(f);
  const result=await live(f);
  assert.equal(result.readiness,'BLOCKED');assert.equal(result.maySynchronize,false);
 }
});
test('signed content tampering and unsanctioned repair instruction are rejected',()=>{
 for(const mutate of [
  f=>{f.incident.primary.digest='f'.repeat(64);},
  f=>{f.incident.recommendedAction='SYNC_SECONDARY_TO_PRIMARY';},
  f=>{f.incident.authorization='ALLOW';},
  f=>{f.incident.go13='GO';},
  f=>{f.incident.secondary={...f.incident.primary};}
 ]){
  const f=fixture();mutate(f);
  assert.equal(verify(f).readiness,'BLOCKED');
 }
});
test('separate reviewer keys and persons are mandatory; revocation blocks',()=>{
 for(const mutate of [
  f=>{f.endorsements.pop();},
  f=>{f.endorsements[1]=f.endorsements[0];},
  f=>{f.policy.pinnedReviewRoots[1].reviewerId='alice';},
  f=>{f.policy.pinnedReviewRoots[0].revoked=true;},
  f=>{f.policy.pinnedReviewRoots[0].enabled=false;}
 ]){
  const f=fixture();mutate(f);
  assert.equal(verify(f).readiness,'BLOCKED');
 }
});
test('signed incident cannot replay against newer independent incident sequence',()=>{
 const f=fixture();f.policy.minimumSequence=13;
 assert.deepEqual(verify(f).findings,['INCIDENT_REPLAY_OR_CHAIN_MISMATCH']);
});
test('expired, future and excessive lifetime review cannot be reused',()=>{
 for(const mutate of [
  f=>{f.policy.nowMs=5000;},
  f=>{f.policy.nowMs=999;},
  f=>{f.policy.maximumLifetimeMs=500;},
  f=>{f.incident.expiresAtMs=86403000;}
 ]){
  const f=fixture();mutate(f);
  assert.equal(verify(f).readiness,'BLOCKED');
 }
});
test('unavailable independent incident anchor rejects without trusting signatures',()=>{
 for(const mutate of [
  f=>{delete f.policy.minimumSequence;},
  f=>{delete f.policy.priorIncidentDigest;},
  f=>{f.policy.nowMs=-1;}
 ]){
  const f=fixture();mutate(f);
  assert.deepEqual(verify(f).findings,['INCIDENT_INDEPENDENT_ANCHOR_UNAVAILABLE']);
 }
});
test('missing witness or pre-aborted request cannot perform live verification',async()=>{
 const f=fixture();
 assert.equal((await verifyLiveWitnessIncident(f.incident,f.endorsements,
  f.policy,null)).readiness,'BLOCKED');
 const c=new AbortController();c.abort();
 assert.equal((await verifyLiveWitnessIncident(f.incident,f.endorsements,
  f.policy,f.witnesses,c.signal)).readiness,'BLOCKED');
});
