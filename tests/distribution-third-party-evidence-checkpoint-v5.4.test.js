'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {VERSION,payload,createThirdPartyEvidenceCheckpointVerifier}=
 require('../distribution/third-party-evidence-checkpoint-v5.4');
function fixture(){
 const namespace='palaco.v54ci',keys=generateKeyPairSync('ed25519');
 const observation={schemaVersion:VERSION,namespace,sequence:12,
  chainDigest:'b'.repeat(64),observerId:'external-auditor',
  observedAtMs:1500,authorization:'DENY',go13:'HOLD',
  purpose:'INDEPENDENT_OBSERVATION_NO_AUTHORITY'};
 const signature=sign(null,payload(observation),keys.privateKey).toString('base64');
 const trusted={observerId:'external-auditor',keyId:'audit-key',
  enabled:true,revoked:false,
  publicKeyPem:keys.publicKey.export({type:'spki',format:'pem'})};
 const ref=()=>({rowCount:1,rows:[{sequence:'12',chain_digest:observation.chainDigest}]});
 const third=()=>({rowCount:1,rows:[{
  namespace,sequence:'12',chain_digest:observation.chainDigest,
  observed_at_ms:'1500',observer_id:observation.observerId,
  key_id:'audit-key',signature
 }]});
 const create=(mods={})=>createThirdPartyEvidenceCheckpointVerifier({
  namespace,anchorQuery:async()=>ref(),
  thirdPartyQuery:async()=>third(),
  trustRootProvider:async()=>trusted,...mods
 });
 return {namespace,observation,signature,trusted,ref,third,create};
}
test('third party signature and same high-water head verify without authorizing',async()=>{
 const f=fixture(),r=await f.create().verify();
 assert.equal(r.readiness,'THIRD_PARTY_CHECKPOINT_MATCHED_NON_AUTHORIZING');
 assert.equal(r.authorization,'DENY');assert.equal(r.go13,'HOLD');
 assert.equal(r.mayAdvance,false);assert.equal(r.mayRestore,false);
});
test('coordinated first and second store rollback is caught by third-party checkpoint',async()=>{
 const f=fixture();
 const rolled=await f.create({
  anchorQuery:async()=>({rowCount:1,rows:[{
   sequence:'11',chain_digest:'a'.repeat(64)}]})
 }).verify();
 assert.deepEqual(rolled.findings,['THIRD_CHECKPOINT_ROOT_ROLLBACK_OR_FORK']);
 assert.equal(rolled.mayReconcile,false);
});
test('forged checkpoint, revoked key and tampered external root are blocked',async()=>{
 const f=fixture();
 for(const mods of [
  {thirdPartyQuery:async()=>({rowCount:1,rows:[{
   ...f.third().rows[0],signature:'A'.repeat(86)+'=='}]})},
  {thirdPartyQuery:async()=>({rowCount:1,rows:[{
   ...f.third().rows[0],chain_digest:'f'.repeat(64)}]})},
  {trustRootProvider:async()=>({...f.trusted,revoked:true})},
  {trustRootProvider:async()=>null},
  {anchorQuery:async()=>({rowCount:1,rows:[{
   sequence:'12',chain_digest:'f'.repeat(64)}]})}
 ]){
  const r=await f.create(mods).verify();
  assert.equal(r.readiness,'BLOCKED');
  assert.equal(r.authorization,'DENY');
 }
});
test('missing third-party records or outages deny regardless of source state',async()=>{
 const f=fixture();
 for(const mods of [
  {thirdPartyQuery:async()=>({rowCount:0,rows:[]})},
  {anchorQuery:async()=>{throw Error('offline');}},
  {thirdPartyQuery:async()=>{throw Error('offline');}},
  {trustRootProvider:async()=>{throw Error('offline');}}
 ])assert.equal((await f.create(mods).verify()).readiness,'BLOCKED');
});
test('untrusted observer, invalid checkpoint and aborted signal reject',async()=>{
 const f=fixture();
 const wrong=await f.create({trustRootProvider:async()=>({
  ...f.trusted,observerId:'other'})}).verify();
 assert.equal(wrong.readiness,'BLOCKED');
 assert.equal(payload({...f.observation,go13:'ALLOW'}),null);
 const abort=new AbortController();abort.abort();
 assert.equal((await f.create().verify(abort.signal)).readiness,'BLOCKED');
});
test('third-party adapter cannot sign or expose database writes',()=>{
 const f=fixture(),verifier=f.create();
 assert.equal(typeof verifier.sign,'undefined');
 assert.equal(typeof verifier.query,'undefined');
 assert.equal(typeof verifier.advance,'undefined');
 assert.ok(Object.isFrozen(verifier));
 assert.throws(()=>createThirdPartyEvidenceCheckpointVerifier({
  namespace:f.namespace,anchorQuery:f.ref,thirdPartyQuery:f.ref,
  trustRootProvider:async()=>f.trusted
 }),TypeError);
});
