'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {VERSION,payload}=require('../distribution/third-party-evidence-checkpoint-v5.4');
const {manifestDigest,createThirdWitnessKeyHistoryVerifier}=
 require('../distribution/third-witness-key-history-v5.5');
function fixture(){
 const namespace='palaco.v55ci',kp=generateKeyPairSync('ed25519');
 const observation={schemaVersion:VERSION,namespace,sequence:12,
  chainDigest:'b'.repeat(64),observerId:'independent-auditor',
  observedAtMs:1500,authorization:'DENY',go13:'HOLD',
  purpose:'INDEPENDENT_OBSERVATION_NO_AUTHORITY'};
 const signature=sign(null,payload(observation),kp.privateKey).toString('base64');
 const manifest={
  schemaVersion:'palaco.distribution.third-witness-key-history.v1',
  namespace,floorSequence:12,floorDigest:observation.chainDigest,
  epochs:[{observerId:observation.observerId,keyId:'external-key',
   validFromMs:1000,validUntilMs:5000,enabled:true,revoked:false,
   publicKeyPem:kp.publicKey.export({type:'spki',format:'pem'})}]
 };
 const third=()=>({rowCount:1,rows:[{
  namespace,sequence:'12',chain_digest:observation.chainDigest,
  observed_at_ms:'1500',observer_id:observation.observerId,
  key_id:'external-key',signature
 }]});
 const anchor=()=>({rowCount:1,rows:[{
  sequence:'12',chain_digest:observation.chainDigest
 }]});
 const create=(mods={})=>createThirdWitnessKeyHistoryVerifier({
  namespace,anchorQuery:async()=>anchor(),
  thirdPartyQuery:async()=>third(),
  historyProvider:async()=>manifest,
  pinnedManifestDigest:manifestDigest(manifest),...mods
 });
 return {namespace,kp,manifest,observation,signature,anchor,third,create};
}
test('pinned history validates third witness Ed25519 and holds all authority',async()=>{
 const f=fixture(),r=await f.create().verify();
 assert.equal(r.readiness,'THIRD_WITNESS_KEY_HISTORY_VERIFIED_NON_AUTHORIZING');
 assert.equal(r.authorization,'DENY');assert.equal(r.go13,'HOLD');
 assert.equal(r.mayRestore,false);assert.equal(r.maySynchronize,false);
 assert.equal(r.keyId,'external-key');assert.equal(r.manifestDigest,manifestDigest(f.manifest));
});
test('three databases jointly rolled back to older revision fail independent floor',async()=>{
 const f=fixture();
 const rollback=await f.create({
  thirdPartyQuery:async()=>({rowCount:1,rows:[{
   ...f.third().rows[0],sequence:'11',chain_digest:'a'.repeat(64)
  }]}),
  anchorQuery:async()=>({rowCount:1,rows:[{
   sequence:'11',chain_digest:'a'.repeat(64)
  }]})
 }).verify();
 assert.deepEqual(rollback.findings,['THIRD_HISTORY_HIGH_WATER_ROLLBACK']);
});
test('replacement of pinned key history or floor is rejected before signature use',async()=>{
 const f=fixture();
 for(const modify of [
  m=>{m.floorSequence=11;},
  m=>{m.floorDigest='f'.repeat(64);},
  m=>{m.epochs[0].publicKeyPem=generateKeyPairSync('ed25519')
   .publicKey.export({type:'spki',format:'pem'});},
  m=>{m.epochs[0].validFromMs=1400;},
  m=>{m.epochs[0].revoked=true;}
 ]){
  const changed=structuredClone(f.manifest);modify(changed);
  const r=await f.create({historyProvider:async()=>changed}).verify();
  assert.deepEqual(r.findings,['THIRD_HISTORY_PIN_MISMATCH']);
 }
});
test('signing key outside immutable epoch or revoked at trusted roster blocks',async()=>{
 const f=fixture();
 for(const time of ['999','5000']){
  const row={...f.third().rows[0],observed_at_ms:time};
  const r=await f.create({
   thirdPartyQuery:async()=>({rowCount:1,rows:[row]})
  }).verify();
  assert.deepEqual(r.findings,['THIRD_HISTORY_KEY_EPOCH_INVALID']);
 }
});
test('tampered witness signature and compromised external root fail closed',async()=>{
 const f=fixture();
 for(const mods of [
  {thirdPartyQuery:async()=>({rowCount:1,rows:[{
   ...f.third().rows[0],signature:'A'.repeat(86)+'=='
  }]})},
  {anchorQuery:async()=>({rowCount:1,rows:[{
   sequence:'11',chain_digest:'a'.repeat(64)
  }]})},
  {historyProvider:async()=>{throw Error('root offline');}},
  {thirdPartyQuery:async()=>{throw Error('third offline');}}
 ]){
  const r=await f.create(mods).verify();
  assert.equal(r.readiness,'BLOCKED');
  assert.equal(r.authorization,'DENY');
 }
});
test('missing independent floor, malformed policy and aborted checks deny',async()=>{
 const f=fixture();
 const invalid=structuredClone(f.manifest);invalid.epochs.push({...invalid.epochs[0]});
 assert.equal(manifestDigest(invalid),null);
 assert.equal(manifestDigest({...f.manifest,epochs:[]}),null);
 const c=new AbortController();c.abort();
 assert.equal((await f.create().verify(c.signal)).readiness,'BLOCKED');
 assert.throws(()=>createThirdWitnessKeyHistoryVerifier({
  namespace:f.namespace,anchorQuery:async()=>({}),
  thirdPartyQuery:async()=>({}),historyProvider:async()=>f.manifest,
  pinnedManifestDigest:'wrong'
 }),TypeError);
 assert.equal(f.create().repair,undefined);
});
