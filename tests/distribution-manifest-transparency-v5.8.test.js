'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {publicationBytes,VERSION}=require('../distribution/manifest-publication-views-v5.7');
const {ZERO,CHECKPOINT_VERSION,entryDigest,checkpointBytes,
 createManifestTransparencyVerifier}=require('../distribution/manifest-transparency-v5.8');
function fixture(){
 const namespace='palaco.v58ci';
 const keys=Array.from({length:3},()=>generateKeyPairSync('ed25519'));
 const roots=keys.map((key,i)=>({
  observerId:i===2?'anchor-reviewer':'observer-'+i,
  keyId:'key-'+i,enabled:true,revoked:false,
  publicKeyPem:key.publicKey.export({type:'spki',format:'pem'})
 }));
 const prev='a'.repeat(64),next='b'.repeat(64);
 let prior=ZERO;
 const rows=[0,1].map((i)=>{
  const view={schemaVersion:VERSION,namespace,rotationNumber:1,
   manifestDigest:next,previousManifestDigest:prev,
   observerId:roots[i].observerId,observedAtMs:1500+i,
   authorization:'DENY',go13:'HOLD',
   purpose:'MANIFEST_VIEW_OBSERVATION_NO_RELEASE'};
  const signature=sign(null,publicationBytes(view),keys[i].privateKey)
   .toString('base64');
  const e={
   namespace,entry_sequence:String(i+1),previous_entry_digest:prior,
   rotation_number:'1',manifest_digest:next,
   previous_manifest_digest:prev,observer_id:view.observerId,
   key_id:roots[i].keyId,observed_at_ms:String(1500+i),signature
  };
  e.entry_digest=entryDigest(e,prior);
  prior=e.entry_digest;return e;
 });
 function signedHead(sequence=2,digest=rows[sequence-1]?.entry_digest){
  const c={schemaVersion:CHECKPOINT_VERSION,namespace,
   entrySequence:sequence,entryDigest:digest,
   observerId:'anchor-reviewer',observedAtMs:2000,
   authorization:'DENY',go13:'HOLD',
   purpose:'MANIFEST_TRANSPARENCY_OBSERVATION_NO_AUTHORITY'};
  return {
   namespace,entry_sequence:String(sequence),entry_digest:digest,
   observer_id:c.observerId,key_id:'key-2',observed_at_ms:'2000',
   signature:sign(null,checkpointBytes(c),keys[2].privateKey).toString('base64')
  };
 }
 const create=(events=rows,head=signedHead(),mods={})=>
  createManifestTransparencyVerifier({
   namespace,pinnedCheckpointSequence:1,
   pinnedCheckpointDigest:rows[0].entry_digest,
   logQuery:async()=>({rowCount:events.length,rows:events}),
   checkpointQuery:async()=>({rowCount:1,rows:[head]}),
   observationRootProvider:async(ns,id)=>roots.find(r=>r.observerId===id),
   checkpointRootProvider:async()=>roots[2],...mods
  });
 return {namespace,keys,roots,rows,create,signedHead};
}
test('complete two-observer signed chain verifies against pinned external checkpoint',async()=>{
 const f=fixture(),r=await f.create().verify();
 assert.equal(r.readiness,'MANIFEST_TRANSPARENCY_VERIFIED_NON_AUTHORIZING');
 assert.equal(r.verifiedObservations,2);
 assert.equal(r.authorization,'DENY');assert.equal(r.go13,'HOLD');
 assert.equal(r.mayPublish,false);assert.equal(r.mayRestore,false);
});
test('omission, reordering and changed predecessor are blocked',async()=>{
 const f=fixture();
 for(const events of [
  f.rows.slice(1),[f.rows[1],f.rows[0]],
  [f.rows[0],{...f.rows[1],previous_entry_digest:'f'.repeat(64)}],
  [f.rows[0],{...f.rows[1],entry_sequence:'3'}]
 ])assert.equal((await f.create(events).verify()).readiness,'BLOCKED');
});
test('privileged restored log is denied by independent signed high watermark',async()=>{
 const f=fixture();
 const out=await f.create(f.rows.slice(0,1)).verify();
 assert.deepEqual(out.findings,['TRANSPARENCY_CHECKPOINT_HEAD_MISMATCH']);
 const rolled=await f.create(f.rows,
  f.signedHead(1,f.rows[0].entry_digest)).verify();
 assert.deepEqual(rolled.findings,['TRANSPARENCY_CHECKPOINT_HEAD_MISMATCH']);
});
test('forged signed events, altered digest and invalid signed checkpoint reject',async()=>{
 const f=fixture();
 for(const data of [
  {rows:[f.rows[0],{...f.rows[1],signature:'A'.repeat(86)+'=='}]},
  {rows:[f.rows[0],{...f.rows[1],entry_digest:'c'.repeat(64)}]},
  {head:{...f.signedHead(),signature:'A'.repeat(86)+'=='}},
  {mods:{checkpointRootProvider:async()=>({...f.roots[2],revoked:true})}}
 ]){
  const r=await f.create(data.rows||f.rows,data.head||f.signedHead(),
   data.mods||{}).verify();
  assert.equal(r.readiness,'BLOCKED');
 }
});
test('authentic contradictory second observer triggers split view',async()=>{
 const f=fixture();
 const e={...f.rows[1],manifest_digest:'c'.repeat(64)};
 const view={schemaVersion:VERSION,namespace:f.namespace,rotationNumber:1,
  manifestDigest:e.manifest_digest,
  previousManifestDigest:e.previous_manifest_digest,
  observerId:e.observer_id,observedAtMs:1501,
  authorization:'DENY',go13:'HOLD',
  purpose:'MANIFEST_VIEW_OBSERVATION_NO_RELEASE'};
 e.signature=sign(null,publicationBytes(view),f.keys[1].privateKey)
  .toString('base64');
 e.entry_digest=entryDigest(e,e.previous_entry_digest);
 const r=await f.create([f.rows[0],e],f.signedHead(2,e.entry_digest)).verify();
 assert.deepEqual(r.findings,['TRANSPARENCY_AUTHENTIC_SPLIT_VIEW']);
});
test('unavailable external checkpoint and aborted verification fail closed',async()=>{
 const f=fixture();
 const abort=new AbortController();abort.abort();
 assert.equal((await f.create().verify(abort.signal)).readiness,'BLOCKED');
 for(const mods of [
  {checkpointQuery:async()=>{throw Error('unavailable');}},
  {logQuery:async()=>({rowCount:0,rows:[]})},
  {observationRootProvider:async()=>null}
 ])assert.equal((await f.create(f.rows,f.signedHead(),mods).verify()).readiness,
  'BLOCKED');
 assert.equal(f.create().repair,undefined);
});
