'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {VERSION,publicationBytes,createManifestPublicationViewVerifier}=
 require('../distribution/manifest-publication-views-v5.7');
function fixture(){
 const namespace='palaco.v57ci';
 const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
 const roots=keys.map((k,i)=>({
  observerId:'observer-'+i,keyId:'key-'+i,enabled:true,revoked:false,
  publicKeyPem:k.publicKey.export({type:'spki',format:'pem'})
 }));
 const previous='a'.repeat(64),next='b'.repeat(64);
 const make=(i,digest=next)=>{
  const p={schemaVersion:VERSION,namespace,rotationNumber:1,
   manifestDigest:digest,previousManifestDigest:previous,
   observerId:roots[i].observerId,observedAtMs:1500,
   authorization:'DENY',go13:'HOLD',
   purpose:'MANIFEST_VIEW_OBSERVATION_NO_RELEASE'};
  return {namespace,rotation_number:'1',manifest_digest:digest,
   previous_manifest_digest:previous,observer_id:p.observerId,
   observed_at_ms:'1500',key_id:roots[i].keyId,
   signature:sign(null,publicationBytes(p),keys[i].privateKey).toString('base64')};
 };
 const views=[make(0),make(1)];
 const build=(first=views[0],second=views[1],mods={})=>
  createManifestPublicationViewVerifier({
   namespace,rotationNumber:1,pinnedPreviousDigest:previous,
   pinnedNextDigest:next,firstQuery:async()=>({rowCount:1,rows:[first]}),
   secondQuery:async()=>({rowCount:1,rows:[second]}),
   rootProvider:async(ns,observer)=>roots.find(r=>r.observerId===observer),
   ...mods
  });
 return {make,roots,views,build,namespace,previous,next};
}
test('two independent signed publication views match with DENY HOLD',async()=>{
 const f=fixture(),result=await f.build().verify();
 assert.equal(result.readiness,'TWO_PUBLICATION_VIEWS_MATCH_NON_AUTHORIZING');
 assert.equal(result.authorization,'DENY');assert.equal(result.go13,'HOLD');
 assert.equal(result.mayPublish,false);assert.equal(result.mayAdvance,false);
});
test('two different validly signed manifests at the same rotation detect split-view',async()=>{
 const f=fixture();
 const outcome=await f.build(f.views[0],f.make(1,'c'.repeat(64))).verify();
 assert.deepEqual(outcome.findings,['PUBLICATION_VIEW_SIGNED_SPLIT_VIEW_DETECTED']);
 assert.equal(outcome.mayReconcile,false);
});
test('forged signature, stale pin, revoked signer and common observer fail',async()=>{
 const f=fixture();
 for(const options of [
  {first:{...f.views[0],signature:'A'.repeat(86)+'=='}},
  {second:{...f.views[1],manifest_digest:'f'.repeat(64)}},
  {mods:{pinnedNextDigest:'f'.repeat(64)}},
  {mods:{rootProvider:async()=>({...f.roots[0],revoked:true})}},
  {mods:{rootProvider:async()=>f.roots[0]}}
 ]){
  const r=await f.build(options.first||f.views[0],
   options.second||f.views[1],options.mods||{}).verify();
  assert.equal(r.readiness,'BLOCKED');
 }
});
test('missing or unavailable independent source is permanently blocked',async()=>{
 const f=fixture();
 for(const mods of [
  {firstQuery:async()=>{throw Error('offline');}},
  {secondQuery:async()=>({rowCount:0,rows:[]})},
  {rootProvider:async()=>{throw Error('roster offline');}}
 ])assert.equal((await f.build(undefined,undefined,mods).verify()).readiness,'BLOCKED');
});
test('replay, wrong namespace and invalid purpose never verify',async()=>{
 const f=fixture();
 for(const changes of [
  {rotation_number:'2'},
  {namespace:'other.namespace'},
  {observed_at_ms:'-1'}
 ]){
  const result=await f.build({...f.views[0],...changes}).verify();
  assert.equal(result.readiness,'BLOCKED');
 }
 assert.equal(publicationBytes({
  schemaVersion:VERSION,namespace:f.namespace,
  rotationNumber:1,manifestDigest:f.next,
  previousManifestDigest:f.previous,observerId:'observer-0',
  observedAtMs:1500,authorization:'ALLOW',go13:'HOLD',
  purpose:'MANIFEST_VIEW_OBSERVATION_NO_RELEASE'
 }),null);
});
test('abort and non-independent adapter cannot publish or mutate trust',async()=>{
 const f=fixture(),controller=new AbortController();controller.abort();
 assert.equal((await f.build().verify(controller.signal)).readiness,'BLOCKED');
 const q=async()=>({rowCount:0,rows:[]});
 assert.throws(()=>createManifestPublicationViewVerifier({
  namespace:f.namespace,rotationNumber:1,pinnedPreviousDigest:f.previous,
  pinnedNextDigest:f.next,firstQuery:q,secondQuery:q,
  rootProvider:async()=>f.roots[0]
 }),TypeError);
 assert.equal(f.build().publish,undefined);
});
