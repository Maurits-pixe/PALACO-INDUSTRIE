'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {VERSION,createProofVerificationGateway}=
 require('../distribution/manifest-proof-gateway-v6.1');
function fixture(mods={}){
 const namespace='palaco.v61ci',events=[];
 let now=1000,verified=0;
 const verifier={namespace,
  async verifyInclusion(){verified++;return {
   readiness:'INDEPENDENT_INCLUSION_VERIFIED_NON_AUTHORIZING',
   authorization:'DENY',go13:'HOLD',mayPublish:false};},
  async verifyConsistency(){verified++;return {
   readiness:'INDEPENDENT_CONSISTENCY_VERIFIED_NON_AUTHORIZING',
   authorization:'DENY',go13:'HOLD',mayPublish:false};}
 };
 const service=createProofVerificationGateway({
  namespace,principalId:'restricted-verifier',
  verifier,clock:()=>now,
  auditAppend:async record=>{events.push(record);return true;},...mods
 });
 const request=(id='request-0001',kind='inclusion')=>({
  schemaVersion:VERSION,requestId:id,namespace,kind,
  envelope:{namespace,readiness:'COMPACT_INCLUSION_PROOF_ISSUED_NON_AUTHORIZING'}
 });
 return {namespace,events,service,request,verifier,
  setTime:v=>{now=v;},get verified(){return verified;}};
}
test('fixed inclusion and consistency requests are audit-confirmed but never authorize',async()=>{
 const f=fixture();
 for(const kind of ['inclusion','consistency']){
  const r=await f.service.handle(f.request('request-'+kind,kind));
  assert.equal(r.readiness,'PROOF_GATEWAY_VERIFIED_NON_AUTHORIZING');
  assert.equal(r.authorization,'DENY');assert.equal(r.go13,'HOLD');
  assert.equal(r.mayAdvance,false);assert.equal(r.mayPublish,false);
 }
 assert.equal(f.events.length,2);
 assert.equal(f.events[0].requestDigest.length,64);
 assert.equal(f.events[0].authorization,'DENY');
 assert.equal(typeof f.service.issue,'undefined');
});
test('replay, invalid schema, cross namespace and oversized envelope always block and audit',async()=>{
 const f=fixture();
 assert.equal((await f.service.handle(f.request())).readiness,
  'PROOF_GATEWAY_VERIFIED_NON_AUTHORIZING');
 assert.deepEqual((await f.service.handle(f.request())).findings,
  ['PROOF_GATEWAY_REPLAY']);
 const invalid=[
  {...f.request('request-0002'),schemaVersion:'bad'},
  {...f.request('request-0003'),namespace:'palaco.other'},
  {...f.request('request-0004'),kind:'activate'},
  {...f.request('request-0005'),unexpected:'x'},
  {...f.request('request-0006'),envelope:{padding:'x'.repeat(5000)}},
  null
 ];
 for(const item of invalid){
  const r=await f.service.handle(item);
  assert.equal(r.readiness,'BLOCKED');
  assert.equal(r.authorization,'DENY');
 }
 assert.equal(f.events.length,invalid.length+2);
 assert.equal(f.verified,1);
});
test('per-minute quota limits even denied inputs; no successful bypass',async()=>{
 const f=fixture({maxPerWindow:2});
 assert.equal((await f.service.handle(null)).readiness,'BLOCKED');
 assert.equal((await f.service.handle(f.request('request-0002'))).readiness,
  'PROOF_GATEWAY_VERIFIED_NON_AUTHORIZING');
 assert.deepEqual((await f.service.handle(f.request('request-0003')).findings,
  ['PROOF_GATEWAY_RATE_LIMIT']);
 assert.equal(f.events.length,3);
});
test('non-monotone clock, audit errors and unavailability fail closed',async()=>{
 const f=fixture();
 await f.service.handle(f.request());
 f.setTime(999);
 assert.deepEqual((await f.service.handle(f.request('request-0002')).findings,
  ['PROOF_GATEWAY_CLOCK_INVALID']);
 const broken=fixture({auditAppend:async()=>false});
 assert.deepEqual((await broken.service.handle(broken.request()).findings,
  ['PROOF_GATEWAY_AUDIT_UNAVAILABLE']);
 const throws=fixture({auditAppend:async()=>{throw Error('offline');}});
 assert.equal((await throws.service.handle(throws.request())).readiness,'BLOCKED');
 const failure=fixture({verifier:{namespace:'palaco.v61ci',
  verifyInclusion:async()=>{throw Error('offline');},
  verifyConsistency:async()=>{throw Error('offline');}}});
 assert.deepEqual((await failure.service.handle(failure.request())).findings,
  ['PROOF_GATEWAY_VERIFIER_UNAVAILABLE']);
});
test('concurrent requests are denied without invoking unbounded downstream verification',async()=>{
 let release;
 const latch=new Promise(resolve=>{release=resolve;});
 const f=fixture({verifier:{namespace:'palaco.v61ci',
  verifyInclusion:async()=>{await latch;return {
   readiness:'INDEPENDENT_INCLUSION_VERIFIED_NON_AUTHORIZING',
   authorization:'DENY',go13:'HOLD',mayPublish:false};},
  verifyConsistency:async()=>({readiness:'BLOCKED'})}});
 const pending=f.service.handle(f.request('request-0001'));
 const concurrent=await f.service.handle(f.request('request-0002'));
 assert.deepEqual(concurrent.findings,['PROOF_GATEWAY_BUSY']);
 release();
 assert.equal((await pending).readiness,'PROOF_GATEWAY_VERIFIED_NON_AUTHORIZING');
});
test('aborted requests, non-authorizing verifier outputs and wrong construction deny',async()=>{
 const f=fixture({verifier:{namespace:'palaco.v61ci',
  verifyInclusion:async()=>({readiness:'INDEPENDENT_INCLUSION_VERIFIED_NON_AUTHORIZING',
   authorization:'ALLOW',go13:'HOLD',mayPublish:false}),
  verifyConsistency:async()=>({readiness:'BLOCKED'})}});
 assert.equal((await f.service.handle(f.request())).readiness,'BLOCKED');
 const good=fixture(),abort=new AbortController();abort.abort();
 assert.deepEqual((await good.service.handle(good.request(),abort.signal)).findings,
  ['PROOF_GATEWAY_ABORTED']);
 assert.throws(()=>createProofVerificationGateway({
  namespace:'palaco.v61ci',verifier:good.verifier,clock:()=>0,
  auditAppend:async()=>true,principalId:'operator',maxPerWindow:0
 }),TypeError);
});
