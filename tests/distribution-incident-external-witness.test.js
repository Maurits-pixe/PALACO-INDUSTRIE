'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createIncidentExternalWitness,verifyIncidentArchiveWitness}=
 require('../distribution/incident-external-witness');
const digest='a'.repeat(64);
const archive=head=>({namespace:'palaco.registry',latest:async()=>head});
const witness=head=>({namespace:'palaco.registry',latest:async()=>head});
test('matching independent archive head is evidence only',async()=>{
 const r=await verifyIncidentArchiveWitness(archive({sequence:4,digest}),
  witness({sequence:4,digest}));
 assert.equal(r.readiness,'INCIDENT_ARCHIVE_HEAD_VERIFIED_NON_AUTHORIZING');
 assert.equal(r.authorization,'DENY');assert.equal(r.go13,'HOLD');
 assert.equal(r.mayRestore,false);assert.equal(r.maySynchronize,false);
});
test('stale restored archive, altered digest and unavailable witness fail closed',async()=>{
 const cases=[
  [archive({sequence:3,digest}),witness({sequence:4,digest})],
  [archive({sequence:4,digest}),witness({sequence:4,digest:'b'.repeat(64)})],
  [archive({sequence:4,digest}),witness(null)],
  [archive(null),witness({sequence:4,digest})],
  [archive({sequence:4,digest}),{namespace:'palaco.registry',
    latest:async()=>{throw Error('offline');}}],
 ];
 for(const [a,w] of cases){
  const r=await verifyIncidentArchiveWitness(a,w);
  assert.equal(r.readiness,'BLOCKED');assert.equal(r.mayRestore,false);
 }
});
test('same object, wrong namespace, abort and forged reply all deny',async()=>{
 const a=archive({sequence:4,digest});
 assert.equal((await verifyIncidentArchiveWitness(a,a)).readiness,'BLOCKED');
 assert.equal((await verifyIncidentArchiveWitness(a,
  {namespace:'other.registry',latest:async()=>({sequence:4,digest})}))
  .readiness,'BLOCKED');
 const c=new AbortController();c.abort();
 assert.equal((await verifyIncidentArchiveWitness(a,witness({sequence:4,digest}),
  c.signal)).readiness,'BLOCKED');
 const malformed=createIncidentExternalWitness({namespace:'palaco.registry',
  query:async()=>({rowCount:1,rows:[{sequence:'999999999999999999',
   incident_digest:digest}]})});
 assert.equal(await malformed.latest(),null);
});
test('witness adapter rejects missing trusted query and never exposes SQL writes',()=>{
 assert.throws(()=>createIncidentExternalWitness({namespace:'palaco.registry'}),TypeError);
 const w=createIncidentExternalWitness({namespace:'palaco.registry',
  query:async()=>({rowCount:0,rows:[]})});
 assert.equal(typeof w.advance,'undefined');
 assert.equal(typeof w.query,'undefined');
 assert.ok(Object.isFrozen(w));
});
