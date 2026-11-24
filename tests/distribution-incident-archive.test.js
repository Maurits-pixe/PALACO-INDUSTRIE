'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {incidentPayload,incidentDigest}=require('../distribution/witness-incident-review');
const {createIncidentArchive}=require('../distribution/incident-append-only-archive');

const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
const roots=keys.map((k,i)=>({
 keyId:'incident-k'+i,reviewerId:'review-person'+i,
 enabled:true,revoked:false,
 publicKeyPem:k.publicKey.export({type:'spki',format:'pem'})
}));
function incident(sequence,prior,incidentId='incident-'+sequence){
 const item={
  schemaVersion:'palaco.distribution.witness-incident.v1',
  namespace:'palaco.registry',incidentId,sequence,
  priorIncidentDigest:prior,observedAtMs:1000,expiresAtMs:5000,
  primary:{revision:10,digest:'a'.repeat(64)},
  secondary:{revision:11,digest:'b'.repeat(64)},
  authorization:'DENY',go13:'HOLD',recommendedAction:'QUARANTINE_NO_SYNC'
 };
 const approvals=keys.map((k,i)=>({
  algorithm:'Ed25519',keyId:'incident-k'+i,
  signature:sign(null,incidentPayload(item),k.privateKey).toString('base64')
 }));
 return {item,approvals};
}
const policy={nowMs:2000,pinnedReviewRoots:roots};
function fakeStore(){
 const rows=[],calls=[];
 const query=async({text,values})=>{
  calls.push({text,values});
  if(text.startsWith('SELECT')){
   const row=rows.at(-1);
   return row?{rowCount:1,rows:[{sequence:row.sequence,
     incident_digest:row.incident_digest}]}:{rowCount:0,rows:[]};
  }
  if(text.startsWith('INSERT')){
   const [namespace,sequence,incidentId,prior,digest]=values;
   const head=rows.at(-1);
   if(sequence!==(head?head.sequence+1:1)||
      prior!==(head?head.incident_digest:'0'.repeat(64))||
      rows.some(r=>r.incidentId===incidentId))
    throw Error('integrity');
   rows.push({namespace,sequence,incidentId,prior,incident_digest:digest});
   return {rowCount:1,rows:[{sequence,incident_digest:digest}]};
  }
  throw Error('unknown SQL');
 };
 return {rows,calls,query};
}
test('two reviewed incidents append in order without unlocking action',async()=>{
 const db=fakeStore(),archive=createIncidentArchive({
  namespace:'palaco.registry',query:db.query});
 const first=incident(1,'0'.repeat(64));
 const one=await archive.appendReviewed(first.item,first.approvals,policy);
 assert.equal(one.readiness,'INCIDENT_ARCHIVED_NON_AUTHORIZING');
 assert.equal(one.authorization,'DENY');assert.equal(one.go13,'HOLD');
 assert.equal(one.maySynchronize,false);assert.equal(one.mayRestore,false);
 assert.deepEqual(await archive.latest(),{sequence:1,digest:incidentDigest(first.item)});
 const second=incident(2,incidentDigest(first.item));
 const two=await archive.appendReviewed(second.item,second.approvals,policy);
 assert.equal(two.sequence,2);assert.equal(db.rows.length,2);
 assert.equal(db.rows[1].prior,incidentDigest(first.item));
 assert.equal(db.calls.filter(c=>c.text.startsWith('INSERT')).length,2);
});
test('replay, missing sequence or wrong predecessor never reach INSERT',async()=>{
 const db=fakeStore(),archive=createIncidentArchive({
  namespace:'palaco.registry',query:db.query});
 const first=incident(1,'0'.repeat(64));
 await archive.appendReviewed(first.item,first.approvals,policy);
 for(const bad of [
  first,incident(3,incidentDigest(first.item)),
  incident(2,'f'.repeat(64))
 ]){
  const r=await archive.appendReviewed(bad.item,bad.approvals,policy);
  assert.deepEqual(r.findings,['INCIDENT_ARCHIVE_HEAD_MISMATCH']);
 }
 assert.equal(db.calls.filter(c=>c.text.startsWith('INSERT')).length,1);
});
test('tampering and missing review quorum prevent archive writes',async()=>{
 const db=fakeStore(),archive=createIncidentArchive({
  namespace:'palaco.registry',query:db.query});
 const original=incident(1,'0'.repeat(64));
 original.item.primary.revision=12;
 let result=await archive.appendReviewed(original.item,original.approvals,policy);
 assert.deepEqual(result.findings,['INCIDENT_ARCHIVE_REVIEW_REJECTED']);
 const next=incident(1,'0'.repeat(64));
 result=await archive.appendReviewed(next.item,[next.approvals[0]],policy);
 assert.deepEqual(result.findings,['INCIDENT_ARCHIVE_REVIEW_REJECTED']);
 assert.equal(db.rows.length,0);
});
test('unavailable archive fails closed without falling back to local writes',async()=>{
 const x=incident(1,'0'.repeat(64));
 for(const query of [
  async()=>{throw Error('offline');},
  async()=>({rowCount:1,rows:[{sequence:'bogus',incident_digest:'bad'}]})
 ]){
  const archive=createIncidentArchive({namespace:'palaco.registry',query});
  const r=await archive.appendReviewed(x.item,x.approvals,policy);
  assert.equal(r.readiness,'BLOCKED');
  assert.equal(r.authorization,'DENY');
 }
});
test('archive cannot be fabricated without namespace and trusted query',()=>{
 for(const config of [{},{namespace:'palaco.registry'},
  {namespace:'bad namespace',query:async()=>({})}])
  assert.throws(()=>createIncidentArchive(config),TypeError);
});
test('database append denial or ambiguous response is never reported as success',async()=>{
 const x=incident(1,'0'.repeat(64));
 for(const response of [
  {rowCount:0,rows:[]},
  {rowCount:1,rows:[{sequence:1,incident_digest:'f'.repeat(64)}]}
 ]){
  const archive=createIncidentArchive({namespace:'palaco.registry',
   query:async({text})=>text.startsWith('SELECT')?
     {rowCount:0,rows:[]}:response});
  const result=await archive.appendReviewed(x.item,x.approvals,policy);
  assert.equal(result.readiness,'BLOCKED');
  assert.equal(result.maySynchronize,false);
 }
});
test('abort prevents writes and never returns a capability',async()=>{
 let writes=0;
 const archive=createIncidentArchive({namespace:'palaco.registry',
  query:async({text})=>{
   if(text.startsWith('INSERT'))writes++;
   return {rowCount:0,rows:[]};
  }});
 const x=incident(1,'0'.repeat(64)),abort=new AbortController();
 abort.abort();
 const result=await archive.appendReviewed(x.item,x.approvals,policy,abort.signal);
 assert.equal(result.readiness,'BLOCKED');assert.equal(writes,0);
});
