'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {incidentPayload,incidentDigest}=require('../distribution/witness-incident-review');
const {createIncidentWriteGateway,isIncidentWriteGateway}=
 require('../distribution/incident-write-gateway');
function fixture(){
 const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
 const roots=keys.map((key,i)=>({keyId:'key-'+i,reviewerId:'person-'+i,
  enabled:true,revoked:false,
  publicKeyPem:key.publicKey.export({type:'spki',format:'pem'})}));
 const incident={schemaVersion:'palaco.distribution.witness-incident.v1',
  namespace:'palaco.registry',incidentId:'case-1',sequence:1,
  priorIncidentDigest:'0'.repeat(64),
  observedAtMs:1000,expiresAtMs:5000,
  primary:{revision:10,digest:'a'.repeat(64)},
  secondary:{revision:11,digest:'b'.repeat(64)},
  authorization:'DENY',go13:'HOLD',
  recommendedAction:'QUARANTINE_NO_SYNC'};
 const endorsements=keys.map((key,i)=>({algorithm:'Ed25519',keyId:'key-'+i,
  signature:sign(null,incidentPayload(incident),key.privateKey).toString('base64')}));
 const records=[],queries=[];
 const query=async request=>{
  queries.push(request);
  if(request.text.startsWith('SELECT')){
   const row=records.at(-1);
   return row?{rowCount:1,rows:[{sequence:row.sequence,incident_digest:row.digest}]}:
    {rowCount:0,rows:[]};
  }
  if(!request.text.startsWith('INSERT'))throw Error('disallowed');
  const [namespace,sequence,id,prior,digest]=request.values;
  const row=records.at(-1);
  if(sequence!==(row?row.sequence+1:1)||
    prior!==(row?row.digest:'0'.repeat(64)))throw Error('concurrent');
  records.push({namespace,sequence,id,prior,digest});
  return {rowCount:1,rows:[{sequence,incident_digest:digest}]};
 };
 const primary={namespace:'palaco.registry',latest:async()=>({...incident.primary})};
 const secondary={namespace:'palaco.registry',latest:async()=>({...incident.secondary})};
 const options={namespace:'palaco.registry',query,primaryWitness:primary,
  secondaryWitness:secondary,
  reviewPolicyProvider:async()=>({nowMs:2000,pinnedReviewRoots:roots})};
 return {incident,endorsements,roots,keys,options,queries,records};
}
test('only a constructed gateway is branded; never provides raw query',()=>{
 const f=fixture(),gateway=createIncidentWriteGateway(f.options);
 assert.equal(isIncidentWriteGateway(gateway),true);
 assert.equal(isIncidentWriteGateway({...gateway}),false);
 assert.equal(typeof gateway.query,'undefined');
 assert.equal(typeof gateway.latest,'undefined');
 assert.ok(Object.isFrozen(gateway));
});
test('two valid independent signatures and exact live witness permit forensic append only',async()=>{
 const f=fixture(),gateway=createIncidentWriteGateway(f.options);
 const result=await gateway.submit(f.incident,f.endorsements);
 assert.equal(result.readiness,'INCIDENT_GATEWAY_ARCHIVED_NON_AUTHORIZING');
 assert.equal(result.authorization,'DENY');assert.equal(result.go13,'HOLD');
 assert.equal(result.mayRestore,false);assert.equal(result.maySynchronize,false);
 assert.equal(result.mayPublish,false);
 assert.equal(result.incidentDigest,incidentDigest(f.incident));
 assert.equal(f.records.length,1);
 assert.equal(f.queries.filter(q=>q.text.startsWith('INSERT')).length,1);
});
test('caller cannot supply trusted policy; invalid reviewer signature never writes',async()=>{
 const f=fixture(),gateway=createIncidentWriteGateway(f.options);
 f.endorsements.pop();
 const result=await gateway.submit(f.incident,f.endorsements,{
  nowMs:2000,pinnedReviewRoots:f.roots
 });
 assert.deepEqual(result.findings,['INCIDENT_GATEWAY_LIVE_REVIEW_REJECTED']);
 assert.equal(f.records.length,0);
});
test('tampered or changed live witness denies without archive writes',async()=>{
 for(const mutate of [
  f=>{f.options.primaryWitness.latest=async()=>({
    revision:11,digest:'c'.repeat(64)});},
  f=>{f.options.secondaryWitness.latest=async()=>null;},
  f=>{f.options.secondaryWitness.latest=async()=>{throw Error('offline');};},
  f=>{f.incident.secondary.digest='f'.repeat(64);}
 ]) {
  const f=fixture();mutate(f);
  const result=await createIncidentWriteGateway(f.options).submit(
   f.incident,f.endorsements);
  assert.equal(result.readiness,'BLOCKED');
  assert.equal(f.records.length,0);
 }
});
test('replay after successful append is refused before further insert',async()=>{
 const f=fixture(),gateway=createIncidentWriteGateway(f.options);
 assert.equal((await gateway.submit(f.incident,f.endorsements)).sequence,1);
 const again=await gateway.submit(f.incident,f.endorsements);
 assert.deepEqual(again.findings,['INCIDENT_GATEWAY_HEAD_MISMATCH']);
 assert.equal(f.records.length,1);
});
test('missing independent policy, missing distinct witness or aborted signal fails closed',async()=>{
 const f=fixture();
 for(const bad of [
  {...f.options,reviewPolicyProvider:null},
  {...f.options,primaryWitness:f.options.secondaryWitness},
  {...f.options,query:null}
 ])assert.throws(()=>createIncidentWriteGateway(bad),TypeError);
 const gateway=createIncidentWriteGateway({
  ...f.options,reviewPolicyProvider:async()=>null});
 assert.deepEqual((await gateway.submit(f.incident,f.endorsements)).findings,
  ['INCIDENT_GATEWAY_POLICY_UNAVAILABLE']);
 const controller=new AbortController();controller.abort();
 const abort=createIncidentWriteGateway(f.options);
 assert.equal((await abort.submit(f.incident,f.endorsements,controller.signal))
  .readiness,'BLOCKED');
 assert.equal(f.records.length,0);
});
test('unavailable archive or concurrent conflicting INSERT never reports success',async()=>{
 const f=fixture();
 const missing=createIncidentWriteGateway({...f.options,
  query:async()=>{throw Error('down');}});
 assert.equal((await missing.submit(f.incident,f.endorsements)).readiness,'BLOCKED');
 const conflict=createIncidentWriteGateway({...f.options,
  query:async request=>request.text.startsWith('SELECT')?
   {rowCount:0,rows:[]}:Promise.reject(Error('concurrent conflict'))});
 assert.deepEqual((await conflict.submit(f.incident,f.endorsements)).findings,
  ['INCIDENT_GATEWAY_ARCHIVE_REJECTED']);
});
