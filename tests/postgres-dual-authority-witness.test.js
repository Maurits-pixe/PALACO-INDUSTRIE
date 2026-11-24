'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {generateKeyPairSync,sign}=require('node:crypto');
const {authorityDigest,rotationPayload}=
 require('../distribution/roster-authority-rotation');
const {createAuthorityAnchorStore}=
 require('../distribution/postgres-authority-anchor');
const {createDualAuthorityWitness}=
 require('../distribution/dual-authority-witness');
const {incidentPayload,verifyLiveWitnessIncident}=
 require('../distribution/witness-incident-review');

function fixture(){
 const keys=Array.from({length:4},()=>generateKeyPairSync('ed25519'));
 const pem=i=>keys[i].publicKey.export({type:'spki',format:'pem'});
 const previous={schemaVersion:'palaco.distribution.roster-authority.v1',
  namespace:'palaco.registry',revision:10,previousDigest:'0'.repeat(64),
  keys:[{keyId:'authority-a',status:'active',publicKeyPem:pem(0)}]};
 const next={...previous,revision:11,previousDigest:authorityDigest(previous),
  keys:[{keyId:'authority-a',status:'revoked',publicKeyPem:pem(0)},
   {keyId:'authority-z',status:'active',publicKeyPem:pem(1)}]};
 const record={schemaVersion:'palaco.distribution.roster-authority-rotation.v1',
  namespace:'palaco.registry',revision:11,
  previousDigest:authorityDigest(previous),nextDigest:authorityDigest(next),
  oldKeyId:'authority-a',newKeyId:'authority-z'};
 const payload=rotationPayload(record);
 const approval=(keyId,i)=>({keyId,algorithm:'Ed25519',
  signature:sign(null,payload,keys[i].privateKey).toString('base64')});
 const endorsements={
  oldAuthority:approval('authority-a',0),
  newAuthority:approval('authority-z',1),
  reviewers:[approval('review-a',2),approval('review-b',3)]
 };
 const reviewers=[
  {keyId:'review-a',reviewerId:'alice',enabled:true,revoked:false,publicKeyPem:pem(2)},
  {keyId:'review-b',reviewerId:'bob',enabled:true,revoked:false,publicKeyPem:pem(3)}
 ];
 return {previous,next,record,endorsements,reviewers};
}
const row=(revision,digest)=>({revision,digest});
const store=(revision,digest)=>({namespace:'palaco.registry',
 latest:async()=>row(revision,digest)});
test('construction fails without distinct, same-scope witness endpoints',()=>{
 const anchor=store(10,'a'.repeat(64));
 for(const options of [{}, {primary:anchor,secondary:anchor},
  {primary:anchor,secondary:{...anchor,namespace:'foreign.registry'}},
  {primary:anchor,secondary:{namespace:'palaco.registry'}}])
  assert.throws(()=>createDualAuthorityWitness(options),TypeError);
});
test('two matching anchors verify evidence only; four valid rotation signatures required',async()=>{
 const f=fixture(),digest=authorityDigest(f.previous);
 const dual=createDualAuthorityWitness({
  primary:store(10,digest),secondary:store(10,digest)
 });
 const head=await dual.verifyHead(10,digest);
 assert.equal(head.readiness,'DUAL_AUTHORITY_HEAD_VERIFIED_NON_AUTHORIZING');
 assert.equal(head.authorization,'DENY');assert.equal(head.go13,'HOLD');
 assert.equal(head.mayAdvance,false);assert.equal(head.mayRestore,false);
 const valid=await dual.verifyRotation(f.previous,f.next,f.record,
  f.endorsements,f.reviewers);
 assert.equal(valid.readiness,'DUAL_AUTHORITY_ROTATION_VERIFIED_NON_AUTHORIZING');
 assert.equal(valid.mayRotate,false);assert.equal(valid.mayPublish,false);
 f.endorsements.reviewers.pop();
 const denied=await dual.verifyRotation(f.previous,f.next,f.record,
  f.endorsements,f.reviewers);
 assert.deepEqual(denied.findings,['DUAL_AUTHORITY_ROTATION_REJECTED']);
});
test('missing, tampered, divergent or unexpectedly advanced witness fails closed',async()=>{
 const digest='a'.repeat(64);
 for(const pair of [
  [store(10,digest),store(11,'b'.repeat(64))],
  [store(10,digest),store(10,'b'.repeat(64))],
  [store(11,digest),store(11,digest)],
  [store(10,digest),{namespace:'palaco.registry',latest:async()=>null}],
  [store(10,digest),{namespace:'palaco.registry',
    latest:async()=>{throw Error('offline');}}]
 ]){
  const dual=createDualAuthorityWitness({primary:pair[0],secondary:pair[1]});
  const result=await dual.verifyHead(10,digest);
  assert.equal(result.readiness,'BLOCKED');
  assert.equal(result.authorization,'DENY');
  assert.equal(result.go13,'HOLD');
  assert.equal(result.mayRestore,false);
 }
});
test('aborted and invalid context are blocked without querying either store',async()=>{
 let calls=0;
 const endpoint={namespace:'palaco.registry',
  latest:async()=>{calls++;return row(10,'a'.repeat(64));}};
 const dual=createDualAuthorityWitness({primary:endpoint,
  secondary:{...endpoint}});
 const controller=new AbortController();controller.abort();
 for(const x of [
  dual.verifyHead(10,'a'.repeat(64),controller.signal),
  dual.verifyHead(0,'a'.repeat(64)),
  dual.verifyHead(10,'g'.repeat(64))
 ])assert.equal((await x).readiness,'BLOCKED');
 assert.equal(calls,0);
});
test('two separate PostgreSQL databases detect restoration of primary witness', {
 skip:process.env.PALACO_TEST_POSTGRES!=='1'
},async()=>{
 const {Client}=require('pg');
 const url=new URL(process.env.PALACO_TEST_DATABASE_URL);
 const admin=new Client({connectionString:url.toString()});
 await admin.connect();
 const dbname='palaco_witness_v41_ci';
 let primary,secondary;
 try{
  // Distinct DB files/restore domains in this CI scenario, but still a
  // single PostgreSQL service / superuser. NOT independent production trust.
  await admin.query('SELECT 1');
  const exists=await admin.query('SELECT 1 FROM pg_database WHERE datname=$1',[dbname]);
  if(exists.rowCount===0)await admin.query('CREATE DATABASE '+dbname);
  primary=new Client({connectionString:url.toString()});
  const secondUrl=new URL(url.toString());secondUrl.pathname='/'+dbname;
  secondary=new Client({connectionString:secondUrl.toString()});
  await Promise.all([primary.connect(),secondary.connect()]);
  const schema=fs.readFileSync(path.join(__dirname,
   '../distribution/sql/authority-anchor-highwater-v3.9.sql'),'utf8');
  await Promise.all([primary.query(schema),secondary.query(schema)]);
  await Promise.all([
   primary.query('TRUNCATE palaco_authority_anchor.latest'),
   secondary.query('TRUNCATE palaco_authority_anchor.latest')
  ]);
  const f=fixture();
  const before=authorityDigest(f.previous);
  const after=authorityDigest(f.next);
  const sql='INSERT INTO palaco_authority_anchor.latest(namespace,revision,state_digest) VALUES($1,$2,$3)';
  await Promise.all([
   primary.query(sql,['palaco.registry',10,before]),
   secondary.query(sql,['palaco.registry',10,before])
  ]);
  const dual=createDualAuthorityWitness({
   primary:createAuthorityAnchorStore({namespace:'palaco.registry',
    query:q=>primary.query(q)}),
   secondary:createAuthorityAnchorStore({namespace:'palaco.registry',
    query:q=>secondary.query(q)})
  });
  const initial=await dual.verifyRotation(f.previous,f.next,
   f.record,f.endorsements,f.reviewers);
  assert.equal(initial.readiness,'DUAL_AUTHORITY_ROTATION_VERIFIED_NON_AUTHORIZING');
  // A protected external witness advances to revision 11.
  await secondary.query(
   'UPDATE palaco_authority_anchor.latest SET revision=$1,state_digest=$2 WHERE namespace=$3',
   [11,after,'palaco.registry']);
  // Simulated privileged restore of older PRIMARY backup: same signed old
  // record, valid schema and old revision/digest, but not the witness head.
  await primary.query('TRUNCATE palaco_authority_anchor.latest');
  await primary.query(sql,['palaco.registry',10,before]);
  const restored=await dual.verifyRotation(f.previous,f.next,
   f.record,f.endorsements,f.reviewers);
  assert.deepEqual(restored.findings,['DUAL_AUTHORITY_WITNESS_DIVERGENCE']);
  assert.equal(restored.authorization,'DENY');
  assert.equal(restored.go13,'HOLD');
  // A two-reviewer forensic incident must match BOTH live witness heads.
  const reviewerA=generateKeyPairSync('ed25519');
  const reviewerB=generateKeyPairSync('ed25519');
  const incident={
    schemaVersion:'palaco.distribution.witness-incident.v1',
    namespace:'palaco.registry',incidentId:'ci-restore-41',
    sequence:1,priorIncidentDigest:'0'.repeat(64),
    observedAtMs:1000,expiresAtMs:5000,
    primary:{revision:10,digest:before},
    secondary:{revision:11,digest:after},
    authorization:'DENY',go13:'HOLD',recommendedAction:'QUARANTINE_NO_SYNC'
  };
  const signed=incidentPayload(incident);
  const signatures=[
    {algorithm:'Ed25519',keyId:'incident-review-a',
      signature:sign(null,signed,reviewerA.privateKey).toString('base64')},
    {algorithm:'Ed25519',keyId:'incident-review-b',
      signature:sign(null,signed,reviewerB.privateKey).toString('base64')}
  ];
  const reviewPolicy={namespace:'palaco.registry',minimumSequence:1,
    priorIncidentDigest:'0'.repeat(64),nowMs:2000,
    pinnedReviewRoots:[
      {keyId:'incident-review-a',reviewerId:'incident-person-a',
        enabled:true,revoked:false,
        publicKeyPem:reviewerA.publicKey.export({type:'spki',format:'pem'})},
      {keyId:'incident-review-b',reviewerId:'incident-person-b',
        enabled:true,revoked:false,
        publicKeyPem:reviewerB.publicKey.export({type:'spki',format:'pem'})}
    ]};
  const liveWitnesses={
    primary:createAuthorityAnchorStore({namespace:'palaco.registry',
      query:q=>primary.query(q)}),
    secondary:createAuthorityAnchorStore({namespace:'palaco.registry',
      query:q=>secondary.query(q)})
  };
  const reviewed=await verifyLiveWitnessIncident(incident,signatures,
    reviewPolicy,liveWitnesses);
  assert.equal(reviewed.readiness,
    'INCIDENT_LIVE_DIVERGENCE_VERIFIED_NON_AUTHORIZING');
  assert.equal(reviewed.maySynchronize,false);
  assert.equal(reviewed.authorization,'DENY');
  const secondaryHead=await secondary.query(
   'SELECT revision,state_digest FROM palaco_authority_anchor.latest WHERE namespace=$1',
   ['palaco.registry']);
  assert.deepEqual(secondaryHead.rows,[{revision:'11',state_digest:after}]);
  // Same revision but altered digest is also detected.
  await primary.query(
   'UPDATE palaco_authority_anchor.latest SET revision=$1,state_digest=$2 WHERE namespace=$3',
   [11,'f'.repeat(64),'palaco.registry']);
  assert.deepEqual((await dual.verifyHead(11,after)).findings,
   ['DUAL_AUTHORITY_WITNESS_DIVERGENCE']);
  const altered=await verifyLiveWitnessIncident(incident,signatures,
    reviewPolicy,liveWitnesses);
  assert.deepEqual(altered.findings,['INCIDENT_LIVE_SNAPSHOT_MISMATCH']);
 }finally{
  if(primary)await primary.end().catch(()=>{});
  if(secondary)await secondary.end().catch(()=>{});
  await admin.end().catch(()=>{});
 }
});
