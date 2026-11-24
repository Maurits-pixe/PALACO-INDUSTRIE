'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {generateKeyPairSync,sign}=require('node:crypto');
const {VERSION,payload,createThirdPartyEvidenceCheckpointVerifier}=
 require('../distribution/third-party-evidence-checkpoint-v5.4');
test('third signed PostgreSQL checkpoint detects coordinated restore of source and external anchor', {
 skip:process.env.PALACO_TEST_POSTGRES!=='1'
},async()=>{
 const {Client}=require('pg');
 const base=new URL(process.env.PALACO_TEST_DATABASE_URL);
 const admin=new Client({connectionString:base.toString()});
 let source,external,third;
 await admin.connect();
 try{
  const names=['palaco_v54_source_ci','palaco_v54_external_ci','palaco_v54_third_ci'];
  for(const name of names){
   const exists=await admin.query('SELECT 1 FROM pg_database WHERE datname=$1',[name]);
   if(!exists.rowCount)await admin.query('CREATE DATABASE '+name);
  }
  const url=name=>{const v=new URL(base.toString());v.pathname='/'+name;return v.toString();};
  source=new Client({connectionString:url(names[0])});
  external=new Client({connectionString:url(names[1])});
  third=new Client({connectionString:url(names[2])});
  await Promise.all([source.connect(),external.connect(),third.connect()]);
  const sql=name=>fs.readFileSync(path.join(__dirname,'../distribution/sql',name),'utf8');
  const sourceSchema=sql('incident-external-witness-v4.6.sql');
  const receiptsSchema=sql('incident-witness-receipts-v4.7.sql');
  const anchorSchema=sql('signed-evidence-external-anchor-v5.0.sql');
  await source.query(sourceSchema);await source.query(receiptsSchema);
  await external.query(anchorSchema);
  await third.query(sql('third-party-evidence-checkpoint-v5.4.sql'));
  const namespace='palaco.v54ci';
  const digest11='a'.repeat(64),digest12='b'.repeat(64);
  // Test-only source metadata fixture; the historic signature verifier
  // is independently exercised in the v5.3 integration.
  await source.query(
   'INSERT INTO palaco_incident_witness.receipts(namespace,sequence,nonce,handoff_digest,recipient_id) VALUES($1,$2,$3,$4,$5)',
   [namespace,11,'nonce-11','c'.repeat(64),'custodian']);
  await source.query(
   'INSERT INTO palaco_incident_witness.receipts(namespace,sequence,nonce,handoff_digest,recipient_id) VALUES($1,$2,$3,$4,$5)',
   [namespace,12,'nonce-12','d'.repeat(64),'custodian']);
  await external.query(
   'INSERT INTO palaco_signed_evidence_anchor.latest(namespace,sequence,chain_digest) VALUES($1,$2,$3)',
   [namespace,12,digest12]);
  const keys=generateKeyPairSync('ed25519');
  const checkpoint={
   schemaVersion:VERSION,namespace,sequence:12,chainDigest:digest12,
   observerId:'third-auditor',observedAtMs:1500,
   authorization:'DENY',go13:'HOLD',
   purpose:'INDEPENDENT_OBSERVATION_NO_AUTHORITY'
  };
  const signature=sign(null,payload(checkpoint),keys.privateKey).toString('base64');
  const add=[
   'INSERT INTO palaco_third_witness.checkpoints',
   '(namespace,sequence,chain_digest,observed_at_ms,observer_id,key_id,signature)',
   'VALUES($1,$2,$3,$4,$5,$6,$7)'
  ].join(' ');
  await third.query(add,[namespace,12,digest12,1500,'third-auditor','third-key',signature]);
  const verifier=createThirdPartyEvidenceCheckpointVerifier({
   namespace,anchorQuery:req=>external.query(req),
   thirdPartyQuery:req=>third.query(req),
   trustRootProvider:async()=>({
    observerId:'third-auditor',keyId:'third-key',enabled:true,revoked:false,
    publicKeyPem:keys.publicKey.export({type:'spki',format:'pem'})
   })
  });
  assert.equal((await verifier.verify()).readiness,
   'THIRD_PARTY_CHECKPOINT_MATCHED_NON_AUTHORIZING');
  // Privileged restore of TWO separate logical databases. Local triggers
  // cannot resist schema reconstruction; the third database remains at 12.
  await source.query('DROP SCHEMA palaco_incident_witness CASCADE');
  await source.query(sourceSchema);await source.query(receiptsSchema);
  await source.query(
   'INSERT INTO palaco_incident_witness.receipts(namespace,sequence,nonce,handoff_digest,recipient_id) VALUES($1,$2,$3,$4,$5)',
   [namespace,11,'nonce-11','c'.repeat(64),'custodian']);
  await external.query('DROP SCHEMA palaco_signed_evidence_anchor CASCADE');
  await external.query(anchorSchema);
  await external.query(
   'INSERT INTO palaco_signed_evidence_anchor.latest(namespace,sequence,chain_digest) VALUES($1,$2,$3)',
   [namespace,11,digest11]);
  const detected=await verifier.verify();
  assert.deepEqual(detected.findings,['THIRD_CHECKPOINT_ROOT_ROLLBACK_OR_FORK']);
  assert.equal(detected.authorization,'DENY');assert.equal(detected.go13,'HOLD');
  assert.equal(detected.mayRestore,false);
  assert.deepEqual((await third.query(
   'SELECT sequence,chain_digest FROM palaco_third_witness.checkpoints WHERE namespace=$1',
   [namespace])).rows,[{sequence:'12',chain_digest:digest12}]);
  await assert.rejects(third.query(
   'UPDATE palaco_third_witness.checkpoints SET sequence=11 WHERE namespace=$1',
   [namespace]),error=>error.code==='23514');
  await assert.rejects(third.query(
   'DELETE FROM palaco_third_witness.checkpoints WHERE namespace=$1',
   [namespace]),error=>error.code==='23514');
  await assert.rejects(third.query('TRUNCATE palaco_third_witness.checkpoints'),
   error=>error.code==='23514');
 }finally{
  if(source)await source.end().catch(()=>{});
  if(external)await external.end().catch(()=>{});
  if(third)await third.end().catch(()=>{});
  await admin.end().catch(()=>{});
 }
});
