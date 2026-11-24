'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {generateKeyPairSync,sign}=require('node:crypto');
const {handoffPayload,handoffDigest,receiptPayload}=
 require('../distribution/incident-witness-handoff');
const {createIncidentWitnessHandoffReceiver}=
 require('../distribution/incident-witness-handoff-receiver');
test('restricted PostgreSQL witness receiver records one signed nonce and rejects replay', {
 skip:process.env.PALACO_TEST_POSTGRES!=='1'
},async()=>{
 const {Client}=require('pg');
 const admin=new Client({connectionString:process.env.PALACO_TEST_DATABASE_URL});
 let runtime;
 await admin.connect();
 try{
  const sql=f=>fs.readFileSync(path.join(__dirname,'../distribution/sql',f),'utf8');
  await admin.query(sql('incident-external-witness-v4.6.sql'));
  await admin.query(sql('incident-witness-receipts-v4.7.sql'));
  await admin.query("CREATE ROLE palaco_handoff_receiver_v47 LOGIN PASSWORD 'ci_receiver_only'");
  await admin.query('REVOKE ALL ON SCHEMA palaco_incident_witness FROM PUBLIC');
  await admin.query('REVOKE ALL ON palaco_incident_witness.heads FROM PUBLIC');
  await admin.query('REVOKE ALL ON palaco_incident_witness.receipts FROM PUBLIC');
  await admin.query('GRANT USAGE ON SCHEMA palaco_incident_witness TO palaco_handoff_receiver_v47');
  await admin.query('GRANT SELECT(namespace,sequence,incident_digest), UPDATE(sequence,incident_digest) ON palaco_incident_witness.heads TO palaco_handoff_receiver_v47');
  await admin.query('GRANT INSERT,SELECT ON palaco_incident_witness.receipts TO palaco_handoff_receiver_v47');
  await admin.query('ALTER TABLE palaco_incident_witness.heads ENABLE ROW LEVEL SECURITY');
  await admin.query('ALTER TABLE palaco_incident_witness.receipts ENABLE ROW LEVEL SECURITY');
  await admin.query("CREATE POLICY receiver_ci_heads_select ON palaco_incident_witness.heads FOR SELECT TO palaco_handoff_receiver_v47 USING(namespace='palaco.v47ci')");
  await admin.query("CREATE POLICY receiver_ci_heads_update ON palaco_incident_witness.heads FOR UPDATE TO palaco_handoff_receiver_v47 USING(namespace='palaco.v47ci') WITH CHECK(namespace='palaco.v47ci')");
  await admin.query("CREATE POLICY receiver_ci_receipts_insert ON palaco_incident_witness.receipts FOR INSERT TO palaco_handoff_receiver_v47 WITH CHECK(namespace='palaco.v47ci')");
  await admin.query("CREATE POLICY receiver_ci_receipts_select ON palaco_incident_witness.receipts FOR SELECT TO palaco_handoff_receiver_v47 USING(namespace='palaco.v47ci')");
  const namespace='palaco.v47ci',before='a'.repeat(64),after='b'.repeat(64);
  await admin.query('INSERT INTO palaco_incident_witness.heads(namespace,sequence,incident_digest) VALUES($1,$2,$3)',
   [namespace,10,before]);
  const url=new URL(process.env.PALACO_TEST_DATABASE_URL);
  url.username='palaco_handoff_receiver_v47';url.password='ci_receiver_only';
  runtime=new Client({connectionString:url.toString()});
  await runtime.connect();
  const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
  const handoff={
   schemaVersion:'palaco.distribution.incident-witness-handoff.v1',
   namespace,senderId:'archive-issuer',recipientId:'independent-witness',
   nonce:'ci-nonce-001',previousSequence:10,previousDigest:before,
   nextSequence:11,nextDigest:after,issuedAtMs:1000,expiresAtMs:5000,
   authorization:'DENY',go13:'HOLD',purpose:'EVIDENCE_ONLY_NO_RELEASE'
  };
  const receipt={
   schemaVersion:'palaco.distribution.incident-witness-receipt.v1',
   namespace,recipientId:handoff.recipientId,nonce:handoff.nonce,
   handoffDigest:handoffDigest(handoff),acceptedAtMs:1300,
   acknowledgement:'EVIDENCE_RECEIVED_NO_AUTHORITY'
  };
  const signatures=[
   {algorithm:'Ed25519',keyId:'issuer-key',
    signature:sign(null,handoffPayload(handoff),keys[0].privateKey).toString('base64')},
   {algorithm:'Ed25519',keyId:'recipient-key',
    signature:sign(null,receiptPayload(receipt),keys[1].privateKey).toString('base64')}
  ];
  const root=(key,index,id)=>({
   identityId:id,keyId:key,enabled:true,revoked:false,
   publicKeyPem:keys[index].publicKey.export({type:'spki',format:'pem'})
  });
  const receiver=createIncidentWitnessHandoffReceiver({
   namespace,query:request=>runtime.query(request),
   trustPolicyProvider:async()=>({
    nowMs:1500,
    senderRoot:root('issuer-key',0,'archive-issuer'),
    recipientRoot:root('recipient-key',1,'independent-witness')
   })
  });
  const args=[handoff,signatures[0],receipt,signatures[1]];
  const success=await receiver.receive(...args);
  assert.equal(success.readiness,'WITNESS_RECEIPT_RECORDED_NON_AUTHORIZING');
  assert.equal(success.authorization,'DENY');assert.equal(success.go13,'HOLD');
  assert.equal((await receiver.receive(...args)).readiness,'BLOCKED');
  const head=await runtime.query('SELECT sequence,incident_digest FROM palaco_incident_witness.heads WHERE namespace=$1',[namespace]);
  assert.deepEqual(head.rows,[{sequence:'11',incident_digest:after}]);
  const stored=await runtime.query('SELECT nonce,handoff_digest FROM palaco_incident_witness.receipts WHERE namespace=$1',[namespace]);
  assert.deepEqual(stored.rows,[{nonce:handoff.nonce,handoff_digest:handoffDigest(handoff)}]);
  for(const query of [
   'DELETE FROM palaco_incident_witness.receipts',
   'TRUNCATE palaco_incident_witness.receipts',
   'ALTER TABLE palaco_incident_witness.receipts DISABLE TRIGGER deny_receipt_update_delete'
  ])await assert.rejects(runtime.query(query),e=>e.code==='42501');
  await assert.rejects(runtime.query("UPDATE palaco_incident_witness.heads SET sequence=10 WHERE namespace='palaco.v47ci'"),
   e=>e.code==='23514');
 }finally{
  if(runtime)await runtime.end().catch(()=>{});
  await admin.end().catch(()=>{});
 }
});
