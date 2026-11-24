'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {generateKeyPairSync,sign}=require('node:crypto');
const {signedEvidenceChain}=require('../distribution/signed-evidence-v5');
const {handoffBytes,handoffDigest,receiptBytes}=
 require('../distribution/signed-evidence-anchor-handoff-v5.1');
const {createSignedEvidenceAnchorReceiver}=
 require('../distribution/signed-evidence-anchor-receiver-v5.1');
test('PostgreSQL independently stored full-evidence root accepts signed CAS once and blocks restored source', {
 skip:process.env.PALACO_TEST_POSTGRES!=='1'
},async()=>{
 const {Client}=require('pg');
 const admin=new Client({connectionString:process.env.PALACO_TEST_DATABASE_URL});
 let source,external,writer;
 await admin.connect();
 try{
  for(const name of ['palaco_full_evidence_v51_source','palaco_full_evidence_v51_root']){
   const exists=await admin.query('SELECT 1 FROM pg_database WHERE datname=$1',[name]);
   if(!exists.rowCount)await admin.query('CREATE DATABASE '+name);
  }
  const base=new URL(process.env.PALACO_TEST_DATABASE_URL);
  const url=name=>{const u=new URL(base.toString());u.pathname='/'+name;return u.toString();};
  source=new Client({connectionString:url('palaco_full_evidence_v51_source')});
  external=new Client({connectionString:url('palaco_full_evidence_v51_root')});
  await Promise.all([source.connect(),external.connect()]);
  const sql=n=>fs.readFileSync(path.join(__dirname,'../distribution/sql',n),'utf8');
  const schema=sql('incident-external-witness-v4.6.sql');
  const receipts=sql('incident-witness-receipts-v4.7.sql');
  const evidence=sql('receipt-signed-evidence-v4.9.sql');
  const commitments=sql('signed-evidence-commitments-v5.0.sql');
  await source.query(schema);await source.query(receipts);
  await source.query(evidence);await source.query(commitments);
  await external.query(sql('signed-evidence-external-anchor-v5.0.sql'));
  await external.query(sql('signed-evidence-anchor-receipts-v5.1.sql'));
  const namespace='palaco.v51ci';
  const rows=[
   {sequence:11,nonce:'receipt-11',handoff_digest:'a'.repeat(64),
    recipient_id:'custodian-ci',evidence_digest:'c'.repeat(64)},
   {sequence:12,nonce:'receipt-12',handoff_digest:'b'.repeat(64),
    recipient_id:'custodian-ci',evidence_digest:'d'.repeat(64)}
  ];
  const receiptInsert=[
   'INSERT INTO palaco_incident_witness.receipts',
   '(namespace,sequence,nonce,handoff_digest,recipient_id)',
   'VALUES($1,$2,$3,$4,$5)'
  ].join(' ');
  const evidenceInsert=[
   'INSERT INTO palaco_incident_witness.receipt_evidence',
   '(namespace,sequence,nonce,handoff_digest,recipient_id,',
   'handoff,sender_signature,receipt,receipt_signature)',
   'VALUES($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb)'
  ].join(' ');
  for(const r of rows){
   await source.query(receiptInsert,[namespace,r.sequence,r.nonce,
    r.handoff_digest,r.recipient_id]);
   await source.query(evidenceInsert,[namespace,r.sequence,r.nonce,
    r.handoff_digest,r.recipient_id,'{}','{}','{}','{}']);
   await source.query(
    'INSERT INTO palaco_incident_witness.evidence_commitments(namespace,sequence,evidence_digest) VALUES($1,$2,$3)',
    [namespace,r.sequence,r.evidence_digest]);
  }
  const previous=signedEvidenceChain(rows.slice(0,1),{namespace,firstSequence:11});
  const complete=signedEvidenceChain(rows,{namespace,firstSequence:11});
  await external.query(
   'INSERT INTO palaco_signed_evidence_anchor.latest(namespace,sequence,chain_digest) VALUES($1,$2,$3)',
   [namespace,previous.sequence,previous.digest]);
  // CI roles and credentials exist only in this disposable database.
  await external.query("CREATE ROLE palaco_v51_anchor_writer LOGIN PASSWORD 'ci_only_v51'");
  await external.query('REVOKE ALL ON SCHEMA palaco_signed_evidence_anchor FROM PUBLIC');
  await external.query('REVOKE ALL ON palaco_signed_evidence_anchor.latest FROM PUBLIC');
  await external.query('REVOKE ALL ON palaco_signed_evidence_anchor.transfer_receipts FROM PUBLIC');
  await external.query('GRANT USAGE ON SCHEMA palaco_signed_evidence_anchor TO palaco_v51_anchor_writer');
  await external.query('GRANT SELECT(namespace,sequence,chain_digest), UPDATE(sequence,chain_digest) ON palaco_signed_evidence_anchor.latest TO palaco_v51_anchor_writer');
  await external.query('GRANT SELECT,INSERT ON palaco_signed_evidence_anchor.transfer_receipts TO palaco_v51_anchor_writer');
  await external.query('ALTER TABLE palaco_signed_evidence_anchor.latest ENABLE ROW LEVEL SECURITY');
  await external.query('ALTER TABLE palaco_signed_evidence_anchor.transfer_receipts ENABLE ROW LEVEL SECURITY');
  await external.query("CREATE POLICY v51_head_read ON palaco_signed_evidence_anchor.latest FOR SELECT TO palaco_v51_anchor_writer USING(namespace='palaco.v51ci')");
  await external.query("CREATE POLICY v51_head_update ON palaco_signed_evidence_anchor.latest FOR UPDATE TO palaco_v51_anchor_writer USING(namespace='palaco.v51ci') WITH CHECK(namespace='palaco.v51ci')");
  await external.query("CREATE POLICY v51_receipt_read ON palaco_signed_evidence_anchor.transfer_receipts FOR SELECT TO palaco_v51_anchor_writer USING(namespace='palaco.v51ci')");
  await external.query("CREATE POLICY v51_receipt_insert ON palaco_signed_evidence_anchor.transfer_receipts FOR INSERT TO palaco_v51_anchor_writer WITH CHECK(namespace='palaco.v51ci')");
  const restricted=new URL(url('palaco_full_evidence_v51_root'));
  restricted.username='palaco_v51_anchor_writer';restricted.password='ci_only_v51';
  writer=new Client({connectionString:restricted.toString()});await writer.connect();
  const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
  const roots={
   senderRoot:{identityId:'issuer-ci',keyId:'issuer-key',enabled:true,revoked:false,
    publicKeyPem:keys[0].publicKey.export({type:'spki',format:'pem'})},
   recipientRoot:{identityId:'custodian-ci',keyId:'custodian-key',enabled:true,revoked:false,
    publicKeyPem:keys[1].publicKey.export({type:'spki',format:'pem'})}
  };
  const handoff={schemaVersion:'palaco.distribution.signed-evidence-anchor-handoff.v1',
   namespace,senderId:'issuer-ci',recipientId:'custodian-ci',nonce:'anchor-nonce-v51',
   previousSequence:11,previousDigest:previous.digest,
   nextSequence:12,nextDigest:complete.digest,
   issuedAtMs:1000,expiresAtMs:5000,
   authorization:'DENY',go13:'HOLD',purpose:'SIGNED_EVIDENCE_ANCHOR_ONLY'};
  const receipt={schemaVersion:'palaco.distribution.signed-evidence-anchor-receipt.v1',
   namespace,recipientId:'custodian-ci',nonce:handoff.nonce,
   handoffDigest:handoffDigest(handoff),acceptedAtMs:1500,
   acknowledgement:'ANCHOR_RECEIVED_NO_AUTHORITY'};
  const signAs=(bytes,key,i)=>({algorithm:'Ed25519',keyId:key,
   signature:sign(null,bytes,keys[i].privateKey).toString('base64')});
  const sender=signAs(handoffBytes(handoff),'issuer-key',0);
  const ack=signAs(receiptBytes(receipt),'custodian-key',1);
  const receiver=createSignedEvidenceAnchorReceiver({
   namespace,firstSequence:11,evidenceQuery:q=>source.query(q),
   anchorQuery:q=>writer.query(q),
   trustPolicyProvider:async()=>({nowMs:2000,...roots})
  });
  const params=[handoff,sender,receipt,ack];
  const result=await receiver.receive(...params);
  assert.equal(result.readiness,'EVIDENCE_ANCHOR_RECEIPT_RECORDED_NON_AUTHORIZING');
  assert.equal(result.authorization,'DENY');assert.equal(result.go13,'HOLD');
  assert.equal((await receiver.receive(...params)).readiness,'BLOCKED');
  const recorded=await writer.query(
   'SELECT nonce,handoff_digest FROM palaco_signed_evidence_anchor.transfer_receipts WHERE namespace=$1',
   [namespace]);
  assert.deepEqual(recorded.rows,[{nonce:handoff.nonce,handoff_digest:handoffDigest(handoff)}]);
  for(const statement of [
   'DELETE FROM palaco_signed_evidence_anchor.transfer_receipts',
   'TRUNCATE palaco_signed_evidence_anchor.transfer_receipts',
   'ALTER TABLE palaco_signed_evidence_anchor.latest DISABLE TRIGGER guard_evidence_anchor_update'
  ])await assert.rejects(writer.query(statement),e=>e.code==='42501');
  // Independent root cannot be forged backward by restricted principal.
  await assert.rejects(writer.query(
   'UPDATE palaco_signed_evidence_anchor.latest SET sequence=11 WHERE namespace=$1',
   [namespace]),e=>e.code==='23514');
  // Privileged source restore: external head and receipt remain unchanged.
  await source.query('DROP SCHEMA palaco_incident_witness CASCADE');
  await source.query(schema);await source.query(receipts);
  await source.query(evidence);await source.query(commitments);
  assert.equal((await receiver.receive(...params)).readiness,'BLOCKED');
  assert.equal((await external.query(
   'SELECT count(*)::int AS total FROM palaco_signed_evidence_anchor.transfer_receipts'
  )).rows[0].total,1);
 }finally{
  if(writer)await writer.end().catch(()=>{});
  if(source)await source.end().catch(()=>{});
  if(external)await external.end().catch(()=>{});
  await admin.end().catch(()=>{});
 }
});
