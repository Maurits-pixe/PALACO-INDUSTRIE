'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {generateKeyPairSync,sign}=require('node:crypto');
const {handoffPayload,handoffDigest,receiptPayload}=
 require('../distribution/incident-witness-handoff');
const {signedEvidenceChain,createSignedEvidenceVerifier,evidenceDigest}=
 require('../distribution/signed-evidence-v5');
const {createAtomicSignedEvidenceReceiver}=
 require('../distribution/atomic-signed-evidence-receiver-v5');
test('PostgreSQL atomic complete signed evidence and external full-root rollback', {
 skip:process.env.PALACO_TEST_POSTGRES!=='1'
},async()=>{
 const {Client}=require('pg');
 const base=new URL(process.env.PALACO_TEST_DATABASE_URL);
 const admin=new Client({connectionString:base.toString()});
 let primary,independent;
 await admin.connect();
 try{
  const names=['palaco_v50_receipts_ci','palaco_v50_root_ci'];
  for(const name of names){
   const exists=await admin.query('SELECT 1 FROM pg_database WHERE datname=$1',[name]);
   if(!exists.rowCount)await admin.query('CREATE DATABASE '+name);
  }
  const url=name=>{const u=new URL(base.toString());u.pathname='/'+name;return u.toString();};
  primary=new Client({connectionString:url(names[0])});
  independent=new Client({connectionString:url(names[1])});
  await Promise.all([primary.connect(),independent.connect()]);
  const sql=n=>fs.readFileSync(path.join(__dirname,'../distribution/sql',n),'utf8');
  const baseSql=sql('incident-external-witness-v4.6.sql');
  const receiptsSql=sql('incident-witness-receipts-v4.7.sql');
  const evidenceSql=sql('receipt-signed-evidence-v4.9.sql');
  const commitmentsSql=sql('signed-evidence-commitments-v5.0.sql');
  await primary.query(baseSql);await primary.query(receiptsSql);
  await primary.query(evidenceSql);await primary.query(commitmentsSql);
  await independent.query(sql('signed-evidence-external-anchor-v5.0.sql'));
  const namespace='palaco.v50ci',keys=[
   generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')
  ];
  const roots={
   senderRoot:{identityId:'issuer-v50',keyId:'issuer-key-v50',
    enabled:true,revoked:false,
    publicKeyPem:keys[0].publicKey.export({type:'spki',format:'pem'})},
   recipientRoot:{identityId:'witness-v50',keyId:'witness-key-v50',
    enabled:true,revoked:false,
    publicKeyPem:keys[1].publicKey.export({type:'spki',format:'pem'})}
  };
  await primary.query(
   'INSERT INTO palaco_incident_witness.heads(namespace,sequence,incident_digest) VALUES($1,$2,$3)',
   [namespace,10,'a'.repeat(64)]);
  const receiver=createAtomicSignedEvidenceReceiver({
   namespace,query:q=>primary.query(q),
   trustPolicyProvider:async()=>({nowMs:2500,...roots})
  });
  function tuple(sequence,previousDigest,nextDigest){
   const handoff={schemaVersion:'palaco.distribution.incident-witness-handoff.v1',
    namespace,senderId:'issuer-v50',recipientId:'witness-v50',
    nonce:'atomic-v50-'+sequence,previousSequence:sequence-1,
    previousDigest,nextSequence:sequence,nextDigest,
    issuedAtMs:1000,expiresAtMs:5000,
    authorization:'DENY',go13:'HOLD',purpose:'EVIDENCE_ONLY_NO_RELEASE'};
   const receipt={schemaVersion:'palaco.distribution.incident-witness-receipt.v1',
    namespace,recipientId:handoff.recipientId,nonce:handoff.nonce,
    handoffDigest:handoffDigest(handoff),acceptedAtMs:2000,
    acknowledgement:'EVIDENCE_RECEIVED_NO_AUTHORITY'};
   const signature=(data,index,keyId)=>({algorithm:'Ed25519',keyId,
    signature:sign(null,data,keys[index].privateKey).toString('base64')});
   return {handoff,receipt,
    senderSignature:signature(handoffPayload(handoff),0,'issuer-key-v50'),
    receiptSignature:signature(receiptPayload(receipt),1,'witness-key-v50')};
  }
  const first=tuple(11,'a'.repeat(64),'b'.repeat(64));
  const second=tuple(12,'b'.repeat(64),'c'.repeat(64));
  async function receive(t){return receiver.receive(
   t.handoff,t.senderSignature,t.receipt,t.receiptSignature);}
  const invalid={...first.receiptSignature,signature:'A'.repeat(86)+'=='};
  assert.equal((await receiver.receive(first.handoff,first.senderSignature,
   first.receipt,invalid)).readiness,'BLOCKED');
  assert.equal((await primary.query(
   'SELECT count(*)::int AS n FROM palaco_incident_witness.receipts'
  )).rows[0].n,0);
  for(const t of [first,second]){
   const proof=await receive(t);
   assert.equal(proof.readiness,'ATOMIC_SIGNED_RECEIPT_RECORDED_NON_AUTHORIZING');
   assert.equal(proof.authorization,'DENY');assert.equal(proof.go13,'HOLD');
   assert.equal(proof.evidenceDigest,evidenceDigest(
    t.handoff,t.senderSignature,t.receipt,t.receiptSignature));
  }
  assert.equal((await receive(second)).readiness,'BLOCKED');
  const stored=await primary.query([
   'SELECT r.sequence,r.nonce,r.handoff_digest,r.recipient_id,',
   'e.handoff,e.sender_signature,e.receipt,e.receipt_signature,',
   'c.evidence_digest',
   'FROM palaco_incident_witness.receipts r',
   'JOIN palaco_incident_witness.receipt_evidence e',
   ' ON e.namespace=r.namespace AND e.sequence=r.sequence',
   'JOIN palaco_incident_witness.evidence_commitments c',
   ' ON c.namespace=r.namespace AND c.sequence=r.sequence',
   'WHERE r.namespace=$1 ORDER BY r.sequence'
  ].join(' '),[namespace]);
  assert.equal(stored.rowCount,2);
  const head=signedEvidenceChain(stored.rows,{namespace,firstSequence:11});
  assert.equal(head.sequence,12);
  await independent.query(
   'INSERT INTO palaco_signed_evidence_anchor.latest(namespace,sequence,chain_digest) VALUES($1,$2,$3)',
   [namespace,12,head.digest]);
  const verifier=createSignedEvidenceVerifier({
   namespace,firstSequence:11,
   evidenceQuery:q=>primary.query(q),
   anchorQuery:q=>independent.query(q),
   historicalRootsProvider:async()=>roots
  });
  const verified=await verifier.verify();
  assert.equal(verified.readiness,'SIGNED_EVIDENCE_HISTORY_VERIFIED_NON_AUTHORIZING');
  assert.equal(verified.verifiedSignatures,4);
  // PostgreSQL triggers prevent even an administrator's ordinary writes.
  await assert.rejects(primary.query(
   'UPDATE palaco_incident_witness.evidence_commitments SET evidence_digest=$1 WHERE namespace=$2',
   ['f'.repeat(64),namespace]),e=>e.code==='23514');
  await assert.rejects(primary.query(
   'DELETE FROM palaco_incident_witness.receipt_evidence WHERE namespace=$1',
   [namespace]),e=>e.code==='23514');
  // Privileged replacement of evidence leaves metadata, but must block:
  await primary.query('DROP TABLE palaco_incident_witness.evidence_commitments');
  await primary.query('DROP TABLE palaco_incident_witness.receipt_evidence');
  await primary.query(evidenceSql);await primary.query(commitmentsSql);
  assert.equal((await verifier.verify()).readiness,'BLOCKED');
  // Separate root remains durable under one-sided primary DB tampering.
  const anchor=await independent.query(
   'SELECT sequence,chain_digest FROM palaco_signed_evidence_anchor.latest WHERE namespace=$1',
   [namespace]);
  assert.deepEqual(anchor.rows,[{sequence:'12',chain_digest:head.digest}]);
  await assert.rejects(independent.query(
   'UPDATE palaco_signed_evidence_anchor.latest SET sequence=11 WHERE namespace=$1',
   [namespace]),e=>e.code==='23514');
 }finally{
  if(primary)await primary.end().catch(()=>{});
  if(independent)await independent.end().catch(()=>{});
  await admin.end().catch(()=>{});
 }
});
