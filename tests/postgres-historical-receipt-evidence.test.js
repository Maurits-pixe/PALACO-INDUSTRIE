'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {generateKeyPairSync,sign}=require('node:crypto');
const {handoffPayload,handoffDigest,receiptPayload}=
 require('../distribution/incident-witness-handoff');
const {receiptChain}=require('../distribution/receipt-succession-verifier');
const {createHistoricalReceiptArchiver,createHistoricalReceiptVerifier}=
 require('../distribution/historical-receipt-evidence');

test('PostgreSQL historical signed receipt recheck rejects forged evidence and restored archive',
 {skip:process.env.PALACO_TEST_POSTGRES!=='1'},async()=>{
 const {Client}=require('pg');
 const base=new URL(process.env.PALACO_TEST_DATABASE_URL);
 const admin=new Client({connectionString:base.toString()});
 let primary,anchor;
 await admin.connect();
 try{
  const names=['palaco_signed_receipts_v49_ci','palaco_signed_root_v49_ci'];
  for(const name of names){
   const exists=await admin.query('SELECT 1 FROM pg_database WHERE datname=$1',[name]);
   if(!exists.rowCount)await admin.query('CREATE DATABASE '+name);
  }
  const url=n=>{const x=new URL(base.toString());x.pathname='/'+n;return x.toString();};
  primary=new Client({connectionString:url(names[0])});
  anchor=new Client({connectionString:url(names[1])});
  await Promise.all([primary.connect(),anchor.connect()]);
  const sql=n=>fs.readFileSync(path.join(__dirname,'../distribution/sql',n),'utf8');
  const baseSql=sql('incident-external-witness-v4.6.sql');
  const receiptSql=sql('incident-witness-receipts-v4.7.sql');
  const evidenceSql=sql('receipt-signed-evidence-v4.9.sql');
  await primary.query(baseSql);
  await primary.query(receiptSql);
  await primary.query(evidenceSql);
  await anchor.query(sql('receipt-succession-anchor-v4.8.sql'));
  const namespace='palaco.v49ci';
  const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
  const pem=i=>keys[i].publicKey.export({type:'spki',format:'pem'});
  const roots={
   senderRoot:{identityId:'sender-v49',keyId:'issuer-v49',enabled:true,
    revoked:false,publicKeyPem:pem(0)},
   recipientRoot:{identityId:'receiver-v49',keyId:'recipient-v49',enabled:true,
    revoked:false,publicKeyPem:pem(1)}
  };
  function make(seq,prior,next){
   const handoff={
    schemaVersion:'palaco.distribution.incident-witness-handoff.v1',
    namespace,senderId:'sender-v49',recipientId:'receiver-v49',
    nonce:'nonce-v49-'+seq,previousSequence:seq-1,previousDigest:prior,
    nextSequence:seq,nextDigest:next,issuedAtMs:1000,expiresAtMs:5000,
    authorization:'DENY',go13:'HOLD',purpose:'EVIDENCE_ONLY_NO_RELEASE'
   };
   const receipt={
    schemaVersion:'palaco.distribution.incident-witness-receipt.v1',
    namespace,recipientId:'receiver-v49',nonce:handoff.nonce,
    handoffDigest:handoffDigest(handoff),acceptedAtMs:1500,
    acknowledgement:'EVIDENCE_RECEIVED_NO_AUTHORITY'
   };
   const sig=(payload,i,keyId)=>({
    algorithm:'Ed25519',keyId,
    signature:sign(null,payload,keys[i].privateKey).toString('base64')
   });
   return {handoff,receipt,
    senderSignature:sig(handoffPayload(handoff),0,'issuer-v49'),
    receiptSignature:sig(receiptPayload(receipt),1,'recipient-v49')};
  }
  const tuples=[make(11,'a'.repeat(64),'b'.repeat(64)),
    make(12,'b'.repeat(64),'c'.repeat(64))];
  const insertReceipt=[
   'INSERT INTO palaco_incident_witness.receipts',
   '(namespace,sequence,nonce,handoff_digest,recipient_id)',
   'VALUES($1,$2,$3,$4,$5)'
  ].join(' ');
  const archiver=createHistoricalReceiptArchiver({
   namespace,query:q=>primary.query(q),historicalRootsProvider:async()=>roots
  });
  for(const t of tuples){
   await primary.query(insertReceipt,[namespace,t.handoff.nextSequence,
    t.handoff.nonce,handoffDigest(t.handoff),t.handoff.recipientId]);
   const proof=await archiver.archive(t.handoff,t.senderSignature,
    t.receipt,t.receiptSignature);
   assert.equal(proof.readiness,'HISTORICAL_RECEIPT_ARCHIVED_NON_AUTHORIZING');
  }
  const records=tuples.map(t=>({
   sequence:String(t.handoff.nextSequence),nonce:t.handoff.nonce,
   handoff_digest:handoffDigest(t.handoff),recipient_id:t.handoff.recipientId
  }));
  const chain=receiptChain(records,{namespace,firstSequence:11});
  await anchor.query(
   'INSERT INTO palaco_receipt_anchor.latest(namespace,sequence,chain_digest) VALUES($1,$2,$3)',
   [namespace,12,chain.digest]);
  const verifier=createHistoricalReceiptVerifier({
   namespace,firstSequence:11,
   receiptQuery:q=>primary.query(q),anchorQuery:q=>anchor.query(q),
   historicalRootsProvider:async()=>roots
  });
  const ok=await verifier.verify();
  assert.equal(ok.readiness,'HISTORICAL_RECEIPTS_VERIFIED_NON_AUTHORIZING');
  assert.equal(ok.verifiedSignatures,4);assert.equal(ok.authorization,'DENY');
  await assert.rejects(primary.query(
   "UPDATE palaco_incident_witness.receipt_evidence SET nonce='forged' WHERE namespace=$1",
   [namespace]),e=>e.code==='23514');
  await assert.rejects(primary.query(
   "DELETE FROM palaco_incident_witness.receipt_evidence WHERE namespace=$1",
   [namespace]),e=>e.code==='23514');
  await assert.rejects(primary.query(
   'TRUNCATE palaco_incident_witness.receipt_evidence'),e=>e.code==='23514');
  // A privileged admin can replace the evidence table entirely. That must
  // fail cryptographic historical verification even if receipt root matches.
  await primary.query('DROP TABLE palaco_incident_witness.receipt_evidence');
  await primary.query(evidenceSql);
  assert.deepEqual((await verifier.verify()).findings,
   ['HISTORICAL_RECEIPTS_SIGNATURE_OR_BINDING_INVALID']);
  // A malicious historic receipt carrying the correct metadata but a
  // forged signature cannot be imported by the reviewed archiver.
  const forged={...tuples[0].receiptSignature,signature:'A'.repeat(86)+'=='};
  assert.equal((await archiver.archive(tuples[0].handoff,
   tuples[0].senderSignature,tuples[0].receipt,forged)).readiness,'BLOCKED');
  assert.equal((await primary.query(
   'SELECT count(*)::int AS count FROM palaco_incident_witness.receipt_evidence'
  )).rows[0].count,0);
 }finally{
  if(primary)await primary.end().catch(()=>{});
  if(anchor)await anchor.end().catch(()=>{});
  await admin.end().catch(()=>{});
 }
});
