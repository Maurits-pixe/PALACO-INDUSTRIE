'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {receiptChain,createReceiptSuccessionVerifier}=
 require('../distribution/receipt-succession-verifier');
test('live PostgreSQL separate root detects privileged receipt registry restore', {
 skip:process.env.PALACO_TEST_POSTGRES!=='1'
},async()=>{
 const {Client}=require('pg');
 const base=new URL(process.env.PALACO_TEST_DATABASE_URL);
 const admin=new Client({connectionString:base.toString()});
 let archive,anchor;
 await admin.connect();
 try{
  const sourceName='palaco_receipts_source_v48_ci';
  const anchorName='palaco_receipts_anchor_v48_ci';
  for(const name of [sourceName,anchorName]){
   const found=await admin.query(
    'SELECT 1 FROM pg_database WHERE datname=$1',[name]);
   if(found.rowCount===0)await admin.query('CREATE DATABASE '+name);
  }
  const urlFor=name=>{const url=new URL(base.toString());
   url.pathname='/'+name;return url.toString();};
  archive=new Client({connectionString:urlFor(sourceName)});
  anchor=new Client({connectionString:urlFor(anchorName)});
  await Promise.all([archive.connect(),anchor.connect()]);
  const sql=name=>fs.readFileSync(path.join(__dirname,
   '../distribution/sql',name),'utf8');
  const sourceSchema=sql('incident-external-witness-v4.6.sql');
  const receiptsSchema=sql('incident-witness-receipts-v4.7.sql');
  const anchorSchema=sql('receipt-succession-anchor-v4.8.sql');
  await archive.query(sourceSchema);
  await archive.query(receiptsSchema);
  await anchor.query(anchorSchema);
  const namespace='palaco.v48ci';
  const records=[
   {sequence:'11',nonce:'handoff-11',handoff_digest:'a'.repeat(64),
    recipient_id:'recipient-v48'},
   {sequence:'12',nonce:'handoff-12',handoff_digest:'b'.repeat(64),
    recipient_id:'recipient-v48'}
  ];
  const insert=[
   'INSERT INTO palaco_incident_witness.receipts',
   '(namespace,sequence,nonce,handoff_digest,recipient_id)',
   'VALUES($1,$2,$3,$4,$5)'
  ].join(' ');
  for(const r of records)await archive.query(insert,[
   namespace,r.sequence,r.nonce,r.handoff_digest,r.recipient_id]);
  const final=receiptChain(records,{namespace,firstSequence:11});
  const prev=receiptChain(records.slice(0,1),{namespace,firstSequence:11});
  await anchor.query(
   'INSERT INTO palaco_receipt_anchor.latest(namespace,sequence,chain_digest) VALUES($1,$2,$3)',
   [namespace,11,prev.digest]);
  await anchor.query(
   'UPDATE palaco_receipt_anchor.latest SET sequence=$2,chain_digest=$3 WHERE namespace=$1',
   [namespace,12,final.digest]);
  const verifier=createReceiptSuccessionVerifier({
   namespace,firstSequence:11,
   archiveQuery:q=>archive.query(q),anchorQuery:q=>anchor.query(q)
  });
  const verified=await verifier.verify();
  assert.equal(verified.readiness,'RECEIPT_SUCCESSION_VERIFIED_NON_AUTHORIZING');
  assert.equal(verified.authorization,'DENY');
  assert.equal(verified.count,2);
  // Privileged operator restores the receipts DB to an older backup.
  // Local triggers are not a defense against schema replacement.
  await archive.query('DROP SCHEMA palaco_incident_witness CASCADE');
  await archive.query(sourceSchema);
  await archive.query(receiptsSchema);
  const old=records[0];
  await archive.query(insert,[namespace,old.sequence,old.nonce,
   old.handoff_digest,old.recipient_id]);
  const restored=await verifier.verify();
  assert.deepEqual(restored.findings,['RECEIPT_CHAIN_ANCHOR_MISMATCH']);
  assert.equal(restored.go13,'HOLD');assert.equal(restored.mayRestore,false);
  const head=await anchor.query(
   'SELECT sequence,chain_digest FROM palaco_receipt_anchor.latest WHERE namespace=$1',
   [namespace]);
  assert.deepEqual(head.rows,[{sequence:'12',chain_digest:final.digest}]);
  await assert.rejects(anchor.query(
   'UPDATE palaco_receipt_anchor.latest SET sequence=$2 WHERE namespace=$1',
   [namespace,11]),e=>e.code==='23514');
  await assert.rejects(anchor.query(
   'DELETE FROM palaco_receipt_anchor.latest WHERE namespace=$1',
   [namespace]),e=>e.code==='23514');
  await assert.rejects(anchor.query('TRUNCATE palaco_receipt_anchor.latest'),
   e=>e.code==='23514');
 }finally{
  if(archive)await archive.end().catch(()=>{});
  if(anchor)await anchor.end().catch(()=>{});
  await admin.end().catch(()=>{});
 }
});
