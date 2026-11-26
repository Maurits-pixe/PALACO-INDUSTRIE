'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {generateKeyPairSync,sign}=require('node:crypto');
const {publicationBytes,VERSION}=require('../distribution/manifest-publication-views-v5.7');
const {ZERO,CHECKPOINT_VERSION,entryDigest,checkpointBytes,
 createManifestTransparencyVerifier}=
 require('../distribution/manifest-transparency-v5.8');
test('PostgreSQL signed manifest transparency rejects gaps, deletion and privileged log restore',{
 skip:process.env.PALACO_TEST_POSTGRES!=='1'
},async()=>{
 const {Client}=require('pg');
 const base=new URL(process.env.PALACO_TEST_DATABASE_URL);
 const admin=new Client({connectionString:base.toString()});
 let ledger,anchor;
 await admin.connect();
 try{
  for(const name of ['palaco_v58_ledger_ci','palaco_v58_checkpoint_ci']){
   const exists=await admin.query('SELECT 1 FROM pg_database WHERE datname=$1',[name]);
   if(!exists.rowCount)await admin.query('CREATE DATABASE '+name);
  }
  const url=name=>{const u=new URL(base);u.pathname='/'+name;return u.toString();};
  ledger=new Client({connectionString:url('palaco_v58_ledger_ci')});
  anchor=new Client({connectionString:url('palaco_v58_checkpoint_ci')});
  await Promise.all([ledger.connect(),anchor.connect()]);
  const schema=fs.readFileSync(path.join(__dirname,
   '../distribution/sql/manifest-transparency-v5.8.sql'),'utf8');
  await ledger.query(schema);await anchor.query(schema);
  const namespace='palaco.v58ci',keys=Array.from({length:3},
   ()=>generateKeyPairSync('ed25519'));
  const roots=keys.map((kp,i)=>({
   observerId:i===2?'checkpoint-auditor':'observer-'+i,
   keyId:'key-'+i,enabled:true,revoked:false,
   publicKeyPem:kp.publicKey.export({type:'spki',format:'pem'})
  }));
  const oldHash='a'.repeat(64),newHash='b'.repeat(64);
  const entries=[];let last=ZERO;
  const insert=[
   'INSERT INTO palaco_manifest_transparency.entries',
   '(namespace,entry_sequence,previous_entry_digest,entry_digest,',
   'rotation_number,manifest_digest,previous_manifest_digest,',
   'observer_id,key_id,observed_at_ms,signature)',
   'VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)'
  ].join(' ');
  for(let i=0;i<2;i++){
   const view={schemaVersion:VERSION,namespace,rotationNumber:1,
    manifestDigest:newHash,previousManifestDigest:oldHash,
    observerId:roots[i].observerId,observedAtMs:1500+i,
    authorization:'DENY',go13:'HOLD',
    purpose:'MANIFEST_VIEW_OBSERVATION_NO_RELEASE'};
   const sig=sign(null,publicationBytes(view),keys[i].privateKey)
    .toString('base64');
   const row={namespace,entry_sequence:String(i+1),
    previous_entry_digest:last,rotation_number:'1',
    manifest_digest:newHash,previous_manifest_digest:oldHash,
    observer_id:roots[i].observerId,key_id:roots[i].keyId,
    observed_at_ms:String(1500+i),signature:sig};
   row.entry_digest=entryDigest(row,last);
   entries.push(row);last=row.entry_digest;
  }
  const values=e=>[e.namespace,e.entry_sequence,e.previous_entry_digest,
   e.entry_digest,e.rotation_number,e.manifest_digest,
   e.previous_manifest_digest,e.observer_id,e.key_id,
   e.observed_at_ms,e.signature];
  await assert.rejects(ledger.query(insert,values(entries[1])),
   e=>e.code==='23514');
  for(const e of entries)await ledger.query(insert,values(e));
  const headProof={schemaVersion:CHECKPOINT_VERSION,namespace,
   entrySequence:2,entryDigest:entries[1].entry_digest,
   observerId:roots[2].observerId,observedAtMs:2000,
   authorization:'DENY',go13:'HOLD',
   purpose:'MANIFEST_TRANSPARENCY_OBSERVATION_NO_AUTHORITY'};
  const headSignature=sign(null,checkpointBytes(headProof),keys[2].privateKey)
   .toString('base64');
  const insertHead=[
   'INSERT INTO palaco_manifest_transparency_anchor.latest',
   '(namespace,entry_sequence,entry_digest,observer_id,key_id,observed_at_ms,signature)',
   'VALUES($1,$2,$3,$4,$5,$6,$7)'
  ].join(' ');
  await anchor.query(insertHead,[namespace,2,entries[1].entry_digest,
   headProof.observerId,roots[2].keyId,2000,headSignature]);
  const verifier=createManifestTransparencyVerifier({
   namespace,logQuery:q=>ledger.query(q),checkpointQuery:q=>anchor.query(q),
   pinnedCheckpointSequence:1,pinnedCheckpointDigest:entries[0].entry_digest,
   observationRootProvider:async(ns,id)=>roots.find(r=>r.observerId===id),
   checkpointRootProvider:async()=>roots[2]
  });
  const confirmed=await verifier.verify();
  assert.equal(confirmed.readiness,'MANIFEST_TRANSPARENCY_VERIFIED_NON_AUTHORIZING');
  assert.equal(confirmed.verifiedObservations,2);
  assert.equal(confirmed.authorization,'DENY');assert.equal(confirmed.go13,'HOLD');
  await assert.rejects(ledger.query(
   'DELETE FROM palaco_manifest_transparency.entries WHERE namespace=$1',
   [namespace]),e=>e.code==='23514');
  await assert.rejects(ledger.query(
   'UPDATE palaco_manifest_transparency.entries SET entry_sequence=3 WHERE namespace=$1',
   [namespace]),e=>e.code==='23514');
  await assert.rejects(ledger.query(
   'TRUNCATE palaco_manifest_transparency.entries'),e=>e.code==='23514');
  await assert.rejects(anchor.query(
   'DELETE FROM palaco_manifest_transparency_anchor.latest WHERE namespace=$1',
   [namespace]),e=>e.code==='23514');
  // Privileged restore removes the final event in primary ledger only.
  await ledger.query('DROP SCHEMA palaco_manifest_transparency CASCADE');
  await ledger.query(schema);
  await ledger.query(insert,values(entries[0]));
  const restored=await verifier.verify();
  assert.deepEqual(restored.findings,['TRANSPARENCY_CHECKPOINT_HEAD_MISMATCH']);
  assert.equal(restored.mayRestore,false);
  const independent=await anchor.query(
   'SELECT entry_sequence,entry_digest FROM palaco_manifest_transparency_anchor.latest WHERE namespace=$1',
   [namespace]);
  assert.deepEqual(independent.rows,[{
   entry_sequence:'2',entry_digest:entries[1].entry_digest
  }]);
 }finally{
  if(ledger)await ledger.end().catch(()=>{});
  if(anchor)await anchor.end().catch(()=>{});
  await admin.end().catch(()=>{});
 }
});
