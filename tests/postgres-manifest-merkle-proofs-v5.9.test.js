'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {generateKeyPairSync,sign}=require('node:crypto');
const {VERSION,merkleRoot,inclusionProof,consistencyProof,
 checkpointBytes,createRootVerifier}=
 require('../distribution/manifest-merkle-proofs-v5.9');
test('PostgreSQL externally signed Merkle roots reject fork, loss and mutation',{
 skip:process.env.PALACO_TEST_POSTGRES!=='1'
},async()=>{
 const {Client}=require('pg');
 const base=new URL(process.env.PALACO_TEST_DATABASE_URL);
 const admin=new Client({connectionString:base.toString()});
 let a,b;
 await admin.connect();
 try{
  for(const name of ['palaco_v59_merkle_log_ci','palaco_v59_merkle_anchor_ci']){
   const exists=await admin.query('SELECT 1 FROM pg_database WHERE datname=$1',[name]);
   if(!exists.rowCount)await admin.query('CREATE DATABASE '+name);
  }
  const url=name=>{const v=new URL(base);v.pathname='/'+name;return v.toString();};
  a=new Client({connectionString:url('palaco_v59_merkle_log_ci')});
  b=new Client({connectionString:url('palaco_v59_merkle_anchor_ci')});
  await Promise.all([a.connect(),b.connect()]);
  const sql=n=>fs.readFileSync(path.join(__dirname,'../distribution/sql',n),'utf8');
  await a.query(sql('manifest-transparency-v5.8.sql'));
  await b.query(sql('manifest-merkle-checkpoints-v5.9.sql'));
  const namespace='palaco.v59ci',kp=generateKeyPairSync('ed25519');
  const roots={observerId:'external-merkle-auditor',keyId:'merkle-auditor-key',
   enabled:true,revoked:false,
   publicKeyPem:kp.publicKey.export({type:'spki',format:'pem'})};
  const leafDigests=Array.from({length:7},(_,i)=>String(i+1).padStart(64,'0'));
  const insert=[
   'INSERT INTO palaco_manifest_merkle_anchor.checkpoints',
   '(namespace,tree_size,merkle_root,observer_id,key_id,observed_at_ms,signature)',
   'VALUES($1,$2,$3,$4,$5,$6,$7)'
  ].join(' ');
  for(const size of [3,7]){
   const statement={schemaVersion:VERSION,namespace,treeSize:size,
    merkleRoot:merkleRoot(leafDigests.slice(0,size)),
    observerId:roots.observerId,observedAtMs:1000+size,
    authorization:'DENY',go13:'HOLD',
    purpose:'MERKLE_PROOF_ROOT_NO_AUTHORITY'};
   const signature=sign(null,checkpointBytes(statement),kp.privateKey)
    .toString('base64');
   await b.query(insert,[namespace,size,statement.merkleRoot,
    roots.observerId,roots.keyId,statement.observedAtMs,signature]);
  }
  const verifier=createRootVerifier({namespace,
   checkpointQuery:req=>b.query(req),trustRootProvider:async()=>roots});
  const inclusion=inclusionProof(leafDigests,5);
  const consistent=consistencyProof(leafDigests,3);
  assert.equal((await verifier.verifyInclusion(inclusion)).readiness,
   'MERKLE_INCLUSION_VERIFIED_NON_AUTHORIZING');
  assert.equal((await verifier.verifyConsistency(consistent)).readiness,
   'MERKLE_APPEND_ONLY_CONSISTENCY_VERIFIED_NON_AUTHORIZING');
  const forged={...consistent,extension:[
   'f'.repeat(64),...consistent.extension.slice(1)
  ]};
  assert.equal((await verifier.verifyConsistency(forged)).readiness,'BLOCKED');
  await assert.rejects(b.query(
   'UPDATE palaco_manifest_merkle_anchor.checkpoints SET merkle_root=$1 WHERE namespace=$2',
   ['f'.repeat(64),namespace]),e=>e.code==='23514');
  await assert.rejects(b.query(
   'DELETE FROM palaco_manifest_merkle_anchor.checkpoints WHERE namespace=$1',
   [namespace]),e=>e.code==='23514');
  await assert.rejects(b.query(
   'TRUNCATE palaco_manifest_merkle_anchor.checkpoints'),
   e=>e.code==='23514');
  // Privileged one-sided rollback: remove newest signed root.
  await b.query('DROP SCHEMA palaco_manifest_merkle_anchor CASCADE');
  await b.query(sql('manifest-merkle-checkpoints-v5.9.sql'));
  assert.equal((await verifier.verifyInclusion(inclusion)).readiness,'BLOCKED');
  assert.equal((await verifier.verifyConsistency(consistent)).readiness,'BLOCKED');
 }finally{
  if(a)await a.end().catch(()=>{});
  if(b)await b.end().catch(()=>{});
  await admin.end().catch(()=>{});
 }
});
