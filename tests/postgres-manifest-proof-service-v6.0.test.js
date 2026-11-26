'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {generateKeyPairSync,sign}=require('node:crypto');
const {VERSION,merkleRoot,checkpointBytes}=
 require('../distribution/manifest-merkle-proofs-v5.9');
const {createManifestProofIssuer}=
 require('../distribution/manifest-proof-issuer-v6.0');
const {createIndependentManifestProofService}=
 require('../distribution/manifest-proof-verification-service-v6.0');
test('PostgreSQL read-only issuer and independent verifier detect missing and conflicting views',{
 skip:process.env.PALACO_TEST_POSTGRES!=='1'
},async()=>{
 const {Client}=require('pg');
 const base=new URL(process.env.PALACO_TEST_DATABASE_URL);
 const admin=new Client({connectionString:base.toString()});
 let log,rootDb;
 await admin.connect();
 try{
  for(const name of ['palaco_v60_issuer_ci','palaco_v60_verifier_ci']){
   if(!(await admin.query('SELECT 1 FROM pg_database WHERE datname=$1',[name])).rowCount)
    await admin.query('CREATE DATABASE '+name);
  }
  const u=name=>{const x=new URL(base);x.pathname='/'+name;return x.toString();};
  log=new Client({connectionString:u('palaco_v60_issuer_ci')});
  rootDb=new Client({connectionString:u('palaco_v60_verifier_ci')});
  await Promise.all([log.connect(),rootDb.connect()]);
  const sql=n=>fs.readFileSync(path.join(__dirname,'../distribution/sql',n),'utf8');
  await log.query(sql('manifest-transparency-v5.8.sql'));
  await rootDb.query(sql('manifest-merkle-checkpoints-v5.9.sql'));
  const namespace='palaco.v60ci';
  const leaves=Array.from({length:3},(_,i)=>(i+1).toString(16).padStart(64,'0'));
  const add=[
   'INSERT INTO palaco_manifest_transparency.entries',
   '(namespace,entry_sequence,previous_entry_digest,entry_digest,',
   'rotation_number,manifest_digest,previous_manifest_digest,',
   'observer_id,key_id,observed_at_ms,signature)',
   'VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)'
  ].join(' ');
  for(let i=0;i<3;i++){
   await log.query(add,[namespace,i+1,i===0?'0'.repeat(64):leaves[i-1],
    leaves[i],1,'b'.repeat(64),'a'.repeat(64),
    'observer-'+i,'key-'+i,1000+i,'A'.repeat(86)+'==']);
  }
  const signer=generateKeyPairSync('ed25519'),root={
   observerId:'independent-checker',keyId:'root-ci',
   enabled:true,revoked:false,
   publicKeyPem:signer.publicKey.export({type:'spki',format:'pem'})
  };
  const signedRoot=[
   'INSERT INTO palaco_manifest_merkle_anchor.checkpoints',
   '(namespace,tree_size,merkle_root,observer_id,key_id,observed_at_ms,signature)',
   'VALUES($1,$2,$3,$4,$5,$6,$7)'
  ].join(' ');
  for(const size of [1,3]){
   const cp={schemaVersion:VERSION,namespace,treeSize:size,
    merkleRoot:merkleRoot(leaves.slice(0,size)),
    observerId:root.observerId,observedAtMs:2000+size,
    authorization:'DENY',go13:'HOLD',
    purpose:'MERKLE_PROOF_ROOT_NO_AUTHORITY'};
   await rootDb.query(signedRoot,[namespace,size,cp.merkleRoot,
    root.observerId,root.keyId,cp.observedAtMs,
    sign(null,checkpointBytes(cp),signer.privateKey).toString('base64')]);
  }
  const issuer=createManifestProofIssuer({namespace,logQuery:q=>log.query(q)});
  const verifier=createIndependentManifestProofService({
   namespace,checkpointQuery:q=>rootDb.query(q),
   trustRootProvider:async()=>root,
   pinnedRootProvider:async(ns,size)=>merkleRoot(leaves.slice(0,size))
  });
  const inc=await issuer.issueInclusion({treeSize:3,index:2});
  const cons=await issuer.issueConsistency({oldSize:1,newSize:3});
  assert.equal((await verifier.verifyInclusion(inc)).readiness,
   'INDEPENDENT_INCLUSION_VERIFIED_NON_AUTHORIZING');
  assert.equal((await verifier.verifyConsistency(cons)).readiness,
   'INDEPENDENT_CONSISTENCY_VERIFIED_NON_AUTHORIZING');
  // A privileged issuer DB restore removes evidence. It cannot change
  // independently retained signed verifier roots and pins.
  await log.query('DROP SCHEMA palaco_manifest_transparency CASCADE');
  await log.query(sql('manifest-transparency-v5.8.sql'));
  await log.query(add,[namespace,1,'0'.repeat(64),leaves[0],
   1,'b'.repeat(64),'a'.repeat(64),'observer-0','key-0',1000,
   'A'.repeat(86)+'==']);
  assert.equal((await issuer.issueInclusion({treeSize:3,index:2})).readiness,
   'BLOCKED');
  assert.equal((await verifier.verifyInclusion({...inc,merkleRoot:'f'.repeat(64)})).readiness,
   'BLOCKED');
  assert.equal((await verifier.verifyConsistency({...cons,proof:{
   ...cons.proof,extension:['f'.repeat(64),...cons.proof.extension.slice(1)]
  }})).readiness,'BLOCKED');
  assert.equal((await verifier.verifyInclusion(inc)).authorization,'DENY');
 }finally{
  if(log)await log.end().catch(()=>{});
  if(rootDb)await rootDb.end().catch(()=>{});
  await admin.end().catch(()=>{});
 }
});
