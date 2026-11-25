'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {generateKeyPairSync,sign}=require('node:crypto');
const {VERSION,publicationBytes,createManifestPublicationViewVerifier}=
 require('../distribution/manifest-publication-views-v5.7');
test('two PostgreSQL observer stores detect a validly signed split-view and reject mutation',{
 skip:process.env.PALACO_TEST_POSTGRES!=='1'
},async()=>{
 const {Client}=require('pg');
 const base=new URL(process.env.PALACO_TEST_DATABASE_URL);
 const admin=new Client({connectionString:base.toString()});
 let a,b;
 await admin.connect();
 try{
  const names=['palaco_v57_first_ci','palaco_v57_second_ci'];
  for(const name of names){
   const x=await admin.query('SELECT 1 FROM pg_database WHERE datname=$1',[name]);
   if(!x.rowCount)await admin.query('CREATE DATABASE '+name);
  }
  function url(name){const u=new URL(base);u.pathname='/'+name;return u.toString();}
  a=new Client({connectionString:url(names[0])});
  b=new Client({connectionString:url(names[1])});
  await Promise.all([a.connect(),b.connect()]);
  const schema=fs.readFileSync(path.join(__dirname,
   '../distribution/sql/manifest-publication-views-v5.7.sql'),'utf8');
  await a.query(schema);await b.query(schema);
  const namespace='palaco.v57ci',previous='a'.repeat(64);
  const digest='b'.repeat(64),fork='c'.repeat(64);
  const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
  const roots=keys.map((key,i)=>({
   observerId:'observer-'+i,keyId:'key-'+i,enabled:true,revoked:false,
   publicKeyPem:key.publicKey.export({type:'spki',format:'pem'})
  }));
  const insert=[
   'INSERT INTO palaco_manifest_publication.views',
   '(namespace,rotation_number,manifest_digest,previous_manifest_digest,',
   'observer_id,key_id,observed_at_ms,signature)',
   'VALUES($1,$2,$3,$4,$5,$6,$7,$8)'
  ].join(' ');
  async function store(db,index,hash){
   const p={schemaVersion:VERSION,namespace,rotationNumber:1,
    manifestDigest:hash,previousManifestDigest:previous,
    observerId:roots[index].observerId,observedAtMs:1500,
    authorization:'DENY',go13:'HOLD',
    purpose:'MANIFEST_VIEW_OBSERVATION_NO_RELEASE'};
   const signature=sign(null,publicationBytes(p),keys[index].privateKey)
    .toString('base64');
   await db.query(insert,[namespace,1,hash,previous,
    p.observerId,roots[index].keyId,1500,signature]);
  }
  await store(a,0,digest);
  await store(b,1,fork);
  function verifier(){return createManifestPublicationViewVerifier({
   namespace,rotationNumber:1,pinnedPreviousDigest:previous,
   pinnedNextDigest:digest,firstQuery:q=>a.query(q),
   secondQuery:q=>b.query(q),
   rootProvider:async(ns,id)=>roots.find(r=>r.observerId===id)
  });}
  const split=await verifier().verify();
  assert.deepEqual(split.findings,['PUBLICATION_VIEW_SIGNED_SPLIT_VIEW_DETECTED']);
  assert.equal(split.authorization,'DENY');assert.equal(split.go13,'HOLD');
  await assert.rejects(b.query(
   'UPDATE palaco_manifest_publication.views SET manifest_digest=$1 WHERE namespace=$2',
   [digest,namespace]),e=>e.code==='23514');
  await assert.rejects(b.query(
   'DELETE FROM palaco_manifest_publication.views WHERE namespace=$1',
   [namespace]),e=>e.code==='23514');
  await assert.rejects(b.query('TRUNCATE palaco_manifest_publication.views'),
   e=>e.code==='23514');
  await assert.rejects(a.query(insert,[namespace,1,digest,previous,
   'observer-0','key-0',1500,'A'.repeat(86)+'==']),
   e=>e.code==='23505');
  // A privileged restore of the second store alone must not be
  // silently interpreted as a valid publication.
  await b.query('DROP SCHEMA palaco_manifest_publication CASCADE');
  await b.query(schema);
  assert.equal((await verifier().verify()).readiness,'BLOCKED');
 }finally{
  if(a)await a.end().catch(()=>{});
  if(b)await b.end().catch(()=>{});
  await admin.end().catch(()=>{});
 }
});
