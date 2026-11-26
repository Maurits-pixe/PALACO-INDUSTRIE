'use strict';
// Disposable CI-only PostgreSQL privileges: no production roles/secrets.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {generateKeyPairSync,sign}=require('node:crypto');
const {authorityDigest,rotationPayload}=
 require('../distribution/roster-authority-rotation');
const {createAuthorityAnchorStore}=
 require('../distribution/postgres-authority-anchor');

test('authority anchor runtime role is restricted by grants and RLS', {
 skip:process.env.PALACO_TEST_POSTGRES!=='1'
},async()=>{
 const {Client}=require('pg');
 const admin=new Client({connectionString:process.env.PALACO_TEST_DATABASE_URL});
 let runtime;
 await admin.connect();
 try{
  await admin.query(fs.readFileSync(path.join(__dirname,
   '../distribution/sql/authority-anchor-highwater-v3.9.sql'),'utf8'));
  await admin.query('TRUNCATE palaco_authority_anchor.latest');
  const old=generateKeyPairSync('ed25519'),next=generateKeyPairSync('ed25519');
  const a=generateKeyPairSync('ed25519'),b=generateKeyPairSync('ed25519');
  const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
  const previous={schemaVersion:'palaco.distribution.roster-authority.v1',
    namespace:'palaco.registry',revision:30,previousDigest:'0'.repeat(64),
    keys:[{keyId:'authority-a',status:'active',publicKeyPem:pem(old)}]};
  const proposed={...previous,revision:31,previousDigest:authorityDigest(previous),
    keys:[{keyId:'authority-a',status:'revoked',publicKeyPem:pem(old)},
      {keyId:'authority-z',status:'active',publicKeyPem:pem(next)}]};
  const intent={schemaVersion:'palaco.distribution.roster-authority-rotation.v1',
    namespace:'palaco.registry',revision:31,
    previousDigest:authorityDigest(previous),nextDigest:authorityDigest(proposed),
    oldKeyId:'authority-a',newKeyId:'authority-z'};
  const payload=rotationPayload(intent);
  const approve=(key,keyId)=>({algorithm:'Ed25519',keyId,
    signature:sign(null,payload,key.privateKey).toString('base64')});
  const endorsements={oldAuthority:approve(old,'authority-a'),
    newAuthority:approve(next,'authority-z'),
    reviewers:[approve(a,'review-a'),approve(b,'review-b')]};
  const reviewerRoots=[
   {keyId:'review-a',reviewerId:'alice',enabled:true,revoked:false,publicKeyPem:pem(a)},
   {keyId:'review-b',reviewerId:'bob',enabled:true,revoked:false,publicKeyPem:pem(b)}
  ];
  await admin.query(
   'INSERT INTO palaco_authority_anchor.latest(namespace,revision,state_digest) VALUES($1,$2,$3),($4,$5,$6)',
   ['palaco.registry',30,authorityDigest(previous),'other.registry',10,'f'.repeat(64)]);
  await admin.query("CREATE ROLE authority_anchor_runtime_ci LOGIN PASSWORD 'ci_anchor_only'");
  await admin.query('REVOKE ALL ON SCHEMA palaco_authority_anchor FROM PUBLIC');
  await admin.query('REVOKE ALL ON palaco_authority_anchor.latest FROM PUBLIC');
  await admin.query('GRANT USAGE ON SCHEMA palaco_authority_anchor TO authority_anchor_runtime_ci');
  await admin.query('GRANT SELECT(namespace,revision,state_digest),UPDATE(revision,state_digest) ON palaco_authority_anchor.latest TO authority_anchor_runtime_ci');
  await admin.query('ALTER TABLE palaco_authority_anchor.latest ENABLE ROW LEVEL SECURITY');
  await admin.query("CREATE POLICY authority_anchor_ci_select ON palaco_authority_anchor.latest FOR SELECT TO authority_anchor_runtime_ci USING(namespace='palaco.registry')");
  await admin.query("CREATE POLICY authority_anchor_ci_update ON palaco_authority_anchor.latest FOR UPDATE TO authority_anchor_runtime_ci USING(namespace='palaco.registry') WITH CHECK(namespace='palaco.registry')");
  const url=new URL(process.env.PALACO_TEST_DATABASE_URL);
  url.username='authority_anchor_runtime_ci';url.password='ci_anchor_only';
  runtime=new Client({connectionString:url.toString()});
  await runtime.connect();
  const store=createAuthorityAnchorStore({namespace:'palaco.registry',
    query:args=>runtime.query(args)});
  assert.deepEqual(await store.latest(),
    {revision:30,digest:authorityDigest(previous)});
  assert.equal(await store.advanceVerified(previous,proposed,intent,
    endorsements,reviewerRoots),true);
  assert.equal((await store.latest()).revision,31);
  assert.equal(await store.advanceVerified(previous,proposed,intent,
    endorsements,reviewerRoots),false);
  const other=createAuthorityAnchorStore({namespace:'other.registry',
    query:args=>runtime.query(args)});
  assert.equal(await other.latest(),null);
  const visible=await runtime.query('SELECT namespace FROM palaco_authority_anchor.latest');
  assert.deepEqual(visible.rows,[{namespace:'palaco.registry'}]);
  for(const statement of [
   "INSERT INTO palaco_authority_anchor.latest(namespace,revision,state_digest) VALUES('new.registry',1,'"+'a'.repeat(64)+"')",
   "DELETE FROM palaco_authority_anchor.latest WHERE namespace='palaco.registry'",
   'TRUNCATE palaco_authority_anchor.latest',
   'ALTER TABLE palaco_authority_anchor.latest DISABLE TRIGGER guard_authority_revision'
  ]) await assert.rejects(runtime.query(statement),err=>err.code==='42501');
  await assert.rejects(runtime.query(
   "UPDATE palaco_authority_anchor.latest SET revision=30 WHERE namespace='palaco.registry'"),
   err=>err.code==='23514');
  assert.deepEqual(await store.latest(),
    {revision:31,digest:authorityDigest(proposed)});
 }finally{
  if(runtime)await runtime.end().catch(()=>{});
  await admin.end().catch(()=>{});
 }
});
