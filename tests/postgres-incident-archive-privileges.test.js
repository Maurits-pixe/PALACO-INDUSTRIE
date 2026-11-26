'use strict';
// Disposable PostgreSQL 17 CI privilege test. No production role provisioning.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {generateKeyPairSync,sign}=require('node:crypto');
const {incidentPayload,incidentDigest}=require('../distribution/witness-incident-review');
const {createIncidentArchive}=require('../distribution/incident-append-only-archive');
const {createIncidentWriteGateway}=require('../distribution/incident-write-gateway');

test('separate archive reader and writer roles enforce least privilege', {
 skip:process.env.PALACO_TEST_POSTGRES!=='1'
},async()=>{
 const {Client}=require('pg');
 const admin=new Client({connectionString:process.env.PALACO_TEST_DATABASE_URL});
 let reader,writer;
 await admin.connect();
 try{
  const schema=fs.readFileSync(path.join(__dirname,
   '../distribution/sql/incident-append-only-v4.3.sql'),'utf8');
  await admin.query(schema);
  const scope='palaco.v44ci';
  const key1=generateKeyPairSync('ed25519');
  const key2=generateKeyPairSync('ed25519');
  const keys=[key1,key2];
  const roots=keys.map((key,i)=>({
   keyId:'review-'+i,reviewerId:'person-'+i,enabled:true,revoked:false,
   publicKeyPem:key.publicKey.export({type:'spki',format:'pem'})
  }));
  await admin.query("CREATE ROLE palaco_archive_reader_v44 LOGIN PASSWORD 'ci_reader_only'");
  await admin.query("CREATE ROLE palaco_archive_writer_v44 LOGIN PASSWORD 'ci_writer_only'");
  await admin.query('REVOKE ALL ON SCHEMA palaco_incident_archive FROM PUBLIC');
  await admin.query('REVOKE ALL ON palaco_incident_archive.entries FROM PUBLIC');
  await admin.query('GRANT USAGE ON SCHEMA palaco_incident_archive TO palaco_archive_reader_v44,palaco_archive_writer_v44');
  await admin.query('GRANT SELECT ON palaco_incident_archive.entries TO palaco_archive_reader_v44');
  await admin.query('GRANT SELECT, INSERT ON palaco_incident_archive.entries TO palaco_archive_writer_v44');
  await admin.query('ALTER TABLE palaco_incident_archive.entries ENABLE ROW LEVEL SECURITY');
  await admin.query("CREATE POLICY archive_ci_reader ON palaco_incident_archive.entries FOR SELECT TO palaco_archive_reader_v44 USING(namespace='palaco.v44ci')");
  await admin.query("CREATE POLICY archive_ci_writer_select ON palaco_incident_archive.entries FOR SELECT TO palaco_archive_writer_v44 USING(namespace='palaco.v44ci')");
  await admin.query("CREATE POLICY archive_ci_writer_insert ON palaco_incident_archive.entries FOR INSERT TO palaco_archive_writer_v44 WITH CHECK(namespace='palaco.v44ci')");
  const base=new URL(process.env.PALACO_TEST_DATABASE_URL);
  const urlFor=(username,password)=>{const url=new URL(base);
   url.username=username;url.password=password;return url.toString();};
  reader=new Client({connectionString:urlFor('palaco_archive_reader_v44','ci_reader_only')});
  writer=new Client({connectionString:urlFor('palaco_archive_writer_v44','ci_writer_only')});
  await Promise.all([reader.connect(),writer.connect()]);
  const dossier={schemaVersion:'palaco.distribution.witness-incident.v1',
   namespace:scope,incidentId:'archive-v44-first',sequence:1,
   priorIncidentDigest:'0'.repeat(64),observedAtMs:1000,expiresAtMs:5000,
   primary:{revision:10,digest:'a'.repeat(64)},
   secondary:{revision:11,digest:'b'.repeat(64)},
   authorization:'DENY',go13:'HOLD',recommendedAction:'QUARANTINE_NO_SYNC'};
  const signatures=keys.map((key,i)=>({
   algorithm:'Ed25519',keyId:'review-'+i,
   signature:sign(null,incidentPayload(dossier),key.privateKey).toString('base64')
  }));
  const readArchive=createIncidentArchive({namespace:scope,query:request=>reader.query(request)});
  const writeArchive=createIncidentArchive({namespace:scope,query:request=>writer.query(request)});
  assert.equal(await readArchive.latest(),null);
  const denied=await readArchive.appendReviewed(dossier,signatures,{
   nowMs:2000,pinnedReviewRoots:roots
  });
  assert.deepEqual(denied.findings,['INCIDENT_ARCHIVE_APPEND_REJECTED']);
  assert.equal(denied.authorization,'DENY');
  const writerGateway=createIncidentWriteGateway({
    namespace:scope,query:request=>writer.query(request),
    reviewPolicyProvider:async()=>({nowMs:2000,pinnedReviewRoots:roots}),
    primaryWitness:{namespace:scope,latest:async()=>({...dossier.primary})},
    secondaryWitness:{namespace:scope,latest:async()=>({...dossier.secondary})}
  });
  assert.equal(typeof writerGateway.query,'undefined');
  assert.equal((await writerGateway.submit(dossier,signatures)).readiness,
    'INCIDENT_GATEWAY_ARCHIVED_NON_AUTHORIZING');
  assert.deepEqual(await readArchive.latest(),{
   sequence:1,digest:incidentDigest(dossier)
  });
  const rejected=await writerGateway.submit(dossier,signatures);
  assert.deepEqual(rejected.findings,['INCIDENT_GATEWAY_HEAD_MISMATCH']);

  assert.deepEqual((await reader.query(
   'SELECT incident_id FROM palaco_incident_archive.entries')).rows,
   [{incident_id:'archive-v44-first'}]);
  for(const sql of [
   "INSERT INTO palaco_incident_archive.entries(namespace,sequence,incident_id,prior_digest,incident_digest,observed_at_ms,dossier,endorsements) VALUES ('palaco.v44ci',2,'unauth','"+
     incidentDigest(dossier)+"','"+'f'.repeat(64)+"',2000,'{}'::jsonb,'[]'::jsonb)",
   'DELETE FROM palaco_incident_archive.entries',
   'TRUNCATE palaco_incident_archive.entries',
   'ALTER TABLE palaco_incident_archive.entries DISABLE TRIGGER reject_incident_mutation'
  ])await assert.rejects(reader.query(sql),error=>error.code==='42501');
  for(const sql of [
   "UPDATE palaco_incident_archive.entries SET observed_at_ms=99 WHERE namespace='palaco.v44ci'",
   "DELETE FROM palaco_incident_archive.entries WHERE namespace='palaco.v44ci'",
   'TRUNCATE palaco_incident_archive.entries',
   'ALTER TABLE palaco_incident_archive.entries DISABLE TRIGGER reject_incident_mutation'
  ])await assert.rejects(writer.query(sql),error=>error.code==='42501');
  const outside=await writer.query('SELECT namespace FROM palaco_incident_archive.entries');
  assert.deepEqual(outside.rows,[{namespace:scope}]);
  const deniedForeign=await writer.query(
   'SELECT namespace FROM palaco_incident_archive.entries WHERE namespace=$1',
   ['palaco.other']);
  assert.equal(deniedForeign.rowCount,0);
  assert.deepEqual(await writeArchive.latest(),{
   sequence:1,digest:incidentDigest(dossier)
  });
 }finally{
  if(reader)await reader.end().catch(()=>{});
  if(writer)await writer.end().catch(()=>{});
  await admin.end().catch(()=>{});
 }
});
