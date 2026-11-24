'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {generateKeyPairSync,sign}=require('node:crypto');
const {incidentPayload,incidentDigest}=
  require('../distribution/witness-incident-review');
const {createIncidentArchive}=
  require('../distribution/incident-append-only-archive');
const on=process.env.PALACO_TEST_POSTGRES==='1';

test('live PostgreSQL incident history chains, survives replay and forbids mutation',
 {skip:!on},async()=>{
 const {Client}=require('pg');
 const pg=new Client({connectionString:process.env.PALACO_TEST_DATABASE_URL});
 const reviewers=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
 const roots=reviewers.map((key,i)=>({
  keyId:'archive-key-'+i,reviewerId:'person-'+i,enabled:true,revoked:false,
  publicKeyPem:key.publicKey.export({type:'spki',format:'pem'})
 }));
 const createIncident=(sequence,prior)=>{
  const dossier={schemaVersion:'palaco.distribution.witness-incident.v1',
   namespace:'palaco.ledgerci',incidentId:'ledger-ci-'+sequence,sequence,
   priorIncidentDigest:prior,observedAtMs:1000,expiresAtMs:5000,
   primary:{revision:20,digest:'a'.repeat(64)},
   secondary:{revision:21,digest:'b'.repeat(64)},
   authorization:'DENY',go13:'HOLD',
   recommendedAction:'QUARANTINE_NO_SYNC'};
  return {dossier,signatures:reviewers.map((key,i)=>({
   algorithm:'Ed25519',keyId:'archive-key-'+i,
   signature:sign(null,incidentPayload(dossier),key.privateKey).toString('base64')
  }))};
 };
 await pg.connect();
 try{
  await pg.query(fs.readFileSync(path.join(__dirname,
   '../distribution/sql/incident-append-only-v4.3.sql'),'utf8'));
  const archive=createIncidentArchive({namespace:'palaco.ledgerci',
   query:args=>pg.query(args)});
  const policy={nowMs:2000,pinnedReviewRoots:roots};
  const first=createIncident(1,'0'.repeat(64));
  const one=await archive.appendReviewed(first.dossier,first.signatures,policy);
  assert.equal(one.readiness,'INCIDENT_ARCHIVED_NON_AUTHORIZING');
  const second=createIncident(2,incidentDigest(first.dossier));
  const two=await archive.appendReviewed(second.dossier,second.signatures,policy);
  assert.equal(two.sequence,2);
  assert.deepEqual(await archive.latest(),
   {sequence:2,digest:incidentDigest(second.dossier)});
  const stored=await pg.query(
   'SELECT sequence,prior_digest,incident_digest,dossier,endorsements FROM palaco_incident_archive.entries WHERE namespace=$1 ORDER BY sequence',
   ['palaco.ledgerci']);
  assert.equal(stored.rowCount,2);
  assert.equal(stored.rows[0].sequence,'1');
  assert.equal(stored.rows[1].prior_digest,incidentDigest(first.dossier));
  assert.deepEqual(stored.rows[1].endorsements,second.signatures);
  assert.equal(stored.rows[1].dossier.incidentId,'ledger-ci-2');
  assert.equal(await archive.appendReviewed(second.dossier,second.signatures,policy)
    .then(r=>r.readiness),'BLOCKED');
  await assert.rejects(pg.query(
   'UPDATE palaco_incident_archive.entries SET observed_at_ms=3000 WHERE namespace=$1',
   ['palaco.ledgerci']),err=>err.code==='23514');
  await assert.rejects(pg.query(
   'DELETE FROM palaco_incident_archive.entries WHERE namespace=$1',
   ['palaco.ledgerci']),err=>err.code==='23514');
  await assert.rejects(pg.query(
   'TRUNCATE palaco_incident_archive.entries'),err=>err.code==='23514');
  // Direct SQL skip and predecessor forgery must not bypass the trigger.
  const sql=[
   'INSERT INTO palaco_incident_archive.entries',
   '(namespace,sequence,incident_id,prior_digest,incident_digest,observed_at_ms,dossier,endorsements)',
   'VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb)'
  ].join(' ');
  await assert.rejects(pg.query(sql,[
   'palaco.ledgerci',4,'skipped','f'.repeat(64),'e'.repeat(64),
   2000,JSON.stringify(second.dossier),JSON.stringify(second.signatures)
  ]),err=>err.code==='23514');
  await assert.rejects(pg.query(sql,[
   'palaco.ledgerci',3,'wrong-link','f'.repeat(64),'e'.repeat(64),
   2000,JSON.stringify(second.dossier),JSON.stringify(second.signatures)
  ]),err=>err.code==='23514');
  assert.deepEqual(await archive.latest(),
   {sequence:2,digest:incidentDigest(second.dossier)});
 }finally{await pg.end();}
});
