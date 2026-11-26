'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {createIncidentArchive}=require('../distribution/incident-append-only-archive');
const {createIncidentExternalWitness,verifyIncidentArchiveWitness}=
 require('../distribution/incident-external-witness');
test('separately stored PostgreSQL incident head detects privileged restored archive', {
 skip:process.env.PALACO_TEST_POSTGRES!=='1'
},async()=>{
 const {Client}=require('pg');
 const root=new URL(process.env.PALACO_TEST_DATABASE_URL);
 const admin=new Client({connectionString:root.toString()});
 const name='palaco_incident_v46_witness';
 let primary,remote;
 await admin.connect();
 try{
  const exists=await admin.query('SELECT 1 FROM pg_database WHERE datname=$1',[name]);
  if(exists.rowCount===0)await admin.query('CREATE DATABASE '+name);
  primary=new Client({connectionString:root.toString()});
  const remoteUrl=new URL(root.toString());remoteUrl.pathname='/'+name;
  remote=new Client({connectionString:remoteUrl.toString()});
  await Promise.all([primary.connect(),remote.connect()]);
  const archiveSchema=fs.readFileSync(path.join(__dirname,
    '../distribution/sql/incident-append-only-v4.3.sql'),'utf8');
  const witnessSchema=fs.readFileSync(path.join(__dirname,
    '../distribution/sql/incident-external-witness-v4.6.sql'),'utf8');
  await primary.query(archiveSchema);
  await remote.query(witnessSchema);
  const namespace='palaco.v46ci',old='a'.repeat(64),fresh='b'.repeat(64);
  // Privileged CI fixture only: simulated archive at head 1 and witness at 2.
  const insert=[
    'INSERT INTO palaco_incident_archive.entries',
    '(namespace,sequence,incident_id,prior_digest,incident_digest,',
    'observed_at_ms,dossier,endorsements)',
    'VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb)'
  ].join(' ');
  await primary.query(insert,[namespace,1,'incident-1','0'.repeat(64),
    old,1000,'{}','[]']);
  await primary.query(insert,[namespace,2,'incident-2',old,
    fresh,2000,'{}','[]']);
   await remote.query(
    'INSERT INTO palaco_incident_witness.heads(namespace,sequence,incident_digest) VALUES($1,$2,$3)',
    [namespace,1,old]);
  await remote.query(
    'UPDATE palaco_incident_witness.heads SET sequence=$2,incident_digest=$3 WHERE namespace=$1',
    [namespace,2,fresh]);
  const archive=createIncidentArchive({namespace,query:q=>primary.query(q)});
  const witness=createIncidentExternalWitness({namespace,query:q=>remote.query(q)});
  const ok=await verifyIncidentArchiveWitness(archive,witness);
  assert.equal(ok.readiness,'INCIDENT_ARCHIVE_HEAD_VERIFIED_NON_AUTHORIZING');
  assert.equal(ok.authorization,'DENY');
  // The operator forcibly restores the primary to an old backup. A real
  // independent witness does not follow this rollback.
  // Administrator-controlled DROP/RESTORE defeats local archive triggers.
  await primary.query('DROP SCHEMA palaco_incident_archive CASCADE');
  await primary.query(archiveSchema);
  await primary.query(insert,[namespace,1,'incident-1','0'.repeat(64),
    old,1000,'{}','[]']);
  const stale=await verifyIncidentArchiveWitness(archive,witness);
  assert.deepEqual(stale.findings,['INCIDENT_WITNESS_HEAD_MISMATCH']);
  assert.equal(stale.mayRestore,false);assert.equal(stale.go13,'HOLD');
  assert.deepEqual(await witness.latest(),{sequence:2,digest:fresh});
  await assert.rejects(remote.query(
    'UPDATE palaco_incident_witness.heads SET sequence=1 WHERE namespace=$1',
    [namespace]),err=>err.code==='23514');
  assert.deepEqual(await witness.latest(),{sequence:2,digest:fresh});
 }finally{
  if(primary)await primary.end().catch(()=>{});
  if(remote)await remote.end().catch(()=>{});
  await admin.end().catch(()=>{});
 }
});
