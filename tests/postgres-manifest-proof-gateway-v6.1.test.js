'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {VERSION,createProofVerificationGateway}=
 require('../distribution/manifest-proof-gateway-v6.1');
test('PostgreSQL restricted append-only proof gateway audit persists denials and fails closed on outage',{
 skip:process.env.PALACO_TEST_POSTGRES!=='1'
},async()=>{
 const {Client}=require('pg');
 const base=new URL(process.env.PALACO_TEST_DATABASE_URL);
 const admin=new Client({connectionString:base.toString()});
 let db,writer;
 await admin.connect();
 try{
  const name='palaco_v61_gateway_ci';
  if(!(await admin.query('SELECT 1 FROM pg_database WHERE datname=$1',[name])).rowCount)
   await admin.query('CREATE DATABASE '+name);
  const target=new URL(base);target.pathname='/'+name;
  db=new Client({connectionString:target.toString()});await db.connect();
  const schema=fs.readFileSync(path.join(__dirname,
   '../distribution/sql/proof-verification-audit-v6.1.sql'),'utf8');
  await db.query(schema);
  const role='palaco_v61_audit_writer';
  await db.query("CREATE ROLE "+role+" LOGIN PASSWORD 'ci_only_v61'");
  await db.query('REVOKE ALL ON SCHEMA palaco_proof_verification_audit FROM PUBLIC');
  await db.query('REVOKE ALL ON palaco_proof_verification_audit.events FROM PUBLIC');
  await db.query('GRANT USAGE ON SCHEMA palaco_proof_verification_audit TO '+role);
  await db.query('GRANT INSERT,SELECT ON palaco_proof_verification_audit.events TO '+role);
  await db.query('GRANT USAGE,SELECT ON SEQUENCE palaco_proof_verification_audit.events_event_id_seq TO '+role);
  await db.query('ALTER TABLE palaco_proof_verification_audit.events ENABLE ROW LEVEL SECURITY');
  await db.query("CREATE POLICY audit_ci_insert ON palaco_proof_verification_audit.events FOR INSERT TO "+role+" WITH CHECK(namespace='palaco.v61ci')");
  await db.query("CREATE POLICY audit_ci_read ON palaco_proof_verification_audit.events FOR SELECT TO "+role+" USING(namespace='palaco.v61ci')");
  const restricted=new URL(target);
  restricted.username=role;restricted.password='ci_only_v61';
  writer=new Client({connectionString:restricted.toString()});
  await writer.connect();
  const namespace='palaco.v61ci';
  let verified=0;
  const verifier={namespace,
   verifyInclusion:async()=>{verified++;return {
    readiness:'INDEPENDENT_INCLUSION_VERIFIED_NON_AUTHORIZING',
    authorization:'DENY',go13:'HOLD',mayPublish:false};},
   verifyConsistency:async()=>({readiness:'BLOCKED'})};
  const insert=[
   'INSERT INTO palaco_proof_verification_audit.events',
   '(namespace,principal_id,request_id,request_digest,timestamp_ms,',
   'readiness,finding,authorization_status,go13_status)',
   'VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)'
  ].join(' ');
  let now=1000;
  const service=createProofVerificationGateway({
   namespace,verifier,clock:()=>now,principalId:'verifier-ci',
   maxPerWindow:2,auditAppend:async e=>{
    const written=await writer.query(insert,[e.namespace,e.principalId,
     e.requestId,e.requestDigest,e.timestampMs,e.readiness,e.finding,
     e.authorization,e.go13]);
    return written.rowCount===1;
   }
  });
  const request=id=>({
   schemaVersion:VERSION,requestId:id,namespace,
   kind:'inclusion',envelope:{proof:'synthetic-ci'}
  });
  assert.equal((await service.handle(request('request-0001'))).readiness,
   'PROOF_GATEWAY_VERIFIED_NON_AUTHORIZING');
  assert.deepEqual((await service.handle(request('request-0001'))).findings,
   ['PROOF_GATEWAY_REPLAY']);
  assert.deepEqual((await service.handle(request('request-0002'))).findings,
   ['PROOF_GATEWAY_RATE_LIMIT']);
  assert.equal(verified,1);
  const count=await writer.query(
   'SELECT readiness,authorization_status,go13_status FROM palaco_proof_verification_audit.events ORDER BY event_id'
  );
  assert.equal(count.rowCount,3);
  assert.deepEqual(count.rows.map(x=>x.readiness),[
   'PROOF_GATEWAY_VERIFIED_NON_AUTHORIZING','BLOCKED','BLOCKED']);
  assert.ok(count.rows.every(x=>x.authorization_status==='DENY'&&x.go13_status==='HOLD'));
  for(const sql of [
   'UPDATE palaco_proof_verification_audit.events SET authorization_status=$1',
   'DELETE FROM palaco_proof_verification_audit.events',
   'TRUNCATE palaco_proof_verification_audit.events',
   'ALTER TABLE palaco_proof_verification_audit.events DISABLE TRIGGER deny_proof_audit_change'
  ]){
   await assert.rejects(writer.query(sql,sql.includes('$1')?['ALLOW']:[]),
    e=>e.code==='42501');
  }
  await assert.rejects(db.query(
   'DELETE FROM palaco_proof_verification_audit.events'),e=>e.code==='23514');
  // A real database outage blocks a fresh request, even if verifier returns valid.
  await writer.end();writer=null;now=61000;
  assert.deepEqual((await service.handle(request('request-0003'))).findings,
   ['PROOF_GATEWAY_AUDIT_UNAVAILABLE']);
 }finally{
  if(writer)await writer.end().catch(()=>{});
  if(db)await db.end().catch(()=>{});
  await admin.end().catch(()=>{});
 }
});
