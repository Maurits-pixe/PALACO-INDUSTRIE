'use strict';

// Test-only privilege separation in disposable PostgreSQL 17 CI service.
// NEVER create these roles/passwords outside the throwaway CI database.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {createPostgresIndependentContinuity}=
  require('../distribution/postgres-independent-continuity');

test('restricted runtime role cannot bootstrap, delete, alter or downgrade', {
  skip:process.env.PALACO_TEST_POSTGRES!=='1'
}, async()=>{
  const {Client}=require('pg');
  const admin=new Client({connectionString:process.env.PALACO_TEST_DATABASE_URL});
  await admin.connect();
  let runtime;
  try {
    await admin.query(fs.readFileSync(path.join(__dirname,
      '../distribution/sql/independent-floor-highwater-v2.6.sql'),'utf8'));
    await admin.query(fs.readFileSync(path.join(__dirname,
      '../distribution/sql/independent-floor-guard-v2.8.sql'),'utf8'));
    await admin.query('TRUNCATE palaco_continuity.floor_highwater');
    await admin.query(
      'INSERT INTO palaco_continuity.floor_highwater(namespace,epoch,minimum_last_seen_ms) VALUES ($1,$2,$3),($4,$5,$6)',
      ['palaco.registry',5,1000,'other.registry',5,1000]);

    await admin.query("CREATE ROLE palaco_runtime_ci LOGIN PASSWORD 'ci_runtime_only'");
    await admin.query('REVOKE ALL ON SCHEMA palaco_continuity FROM PUBLIC');
    await admin.query('REVOKE ALL ON palaco_continuity.floor_highwater FROM PUBLIC');
    await admin.query('GRANT USAGE ON SCHEMA palaco_continuity TO palaco_runtime_ci');
    await admin.query('GRANT SELECT(namespace,epoch,minimum_last_seen_ms), UPDATE(epoch,minimum_last_seen_ms) ON palaco_continuity.floor_highwater TO palaco_runtime_ci');
    await admin.query('ALTER TABLE palaco_continuity.floor_highwater ENABLE ROW LEVEL SECURITY');
    await admin.query("CREATE POLICY palaco_ci_select ON palaco_continuity.floor_highwater FOR SELECT TO palaco_runtime_ci USING (namespace = 'palaco.registry')");
    await admin.query("CREATE POLICY palaco_ci_update ON palaco_continuity.floor_highwater FOR UPDATE TO palaco_runtime_ci USING (namespace = 'palaco.registry') WITH CHECK (namespace = 'palaco.registry')");

    const url=new URL(process.env.PALACO_TEST_DATABASE_URL);
    url.username='palaco_runtime_ci';url.password='ci_runtime_only';
    runtime=new Client({connectionString:url.toString()});
    await runtime.connect();
    const adapter=createPostgresIndependentContinuity({
      namespace:'palaco.registry',query:args=>runtime.query(args)
    });
    const signal=()=>new AbortController().signal;
    assert.equal(await adapter.advance(6,1100,signal()),true);
    assert.equal(await adapter.advance(5,1101,signal()),false);

    const foreign=createPostgresIndependentContinuity({
      namespace:'other.registry',query:args=>runtime.query(args)
    });
    assert.equal(await foreign.advance(9,2000,signal()),false);
    const invisible=await runtime.query(
      'SELECT namespace FROM palaco_continuity.floor_highwater');
    assert.deepEqual(invisible.rows,[{namespace:'palaco.registry'}]);

    for(const sql of [
      "INSERT INTO palaco_continuity.floor_highwater(namespace,epoch,minimum_last_seen_ms) VALUES ('new.registry',1,1)",
      "DELETE FROM palaco_continuity.floor_highwater WHERE namespace='palaco.registry'",
      'TRUNCATE palaco_continuity.floor_highwater',
      'ALTER TABLE palaco_continuity.floor_highwater DISABLE TRIGGER reject_floor_regression'
    ]) {
      await assert.rejects(runtime.query(sql),error=>error.code==='42501');
    }
    await assert.rejects(runtime.query(
      "UPDATE palaco_continuity.floor_highwater SET epoch=4 WHERE namespace='palaco.registry'"),
      error=>error.code==='23514');
    const preserved=await admin.query(
      'SELECT epoch,minimum_last_seen_ms FROM palaco_continuity.floor_highwater WHERE namespace=$1',
      ['palaco.registry']);
    assert.deepEqual(preserved.rows[0],{epoch:'6',minimum_last_seen_ms:'1100'});
  }finally{
    if(runtime) await runtime.end().catch(()=>{});
    await admin.end().catch(()=>{});
  }
});
