'use strict';

// Two-phase isolated PostgreSQL CI test. GitHub Actions forcibly stops and
// starts the TEMPORARY database container between the two invocations.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createPostgresIndependentContinuity } =
  require('../distribution/postgres-independent-continuity');

const enabled = process.env.PALACO_TEST_POSTGRES === '1';
const phase = process.env.PALACO_TEST_PHASE;

test('PostgreSQL recovery after abrupt isolated database restart',
  { skip: !enabled || !['prepare', 'verify'].includes(phase) }, async () => {
    const { Client } = require('pg');
    const client = new Client({connectionString:process.env.PALACO_TEST_DATABASE_URL});
    await client.connect();
    try {
      const runtime = createPostgresIndependentContinuity({
        namespace:'palaco.registry',query:args=>client.query(args)
      });
      const signal = () => new AbortController().signal;
      if (phase === 'prepare') {
        const schema = fs.readFileSync(path.join(__dirname,
          '../distribution/sql/independent-floor-highwater-v2.6.sql'),'utf8');
        const guard = fs.readFileSync(path.join(__dirname,
          '../distribution/sql/independent-floor-guard-v2.8.sql'),'utf8');
        await client.query(schema);
        await client.query(guard);
        await client.query('TRUNCATE palaco_continuity.floor_highwater');
        await client.query(
          'INSERT INTO palaco_continuity.floor_highwater(namespace,epoch,minimum_last_seen_ms) VALUES($1,$2,$3)',
          ['palaco.registry',20,4000]);
        assert.equal(await runtime.advance(21,4500,signal()),true);
        const saved = await client.query(
          'SELECT epoch,minimum_last_seen_ms FROM palaco_continuity.floor_highwater WHERE namespace=$1',
          ['palaco.registry']);
        assert.deepEqual(saved.rows[0],{epoch:'21',minimum_last_seen_ms:'4500'});
      } else {
        // This invocation runs ONLY AFTER GitHub Actions forcibly KILLs then
        // restarts PostgreSQL. The prior committed floor must remain durable.
        const saved = await client.query(
          'SELECT epoch,minimum_last_seen_ms FROM palaco_continuity.floor_highwater WHERE namespace=$1',
          ['palaco.registry']);
        assert.equal(saved.rowCount,1);
        assert.deepEqual(saved.rows[0],{epoch:'21',minimum_last_seen_ms:'4500'});
        assert.equal(await runtime.advance(20,4600,signal()),false);
        assert.equal(await runtime.advance(22,4499,signal()),false);
        assert.equal(await runtime.advance(22,4700,signal()),true);
        await assert.rejects(
          client.query('UPDATE palaco_continuity.floor_highwater SET epoch=$1 WHERE namespace=$2',
            [20,'palaco.registry']),
          error=>error.code==='23514');
        const final = await client.query(
          'SELECT epoch,minimum_last_seen_ms FROM palaco_continuity.floor_highwater WHERE namespace=$1',
          ['palaco.registry']);
        assert.deepEqual(final.rows[0],{epoch:'22',minimum_last_seen_ms:'4700'});
      }
    } finally { await client.end(); }
});
