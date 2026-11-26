'use strict';

// LIVE PostgreSQL contract tests: opt-in, isolated CI database only.
// npm test skips this suite unless PALACO_TEST_POSTGRES=1.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createPostgresIndependentContinuity } =
  require('../distribution/postgres-independent-continuity');

const enabled = process.env.PALACO_TEST_POSTGRES === '1';

test('live PostgreSQL: monotonic floor, concurrent CAS and transaction rollback', {skip: !enabled}, async () => {
  const { Client } = require('pg');
  const admin = new Client({ connectionString: process.env.PALACO_TEST_DATABASE_URL });
  await admin.connect();
  const clients = [];
  const newClient = async () => {
    const client = new Client({ connectionString: process.env.PALACO_TEST_DATABASE_URL });
    await client.connect();
    clients.push(client);
    return client;
  };
  const signal = () => new AbortController().signal;
  try {
    const schema = fs.readFileSync(path.join(__dirname,
      '../distribution/sql/independent-floor-highwater-v2.6.sql'), 'utf8');
    await admin.query(schema);
    await admin.query('TRUNCATE palaco_continuity.floor_highwater');
    // Test-only administrative bootstrap, never used by runtime adapter.
    await admin.query(
      'INSERT INTO palaco_continuity.floor_highwater(namespace,epoch,minimum_last_seen_ms) VALUES ($1,$2,$3)',
      ['palaco.registry', 5, 1000]);

    const a = await newClient();
    const b = await newClient();
    const authority = client => createPostgresIndependentContinuity({
      namespace: 'palaco.registry',
      query: args => client.query(args)
    });
    const first = authority(a);
    const second = authority(b);

    assert.equal(await first.advance(6, 1100, signal()), true);
    assert.equal(await second.advance(5, 1200, signal()), false);
    assert.equal(await second.advance(7, 1099, signal()), false);

    // Independent adapter recreation reads the same database high watermark.
    const restarted = authority(b);
    assert.equal(await restarted.advance(7, 1200, signal()), true);

    // Lock a row deliberately; a second CAS must wait until COMMIT and
    // then reject a now-stale request rather than overwrite the newer state.
    await a.query('BEGIN');
    await a.query(
      'UPDATE palaco_continuity.floor_highwater SET epoch=$1,minimum_last_seen_ms=$2 WHERE namespace=$3',
      [10, 2000, 'palaco.registry']);
    const blocked = restarted.advance(9, 2500, signal());
    // Ensure the competing request is submitted before releasing the lock.
    await new Promise(resolve => setTimeout(resolve, 40));
    await a.query('COMMIT');
    assert.equal(await blocked, false);

    const persisted = await admin.query(
      'SELECT epoch,minimum_last_seen_ms FROM palaco_continuity.floor_highwater WHERE namespace=$1',
      ['palaco.registry']);
    assert.equal(persisted.rowCount, 1);
    assert.deepEqual(persisted.rows[0], {epoch: '10', minimum_last_seen_ms: '2000'});

    // PostgreSQL ROLLBACK must not persist an uncommitted increase.
    await a.query('BEGIN');
    await a.query(
      'UPDATE palaco_continuity.floor_highwater SET epoch=$1,minimum_last_seen_ms=$2 WHERE namespace=$3',
      [11, 3000, 'palaco.registry']);
    await a.query('ROLLBACK');
    assert.equal(await restarted.advance(10, 2000, signal()), true);

    // Missing namespace cannot be created by the runtime UPDATE contract.
    const missing = createPostgresIndependentContinuity({
      namespace: 'other.registry', query: args => b.query(args)
    });
    assert.equal(await missing.advance(20, 9000, signal()), false);
    const count = await admin.query(
      'SELECT count(*)::integer AS n FROM palaco_continuity.floor_highwater');
    assert.equal(count.rows[0].n, 1);
  } finally {
    for (const c of clients) await c.end().catch(() => {});
    await admin.end().catch(() => {});
  }
});
