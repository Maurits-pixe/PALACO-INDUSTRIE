'use strict';

// Disposable CI experiment: restored SQLite snapshot versus an independent
// PostgreSQL continuity high-watermark. No production database is accessed.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { generateKeyPairSync, sign } = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const { createDurableChallengeRegistry, initializeDurableChallengeSchema } =
  require('../distribution/durable-challenge-registry');
const { clockFloorPayload } = require('../distribution/signed-clock-floor');
const { createPostgresIndependentContinuity } =
  require('../distribution/postgres-independent-continuity');
const { createIndependentlyGuardedChallengeRegistry } =
  require('../distribution/prefetched-signed-challenge-registry');

const enabled = process.env.PALACO_TEST_POSTGRES === '1';

test('restored SQLite snapshot cannot bypass independently advanced PostgreSQL floor',
  { skip: !enabled }, async () => {
    const { Client } = require('pg');
    const pg = new Client({ connectionString: process.env.PALACO_TEST_DATABASE_URL });
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'palaco-rollback-'));
    const dbFile = path.join(temp, 'challenge.sqlite');
    const backupFile = path.join(temp, 'older-snapshot.sqlite');
    let db;
    try {
      await pg.connect();
      const schema = fs.readFileSync(path.join(__dirname,
        '../distribution/sql/independent-floor-highwater-v2.6.sql'), 'utf8');
      await pg.query(schema);
      await pg.query('TRUNCATE palaco_continuity.floor_highwater');
      // Administrative initialization exists only in this throwaway CI database.
      await pg.query(
        'INSERT INTO palaco_continuity.floor_highwater(namespace,epoch,minimum_last_seen_ms) VALUES($1,$2,$3)',
        ['palaco.registry', 5, 1000]);

      const keys = generateKeyPairSync('ed25519');
      const roots = [{
        keyId: 'test-floor-root', enabled: true, revoked: false,
        publicKeyPem: keys.publicKey.export({type:'spki',format:'pem'})
      }];
      let floor = 1000;
      let epoch = 5;
      let now = 1000;
      const clock = () => now;
      const independent = createPostgresIndependentContinuity({
        namespace: 'palaco.registry', query: request => pg.query(request)
      });
      const fetchSignedFloor = challenge => {
        const statement = {
          schemaVersion: 'palaco.distribution.signed-clock-floor.v1',
          namespace: 'palaco.registry', epoch,
          minimumLastSeenMs: floor, challenge
        };
        return {
          floor: statement,
          endorsement: {
            algorithm:'Ed25519', keyId:'test-floor-root',
            signature: sign(null, clockFloorPayload(statement), keys.privateKey)
              .toString('base64')
          }
        };
      };
      const guarded = database => createIndependentlyGuardedChallengeRegistry(
        database, {
          floorAuthority: {
            namespace:'palaco.registry', fetchSignedFloor,
            pinnedRoots:roots, minimumEpoch:5
          },
          independentContinuity: independent, clock
        }
      );
      const queryClock = database =>
        database.prepare('SELECT last_seen_ms FROM distribution_challenge_clock WHERE singleton=1')
          .get().last_seen_ms;
      const count = database =>
        database.prepare('SELECT COUNT(*) AS n FROM distribution_challenges').get().n;

      // Snapshot from a valid, older state.
      db = new DatabaseSync(dbFile);
      initializeDurableChallengeSchema(db);
      const oldToken = createDurableChallengeRegistry(db, {clock}).issue('palaco.one').challenge;
      assert.match(oldToken,/^[0-9a-f]{64}$/);
      assert.equal(queryClock(db),1000);
      db.close(); db = null;
      fs.copyFileSync(dbFile, backupFile);

      // Both independent PostgreSQL and SQLite advance beyond the backup.
      db = new DatabaseSync(dbFile);
      now = 2000;
      assert.equal((await guarded(db).issue('palaco.one')).issued,true);
      assert.equal(queryClock(db),2000);
      now = 3000;
      floor = 2000;
      epoch = 6;
      assert.equal((await guarded(db).issue('palaco.one')).issued,true);
      assert.equal(queryClock(db),3000);
      db.close(); db = null;

      const witness = await pg.query(
        'SELECT epoch,minimum_last_seen_ms FROM palaco_continuity.floor_highwater WHERE namespace=$1',
        ['palaco.registry']);
      assert.deepEqual(witness.rows[0],{epoch:'6',minimum_last_seen_ms:'2000'});

      // Restore ONLY SQLite from its older backup. The separate PostgreSQL
      // witness has NOT been restored and is still at epoch 6 / floor 2000.
      fs.copyFileSync(backupFile, dbFile);
      db = new DatabaseSync(dbFile);
      now = 4000;
      assert.equal(queryClock(db),1000);
      assert.equal(count(db),1);
      assert.equal((await guarded(db).issue('palaco.one')).issued,false);
      assert.equal(queryClock(db),1000);
      assert.equal(count(db),1);

      // A stale but properly signed floor is independently denied by
      // PostgreSQL, even with a fresh challenge nonce.
      floor = 1000;
      assert.equal((await guarded(db).issue('palaco.one')).issued,false);
      assert.equal(queryClock(db),1000);
      assert.equal(count(db),1);

      // Restored pending challenge must not be consumed while clock rollback
      // is unresolved. Even an invalid receipt cannot be processed.
      const result = await guarded(db).consume(
        'palaco.one', oldToken, null, null, [], 0);
      assert.equal(result.readiness,'BLOCKED');
      assert.equal(result.authorization,'DENY');
      assert.equal(result.go13,'HOLD');
      assert.equal(db.prepare("SELECT status FROM distribution_challenges LIMIT 1").get().status,
        'pending');
      assert.equal(queryClock(db),1000);

      const finalWitness = await pg.query(
        'SELECT epoch,minimum_last_seen_ms FROM palaco_continuity.floor_highwater WHERE namespace=$1',
        ['palaco.registry']);
      assert.deepEqual(finalWitness.rows[0],{epoch:'6',minimum_last_seen_ms:'2000'});
    } finally {
      if (db) db.close();
      await pg.end().catch(()=>{});
      fs.rmSync(temp,{recursive:true,force:true});
    }
  });
