'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {generateKeyPairSync,sign}=require('node:crypto');
const {DatabaseSync}=require('node:sqlite');
const {initializeDurableChallengeSchema,createDurableChallengeRegistry}=
  require('../distribution/durable-challenge-registry');
const {clockFloorPayload}=require('../distribution/signed-clock-floor');
const {checkpointPayload}=require('../distribution/continuity-checkpoint');
const {createCheckpointExecutionGate}=require('../distribution/checkpoint-execution-gate');
const {createPostgresIndependentContinuity}=
  require('../distribution/postgres-independent-continuity');
const {createCheckpointGuardedChallengeRegistry}=
  require('../distribution/prefetched-signed-challenge-registry');

test('real PostgreSQL: strict issue and consume blocked on restored witness', {
 skip:process.env.PALACO_TEST_POSTGRES!=='1'
},async()=>{
 const {Client}=require('pg');
 const pg=new Client({connectionString:process.env.PALACO_TEST_DATABASE_URL});
 await pg.connect();
 const sqlite=new DatabaseSync(':memory:');
 try {
  await pg.query(fs.readFileSync(path.join(__dirname,
    '../distribution/sql/independent-floor-highwater-v2.6.sql'),'utf8'));
  await pg.query('TRUNCATE palaco_continuity.floor_highwater');
  await pg.query(
    'INSERT INTO palaco_continuity.floor_highwater(namespace,epoch,minimum_last_seen_ms) VALUES($1,$2,$3)',
    ['palaco.registry',5,1000]);
  initializeDurableChallengeSchema(sqlite);
  const clock=()=>1000;
  assert.equal(createDurableChallengeRegistry(sqlite,{clock}).issue('palaco.one').issued,true);
  const count=()=>sqlite.prepare('SELECT COUNT(*) n FROM distribution_challenges').get().n;
  const key=generateKeyPairSync('ed25519');
  const ck=generateKeyPairSync('ed25519');
  const publicKey=(keyId,k)=>[{keyId,enabled:true,revoked:false,
    publicKeyPem:k.publicKey.export({type:'spki',format:'pem'})}];
  const floorAuthority={namespace:'palaco.registry',minimumEpoch:5,
    pinnedRoots:publicKey('floor',key),fetchSignedFloor:nonce=>{
      const floor={schemaVersion:'palaco.distribution.signed-clock-floor.v1',
        namespace:'palaco.registry',epoch:5,minimumLastSeenMs:1000,challenge:nonce};
      return {floor,endorsement:{algorithm:'Ed25519',keyId:'floor',
        signature:sign(null,clockFloorPayload(floor),key.privateKey).toString('base64')}};
    }};
  const independentContinuity=createPostgresIndependentContinuity({
    namespace:'palaco.registry',query:args=>pg.query(args)
  });
  let checkpointEpoch=5;
  let checkpointFloor=1000;
  const checkpointGate=createCheckpointExecutionGate({
    namespace:'palaco.registry',
    fetchCheckpoint:async nonce=>{
      const checkpoint={
        schemaVersion:'palaco.distribution.continuity-checkpoint.v1',
        namespace:'palaco.registry',sequence:11,epoch:checkpointEpoch,
        minimumLastSeenMs:checkpointFloor,challenge:nonce,
        previousDigest:'0'.repeat(64)
      };
      return {checkpoint,endorsement:{algorithm:'Ed25519',keyId:'checkpoint',
        signature:sign(null,checkpointPayload(checkpoint),ck.privateKey).toString('base64')}};
    },
    fetchIndependentAnchor:async nonce=>({
      namespace:'palaco.registry',challenge:nonce,pinnedRoots:publicKey('checkpoint',ck),
      minimumSequence:11,priorDigest:'0'.repeat(64),
      minimumEpoch:5,minimumLastSeenMs:1000
    }),
    query:args=>pg.query(args)
  });
  const r=createCheckpointGuardedChallengeRegistry(sqlite,{
    floorAuthority,independentContinuity,checkpointGate,clock
  });
  assert.equal((await r.issue('palaco.one')).issued,true);
  assert.equal(count(),2);
  // Database owner in disposable test environment simulates a rollback.
  await pg.query(
    'UPDATE palaco_continuity.floor_highwater SET epoch=$1,minimum_last_seen_ms=$2 WHERE namespace=$3',
    [4,900,'palaco.registry']);
  // Independent checkpoint still asserts epoch 5/floor 1000.
  assert.equal((await r.issue('palaco.one')).issued,false);
  assert.equal(count(),2);
  const token=(await sqlite.prepare('SELECT challenge_hash FROM distribution_challenges LIMIT 1').get()).challenge_hash;
  // Consume attempts are denied before reading/modifying SQLite challenge rows.
  const denied=await r.consume('palaco.one',token,null,null,[],0);
  assert.equal(denied.readiness,'BLOCKED');
  assert.equal(denied.authorization,'DENY');
  assert.equal(sqlite.prepare("SELECT COUNT(*) n FROM distribution_challenges WHERE status='consumed'").get().n,0);
 }finally{sqlite.close();await pg.end();}
});
