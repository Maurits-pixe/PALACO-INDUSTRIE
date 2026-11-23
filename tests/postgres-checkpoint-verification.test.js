'use strict';
// Uses a disposable PostgreSQL service in CI; no external signing service.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {generateKeyPairSync,sign}=require('node:crypto');
const {checkpointPayload,checkpointDigest}=
  require('../distribution/continuity-checkpoint');
const {verifyPostgresCheckpoint}=
  require('../distribution/postgres-checkpoint-verifier');

test('real PostgreSQL rollback is detected against an independently supplied signed anchor',
  {skip:process.env.PALACO_TEST_POSTGRES!=='1'},async()=>{
  const {Client}=require('pg');
  const db=new Client({connectionString:process.env.PALACO_TEST_DATABASE_URL});
  await db.connect();
  try{
    const schema=fs.readFileSync(path.join(__dirname,
      '../distribution/sql/independent-floor-highwater-v2.6.sql'),'utf8');
    await db.query(schema);
    await db.query('TRUNCATE palaco_continuity.floor_highwater');
    await db.query(
      'INSERT INTO palaco_continuity.floor_highwater(namespace,epoch,minimum_last_seen_ms) VALUES($1,$2,$3)',
      ['palaco.registry',8,2500]);
    const signer=generateKeyPairSync('ed25519');
    const roots=[{keyId:'external-witness',enabled:true,revoked:false,
      publicKeyPem:signer.publicKey.export({type:'spki',format:'pem'})}];
    const challenge='b'.repeat(64);
    const previousDigest='a'.repeat(64);
    const checkpoint={
      schemaVersion:'palaco.distribution.continuity-checkpoint.v1',
      namespace:'palaco.registry',sequence:42,epoch:8,
      minimumLastSeenMs:2500,previousDigest,challenge
    };
    const endorsement={algorithm:'Ed25519',keyId:'external-witness',
      signature:sign(null,checkpointPayload(checkpoint),signer.privateKey).toString('base64')};
    const externalAnchor={namespace:'palaco.registry',challenge,pinnedRoots:roots,
      minimumSequence:42,priorDigest:previousDigest,
      minimumEpoch:8,minimumLastSeenMs:2500};
    const verify=()=>verifyPostgresCheckpoint(args=>db.query(args),
      checkpoint,endorsement,externalAnchor);

    assert.equal((await verify()).readiness,'CHECKPOINT_VERIFIED');
    // Simulate a privileged rollback: the witness itself has been restored.
    // The independently held signed checkpoint and anchor have NOT changed.
    await db.query(
      'UPDATE palaco_continuity.floor_highwater SET epoch=$1,minimum_last_seen_ms=$2 WHERE namespace=$3',
      [7,2000,'palaco.registry']);
    const rollback=await verify();
    assert.equal(rollback.readiness,'BLOCKED');
    assert.equal(rollback.findings[0],'POSTGRES_CHECKPOINT_MISMATCH');

    // An older, correctly signed checkpoint is still rejected if its sequence
    // predates the separately held witness anchor.
    const older={...checkpoint,sequence:41,epoch:7,minimumLastSeenMs:2000};
    const oldEndorsement={...endorsement,
      signature:sign(null,checkpointPayload(older),signer.privateKey).toString('base64')};
    const rejected=await verifyPostgresCheckpoint(args=>db.query(args),
      older,oldEndorsement,externalAnchor);
    assert.equal(rejected.readiness,'BLOCKED');
    assert.equal(rejected.findings[0],'CHECKPOINT_ROLLBACK_OR_CHAIN_MISMATCH');
    assert.ok(checkpointDigest(checkpoint));
  }finally{await db.end();}
});
