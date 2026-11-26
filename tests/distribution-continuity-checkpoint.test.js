'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {checkpointPayload,checkpointDigest,verifyContinuityCheckpoint}=
  require('../distribution/continuity-checkpoint');

const signer=generateKeyPairSync('ed25519');
const another=generateKeyPairSync('ed25519');
const roots=[{keyId:'independent-witness',enabled:true,revoked:false,
  publicKeyPem:signer.publicKey.export({type:'spki',format:'pem'})}];
const previousDigest='0'.repeat(64);
const challenge='a'.repeat(64);

function fixture(override={}) {
  const checkpoint={
    schemaVersion:'palaco.distribution.continuity-checkpoint.v1',
    namespace:'palaco.registry',sequence:11,epoch:7,
    minimumLastSeenMs:2000,previousDigest,challenge,...override
  };
  const endorsement={algorithm:'Ed25519',keyId:'independent-witness',
    signature:sign(null,checkpointPayload(checkpoint),signer.privateKey).toString('base64')};
  const options={namespace:'palaco.registry',challenge,pinnedRoots:roots,
    minimumSequence:11,priorDigest:previousDigest,
    minimumEpoch:6,minimumLastSeenMs:1500};
  return {checkpoint,endorsement,options};
}
function check(f) {return verifyContinuityCheckpoint(f.checkpoint,f.endorsement,f.options);}

test('fresh independently signed checkpoint verifies but never grants authority',()=>{
  const f=fixture();
  const result=check(f);
  assert.equal(result.readiness,'CHECKPOINT_VERIFIED');
  assert.equal(result.authorization,'DENY');
  assert.equal(result.go13,'HOLD');
  assert.equal(result.mayRestore,false);
  assert.equal(result.digest,checkpointDigest(f.checkpoint));
  assert.match(result.digest,/^[a-f0-9]{64}$/);
  assert.ok(Object.isFrozen(result));
});

test('signed historical checkpoint rejected by independently held sequence',()=>{
  const f=fixture({sequence:10});
  assert.equal(check(f).readiness,'BLOCKED');
  assert.equal(check(f).findings[0],'CHECKPOINT_ROLLBACK_OR_CHAIN_MISMATCH');
});

test('signed but rolled back clock floor or epoch is blocked',()=>{
  for(const changes of [{epoch:5},{minimumLastSeenMs:1499}]) {
    const f=fixture(changes);
    assert.equal(check(f).readiness,'BLOCKED');
  }
});

test('fresh nonce requirement prevents replay with an old challenge',()=>{
  const f=fixture();
  f.options.challenge='b'.repeat(64);
  assert.equal(check(f).readiness,'BLOCKED');
});

test('signature cannot be reused after data modification',()=>{
  const f=fixture();
  f.checkpoint.minimumLastSeenMs=5000;
  assert.equal(check(f).findings[0],'CHECKPOINT_SIGNATURE_INVALID');
});

test('distinct signing key cannot impersonate pinned root',()=>{
  const f=fixture();
  f.endorsement.signature=sign(null,checkpointPayload(f.checkpoint),
    another.privateKey).toString('base64');
  assert.equal(check(f).readiness,'BLOCKED');
});

test('revoked root, duplicate key IDs and missing independent anchor deny',()=>{
  const f=fixture();
  f.options.pinnedRoots=[{...roots[0],revoked:true}];
  assert.equal(check(f).readiness,'BLOCKED');
  f.options.pinnedRoots=[...roots,...roots];
  assert.equal(check(f).readiness,'BLOCKED');
  f.options.pinnedRoots=roots;
  delete f.options.priorDigest;
  assert.equal(check(f).findings[0],'CHECKPOINT_ANCHOR_MISSING');
});

test('chain predecessor digest is cryptographically bound',()=>{
  const f=fixture({previousDigest:'1'.repeat(64)});
  assert.equal(check(f).findings[0],'CHECKPOINT_ROLLBACK_OR_CHAIN_MISMATCH');
  assert.notEqual(checkpointDigest(f.checkpoint),checkpointDigest(fixture().checkpoint));
});

test('malformed payload cannot be hashed or verified',()=>{
  const f=fixture();
  f.checkpoint.sequence=0;
  assert.equal(checkpointPayload(f.checkpoint),null);
  assert.equal(checkpointDigest(f.checkpoint),null);
  assert.equal(check(f).readiness,'BLOCKED');
});
