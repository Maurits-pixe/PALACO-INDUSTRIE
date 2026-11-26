'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {DatabaseSync}=require('node:sqlite');
const {initializeDurableChallengeSchema,createDurableChallengeRegistry}=
  require('../distribution/durable-challenge-registry');
const {clockFloorPayload}=require('../distribution/signed-clock-floor');
const {checkpointPayload}=require('../distribution/continuity-checkpoint');
const {createIndependentContinuityAuthority}=
  require('../distribution/independent-continuity-authority');
const {createCheckpointExecutionGate}=
  require('../distribution/checkpoint-execution-gate');
const {createCheckpointGuardedChallengeRegistry}=
  require('../distribution/prefetched-signed-challenge-registry');

const floorKey=generateKeyPairSync('ed25519');
const cpKey=generateKeyPairSync('ed25519');
const root=(id,key)=>[{keyId:id,enabled:true,revoked:false,
  publicKeyPem:key.publicKey.export({type:'spki',format:'pem'})}];

function fixture(overrides={}) {
 const db=new DatabaseSync(':memory:');
 initializeDurableChallengeSchema(db);
 const clock=()=>1000;
 assert.equal(createDurableChallengeRegistry(db,{clock}).issue('palaco.one').issued,true);
 let checkpointCalls=0;
 const floorAuthority={namespace:'palaco.registry',minimumEpoch:5,
  pinnedRoots:root('floor',floorKey),fetchSignedFloor:nonce=>{
   const floor={schemaVersion:'palaco.distribution.signed-clock-floor.v1',
    namespace:'palaco.registry',epoch:5,minimumLastSeenMs:1000,challenge:nonce};
   return {floor,endorsement:{algorithm:'Ed25519',keyId:'floor',
    signature:sign(null,clockFloorPayload(floor),floorKey.privateKey).toString('base64')}};
  }};
 const independentContinuity=createIndependentContinuityAuthority({
  namespace:'palaco.registry',compareAndAdvance:async()=>true
 });
 const checkpointGate=createCheckpointExecutionGate({
  namespace:'palaco.registry',
  fetchCheckpoint:async challenge=>{
   checkpointCalls++;
   const checkpoint={schemaVersion:'palaco.distribution.continuity-checkpoint.v1',
    namespace:'palaco.registry',sequence:11,epoch:5,minimumLastSeenMs:1000,
    previousDigest:'0'.repeat(64),challenge};
   return {checkpoint,endorsement:{algorithm:'Ed25519',keyId:'checkpoint',
    signature:sign(null,checkpointPayload(checkpoint),cpKey.privateKey).toString('base64')}};
  },
  fetchIndependentAnchor:async challenge=>({
   namespace:'palaco.registry',challenge,pinnedRoots:root('checkpoint',cpKey),
   minimumSequence:11,priorDigest:'0'.repeat(64),
   minimumEpoch:5,minimumLastSeenMs:1000
  }),
  query:async()=>({rowCount:1,rows:[{epoch:'5',minimum_last_seen_ms:'1000'}]})
 });
 const options={floorAuthority,independentContinuity,checkpointGate,clock,
  fetchTimeoutMs:70,maxProofAgeMs:1000,...overrides};
 return {db,options,checkpointCalls:()=>checkpointCalls,
  count:()=>db.prepare('SELECT COUNT(*) n FROM distribution_challenges').get().n};
}

test('strict checkpoint path requires both authenticated gates',()=>{
 const f=fixture();
 try {
  assert.throws(()=>createCheckpointGuardedChallengeRegistry(f.db,{
   ...f.options,checkpointGate:null
  }),TypeError);
  assert.throws(()=>createCheckpointGuardedChallengeRegistry(f.db,{
   ...f.options,independentContinuity:null
  }),TypeError);
  assert.throws(()=>createCheckpointGuardedChallengeRegistry(f.db,{
   ...f.options,checkpointGate:{namespace:'palaco.registry',verify:async()=>true}
  }),TypeError);
 }finally{f.db.close();}
});

test('valid checkpoint authorizes only challenge mechanics, never release',async()=>{
 const f=fixture();
 try {
  const registry=createCheckpointGuardedChallengeRegistry(f.db,f.options);
  const issued=await registry.issue('palaco.one');
  assert.equal(issued.issued,true);
  assert.equal(f.checkpointCalls(),1);
  // Invalid receipt still fails closed, and a separately verified checkpoint
  // must have been fetched for the consume attempt.
  const result=await registry.consume('palaco.one',issued.challenge,null,null,[],0);
  assert.equal(result.authorization,'DENY');
  assert.equal(result.go13,'HOLD');
  assert.equal(f.checkpointCalls(),2);
 }finally{f.db.close();}
});

test('tampered signed checkpoint denies issue without SQLite mutation',async()=>{
 const f=fixture();
 try {
  const original=f.options.checkpointGate;
  const gate=createCheckpointExecutionGate({
   namespace:'palaco.registry',
   fetchCheckpoint:async nonce=>{
    const cp={schemaVersion:'palaco.distribution.continuity-checkpoint.v1',
     namespace:'palaco.registry',sequence:11,epoch:5,minimumLastSeenMs:1000,
     challenge:nonce,previousDigest:'0'.repeat(64)};
    const signature=sign(null,checkpointPayload(cp),cpKey.privateKey).toString('base64');
    cp.epoch=6;
    return {checkpoint:cp,endorsement:{algorithm:'Ed25519',keyId:'checkpoint',signature}};
   },
   fetchIndependentAnchor:async challenge=>({
    namespace:'palaco.registry',challenge,pinnedRoots:root('checkpoint',cpKey),
    minimumSequence:11,priorDigest:'0'.repeat(64),
    minimumEpoch:5,minimumLastSeenMs:1000
   }),
   query:async()=>({rowCount:1,rows:[{epoch:'5',minimum_last_seen_ms:'1000'}]})
  });
  const r=createCheckpointGuardedChallengeRegistry(f.db,{
   ...f.options,checkpointGate:gate
  });
  assert.equal((await r.issue('palaco.one')).issued,false);
  assert.equal(f.count(),1);
  assert.ok(original);
 }finally{f.db.close();}
});

test('unavailable checkpoint witness denies without mutation',async()=>{
 const f=fixture();
 try {
  const gate=createCheckpointExecutionGate({
   namespace:'palaco.registry',
   fetchCheckpoint:async()=>{throw Error('unavailable');},
   fetchIndependentAnchor:async()=>{throw Error('unavailable');},
   query:async()=>{throw Error('unavailable');}
  });
  const r=createCheckpointGuardedChallengeRegistry(f.db,{
   ...f.options,checkpointGate:gate
  });
  assert.equal((await r.issue('palaco.one')).issued,false);
  assert.equal(f.count(),1);
 }finally{f.db.close();}
});

test('checkpoint gate enforces timeout while retaining underlying permit',async()=>{
 const {createSharedAuthorityAdmission}=require('../distribution/shared-authority-admission');
 const f=fixture();
 try {
  const sharedAdmission=createSharedAuthorityAdmission({maxInFlight:1});
  let settle;
  const stalled=new Promise(resolve=>{settle=resolve;});
  const gate=createCheckpointExecutionGate({
   namespace:'palaco.registry',
   fetchCheckpoint:()=>stalled,
   fetchIndependentAnchor:async()=>({}),
   query:async()=>({rowCount:0,rows:[]})
  });
  const r=createCheckpointGuardedChallengeRegistry(f.db,{
   ...f.options,checkpointGate:gate,sharedAdmission,fetchTimeoutMs:10
  });
  assert.equal((await r.issue('palaco.one')).issued,false);
  assert.equal(sharedAdmission.snapshot().active,1);
  assert.equal((await r.issue('palaco.one')).reason,'SHARED_AUTHORITY_CAPACITY_REACHED');
  settle(null);
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(sharedAdmission.snapshot().active,0);
  assert.equal(f.count(),1);
 }finally{f.db.close();}
});
