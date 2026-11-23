'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {DatabaseSync}=require('node:sqlite');
const {generateKeyPairSync,sign}=require('node:crypto');
const {initializeDurableChallengeSchema,createDurableChallengeRegistry}=
 require('../distribution/durable-challenge-registry');
const {createApplicationChallengeIngress,isApplicationChallengeIngress}=
 require('../distribution/application-challenge-ingress');
const {createIndependentContinuityAuthority}=
 require('../distribution/independent-continuity-authority');
const {createCheckpointExecutionGate}=
 require('../distribution/checkpoint-execution-gate');
const {clockFloorPayload}=require('../distribution/signed-clock-floor');
const {checkpointPayload}=require('../distribution/continuity-checkpoint');

const signer=generateKeyPairSync('ed25519');
const witness=generateKeyPairSync('ed25519');
const roots=(id,keys)=>[{keyId:id,enabled:true,revoked:false,
 publicKeyPem:keys.publicKey.export({type:'spki',format:'pem'})}];

function fixture(mode='valid') {
 const db=new DatabaseSync(':memory:');
 initializeDurableChallengeSchema(db);
 const clock=()=>1000;
 assert.equal(createDurableChallengeRegistry(db,{clock}).issue('palaco.one').issued,true);
 let counts={signed:0,checkpoint:0};
 const independentContinuity=createIndependentContinuityAuthority({
  namespace:'palaco.registry',compareAndAdvance:async()=>mode!=='independent-fails'
 });
 const floorAuthority={namespace:'palaco.registry',minimumEpoch:5,
  pinnedRoots:roots('floor',signer),fetchSignedFloor:nonce=>{
   counts.signed++;
   const floor={schemaVersion:'palaco.distribution.signed-clock-floor.v1',
    namespace:'palaco.registry',epoch:5,minimumLastSeenMs:1000,challenge:nonce};
   return {floor,endorsement:{algorithm:'Ed25519',keyId:'floor',
    signature:sign(null,clockFloorPayload(floor),signer.privateKey).toString('base64')}};
  }};
 const checkpointGate=createCheckpointExecutionGate({
  namespace:'palaco.registry',
  fetchCheckpoint:async nonce=>{
   counts.checkpoint++;
   if(mode==='missing-proof') throw Error('offline');
   const checkpoint={schemaVersion:'palaco.distribution.continuity-checkpoint.v1',
    namespace:'palaco.registry',sequence:11,epoch:5,minimumLastSeenMs:1000,
    previousDigest:'0'.repeat(64),challenge:nonce};
   return {checkpoint,endorsement:{algorithm:'Ed25519',keyId:'witness',
    signature:sign(null,checkpointPayload(checkpoint),witness.privateKey).toString('base64')}};
  },
  fetchIndependentAnchor:async nonce=>({
   namespace:'palaco.registry',challenge:nonce,pinnedRoots:roots('witness',witness),
   minimumSequence:11,priorDigest:'0'.repeat(64),
   minimumEpoch:5,minimumLastSeenMs:1000
  }),
  query:async()=>({rowCount:1,rows:[{epoch:'5',minimum_last_seen_ms:'1000'}]})
 });
 const options={clock,floorAuthority,checkpointGate,independentContinuity,
  pinnedReceiptRoots:roots('receipt',witness),minimumReceiptSequence:1};
 return {db,options,counts,count:()=>db.prepare('SELECT COUNT(*) n FROM distribution_challenges').get().n};
}
const issue={method:'POST',path:'/api/distribution/challenges/issue',body:{namespace:'palaco.one'}};
const consume={method:'POST',path:'/api/distribution/challenges/consume',
 body:{namespace:'palaco.one',challenge:'0'.repeat(64),state:null,endorsement:null}};

test('ingress cannot be constructed without real independent signed gates',()=>{
 const f=fixture();try{
  assert.throws(()=>createApplicationChallengeIngress(f.db,{
   ...f.options,checkpointGate:null}),TypeError);
  assert.throws(()=>createApplicationChallengeIngress(f.db,{
   ...f.options,independentContinuity:null}),TypeError);
  assert.equal(isApplicationChallengeIngress({dispatch:async()=>({})}),false);
 }finally{f.db.close();}
});
test('only canonical issue and consume routes are accepted',async()=>{
 const f=fixture();try{
  const ingress=createApplicationChallengeIngress(f.db,f.options);
  assert.equal(isApplicationChallengeIngress(ingress),true);
  for(const request of [
   {...issue,method:'GET'}, {...issue,path:'/api/legacy/challenge/issue'},
   {...issue,path:'/api/distribution/challenges/issue/'},
   {...issue,body:{namespace:'palaco.one',untrustedRegistry:true}},
   {...consume,body:{...consume.body,bypassCheckpoint:true}},
   {method:'POST',path:'/api/distribution/challenges/release',body:{}},
   {method:'POST',path:'/api/distribution/challenges/issue',body:null}
  ]){
   const result=await ingress.dispatch(request);
   assert.equal(result.authorization,'DENY');
   assert.equal(result.readiness,'BLOCKED');
  }
  assert.equal(f.count(),1);
  assert.equal(f.counts.signed,0);
  assert.equal(f.counts.checkpoint,0);
 }finally{f.db.close();}
});
test('valid challenge mechanics never imply release; each call independently checks',async()=>{
 const f=fixture();try{
  const ingress=createApplicationChallengeIngress(f.db,f.options);
  const result=await ingress.dispatch(issue);
  assert.equal(result.issued,true);
  assert.equal(result.authorization,'DENY');
  assert.equal(result.go13,'HOLD');
  assert.equal(result.mayPublish,false);
  assert.equal(f.count(),2);
  assert.equal(f.counts.signed,1);
  assert.equal(f.counts.checkpoint,1);
  const after=await ingress.dispatch({...consume,
   body:{...consume.body,challenge:result.challenge}});
  assert.equal(after.authorization,'DENY');
  assert.equal(after.go13,'HOLD');
  assert.equal(after.mayPublish,false);
  assert.equal(f.counts.signed,2);
  assert.equal(f.counts.checkpoint,2);
 }finally{f.db.close();}
});
test('failed independent checkpoint cannot issue or consume or mutate challenges',async()=>{
 const f=fixture('missing-proof');try{
  const ingress=createApplicationChallengeIngress(f.db,f.options);
  assert.equal((await ingress.dispatch(issue)).readiness,'BLOCKED');
  assert.equal((await ingress.dispatch(consume)).readiness,'BLOCKED');
  assert.equal(f.count(),1);
  assert.equal(f.db.prepare("SELECT COUNT(*) n FROM distribution_challenges WHERE status='consumed'").get().n,0);
  assert.equal(f.counts.checkpoint,2);
 }finally{f.db.close();}
});
test('failed independent continuity denies via the only ingress',async()=>{
 const f=fixture('independent-fails');try{
  const ingress=createApplicationChallengeIngress(f.db,f.options);
  assert.equal((await ingress.dispatch(issue)).readiness,'BLOCKED');
  assert.equal(f.count(),1);
 }finally{f.db.close();}
});
test('closed ingress rejects all future operations',async()=>{
 const f=fixture();try{
  const ingress=createApplicationChallengeIngress(f.db,f.options);
  ingress.close();
  assert.equal((await ingress.dispatch(issue)).findings[0],'CHALLENGE_INGRESS_CLOSED');
  assert.equal(f.count(),1);
 }finally{f.db.close();}
});
