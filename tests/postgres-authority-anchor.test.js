'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {generateKeyPairSync,sign}=require('node:crypto');
const {authorityDigest,rotationPayload}=
  require('../distribution/roster-authority-rotation');
const {createAuthorityAnchorStore,verifyAnchoredAuthorityRotation}=
  require('../distribution/postgres-authority-anchor');

const keys=Array.from({length:4},()=>generateKeyPairSync('ed25519'));
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
function fixture(){
 const previous={schemaVersion:'palaco.distribution.roster-authority.v1',
  namespace:'palaco.registry',revision:10,previousDigest:'0'.repeat(64),
  keys:[{keyId:'authority-a',status:'active',publicKeyPem:pem(keys[0])}]};
 const next={...previous,revision:11,previousDigest:authorityDigest(previous),keys:[
  {keyId:'authority-a',status:'revoked',publicKeyPem:pem(keys[0])},
  {keyId:'authority-z',status:'active',publicKeyPem:pem(keys[1])}
 ]};
 const record={schemaVersion:'palaco.distribution.roster-authority-rotation.v1',
  namespace:'palaco.registry',revision:11,previousDigest:authorityDigest(previous),
  nextDigest:authorityDigest(next),oldKeyId:'authority-a',newKeyId:'authority-z'};
 const payload=rotationPayload(record);
 const endorsement=(key,keyId)=>({algorithm:'Ed25519',keyId,
  signature:sign(null,payload,key.privateKey).toString('base64')});
 const endorsements={oldAuthority:endorsement(keys[0],'authority-a'),
  newAuthority:endorsement(keys[1],'authority-z'),
  reviewers:[endorsement(keys[2],'review-a'),endorsement(keys[3],'review-b')]};
 const reviewers=[
  {keyId:'review-a',reviewerId:'alice',enabled:true,revoked:false,
   publicKeyPem:pem(keys[2])},
  {keyId:'review-b',reviewerId:'bob',enabled:true,revoked:false,
   publicKeyPem:pem(keys[3])}
 ];
 return {previous,next,record,endorsements,reviewers};
}
test('no usable adapter without a named independent query provider',()=>{
 for(const args of [{}, {namespace:'palaco.registry'},
  {namespace:'bad namespace',query:async()=>({})}])
  assert.throws(()=>createAuthorityAnchorStore(args),TypeError);
});
test('unavailable, malformed or stale anchor rejects every rotation',async()=>{
 const f=fixture();
 for(const fake of [
  async()=>{throw Error('offline');},
  async()=>({rowCount:0,rows:[]}),
  async()=>({rowCount:1,rows:[{revision:'9',state_digest:authorityDigest(f.previous)}]}),
  async()=>({rowCount:1,rows:[{revision:'10',state_digest:'f'.repeat(64)}]}),
  async()=>({rowCount:1,rows:[{revision:'9999999999999999999999',
    state_digest:authorityDigest(f.previous)}]})
 ]){
  const store=createAuthorityAnchorStore({namespace:'palaco.registry',query:fake});
  const verified=await verifyAnchoredAuthorityRotation(store,f.previous,f.next,
    f.record,f.endorsements,f.reviewers);
  assert.equal(verified.readiness,'BLOCKED');
  assert.equal(verified.authorization,'DENY');
  assert.equal(verified.go13,'HOLD');
 }
});
test('independent anchor adapter refuses bad CAS values before network I/O',async()=>{
 let calls=0;
 const store=createAuthorityAnchorStore({namespace:'palaco.registry',
  query:async()=>{calls++;return {rowCount:0,rows:[]};}});
 assert.equal(await store.compareAndAdvance(10,'a'.repeat(64),12,'b'.repeat(64)),false);
 assert.equal(await store.compareAndAdvance(10,'a'.repeat(64),11,'a'.repeat(64)),false);
 assert.equal(await store.compareAndAdvance(-1,'a'.repeat(64),0,'b'.repeat(64)),false);
 assert.equal(calls,0);
});
test('trusted read-only proof does not advance or grant release authority',async()=>{
 const f=fixture(),queries=[];
 const store=createAuthorityAnchorStore({namespace:'palaco.registry',query:async request=>{
  queries.push(request);
  return {rowCount:1,rows:[{revision:'10',state_digest:authorityDigest(f.previous)}]};
 }});
 const proof=await verifyAnchoredAuthorityRotation(store,f.previous,f.next,
  f.record,f.endorsements,f.reviewers);
 assert.equal(proof.readiness,'ANCHOR_MATCH_VERIFIED_NON_AUTHORIZING');
 assert.equal(proof.authorization,'DENY');assert.equal(proof.go13,'HOLD');
 assert.equal(proof.mayAdvance,false);assert.equal(proof.mayRotate,false);
 assert.equal(queries.length,1);assert.match(queries[0].text,/^SELECT/);
});
test('disposable live PostgreSQL advances independently and rejects historical replay',
 {skip:process.env.PALACO_TEST_POSTGRES!=='1'},async()=>{
 const {Client}=require('pg');
 const pg=new Client({connectionString:process.env.PALACO_TEST_DATABASE_URL});
 await pg.connect();
 try{
  const schema=fs.readFileSync(path.join(__dirname,
   '../distribution/sql/authority-anchor-highwater-v3.9.sql'),'utf8');
  await pg.query(schema);
  await pg.query('TRUNCATE palaco_authority_anchor.latest');
  const f=fixture();
  const oldDigest=authorityDigest(f.previous);
  const newDigest=authorityDigest(f.next);
  await pg.query(
   'INSERT INTO palaco_authority_anchor.latest(namespace,revision,state_digest) VALUES($1,$2,$3)',
   ['palaco.registry',10,oldDigest]
  );
  const store=createAuthorityAnchorStore({namespace:'palaco.registry',
   query:request=>pg.query(request)});
  const proof=await verifyAnchoredAuthorityRotation(store,f.previous,f.next,
   f.record,f.endorsements,f.reviewers);
  assert.equal(proof.readiness,'ANCHOR_MATCH_VERIFIED_NON_AUTHORIZING');
  assert.equal(proof.authorization,'DENY');
  assert.equal(await store.compareAndAdvance(10,oldDigest,11,newDigest),true);
  assert.deepEqual(await store.latest(),{revision:11,digest:newDigest});
  assert.equal(await store.compareAndAdvance(10,oldDigest,11,newDigest),false);
  const replay=await verifyAnchoredAuthorityRotation(store,f.previous,f.next,
   f.record,f.endorsements,f.reviewers);
  assert.deepEqual(replay.findings,['AUTHORITY_INDEPENDENT_HEAD_MISMATCH']);
  const after=await store.latest();
  assert.deepEqual(after,{revision:11,digest:newDigest});
  await assert.rejects(pg.query(
   'UPDATE palaco_authority_anchor.latest SET revision=$1 WHERE namespace=$2',
   [10,'palaco.registry']),err=>err.code==='23514');
  assert.deepEqual(await store.latest(),after);
  // Verify a simulated restored old authority history is refused as stale.
  assert.equal((await verifyAnchoredAuthorityRotation(store,f.previous,f.next,
    f.record,f.endorsements,f.reviewers)).readiness,'BLOCKED');
 }finally{await pg.end();}
});
