'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {DatabaseSync}=require('node:sqlite');
const {initializeDurableChallengeSchema,createDurableChallengeRegistry,
createAuditedDurableChallengeRegistry}=require('../distribution/durable-challenge-registry');
function setup(){
 const db=new DatabaseSync(':memory:');initializeDurableChallengeSchema(db);
 let time=1000;const clock=()=>time;
 const initial=createDurableChallengeRegistry(db,{clock});
 const token=initial.issue('palaco.one').challenge;
 assert.match(token,/^[a-f0-9]{64}$/);
 return {db,token,clock,setTime:v=>{time=v;}};
}
test('strict factory requires clock floor',()=>{
 const {db}=setup();try{assert.throws(()=>createAuditedDurableChallengeRegistry(db),RangeError);}
 finally{db.close();}
});
test('valid independent floor permits issuing a diagnostic challenge',()=>{
 const {db,clock}=setup();try{
  const r=createAuditedDurableChallengeRegistry(db,{minimumLastSeenMs:1000,clock});
  assert.equal(r.issue('palaco.one').issued,true);
 }finally{db.close();}
});
test('restored clock behind floor blocks BEFORE clock update',()=>{
 const {db,clock,setTime}=setup();try{
  setTime(2000);
  const r=createAuditedDurableChallengeRegistry(db,{minimumLastSeenMs:1500,clock});
  assert.equal(r.issue('palaco.one').issued,false);
  assert.equal(db.prepare('SELECT last_seen_ms FROM distribution_challenge_clock').get().last_seen_ms,1000);
 }finally{db.close();}
});
test('missing persisted clock blocks instead of silently bootstrap',()=>{
 const {db,clock}=setup();try{
  db.exec('DELETE FROM distribution_challenge_clock');
  const r=createAuditedDurableChallengeRegistry(db,{minimumLastSeenMs:0,clock});
  assert.equal(r.issue('palaco.one').issued,false);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM distribution_challenge_clock').get().n,0);
 }finally{db.close();}
});
test('corrupt registry metadata blocks issue without mutation',()=>{
 const {db,clock}=setup();try{
  db.exec("UPDATE distribution_challenges SET namespace='***'");
  const r=createAuditedDurableChallengeRegistry(db,{minimumLastSeenMs:1000,clock});
  assert.equal(r.issue('palaco.one').issued,false);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM distribution_challenges').get().n,1);
 }finally{db.close();}
});
test('corrupt registry blocks consuming an outstanding token',()=>{
 const {db,token,clock}=setup();try{
  db.exec("UPDATE distribution_challenges SET status='tampered'");
  const r=createAuditedDurableChallengeRegistry(db,{minimumLastSeenMs:1000,clock});
  assert.equal(r.consume('palaco.one',token,null,null,[],0).readiness,'BLOCKED');
  assert.equal(db.prepare('SELECT status FROM distribution_challenges').get().status,'tampered');
 }finally{db.close();}
});
test('floor callback is checked anew at each transaction',()=>{
 const {db,clock,setTime}=setup();try{
  let floor=1000;
  const r=createAuditedDurableChallengeRegistry(db,{minimumLastSeenMs:()=>floor,clock});
  assert.equal(r.issue('palaco.one').issued,true);
  floor=2000;setTime(3000);
  assert.equal(r.issue('palaco.one').issued,false);
  assert.equal(db.prepare('SELECT last_seen_ms FROM distribution_challenge_clock').get().last_seen_ms,1000);
 }finally{db.close();}
});
test('row limit blocks further transactions',()=>{
 const {db,clock}=setup();try{
  const r=createAuditedDurableChallengeRegistry(db,{minimumLastSeenMs:1000,clock,maxRows:1});
  assert.equal(r.issue('palaco.one').issued,true);
  assert.equal(r.issue('palaco.one').issued,false);
 }finally{db.close();}
});
