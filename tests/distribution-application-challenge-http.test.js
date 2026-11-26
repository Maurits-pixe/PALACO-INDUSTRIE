'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const { dispatchDistributionHttp }=require('../distribution/application-challenge-http');

const ISSUE='/api/distribution/challenges/issue';
const CONSUME='/api/distribution/challenges/consume';
const valid={method:'POST',path:ISSUE,authenticated:true,csrfValid:true,
  ingress:null,readBody:async()=>({namespace:'palaco.one'})};

test('unauthenticated requests deny before body read or database admission',async()=>{
 let reads=0;
 const response=await dispatchDistributionHttp({...valid,authenticated:false,
  readBody:async()=>{reads++;throw Error('must not read');}});
 assert.equal(response.status,401);
 assert.equal(response.payload.authorization,'DENY');
 assert.equal(response.payload.go13,'HOLD');
 assert.equal(reads,0);
});
test('missing CSRF denies before reading the request body',async()=>{
 let reads=0;
 const response=await dispatchDistributionHttp({...valid,csrfValid:false,
  readBody:async()=>{reads++;return {};}});
 assert.equal(response.status,403);
 assert.equal(response.payload.error,'CSRF_REQUIRED');
 assert.equal(reads,0);
});
test('missing independent server trust disables issue and consume',async()=>{
 for(const path of [ISSUE,CONSUME]){
  const response=await dispatchDistributionHttp({...valid,path});
  assert.equal(response.status,503);
  assert.equal(response.payload.error,'DISTRIBUTION_TRUST_NOT_CONFIGURED');
  assert.equal(response.payload.authorization,'DENY');
  assert.equal(response.payload.go13,'HOLD');
  assert.equal(response.payload.mayPublish,false);
 }
});
test('no alternate paths, methods or bypass query strings are admitted',async()=>{
 for(const request of [
  {...valid,path:'/api/distribution/challenges/issue/'},
  {...valid,path:'/api/distribution/challenges/issue?bypass=true'},
  {...valid,path:'/api/distribution/legacy/issue'},
  {...valid,path:'/api/distribution/challenges/approve'},
  {...valid,method:'GET'}
 ]){
  const response=await dispatchDistributionHttp(request);
  assert.ok([404,405].includes(response.status));
  assert.equal(response.payload.authorization,'DENY');
 }
});
test('unbranded fake ingress cannot bypass disabled trust state',async()=>{
 let called=0;
 const fake={dispatch:async()=>{called++;return {issued:true};}};
 const response=await dispatchDistributionHttp({...valid,ingress:fake});
 assert.equal(response.status,503);
 assert.equal(called,0);
});
test('non-distribution path is not interpreted as distribution command',async()=>{
 const response=await dispatchDistributionHttp({...valid,path:'/api/health'});
 assert.equal(response.status,404);
});
