'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createIndependentContinuityAuthority,isIndependentContinuityAuthority}=
  require('../distribution/independent-continuity-authority');

test('strict authority accepts only exact boolean true',async()=>{
  const accepted=createIndependentContinuityAuthority({
    namespace:'palaco.registry',compareAndAdvance:async()=>true
  });
  const rejected=createIndependentContinuityAuthority({
    namespace:'palaco.registry',compareAndAdvance:async()=>({accepted:true})
  });
  const signal=new AbortController().signal;
  assert.equal(await accepted.advance(5,1000,signal),true);
  assert.equal(await rejected.advance(5,1000,signal),false);
  assert.equal(isIndependentContinuityAuthority(accepted),true);
});
test('malformed epochs and floors fail without calling backend',async()=>{
  let called=0;
  const authority=createIndependentContinuityAuthority({
    namespace:'palaco.registry',compareAndAdvance:async()=>{called++;return true;}
  });
  const signal=new AbortController().signal;
  for(const [epoch,floor] of [[-1,1],[1,-1],[1,1.2],['1',1],[1,NaN]])
    assert.equal(await authority.advance(epoch,floor,signal),false);
  assert.equal(called,0);
});
test('aborted authority request is rejected',async()=>{
  let complete;
  const authority=createIndependentContinuityAuthority({
    namespace:'palaco.registry',compareAndAdvance:()=>new Promise(resolve=>{complete=resolve;})
  });
  const controller=new AbortController();
  const pending=authority.advance(5,1000,controller.signal);
  controller.abort();
  complete(true);
  assert.equal(await pending,false);
});
test('missing namespace and forged authority are rejected',()=>{
  assert.throws(()=>createIndependentContinuityAuthority({compareAndAdvance:()=>true}),TypeError);
  assert.throws(()=>createIndependentContinuityAuthority({
    namespace:'***',compareAndAdvance:()=>true}),TypeError);
  assert.equal(isIndependentContinuityAuthority({namespace:'palaco.registry',advance:()=>true}),false);
  assert.equal(isIndependentContinuityAuthority(null),false);
});
