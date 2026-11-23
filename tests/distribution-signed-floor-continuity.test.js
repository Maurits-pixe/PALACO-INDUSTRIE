'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createSignedFloorContinuity,isSignedFloorContinuity}=
  require('../distribution/signed-floor-continuity');

test('signed floor epoch and bound advance monotonically',()=>{
 const c=createSignedFloorContinuity();
 assert.equal(c.observe(5,1000),true);
 assert.equal(c.observe(5,1000),true);
 assert.equal(c.observe(6,1500),true);
 assert.deepEqual(c.snapshot(),{epoch:6,minimumLastSeenMs:1500});
});
test('epoch rollback is rejected without changing the high-watermark',()=>{
 const c=createSignedFloorContinuity();
 assert.equal(c.observe(8,1000),true);
 assert.equal(c.observe(7,1200),false);
 assert.deepEqual(c.snapshot(),{epoch:8,minimumLastSeenMs:1000});
});
test('signed floor rollback is rejected even if epoch advances',()=>{
 const c=createSignedFloorContinuity();
 assert.equal(c.observe(8,2000),true);
 assert.equal(c.observe(9,1999),false);
 assert.deepEqual(c.snapshot(),{epoch:8,minimumLastSeenMs:2000});
});
test('bad inputs and fabricated continuity object are rejected',()=>{
 const c=createSignedFloorContinuity();
 for(const [epoch,floor] of [[-1,0],[0,-1],['1',1],[1,NaN],[1,1.1]])
  assert.equal(c.observe(epoch,floor),false);
 assert.equal(isSignedFloorContinuity(c),true);
 assert.equal(isSignedFloorContinuity({observe:()=>true}),false);
 assert.equal(isSignedFloorContinuity(null),false);
});
test('snapshot is immutable and cannot reset continuity',()=>{
 const c=createSignedFloorContinuity();
 c.observe(10,5000);
 const snap=c.snapshot();
 assert.ok(Object.isFrozen(snap));
 assert.equal(c.observe(9,4999),false);
 assert.equal(c.snapshot().epoch,10);
});
