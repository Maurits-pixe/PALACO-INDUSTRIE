'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSharedAuthorityAdmission, isSharedAuthorityAdmission } =
  require('../distribution/shared-authority-admission');

test('shared admission limits concurrent permits', () => {
  const shared = createSharedAuthorityAdmission({maxInFlight:2});
  const a=shared.acquire(),b=shared.acquire();
  assert.equal(typeof a,'function'); assert.equal(typeof b,'function');
  assert.equal(shared.acquire(),null);
  assert.deepEqual(shared.snapshot(),{active:2,capacity:2,available:0});
  assert.equal(a(),true);
  assert.equal(a(),false);
  assert.equal(typeof shared.acquire(),'function');
});
test('release is idempotent and never creates extra capacity', () => {
  const shared=createSharedAuthorityAdmission({maxInFlight:1});
  const release=shared.acquire();
  assert.equal(shared.acquire(),null);
  assert.equal(release(),true);
  assert.equal(release(),false);
  const next=shared.acquire();
  assert.equal(typeof next,'function');
  assert.equal(shared.acquire(),null);
  next();
  assert.equal(shared.snapshot().active,0);
});
test('shared budget accepts only constructed branded objects', () => {
  const shared=createSharedAuthorityAdmission();
  assert.equal(isSharedAuthorityAdmission(shared),true);
  assert.equal(isSharedAuthorityAdmission({acquire:()=>()=>{}}),false);
  assert.equal(isSharedAuthorityAdmission(null),false);
});
test('invalid shared capacity fails before allocation', () => {
  for(const value of [0,-1,4097,'2',NaN,1.2]) {
    assert.throws(()=>createSharedAuthorityAdmission({maxInFlight:value}),RangeError);
  }
});
test('snapshots are immutable and diagnostic only', () => {
  const shared=createSharedAuthorityAdmission();
  const snapshot=shared.snapshot();
  assert.ok(Object.isFrozen(snapshot));
  assert.equal(snapshot.available,32);
  assert.equal(snapshot.active,0);
});
