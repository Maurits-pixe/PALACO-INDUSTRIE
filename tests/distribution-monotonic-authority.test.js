'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { assessMonotonicAdvance, assessMonotonicRecovery } = require('../distribution/monotonic-authority');
const ns = 'palaco.one';
const current = () => ({ namespace: ns, sequence: 9, digest: 'a'.repeat(64), authenticated: true });
const expected = () => ({ namespace: ns, sequence: 9, digest: 'a'.repeat(64) });
const proposed = () => ({ namespace: ns, sequence: 10, digest: 'b'.repeat(64) });
const advance = (c=current(), p=proposed(), e=expected(), n=ns) => assessMonotonicAdvance(n,c,p,e);
const recover = (c=current(), r=expected(), n=ns) => assessMonotonicRecovery(n,c,r);

test('valid advance is diagnostic only', () => {
 const r=advance();
 assert.equal(r.readiness,'ADVANCE_PRECONDITIONS_MATCH');
 assert.equal(r.authorization,'DENY');
 assert.equal(r.go13,'HOLD');
 assert.equal(r.mayAdvance,false);
 assert.equal(r.mayPublish,false);
 assert.ok(Object.isFrozen(r.findings));
});
test('stale compare-and-swap state blocks', () => {
 assert.ok(advance(current(),proposed(),{...expected(),sequence:8}).findings.includes('AUTHORITY_COMPARE_AND_SWAP_CONFLICT'));
});
test('rollback replay and sequence gaps block', () => {
 for(const sequence of [7,9,11]) assert.equal(advance(current(),{...proposed(),sequence}).readiness,'BLOCKED');
});
test('reused digest blocks', () => {
 assert.ok(advance(current(),{...proposed(),digest:'a'.repeat(64)}).findings.includes('REUSED_CHECKPOINT_DIGEST'));
});
test('missing or untrusted authority blocks both operations', () => {
 for(const c of [null,{...current(),authenticated:false},{...current(),namespace:'another.ns'}]){
  assert.equal(advance(c).readiness,'BLOCKED');
  assert.equal(recover(c).readiness,'BLOCKED');
 }
});
test('matching restored state diagnostic only', () => {
 const r=recover();
 assert.equal(r.readiness,'RECOVERY_PRECONDITIONS_MATCH');
 assert.equal(r.mayRestore,false);
});
test('old future and forked restore block', () => {
 for(const r of [{...expected(),sequence:8},{...expected(),sequence:10},{...expected(),digest:'c'.repeat(64)}])
  assert.equal(recover(current(),r).readiness,'BLOCKED');
});
test('invalid namespace and corrupt digests fail closed', () => {
 assert.equal(advance(current(),proposed(),expected(),'../escape').readiness,'BLOCKED');
 assert.equal(advance(current(),{...proposed(),digest:'bad'}).readiness,'BLOCKED');
 assert.equal(recover(current(),{...expected(),digest:'bad'}).readiness,'BLOCKED');
});
