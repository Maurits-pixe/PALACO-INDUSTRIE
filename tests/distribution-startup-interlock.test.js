'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createDistributionStartupInterlock}=
  require('../distribution/distribution-startup-interlock');

test('clean startup is closed without independent trust',()=>{
 const result=createDistributionStartupInterlock({});
 assert.equal(result.ingress,null);
 assert.equal(result.report.readiness,'BLOCKED');
 assert.equal(result.report.authorization,'DENY');
 assert.equal(result.report.go13,'HOLD');
 assert.equal(result.report.ingressEnabled,false);
 assert.equal(result.report.mayPublish,false);
 assert.deepEqual(result.report.findings,['INDEPENDENT_DISTRIBUTION_TRUST_NOT_PROVISIONED']);
 assert.ok(Object.isFrozen(result.report));
});
test('no environment switch, even contradictory switches, can enable distribution',()=>{
 for(const env of [
  {PALACO_DISTRIBUTION_ENABLE:'true'},
  {PALACO_DISTRIBUTION_ENABLED:'1',PALACO_GO13_RELEASE:'GO'},
  {PALACO_AUTHORIZATION:'ALLOW',PALACO_CHECKPOINT_BYPASS:'yes'},
  {PALACO_DISTRIBUTION_FORCE:'true',PALACO_LEGACY_CHALLENGES:'true'},
  {PALACO_DISTRIBUTION_BYPASS:'1',PALACO_DISTRIBUTION_ALLOW:'1'}
 ]){
  const state=createDistributionStartupInterlock(env);
  assert.equal(state.ingress,null);
  assert.equal(state.report.ingressEnabled,false);
  assert.equal(state.report.authorization,'DENY');
  assert.equal(state.report.go13,'HOLD');
  assert.deepEqual(state.report.findings,['UNAUTHORIZED_DISTRIBUTION_STARTUP_OVERRIDE']);
 }
});
test('startup report never reflects secret values or enables on mutable env',()=>{
 const env={PALACO_DISTRIBUTION_ENABLE:'secret-must-not-appear'};
 const state=createDistributionStartupInterlock(env);
 env.PALACO_DISTRIBUTION_ENABLE='true';
 assert.equal(state.ingress,null);
 assert.ok(!JSON.stringify(state).includes('secret-must-not-appear'));
 assert.ok(Object.isFrozen(state));
 assert.ok(Object.isFrozen(state.report.findings));
});
test('malformed environment map is rejected',()=>{
 for(const bad of [null,[],42,'abc'])
  assert.throws(()=>createDistributionStartupInterlock(bad),TypeError);
});
