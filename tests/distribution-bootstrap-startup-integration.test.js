'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {dossierPayload}=require('../distribution/bootstrap-review-dossier');
const {createDistributionStartupInterlock}=
 require('../distribution/distribution-startup-interlock');

function reviewFixture(){
 const a=generateKeyPairSync('ed25519');
 const b=generateKeyPairSync('ed25519');
 const dossier={
  schemaVersion:'palaco.distribution.bootstrap-dossier.v1',
  namespace:'palaco.registry',sequence:16,
  issuedAtMs:1000,expiresAtMs:6000,
  sourceDigest:'a'.repeat(64),checkpointDigest:'b'.repeat(64),
  anchorDigest:'c'.repeat(64),postgresSchemaDigest:'d'.repeat(64),
  pinnedRootsDigest:'e'.repeat(64),authorization:'DENY',go13:'HOLD'
 };
 const endorsements=[{algorithm:'Ed25519',keyId:'reviewer-key-a',
   signature:sign(null,dossierPayload(dossier),a.privateKey).toString('base64')},
  {algorithm:'Ed25519',keyId:'reviewer-key-b',
   signature:sign(null,dossierPayload(dossier),b.privateKey).toString('base64')}];
 const roots=[
  {keyId:'reviewer-key-a',reviewerId:'person-a',enabled:true,revoked:false,
   publicKeyPem:a.publicKey.export({type:'spki',format:'pem'})},
  {keyId:'reviewer-key-b',reviewerId:'person-b',enabled:true,revoked:false,
   publicKeyPem:b.publicKey.export({type:'spki',format:'pem'})}
 ];
 return {dossier,endorsements,reviewPolicy:{
  namespace:'palaco.registry',pinnedReviewRoots:roots,
  minimumSequence:16,nowMs:3000}};
}
function assertHeld(state){
 assert.equal(state.ingress,null);
 assert.equal(state.report.readiness,'BLOCKED');
 assert.equal(state.report.authorization,'DENY');
 assert.equal(state.report.go13,'HOLD');
 assert.equal(state.report.ingressEnabled,false);
 assert.equal(state.report.mayAdvance,false);
 assert.equal(state.report.mayPublish,false);
 assert.equal(state.report.mayInstall,false);
 assert.ok(Object.isFrozen(state.report.findings));
}
test('signed two-reviewer dossier is recognized only as non-authorizing evidence',()=>{
 const state=createDistributionStartupInterlock({},reviewFixture());
 assertHeld(state);
 assert.equal(state.report.evidenceStatus,'VERIFIED_NON_AUTHORIZING');
 assert.match(state.report.evidenceDigest,/^[a-f0-9]{64}$/);
 assert.deepEqual(state.report.findings,['BOOTSTRAP_EVIDENCE_VERIFIED_NO_RELEASE_AUTHORITY']);
});
test('tampered, stale and revoked dossier cannot activate ingress',()=>{
 for(const mode of ['tamper','stale','revoked','missing-sequence']){
  const evidence=reviewFixture();
  if(mode==='tamper')evidence.dossier.checkpointDigest='f'.repeat(64);
  if(mode==='stale')evidence.reviewPolicy.nowMs=7000;
  if(mode==='revoked')evidence.reviewPolicy.pinnedReviewRoots[1].revoked=true;
  if(mode==='missing-sequence')delete evidence.reviewPolicy.minimumSequence;
  const state=createDistributionStartupInterlock({},evidence);
  assertHeld(state);
  assert.equal(state.report.evidenceStatus,'NOT_PROVIDED');
  assert.notEqual(state.report.findings[0],
    'BOOTSTRAP_EVIDENCE_VERIFIED_NO_RELEASE_AUTHORITY');
 }
});
test('malformed evidence inputs fail closed without throwing or logging payloads',()=>{
 for(const input of [{},{dossier:null,endorsements:[],reviewPolicy:{}},
  {dossier:{$secret:'DO_NOT_ECHO'},endorsements:[],reviewPolicy:{}},
  {dossier:[],endorsements:[],reviewPolicy:{}}]){
  const state=createDistributionStartupInterlock({},input);
  assertHeld(state);
  assert.equal(state.report.evidenceStatus,'NOT_PROVIDED');
  assert.equal(state.report.evidenceDigest,null);
  assert.ok(!JSON.stringify(state.report).includes('DO_NOT_ECHO'));
 }
});
test('verified dossier and unauthorized release env remain in HOLD',()=>{
 const state=createDistributionStartupInterlock({
  PALACO_DISTRIBUTION_ENABLE:'true',
  PALACO_GO13_RELEASE:'GO',
  PALACO_AUTHORIZATION:'ALLOW'
 },reviewFixture());
 assertHeld(state);
 assert.equal(state.report.evidenceStatus,'VERIFIED_NON_AUTHORIZING');
 assert.deepEqual(state.report.findings,[
  'UNAUTHORIZED_DISTRIBUTION_STARTUP_OVERRIDE',
  'BOOTSTRAP_EVIDENCE_VERIFIED_NO_RELEASE_AUTHORITY'
 ]);
});
test('missing signed dossier leaves legacy default startup deny reason',()=>{
 const state=createDistributionStartupInterlock({});
 assertHeld(state);
 assert.equal(state.report.evidenceStatus,'NOT_PROVIDED');
 assert.equal(state.report.evidenceDigest,null);
 assert.deepEqual(state.report.findings,
  ['INDEPENDENT_DISTRIBUTION_TRUST_NOT_PROVISIONED']);
});
