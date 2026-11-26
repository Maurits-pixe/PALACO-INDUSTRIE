'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {generateKeyPairSync,sign}=require('node:crypto');
const {authorityDigest,rotationPayload}=
  require('../distribution/roster-authority-rotation');
const {rosterPayload,rosterDigest,verifyRotationBoundReviewerRosterTransition}=
  require('../distribution/reviewer-roster-transition');
const {dossierPayload,verifyRosterBoundBootstrapDossier}=
  require('../distribution/bootstrap-review-dossier');

function fixture(){
 const keys=Array.from({length:6},()=>generateKeyPairSync('ed25519'));
 const pem=i=>keys[i].publicKey.export({type:'spki',format:'pem'});
 const prevAuthority={schemaVersion:'palaco.distribution.roster-authority.v1',
  namespace:'palaco.registry',revision:3,previousDigest:'0'.repeat(64),
  keys:[{keyId:'authority-a',status:'active',publicKeyPem:pem(0)}]};
 const nextAuthority={...prevAuthority,revision:4,
  previousDigest:authorityDigest(prevAuthority),
  keys:[{keyId:'authority-a',status:'revoked',publicKeyPem:pem(0)},
    {keyId:'authority-z',status:'active',publicKeyPem:pem(1)}]};
 const intent={schemaVersion:'palaco.distribution.roster-authority-rotation.v1',
  namespace:'palaco.registry',revision:4,previousDigest:authorityDigest(prevAuthority),
  nextDigest:authorityDigest(nextAuthority),oldKeyId:'authority-a',
  newKeyId:'authority-z'};
 const approval=(i,keyId,payload)=>({algorithm:'Ed25519',keyId,
  signature:sign(null,payload,keys[i].privateKey).toString('base64')});
 const endorsementPayload=rotationPayload(intent);
 const rotationEvidence={
  previous:prevAuthority,next:nextAuthority,record:intent,
  endorsements:{
   oldAuthority:approval(0,'authority-a',endorsementPayload),
   newAuthority:approval(1,'authority-z',endorsementPayload),
   reviewers:[approval(2,'approval-1',endorsementPayload),
     approval(3,'approval-2',endorsementPayload)]
  },
  anchor:{namespace:'palaco.registry',minimumRevision:3,
   previousDigest:authorityDigest(prevAuthority),pinnedReviewers:[
    {keyId:'approval-1',reviewerId:'person-1',enabled:true,revoked:false,publicKeyPem:pem(2)},
    {keyId:'approval-2',reviewerId:'person-2',enabled:true,revoked:false,publicKeyPem:pem(3)}
   ]}
 };
 const previous={schemaVersion:'palaco.distribution.reviewer-roster.v1',
  namespace:'palaco.registry',revision:12,previousDigest:'0'.repeat(64),
  reviewers:[
   {reviewerId:'alice',keyId:'key-alice',status:'active',publicKeyPem:pem(4)},
   {reviewerId:'bob',keyId:'key-bob',status:'active',publicKeyPem:pem(5)}
  ]};
 const next={...previous,revision:13,previousDigest:rosterDigest(previous),
  reviewers:previous.reviewers.map(r=>({...r}))};
 const endorsement=approval(1,'authority-z',rosterPayload(next));
 const options={namespace:'palaco.registry',minimumRevision:12,
  previousDigest:rosterDigest(previous),
  pinnedRoots:[{keyId:'unsafe-override',enabled:true,revoked:false,publicKeyPem:pem(0)}]};
 return {previous,next,endorsement,options,rotationEvidence,keys,approval};
}
const check=f=>verifyRotationBoundReviewerRosterTransition(
 f.previous,f.next,f.endorsement,f.options,f.rotationEvidence);
test('new roster signed by rotated authority accepted only after four-party evidence',()=>{
 const f=fixture();const result=check(f);
 assert.equal(result.readiness,'ROSTER_TRANSITION_VERIFIED_NON_AUTHORIZING');
 assert.equal(result.authorization,'DENY');assert.equal(result.go13,'HOLD');
 assert.equal(result.mayPublish,false);
});
test('old authority can no longer sign reviewer roster after verified rotation',()=>{
 const f=fixture();
 f.endorsement=f.approval(0,'authority-a',rosterPayload(f.next));
 assert.deepEqual(check(f).findings,['ROSTER_SIGNATURE_INVALID']);
});
test('absent or untrusted authority rotation prevents roster approval',()=>{
 const f=fixture();
 assert.deepEqual(verifyRotationBoundReviewerRosterTransition(f.previous,f.next,
  f.endorsement,f.options,null).findings,['AUTHORITY_ROTATION_EVIDENCE_MISSING']);
 f.rotationEvidence.anchor.previousDigest='f'.repeat(64);
 assert.deepEqual(check(f).findings,['AUTHORITY_ROTATION_EVIDENCE_REJECTED']);
});
test('missing independent reviewer cosignature blocks new signing authority',()=>{
 const f=fixture();f.rotationEvidence.endorsements.reviewers.pop();
 assert.deepEqual(check(f).findings,['AUTHORITY_ROTATION_EVIDENCE_REJECTED']);
});
test('rotated authority cannot be replayed into another namespace',()=>{
 const f=fixture();f.options.namespace='other.registry';
 assert.deepEqual(check(f).findings,['AUTHORITY_ROTATION_NAMESPACE_MISMATCH']);
});

test('bootstrap reviewer quorum inherits only rotation-attested roster identities',()=>{
 const f=fixture();
 const dossier={
  schemaVersion:'palaco.distribution.bootstrap-dossier.v1',
  namespace:'palaco.registry',sequence:20,issuedAtMs:1000,expiresAtMs:5000,
  sourceDigest:'a'.repeat(64),checkpointDigest:'b'.repeat(64),
  anchorDigest:'c'.repeat(64),postgresSchemaDigest:'d'.repeat(64),
  pinnedRootsDigest:rosterDigest(f.next),authorization:'DENY',go13:'HOLD'
 };
 const endorsements=[
  f.approval(4,'key-alice',dossierPayload(dossier)),
  f.approval(5,'key-bob',dossierPayload(dossier))
 ];
 const policy={namespace:'palaco.registry',minimumSequence:20,nowMs:2000,
  pinnedReviewRoots:[{keyId:'forged',reviewerId:'forged',enabled:true,revoked:false,
    publicKeyPem:f.keys[0].publicKey.export({type:'spki',format:'pem'})}]};
 const rosterEvidence={previous:f.previous,next:f.next,
  endorsement:f.endorsement,anchor:f.options,
  authorityRotation:f.rotationEvidence};
 const verified=verifyRosterBoundBootstrapDossier(dossier,endorsements,
  policy,rosterEvidence);
 assert.deepEqual(verified.findings,['BOOTSTRAP_EVIDENCE_VERIFIED_NO_RELEASE_AUTHORITY']);
 assert.equal(verified.authorization,'DENY');
 f.rotationEvidence.endorsements.reviewers.pop();
 assert.deepEqual(verifyRosterBoundBootstrapDossier(dossier,endorsements,
  policy,rosterEvidence).findings,['BOOTSTRAP_ROSTER_TRANSITION_REJECTED']);
});
