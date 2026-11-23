'use strict';

// Read-only, operator-reviewed bootstrap dossier verifier.
// This is diagnostic evidence, NOT an enabling capability or a trust service.
const {createPublicKey,verify,createHash} = require('node:crypto');
const {verifyReviewerRosterTransition,
  verifyRotationBoundReviewerRosterTransition}=require('./reviewer-roster-transition');
const HEX=/^[a-f0-9]{64}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const VERSION='palaco.distribution.bootstrap-dossier.v1';

function dossierPayload(d) {
  if(!d||typeof d!=='object'||Array.isArray(d)||
    d.schemaVersion!==VERSION||typeof d.namespace!=='string'||!NS.test(d.namespace)||
    !Number.isSafeInteger(d.sequence)||d.sequence<1||
    !Number.isSafeInteger(d.issuedAtMs)||d.issuedAtMs<0||
    !Number.isSafeInteger(d.expiresAtMs)||d.expiresAtMs<=d.issuedAtMs||
    !HEX.test(d.sourceDigest||'')||!HEX.test(d.checkpointDigest||'')||
    !HEX.test(d.anchorDigest||'')||!HEX.test(d.postgresSchemaDigest||'')||
    !HEX.test(d.pinnedRootsDigest||'')||
    d.go13!=='HOLD'||d.authorization!=='DENY') return null;
  return Buffer.from([
    'PALACO-INDUSTRIE-BOOTSTRAP-DOSSIER-V1',VERSION,d.namespace,
    String(d.sequence),String(d.issuedAtMs),String(d.expiresAtMs),
    d.sourceDigest,d.checkpointDigest,d.anchorDigest,d.postgresSchemaDigest,
    d.pinnedRootsDigest,d.authorization,d.go13,''
  ].join('\n'),'utf8');
}

function deny(findings, digest=null) {
  return Object.freeze({
    schemaVersion:'palaco.distribution.bootstrap-assessment.v1',
    readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
    ingressEnabled:false,mayAdvance:false,mayRestore:false,
    mayRotate:false,mayInstall:false,mayPublish:false,
    dossierDigest:digest,
    findings:Object.freeze(findings)
  });
}

/**
 * Trust roots & sequence must be supplied by a reviewed, independently
 * protected caller. Signatures attest dossier bytes only; no operational
 * independence, actual external witnesses, or live readiness is inferred.
 */
function verifyBootstrapDossier(dossier,endorsements,{
  namespace,pinnedReviewRoots,minimumSequence,nowMs,maximumLifetimeMs=86400000
}={}) {
  const payload=dossierPayload(dossier);
  if(!payload||dossier.namespace!==namespace)
    return deny(['BOOTSTRAP_DOSSIER_MALFORMED']);
  const digest=createHash('sha256').update(payload).digest('hex');
  if(!Number.isSafeInteger(minimumSequence)||minimumSequence<1||
    !Number.isSafeInteger(nowMs)||nowMs<0||
    !Number.isSafeInteger(maximumLifetimeMs)||maximumLifetimeMs<1||
    maximumLifetimeMs>86400000)
    return deny(['BOOTSTRAP_ANCHOR_UNAVAILABLE'],digest);
  if(dossier.sequence<minimumSequence||nowMs<dossier.issuedAtMs||
    nowMs>=dossier.expiresAtMs||
    dossier.expiresAtMs-dossier.issuedAtMs>maximumLifetimeMs)
    return deny(['BOOTSTRAP_DOSSIER_STALE'],digest);
  if(!Array.isArray(pinnedReviewRoots)||pinnedReviewRoots.length<2||
    pinnedReviewRoots.length>32||
    !Array.isArray(endorsements)||endorsements.length!==2)
    return deny(['BOOTSTRAP_REVIEW_QUORUM_MISSING'],digest);
  const keys=new Set(),reviewers=new Set();
  for(const endorsement of endorsements){
    if(!endorsement||endorsement.algorithm!=='Ed25519'||
      typeof endorsement.keyId!=='string'||!ID.test(endorsement.keyId)||
      typeof endorsement.signature!=='string'||
      !/^[A-Za-z0-9+/]{86}==$/.test(endorsement.signature)||
      Buffer.from(endorsement.signature,'base64').toString('base64')!==endorsement.signature||
      keys.has(endorsement.keyId))
      return deny(['BOOTSTRAP_REVIEW_SIGNATURE_INVALID'],digest);
    keys.add(endorsement.keyId);
    const matching=pinnedReviewRoots.filter(root=>root&&root.keyId===endorsement.keyId);
    if(matching.length!==1||matching[0].enabled!==true||
       matching[0].revoked!==false||typeof matching[0].reviewerId!=='string'||
       !ID.test(matching[0].reviewerId)||reviewers.has(matching[0].reviewerId)||
       typeof matching[0].publicKeyPem!=='string'||
       matching[0].publicKeyPem.length>4096)
      return deny(['BOOTSTRAP_REVIEW_ROOT_UNTRUSTED'],digest);
    reviewers.add(matching[0].reviewerId);
    try{
      const key=createPublicKey(matching[0].publicKeyPem);
      if(key.asymmetricKeyType!=='ed25519'||
        !verify(null,payload,key,Buffer.from(endorsement.signature,'base64')))
        return deny(['BOOTSTRAP_REVIEW_SIGNATURE_INVALID'],digest);
    }catch(_){return deny(['BOOTSTRAP_REVIEW_SIGNATURE_INVALID'],digest);}
  }
  // Even valid two-person approval is evidence only, never deployment authority.
  return deny(['BOOTSTRAP_EVIDENCE_VERIFIED_NO_RELEASE_AUTHORITY'],digest);
}
/**
 * Opt-in provenance-bound verification. Never treat unverified caller roots as
 * authoritative when a signed roster lineage is expected.
 * The separate roster authority anchor must be provided out of band.
 */
function verifyRosterBoundBootstrapDossier(dossier,endorsements,reviewPolicy,
  rosterEvidence) {
  if(!rosterEvidence||typeof rosterEvidence!=='object'||Array.isArray(rosterEvidence))
    return deny(['BOOTSTRAP_ROSTER_EVIDENCE_MISSING']);
  const transition=Object.hasOwn(rosterEvidence,'authorityRotation')
    ? verifyRotationBoundReviewerRosterTransition(
      rosterEvidence.previous,rosterEvidence.next,rosterEvidence.endorsement,
      rosterEvidence.anchor,rosterEvidence.authorityRotation)
    : verifyReviewerRosterTransition(
      rosterEvidence.previous,rosterEvidence.next,rosterEvidence.endorsement,
      rosterEvidence.anchor);
  if(transition.readiness!=='ROSTER_TRANSITION_VERIFIED_NON_AUTHORIZING')
    return deny(['BOOTSTRAP_ROSTER_TRANSITION_REJECTED']);
  if(!dossier||dossier.pinnedRootsDigest!==transition.digest)
    return deny(['BOOTSTRAP_ROSTER_DIGEST_MISMATCH']);
  if(!reviewPolicy||typeof reviewPolicy!=='object'||Array.isArray(reviewPolicy)||
     reviewPolicy.namespace!==rosterEvidence.anchor.namespace)
    return deny(['BOOTSTRAP_ROSTER_SCOPE_MISMATCH']);
  // Do not let a caller override the roots extracted from the signed roster.
  return verifyBootstrapDossier(dossier,endorsements,{
    ...reviewPolicy,pinnedReviewRoots:transition.reviewRoots
  });
}
module.exports={VERSION,dossierPayload,verifyBootstrapDossier,
  verifyRosterBoundBootstrapDossier};
