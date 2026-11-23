'use strict';

const {verifyBootstrapDossier} = require('./bootstrap-review-dossier');

/**
 * v3.4 startup interlock.
 * Operator environment variables are *not* release authority. This boundary
 * never creates an ingress or binds signing keys, databases or anchor services.
 * All states deny until an independent, reviewed bootstrap is implemented.
 */
const ATTEMPT_KEYS=Object.freeze([
  'PALACO_DISTRIBUTION_ENABLE',
  'PALACO_DISTRIBUTION_ENABLED',
  'PALACO_DISTRIBUTION_ALLOW',
  'PALACO_DISTRIBUTION_FORCE',
  'PALACO_DISTRIBUTION_BYPASS',
  'PALACO_GO13_RELEASE',
  'PALACO_AUTHORIZATION',
  'PALACO_CHECKPOINT_BYPASS',
  'PALACO_LEGACY_CHALLENGES'
]);

/**
 * Optional explicit review evidence is passed by trusted startup code only;
 * neither HTTP requests nor environment variables can supply it.
 * A verified dossier is documentary evidence and NEVER enables ingress.
 */
function createDistributionStartupInterlock(environment={}, reviewEvidence=null) {
  if (!environment || typeof environment!=='object' || Array.isArray(environment))
    throw new TypeError('Environment map required');
  const attempts=ATTEMPT_KEYS.filter(key =>
    Object.hasOwn(environment,key) &&
    environment[key] !== undefined &&
    String(environment[key]).trim() !== '');
  let evidenceStatus='NOT_PROVIDED';
  let evidenceDigest=null;
  let evidenceFinding=null;
  if(reviewEvidence!==null) {
    try {
      if(!reviewEvidence || typeof reviewEvidence!=='object' ||
          Array.isArray(reviewEvidence) ||
          !Object.hasOwn(reviewEvidence,'dossier') ||
          !Object.hasOwn(reviewEvidence,'endorsements') ||
          !Object.hasOwn(reviewEvidence,'reviewPolicy')) {
        evidenceFinding='BOOTSTRAP_REVIEW_INPUT_INVALID';
      } else {
        const assessment=verifyBootstrapDossier(
          reviewEvidence.dossier,reviewEvidence.endorsements,
          reviewEvidence.reviewPolicy);
        evidenceDigest=assessment.dossierDigest;
        evidenceFinding=assessment.findings[0] || 'BOOTSTRAP_REVIEW_INPUT_INVALID';
        if(evidenceFinding==='BOOTSTRAP_EVIDENCE_VERIFIED_NO_RELEASE_AUTHORITY')
          evidenceStatus='VERIFIED_NON_AUTHORIZING';
      }
    } catch (_) { evidenceFinding='BOOTSTRAP_REVIEW_INPUT_INVALID'; }
  }
  const findings=Object.freeze([
    ...(attempts.length ? ['UNAUTHORIZED_DISTRIBUTION_STARTUP_OVERRIDE'] : []),
    ...(evidenceFinding ? [evidenceFinding] :
      attempts.length ? [] : ['INDEPENDENT_DISTRIBUTION_TRUST_NOT_PROVISIONED'])
  ]);
  const report=Object.freeze({
    schemaVersion:'palaco.distribution.startup-interlock.v1',
    readiness:'BLOCKED', authorization:'DENY', go13:'HOLD',
    ingressEnabled:false, evidenceStatus, evidenceDigest,
    mayAdvance:false,mayRestore:false,
    mayRotate:false,mayInstall:false,mayPublish:false,
    findings
  });
  return Object.freeze({
    report,
    // Always null: an operator cannot elevate an HTTP route with env vars.
    ingress:null
  });
}

module.exports={createDistributionStartupInterlock};
