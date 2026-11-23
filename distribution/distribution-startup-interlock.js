'use strict';

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

function createDistributionStartupInterlock(environment={}) {
  if (!environment || typeof environment!=='object' || Array.isArray(environment))
    throw new TypeError('Environment map required');
  const attempts=ATTEMPT_KEYS.filter(key =>
    Object.hasOwn(environment,key) &&
    environment[key] !== undefined &&
    String(environment[key]).trim() !== '');
  const findings=Object.freeze(attempts.length
    ? ['UNAUTHORIZED_DISTRIBUTION_STARTUP_OVERRIDE']
    : ['INDEPENDENT_DISTRIBUTION_TRUST_NOT_PROVISIONED']);
  const report=Object.freeze({
    schemaVersion:'palaco.distribution.startup-interlock.v1',
    readiness:'BLOCKED', authorization:'DENY', go13:'HOLD',
    ingressEnabled:false, mayAdvance:false,mayRestore:false,
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
