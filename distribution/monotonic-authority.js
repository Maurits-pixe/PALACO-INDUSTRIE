'use strict';

const { timingSafeEqual } = require('node:crypto');
const HEX = /^[a-f0-9]{64}$/;
const NS = /^[a-z][a-z0-9._-]{2,79}$/;

function validAnchor(value) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Number.isSafeInteger(value.sequence) && value.sequence >= 0 &&
    typeof value.digest === 'string' && HEX.test(value.digest);
}
function equalDigest(a, b) {
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}
function result(readiness, findings) {
  return Object.freeze({
    schemaVersion: 'palaco.distribution.monotonic-authority-assessment.v1',
    readiness, authorization: 'DENY', go13: 'HOLD',
    mayAdvance: false, mayRestore: false, mayRotate: false,
    mayPublish: false, mayInstall: false,
    findings: Object.freeze(findings)
  });
}

/* Caller must independently authenticate state; this is a pure preflight,
 * not an atomic or monotonic storage implementation. */
function assessMonotonicAdvance(namespace, current, proposed, expected) {
  const findings = [];
  if (typeof namespace !== 'string' || !NS.test(namespace))
    findings.push('INVALID_NAMESPACE');
  if (!validAnchor(current) || current.namespace !== namespace || current.authenticated !== true)
    findings.push('UNTRUSTED_CURRENT_AUTHORITY_STATE');
  if (!validAnchor(expected) || expected.namespace !== namespace)
    findings.push('INVALID_EXPECTED_STATE');
  if (!validAnchor(proposed) || proposed.namespace !== namespace)
    findings.push('INVALID_PROPOSED_STATE');
  if (findings.length === 0) {
    if (current.sequence !== expected.sequence || !equalDigest(current.digest, expected.digest))
      findings.push('AUTHORITY_COMPARE_AND_SWAP_CONFLICT');
    if (proposed.sequence <= current.sequence) findings.push('NON_MONOTONIC_SEQUENCE');
    else if (proposed.sequence !== current.sequence + 1) findings.push('SEQUENCE_GAP');
    if (proposed.sequence === current.sequence && !equalDigest(proposed.digest, current.digest))
      findings.push('SAME_SEQUENCE_FORK');
    if (equalDigest(proposed.digest, current.digest))
      findings.push('REUSED_CHECKPOINT_DIGEST');
  }
  return result(findings.length ? 'BLOCKED' : 'ADVANCE_PRECONDITIONS_MATCH', findings);
}
function assessMonotonicRecovery(namespace, current, restored) {
  const findings = [];
  if (typeof namespace !== 'string' || !NS.test(namespace))
    findings.push('INVALID_NAMESPACE');
  if (!validAnchor(current) || current.namespace !== namespace || current.authenticated !== true)
    findings.push('UNTRUSTED_CURRENT_AUTHORITY_STATE');
  if (!validAnchor(restored) || restored.namespace !== namespace)
    findings.push('INVALID_RESTORED_STATE');
  if (findings.length === 0) {
    if (restored.sequence < current.sequence) findings.push('RESTORED_STATE_ROLLBACK');
    else if (restored.sequence > current.sequence) findings.push('AUTHORITY_STATE_STALE');
    else if (!equalDigest(restored.digest, current.digest))
      findings.push('RESTORED_STATE_FORK');
  }
  return result(findings.length ? 'BLOCKED' : 'RECOVERY_PRECONDITIONS_MATCH', findings);
}
module.exports = { assessMonotonicAdvance, assessMonotonicRecovery };
