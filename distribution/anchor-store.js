'use strict';
const { assessTrustContinuity } = require('./trust-continuity');
const { verifyCheckpointAuthority } = require('./authenticated-checkpoint');
const NAME = /^[a-z][a-z0-9._-]{2,79}$/;
const HASH = /^[a-f0-9]{64}$/;

function outcome(readiness, findings) {
  return Object.freeze({
    schemaVersion: 'palaco.distribution.anchor-store.v1',
    readiness, authorization: 'DENY', go13: 'HOLD',
    mayPublish: false, mayInstall: false,
    findings: Object.freeze(findings)
  });
}

// Schema only; authenticated initial anchor provisioning is explicitly external.
function initializeAnchorSchema(db) {
  db.exec('CREATE TABLE IF NOT EXISTS distribution_trust_anchors (' +
    'namespace TEXT PRIMARY KEY NOT NULL, ' +
    'sequence INTEGER NOT NULL CHECK(sequence >= 0), ' +
    'digest TEXT NOT NULL CHECK(length(digest) = 64)) STRICT');
}

// Requires sole ownership of the caller-provided DB transaction scope.
function commitVerifiedAnchor(db, namespace, snapshot, checkpoint, endorsement, pinnedRoots) {
  if (typeof namespace !== 'string' || !NAME.test(namespace))
    return outcome('BLOCKED', ['INVALID_NAMESPACE']);
  let transaction = false;
  try {
    db.exec('BEGIN IMMEDIATE');
    transaction = true;
    const anchor = db.prepare(
      'SELECT sequence, digest FROM distribution_trust_anchors WHERE namespace = ?'
    ).get(namespace);
    if (!anchor || !Number.isSafeInteger(anchor.sequence) || anchor.sequence < 0 ||
        typeof anchor.digest !== 'string' || !HASH.test(anchor.digest)) {
      db.exec('ROLLBACK'); transaction = false;
      return outcome('BLOCKED', ['TRUSTED_ANCHOR_NOT_PROVISIONED']);
    }
    const continuity = assessTrustContinuity(snapshot, checkpoint, anchor);
    const authority = verifyCheckpointAuthority(checkpoint, endorsement, pinnedRoots);
    const findings = [...continuity.findings, ...authority.findings];
    if (findings.length) {
      db.exec('ROLLBACK'); transaction = false;
      return outcome('BLOCKED', findings);
    }
    const changed = db.prepare('UPDATE distribution_trust_anchors SET sequence=?, digest=? ' +
      'WHERE namespace=? AND sequence=? AND digest=?')
      .run(checkpoint.sequence, checkpoint.digest, namespace, anchor.sequence, anchor.digest);
    if (changed.changes !== 1) {
      db.exec('ROLLBACK'); transaction = false;
      return outcome('BLOCKED', ['CONCURRENT_ANCHOR_MODIFICATION']);
    }
    db.exec('COMMIT'); transaction = false;
    return outcome('ANCHOR_COMMITTED', []);
  } catch (_) {
    if (transaction) {
      try { db.exec('ROLLBACK'); } catch (_) { /* no success claim */ }
    }
    return outcome('BLOCKED', ['ANCHOR_STORAGE_FAILURE']);
  }
}

module.exports = { initializeAnchorSchema, commitVerifiedAnchor };
